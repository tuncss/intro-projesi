import logging
import shlex
import subprocess
import threading
import time
from dataclasses import dataclass

from ngfw.config import Config
from ngfw.event_bus import EventBus


log = logging.getLogger("ngfw.action")

# Every iptables rule we manage carries this comment prefix so we can recognize
# and clean up only our rules, never the user's.
COMMENT_TAG = "mini-ngfw"


@dataclass
class BlockEntry:
    ip: str
    reason: str
    blocked_at: float
    expires_at: float


class ActionEngine:
    def __init__(self, cfg: Config, bus: EventBus) -> None:
        self.cfg = cfg
        self.bus = bus
        self._blocks: dict[str, BlockEntry] = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._cleanup_thread: threading.Thread | None = None

    def start(self) -> None:
        # Wipe any stale NGFW-managed rules left over from a previous run.
        purged = self._purge_managed_rules()
        if purged:
            log.info("Cleared %d stale managed iptables rules on startup", purged)
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop,
            daemon=True,
            name="action-cleanup",
        )
        self._cleanup_thread.start()

    def stop(self) -> None:
        self._stop.set()

    def block(self, ip: str, reason: str) -> bool:
        """Returns True if newly blocked, False if already blocked."""
        with self._lock:
            already = ip in self._blocks
            if not already:
                now = time.time()
                self._blocks[ip] = BlockEntry(
                    ip=ip,
                    reason=reason,
                    blocked_at=now,
                    expires_at=now + self.cfg.block_ttl,
                )
        # Always reconcile iptables - self-heals if state drifted from kernel.
        added = self._iptables_add(ip)
        if already and not added:
            return False
        self.bus.publish(
            "action",
            {"type": "block", "ip": ip, "reason": reason, "ttl": self.cfg.block_ttl},
        )
        return not already

    def unblock(self, ip: str) -> bool:
        with self._lock:
            present = ip in self._blocks
            if present:
                del self._blocks[ip]
        removed = self._iptables_del(ip)
        if not present and not removed:
            return False
        self.bus.publish("action", {"type": "unblock", "ip": ip})
        return True

    def list_blocks(self) -> list[BlockEntry]:
        with self._lock:
            return list(self._blocks.values())

    def reset_all(self) -> int:
        """Clear in-memory state and remove every NGFW-managed iptables rule.

        Returns the count of iptables rules removed.
        """
        with self._lock:
            ips = list(self._blocks.keys())
            self._blocks.clear()
        for ip in ips:
            self.bus.publish("action", {"type": "unblock", "ip": ip})
        removed = self._purge_managed_rules()
        log.info("Reset: cleared %d in-memory blocks, removed %d iptables rules",
                 len(ips), removed)
        return removed

    def _cleanup_loop(self) -> None:
        while not self._stop.wait(self.cfg.cleanup_interval):
            now = time.time()
            expired = [e.ip for e in self.list_blocks() if e.expires_at <= now]
            for ip in expired:
                self.unblock(ip)

    def _comment_for(self, ip: str) -> str:
        return f"{COMMENT_TAG}:{ip}"

    def _rule_exists(self, ip: str) -> bool:
        res = subprocess.run(
            ["sudo", "iptables", "-C", self.cfg.iptables_chain,
             "-s", ip, "-m", "comment", "--comment", self._comment_for(ip),
             "-j", "DROP"],
            check=False, capture_output=True,
        )
        return res.returncode == 0

    def _iptables_add(self, ip: str) -> bool:
        """Insert at top of chain. No-op if already present. Returns True if added."""
        if self._rule_exists(ip):
            return False
        res = subprocess.run(
            ["sudo", "iptables", "-I", self.cfg.iptables_chain, "1",
             "-s", ip, "-m", "comment", "--comment", self._comment_for(ip),
             "-j", "DROP"],
            check=False, capture_output=True, text=True,
        )
        if res.returncode != 0:
            log.error("iptables add failed for %s: %s", ip, res.stderr.strip())
            return False
        return True

    def _iptables_del(self, ip: str) -> bool:
        """Delete every matching rule (in case of duplicates from drift)."""
        removed = False
        for _ in range(10):
            if not self._rule_exists(ip):
                break
            res = subprocess.run(
                ["sudo", "iptables", "-D", self.cfg.iptables_chain,
                 "-s", ip, "-m", "comment", "--comment", self._comment_for(ip),
                 "-j", "DROP"],
                check=False, capture_output=True,
            )
            if res.returncode != 0:
                break
            removed = True
        return removed

    def _purge_managed_rules(self) -> int:
        """Delete every rule in any chain whose comment carries our tag."""
        res = subprocess.run(
            ["sudo", "iptables-save"], check=False, capture_output=True, text=True,
        )
        if res.returncode != 0:
            log.warning("iptables-save failed: %s", res.stderr.strip())
            return 0
        removed = 0
        for line in res.stdout.splitlines():
            if not line.startswith("-A "):
                continue
            if COMMENT_TAG not in line:
                continue
            try:
                parts = shlex.split(line)
            except ValueError:
                continue
            parts[0] = "-D"
            r = subprocess.run(
                ["sudo", "iptables", *parts], check=False, capture_output=True,
            )
            if r.returncode == 0:
                removed += 1
        return removed
