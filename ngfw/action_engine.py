import subprocess
import threading
import time
from dataclasses import dataclass

from ngfw.config import Config
from ngfw.event_bus import EventBus


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
            if ip in self._blocks:
                return False
            now = time.time()
            entry = BlockEntry(
                ip=ip,
                reason=reason,
                blocked_at=now,
                expires_at=now + self.cfg.block_ttl,
            )
            self._blocks[ip] = entry
        self._iptables_add(ip)
        self.bus.publish(
            "action",
            {"type": "block", "ip": ip, "reason": reason, "ttl": self.cfg.block_ttl},
        )
        return True

    def unblock(self, ip: str) -> bool:
        with self._lock:
            if ip not in self._blocks:
                return False
            del self._blocks[ip]
        self._iptables_del(ip)
        self.bus.publish("action", {"type": "unblock", "ip": ip})
        return True

    def list_blocks(self) -> list[BlockEntry]:
        with self._lock:
            return list(self._blocks.values())

    def _cleanup_loop(self) -> None:
        while not self._stop.wait(self.cfg.cleanup_interval):
            now = time.time()
            expired = [e.ip for e in self.list_blocks() if e.expires_at <= now]
            for ip in expired:
                self.unblock(ip)

    def _iptables_add(self, ip: str) -> None:
        subprocess.run(
            ["sudo", "iptables", "-A", self.cfg.iptables_chain, "-s", ip, "-j", "DROP"],
            check=True,
        )

    def _iptables_del(self, ip: str) -> None:
        subprocess.run(
            ["sudo", "iptables", "-D", self.cfg.iptables_chain, "-s", ip, "-j", "DROP"],
            check=False,
        )
