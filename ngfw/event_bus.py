"""In-process pub/sub event bus.

Downstream topics: "packet", "flow_closed", "classified", "action",
"metrics_tick".
"""

import queue
import threading
from typing import Any


class EventBus:
    def __init__(self) -> None:
        self._subs: dict[str, list[queue.Queue]] = {}
        self._lock = threading.Lock()

    def subscribe(self, topic: str, maxsize: int = 1000) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=maxsize)
        with self._lock:
            self._subs.setdefault(topic, []).append(q)
        return q

    def publish(self, topic: str, event: Any) -> None:
        with self._lock:
            subs = list(self._subs.get(topic, ()))
        for q in subs:
            try:
                q.put_nowait(event)
            except queue.Full:
                pass  # drop on slow consumer; do not block producer
