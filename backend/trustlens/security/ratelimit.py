"""Small in-process rate limiter.

Documented limitation: this protects a single Render instance only. A
multi-instance deployment must move limits to the database or a shared store.
"""

from __future__ import annotations

import threading
import time
from collections import deque


class RateLimiter:
    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()
        self._last_prune = time.monotonic()

    def allow(self, key: str, limit: int, window_seconds: int = 60) -> tuple[bool, int]:
        now = time.monotonic()
        cutoff = now - window_seconds
        with self._lock:
            bucket = self._hits.setdefault(key, deque())
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            if len(bucket) >= limit:
                retry_after = max(1, int(window_seconds - (now - bucket[0])))
                return False, retry_after
            bucket.append(now)

            if now - self._last_prune > 600:
                self._prune(cutoff)
                self._last_prune = now
        return True, 0

    def _prune(self, cutoff: float) -> None:
        for key in [key for key, bucket in self._hits.items() if not bucket or bucket[-1] < cutoff]:
            self._hits.pop(key, None)


limiter = RateLimiter()
