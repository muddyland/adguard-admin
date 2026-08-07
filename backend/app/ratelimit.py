"""In-process sliding-window rate limiting for authentication endpoints.

The app already backs off carefully from AdGuard's own brute-force lockout but
had no protection of its own, so /api/auth/token could be hammered freely.

Scope: this is per-process state. It is sufficient for the single-worker
deployment the Dockerfile ships, and it degrades gracefully (each worker
enforces its own budget) if you scale out. If you run many workers, put a real
rate limiter in the reverse proxy in front of this app as well.
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict, deque


class RateLimiter:
    """Sliding-window limiter keyed by an arbitrary string.

    A key that exceeds `max_attempts` failures inside `window_seconds` is locked
    out for `lockout_seconds`. Only *failed* attempts are recorded, so an active
    user never rate-limits themselves.
    """

    def __init__(self, max_attempts: int, window_seconds: int, lockout_seconds: int) -> None:
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.lockout_seconds = lockout_seconds
        self._failures: dict[str, deque[float]] = defaultdict(deque)
        self._locked_until: dict[str, float] = {}
        self._lock = threading.Lock()

    def _now(self) -> float:
        return time.monotonic()

    def retry_after(self, key: str) -> int:
        """Seconds the caller must wait, or 0 if the key may proceed."""
        with self._lock:
            until = self._locked_until.get(key)
            if until is None:
                return 0
            remaining = until - self._now()
            if remaining <= 0:
                self._locked_until.pop(key, None)
                self._failures.pop(key, None)
                return 0
            # Round up so a caller who waits exactly this long is allowed through.
            return int(remaining) + 1

    def record_failure(self, key: str) -> None:
        with self._lock:
            now = self._now()
            attempts = self._failures[key]
            attempts.append(now)
            cutoff = now - self.window_seconds
            while attempts and attempts[0] < cutoff:
                attempts.popleft()
            if len(attempts) >= self.max_attempts:
                self._locked_until[key] = now + self.lockout_seconds
                attempts.clear()

    def record_success(self, key: str) -> None:
        with self._lock:
            self._failures.pop(key, None)
            self._locked_until.pop(key, None)

    def reset(self) -> None:
        """Drop all state (used by tests)."""
        with self._lock:
            self._failures.clear()
            self._locked_until.clear()
