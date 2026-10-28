"""
In-memory rate limiter for login attempts.

For multi-worker deployments, replace with Redis-backed limiter.
"""
import time
import threading
import logging
from collections import defaultdict

logger = logging.getLogger(__name__)


class RateLimiter:
    def __init__(self):
        self._attempts = defaultdict(list)
        self._lockout_until = {}
        self._lock = threading.Lock()

    def _prune(self, key, window_seconds):
        cutoff = time.time() - window_seconds
        self._attempts[key] = [t for t in self._attempts[key] if t > cutoff]

    def is_locked(self, key):
        with self._lock:
            until = self._lockout_until.get(key)
            if not until:
                return False, 0
            remaining = int(until - time.time())
            if remaining <= 0:
                del self._lockout_until[key]
                return False, 0
            return True, remaining

    def record_attempt(self, key, window_seconds, max_attempts, lockout_seconds):
        with self._lock:
            self._prune(key, window_seconds)
            self._attempts[key].append(time.time())

            if len(self._attempts[key]) >= max_attempts:
                self._lockout_until[key] = time.time() + lockout_seconds
                self._attempts[key] = []
                logger.warning(f"Rate limit hit for {key}. Locked for {lockout_seconds}s.")
                return True, lockout_seconds

            return False, 0

    def reset(self, key):
        with self._lock:
            self._attempts.pop(key, None)
            self._lockout_until.pop(key, None)


login_limiter = RateLimiter()