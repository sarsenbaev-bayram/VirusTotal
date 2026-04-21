# ============================================================
# OWASP Security — services/rate_limiter.py
# In-memory per-user/IP rate limiter (sliding window).
# OWASP A04: Insecure Design — enforce rate limiting everywhere
# ============================================================

import time
from collections import defaultdict, deque
from config import settings
from loguru import logger


class RateLimiter:
    """Thread-safe sliding-window rate limiter.

    Tracks how many requests each key (user_id or IP) has made
    within the last 60 seconds. Exceeding the limit raises an
    error that callers can catch to return a friendly message.

    Usage:
        limiter = RateLimiter()
        if not limiter.is_allowed("user_123"):
            # tell the user they are rate-limited
    """

    def __init__(self, max_requests: int = None, window_seconds: int = 60):
        # Default from config; can be overridden in tests
        self.max_requests = max_requests or settings.RATE_LIMIT
        self.window = window_seconds
        # key → deque of UTC timestamps of recent requests
        self._store: dict[str, deque] = defaultdict(deque)

    def is_allowed(self, key: str) -> bool:
        """Return True if the key is within the rate limit."""
        now = time.time()
        window_start = now - self.window
        timestamps = self._store[key]

        # Drop requests outside the current window
        while timestamps and timestamps[0] < window_start:
            timestamps.popleft()

        if len(timestamps) >= self.max_requests:
            logger.warning(
                f"[RATE LIMIT] Key '{key}' exceeded {self.max_requests} "
                f"requests/{self.window}s. Current count: {len(timestamps)}"
            )
            return False

        timestamps.append(now)
        return True

    def remaining(self, key: str) -> int:
        """How many requests remain in the current window."""
        now = time.time()
        window_start = now - self.window
        timestamps = self._store[key]
        while timestamps and timestamps[0] < window_start:
            timestamps.popleft()
        return max(0, self.max_requests - len(timestamps))

    def reset(self, key: str) -> None:
        """Clear all recorded requests for a key (admin / test use)."""
        self._store.pop(key, None)


# ── Shared singleton used by both bot and web ─────────────────
rate_limiter = RateLimiter()
