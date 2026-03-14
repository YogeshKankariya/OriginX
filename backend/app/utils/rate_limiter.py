from collections import deque
from dataclasses import dataclass
from threading import Lock
import time


@dataclass(frozen=True)
class RateLimitDecision:
    allowed: bool
    retry_after_seconds: int


class InMemoryRateLimiter:
    """Simple per-process sliding-window rate limiter."""

    def __init__(self) -> None:
        self._buckets: dict[str, deque[float]] = {}
        self._lock = Lock()

    def check(self, key: str, limit: int, window_seconds: int) -> RateLimitDecision:
        now = time.time()
        cutoff = now - max(1, window_seconds)

        with self._lock:
            bucket = self._buckets.setdefault(key, deque())
            while bucket and bucket[0] < cutoff:
                bucket.popleft()

            if len(bucket) >= max(1, limit):
                retry_after = int(max(1, window_seconds - (now - bucket[0])))
                return RateLimitDecision(allowed=False, retry_after_seconds=retry_after)

            bucket.append(now)
            return RateLimitDecision(allowed=True, retry_after_seconds=0)


def client_identifier(remote_host: str | None, x_forwarded_for: str | None) -> str:
    forwarded = (x_forwarded_for or "").split(",")[0].strip()
    if forwarded:
        return forwarded
    if remote_host:
        return remote_host
    return "unknown"


rate_limiter = InMemoryRateLimiter()
