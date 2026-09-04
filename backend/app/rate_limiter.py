"""Rate limiting.

A small token-bucket limiter (per IP + route) with a thread-safe in-memory
store.  High-throughput / multi-worker deployments should replace the store
with Redis, but the interface stays identical ((Route base keys stay stable).
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict
from typing import Callable, Optional

from fastapi import HTTPException, Request, Response, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

_TUPLE = tuple[int, float]


def parse_rate(spec: str) -> tuple[int, float]:
    """'30/minute' -> (30, 60.0)."""
    count_str, _, unit = spec.partition("/")
    count = int(count_str)
    unit = unit.lower()
    secs = {"second": 1.0, "minute": 60.0, "hour": 3600.0}.get(unit, 60.0)
    return count, secs


class TokenBucket:
    __slots__ = ("capacity", "refill_per_sec", "tokens", "last")

    def __init__(self, capacity: int, window_secs: float) -> None:
        self.capacity = capacity
        if window_secs <= 0 or capacity <= 0:
            self.refill_per_sec = 1.0
        else:
            self.refill_per_sec = capacity / window_secs
        self.tokens = float(capacity)
        self.last = time.monotonic()

    def take(self, n: int = 1) -> bool:
        now = time.monotonic()
        self.tokens = min(self.capacity, self.tokens + (now - self.last) * self.refill_per_sec)
        self.last = now
        if self.tokens >= n:
            self.tokens -= n
            return True
        return False


class RateLimiter:
    def __init__(self) -> None:
        self._buckets: dict[str, TokenBucket] = {}
        self._lock = threading.Lock()

    def allow(self, key: str, capacity: int, window_secs: float) -> bool:
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = TokenBucket(capacity, window_secs)
                self._buckets[key] = bucket
            return bucket.take()


_limiter = RateLimiter()


def rate_limit_key(request: Request, route: str) -> str:
    ip = request.client.host if request.client else "unknown"
    return f"{route}:{ip}"


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app: ASGIApp,
        *,
        enabled: bool = True,
        limits: Optional[dict[str, str]] = None,
        limiter: Optional[RateLimiter] = None,
    ) -> None:
        super().__init__(app)
        self.enabled = enabled
        self._limiter = limiter or _limiter
        self.limits = {
            "default": parse_rate("120/minute"),
            "analyze": parse_rate("30/minute"),
            "auth": parse_rate("10/minute"),
        }
        if limits:
            for k, v in limits.items():
                self.limits[k] = parse_rate(v)

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if not self.enabled:
            return await call_next(request)
        path = request.url.path
        route = "default"
        if path.startswith("/api/analyze"):
            route = "analyze"
        elif path.startswith("/api/auth/login"):
            route = "auth"
        capacity, window = self.limits.get(route, self.limits["default"])
        if not self._limiter.allow(rate_limit_key(request, route), capacity, window):
            return Response(
                content=b'{"detail":"rate limit exceeded. try again later."}',
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                headers={"content-type": "application/json",
                         "retry-after": "60"},
            )
        return await call_next(request)