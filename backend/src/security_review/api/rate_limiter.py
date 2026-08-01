from __future__ import annotations

import logging
import os
import threading
import time
from abc import ABC, abstractmethod

from fastapi import HTTPException, Request, status

logger = logging.getLogger(__name__)


class RateLimiterBackend(ABC):
    """Pluggable fixed-window counter storage for rate limiting."""

    @abstractmethod
    def increment(self, key: str, window_seconds: int) -> tuple[int, int]:
        """Increment the counter for ``key`` in the current window.

        Returns ``(new_count, retry_after_seconds)``.
        """
        raise NotImplementedError

    @abstractmethod
    def reset(self) -> None:
        raise NotImplementedError


class InMemoryRateLimiterBackend(RateLimiterBackend):
    """Single-process, in-memory counter storage.

    State is not shared across multiple backend instances/processes — fine for a
    single-instance deployment or local dev, but for horizontally-scaled
    production deployments set ``REDIS_URL`` to use ``RedisRateLimiterBackend``
    instead, which shares counters across every instance.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._windows: dict[str, tuple[float, int]] = {}

    def increment(self, key: str, window_seconds: int) -> tuple[int, int]:
        now = time.monotonic()
        with self._lock:
            window_start, count = self._windows.get(key, (now, 0))
            if now - window_start >= window_seconds:
                window_start, count = now, 0
            count += 1
            self._windows[key] = (window_start, count)

        retry_after = max(1, int(window_seconds - (now - window_start)))
        return count, retry_after

    def reset(self) -> None:
        with self._lock:
            self._windows.clear()


class RedisRateLimiterBackend(RateLimiterBackend):
    """Shared counter storage backed by Redis (INCR + EXPIRE fixed-window pattern),
    so rate limits are enforced consistently across every backend instance in a
    multi-instance/horizontally-scaled production deployment.
    """

    def __init__(self, client, prefix: str) -> None:
        self._client = client
        self._prefix = prefix

    def increment(self, key: str, window_seconds: int) -> tuple[int, int]:
        full_key = f"{self._prefix}{key}"
        count = self._client.incr(full_key)
        if count == 1:
            self._client.expire(full_key, window_seconds)
        ttl = self._client.ttl(full_key)
        retry_after = ttl if ttl and ttl > 0 else window_seconds
        return int(count), int(retry_after)

    def reset(self) -> None:
        for redis_key in self._client.scan_iter(match=f"{self._prefix}*"):
            self._client.delete(redis_key)


def _create_backend(prefix: str) -> RateLimiterBackend:
    redis_url = os.getenv("REDIS_URL")
    if not redis_url:
        return InMemoryRateLimiterBackend()

    try:
        import redis

        client = redis.Redis.from_url(redis_url, decode_responses=True)
        client.ping()
        logger.info("Rate limiting backed by Redis (%s).", prefix)
        return RedisRateLimiterBackend(client, prefix)
    except ImportError:
        logger.warning(
            "REDIS_URL is set but the 'redis' package is not installed; falling "
            "back to in-memory rate limiting. Install it with `uv add redis`."
        )
    except Exception:
        logger.warning(
            "REDIS_URL is set but Redis is unreachable; falling back to "
            "in-memory rate limiting.",
            exc_info=True,
        )
    return InMemoryRateLimiterBackend()


class _FixedWindowRateLimiter:
    """Fixed-window rate limiter for basic brute-force mitigation. Delegates
    counter storage to a pluggable ``RateLimiterBackend`` (in-memory by default,
    Redis when ``REDIS_URL`` is configured).
    """

    def __init__(self, max_attempts: int, window_seconds: int, backend: RateLimiterBackend) -> None:
        self._max_attempts = max_attempts
        self._window_seconds = window_seconds
        self._backend = backend

    def check(self, key: str) -> None:
        count, retry_after = self._backend.increment(key, self._window_seconds)

        if count > self._max_attempts:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many authentication attempts. Please try again later.",
                headers={"Retry-After": str(retry_after)},
            )

    def reset(self) -> None:
        self._backend.reset()


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


_login_limiter = _FixedWindowRateLimiter(
    max_attempts=int(os.getenv("SECURITY_REVIEW_LOGIN_RATE_LIMIT", "10")),
    window_seconds=int(os.getenv("SECURITY_REVIEW_LOGIN_RATE_WINDOW_SECONDS", "60")),
    backend=_create_backend("ratelimit:login:"),
)
_signup_limiter = _FixedWindowRateLimiter(
    max_attempts=int(os.getenv("SECURITY_REVIEW_SIGNUP_RATE_LIMIT", "5")),
    window_seconds=int(os.getenv("SECURITY_REVIEW_SIGNUP_RATE_WINDOW_SECONDS", "60")),
    backend=_create_backend("ratelimit:signup:"),
)
_forgot_password_limiter = _FixedWindowRateLimiter(
    max_attempts=int(os.getenv("SECURITY_REVIEW_FORGOT_PASSWORD_RATE_LIMIT", "5")),
    window_seconds=int(os.getenv("SECURITY_REVIEW_FORGOT_PASSWORD_RATE_WINDOW_SECONDS", "60")),
    backend=_create_backend("ratelimit:forgot-password:"),
)


def enforce_login_rate_limit(request: Request) -> None:
    _login_limiter.check(_client_ip(request))


def enforce_signup_rate_limit(request: Request) -> None:
    _signup_limiter.check(_client_ip(request))


def enforce_forgot_password_rate_limit(request: Request) -> None:
    _forgot_password_limiter.check(_client_ip(request))


def reset_rate_limiters() -> None:
    """Clear all rate limiter state. Intended for test isolation only."""
    _login_limiter.reset()
    _signup_limiter.reset()
    _forgot_password_limiter.reset()


