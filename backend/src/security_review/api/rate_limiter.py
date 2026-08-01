from __future__ import annotations

import os
import threading
import time

from fastapi import HTTPException, Request, status


class _FixedWindowRateLimiter:
    """In-memory fixed-window rate limiter for basic brute-force mitigation.

    This is single-process/in-memory only (state is not shared across multiple
    backend instances); for multi-instance deployments, back this with a shared
    store such as Redis instead.
    """

    def __init__(self, max_attempts: int, window_seconds: int) -> None:
        self._max_attempts = max_attempts
        self._window_seconds = window_seconds
        self._lock = threading.Lock()
        self._windows: dict[str, tuple[float, int]] = {}

    def check(self, key: str) -> None:
        now = time.monotonic()
        with self._lock:
            window_start, count = self._windows.get(key, (now, 0))
            if now - window_start >= self._window_seconds:
                window_start, count = now, 0
            count += 1
            self._windows[key] = (window_start, count)
            exceeded = count > self._max_attempts

        if exceeded:
            retry_after = max(1, int(self._window_seconds - (now - window_start)))
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many authentication attempts. Please try again later.",
                headers={"Retry-After": str(retry_after)},
            )

    def reset(self) -> None:
        with self._lock:
            self._windows.clear()


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


_login_limiter = _FixedWindowRateLimiter(
    max_attempts=int(os.getenv("SECURITY_REVIEW_LOGIN_RATE_LIMIT", "10")),
    window_seconds=int(os.getenv("SECURITY_REVIEW_LOGIN_RATE_WINDOW_SECONDS", "60")),
)
_signup_limiter = _FixedWindowRateLimiter(
    max_attempts=int(os.getenv("SECURITY_REVIEW_SIGNUP_RATE_LIMIT", "5")),
    window_seconds=int(os.getenv("SECURITY_REVIEW_SIGNUP_RATE_WINDOW_SECONDS", "60")),
)


def enforce_login_rate_limit(request: Request) -> None:
    _login_limiter.check(_client_ip(request))


def enforce_signup_rate_limit(request: Request) -> None:
    _signup_limiter.check(_client_ip(request))


def reset_rate_limiters() -> None:
    """Clear all rate limiter state. Intended for test isolation only."""
    _login_limiter.reset()
    _signup_limiter.reset()
