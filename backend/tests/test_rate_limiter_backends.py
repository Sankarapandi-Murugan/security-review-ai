from security_review.api.rate_limiter import (
    InMemoryRateLimiterBackend,
    RedisRateLimiterBackend,
    _create_backend,
)


def test_create_backend_defaults_to_in_memory(monkeypatch):
    monkeypatch.delenv("REDIS_URL", raising=False)

    backend = _create_backend("ratelimit:test:")

    assert isinstance(backend, InMemoryRateLimiterBackend)


def test_create_backend_falls_back_to_in_memory_when_redis_unreachable(monkeypatch):
    monkeypatch.setenv("REDIS_URL", "redis://127.0.0.1:1/0")  # invalid port, unreachable

    backend = _create_backend("ratelimit:test:")

    assert isinstance(backend, InMemoryRateLimiterBackend)


def test_in_memory_backend_increments_and_resets():
    backend = InMemoryRateLimiterBackend()

    count1, _ = backend.increment("key-a", window_seconds=60)
    count2, _ = backend.increment("key-a", window_seconds=60)
    assert count1 == 1
    assert count2 == 2

    backend.reset()
    count_after_reset, _ = backend.increment("key-a", window_seconds=60)
    assert count_after_reset == 1


class _FakeRedisClient:
    def __init__(self) -> None:
        self._store: dict[str, int] = {}
        self._ttls: dict[str, int] = {}

    def incr(self, key: str) -> int:
        self._store[key] = self._store.get(key, 0) + 1
        return self._store[key]

    def expire(self, key: str, seconds: int) -> None:
        self._ttls[key] = seconds

    def ttl(self, key: str) -> int:
        return self._ttls.get(key, -1)

    def scan_iter(self, match: str):
        prefix = match.rstrip("*")
        return [key for key in self._store if key.startswith(prefix)]

    def delete(self, key: str) -> None:
        self._store.pop(key, None)
        self._ttls.pop(key, None)


def test_redis_backend_increments_and_sets_ttl_once():
    client = _FakeRedisClient()
    backend = RedisRateLimiterBackend(client, prefix="ratelimit:test:")

    count1, retry_after1 = backend.increment("1.2.3.4", window_seconds=60)
    count2, retry_after2 = backend.increment("1.2.3.4", window_seconds=60)

    assert count1 == 1
    assert count2 == 2
    assert retry_after1 == 60
    assert retry_after2 == 60


def test_redis_backend_reset_clears_prefixed_keys():
    client = _FakeRedisClient()
    backend = RedisRateLimiterBackend(client, prefix="ratelimit:test:")
    backend.increment("1.2.3.4", window_seconds=60)

    backend.reset()

    count, _ = backend.increment("1.2.3.4", window_seconds=60)
    assert count == 1
