import pytest

from security_review.api.rate_limiter import reset_rate_limiters


@pytest.fixture(autouse=True)
def _reset_auth_rate_limits():
    """Ensure each test starts with a clean rate-limiter state.

    TestClient requests all share the same client host ("testclient"), so without
    this reset, rate-limit assertions in one test could bleed into unrelated tests.
    """
    reset_rate_limiters()
    yield
