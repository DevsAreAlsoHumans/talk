import time

import pytest
from fastapi import HTTPException

from app import ratelimit


@pytest.fixture(autouse=True)
def clean_buckets():
    ratelimit.reset()
    yield
    ratelimit.reset()


def test_allows_calls_under_the_limit():
    for _ in range(3):
        allowed, retry = ratelimit.hit("k", limit=3, window=60)
        assert allowed is True
        assert retry == 0


def test_blocks_the_call_over_the_limit():
    for _ in range(3):
        ratelimit.hit("k", limit=3, window=60)
    allowed, retry = ratelimit.hit("k", limit=3, window=60)
    assert allowed is False
    assert retry > 0


def test_keys_are_independent():
    for _ in range(3):
        ratelimit.hit("a", limit=3, window=60)
    allowed, _ = ratelimit.hit("b", limit=3, window=60)
    assert allowed is True


def test_window_slides():
    ratelimit.hit("k", limit=1, window=1)
    assert ratelimit.hit("k", limit=1, window=1)[0] is False
    time.sleep(1.05)
    assert ratelimit.hit("k", limit=1, window=1)[0] is True


def test_enforce_raises_429_with_retry_after():
    class FakeClient:
        host = "10.0.0.1"

    class FakeRequest:
        headers: dict = {}
        client = FakeClient()

    request = FakeRequest()
    ratelimit.enforce(request, "login", limit=1, window=60)

    with pytest.raises(HTTPException) as exc:
        ratelimit.enforce(request, "login", limit=1, window=60)

    assert exc.value.status_code == 429
    assert "Retry-After" in exc.value.headers


def test_enforce_separates_clients_by_ip():
    class Request:
        def __init__(self, ip):
            self.headers = {"x-forwarded-for": ip}
            self.client = None

    ratelimit.enforce(Request("1.1.1.1"), "login", limit=1, window=60)
    # Une autre IP conserve son propre quota.
    ratelimit.enforce(Request("2.2.2.2"), "login", limit=1, window=60)

    with pytest.raises(HTTPException):
        ratelimit.enforce(Request("1.1.1.1"), "login", limit=1, window=60)
