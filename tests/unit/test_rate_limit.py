import asyncio

import fakeredis

from app.config import Settings
from app.security.rate_limit import is_rate_limited, reset


def _run(coro_factory):
    async def runner():
        redis = fakeredis.FakeAsyncRedis(server=fakeredis.FakeServer(), decode_responses=True)
        try:
            return await coro_factory(redis)
        finally:
            await redis.aclose()

    return asyncio.run(runner())


def test_limit_is_enforced_then_reset():
    async def scenario(redis):
        results = [await is_rate_limited(redis, "k", limit=3, window_seconds=60) for _ in range(5)]
        await reset(redis, "k")
        after_reset = await is_rate_limited(redis, "k", limit=3, window_seconds=60)
        return results, after_reset

    results, after_reset = _run(scenario)
    assert results == [False, False, False, True, True]
    assert after_reset is False


def test_counter_always_has_a_ttl_and_keys_are_independent():
    async def scenario(redis):
        await is_rate_limited(redis, "a", limit=1, window_seconds=60)
        await is_rate_limited(redis, "a", limit=1, window_seconds=60)
        return await redis.ttl("a"), await is_rate_limited(redis, "b", limit=1, window_seconds=60)

    ttl, other_key_limited = _run(scenario)
    assert 0 < ttl <= 60
    assert other_key_limited is False


def test_settings_reject_a_short_secret_key():
    import pytest

    with pytest.raises(ValueError, match="SECRET_KEY"):
        Settings(secret_key="trop-court")


def test_settings_generate_an_ephemeral_key_when_missing():
    settings = Settings(secret_key="")
    assert len(settings.secret_key) >= 32


def test_cookie_names_use_host_prefix_only_when_secure():
    assert Settings(secret_key="", cookie_secure=True).session_cookie_name.startswith("__Host-")
    assert not Settings(secret_key="", cookie_secure=False).session_cookie_name.startswith("__Host-")
