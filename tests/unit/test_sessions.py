import asyncio

import fakeredis

from app.security.sessions import SessionStore, hash_session_id


def _run(coro_factory):
    async def runner():
        redis = fakeredis.FakeAsyncRedis(server=fakeredis.FakeServer(), decode_responses=True)
        try:
            return await coro_factory(redis)
        finally:
            await redis.aclose()

    return asyncio.run(runner())


def test_session_ttl_is_moved_forward_on_every_use():
    async def scenario(redis):
        store = SessionStore(redis, ttl_seconds=100)
        session_id = await store.create("user-1")
        key = f"session:{hash_session_id(session_id)}"
        ttl_after_create = await redis.ttl(key)
        # La session a vieilli (elle ne lui restait que 3 secondes)…
        await redis.expire(key, 3)
        user_id = await store.get_user_id(session_id)
        ttl_after_use = await redis.ttl(key)
        return user_id, ttl_after_create, ttl_after_use

    user_id, ttl_after_create, ttl_after_use = _run(scenario)
    assert ttl_after_create == 100
    assert user_id == "user-1"
    # …un simple appel a repoussé l'échéance : aucune déconnexion pendant l'utilisation.
    assert ttl_after_use > 50


def test_unknown_or_invalid_session_returns_none_without_error():
    async def scenario(redis):
        store = SessionStore(redis, ttl_seconds=100)
        missing = await store.get_user_id("inconnu")
        too_long = await store.get_user_id("x" * 129)
        empty = await store.get_user_id(None)
        return missing, too_long, empty

    missing, too_long, empty = _run(scenario)
    assert missing is None
    assert too_long is None
    assert empty is None
