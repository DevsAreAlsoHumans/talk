import os
import time
from uuid import uuid4

import pytest
from conftest import identity_payload
from redis.asyncio import Redis

from app.storage import RedisStore


@pytest.mark.asyncio
async def test_real_redis_scripts_and_sorted_username_index():
    redis_host = os.getenv("REDIS_TEST_HOST")
    if not redis_host:
        pytest.skip("REDIS_TEST_HOST n'est pas configurée")
    redis = Redis(
        host=redis_host,
        port=int(os.getenv("REDIS_TEST_PORT", "6379")),
        db=int(os.getenv("REDIS_TEST_DB", "15")),
        username=os.getenv("REDIS_TEST_USERNAME") or None,
        password=os.getenv("REDIS_TEST_PASSWORD") or None,
        decode_responses=True,
    )
    await redis.flushdb()
    store = RedisStore(redis)
    identity = identity_payload()
    user = await store.register_user(
        username="alice",
        display_name="Alice",
        password_hash="$argon2id$test",
        identity_key=identity,
    )
    try:
        assert await redis.type("talk:usernames:v2") == "zset"
        assert [item["username"] for item in await store.search_users("ali")] == ["alice"]

        envelope = {
            "recipient_id": user["id"],
            "key_id": identity["key_id"],
            "algorithm": "RSA-OAEP-256",
            "wrapped_key": "A" * 512,
            "key_version": 1,
        }
        room, channel = await store.create_room(
            name="Projet",
            owner_id=user["id"],
            member_ids=[user["id"]],
            key_envelopes=[envelope],
            channel_name="général",
        )
        created, sequence = await store.save_message(
            {
                "client_id": str(uuid4()),
                "sender_id": user["id"],
                "room_id": room["id"],
                "channel_id": channel["id"],
                "algorithm": "AES-GCM-256",
                "key_version": 1,
                "ciphertext": "Y" * 64,
                "nonce": "A" * 16,
                "created_at": int(time.time() * 1000),
            },
            expected_version=1,
        )
        assert created is True
        assert sequence == 1
    finally:
        await redis.flushdb()
        await redis.aclose()
