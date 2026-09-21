"""Fixtures partagées.

Par défaut les tests utilisent `fakeredis` (aucune dépendance externe). Si la variable
``TEST_REDIS_URL`` est définie (CI, docker compose), les tests d'intégration tournent contre
un vrai Redis, vidé avant chaque test.
"""

import os
from collections.abc import Callable
from dataclasses import dataclass

import fakeredis
import pytest
import redis as sync_redis
from argon2 import PasswordHasher
from fakeredis import aioredis as fake_aioredis
from redis.asyncio import Redis
from starlette.testclient import TestClient

from app.config import Settings
from app.main import create_app
from app.security import passwords
from tests.helpers import e2e
from tests.helpers.actor import Actor

TEST_SECRET_KEY = "cle-de-test-uniquement-0123456789abcdef"


@pytest.fixture(autouse=True)
def fast_password_hasher(monkeypatch):
    """Argon2 avec des paramètres minimaux : les tests restent rapides (l'algorithme reste Argon2id)."""
    monkeypatch.setattr(passwords, "_hasher", PasswordHasher(time_cost=1, memory_cost=8, parallelism=1))


@pytest.fixture
def settings() -> Settings:
    return Settings(
        secret_key=TEST_SECRET_KEY,
        allowed_origins="http://testserver",
        cookie_secure=False,
        login_ip_limit=1000,
        login_account_limit=1000,
        register_limit=1000,
        message_limit=1000,
    )


@dataclass
class RedisBackend:
    async_factory: Callable[[], Redis]  # client utilisé par l'application
    inspector: sync_redis.Redis  # client synchrone sur la même base, pour inspecter ce qui est stocké


@pytest.fixture
def redis_backend() -> RedisBackend:
    url = os.environ.get("TEST_REDIS_URL")
    if url:
        inspector = sync_redis.Redis.from_url(url, decode_responses=True)
        inspector.flushdb()
        return RedisBackend(lambda: Redis.from_url(url, decode_responses=True), inspector)
    server = fakeredis.FakeServer()
    return RedisBackend(
        lambda: fake_aioredis.FakeRedis(server=server, decode_responses=True),
        fakeredis.FakeRedis(server=server, decode_responses=True),
    )


@pytest.fixture
def client(settings, redis_backend):
    app = create_app(settings, redis_factory=redis_backend.async_factory)
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def raw_redis(redis_backend):
    return redis_backend.inspector


@pytest.fixture
def make_user(client):
    """Fabrique un utilisateur inscrit et connecté."""

    def _make(username: str) -> Actor:
        identity = e2e.Identity.create(username)
        actor = Actor(client, identity)
        assert actor.register().status_code == 201
        assert actor.login().status_code == 200
        return actor

    return _make


@pytest.fixture
def alice(make_user) -> Actor:
    return make_user("alice")


@pytest.fixture
def bob(make_user) -> Actor:
    return make_user("bob")
