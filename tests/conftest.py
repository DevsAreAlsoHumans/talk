"""Fixtures pytest partagées : app (fakeredis), clients HTTP/WS, accès Redis.

``create_app()`` pose ``app.state.redis`` depuis ``settings.REDIS_URL`` ; on le
remplace ici par un client ``fakeredis.FakeRedis(decode_responses=True)``.
La dépendance ``get_redis()`` ainsi que le middleware CSRF lisent tous deux
``request.app.state.redis`` (voir ``app/db/redis.py``) : aucun Redis externe
n'est donc nécessaire.
"""

from __future__ import annotations

import fakeredis
import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.main import create_app

#: Base URL des clients de test (doit correspondre à l'Origin attendue par CSRF).
BASE_URL = "http://testserver"


@pytest.fixture
def app() -> FastAPI:
    """Application FastAPI complète, Redis réel remplacé par fakeredis (par test)."""
    application = create_app()
    application.state.redis = fakeredis.FakeRedis(decode_responses=True)
    return application


@pytest.fixture
def redis(app: FastAPI):
    """Client fakeredis de l'application (assertions de stockage directement)."""
    return app.state.redis


@pytest.fixture
def make_client(app: FastAPI):
    """Fabrique des clients httpx isolés : un cookie jar par « utilisateur »."""

    def _factory() -> httpx.AsyncClient:
        transport = httpx.ASGITransport(app=app)
        return httpx.AsyncClient(transport=transport, base_url=BASE_URL)

    return _factory


@pytest.fixture
async def client(make_client) -> httpx.AsyncClient:
    """Client httpx par défaut pour les tests REST."""
    async with make_client() as async_client:
        yield async_client


@pytest.fixture
def testclient(app: FastAPI) -> TestClient:
    """Client TestClient (Starlette) : REST + WebSocket (httpx ne gère pas le WS)."""
    with TestClient(app) as sync_client:
        yield sync_client
