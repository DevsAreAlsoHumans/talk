import fakeredis
import pytest
from fastapi.testclient import TestClient

from app.config import get_settings
from app.db import get_redis
from app.main import create_app

VALID_PASSWORD = "correct-horse-battery"
VALID_USERNAME = "augustin"


@pytest.fixture(autouse=True)
def _reset_settings() -> None:
    get_settings.cache_clear()


@pytest.fixture
def redis_client():
    client = fakeredis.FakeStrictRedis(decode_responses=True)
    yield client
    client.flushall()


@pytest.fixture
def client(redis_client) -> TestClient:
    app = create_app()
    app.dependency_overrides[get_redis] = lambda: redis_client
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def csrf_headers(client: TestClient) -> dict[str, str]:
    client.get("/auth/csrf")
    return {"X-CSRF-Token": client.cookies.get("csrf_token") or ""}


@pytest.fixture
def registered(client: TestClient, csrf_headers) -> dict[str, str]:
    response = client.post(
        "/auth/register",
        json={"username": VALID_USERNAME, "password": VALID_PASSWORD},
        headers=csrf_headers,
    )
    assert response.status_code == 201, response.text
    return {"X-CSRF-Token": client.cookies.get("csrf_token") or ""}
