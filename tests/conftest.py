import fakeredis
import pytest
from fastapi.testclient import TestClient

from app.config import get_settings
from app.db import get_redis
from app.main import create_app

VALID_PASSWORD = "correct-horse-battery"
VALID_USERNAME = "augustin"
OTHER_USERNAME = "invitee"


@pytest.fixture(autouse=True)
def _reset_settings() -> None:
    get_settings.cache_clear()


@pytest.fixture
def redis_client():
    client = fakeredis.FakeStrictRedis(decode_responses=True)
    yield client
    client.flushall()


@pytest.fixture
def client(app) -> TestClient:
    return TestClient(app)


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



@pytest.fixture
def app(redis_client):
    application = create_app()
    application.dependency_overrides[get_redis] = lambda: redis_client
    return application


@pytest.fixture
def new_client(app):
    """Usine a clients : un second client = un second compte, meme Redis."""

    def factory() -> TestClient:
        return TestClient(app)

    return factory


@pytest.fixture
def other_account(new_client) -> dict:
    """Compte secondaire, necessaire pour tester l'isolement entre membres."""
    client = new_client()
    response = client.post(
        "/auth/register",
        json={"username": OTHER_USERNAME, "password": VALID_PASSWORD},
        headers={"X-CSRF-Token": client.get("/auth/csrf").cookies.get("csrf_token") or ""},
    )
    assert response.status_code == 201, response.text
    return {
        "client": client,
        "headers": {"X-CSRF-Token": client.cookies.get("csrf_token") or ""},
        "user": response.json()["user"],
    }
