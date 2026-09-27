import fakeredis
import pytest
from fastapi.testclient import TestClient

from app.config import get_settings
from app.db import get_redis
from app.main import create_app

VALID_PASSWORD = "correct-horse-battery"
VALID_USERNAME = "augustin"
OTHER_USERNAME = "invitee"

# Enveloppe factice : le serveur ne verifie que la forme, jamais le contenu.
IV = "AAAAAAAAAAAAAAAA"
CIPHERTEXT = "Y2lwaGVydGV4dC1maWtlLWNvbnRlbnU="


@pytest.fixture(autouse=True)
def _reset_settings() -> None:
    get_settings.cache_clear()


@pytest.fixture
def redis_client():
    client = fakeredis.FakeStrictRedis(decode_responses=True)
    yield client
    client.flushall()


@pytest.fixture
def app(redis_client):
    application = create_app()
    application.dependency_overrides[get_redis] = lambda: redis_client
    return application


@pytest.fixture
def client(app) -> TestClient:
    return TestClient(app)


@pytest.fixture
def new_client(app):
    """Usine a clients : un second client = un second compte, meme Redis."""

    def factory() -> TestClient:
        return TestClient(app)

    return factory


def _csrf(client: TestClient) -> dict[str, str]:
    client.get("/auth/csrf")
    return {"X-CSRF-Token": client.cookies.get("csrf_token") or ""}


@pytest.fixture
def csrf_headers(client: TestClient) -> dict[str, str]:
    return _csrf(client)


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
def other_account(new_client) -> dict:
    """Compte secondaire, necessaire pour tester l'isolement entre membres."""
    client = new_client()
    response = client.post(
        "/auth/register",
        json={"username": OTHER_USERNAME, "password": VALID_PASSWORD},
        headers=_csrf(client),
    )
    assert response.status_code == 201, response.text
    return {
        "client": client,
        "headers": {"X-CSRF-Token": client.cookies.get("csrf_token") or ""},
        "user": response.json()["user"],
    }


@pytest.fixture
def salon(client: TestClient, registered) -> dict:
    response = client.post("/salons", json={"name": "mon-salon"}, headers=registered)
    assert response.status_code == 201, response.text
    created = response.json()
    channels = client.get(f"/salons/{created['id']}/channels").json()
    return {"id": created["id"], "channel_id": channels[0]["id"]}


def envelope(ciphertext: str = CIPHERTEXT, iv: str = IV, key_version: int = 1) -> dict:
    return {"ciphertext": ciphertext, "iv": iv, "key_version": key_version}
