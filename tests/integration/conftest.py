import pytest
from httpx import ASGITransport, AsyncClient

from app import ratelimit
from app.db import close_db, connect_db, get_db
from app.main import app


@pytest.fixture(autouse=True)
async def setup_db():
    await connect_db()
    db = get_db()
    await db.users.delete_many({})
    await db.refresh_tokens.delete_many({})
    await db.salons.delete_many({})
    await db.messages.delete_many({})
    await db.analytics.delete_many({})
    # Les compteurs sont en mémoire : sans remise à zéro, un test épuiserait
    # le quota des suivants.
    ratelimit.reset()
    yield
    await close_db()


@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    # `Origin` reproduit ce qu'un navigateur envoie sur toute mutation :
    # sans lui, la vérification d'origine rejetterait chaque requête.
    async with AsyncClient(
        transport=transport,
        base_url="http://test",
        headers={"origin": "http://test"},
    ) as ac:
        yield ac


@pytest.fixture
async def csrf_client(client):
    """Client with CSRF token set."""
    response = await client.get("/health")
    csrf_token = response.cookies.get("csrf_token")
    client.cookies.set("csrf_token", csrf_token)
    client.headers["x-csrf-token"] = csrf_token
    return client


@pytest.fixture
def sample_user():
    return {
        "username": "alice",
        "email": "alice@example.com",
        "password": "StrongP@ss1",
        "public_key": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n-----END PUBLIC KEY-----",
    }


@pytest.fixture
async def auth_headers(csrf_client, sample_user):
    """Register a user and return headers with auth + CSRF tokens."""
    await csrf_client.post("/auth/signup", json=sample_user)
    response = await csrf_client.post(
        "/auth/login",
        json={"username": sample_user["username"], "password": sample_user["password"]},
    )
    tokens = response.json()
    csrf_client.headers["Authorization"] = f"Bearer {tokens['access_token']}"
    return csrf_client


@pytest.fixture
async def salon_id(auth_headers):
    """Salon prêt à l'emploi, appartenant à l'utilisateur authentifié."""
    response = await auth_headers.post(
        "/salons",
        json={"name": "Test", "encrypted_salon_key": "key"},
    )
    return response.json()["id"]


@pytest.fixture
async def second_user(csrf_client):
    """Second compte (bob) pour les tests multi-utilisateurs."""
    payload = {
        "username": "bob",
        "email": "bob@example.com",
        "password": "StrongP@ss1",
        "public_key": "bob_key",
    }
    await csrf_client.post("/auth/signup", json=payload)
    response = await csrf_client.post(
        "/auth/login",
        json={"username": payload["username"], "password": payload["password"]},
    )
    return {"payload": payload, "tokens": response.json()}
