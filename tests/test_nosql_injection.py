"""Le validateur d'entrée doit rejeter les opérateurs NoSQL avant MongoDB."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.config import get_settings
from tests.conftest import VALID_PASSWORD, csrf_headers, sync_database, unique_username

OPERATOR_PAYLOADS = [
    {"$ne": None},
    {"$gt": ""},
    {"$regex": ".*"},
    {"$exists": True},
]


def _register(client: TestClient, username: object) -> object:
    return client.post(
        "/auth/register",
        json={"username": username, "password": VALID_PASSWORD},
        headers=csrf_headers(client),
    )


def test_register_rejects_operator_as_username(client: TestClient) -> None:
    for payload in OPERATOR_PAYLOADS:
        response = _register(client, payload)
        assert response.status_code == 422, payload


def test_login_rejects_operator_as_username(client: TestClient) -> None:
    client.get("/auth/csrf")

    for payload in OPERATOR_PAYLOADS:
        response = client.post(
            "/auth/login",
            json={"username": payload, "password": VALID_PASSWORD},
            headers=csrf_headers(client),
        )
        assert response.status_code == 422, payload


def test_register_rejects_operator_as_password(client: TestClient) -> None:
    response = client.post(
        "/auth/register",
        json={"username": unique_username(), "password": {"$ne": None}},
        headers=csrf_headers(client),
    )

    assert response.status_code == 422


def test_injected_operator_cannot_bypass_authentication(client: TestClient) -> None:
    """`{"$ne": null}` ne doit pas se comporter comme « n'importe quel compte »."""
    client.get("/auth/csrf")

    response = client.post(
        "/auth/login",
        json={"username": {"$ne": None}, "password": {"$ne": None}},
        headers=csrf_headers(client),
    )

    assert response.status_code == 422
    assert client.get("/auth/me").status_code == 401


def test_dollar_where_field_is_rejected(client: TestClient) -> None:
    response = client.post(
        "/auth/register",
        json={
            "username": unique_username(),
            "password": VALID_PASSWORD,
            "$where": "this.password.length > 0",
        },
        headers=csrf_headers(client),
    )

    assert response.status_code == 422


def test_injection_attempt_leaks_no_server_internals(client: TestClient) -> None:
    """Un refus ne doit rien divulguer de l'implémentation.

    FastAPI récapitule la valeur fautive dans son erreur de validation : c'est
    l'echo de ce que l'appelant a lui-même envoyé, ce qui ne révèle rien. Ce
    qui doit être vérifié ici, c'est l'absence de fuite côté serveur.
    """
    response = _register(client, {"$ne": None})

    assert response.status_code == 422
    assert "Traceback" not in response.text
    assert "pymongo" not in response.text.lower()
    assert "talk_test" not in response.text
    assert "password_hash" not in response.text


def test_rejected_injection_writes_nothing_to_the_database(client: TestClient) -> None:
    client.get("/auth/csrf")

    response = _register(client, {"$ne": None})

    mongo = sync_database()
    try:
        database = mongo[get_settings().mongo_db_name]
        assert database.users.count_documents({}) == 0
    finally:
        mongo.close()
    assert response.status_code == 422
