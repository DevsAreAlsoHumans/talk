"""Tests du middleware CSRF via l'API (les mutations d'auth servent de cobaye).

Cas couverts : mutation sans token → 403 ; token invalide → 403 ; origine
étrangère → 403 ; ``/api/csrf`` exclu du contrôle de token mais pas de
l'origine ; nouvelle origine → nouvel échec ; les GET ne sont pas concernés.
"""

from __future__ import annotations

from tests.helpers.crypto_client import ORIGIN, default_public_key, fetch_csrf

_LOGIN_BODY = {"username": "qui-conque", "password": "motdepasse"}


async def test_mutation_without_token_forbidden(client) -> None:
    response = await client.post(
        "/api/auth/register",
        json={
            "username": "csrf_no_token",
            "password": "password123",
            "public_key": default_public_key(),
        },
        headers={"origin": ORIGIN},
    )
    assert response.status_code == 403
    assert response.json() == {"detail": "Requête refusée"}


async def test_mutation_with_invalid_token_forbidden(client) -> None:
    await fetch_csrf(client)  # pose le cookie ; on envoie un token erroné
    response = await client.post(
        "/api/auth/login",
        json=_LOGIN_BODY,
        headers={"x-csrf-token": "mauvais-token", "origin": ORIGIN},
    )
    assert response.status_code == 403


async def test_mutation_with_foreign_origin_forbidden(client) -> None:
    token = await fetch_csrf(client)
    response = await client.post(
        "/api/auth/login",
        json=_LOGIN_BODY,
        headers={"x-csrf-token": token, "origin": "https://evil.example"},
    )
    assert response.status_code == 403


async def test_mutation_with_referer_foreign_forbidden(client) -> None:
    token = await fetch_csrf(client)
    response = await client.post(
        "/api/auth/login",
        json=_LOGIN_BODY,
        headers={"x-csrf-token": token, "referer": "https://evil.example/page"},
    )
    assert response.status_code == 403


async def test_csrf_endpoint_origin_is_still_checked(client) -> None:
    """``/api/csrf`` n'exige pas de token mais son origine reste vérifiée."""
    response = await client.get("/api/csrf", headers={"origin": "https://evil.example"})
    assert response.status_code == 403


async def test_valid_token_and_origin_reaches_endpoint(client) -> None:
    token = await fetch_csrf(client)
    response = await client.post(
        "/api/auth/login",
        json=_LOGIN_BODY,
        headers={"x-csrf-token": token, "origin": ORIGIN},
    )
    # 401 du endpoint (identifiants inconnus) — et non 403 du middleware.
    assert response.status_code == 401


async def test_valid_token_without_origin_allowed(client) -> None:
    """Conforme au contrat : contrôle de l'origine « uniquement si présente »."""
    token = await fetch_csrf(client)
    response = await client.post(
        "/api/auth/login",
        json=_LOGIN_BODY,
        headers={"x-csrf-token": token},
    )
    assert response.status_code == 401


async def test_get_routes_not_concerned(client) -> None:
    """Les GET ne sont jamais soumis au token CSRF."""
    response = await client.get("/api/me")
    assert response.status_code == 401  # 401 authentification, jamais 403
    csrf_response = await client.get("/api/csrf")
    assert csrf_response.status_code == 200
