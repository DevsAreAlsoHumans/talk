"""Changement de mot de passe : 204 + hash mis à jour, ancien mot de passe
refusé au login, 403 si l'ancien mot de passe est faux, 422 si le nouveau
est trop court, 401 sans session. Le changement n'invalide PAS la session
courante ni les sessions existantes (décision assumée).
"""

from __future__ import annotations

import json

from tests.helpers.crypto_client import csrf_headers, fetch_csrf, login, register

OLD_PASSWORD = "password123"
NEW_PASSWORD = "New-S3cure-Pass!"


def _stored_user(redis, user_id: str) -> dict:
    """Enregistrement Redis ``user:{id}`` (JSON) tel que stocké côté serveur."""
    raw = redis.get(f"user:{user_id}")
    assert raw is not None, "user record missing in Redis"
    return json.loads(raw)


async def _change_password(client, old_password: str, new_password: str):
    """POST /api/auth/change-password (mutation : token CSRF + Origin)."""
    csrf_token = await fetch_csrf(client)
    return await client.post(
        "/api/auth/change-password",
        json={"old_password": old_password, "new_password": new_password},
        headers=csrf_headers(csrf_token),
    )


async def test_change_password_updates_stored_hash_and_keeps_session(redis, client) -> None:
    data = await register(client, "alice_cp", OLD_PASSWORD)
    user_id = data["user"]["id"]
    old_hash = _stored_user(redis, user_id)["password_hash"]

    response = await _change_password(client, OLD_PASSWORD, NEW_PASSWORD)
    assert response.status_code == 204

    new_hash = _stored_user(redis, user_id)["password_hash"]
    assert new_hash != old_hash
    assert new_hash != OLD_PASSWORD and new_hash != NEW_PASSWORD  # jamais en clair

    # Décision assumée : la session courante reste valide après le changement.
    assert (await client.get("/api/me")).status_code == 200


async def test_old_password_rejected_and_new_accepted_after_change(make_client, client) -> None:
    await register(client, "alice_cp2", OLD_PASSWORD)
    response = await _change_password(client, OLD_PASSWORD, NEW_PASSWORD)
    assert response.status_code == 204

    # Nouvel « appareil » (cookie jar vierge) : l'ancien mot de passe échoue…
    async with make_client() as fresh_client:
        csrf_token = await fetch_csrf(fresh_client)
        old_login = await fresh_client.post(
            "/api/auth/login",
            json={"username": "alice_cp2", "password": OLD_PASSWORD},
            headers=csrf_headers(csrf_token),
        )
        assert old_login.status_code == 401
        assert old_login.json() == {"detail": "Invalid credentials"}

        # … et le nouveau permet la connexion (login + rotation de session).
        await login(fresh_client, "alice_cp2", NEW_PASSWORD)
        assert (await fresh_client.get("/api/me")).status_code == 200


async def test_wrong_old_password_returns_403_without_touching_hash(redis, client) -> None:
    data = await register(client, "alice_cp3", OLD_PASSWORD)
    user_id = data["user"]["id"]
    before = _stored_user(redis, user_id)["password_hash"]

    response = await _change_password(client, "incorrect", NEW_PASSWORD)
    assert response.status_code == 403
    assert response.json() == {"detail": "Incorrect current password"}
    assert _stored_user(redis, user_id)["password_hash"] == before


async def test_new_password_too_short_returns_422(client) -> None:
    await register(client, "alice_cp4", OLD_PASSWORD)
    response = await _change_password(client, OLD_PASSWORD, "short")
    assert response.status_code == 422


async def test_change_password_requires_authenticated_session(client) -> None:
    csrf_token = await fetch_csrf(client)  # session anonyme, pas d'utilisateur
    response = await client.post(
        "/api/auth/change-password",
        json={"old_password": OLD_PASSWORD, "new_password": NEW_PASSWORD},
        headers=csrf_headers(csrf_token),
    )
    assert response.status_code == 401
    assert response.json() == {"detail": "Authentication required"}
