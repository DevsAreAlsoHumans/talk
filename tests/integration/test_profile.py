"""Profil public personnalisable (``display_name`` + ``about``).

Couvre le contrat ``PATCH /api/me`` :
- 200 : le profil est mis à jour et reflété partout via ``to_public`` /
  ``MemberPublic`` : ``/api/me``, ``/api/users/{username}`` et
  ``/api/rooms/{id}/members`` ;
- validation : > 32 / > 500 → 422, champ inconnu → 422, ``""`` → null,
  espaces supprimés (trim), champ omis → inchangé ;
- 401 non authentifié ;
- rétro-compatibilité : nouvelles inscriptions → ``display_name``/``about``
  à ``None`` (register, login, /api/me).

Ces champs sont de l'**identité publique** (comme le pseudo) : pas de
chiffrement E2E, contrairement aux messages.
"""

from __future__ import annotations

from tests.helpers.crypto_client import (
    create_room,
    csrf_headers,
    fetch_csrf,
    login,
    register,
)


async def test_update_own_profile(make_client, client) -> None:
    """PATCH /api/me → 200 ; /api/me, /users/{username} et /rooms/{id}/members
    reflètent ``display_name``/``about`` (salon à deux membres)."""
    data = await register(client, "alice_prof", "password123")
    token = data["csrf_token"]

    response = await client.patch(
        "/api/me",
        json={"display_name": "Alice Bot", "about": "Développeuse full-stack"},
        headers=csrf_headers(token),
    )
    assert response.status_code == 200
    user = response.json()["user"]
    assert user["id"] == data["user"]["id"]
    assert user["username"] == "alice_prof"
    assert user["display_name"] == "Alice Bot"
    assert user["about"] == "Développeuse full-stack"

    # /api/me reflète la mise à jour.
    me = (await client.get("/api/me")).json()
    assert me["user"]["display_name"] == "Alice Bot"
    assert me["user"]["about"] == "Développeuse full-stack"

    # GET /api/users/{username} → profil public avec les nouveaux champs.
    profile = (await client.get("/api/users/alice_prof")).json()
    assert profile["display_name"] == "Alice Bot"
    assert profile["about"] == "Développeuse full-stack"

    # Membre d'un salon à 2 membres : les exposer publiquement.
    room = await create_room(client, "salon-profil", token)
    async with make_client() as bob:
        bob_data = await register(bob, "bob_prof", "password123")
        joined = await bob.post(
            f"/api/rooms/{room['id']}/join", headers=csrf_headers(bob_data["csrf_token"])
        )
        assert joined.status_code == 200

        members = (await bob.get(f"/api/rooms/{room['id']}/members")).json()
        alice_member = next(m for m in members if m["username"] == "alice_prof")
        assert alice_member["display_name"] == "Alice Bot"
        assert alice_member["about"] == "Développeuse full-stack"
        bob_member = next(m for m in members if m["username"] == "bob_prof")
        assert bob_member["display_name"] is None
        assert bob_member["about"] is None


async def test_profile_validation(client) -> None:
    """422 pour longueur excessive ou champ inconnu ; ``""`` → null ; trim."""
    data = await register(client, "alice_val", "password123")
    headers = csrf_headers(data["csrf_token"])

    too_long_name = await client.patch("/api/me", json={"display_name": "x" * 33}, headers=headers)
    assert too_long_name.status_code == 422

    too_long_about = await client.patch("/api/me", json={"about": "y" * 501}, headers=headers)
    assert too_long_about.status_code == 422

    unknown = await client.patch(
        "/api/me", json={"display_name": "Alice", "email": "alice@example.com"}, headers=headers
    )
    assert unknown.status_code == 422

    # "" (ou uniquement des espaces) → champ effacé (null) ; trim sur le reste.
    blank = await client.patch(
        "/api/me", json={"display_name": "   ", "about": ""}, headers=headers
    )
    assert blank.status_code == 200
    assert blank.json()["user"]["display_name"] is None
    assert blank.json()["user"]["about"] is None

    trimmed = await client.patch("/api/me", json={"display_name": "  Alice  "}, headers=headers)
    assert trimmed.status_code == 200
    assert trimmed.json()["user"]["display_name"] == "Alice"
    # Champ omis → inchangé (about reste null, effacé ci-dessus).
    assert trimmed.json()["user"]["about"] is None


async def test_profile_requires_auth(client) -> None:
    """Sans session utilisateur, PATCH /api/me → 401."""
    csrf_token = await fetch_csrf(client)  # session anonyme, sans utilisateur
    response = await client.patch(
        "/api/me", json={"display_name": "Alice"}, headers=csrf_headers(csrf_token)
    )
    assert response.status_code == 401
    assert response.json() == {"detail": "Authentication required"}


async def test_register_login_include_profile_defaults(client) -> None:
    """Nouvelles inscriptions → ``display_name``/``about`` à ``None``
    (rétro-compatibilité : register, login et /api/me)."""
    data = await register(client, "alice_def", "password123")
    assert data["user"]["display_name"] is None
    assert data["user"]["about"] is None

    login_data = await login(client, "alice_def", "password123")
    assert login_data["user"]["display_name"] is None
    assert login_data["user"]["about"] is None

    me = (await client.get("/api/me")).json()
    assert me["user"]["display_name"] is None
    assert me["user"]["about"] is None
