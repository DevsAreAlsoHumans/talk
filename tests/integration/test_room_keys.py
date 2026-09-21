"""Lecture des copies enveloppées de clés de salon (``GET /api/rooms/{id}/keys``).

Cet endpoint de lecture permet au frontend de restaurer sa clé de salon après
un rechargement de page (le navigateur a perdu sa copie en mémoire). L'appelant
ne reçoit QUE la copie chiffrée RSA-OAEP à son nom — jamais celle d'un autre
membre, jamais de clé en clair — et ``null`` tant qu'aucune copie n'a été posée
pour lui. Contrôle d'accès : 404 salon inconnu, 403 non-membre ; GET sans
effet de bord (pas de diffusion WebSocket, pas de CSRF).
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.repositories.rooms import list_wrapped_keys
from tests.helpers.crypto_client import (
    SyncBrowser,
    create_room,
    decrypt_message,
    register,
    unwrap_key,
    wrap_key,
)


def test_member_retrieves_his_own_wrapped_key(app: FastAPI, redis) -> None:
    """Un navigateur qui a créé le salon relit exactement la copie posée à son
    nom par ``create_room`` (via son POST interne ``/keys``) : même valeur que
    le stockage Redis, non nulle, et dé-enveloppable avec SA clé privée."""
    with TestClient(app) as alice_c:
        alice = SyncBrowser(alice_c, "alice_rk1", "password123")
        alice.register()
        room = alice.create_room("salle-rk1")
        room_id = room["id"]

        response = alice.client.get(f"/api/rooms/{room_id}/keys")
        assert response.status_code == 200
        data = response.json()
        assert set(data) == {"room_id", "wrapped_key"}
        assert data["room_id"] == room_id
        assert data["wrapped_key"] is not None

        stored = list_wrapped_keys(redis, room_id)
        assert data["wrapped_key"] == stored[alice.user_id]
        assert unwrap_key(alice.private_key, data["wrapped_key"]) == alice.room_keys[room_id]


def test_member_without_copy_gets_null_then_after_share(app: FastAPI) -> None:
    """Restauration de bout en bout : avant partage, la copie de Bob est
    ``null`` ; après que l'hôte a posé la wrapped_key, Bob la relit (même
    session), la dé-enveloppe avec SA clé privée et déchiffre un message
    qu'Alice a chiffré avec la clé de salon — preuve E2E de la restauration."""
    secret = "RESTAURE-MOI"
    with TestClient(app) as alice_c, TestClient(app) as bob_c:
        alice = SyncBrowser(alice_c, "alice_rk2", "password123")
        bob = SyncBrowser(bob_c, "bob_rk2", "password123")
        alice.register()
        bob.register()

        room = alice.create_room("salle-rk2")
        room_id = room["id"]
        room_key = alice.room_keys[room_id]
        bob.join_room(room_id)

        # Bob n'a pas encore de copie à son nom → wrapped_key null (200).
        missing = bob.client.get(f"/api/rooms/{room_id}/keys")
        assert missing.status_code == 200
        assert missing.json() == {"room_id": room_id, "wrapped_key": None}

        # Alice dépose la copie chiffrée pour la clé publique de Bob.
        alice.post_wrapped_key(room_id, bob.user_id, wrap_key(bob.public_key_b64, room_key))

        # Bob relit SA copie et la dé-enveloppe avec SA clé privée.
        recovered_response = bob.client.get(f"/api/rooms/{room_id}/keys")
        assert recovered_response.status_code == 200
        wrapped = recovered_response.json()["wrapped_key"]
        assert wrapped is not None
        recovered = unwrap_key(bob.private_key, wrapped)
        assert recovered == room_key

        # Alice publie un message ; Bob le déchiffre avec la clé restaurée.
        message = alice.post_message(room_id, secret)
        assert decrypt_message(recovered, message["nonce"], message["ciphertext"]) == secret


async def test_non_member_403(make_client, client) -> None:
    """Un tiers non membre du salon → 403 ; un id de salon inconnu → 404."""
    data = await register(client, "alice_rk3", "password123")
    room = await create_room(client, "salle-rk3", data["csrf_token"])
    room_id = room["id"]

    async with make_client() as eve:
        await register(eve, "eve_rk3", "password123")
        response = await eve.get(f"/api/rooms/{room_id}/keys")
        assert response.status_code == 403

    unknown = await client.get("/api/rooms/inconnue/keys")
    assert unknown.status_code == 404
