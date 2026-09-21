"""Pagination de l'historique des messages (rétro-compatible).

Contrat v2 du GET ``/api/rooms/{id}/messages`` :
- ``?limit=<n>`` seul : les ``n`` derniers messages, triés croissants ;
- ``?before=<seq>&limit=<n>`` : page de ``n`` messages antérieurs (borne
  exclusive, sans doublon avec ``seq``), triés croissants ;
- ``?before=<seq>`` sans ``limit`` : défaut de 50 messages ;
- sans paramètres ou avec ``?after=`` : comportement v1 strictement inchangé
  (``after=0`` renvoie tout l'historique) ;
- validation : ``limit`` ∈ [0, 200] et ``before``/``after`` ≥ 0 (sinon 422).
"""

from __future__ import annotations

from tests.helpers.crypto_client import (
    create_room,
    encrypt_message,
    generate_room_key,
    get_history,
    post_message,
    register,
)


async def _post_n_messages(client, room_id: str, csrf_token: str, count: int) -> None:
    room_key = generate_room_key()
    for _ in range(count):
        nonce, ciphertext = encrypt_message(room_key, "message chiffré")
        await post_message(client, room_id, nonce, ciphertext, csrf_token)


async def test_limit_returns_last_n_messages_ascending(client) -> None:
    """``?limit=50`` sur 60 messages : exactement les 50 derniers (seq 11..60),
    rendus dans l'ordre croissant."""
    data = await register(client, "alice_pgl", "password123")
    room = await create_room(client, "pagination-limit", data["csrf_token"])
    await _post_n_messages(client, room["id"], data["csrf_token"], 60)

    response = await client.get(f"/api/rooms/{room['id']}/messages", params={"limit": 50})
    assert response.status_code == 200
    messages = response.json()["messages"]
    assert len(messages) == 50
    assert [item["seq"] for item in messages] == list(range(11, 61))


async def test_before_returns_previous_page_exclusive(client) -> None:
    """``?before=<seq du 40e>&limit=10`` : les 10 messages antérieurs (seq
    30..39), croissants et sans doublon avec le message de seq 40."""
    data = await register(client, "alice_pgb", "password123")
    room = await create_room(client, "pagination-before", data["csrf_token"])
    await _post_n_messages(client, room["id"], data["csrf_token"], 60)

    before = 40
    response = await client.get(
        f"/api/rooms/{room['id']}/messages", params={"before": before, "limit": 10}
    )
    assert response.status_code == 200
    messages = response.json()["messages"]
    assert len(messages) == 10
    seqs = [item["seq"] for item in messages]
    assert seqs == list(range(30, 40))
    assert before not in seqs


async def test_before_without_limit_defaults_to_50(client) -> None:
    """``?before=<seq>`` sans ``limit`` : page par défaut de 50 messages."""
    data = await register(client, "alice_pgd", "password123")
    room = await create_room(client, "pagination-default", data["csrf_token"])
    await _post_n_messages(client, room["id"], data["csrf_token"], 60)

    response = await client.get(f"/api/rooms/{room['id']}/messages", params={"before": 60})
    assert response.status_code == 200
    messages = response.json()["messages"]
    assert len(messages) == 50
    assert [item["seq"] for item in messages] == list(range(10, 60))


async def test_no_params_and_after_keep_v1_behavior(client) -> None:
    """Sans paramètres : tout l'historique ; ``?after=`` : polling v1 inchangé."""
    data = await register(client, "alice_pgv1", "password123")
    room = await create_room(client, "pagination-v1", data["csrf_token"])
    await _post_n_messages(client, room["id"], data["csrf_token"], 5)

    # Absence de paramètres → comportement v1 exact (tout l'historique).
    response = await client.get(f"/api/rooms/{room['id']}/messages")
    assert response.status_code == 200
    assert [item["seq"] for item in response.json()["messages"]] == [1, 2, 3, 4, 5]

    # ?after= continue de fonctionner.
    delta = await get_history(client, room["id"], after=3)
    assert [item["seq"] for item in delta] == [4, 5]
    assert [item["seq"] for item in (await get_history(client, room["id"], after=5))] == []


async def test_limit_validation_default_and_rejections(client) -> None:
    """``limit=0`` = défaut (tout) ; valeurs hors bornes → 422."""
    data = await register(client, "alice_pgval", "password123")
    room = await create_room(client, "pagination-val", data["csrf_token"])
    await _post_n_messages(client, room["id"], data["csrf_token"], 3)

    # limit=0 → défaut : tout l'historique.
    response = await client.get(f"/api/rooms/{room['id']}/messages", params={"limit": 0})
    assert response.status_code == 200
    assert [item["seq"] for item in response.json()["messages"]] == [1, 2, 3]

    # Bornes de validation : négatifs ou plafond dépassé rejetés en 422.
    negative = await client.get(f"/api/rooms/{room['id']}/messages", params={"limit": -1})
    assert negative.status_code == 422
    over = await client.get(f"/api/rooms/{room['id']}/messages", params={"limit": 201})
    assert over.status_code == 422
    negative_before = await client.get(f"/api/rooms/{room['id']}/messages", params={"before": -1})
    assert negative_before.status_code == 422
