"""Édition et suppression de messages.

Le serveur ne lit pas les messages : éditer revient donc à remplacer une
enveloppe chiffrée par une autre, et supprimer à l'effacer réellement.
"""


async def _post(client, salon_id, text="msg"):
    response = await client.post(
        f"/salons/{salon_id}/messages",
        json={"ciphertext": text, "iv": "iv"},
    )
    return response.json()["id"]


# ---------- Édition ----------


async def test_author_can_edit_their_message(auth_headers, salon_id):
    message_id = await _post(auth_headers, salon_id, "avant")

    response = await auth_headers.patch(
        f"/salons/{salon_id}/messages/{message_id}",
        json={"ciphertext": "apres", "iv": "iv2"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["ciphertext"] == "apres"
    assert body["iv"] == "iv2"
    assert body["edited_at"] is not None


async def test_edit_is_visible_in_the_history(auth_headers, salon_id):
    message_id = await _post(auth_headers, salon_id, "avant")
    await auth_headers.patch(
        f"/salons/{salon_id}/messages/{message_id}",
        json={"ciphertext": "apres", "iv": "iv2"},
    )

    messages = (await auth_headers.get(f"/salons/{salon_id}/messages")).json()["messages"]
    assert messages[0]["ciphertext"] == "apres"
    assert messages[0]["edited_at"] is not None


async def test_a_fresh_message_is_not_marked_edited(auth_headers, salon_id):
    await _post(auth_headers, salon_id)
    messages = (await auth_headers.get(f"/salons/{salon_id}/messages")).json()["messages"]
    assert messages[0]["edited_at"] is None


async def test_others_cannot_edit_your_message(auth_headers, salon_id, csrf_client, second_user):
    message_id = await _post(auth_headers, salon_id)

    bob = (await auth_headers.get(f"/auth/users/{second_user['payload']['username']}/public-key")).json()
    await auth_headers.post(
        f"/salons/{salon_id}/members",
        json={"user_id": bob["id"], "encrypted_salon_key": "key-for-bob"},
    )

    csrf_client.headers["Authorization"] = f"Bearer {second_user['tokens']['access_token']}"
    response = await csrf_client.patch(
        f"/salons/{salon_id}/messages/{message_id}",
        json={"ciphertext": "pirate", "iv": "iv"},
    )
    assert response.status_code == 403


async def test_edit_unknown_message(auth_headers, salon_id):
    response = await auth_headers.patch(
        f"/salons/{salon_id}/messages/507f1f77bcf86cd799439011",
        json={"ciphertext": "x", "iv": "iv"},
    )
    assert response.status_code == 404


async def test_edit_invalid_message_id(auth_headers, salon_id):
    response = await auth_headers.patch(
        f"/salons/{salon_id}/messages/pas-un-id",
        json={"ciphertext": "x", "iv": "iv"},
    )
    assert response.status_code == 400


async def test_edit_respects_the_size_cap(auth_headers, salon_id):
    message_id = await _post(auth_headers, salon_id)
    response = await auth_headers.patch(
        f"/salons/{salon_id}/messages/{message_id}",
        json={"ciphertext": "A" * 20000, "iv": "iv"},
    )
    assert response.status_code == 422


async def test_non_member_cannot_edit(auth_headers, salon_id, csrf_client, second_user):
    message_id = await _post(auth_headers, salon_id)
    csrf_client.headers["Authorization"] = f"Bearer {second_user['tokens']['access_token']}"
    response = await csrf_client.patch(
        f"/salons/{salon_id}/messages/{message_id}",
        json={"ciphertext": "x", "iv": "iv"},
    )
    assert response.status_code == 403


# ---------- Suppression ----------


async def test_author_can_delete_their_message(auth_headers, salon_id):
    message_id = await _post(auth_headers, salon_id)
    response = await auth_headers.delete(f"/salons/{salon_id}/messages/{message_id}")
    assert response.status_code == 200


async def test_deletion_really_erases_the_ciphertext(auth_headers, salon_id):
    """Une suppression seulement visuelle n'en serait pas une : le texte
    chiffré doit disparaître de la base."""
    message_id = await _post(auth_headers, salon_id, "secret-chiffre")
    await auth_headers.delete(f"/salons/{salon_id}/messages/{message_id}")

    messages = (await auth_headers.get(f"/salons/{salon_id}/messages")).json()["messages"]
    assert messages[0]["deleted"] is True
    assert messages[0]["ciphertext"] == ""
    assert messages[0]["iv"] == ""


async def test_deleting_twice_is_rejected(auth_headers, salon_id):
    message_id = await _post(auth_headers, salon_id)
    await auth_headers.delete(f"/salons/{salon_id}/messages/{message_id}")
    response = await auth_headers.delete(f"/salons/{salon_id}/messages/{message_id}")
    assert response.status_code == 410


async def test_a_deleted_message_cannot_be_edited(auth_headers, salon_id):
    message_id = await _post(auth_headers, salon_id)
    await auth_headers.delete(f"/salons/{salon_id}/messages/{message_id}")
    response = await auth_headers.patch(
        f"/salons/{salon_id}/messages/{message_id}",
        json={"ciphertext": "x", "iv": "iv"},
    )
    assert response.status_code == 410


async def test_others_cannot_delete_your_message(auth_headers, salon_id, csrf_client, second_user):
    message_id = await _post(auth_headers, salon_id)

    bob = (await auth_headers.get(f"/auth/users/{second_user['payload']['username']}/public-key")).json()
    await auth_headers.post(
        f"/salons/{salon_id}/members",
        json={"user_id": bob["id"], "encrypted_salon_key": "key-for-bob"},
    )

    csrf_client.headers["Authorization"] = f"Bearer {second_user['tokens']['access_token']}"
    response = await csrf_client.delete(f"/salons/{salon_id}/messages/{message_id}")
    assert response.status_code == 403


async def test_delete_unknown_message(auth_headers, salon_id):
    response = await auth_headers.delete(f"/salons/{salon_id}/messages/507f1f77bcf86cd799439011")
    assert response.status_code == 404


async def test_edit_and_delete_need_the_origin_check(auth_headers, salon_id):
    """Ces mutations passent par le même garde-fou CSRF que les autres."""
    message_id = await _post(auth_headers, salon_id)

    response = await auth_headers.patch(
        f"/salons/{salon_id}/messages/{message_id}",
        json={"ciphertext": "x", "iv": "iv"},
        headers={"origin": "https://evil.example"},
    )
    assert response.status_code == 403

    response = await auth_headers.delete(
        f"/salons/{salon_id}/messages/{message_id}",
        headers={"origin": "https://evil.example"},
    )
    assert response.status_code == 403
