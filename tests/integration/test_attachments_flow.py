"""Messages vocaux : pièces jointes chiffrées.

Le serveur ne sait pas plus ce qu'il stocke ici que pour du texte : il reçoit
des octets chiffrés et un IV.
"""

import base64

from app.db import get_db

AUDIO = base64.b64encode(b"\x1aE\xdf\xa3 faux conteneur webm chiffre").decode()


def _payload(**overrides):
    data = {"kind": "audio", "ciphertext": AUDIO, "iv": "iv-audio", "duration_ms": 4200}
    data.update(overrides)
    return data


async def _upload(client, salon_id, **overrides):
    return await client.post(f"/salons/{salon_id}/attachments", json=_payload(**overrides))


# ---------- Dépôt ----------


async def test_upload_returns_metadata(auth_headers, salon_id):
    response = await _upload(auth_headers, salon_id)
    assert response.status_code == 201

    body = response.json()
    assert body["kind"] == "audio"
    assert body["duration_ms"] == 4200
    assert body["mime"] == "audio/webm"
    assert body["size"] > 0
    # Les métadonnées ne divulguent pas le contenu.
    assert "ciphertext" not in body


async def test_payload_is_stored_as_binary_not_base64(auth_headers, salon_id):
    """Stocker du binaire plutôt que du base64 économise un tiers de place."""
    await _upload(auth_headers, salon_id)
    doc = await get_db().attachments.find_one({})
    assert isinstance(bytes(doc["payload"]), bytes)
    assert len(bytes(doc["payload"])) < len(AUDIO)


async def test_invalid_base64_is_rejected(auth_headers, salon_id):
    response = await _upload(auth_headers, salon_id, ciphertext="!!!pas du base64!!!")
    assert response.status_code == 400


async def test_duration_is_capped(auth_headers, salon_id):
    response = await _upload(auth_headers, salon_id, duration_ms=999_999)
    assert response.status_code == 422


async def test_unknown_kind_is_rejected(auth_headers, salon_id):
    response = await _upload(auth_headers, salon_id, kind="video")
    assert response.status_code == 422


async def test_non_member_cannot_upload(auth_headers, salon_id, csrf_client, second_user):
    csrf_client.headers["Authorization"] = f"Bearer {second_user['tokens']['access_token']}"
    response = await _upload(csrf_client, salon_id)
    assert response.status_code == 403


# ---------- Téléchargement ----------


async def test_download_returns_the_ciphertext_unchanged(auth_headers, salon_id):
    attachment_id = (await _upload(auth_headers, salon_id)).json()["id"]

    response = await auth_headers.get(f"/salons/{salon_id}/attachments/{attachment_id}")
    assert response.status_code == 200
    body = response.json()
    assert body["ciphertext"] == AUDIO
    assert body["iv"] == "iv-audio"


async def test_download_unknown_attachment(auth_headers, salon_id):
    response = await auth_headers.get(f"/salons/{salon_id}/attachments/507f1f77bcf86cd799439011")
    assert response.status_code == 404


async def test_download_invalid_id(auth_headers, salon_id):
    response = await auth_headers.get(f"/salons/{salon_id}/attachments/pas-un-id")
    assert response.status_code == 404


async def test_non_member_cannot_download(auth_headers, salon_id, csrf_client, second_user):
    attachment_id = (await _upload(auth_headers, salon_id)).json()["id"]
    csrf_client.headers["Authorization"] = f"Bearer {second_user['tokens']['access_token']}"
    response = await csrf_client.get(f"/salons/{salon_id}/attachments/{attachment_id}")
    assert response.status_code == 403


async def test_member_can_download_someone_elses_voice_message(auth_headers, salon_id, csrf_client, second_user):
    attachment_id = (await _upload(auth_headers, salon_id)).json()["id"]
    bob = (await auth_headers.get("/auth/users/bob/public-key")).json()
    await auth_headers.post(
        f"/salons/{salon_id}/members",
        json={"user_id": bob["id"], "encrypted_salon_key": "key-for-bob"},
    )

    csrf_client.headers["Authorization"] = f"Bearer {second_user['tokens']['access_token']}"
    response = await csrf_client.get(f"/salons/{salon_id}/attachments/{attachment_id}")
    assert response.status_code == 200


# ---------- Rattachement à un message ----------


async def test_voice_message_needs_no_text(auth_headers, salon_id):
    """Un message vocal peut n'avoir aucun texte."""
    attachment_id = (await _upload(auth_headers, salon_id)).json()["id"]

    response = await auth_headers.post(
        f"/salons/{salon_id}/messages",
        json={"attachment_id": attachment_id},
    )
    assert response.status_code == 201
    assert response.json()["attachment"]["id"] == attachment_id


async def test_a_message_without_text_nor_attachment_is_rejected(auth_headers, salon_id):
    response = await auth_headers.post(f"/salons/{salon_id}/messages", json={})
    assert response.status_code == 422


async def test_attachment_appears_in_the_history(auth_headers, salon_id):
    attachment_id = (await _upload(auth_headers, salon_id)).json()["id"]
    await auth_headers.post(f"/salons/{salon_id}/messages", json={"attachment_id": attachment_id})

    messages = (await auth_headers.get(f"/salons/{salon_id}/messages")).json()["messages"]
    assert messages[0]["attachment"]["duration_ms"] == 4200


async def test_linking_removes_the_expiry(auth_headers, salon_id):
    """Une pièce jointe orpheline expire ; rattachée, elle est conservée."""
    attachment_id = (await _upload(auth_headers, salon_id)).json()["id"]

    before = await get_db().attachments.find_one({})
    assert before.get("expires_at") is not None

    await auth_headers.post(f"/salons/{salon_id}/messages", json={"attachment_id": attachment_id})

    after = await get_db().attachments.find_one({})
    assert after.get("expires_at") is None
    assert after.get("message_id") is not None


async def test_an_attachment_cannot_be_reused(auth_headers, salon_id):
    attachment_id = (await _upload(auth_headers, salon_id)).json()["id"]
    await auth_headers.post(f"/salons/{salon_id}/messages", json={"attachment_id": attachment_id})

    response = await auth_headers.post(
        f"/salons/{salon_id}/messages",
        json={"attachment_id": attachment_id},
    )
    assert response.status_code == 409


async def test_cannot_attach_someone_elses_upload(auth_headers, salon_id, csrf_client, second_user):
    attachment_id = (await _upload(auth_headers, salon_id)).json()["id"]

    bob = (await auth_headers.get("/auth/users/bob/public-key")).json()
    await auth_headers.post(
        f"/salons/{salon_id}/members",
        json={"user_id": bob["id"], "encrypted_salon_key": "key-for-bob"},
    )

    csrf_client.headers["Authorization"] = f"Bearer {second_user['tokens']['access_token']}"
    response = await csrf_client.post(
        f"/salons/{salon_id}/messages",
        json={"attachment_id": attachment_id},
    )
    assert response.status_code == 403


async def test_unknown_attachment_is_rejected(auth_headers, salon_id):
    response = await auth_headers.post(
        f"/salons/{salon_id}/messages",
        json={"attachment_id": "507f1f77bcf86cd799439011"},
    )
    assert response.status_code == 404


# ---------- Suppression ----------


async def test_deleting_the_message_erases_the_audio(auth_headers, salon_id):
    attachment_id = (await _upload(auth_headers, salon_id)).json()["id"]
    message_id = (
        await auth_headers.post(f"/salons/{salon_id}/messages", json={"attachment_id": attachment_id})
    ).json()["id"]

    await auth_headers.delete(f"/salons/{salon_id}/messages/{message_id}")

    # Le contenu vocal disparaît réellement, comme le texte chiffré.
    assert await get_db().attachments.count_documents({}) == 0
    messages = (await auth_headers.get(f"/salons/{salon_id}/messages")).json()["messages"]
    assert messages[0]["attachment"] is None


async def test_deleting_the_account_erases_the_audio(auth_headers, salon_id):
    await _upload(auth_headers, salon_id)
    assert await get_db().attachments.count_documents({}) == 1

    await auth_headers.delete("/auth/me")
    assert await get_db().attachments.count_documents({}) == 0


# ---------- Limites ----------


async def test_upload_flood_is_throttled(auth_headers, salon_id):
    from app import ratelimit
    from app.config import settings

    ratelimit.reset()
    for _ in range(settings.rate_limit_attachment):
        assert (await _upload(auth_headers, salon_id)).status_code == 201

    assert (await _upload(auth_headers, salon_id)).status_code == 429


async def test_upload_requires_the_origin_check(auth_headers, salon_id):
    response = await auth_headers.post(
        f"/salons/{salon_id}/attachments",
        json=_payload(),
        headers={"origin": "https://evil.example"},
    )
    assert response.status_code == 403
