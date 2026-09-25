async def test_get_messages_empty(auth_headers, salon_id):
    response = await auth_headers.get(f"/salons/{salon_id}/messages")
    assert response.status_code == 200
    body = response.json()
    assert body["messages"] == []
    assert body["has_more"] is False
    assert body["next_cursor"] is None


async def test_send_message_via_http(auth_headers, salon_id):
    response = await auth_headers.post(
        f"/salons/{salon_id}/messages",
        json={"ciphertext": "encrypted_content_base64", "iv": "initialization_vector_base64"},
    )
    assert response.status_code == 201
    data = response.json()
    assert data["ciphertext"] == "encrypted_content_base64"
    assert data["iv"] == "initialization_vector_base64"
    assert data["channel_id"] is None


async def test_get_messages_after_send(auth_headers, salon_id):
    for i in (1, 2):
        await auth_headers.post(
            f"/salons/{salon_id}/messages",
            json={"ciphertext": f"msg{i}", "iv": f"iv{i}"},
        )
    response = await auth_headers.get(f"/salons/{salon_id}/messages")
    assert response.status_code == 200
    assert len(response.json()["messages"]) == 2


async def test_messages_are_chronological(auth_headers, salon_id):
    for i in range(5):
        await auth_headers.post(
            f"/salons/{salon_id}/messages",
            json={"ciphertext": f"msg{i}", "iv": "iv"},
        )
    messages = (await auth_headers.get(f"/salons/{salon_id}/messages")).json()["messages"]
    assert [m["ciphertext"] for m in messages] == [f"msg{i}" for i in range(5)]


async def test_pagination_with_cursor(auth_headers, salon_id):
    for i in range(12):
        await auth_headers.post(
            f"/salons/{salon_id}/messages",
            json={"ciphertext": f"msg{i:02d}", "iv": "iv"},
        )

    first = (await auth_headers.get(f"/salons/{salon_id}/messages?limit=5")).json()
    assert len(first["messages"]) == 5
    assert first["has_more"] is True
    assert first["next_cursor"] is not None
    # La première page contient les messages les plus récents.
    assert [m["ciphertext"] for m in first["messages"]] == ["msg07", "msg08", "msg09", "msg10", "msg11"]

    second = (await auth_headers.get(f"/salons/{salon_id}/messages?limit=5&before={first['next_cursor']}")).json()
    assert [m["ciphertext"] for m in second["messages"]] == ["msg02", "msg03", "msg04", "msg05", "msg06"]

    third = (await auth_headers.get(f"/salons/{salon_id}/messages?limit=5&before={second['next_cursor']}")).json()
    assert [m["ciphertext"] for m in third["messages"]] == ["msg00", "msg01"]
    assert third["has_more"] is False


async def test_pagination_rejects_invalid_cursor(auth_headers, salon_id):
    response = await auth_headers.get(f"/salons/{salon_id}/messages?before=not-an-objectid")
    assert response.status_code == 400


async def test_pagination_limit_is_capped(auth_headers, salon_id):
    response = await auth_headers.get(f"/salons/{salon_id}/messages?limit=5000")
    assert response.status_code == 422


async def test_message_in_channel(auth_headers, salon_id):
    channels = (await auth_headers.get(f"/salons/{salon_id}/channels")).json()
    channel_id = channels[0]["id"]

    await auth_headers.post(
        f"/salons/{salon_id}/messages",
        json={"ciphertext": "in-channel", "iv": "iv", "channel_id": channel_id},
    )
    await auth_headers.post(
        f"/salons/{salon_id}/messages",
        json={"ciphertext": "no-channel", "iv": "iv"},
    )

    filtered = (await auth_headers.get(f"/salons/{salon_id}/messages?channel_id={channel_id}")).json()
    assert [m["ciphertext"] for m in filtered["messages"]] == ["in-channel"]


async def test_message_unknown_channel_rejected(auth_headers, salon_id):
    response = await auth_headers.post(
        f"/salons/{salon_id}/messages",
        json={"ciphertext": "x", "iv": "iv", "channel_id": "507f1f77bcf86cd799439011"},
    )
    assert response.status_code == 404


async def test_message_too_long_rejected(auth_headers, salon_id):
    response = await auth_headers.post(
        f"/salons/{salon_id}/messages",
        json={"ciphertext": "A" * 20000, "iv": "iv"},
    )
    assert response.status_code == 422


async def test_send_message_not_member(auth_headers, salon_id, csrf_client, second_user):
    csrf_client.headers["Authorization"] = f"Bearer {second_user['tokens']['access_token']}"
    response = await csrf_client.post(
        f"/salons/{salon_id}/messages",
        json={"ciphertext": "hacked", "iv": "iv"},
    )
    assert response.status_code == 403


async def test_messages_invalid_salon_id(auth_headers):
    response = await auth_headers.get("/salons/not-valid/messages")
    assert response.status_code == 400


async def test_messages_unknown_salon_is_forbidden(auth_headers):
    response = await auth_headers.get("/salons/507f1f77bcf86cd799439011/messages")
    assert response.status_code == 403
