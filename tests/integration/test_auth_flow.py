async def test_signup_success(csrf_client, sample_user):
    response = await csrf_client.post("/auth/signup", json=sample_user)
    assert response.status_code == 201
    data = response.json()
    assert data["username"] == "alice"
    assert "id" in data


async def test_signup_duplicate_username(csrf_client, sample_user):
    await csrf_client.post("/auth/signup", json=sample_user)
    response = await csrf_client.post("/auth/signup", json=sample_user)
    assert response.status_code == 409


async def test_login_success(csrf_client, sample_user):
    await csrf_client.post("/auth/signup", json=sample_user)
    response = await csrf_client.post(
        "/auth/login",
        json={"username": "alice", "password": "StrongP@ss1"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data


async def test_login_wrong_password(csrf_client, sample_user):
    await csrf_client.post("/auth/signup", json=sample_user)
    response = await csrf_client.post(
        "/auth/login",
        json={"username": "alice", "password": "WrongPassword1"},
    )
    assert response.status_code == 401


async def test_me_with_valid_token(auth_headers):
    response = await auth_headers.get("/auth/me")
    assert response.status_code == 200
    assert response.json()["username"] == "alice"


async def test_me_without_token(csrf_client):
    response = await csrf_client.get("/auth/me")
    assert response.status_code == 401


async def test_logout(auth_headers):
    response = await auth_headers.post("/auth/logout")
    assert response.status_code == 200


async def test_refresh_token(csrf_client, sample_user):
    await csrf_client.post("/auth/signup", json=sample_user)
    login_resp = await csrf_client.post(
        "/auth/login",
        json={"username": "alice", "password": "StrongP@ss1"},
    )
    refresh_token = login_resp.json()["refresh_token"]
    response = await csrf_client.post("/auth/refresh", json={"refresh_token": refresh_token})
    assert response.status_code == 200
    assert "access_token" in response.json()


# ---------- Droit à l'effacement (RGPD art. 17) ----------


async def test_delete_account(auth_headers):
    response = await auth_headers.delete("/auth/me")
    assert response.status_code == 200

    # Le compte n'existe plus : le jeton ne vaut plus rien.
    assert (await auth_headers.get("/auth/me")).status_code == 401


async def test_deleted_account_cannot_log_in_again(auth_headers, csrf_client, sample_user):
    await auth_headers.delete("/auth/me")
    response = await csrf_client.post(
        "/auth/login",
        json={"username": sample_user["username"], "password": sample_user["password"]},
    )
    assert response.status_code == 401


async def test_delete_account_removes_messages_and_salons(auth_headers, salon_id):
    """L'effacement doit emporter les données associées, pas seulement le compte."""
    from app.db import get_db

    await auth_headers.post(f"/salons/{salon_id}/messages", json={"ciphertext": "x", "iv": "iv"})

    db = get_db()
    assert await db.messages.count_documents({}) == 1
    assert await db.salons.count_documents({}) == 1

    await auth_headers.delete("/auth/me")

    assert await db.users.count_documents({}) == 0
    assert await db.messages.count_documents({}) == 0
    assert await db.salons.count_documents({}) == 0
    assert await db.refresh_tokens.count_documents({}) == 0


async def test_delete_account_requires_authentication(csrf_client):
    assert (await csrf_client.delete("/auth/me")).status_code == 401


async def test_delete_account_leaves_other_accounts_intact(auth_headers, second_user):
    """Supprimer son compte ne doit pas toucher celui des autres."""
    from app.db import get_db

    await auth_headers.delete("/auth/me")
    db = get_db()
    remaining = await db.users.find({}).to_list(length=10)
    assert [u["username"] for u in remaining] == ["bob"]
