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
