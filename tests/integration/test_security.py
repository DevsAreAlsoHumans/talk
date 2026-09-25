async def test_csrf_blocks_post_without_token(client):
    """POST without CSRF token should be rejected."""
    response = await client.post(
        "/auth/signup",
        json={
            "username": "alice",
            "email": "alice@example.com",
            "password": "StrongP@ss1",
            "public_key": "-----BEGIN PUBLIC KEY-----\nKEY\n-----END PUBLIC KEY-----",
        },
    )
    assert response.status_code == 403
    assert "CSRF" in response.json()["detail"]


async def test_nosql_injection_login(csrf_client):
    """NoSQL injection attempt in login should fail cleanly."""
    response = await csrf_client.post(
        "/auth/login",
        json={
            "username": {"$gt": ""},
            "password": {"$gt": ""},
        },
    )
    # Pydantic should reject non-string fields -> 422
    assert response.status_code == 422


async def test_nosql_injection_signup(csrf_client):
    """NoSQL injection in signup fields should be rejected by validation."""
    response = await csrf_client.post(
        "/auth/signup",
        json={
            "username": {"$gt": ""},
            "email": "a@b.com",
            "password": "StrongP@ss1",
            "public_key": "key",
        },
    )
    assert response.status_code == 422


async def test_expired_token_rejected(csrf_client, sample_user):
    """Manually crafted expired token should be rejected."""
    from datetime import timedelta

    from app.auth.service import create_access_token

    token = create_access_token({"sub": "fakeid"}, expires_delta=timedelta(seconds=-10))
    csrf_client.headers["Authorization"] = f"Bearer {token}"
    response = await csrf_client.get("/auth/me")
    assert response.status_code == 401


async def test_invalid_token_rejected(csrf_client):
    """Random string as token should be rejected."""
    csrf_client.headers["Authorization"] = "Bearer totally.invalid.token"
    response = await csrf_client.get("/auth/me")
    assert response.status_code == 401


async def test_security_headers_present(client):
    """Security headers should be set on every response."""
    response = await client.get("/health")
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("X-Frame-Options") == "DENY"


async def test_get_requests_skip_csrf(client):
    """GET requests should not require CSRF token."""
    response = await client.get("/health")
    assert response.status_code == 200


# ---------- Vérification d'origine ----------


async def test_foreign_origin_is_rejected(csrf_client, sample_user):
    """Le scénario CSRF classique : une page tierce poste vers notre API."""
    response = await csrf_client.post(
        "/auth/signup",
        json=sample_user,
        headers={"origin": "https://evil.example"},
    )
    assert response.status_code == 403
    assert "Origine" in response.json()["detail"]


async def test_lookalike_domain_is_rejected(csrf_client, sample_user):
    response = await csrf_client.post(
        "/auth/signup",
        json=sample_user,
        headers={"origin": "http://test.evil.example"},
    )
    assert response.status_code == 403


async def test_missing_origin_and_referer_is_rejected(csrf_client, sample_user):
    """Recommandation OWASP : en l'absence des deux en-têtes, on bloque."""
    del csrf_client.headers["origin"]
    response = await csrf_client.post("/auth/signup", json=sample_user)
    assert response.status_code == 403
    assert "Origine" in response.json()["detail"]


async def test_referer_is_accepted_when_origin_absent(csrf_client, sample_user):
    """Repli sur Referer pour les navigateurs qui n'envoient pas Origin."""
    del csrf_client.headers["origin"]
    csrf_client.headers["referer"] = "http://test/app.html"
    response = await csrf_client.post("/auth/signup", json=sample_user)
    assert response.status_code == 201


async def test_foreign_referer_is_rejected(csrf_client, sample_user):
    del csrf_client.headers["origin"]
    csrf_client.headers["referer"] = "https://evil.example/piege.html"
    response = await csrf_client.post("/auth/signup", json=sample_user)
    assert response.status_code == 403


async def test_null_origin_is_rejected(csrf_client, sample_user):
    """`Origin: null` provient d'une iframe cloisonnée ou d'un fichier local."""
    response = await csrf_client.post(
        "/auth/signup",
        json=sample_user,
        headers={"origin": "null"},
    )
    assert response.status_code == 403


async def test_origin_is_checked_before_the_csrf_token(client, sample_user):
    """Une requête tierce est écartée sans même examiner le jeton."""
    response = await client.post(
        "/auth/signup",
        json=sample_user,
        headers={"origin": "https://evil.example"},
    )
    assert response.status_code == 403
    assert "Origine" in response.json()["detail"]


async def test_safe_methods_ignore_origin(client):
    """Une lecture depuis une autre origine ne modifie rien : pas de blocage."""
    response = await client.get("/health", headers={"origin": "https://evil.example"})
    assert response.status_code == 200


async def test_origin_check_applies_to_every_mutation(auth_headers, salon_id):
    """La vérification couvre toutes les mutations, pas seulement l'authentification."""
    response = await auth_headers.post(
        f"/salons/{salon_id}/messages",
        json={"ciphertext": "x", "iv": "iv"},
        headers={"origin": "https://evil.example"},
    )
    assert response.status_code == 403

    response = await auth_headers.request(
        "DELETE",
        f"/salons/{salon_id}/members/507f1f77bcf86cd799439011",
        json={"rekey": []},
        headers={"origin": "https://evil.example"},
    )
    assert response.status_code == 403
