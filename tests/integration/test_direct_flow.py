"""Conversations privées à deux, et empreintes de clé publique."""


def _direct_payload(username="bob"):
    return {
        "username": username,
        "encrypted_salon_key_self": "cle-chiffree-pour-moi",
        "encrypted_salon_key_other": "cle-chiffree-pour-lui",
    }


# ---------- Création ----------


async def test_open_a_direct_conversation(auth_headers, second_user):
    response = await auth_headers.post("/salons/direct", json=_direct_payload())
    assert response.status_code == 201

    salon = response.json()
    assert salon["is_direct"] is True
    assert len(salon["members"]) == 2
    assert {m["username"] for m in salon["members"]} == {"alice", "bob"}


async def test_each_side_gets_its_own_encrypted_key(auth_headers, second_user):
    salon = (await auth_headers.post("/salons/direct", json=_direct_payload())).json()
    keys = {m["username"]: m["encrypted_salon_key"] for m in salon["members"]}
    assert keys["alice"] == "cle-chiffree-pour-moi"
    assert keys["bob"] == "cle-chiffree-pour-lui"


async def test_a_direct_conversation_has_a_default_channel(auth_headers, second_user):
    salon = (await auth_headers.post("/salons/direct", json=_direct_payload())).json()
    assert len(salon["channels"]) == 1


async def test_reopening_returns_the_same_conversation(auth_headers, second_user):
    """Idempotent : on ne veut pas dix fils avec la même personne."""
    first = (await auth_headers.post("/salons/direct", json=_direct_payload())).json()
    second = (await auth_headers.post("/salons/direct", json=_direct_payload())).json()
    assert first["id"] == second["id"]

    salons = (await auth_headers.get("/salons")).json()
    assert len([s for s in salons if s["is_direct"]]) == 1


async def test_cannot_talk_to_yourself(auth_headers):
    response = await auth_headers.post("/salons/direct", json=_direct_payload("alice"))
    assert response.status_code == 400


async def test_unknown_recipient(auth_headers):
    response = await auth_headers.post("/salons/direct", json=_direct_payload("fantome"))
    assert response.status_code == 404


async def test_direct_appears_in_the_salon_list(auth_headers, second_user):
    await auth_headers.post("/salons/direct", json=_direct_payload())
    salons = (await auth_headers.get("/salons")).json()
    assert any(s["is_direct"] for s in salons)


async def test_a_regular_salon_is_not_direct(auth_headers, salon_id):
    salon = (await auth_headers.get(f"/salons/{salon_id}")).json()
    assert salon["is_direct"] is False


# ---------- Messages dans une conversation privée ----------


async def test_both_sides_can_read_the_thread(auth_headers, csrf_client, second_user):
    salon = (await auth_headers.post("/salons/direct", json=_direct_payload())).json()
    await auth_headers.post(
        f"/salons/{salon['id']}/messages",
        json={"ciphertext": "coucou-chiffre", "iv": "iv"},
    )

    csrf_client.headers["Authorization"] = f"Bearer {second_user['tokens']['access_token']}"
    messages = (await csrf_client.get(f"/salons/{salon['id']}/messages")).json()["messages"]
    assert [m["ciphertext"] for m in messages] == ["coucou-chiffre"]


async def test_a_third_party_is_locked_out(auth_headers, csrf_client, second_user, sample_user):
    salon = (await auth_headers.post("/salons/direct", json=_direct_payload())).json()

    # Charlie s'inscrit et tente d'entrer dans la conversation.
    await csrf_client.post(
        "/auth/signup",
        json={
            "username": "charlie",
            "email": "charlie@example.com",
            "password": "StrongP@ss1",
            "public_key": "charlie_key",
        },
    )
    login = await csrf_client.post("/auth/login", json={"username": "charlie", "password": "StrongP@ss1"})
    csrf_client.headers["Authorization"] = f"Bearer {login.json()['access_token']}"

    assert (await csrf_client.get(f"/salons/{salon['id']}/messages")).status_code == 403


# ---------- Empreintes ----------


async def test_profile_exposes_a_fingerprint(auth_headers):
    me = (await auth_headers.get("/auth/me")).json()
    assert me["fingerprint"] is not None
    assert len(me["fingerprint"].split(" ")) == 12


async def test_public_key_lookup_exposes_a_fingerprint(auth_headers, second_user):
    body = (await auth_headers.get("/auth/users/bob/public-key")).json()
    assert body["fingerprint"] is not None


async def test_members_carry_their_fingerprint(auth_headers, second_user):
    salon = (await auth_headers.post("/salons/direct", json=_direct_payload())).json()
    alice = next(m for m in salon["members"] if m["username"] == "alice")
    assert alice["fingerprint"] is not None


async def test_fingerprint_matches_between_endpoints(auth_headers, second_user):
    """La même clé doit donner la même empreinte partout, sinon l'utilisateur
    ne saurait pas laquelle comparer."""
    from_lookup = (await auth_headers.get("/auth/users/alice/public-key")).json()["fingerprint"]
    from_profile = (await auth_headers.get("/auth/me")).json()["fingerprint"]
    assert from_lookup == from_profile


async def test_two_users_have_different_fingerprints(auth_headers, second_user):
    alice = (await auth_headers.get("/auth/users/alice/public-key")).json()["fingerprint"]
    bob = (await auth_headers.get("/auth/users/bob/public-key")).json()["fingerprint"]
    assert alice != bob
