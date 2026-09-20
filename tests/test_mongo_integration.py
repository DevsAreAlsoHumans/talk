"""Intégration contre un VRAI Mongo — le chemin réel d'app/db.py.

Le reste de la suite repose sur la BDD InMemory (conftest) : déterministe et
sans Mongo. Ce module fait basculer `get_db` vers un vrai serveur Mongo (URI
via l'environnement, cf. ci.yml / docker-compose) pour vérifier ce qui ne peut
pas être couvert en mémoire : index uniques, ObjectId, persistance des blobs.

Comportement :
- TALK_MONGODB_URI absent OU Mongo injoignable -> test ignoré (skip) ;
- Mongo joignable -> un flux complet est rejoué sur une base dédiée
  `{db_name}_test`, supprimée à la fin.

Contraintes d'implémentation :
- un client `AsyncIOMotorClient` se lie au premier event-loop qui l'utilise ;
  on n'utilise donc JAMAIS deux fois la même connexion sur des loops
  différents (probe / app / nettoyage = trois clients distincts) ;
- un seul TestClient (changé de session via login) pour un seul loop app.
"""

import asyncio
import base64
import json
import os
import uuid

import pytest
from conftest import create_room, register
from starlette.testclient import TestClient

from app.config import get_settings
from app.db import Mongo, get_db
from app.main import app

_settings = get_settings()

pytestmark = [
    pytest.mark.skipif(
        not _settings.mongodb_uri, reason="TALK_MONGODB_URI absent : pas d'intégration Mongo"
    )
]

URI = _settings.mongodb_uri
# Base dédiée aux tests : jamais la base de production (« talk »).
DB_NAME = _settings.db_name if _settings.db_name.endswith("_test") else f"{_settings.db_name}_test"


def _fast_fail_uri(uri: str) -> str:
    """Timeout de sélection serveur court : skip rapide si Mongo est absent."""
    sep = "&" if "?" in uri else "?"
    return f"{uri}{sep}serverSelectionTimeoutMS=3000"


def _csrf(client: TestClient) -> str:
    r = client.get("/api/auth/csrf")
    assert r.status_code == 200
    return r.json()["csrf_token"]


def _login(client: TestClient, username: str) -> None:
    """Change de session sur le MÊME client (un seul loop app possible)."""
    token = _csrf(client)
    r = client.post(
        "/api/auth/login",
        json={"username": username, "password": "P4ssw0rdX!"},
        headers={"X-CSRF-Token": token},
    )
    assert r.status_code == 200


async def test_flux_complet_sur_mongo_reel() -> None:
    """Inscription -> salon -> canaux -> clés -> message chiffré -> historique."""
    # Probe sur un client dédié (loop pytest) : skip propre si Mongo absent.
    probe = Mongo(_fast_fail_uri(URI), DB_NAME)
    try:
        await asyncio.wait_for(probe._client.admin.command("ping"), timeout=5)
    except Exception as exc:  # noqa: BLE001 — toute erreur de connectivité => skip
        probe._client.close()
        pytest.skip(f"Mongo injoignable ({URI}) : intégration ignorée — {exc}")
    probe._client.close()

    # Client Mongo de l'app créé au PREMIER appel requête, dans le loop du
    # TestClient : motor se lie à ce loop, cohérent pour tout le test.
    holder: dict[str, Mongo] = {}

    async def db_factory() -> Mongo:
        if "db" not in holder:
            holder["db"] = Mongo(_fast_fail_uri(URI), DB_NAME)
            await holder["db"].init_indexes()
        return holder["db"]

    app.dependency_overrides[get_db] = db_factory
    try:
        with TestClient(app) as client:
            register(client, "alice")          # session alice
            rid = create_room(client)          # salon + canal général auto

            # Canal supplémentaire ; doublon rejeté (index unique) sans 500.
            token = _csrf(client)
            r = client.post(
                f"/api/rooms/{rid}/channels",
                json={"name": "prive"},
                headers={"X-CSRF-Token": token},
            )
            assert r.status_code == 201
            cid = r.json()["id"]
            dup = client.post(
                f"/api/rooms/{rid}/channels",
                json={"name": "prive"},
                headers={"X-CSRF-Token": token},
            )
            assert dup.status_code == 409
            # Canal d'origine « general » (modèle Discord) + le nouveau.
            assert [c["name"] for c in client.get(f"/api/rooms/{rid}/channels").json()] == [
                "general",
                "prive",
            ]

            # bob s'inscrit puis dépose sa clé publique (session bob).
            token = _csrf(client)
            r = client.post(
                "/api/auth/register",
                json={"username": "bob", "password": "P4ssw0rdX!"},
                headers={"X-CSRF-Token": token},
            )
            assert r.status_code == 201
            token = _csrf(client)
            key = {"public_key": f"pk-{uuid.uuid4().hex}"}
            r = client.put("/api/keys", json=key, headers={"X-CSRF-Token": token})
            assert r.status_code == 204

            # Retour à alice : invite de bob + clé de salon enveloppée.
            _login(client, "alice")
            token = _csrf(client)
            r = client.put("/api/keys", json=key, headers={"X-CSRF-Token": token})
            assert r.status_code == 204
            r = client.post(
                f"/api/rooms/{rid}/invite",
                json={"username": "bob"},
                headers={"X-CSRF-Token": token},
            )
            assert r.status_code == 200
            blob = {
                "v": 1,
                "iv": base64.b64encode(b"x" * 12).decode(),
                "ct": base64.b64encode(b"y" * 64).decode(),
            }
            r = client.post(
                f"/api/rooms/{rid}/keys",
                json={"to": "bob", "blob": blob},
                headers={"X-CSRF-Token": token},
            )
            assert r.status_code == 204

            # bob retrouve son exemplaire intact — pas de lecture côté serveur.
            _login(client, "bob")
            mine = client.get(f"/api/rooms/{rid}/keys/me")
            assert mine.status_code == 200
            assert mine.json()["ct"] == blob["ct"]

            # Message chiffré via WebSocket : persisté puis rejoué (GET history).
            _login(client, "alice")
            cipher = base64.b64encode(b"cipher" + os.urandom(16)).decode()
            with client.websocket_connect(f"/api/ws?room_id={rid}") as a_ws:
                # Basculer la session pendant que la socket alice reste ouverte.
                _login(client, "bob")
                with client.websocket_connect(f"/api/ws?room_id={rid}") as b_ws:
                    presence = a_ws.receive_json()
                    assert presence["type"] == "presence"
                    assert presence["event"] == "join"
                    a_ws.send_text(json.dumps({"channel": cid, "payload": cipher}))
                    assert b_ws.receive_json()["payload"] == cipher

            _login(client, "alice")
            history = client.get(f"/api/rooms/{rid}/channels/{cid}/messages")
            assert history.status_code == 200
            payloads = [m["payload"] for m in history.json()]
            assert cipher in payloads
            assert all(m["sender"] == "alice" for m in history.json())

            # Réaction chiffrée sur le message n=1 : stockée puis rejouée,
            # retrait par toggle (blob absent) — même sur Mongo embarqué.
            token = _csrf(client)
            n1 = history.json()[0]["n"]
            react_blob = {
                "v": 1,
                "iv": base64.b64encode(b"i" * 12).decode(),
                "ct": base64.b64encode(b"e" * 24).decode(),
            }
            r = client.post(
                f"/api/rooms/{rid}/channels/{cid}/reactions",
                json={"n": n1, "blob": react_blob},
                headers={"X-CSRF-Token": token},
            )
            assert r.status_code == 201
            rows = client.get(f"/api/rooms/{rid}/channels/{cid}/reactions")
            assert rows.status_code == 200
            assert len(rows.json()) == 1
            assert rows.json()[0]["n"] == n1
            assert json.loads(rows.json()[0]["payload"]) == react_blob

            r = client.post(
                f"/api/rooms/{rid}/channels/{cid}/reactions",
                json={"n": n1},
                headers={"X-CSRF-Token": token},
            )
            assert r.status_code == 204
            rows = client.get(f"/api/rooms/{rid}/channels/{cid}/reactions")
            assert rows.json() == []

            # Alice (créatrice) transfère la propriété à Bob puis quitte : sa
            # clé enveloppée est purgée, elle disparaît du panneau membres.
            _login(client, "alice")
            token = _csrf(client)
            r = client.post(
                f"/api/rooms/{rid}/transfer",
                json={"to": "bob"},
                headers={"X-CSRF-Token": token},
            )
            assert r.status_code == 204
            assert client.get(f"/api/rooms/{rid}/members").json()["owner_id"] == "bob"
            r = client.delete(
                f"/api/rooms/{rid}/members/me",
                headers={"X-CSRF-Token": token},
            )
            assert r.status_code == 204
            assert client.get(f"/api/rooms/{rid}/keys/me").status_code == 403
            # Bob (propriétaire) vérifie qu'Alice a quitté puis supprime.
            _login(client, "bob")
            names = {
                m["username"]
                for m in client.get(f"/api/rooms/{rid}/members").json()["members"]
            }
            assert names == {"bob"}

            token = _csrf(client)
            r = client.delete(f"/api/rooms/{rid}", headers={"X-CSRF-Token": token})
            assert r.status_code == 204
            assert client.get("/api/rooms").json() == []

            # Doublon de pseudo : index unique -> 409 sans crash serveur.
            token = _csrf(client)
            dup_user = client.post(
                "/api/auth/register",
                json={"username": "alice", "password": "P4ssw0rdX!"},
                headers={"X-CSRF-Token": token},
            )
            assert dup_user.status_code == 409
    finally:
        app.dependency_overrides.pop(get_db, None)
        app_mongo = holder.get("db")
        if app_mongo is not None:
            app_mongo._client.close()
        # Nettoyage sur un client dédié (loop pytest) : base de test supprimée.
        cleaner = Mongo(_fast_fail_uri(URI), DB_NAME)
        await cleaner._client.drop_database(DB_NAME)
        cleaner._client.close()
