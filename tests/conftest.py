"""Outils communs aux tests : faux Redis en mémoire et « navigateurs » de test."""

import fakeredis
import pytest
from fakeredis.aioredis import FakeRedis
from fastapi.testclient import TestClient

from app.database import db
from app.main import app

ORIGIN = "http://testserver"
PASSWORD = "motdepasse123"
# Un faux message chiffré au bon format (le vrai chiffrement est testé dans crypto.test.js)
CIPHER = {"version": 1, "nonce": "AAAAAAAAAAAAAAAA", "ciphertext": "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo"}


# Faux Redis en mémoire, vidé à chaque test
@pytest.fixture
def redis_server():
    server = fakeredis.FakeServer()
    app.dependency_overrides[db] = lambda: FakeRedis(server=server, decode_responses=True)
    yield server
    app.dependency_overrides.clear()


# Accès direct au faux Redis pour regarder ce qui est vraiment stocké
@pytest.fixture
def stored(redis_server):
    return fakeredis.FakeRedis(server=redis_server, decode_responses=True)


# Ouvre un nouveau « navigateur » (ses propres cookies) avec l'origine et le jeton CSRF prêts
@pytest.fixture
def browser(redis_server):
    opened = []

    def open_browser():
        client = TestClient(app, raise_server_exceptions=False)
        client.headers["Origin"] = ORIGIN
        client.headers["X-CSRF-Token"] = client.get("/api/csrf").json()["csrf_token"]
        opened.append(client)
        return client

    yield open_browser
    for client in opened:
        client.close()


@pytest.fixture
def client(browser):
    return browser()


def signup(client, username="alice", password=PASSWORD):
    return client.post("/api/signup", json={"username": username, "password": password})


def login(client, username="alice", password=PASSWORD):
    return client.post("/api/login", json={"username": username, "password": password})


# Crée un salon et renvoie aussi le chemin des messages de son canal « général »
def create_server(client, name="Cours"):
    server = client.post("/api/servers", json={"name": name}).json()
    return server, f"/api/servers/{server['id']}/channels/{server['channel_id']}/messages"
