"""Acteur de test : un utilisateur avec sa propre session, au-dessus d'un TestClient partagé.

Les cookies sont gérés à la main (un TestClient n'a qu'un seul « cookie jar ») pour que
plusieurs utilisateurs puissent coexister dans le même test, comme dans un vrai déploiement.
"""

from http.cookies import SimpleCookie

from starlette.testclient import TestClient

from tests.helpers import e2e

ORIGIN = "http://testserver"


class Actor:
    def __init__(self, client: TestClient, identity: e2e.Identity) -> None:
        self.client = client
        self.identity = identity
        self.cookies: dict[str, str] = {}
        self.csrf_token = ""
        self.user_id = ""
        self.room_keys: dict[str, bytes] = {}

    # ---- HTTP ----

    def headers(self, *, csrf: bool = True, origin: str | None = ORIGIN) -> dict[str, str]:
        headers = {}
        if origin:
            headers["Origin"] = origin
        if csrf and self.csrf_token:
            headers["X-CSRF-Token"] = self.csrf_token
        if self.cookies:
            headers["Cookie"] = "; ".join(f"{name}={value}" for name, value in self.cookies.items())
        return headers

    def request(self, method: str, path: str, *, csrf: bool = True, origin: str | None = ORIGIN, **kwargs):
        headers = {**self.headers(csrf=csrf, origin=origin), **kwargs.pop("headers", {})}
        self.client.cookies.clear()
        response = self.client.request(method, path, headers=headers, **kwargs)
        self.client.cookies.clear()
        self._store_cookies(response)
        return response

    def _store_cookies(self, response) -> None:
        for header in response.headers.get_list("set-cookie"):
            cookie = SimpleCookie()
            cookie.load(header)
            for name, morsel in cookie.items():
                if morsel.value:
                    self.cookies[name] = morsel.value
                else:
                    self.cookies.pop(name, None)

    def get(self, path: str, **kwargs):
        return self.request("GET", path, **kwargs)

    def post(self, path: str, json=None, **kwargs):
        return self.request("POST", path, json=json, **kwargs)

    def put(self, path: str, json=None, **kwargs):
        return self.request("PUT", path, json=json, **kwargs)

    # ---- Parcours métier ----

    def fetch_csrf(self) -> str:
        self.csrf_token = self.get("/api/csrf").json()["csrf_token"]
        return self.csrf_token

    def register(self):
        self.fetch_csrf()
        return self.post("/api/auth/register", self.identity.registration_payload())

    def login(self):
        self.fetch_csrf()
        response = self.post(
            "/api/auth/login", {"username": self.identity.username, "auth_secret": self.identity.auth_secret}
        )
        if response.status_code == 200:
            body = response.json()
            self.user_id = body["user"]["id"]
            self.csrf_token = body["csrf_token"]
        return response

    def create_room(self, name: str = "général") -> str:
        room_key = e2e.generate_room_key()
        response = self.post(
            "/api/rooms", {"name": name, "wrapped_key": e2e.wrap_room_key(room_key, self.identity.public_key)}
        )
        assert response.status_code == 201, response.text
        room_id = response.json()["id"]
        self.room_keys[room_id] = room_key
        return room_id

    def add_member(self, room_id: str, other: "Actor"):
        wrapped = e2e.wrap_room_key(self.room_keys[room_id], other.identity.public_key)
        return self.post(
            f"/api/rooms/{room_id}/members", {"username": other.identity.username, "wrapped_key": wrapped}
        )

    def load_room_key(self, room_id: str) -> bytes:
        """Récupère la clé du salon comme le ferait le navigateur : déballage avec la clé privée."""
        room = self.get(f"/api/rooms/{room_id}").json()
        self.room_keys[room_id] = e2e.unwrap_room_key(room["wrapped_key"], self.identity.private_key)
        return self.room_keys[room_id]

    def send(self, room_id: str, text: str):
        payload = e2e.encrypt_message(self.room_keys[room_id], text, room_id, self.user_id)
        return self.post(f"/api/rooms/{room_id}/messages", payload)

    def send_media(self, room_id: str, data: bytes, *, kind: str = "image", mime: str = "image/png"):
        payload = e2e.encrypt_bytes(self.room_keys[room_id], data, room_id, self.user_id)
        return self.post(f"/api/rooms/{room_id}/messages", {**payload, "kind": kind, "mime": mime})

    def set_avatar(self, room_id: str, data: bytes):
        payload = e2e.encrypt_bytes(self.room_keys[room_id], data, room_id, self.user_id)
        return self.put(f"/api/rooms/{room_id}/avatar", payload)

    def update_profile(self, display_name: str, bio: str):
        return self.put("/api/me/profile", {"display_name": display_name, "bio": bio})

    def read(self, room_id: str, **params) -> list[str]:
        response = self.get(f"/api/rooms/{room_id}/messages", params=params)
        assert response.status_code == 200, response.text
        return [
            e2e.decrypt_message(self.room_keys[room_id], message) for message in response.json()["messages"]
        ]

    def websocket(self, *, origin: str | None = ORIGIN):
        headers = {}
        if origin:
            headers["Origin"] = origin
        if self.cookies:
            headers["Cookie"] = "; ".join(f"{name}={value}" for name, value in self.cookies.items())
        return self.client.websocket_connect("/ws", headers=headers)
