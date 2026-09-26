"""Dépendances FastAPI : CSRF, utilisateur courant, WebSocket et anti-brute-force.

Point central du CSRF : la valeur attendue est toujours lue dans le document de
session désigné par le cookie `talk_session` de l'appelant. Il n'existe aucune
recherche du jeton dans une collection globale. Un jeton valide appartenant à une
autre session ne peut donc pas égaler la valeur stockée pour celle-ci, et un
jeton présenté sans cookie de session n'a aucune valeur attendue : le rejet est
structurel, pas heuristique.
"""

from __future__ import annotations

import threading
import time
from typing import Annotated, Any

from fastapi import Depends, HTTPException, Request, WebSocket, status
from pymongo.asynchronous.database import AsyncDatabase
from starlette.exceptions import WebSocketException

from app.config import CSRF_HEADER_NAME, SESSION_COOKIE_NAME, get_settings
from app.db import get_db
from app.security import tokens_equal
from app.store import MongoUserStore, UserStore

POLICY_VIOLATION = 1008

# Anti-brute-force : fenêtre glissante de 15 minutes.
ATTEMPT_WINDOW_SECONDS = 900
LOGIN_ATTEMPT_LIMIT = 5
IP_ATTEMPT_LIMIT = 30


class SlidingWindowLimiter:
    """Compteur d'événements par clé, sur fenêtre glissante.

    Volontairement en mémoire : le MVP n'ajoute ainsi aucune dépendance et aucun
    service supplémentaire. See la documentation pour les limites connues.
    """

    def __init__(self, limit: int, window_seconds: int) -> None:
        self._limit = limit
        self._window = window_seconds
        self._hits: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def _prune(self, now: float) -> None:
        cutoff = now - self._window
        expired = [key for key, hits in self._hits.items() if not hits or hits[-1] <= cutoff]
        for key in expired:
            del self._hits[key]

    def register(self, key: str) -> int:
        """Enregistre un événement. Retourne 0 si autorisé, sinon un `Retry-After`."""
        now = time.monotonic()
        with self._lock:
            self._prune(now)
            cutoff = now - self._window
            hits = [stamp for stamp in self._hits.get(key, []) if stamp > cutoff]
            if len(hits) >= self._limit:
                self._hits[key] = hits
                return max(1, int(self._window - (now - hits[0])) + 1)
            hits.append(now)
            self._hits[key] = hits
            return 0

    def reset(self, key: str) -> None:
        with self._lock:
            self._hits.pop(key, None)


_login_limiter = SlidingWindowLimiter(LOGIN_ATTEMPT_LIMIT, ATTEMPT_WINDOW_SECONDS)
_ip_limiter = SlidingWindowLimiter(IP_ATTEMPT_LIMIT, ATTEMPT_WINDOW_SECONDS)


def get_store(database: Annotated[AsyncDatabase, Depends(get_db)]) -> UserStore:
    """Dépendance FastAPI : accès aux données."""
    return MongoUserStore(database)


def client_ip(request: Request) -> str:
    settings = get_settings()
    if settings.trust_proxy_headers:
        forwarded = request.headers.get("x-forwarded-for", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
    if request.client is not None:
        return request.client.host
    return "unknown"


def enforce_login_rate_limit(request: Request, username: str) -> None:
    """Limite les tentatives par couple (IP, identifiant) et par IP.

    Le comptage n'est jamais indexé sur le seul identifiant : sinon n'importe qui
    pourrait s'épuiser le quota d'un compte et en priver son titulaire
    (déni de service délibéré). Aucun état « compte verrouillé » n'est créé,
    donc aucun blocage permanent n'est possible.
    """
    address = client_ip(request)
    keys = (f"pair:{address}:{username}", f"ip:{address}")
    for key, limiter in ((keys[0], _login_limiter), (keys[1], _ip_limiter)):
        retry_after = limiter.register(key)
        if retry_after:
            raise HTTPException(
                status.HTTP_429_TOO_MANY_REQUESTS,
                "Trop de tentatives de connexion. Réessayez plus tard.",
                headers={"Retry-After": str(retry_after)},
            )


def reset_login_rate_limit(request: Request, username: str) -> None:
    address = client_ip(request)
    _login_limiter.reset(f"pair:{address}:{username}")
    _ip_limiter.reset(f"ip:{address}")


def _presented_token(request: Request) -> str | None:
    return request.cookies.get(SESSION_COOKIE_NAME) or None


async def require_csrf(
    request: Request,
    store: Annotated[UserStore, Depends(get_store)],
) -> dict[str, Any]:
    """Valide le jeton CSRF d'une mutation. À utiliser sur toute route mutante."""
    token = _presented_token(request)
    session = await store.get_session(token) if token else None
    if session is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Jeton CSRF manquant.")
    presented = request.headers.get(CSRF_HEADER_NAME, "")
    if not presented or not tokens_equal(presented, str(session.get("csrf_token", ""))):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Jeton CSRF invalide.")
    return session


async def get_current_user(
    request: Request,
    store: Annotated[UserStore, Depends(get_store)],
) -> dict[str, Any]:
    """Retourne l'utilisateur de la session courante, ou 401."""
    token = _presented_token(request)
    user = await store.get_user_by_session(token) if token else None
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Authentification requise.")
    return user


def require_trusted_origin(origin: str | None) -> None:
    """refuse toute origine non listée. En production, `https` est obligatoire."""
    settings = get_settings()
    if origin is None or origin not in settings.app_origins:
        raise WebSocketException(POLICY_VIOLATION, "Origin non autorisée.")
    if settings.is_production and not origin.startswith("https://"):
        raise WebSocketException(POLICY_VIOLATION, "Origin non autorisée.")


async def require_trusted_origin_ws(websocket: WebSocket) -> None:
    require_trusted_origin(websocket.headers.get("origin"))


async def get_current_user_ws(
    websocket: WebSocket,
    store: Annotated[UserStore, Depends(get_store)],
) -> dict[str, Any]:
    """Authentifie un WebSocket via le cookie `talk_session`."""
    token = websocket.cookies.get(SESSION_COOKIE_NAME)
    user = await store.get_user_by_session(token) if token else None
    if user is None:
        raise WebSocketException(POLICY_VIOLATION, "Session invalide ou expirée.")
    return user
