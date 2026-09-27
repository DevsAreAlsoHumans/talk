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

from app.chat_store import ChatStore, MongoChatStore, to_object_id
from app.config import CSRF_HEADER_NAME, SESSION_COOKIE_NAME, get_settings
from app.db import get_db
from app.security import tokens_equal
from app.store import MongoUserStore, UserStore

POLICY_VIOLATION = 1008

# Anti-brute-force : fenêtre glissante de 15 minutes.
ATTEMPT_WINDOW_SECONDS = 900
LOGIN_ATTEMPT_LIMIT = 5
IP_ATTEMPT_LIMIT = 30

# Anti-spam d'envoi de messages : fenêtre glissante de 10 secondes.
MESSAGE_WINDOW_SECONDS = 10
MESSAGE_ATTEMPT_LIMIT = 30

CHANNEL_NOT_FOUND = "Canal introuvable."
CHANNEL_FORBIDDEN = "Accès refusé à ce canal."
CHANNEL_CREATOR_ONLY = (
    "Seul le créateur du canal peut ajouter ou retirer un membre, et distribuer la clé de salon."
)


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
_message_limiter = SlidingWindowLimiter(MESSAGE_ATTEMPT_LIMIT, MESSAGE_WINDOW_SECONDS)


def get_store(database: Annotated[AsyncDatabase, Depends(get_db)]) -> UserStore:
    """Dépendance FastAPI : accès aux données."""
    return MongoUserStore(database)


def get_chat_store(database: Annotated[AsyncDatabase, Depends(get_db)]) -> ChatStore:
    """Dépendance FastAPI : accès aux canaux, enveloppes et messages."""
    return MongoChatStore(database)


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


def message_rate_limit_retry_after(user_id: Any) -> int:
    """Enregistre un envoi de message. Renvoie 0 si autorisé, sinon un délai.

    Le limiteur est en mémoire, comme celui des connexions : il protège d'un
    usage excessif mais ne constitue pas une garantie en cas de plusieurs
    workers.
    """
    return _message_limiter.register(f"msg:{user_id}")


async def require_channel_member(
    channel_id: str,
    user: Annotated[dict[str, Any], Depends(get_current_user)],
    store: Annotated[ChatStore, Depends(get_chat_store)],
) -> dict[str, Any]:
    """Exige l'appartenance au canal et renvoie celui-ci.

    Distingue volontairement l'absence de l'existence : un identifiant qui ne
    correspond à aucun canal répond 404, l'existence d'un canal dont l'appelant
    n'est pas membre répond 403. Cette nuance reste en pratique peu observable,
    mais elle évite de confirmer l'existence d'un canal à un tiers.
    """
    object_id = to_object_id(channel_id)
    if object_id is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, CHANNEL_NOT_FOUND)
    channel = await store.get_channel(object_id)
    if channel is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, CHANNEL_NOT_FOUND)
    if user["_id"] not in channel.get("members", []):
        raise HTTPException(status.HTTP_403_FORBIDDEN, CHANNEL_FORBIDDEN)
    return channel


async def require_channel_creator(
    channel_id: str,
    user: Annotated[dict[str, Any], Depends(get_current_user)],
    store: Annotated[ChatStore, Depends(get_chat_store)],
) -> dict[str, Any]:
    """Exige que l'appelant soit le créateur du canal, et renvoie celui-ci.

    Le créateur est l'utilisateur inscrit dans `created_by` par `create_channel`,
    à partir de la session et jamais d'un corps de requête. Ce champ est donc la
    seule autorité possible : l'identité de l'appelant vient de la session, celle
    du canal de la base, et un `user_id` fourni par le client ne sert qu'à
    désigner le *destinataire* de l'opération, jamais à décider qui l'exécute.

    Cette dépendance remplace `require_channel_member` là où un acte engage le
    canal : inviter, retirer, distribuer la clé de salon. Un membre ordinaire en
    est exclu — il pourrait sinon préparer une enveloppe pour un tiers et
    devancer le créateur, le dépôt étant « premier arrivé, premier servi » et
    jamais écrasé. Un tiers est exclu pour la même raison, et reçoit le même
    refus : la seule différence est qu'un membre a déjà accès au canal.
    """
    object_id = to_object_id(channel_id)
    if object_id is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, CHANNEL_NOT_FOUND)
    channel = await store.get_channel(object_id)
    if channel is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, CHANNEL_NOT_FOUND)
    if channel.get("created_by") != user["_id"]:
        raise HTTPException(status.HTTP_403_FORBIDDEN, CHANNEL_CREATOR_ONLY)
    return channel


async def require_public_key(
    user: Annotated[dict[str, Any], Depends(get_current_user)],
    store: Annotated[UserStore, Depends(get_store)],
) -> dict[str, Any]:
    """Exige que l'appelant ait publié sa clé publique.

    Sans elle, il ne pourrait emballer aucune clé de salon : mieux vaut refuser
    de produire un salon ou un message que personne ne pourra déchiffrer.
    """
    public_key = await store.get_public_key(user["_id"])
    if public_key is None or "public_key" not in public_key:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "Aucune clé publique publiée : impossible de participer à un canal.",
        )
    return public_key["public_key"]
