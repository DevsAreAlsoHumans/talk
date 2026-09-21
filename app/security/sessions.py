"""Gestion des sessions : cycle de vie complet + helpers de cookie.

Le cookie contient le ``sid`` (valeur opaque) accompagné d'une **signature
HMAC-SHA256** calculée avec ``SECRET_KEY`` : un attaquant ne peut pas forger ni
modifier un sid (anti-forgeage), même sans accès direct à Redis. Le token CSRF,
lui, est stocké côté serveur dans Redis — il n'est renvoyé au client qu'au
moment de la création/rotation (via les réponses ``csrf_token``).
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

from redis import Redis
from starlette.responses import Response

from app.config import settings
from app.repositories import sessions as sessions_repo


def _new_secret() -> str:
    """Génère une valeur aléatoire opaque (sid, token CSRF)."""
    return secrets.token_urlsafe(32)


def _sign(value: str) -> str:
    """Signature HMAC-SHA256 de ``value`` (production reproductible -> tests)."""
    return hmac.new(settings.SECRET_KEY.encode(), value.encode(), hashlib.sha256).hexdigest()


def _with_signature(value: str) -> str:
    """Renvoie ``value.signature`` (le sid ne contient jamais de point)."""
    return f"{value}.{_sign(value)}"


def parse_signed_cookie(raw: str | None) -> str | None:
    """Valide la signature d'un cookie et renvoie le sid, ou ``None`` sinon.

    La comparaison de signature utilise ``hmac.compare_digest`` (temps
    constant) pour éviter une fuite par canal auxiliaire.
    """
    if not raw or "." not in raw:
        return None
    value, _, signature = raw.rpartition(".")
    if not hmac.compare_digest(_sign(value), signature):
        return None
    return value


def create_session(redis: Redis, user_id: str | None) -> tuple[str, str]:
    """Crée une session et renvoie ``(sid, token CSRF)``.

    ``user_id=None`` correspond à une session anonyme (avant login/register).
    """
    sid = _new_secret()
    token = _new_secret()
    sessions_repo.save_session(redis, sid, user_id, token)
    return sid, token


def get_session(redis: Redis, request) -> dict | None:
    """Renvoie la session lue depuis le cookie (ou ``None`` si absente)."""
    sid = read_session_id(request)
    if sid is None:
        return None
    return sessions_repo.get_session(redis, sid)


def rotate_session(redis: Redis, sid: str, *, user_id: str | None = None) -> tuple[str, str]:
    """Rotation de session : nouveau ``sid`` + nouveau token CSRF.

    L'ancienne session est invalidée (anti-fixation). Si ``user_id`` est donné,
    la session est rattachée à cet utilisateur (cas login/register).
    """
    existing = sessions_repo.get_session(redis, sid)
    owner = user_id if user_id is not None else (existing["user_id"] if existing else None)
    new_sid = _new_secret()
    new_token = _new_secret()
    sessions_repo.save_session(redis, new_sid, owner, new_token)
    sessions_repo.delete_session(redis, sid)
    return new_sid, new_token


def destroy_session(redis: Redis, request) -> None:
    """Détruit la session associée au cookie de la requête, s'il y en a une."""
    sid = read_session_id(request)
    if sid is not None:
        sessions_repo.delete_session(redis, sid)


def read_session_id(request) -> str | None:
    """Lit le ``sid`` depuis le cookie de session (signature vérifiée)."""
    raw = request.cookies.get(settings.COOKIE_NAME)
    return parse_signed_cookie(raw)


def set_session_cookie(response: Response, sid: str) -> None:
    """Pose le cookie de session (signé, HttpOnly, SameSite=Lax, Secure si config)."""
    response.set_cookie(
        settings.COOKIE_NAME,
        _with_signature(sid),
        max_age=settings.SESSION_TTL,
        httponly=True,
        samesite="lax",
        secure=settings.COOKIE_SECURE,
        path="/",
    )


def clear_session_cookie(response: Response) -> None:
    """Supprime le cookie de session de la réponse (logout)."""
    response.delete_cookie(settings.COOKIE_NAME, path="/")
