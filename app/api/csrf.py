"""Endpoint CSRF : création/réutilisation de la session anonyme.

Le token CSRF est le token de session stocké côté serveur ; le client le
récupère ici (cookie de session posé au passage) puis l'envoie dans le header
``X-CSRF-Token`` sur toutes ses mutations.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response
from redis import Redis

from app.db.redis import get_redis
from app.security.sessions import create_session, get_session, set_session_cookie

router = APIRouter(prefix="/csrf", tags=["csrf"])


@router.get("")
def get_csrf_token(
    request: Request,
    response: Response,
    redis: Redis = Depends(get_redis),
) -> dict[str, str]:
    """Renvoie ``{"csrf_token": "..."}``.

    Crée une session anonyme si aucune n'existe ; sinon réutilise la session
    existante (le cookie n'est pas recréé, la session utilisateur est intacte).
    """
    session = get_session(redis, request)
    if session is None:
        sid, token = create_session(redis, user_id=None)
        set_session_cookie(response, sid)
        return {"csrf_token": token}
    return {"csrf_token": session["csrf_token"]}
