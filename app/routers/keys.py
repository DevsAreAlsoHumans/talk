"""Routeur des clés publiques ECDH — matériel d'échange, aucun secret.

La clé publique permet d'« envelopper » individuellement la clé de salon
(ECDH + HKDF) lors de l'invitation. Elle est publique par nature :
sa divulgation ne révèle aucun contenu.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Response, status

from ..db import Database, get_db
from ..deps import get_current_user, require_csrf
from ..models import PublicKeyPayload, UserPublic

router = APIRouter(prefix="/api/keys", tags=["keys"])

DbDep = Annotated[Database, Depends(get_db)]
CurrentUser = Annotated[UserPublic, Depends(get_current_user)]


@router.put("", status_code=status.HTTP_204_NO_CONTENT)
async def put_public_key(
    payload: PublicKeyPayload,
    user: CurrentUser,
    db: DbDep,
    _: None = Depends(require_csrf),  # mutation : CSRF obligatoire
):
    await db.set_public_key(user.username, payload.public_key)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/{username}", response_model=PublicKeyPayload)
async def get_public_key(username: str, user: CurrentUser, db: DbDep):
    raw = await db.get_public_key(username)
    if raw is None:
        # Réponse uniforme : on ne révèle pas si l'utilisateur existe.
        raise HTTPException(status_code=404, detail="Aucune clé publique")
    return PublicKeyPayload(public_key=raw)
