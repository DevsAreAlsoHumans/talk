from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException, status
from pymongo import ReturnDocument

from app.db.mongo import db
from app.models.user import PublicKeyUpdate, UserPublic
from app.security.sessions import get_current_user_id, require_csrf

router = APIRouter(prefix="/users", tags=["users"])


@router.put(
    "/me/public-key", response_model=UserPublic, dependencies=[Depends(require_csrf)]
)
async def update_public_key(
    payload: PublicKeyUpdate, user_id: str = Depends(get_current_user_id)
) -> UserPublic:
    """Enregistre la clé publique E2E générée côté client (jamais la clé privée)."""
    document = await db.users.find_one_and_update(
        {"_id": ObjectId(user_id)},
        {"$set": {"public_key": payload.public_key}},
        return_document=ReturnDocument.AFTER,
    )
    if document is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Utilisateur introuvable."
        )
    return UserPublic(
        id=str(document["_id"]),
        username=document["username"],
        discriminator=document["discriminator"],
        email=document["email"],
        public_key=document.get("public_key"),
    )
