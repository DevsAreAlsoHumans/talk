import mimetypes
import re

from bson import ObjectId
from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from fastapi.responses import FileResponse
from pymongo import ReturnDocument

from app.db.mongo import db
from app.models.user import AvatarDicebearUpdate, PublicKeyUpdate, UserPublic
from app.security.sessions import get_current_user_id, require_csrf
from app.services.storage import blob_path, save_blob

router = APIRouter(prefix="/users", tags=["users"])

_MAX_AVATAR_SIZE = 2 * 1024 * 1024
_ALLOWED_AVATAR_TYPES = {"image/png", "image/jpeg", "image/webp", "image/gif"}
_BLOB_ID_PATTERN = re.compile(r"^[0-9a-f]{32}(\.[a-zA-Z0-9]{1,10})?$")


async def _update_user(user_id: str, update: dict) -> UserPublic:
    document = await db.users.find_one_and_update(
        {"_id": ObjectId(user_id)}, {"$set": update}, return_document=ReturnDocument.AFTER
    )
    if document is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Utilisateur introuvable."
        )
    return UserPublic.from_document(document)


@router.put("/me/public-key", response_model=UserPublic, dependencies=[Depends(require_csrf)])
async def update_public_key(
    payload: PublicKeyUpdate, user_id: str = Depends(get_current_user_id)
) -> UserPublic:
    """Enregistre la clé publique E2E générée côté client (jamais la clé privée)."""
    return await _update_user(user_id, {"public_key": payload.public_key})


@router.put(
    "/me/avatar/dicebear", response_model=UserPublic, dependencies=[Depends(require_csrf)]
)
async def set_dicebear_avatar(
    payload: AvatarDicebearUpdate, user_id: str = Depends(get_current_user_id)
) -> UserPublic:
    """Choisit un avatar généré (seed Dicebear) : aucun fichier stocké côté serveur."""
    return await _update_user(user_id, {"avatar": {"type": "dicebear", "value": payload.seed}})


@router.post(
    "/me/avatar/upload", response_model=UserPublic, dependencies=[Depends(require_csrf)]
)
async def upload_avatar(
    file: UploadFile = File(...), user_id: str = Depends(get_current_user_id)
) -> UserPublic:
    """Upload d'une image de profil personnalisée (non chiffrée : c'est une photo publique)."""
    if file.content_type not in _ALLOWED_AVATAR_TYPES:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="Format d'image non supporté (png, jpeg, webp, gif uniquement).",
        )

    data = await file.read()
    if len(data) > _MAX_AVATAR_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Image trop volumineuse (2 Mo maximum).",
        )

    extension = mimetypes.guess_extension(file.content_type) or ""
    blob_id = save_blob(data, extension)
    return await _update_user(user_id, {"avatar": {"type": "upload", "value": blob_id}})


@router.get("/avatars/{blob_id}")
async def get_avatar(blob_id: str) -> FileResponse:
    """Sert un avatar uploadé (public, pas d'authentification requise)."""
    if not _BLOB_ID_PATTERN.match(blob_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Avatar introuvable.")

    path = blob_path(blob_id)
    if not path.is_file():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Avatar introuvable.")
    return FileResponse(path)
