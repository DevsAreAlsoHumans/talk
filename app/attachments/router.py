from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException, status

from app.attachments.models import AttachmentCreate, AttachmentPayload, AttachmentResponse
from app.attachments.service import decode_payload, encode_payload, get_attachment, store_attachment
from app.auth.router import get_current_user
from app.config import settings
from app.ratelimit import hit
from app.salons.service import is_member

router = APIRouter(prefix="/salons/{salon_id}/attachments", tags=["attachments"])


def _to_response(doc: dict) -> AttachmentResponse:
    return AttachmentResponse(
        id=str(doc["_id"]),
        kind=doc["kind"],
        duration_ms=doc["duration_ms"],
        mime=doc["mime"],
        size=doc["size"],
        created_at=doc["created_at"],
    )


async def _require_member(salon_id: str, user: dict) -> None:
    if not ObjectId.is_valid(salon_id):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid salon ID")
    if not await is_member(salon_id, str(user["_id"])):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not a member")


@router.post("", status_code=status.HTTP_201_CREATED, response_model=AttachmentResponse)
async def upload(salon_id: str, data: AttachmentCreate, user: dict = Depends(get_current_user)):
    """Dépose une pièce jointe chiffrée, à référencer ensuite dans un message."""
    await _require_member(salon_id, user)

    allowed, retry_after = hit(
        f"attach:{user['_id']}",
        settings.rate_limit_attachment,
        settings.rate_limit_attachment_window,
    )
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Trop d'envois vocaux. Patientez un instant.",
            headers={"Retry-After": str(retry_after)},
        )

    raw = decode_payload(data.ciphertext)
    if raw is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Contenu chiffré illisible (base64 invalide)",
        )

    doc = await store_attachment(
        salon_id=salon_id,
        uploader_id=user["_id"],
        kind=data.kind,
        raw=raw,
        iv=data.iv,
        duration_ms=data.duration_ms,
        mime=data.mime,
    )
    return _to_response(doc)


@router.get("/{attachment_id}", response_model=AttachmentPayload)
async def download(salon_id: str, attachment_id: str, user: dict = Depends(get_current_user)):
    """Renvoie le contenu chiffré ; seul un membre du salon peut le déchiffrer."""
    await _require_member(salon_id, user)

    doc = await get_attachment(salon_id, attachment_id)
    if not doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Pièce jointe introuvable")

    return AttachmentPayload(
        **_to_response(doc).model_dump(),
        ciphertext=encode_payload(bytes(doc["payload"])),
        iv=doc["iv"],
    )
