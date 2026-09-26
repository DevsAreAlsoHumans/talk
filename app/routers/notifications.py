from bson import ObjectId
from bson.errors import InvalidId
from fastapi import APIRouter, Depends, HTTPException, status
from pymongo import ReturnDocument

from app.db.mongo import db
from app.models.notification import NotificationPublic
from app.security.sessions import get_current_user_id, require_csrf
from app.services.notifications import to_public

router = APIRouter(prefix="/notifications", tags=["notifications"])


@router.get("", response_model=list[NotificationPublic])
async def list_notifications(
    user_id: str = Depends(get_current_user_id),
) -> list[NotificationPublic]:
    """Liste les notifications de l'utilisateur courant, les plus récentes d'abord."""
    cursor = db.notifications.find({"user_id": user_id}).sort("created_at", -1)
    documents = await cursor.to_list(length=100)
    return [to_public(document) for document in documents]


@router.post(
    "/{notification_id}/read",
    response_model=NotificationPublic,
    dependencies=[Depends(require_csrf)],
)
async def mark_as_read(
    notification_id: str, user_id: str = Depends(get_current_user_id)
) -> NotificationPublic:
    """Marque une notification comme lue."""
    try:
        object_id = ObjectId(notification_id)
    except InvalidId as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Notification introuvable."
        ) from exc

    document = await db.notifications.find_one_and_update(
        {"_id": object_id, "user_id": user_id},
        {"$set": {"read": True}},
        return_document=ReturnDocument.AFTER,
    )
    if document is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Notification introuvable."
        )
    return to_public(document)


@router.post(
    "/read-all", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(require_csrf)]
)
async def mark_all_as_read(user_id: str = Depends(get_current_user_id)) -> None:
    """Marque toutes les notifications de l'utilisateur courant comme lues."""
    await db.notifications.update_many(
        {"user_id": user_id, "read": False}, {"$set": {"read": True}}
    )
