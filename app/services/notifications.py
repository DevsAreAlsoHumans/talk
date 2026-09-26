from datetime import UTC, datetime
from typing import Any

from app.db.mongo import db
from app.db.redis_client import redis_client
from app.models.notification import NotificationPublic
from app.services.realtime import notification_channel


def to_public(document: dict[str, Any]) -> NotificationPublic:
    return NotificationPublic(
        id=str(document["_id"]),
        type=document["type"],
        payload=document["payload"],
        read=document["read"],
        created_at=document["created_at"],
    )


async def create_notification(
    user_id: str, notification_type: str, payload: dict[str, Any]
) -> NotificationPublic:
    """Enregistre une notification et la diffuse en temps réel à son destinataire."""
    document: dict[str, Any] = {
        "user_id": user_id,
        "type": notification_type,
        "payload": payload,
        "read": False,
        "created_at": datetime.now(UTC),
    }
    result = await db.notifications.insert_one(document)
    document["_id"] = result.inserted_id

    notification = to_public(document)
    await redis_client.publish(notification_channel(user_id), notification.model_dump_json())
    return notification
