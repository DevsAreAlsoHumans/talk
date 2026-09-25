"""Stockage des pièces jointes chiffrées.

Le contenu est déposé en binaire BSON plutôt qu'en base64 : la base y gagne
un tiers de place, et le document reste très en deçà de la limite MongoDB
de 16 Mo.

Une pièce jointe est téléversée **avant** le message qui la porte. Si le
message n'est finalement jamais envoyé, elle resterait orpheline : elle naît
donc avec une date d'expiration, effacée seulement lorsqu'un message la
référence. Un index TTL se charge du ménage.
"""

import base64
import binascii
from datetime import datetime, timedelta, timezone

from bson import Binary, ObjectId

from app.db import get_db

# Délai laissé au client pour envoyer le message qui référence la pièce jointe.
ORPHAN_TTL = timedelta(hours=1)


def decode_payload(ciphertext_b64: str) -> bytes | None:
    try:
        return base64.b64decode(ciphertext_b64, validate=True)
    except (ValueError, binascii.Error):
        return None


def encode_payload(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


async def store_attachment(
    salon_id: str,
    uploader_id: ObjectId,
    kind: str,
    raw: bytes,
    iv: str,
    duration_ms: int,
    mime: str,
) -> dict:
    db = get_db()
    now = datetime.now(timezone.utc)
    doc = {
        "salon_id": ObjectId(salon_id),
        "uploader_id": uploader_id,
        "kind": kind,
        "payload": Binary(raw),
        "iv": iv,
        "duration_ms": duration_ms,
        "mime": mime,
        "size": len(raw),
        "created_at": now,
        # Retirée dès qu'un message la référence.
        "expires_at": now + ORPHAN_TTL,
    }
    result = await db.attachments.insert_one(doc)
    doc["_id"] = result.inserted_id
    return doc


async def get_attachment(salon_id: str, attachment_id: str) -> dict | None:
    if not ObjectId.is_valid(attachment_id):
        return None
    db = get_db()
    return await db.attachments.find_one({"_id": ObjectId(attachment_id), "salon_id": ObjectId(salon_id)})


async def link_attachment(attachment_id: str, message_id: ObjectId) -> bool:
    """Rattache la pièce jointe à son message et lui retire son expiration."""
    if not ObjectId.is_valid(attachment_id):
        return False
    db = get_db()
    result = await db.attachments.update_one(
        {"_id": ObjectId(attachment_id), "message_id": {"$exists": False}},
        {"$set": {"message_id": message_id}, "$unset": {"expires_at": ""}},
    )
    return result.modified_count > 0


async def delete_for_message(message_id: ObjectId) -> None:
    """Supprimer un message emporte sa pièce jointe."""
    await get_db().attachments.delete_many({"message_id": message_id})


async def delete_for_user(user_id: ObjectId) -> None:
    await get_db().attachments.delete_many({"uploader_id": user_id})
