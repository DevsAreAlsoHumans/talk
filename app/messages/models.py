from datetime import datetime

from pydantic import BaseModel, Field

# Un message chiffré en base64 : ~4/3 de la taille en clair.
MAX_CIPHERTEXT = 16384


class MessageCreate(BaseModel):
    ciphertext: str = Field(..., min_length=1, max_length=MAX_CIPHERTEXT)
    iv: str = Field(..., min_length=1, max_length=64)
    channel_id: str | None = Field(default=None, max_length=64)


class MessageEdit(BaseModel):
    """Édition : le client rechiffre le nouveau texte avec un IV neuf.

    Le serveur ne peut pas « modifier » un message puisqu'il ne le lit pas ;
    il remplace simplement l'enveloppe chiffrée.
    """

    ciphertext: str = Field(..., min_length=1, max_length=MAX_CIPHERTEXT)
    iv: str = Field(..., min_length=1, max_length=64)


class MessageResponse(BaseModel):
    id: str
    salon_id: str
    channel_id: str | None = None
    sender_id: str
    sender_username: str
    ciphertext: str
    iv: str
    created_at: datetime
    edited_at: datetime | None = None
    deleted: bool = False


class MessagePage(BaseModel):
    """Page de messages avec curseur : évite de charger tout l'historique."""

    messages: list[MessageResponse]
    next_cursor: str | None = None
    has_more: bool = False
