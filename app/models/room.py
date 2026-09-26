from datetime import datetime

from pydantic import BaseModel, Field

from app.models.user import PeerPublic


class RoomCreate(BaseModel):
    """Cible d'un salon DM : pseudo + discriminant façon Discord."""

    username: str
    discriminator: str = Field(pattern=r"^\d{4}$")


class RoomPublic(BaseModel):
    """Salon exposé côté client (DM uniquement pour l'instant)."""

    id: str
    type: str
    peer: PeerPublic


class MessageCreate(BaseModel):
    """Message chiffré côté client, jamais de contenu en clair."""

    ciphertext: str
    iv: str


class MessagePublic(BaseModel):
    """Message tel que renvoyé par l'API (toujours chiffré)."""

    id: str
    room_id: str
    sender_id: str
    ciphertext: str
    iv: str
    created_at: datetime
