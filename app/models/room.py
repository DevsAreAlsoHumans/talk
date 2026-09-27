from datetime import datetime

from pydantic import BaseModel, Field

from app.models.attachment import AttachmentPublic
from app.models.user import PeerPublic


class RoomCreate(BaseModel):
    """Cible d'un salon DM : pseudo + discriminant façon Discord."""

    username: str
    discriminator: str = Field(pattern=r"^\d{4}$")


class GroupRoomCreate(BaseModel):
    """Nom d'un nouveau salon de groupe."""

    name: str = Field(min_length=1, max_length=64)


class RoomMemberCreate(BaseModel):
    """Cible d'un ajout de membre à un salon de groupe : pseudo + discriminant."""

    username: str
    discriminator: str = Field(pattern=r"^\d{4}$")


class MemberRoleUpdate(BaseModel):
    """Nouveau rôle attribué à un membre (par le owner uniquement)."""

    role: str = Field(pattern=r"^(admin|member)$")


class RoomMemberPublic(BaseModel):
    """Membre d'un salon de groupe, avec son rôle."""

    user: PeerPublic
    role: str


class RoomPublic(BaseModel):
    """Salon exposé côté client : soit un DM (`peer`), soit un groupe (`name` + `members`)."""

    id: str
    type: str
    peer: PeerPublic | None = None
    name: str | None = None
    members: list[RoomMemberPublic] | None = None
    key_epoch: int | None = None


class MessageCreate(BaseModel):
    """Message chiffré côté client, jamais de contenu en clair."""

    ciphertext: str
    iv: str
    attachment_id: str | None = None
    key_epoch: int | None = None


class MessagePublic(BaseModel):
    """Message tel que renvoyé par l'API (toujours chiffré)."""

    id: str
    room_id: str
    sender_id: str
    ciphertext: str
    iv: str
    attachment: AttachmentPublic | None = None
    key_epoch: int | None = None
    created_at: datetime
