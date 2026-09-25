from datetime import datetime

from pydantic import BaseModel, Field


class SalonCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    encrypted_salon_key: str = Field(..., min_length=1, max_length=4096)


class DirectCreate(BaseModel):
    """Conversation privée à deux.

    Le créateur chiffre la même clé AES deux fois : une fois avec sa propre
    clé publique, une fois avec celle du destinataire.
    """

    username: str = Field(..., min_length=3, max_length=30)
    encrypted_salon_key_self: str = Field(..., min_length=1, max_length=4096)
    encrypted_salon_key_other: str = Field(..., min_length=1, max_length=4096)


class MemberAdd(BaseModel):
    user_id: str = Field(..., min_length=1, max_length=64)
    encrypted_salon_key: str = Field(..., min_length=1, max_length=4096)


class RekeyEntry(BaseModel):
    user_id: str = Field(..., min_length=1, max_length=64)
    encrypted_salon_key: str = Field(..., min_length=1, max_length=4096)


class MemberRemove(BaseModel):
    """Retrait d'un membre + redistribution d'une nouvelle clé de salon.

    La rotation garantit qu'un ancien membre ne peut plus déchiffrer
    les messages postés après son départ (forward secrecy).
    """

    rekey: list[RekeyEntry] = Field(default_factory=list, max_length=200)


class ChannelCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=50, pattern=r"^[a-z0-9À-ÿ][a-z0-9À-ÿ -]*$")


class ChannelResponse(BaseModel):
    id: str
    name: str
    created_at: datetime


class MemberResponse(BaseModel):
    user_id: str
    username: str
    encrypted_salon_key: str
    # Empreinte de la clé publique du membre, à comparer de vive voix.
    fingerprint: str | None = None


class SalonResponse(BaseModel):
    id: str
    name: str
    owner_id: str
    members: list[MemberResponse]
    channels: list[ChannelResponse]
    key_version: int = 1
    is_direct: bool = False
    created_at: datetime
