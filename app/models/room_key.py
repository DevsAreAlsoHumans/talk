from pydantic import BaseModel


class RoomKeyEntry(BaseModel):
    """Clé de salon enveloppée pour un membre précis (ECDH + AES-GCM, côté client)."""

    member_id: str
    wrapped_key: str
    wrapped_key_iv: str


class RoomKeyRotate(BaseModel):
    """Nouvelle rotation de clé de salon : une entrée par membre actuel, sans exception."""

    wrapper_public_key: str
    entries: list[RoomKeyEntry]


class RoomKeyPublic(BaseModel):
    """Entrée de clé de salon telle que récupérée par son destinataire."""

    epoch: int
    wrapped_key: str
    wrapped_key_iv: str
    wrapper_public_key: str
