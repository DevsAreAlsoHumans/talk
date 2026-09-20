"""Schémas Pydantic — messages (uniquement ciphertext + nonce, en base64)."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.schemas.validation import valid_base64


class MessageCreate(BaseModel):
    """Corps de ``POST /api/rooms/{id}/messages``.

    Le serveur ne reçoit que du chiffré : nonce et ciphertext en base64.
    """

    model_config = ConfigDict(extra="forbid")

    nonce: str = Field(min_length=1, max_length=256)
    ciphertext: str = Field(min_length=1, max_length=4096)

    @field_validator("nonce", "ciphertext")
    @classmethod
    def _check_base64(cls, value: str) -> str:
        return valid_base64(value)


class Message(BaseModel):
    """Message envoyé par le serveur.

    ``seq`` est renvoyé par le serveur (score du sorted set) afin que le
    client puisse faire du polling/upsert incrémental avec ``?after=``.
    """

    id: str
    seq: int
    room_id: str
    author_id: str
    nonce: str
    ciphertext: str
    created_at: str
