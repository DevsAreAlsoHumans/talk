"""Schémas Pydantic — messages (uniquement ciphertext + nonce, en base64)."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.schemas.validation import valid_base64

#: Plafond des pièces jointes chiffrées (en caractères base64) : 6 000 000 de
#: caractères ≈ 4,5 Mo décodés — le client limite lui-même l'envoi binaire à
#: 4 Mo, ce plafond serveur sert de garde-fou anti-abus.
MAX_ATTACHMENT_B64 = 6_000_000


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


class AttachmentCreate(BaseModel):
    """Corps de ``POST /api/rooms/{id}/attachments`` (image/GIF chiffrée).

    Contrat d'intégration frontend : ``kind`` doit valoir exactement
    ``"image"`` (``Literal["image"]``) ; ``mime`` est optionnel, au plus 64
    caractères et doit commencer par ``image/`` (sinon 422). À l'instar de
    ``MessageCreate``, le serveur ne reçoit que du chiffré : nonce et
    ciphertext en base64, le ciphertext étant plafonné à
    ``MAX_ATTACHMENT_B64`` caractères (≈ 4,5 Mo décodés).
    """

    model_config = ConfigDict(extra="forbid")

    kind: Literal["image"]
    mime: str | None = Field(default=None, max_length=64, pattern=r"^image/")
    nonce: str = Field(min_length=1, max_length=256)
    ciphertext: str = Field(min_length=1, max_length=MAX_ATTACHMENT_B64)

    @field_validator("nonce", "ciphertext")
    @classmethod
    def _check_base64(cls, value: str) -> str:
        return valid_base64(value)


class Message(BaseModel):
    """Message envoyé par le serveur.

    ``seq`` est renvoyé par le serveur (score du sorted set) afin que le
    client puisse faire du polling/upsert incrémental avec ``?after=``.

    ``kind`` et ``mime`` distinguent les pièces jointes des messages
    textuels ; leurs défauts (``"text"`` / ``None``) garantissent une réponse
    strictement inchangée pour les messages textuels v1.
    """

    id: str
    seq: int
    room_id: str
    author_id: str
    nonce: str
    ciphertext: str
    created_at: str
    kind: str = "text"
    mime: str | None = None
