"""Schémas Pydantic — salons (création, lecture, membres, clés enveloppées)."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.schemas.validation import valid_base64


class RoomCreate(BaseModel):
    """Corps de ``POST /api/rooms``."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=64)


class Room(BaseModel):
    """Représentation d'un salon."""

    id: str
    name: str
    owner_id: str
    created_at: str


class MemberPublic(BaseModel):
    """Membre d'un salon : identité, clé publique (jamais de hash), présence
    et profil public personnalisable (``display_name``/``about``, optionnels)."""

    id: str
    username: str
    public_key: str
    online: bool = False
    display_name: str | None = None
    about: str | None = None


class RoomKeyView(BaseModel):
    """Réponse de ``GET /api/rooms/{room_id}/keys`` (lecture seule).

    Renvoie la copie de la clé de salon enveloppée à destination de
    l'utilisateur courant — jamais celle d'un autre membre, jamais de clé en
    clair. ``wrapped_key`` vaut ``None`` tant qu'aucune copie n'a été posée
    à son nom (200, pas d'erreur).
    """

    room_id: str
    wrapped_key: str | None


class KeyWrapRequest(BaseModel):
    """Corps de ``POST /api/rooms/{room_id}/keys`` (clé de salon enveloppée)."""

    model_config = ConfigDict(extra="forbid")

    target_user_id: str = Field(min_length=1, max_length=64)
    wrapped_key: str = Field(min_length=1, max_length=1024)

    @field_validator("wrapped_key")
    @classmethod
    def _check_wrapped_key(cls, value: str) -> str:
        return valid_base64(value)
