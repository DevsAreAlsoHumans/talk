"""Schémas de validation des entrées et de représentation des sorties.

Les schémas d'entrée interdisent tout champ supplémentaire (`extra="forbid"`) et
attribuent un type `str` strict aux identifiants : un objet JSON est donc rejeté
par le validateur avant d'atteindre MongoDB, ce qui ferme la porte à l'injection
d'opérateurs NoSQL (`{"$ne": null}`, `{"$regex": ...}`).
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

USERNAME_PATTERN = re.compile(r"^[a-z0-9_]{3,32}$")
MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 256

_USERNAME_ERROR = "Le nom d'utilisateur doit faire 3 à 32 caractères parmi a-z, 0-9 et _."


def normalize_username(value: str) -> str:
    """Normalise un nom d'utilisateur pour rendre l'unicité insensible à la casse."""
    return value.strip().lower()


class RegisterIn(BaseModel):
    """Corps attendu pour l'inscription."""

    model_config = ConfigDict(extra="forbid")

    username: str
    password: str = Field(min_length=MIN_PASSWORD_LENGTH, max_length=MAX_PASSWORD_LENGTH)

    @field_validator("username")
    @classmethod
    def _validate_username(cls, value: str) -> str:
        normalized = normalize_username(value)
        if not USERNAME_PATTERN.fullmatch(normalized):
            raise ValueError(_USERNAME_ERROR)
        return normalized


class LoginIn(BaseModel):
    """Corps attendu pour la connexion.

    Le nom d'utilisateur n'est volontairement pas validé par motif ici : un
    identifiant mal formé doit répondre 401 comme un identifiant inconnu, et
    non révéler par un 422 qu'un compte existe ou non.
    """

    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=MAX_PASSWORD_LENGTH)


class CsrfOut(BaseModel):
    """Réponse du bootstrap CSRF."""

    csrf_token: str


class UserPublic(BaseModel):
    """Représentation publique d'un utilisateur. Ne contient jamais le haché."""

    id: str
    username: str
    created_at: datetime

    @classmethod
    def from_document(cls, document: dict[str, Any]) -> UserPublic:
        return cls(
            id=str(document["_id"]),
            username=document["username"],
            created_at=document["created_at"],
        )
