"""Modèles validés strictement par Pydantic — zone de filtrage des entrées.

Aucun champ « brut » : tout est assaini en amont, donc pas d'injection possible
dans le pipeline (NoSQL, templating, logs).
"""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .db import utcnow


class UserRegister(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    # Longueur bornée + regex : bloque les payloads monstrueux (DoS) et les
    # caractères exploitables (espacements, caractères de contrôle).
    username: str = Field(min_length=3, max_length=32, pattern=r"^[A-Za-z0-9_.]+$")
    password: str = Field(min_length=10, max_length=128)

    @field_validator("password")
    @classmethod
    def _password_not_username(cls, password: str, info) -> str:
        # Interdiction du mot de passe == pseudo : top1 des mots de passe faibles.
        if info.data.get("username") and password.lower() in {
            info.data["username"].lower(),
            "password",
            "1234567890",
        }:
            raise ValueError("mot de passe trop faible")
        return password


class UserLogin(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    username: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=1, max_length=128)


class UserPublic(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    username: str
    created_at: datetime


class _StrictName(BaseModel):
    """Nom (« salon » ou « canal ») assaini : borné, sans contrôle ni
    mot réservé — même filet que pour les salons."""

    name: str = Field(min_length=1, max_length=64)

    @field_validator("name")
    @classmethod
    def _no_control_chars(cls, name: str) -> str:
        # Interdire retour-chariot / séparateurs : neutralise l'injection
        # de commandes dans les logs et le rendu web.
        if any(ord(c) < 32 for c in name):
            raise ValueError("caractères interdits dans le nom")
        if name.strip().upper() in {"ADMIN", "SYSTEM", "ROOT"}:
            raise ValueError("nom réservé")
        return name


class RoomCreate(_StrictName):
    model_config = ConfigDict(str_strip_whitespace=True)


class ChannelCreate(_StrictName):
    model_config = ConfigDict(str_strip_whitespace=True)


class RoomPublic(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    owner_id: str
    created_at: datetime


class ChannelPublic(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    created_at: datetime


class _UserOut:
    """Helper de sérialisation — on n'expose JAMAIS password_hash."""

    @staticmethod
    def of(user: dict) -> UserPublic:
        return UserPublic(
            id=str(user["_id"]),
            username=user["username"],
            created_at=user.get("created_at") or utcnow(),
        )


class PublicKeyPayload(BaseModel):
    """Clé publique ECDH (P-256, point raw en base64) — matériel public."""

    public_key: str = Field(min_length=1, max_length=256)


class InvitePayload(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    username: str = Field(min_length=3, max_length=32, pattern=r"^[A-Za-z0-9_.]+$")


class PeerPayload(BaseModel):
    """Interlocuteur visé (invitation ami, message privé) — mêmes règles que
    `InvitePayload` : pseudo assaini, jamais un opérateur NoSQL ni du brut."""

    model_config = ConfigDict(str_strip_whitespace=True)

    peer: str = Field(min_length=3, max_length=32, pattern=r"^[A-Za-z0-9_.]+$")


class FriendshipOut(BaseModel):
    """Une relation d'amitié vue depuis le demandeur (liste/sidebar)."""

    username: str
    status: str  # "pending" | "accepted"
    requested_by: str


class KeyBlob(BaseModel):
    """Blob opaque : clé de salon enveloppée (ou message) — jamais déchiffré."""

    v: int = Field(default=1, ge=1, le=1)
    iv: str = Field(min_length=1, max_length=64)
    ct: str = Field(min_length=1, max_length=4096)


class RoomKeyShare(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    to: str = Field(min_length=3, max_length=32, pattern=r"^[A-Za-z0-9_.]+$")
    blob: KeyBlob


class MemberPublic(BaseModel):
    username: str
    public_key: str | None = None


class RoomMembers(BaseModel):
    owner_id: str
    members: list[MemberPublic]


class MessageOut(BaseModel):
    """Historique : blobs chiffrés avec leur séquence mono- croissante."""

    n: int
    sender: str
    ts: datetime
    payload: str
