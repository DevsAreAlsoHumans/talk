from typing import Any

from pydantic import BaseModel, EmailStr, Field


class UserRegister(BaseModel):
    """Données envoyées à l'inscription."""

    username: str = Field(min_length=3, max_length=32)
    email: EmailStr
    password: str


class UserLogin(BaseModel):
    """Données envoyées à la connexion."""

    email: EmailStr
    password: str


class UserPublic(BaseModel):
    """Représentation de l'utilisateur courant (endpoint /auth/me)."""

    id: str
    username: str
    discriminator: str
    email: EmailStr
    public_key: str | None = None


class PeerPublic(BaseModel):
    """Représentation d'un autre utilisateur, exposée via les salons/amis (jamais l'email)."""

    id: str
    username: str
    discriminator: str
    public_key: str | None = None

    @classmethod
    def from_document(cls, document: dict[str, Any]) -> "PeerPublic":
        return cls(
            id=str(document["_id"]),
            username=document["username"],
            discriminator=document["discriminator"],
            public_key=document.get("public_key"),
        )


class PublicKeyUpdate(BaseModel):
    """Clé publique E2E envoyée par le client (générée côté navigateur)."""

    public_key: str
