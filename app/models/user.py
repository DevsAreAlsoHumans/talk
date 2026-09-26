from typing import Any

from pydantic import BaseModel, EmailStr, Field, computed_field


class UserRegister(BaseModel):
    """Données envoyées à l'inscription."""

    username: str = Field(min_length=3, max_length=32)
    email: EmailStr
    password: str


class UserLogin(BaseModel):
    """Données envoyées à la connexion."""

    email: EmailStr
    password: str


class AvatarPublic(BaseModel):
    """Avatar d'un utilisateur : seed Dicebear (pas de stockage) ou image uploadée."""

    type: str  # "dicebear" ou "upload"
    value: str

    @computed_field
    @property
    def url(self) -> str:
        if self.type == "dicebear":
            return f"https://api.dicebear.com/9.x/identicon/svg?seed={self.value}"
        return f"/users/avatars/{self.value}"

    @classmethod
    def from_document(cls, avatar: dict[str, Any] | None) -> "AvatarPublic | None":
        if avatar is None:
            return None
        return cls(type=avatar["type"], value=avatar["value"])


class UserPublic(BaseModel):
    """Représentation de l'utilisateur courant (endpoint /auth/me)."""

    id: str
    username: str
    discriminator: str
    email: EmailStr
    public_key: str | None = None
    avatar: AvatarPublic | None = None

    @classmethod
    def from_document(cls, document: dict[str, Any]) -> "UserPublic":
        return cls(
            id=str(document["_id"]),
            username=document["username"],
            discriminator=document["discriminator"],
            email=document["email"],
            public_key=document.get("public_key"),
            avatar=AvatarPublic.from_document(document.get("avatar")),
        )


class PeerPublic(BaseModel):
    """Représentation d'un autre utilisateur, exposée via les salons/amis (jamais l'email)."""

    id: str
    username: str
    discriminator: str
    public_key: str | None = None
    avatar: AvatarPublic | None = None

    @classmethod
    def from_document(cls, document: dict[str, Any]) -> "PeerPublic":
        return cls(
            id=str(document["_id"]),
            username=document["username"],
            discriminator=document["discriminator"],
            public_key=document.get("public_key"),
            avatar=AvatarPublic.from_document(document.get("avatar")),
        )


class PublicKeyUpdate(BaseModel):
    """Clé publique E2E envoyée par le client (générée côté navigateur)."""

    public_key: str


class AvatarDicebearUpdate(BaseModel):
    """Seed Dicebear choisie par l'utilisateur pour son avatar."""

    seed: str = Field(min_length=1, max_length=64)
