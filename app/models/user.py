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
    """Représentation d'un utilisateur exposée par l'API (jamais le hash du mot de passe)."""

    id: str
    username: str
    discriminator: str
    email: EmailStr
