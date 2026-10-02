"""Schémas Pydantic : tout ce qui arrive dans l'API est validé ici."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

# Base64 version URL, rien d'autre
BASE64_URL = r"^[A-Za-z0-9_-]+$"


class StrictModel(BaseModel):
    # Un champ en trop = requête refusée
    model_config = ConfigDict(extra="forbid")


class Credentials(StrictModel):
    username: str = Field(pattern=r"^[A-Za-z0-9_]{3,24}$")
    password: str = Field(min_length=10, max_length=128)


class Named(StrictModel):
    # Les espaces autour du nom sont enlevés (pas pour le mot de passe)
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    name: str = Field(min_length=1, max_length=40)


# Le serveur reçoit seulement le message chiffré, jamais le texte
class EncryptedMessage(StrictModel):
    version: Literal[1]
    # 12 octets en base64 = 16 caractères
    nonce: str = Field(min_length=16, max_length=16, pattern=BASE64_URL)
    ciphertext: str = Field(min_length=24, max_length=12000, pattern=BASE64_URL)
