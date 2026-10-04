"""Schémas Pydantic : tout ce qui arrive dans l'API est validé ici."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

# Base64 version URL, rien d'autre
BASE64_URL = r"^[A-Za-z0-9_-]+$"
# Format autorisé pour les identifiants
USERNAME = r"^[A-Za-z0-9_]{3,24}$"


class StrictModel(BaseModel):
    # Un champ en trop = requête refusée
    model_config = ConfigDict(extra="forbid")


class Credentials(StrictModel):
    username: str = Field(pattern=USERNAME)
    password: str = Field(min_length=10, max_length=128)


# Clé publique RSA de l'utilisateur (format SPKI en base64). La clé privée reste dans le navigateur
class PublicKey(StrictModel):
    public_key: str = Field(min_length=100, max_length=1000, pattern=BASE64_URL)


class Named(StrictModel):
    # Les espaces autour du nom sont enlevés (pas pour le mot de passe)
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    name: str = Field(min_length=1, max_length=40)


# Nouveau salon : son nom + la clé du salon chiffrée avec MA clé publique
class NewServer(Named):
    wrapped_key: str = Field(min_length=100, max_length=1000, pattern=BASE64_URL)


# Ajout d'un membre : la clé du salon chiffrée avec SA clé publique
class NewMember(StrictModel):
    username: str = Field(pattern=USERNAME)
    wrapped_key: str = Field(min_length=100, max_length=1000, pattern=BASE64_URL)


# Le serveur reçoit seulement le message chiffré, jamais le texte
class EncryptedMessage(StrictModel):
    version: Literal[1]
    # 12 octets en base64 = 16 caractères
    nonce: str = Field(min_length=16, max_length=16, pattern=BASE64_URL)
    ciphertext: str = Field(min_length=24, max_length=12000, pattern=BASE64_URL)
