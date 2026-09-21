"""Schémas Pydantic — module auth (inscription, connexion, réponse)."""

from __future__ import annotations

import base64
import binascii

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.serialization import load_der_public_key
from pydantic import BaseModel, ConfigDict, Field, field_validator

# Noms d'utilisateur : alphanumérique + `_ . -` (payload sûr pour les clés Redis).
USERNAME_PATTERN = r"^[a-zA-Z0-9_.-]+$"
# Une clé SPKI RSA-2048 fait ~294 octets ; on exige ≥ 270 octets décodés.
PUBLIC_KEY_MIN_RAW_BYTES = 270


def valid_public_key(value: str) -> str:
    """Valide une clé publique : base64 standard décodable + SPKI RSA-2048+.

    Retourne la chaîne inchangée ou lève ``ValueError`` (→ 422).
    """
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("public key is not valid base64") from exc
    if len(raw) < PUBLIC_KEY_MIN_RAW_BYTES:
        raise ValueError("public key too short (RSA-2048 minimum)")
    try:
        key = load_der_public_key(raw)
    except ValueError as exc:
        raise ValueError("public key is not a valid SPKI DER key") from exc
    if not isinstance(key, RSAPublicKey):
        raise ValueError("public key must be RSA")
    if key.key_size < 2048:
        raise ValueError("public RSA key must be at least 2048 bits")
    return value


class RegisterRequest(BaseModel):
    """Corps de ``POST /api/auth/register``."""

    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=3, max_length=32, pattern=USERNAME_PATTERN)
    password: str = Field(min_length=8, max_length=128)
    public_key: str = Field(min_length=44, max_length=1000)

    @field_validator("public_key")
    @classmethod
    def _check_public_key(cls, value: str) -> str:
        return valid_public_key(value)


class LoginRequest(BaseModel):
    """Corps de ``POST /api/auth/login``."""

    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=3, max_length=32, pattern=USERNAME_PATTERN)
    password: str = Field(min_length=1, max_length=128)


class ChangePasswordRequest(BaseModel):
    """Corps de ``POST /api/auth/change-password``."""

    model_config = ConfigDict(extra="forbid")

    old_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=8, max_length=128)


class UserPublic(BaseModel):
    """Utilisateur sous forme publique (jamais de hash de mot de passe).

    ``display_name`` et ``about`` sont de l'identité publique (comme le
    pseudo) : optionnels, ils n'existent pas pour les comptes antérieurs à
    leur introduction (rétro-compatibilité : `None`).
    """

    id: str
    username: str
    public_key: str
    created_at: str
    display_name: str | None = None
    about: str | None = None


class ProfileUpdate(BaseModel):
    """Corps de ``PATCH /api/me`` : profil public personnalisable.

    Ces champs sont **publics** (identité, comme le pseudo) : ils ne passent
    pas par le chiffrement E2E. Les espaces de tête/queue sont supprimés et
    une valeur vide (ou uniquement des espaces) est normalisée à ``None``
    (effacement du champ). ``extra="forbid"`` : un champ inconnu renvoie 422.
    """

    model_config = ConfigDict(extra="forbid")

    display_name: str | None = Field(default=None, max_length=32)
    about: str | None = Field(default=None, max_length=500)

    @field_validator("display_name", "about")
    @classmethod
    def _strip_blank(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        return value or None


class AuthResponse(BaseModel):
    """Réponse des routes register/login : user + nouveau token CSRF."""

    user: UserPublic
    csrf_token: str
