import re
import unicodedata
from typing import Any, Literal, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.security import InvalidBase64Error, decode_base64url

USERNAME_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{1,30}[a-z0-9])$")
CONTROL_CHARACTERS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


class APIModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


def normalize_username(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value).casefold()
    if not USERNAME_PATTERN.fullmatch(normalized):
        raise ValueError(
            "Le nom d'utilisateur doit contenir 3 à 32 caractères parmi a-z, 0-9, '.', '_' et '-'"
        )
    return normalized


def validate_display_name(value: str) -> str:
    normalized = " ".join(unicodedata.normalize("NFKC", value).split())
    if CONTROL_CHARACTERS.search(normalized):
        raise ValueError("Le nom affiché contient un caractère non autorisé")
    return normalized


def validate_password(value: str) -> str:
    if CONTROL_CHARACTERS.search(value):
        raise ValueError("Le mot de passe contient un caractère non autorisé")
    return value


class PublicJWK(APIModel):
    kty: Literal["RSA"]
    alg: Literal["RSA-OAEP-256"]
    use: Literal["enc"]
    n: str = Field(min_length=300, max_length=1024)
    e: str = Field(min_length=2, max_length=16)
    ext: Literal[True]
    key_ops: list[Literal["encrypt"]] = Field(min_length=1, max_length=1)
    kid: Optional[UUID] = None

    @model_validator(mode="after")
    def validate_encoding(self) -> "PublicJWK":
        try:
            modulus_bytes = decode_base64url(self.n)
            exponent_bytes = decode_base64url(self.e)
        except InvalidBase64Error as exc:
            raise ValueError("La clé publique RSA contient des données invalides") from exc

        modulus = int.from_bytes(modulus_bytes, "big")
        exponent = int.from_bytes(exponent_bytes, "big")
        modulus_bits = modulus.bit_length()
        if modulus_bytes[0] == 0 or not 2048 <= modulus_bits <= 4096 or modulus % 2 == 0:
            raise ValueError("Le module RSA doit être impair et faire entre 2048 et 4096 bits")
        if exponent != 65537:
            raise ValueError("L'exposant public RSA doit être 65537")
        return self


class IdentityKeyInput(APIModel):
    key_id: UUID
    device_name: str = Field(min_length=1, max_length=64)
    public_key: PublicJWK

    @model_validator(mode="after")
    def bind_key_id(self) -> "IdentityKeyInput":
        if self.public_key.kid is None:
            self.public_key.kid = self.key_id
        elif self.public_key.kid != self.key_id:
            raise ValueError("Le kid de la clé publique doit correspondre à key_id")
        return self

    @field_validator("device_name")
    @classmethod
    def clean_device_name(cls, value: str) -> str:
        cleaned = " ".join(value.split())
        if CONTROL_CHARACTERS.search(cleaned):
            raise ValueError("Le nom d'appareil contient un caractère non autorisé")
        return cleaned


class RegisterRequest(APIModel):
    username: str = Field(min_length=3, max_length=32)
    display_name: str = Field(min_length=1, max_length=32)
    password: str = Field(min_length=12, max_length=128)
    identity_key: IdentityKeyInput

    @field_validator("username")
    @classmethod
    def clean_username(cls, value: str) -> str:
        return normalize_username(value)

    @field_validator("display_name")
    @classmethod
    def clean_display_name(cls, value: str) -> str:
        return validate_display_name(value)

    @field_validator("password")
    @classmethod
    def clean_password(cls, value: str) -> str:
        return validate_password(value)


class LoginRequest(APIModel):
    username: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=1, max_length=128)

    @field_validator("username")
    @classmethod
    def clean_username(cls, value: str) -> str:
        return normalize_username(value)


class KeyEnvelopeInput(APIModel):
    recipient_id: UUID
    key_id: UUID
    algorithm: Literal["RSA-OAEP-256"]
    wrapped_key: str = Field(min_length=300, max_length=800)
    key_version: int = Field(ge=1, le=1_000_000)

    @field_validator("wrapped_key")
    @classmethod
    def validate_wrapped_key(cls, value: str) -> str:
        try:
            decoded = decode_base64url(value)
        except InvalidBase64Error as exc:
            raise ValueError("La clé de salon enveloppée n'est pas valide") from exc
        if not 256 <= len(decoded) <= 512:
            raise ValueError("La clé de salon enveloppée a une taille RSA invalide")
        return value


class UsernameInvite(APIModel):
    username: str = Field(min_length=3, max_length=32)

    @field_validator("username")
    @classmethod
    def clean_username(cls, value: str) -> str:
        return normalize_username(value)


class RoomCreateRequest(APIModel):
    name: str = Field(min_length=1, max_length=48)
    channel_name: str = Field(min_length=1, max_length=32)
    invites: list[UsernameInvite] = Field(default_factory=list, max_length=20)
    key_envelopes: list[KeyEnvelopeInput] = Field(min_length=1, max_length=1000)

    @field_validator("name", "channel_name")
    @classmethod
    def clean_name(cls, value: str) -> str:
        cleaned = " ".join(value.split())
        if CONTROL_CHARACTERS.search(cleaned):
            raise ValueError("Le nom contient un caractère non autorisé")
        return cleaned


class RoomMemberRequest(APIModel):
    username: str = Field(min_length=3, max_length=32)
    key_envelopes: list[KeyEnvelopeInput] = Field(min_length=1, max_length=200)

    @field_validator("username")
    @classmethod
    def clean_username(cls, value: str) -> str:
        return normalize_username(value)


class RoomKeyShareRequest(APIModel):
    key_envelopes: list[KeyEnvelopeInput] = Field(min_length=1, max_length=1000)


class RoomKeyRotateRequest(RoomKeyShareRequest):
    pass


class ChannelCreateRequest(APIModel):
    name: str = Field(min_length=1, max_length=32)

    @field_validator("name")
    @classmethod
    def clean_name(cls, value: str) -> str:
        cleaned = " ".join(value.split())
        if CONTROL_CHARACTERS.search(cleaned):
            raise ValueError("Le nom du salon contient un caractère non autorisé")
        return cleaned


class MessageCreateRequest(APIModel):
    client_id: UUID
    algorithm: Literal["AES-GCM-256"]
    key_version: int = Field(ge=1, le=1_000_000)
    ciphertext: str = Field(min_length=16, max_length=70_000)
    nonce: str = Field(min_length=16, max_length=24)

    @field_validator("ciphertext")
    @classmethod
    def validate_ciphertext(cls, value: str) -> str:
        try:
            decoded = decode_base64url(value)
        except InvalidBase64Error as exc:
            raise ValueError("Le contenu chiffré n'est pas du Base64URL valide") from exc
        if len(decoded) < 16 or len(decoded) > 50_000:
            raise ValueError("Le message chiffré a une taille invalide")
        return value

    @field_validator("nonce")
    @classmethod
    def validate_nonce(cls, value: str) -> str:
        try:
            decode_base64url(value, expected_bytes=12)
        except InvalidBase64Error as exc:
            raise ValueError("Le nonce AES-GCM doit faire 12 octets") from exc
        return value


class ErrorDetail(APIModel):
    code: str
    message: str


class ErrorResponse(APIModel):
    error: ErrorDetail
    details: Optional[list[dict[str, Any]]] = None
