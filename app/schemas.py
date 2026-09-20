"""Schémas Pydantic : validation stricte de toutes les entrées et sorties de l'API.

- ``extra="forbid"`` : tout champ inattendu est refusé ;
- ``strict=True`` : pas de coercition de type. Un objet JSON comme ``{"$ne": null}``
  glissé à la place d'une chaîne est rejeté (injection NoSQL / opérateurs) ;
- formats base64 et clés publiques vérifiés (longueurs exactes, point sur la courbe).
"""

import base64
import binascii
from typing import Annotated, Literal
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric import ec
from pydantic import AfterValidator, BaseModel, ConfigDict, StringConstraints, model_validator

USERNAME_PATTERN = r"^[a-z0-9_]{3,32}$"
ROOM_NAME_PATTERN = r"^[^\x00-\x1f\x7f<>]{1,50}$"
# Texte libre (surnom, biographie) : pas de caractères de contrôle ni de balisage.
TEXT_PATTERN = r"^[^\x00-\x1f\x7f<>]*$"

IV_BYTES = 12
AUTH_SECRET_BYTES = 32
PUBLIC_KEY_BYTES = 65  # point non compressé P-256 : 0x04 || X || Y
WRAPPED_ROOM_KEY_BYTES = 32 + 16  # clé de salon AES-256 + tag GCM
GCM_TAG_BYTES = 16
MAX_PLAINTEXT_BYTES = 8192  # messages texte (DISCORD-like, raisonnable)
MAX_MEDIA_BYTES = 2 * 1024 * 1024  # images et messages vocaux : 2 Mo de texte clair chiffré
MAX_AVATAR_BYTES = 512 * 1024  # avatar redimensionné côté navigateur, 512 Ko max
MIN_AVATAR_BYTES = 32  # un avatar est une vraie image : on refuse les bouts de données minuscules

DISPLAY_NAME_MAX = 32
BIO_MAX = 200

MIME_PATTERN = r"^[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+$"

DisplayName = Annotated[
    str, StringConstraints(strip_whitespace=True, max_length=DISPLAY_NAME_MAX, pattern=TEXT_PATTERN)
]
Bio = Annotated[str, StringConstraints(strip_whitespace=True, max_length=BIO_MAX, pattern=TEXT_PATTERN)]
Mime = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=3, max_length=64, pattern=MIME_PATTERN)
]
Kind = Literal["text", "image", "voice"]


def _decode_base64(value: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("base64 invalide") from exc


def _base64_type(*, min_bytes: int, max_bytes: int, extra_check=None):
    max_chars = 4 * ((max_bytes + 2) // 3)

    def check(value: str) -> str:
        raw = _decode_base64(value)
        if not min_bytes <= len(raw) <= max_bytes:
            raise ValueError("longueur invalide")
        if extra_check is not None:
            extra_check(raw)
        return value

    return Annotated[str, StringConstraints(max_length=max_chars), AfterValidator(check)]


def _check_p256_point(raw: bytes) -> None:
    try:
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)
    except ValueError as exc:
        raise ValueError("clé publique invalide") from exc


Username = Annotated[str, StringConstraints(pattern=USERNAME_PATTERN)]
RoomName = Annotated[str, StringConstraints(pattern=ROOM_NAME_PATTERN)]
AuthSecret = _base64_type(min_bytes=AUTH_SECRET_BYTES, max_bytes=AUTH_SECRET_BYTES)
PublicKey = _base64_type(
    min_bytes=PUBLIC_KEY_BYTES, max_bytes=PUBLIC_KEY_BYTES, extra_check=_check_p256_point
)
EncryptedPrivateKey = _base64_type(min_bytes=IV_BYTES + GCM_TAG_BYTES + 1, max_bytes=512)
Iv = _base64_type(min_bytes=IV_BYTES, max_bytes=IV_BYTES)
WrappedKeyBytes = _base64_type(min_bytes=WRAPPED_ROOM_KEY_BYTES, max_bytes=WRAPPED_ROOM_KEY_BYTES)
Ciphertext = _base64_type(min_bytes=GCM_TAG_BYTES + 1, max_bytes=MAX_PLAINTEXT_BYTES + GCM_TAG_BYTES)
MediaCiphertext = _base64_type(min_bytes=GCM_TAG_BYTES + 1, max_bytes=MAX_MEDIA_BYTES + GCM_TAG_BYTES)
AvatarCiphertext = _base64_type(
    min_bytes=MIN_AVATAR_BYTES + GCM_TAG_BYTES, max_bytes=MAX_AVATAR_BYTES + GCM_TAG_BYTES
)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


# ---------- Entrées ----------


class RegisterRequest(StrictModel):
    username: Username
    auth_secret: AuthSecret
    public_key: PublicKey
    encrypted_private_key: EncryptedPrivateKey


class LoginRequest(StrictModel):
    username: Username
    auth_secret: AuthSecret


class WrappedRoomKey(StrictModel):
    """Clé de salon chiffrée pour un membre (ECDH éphémère + AES-GCM)."""

    ephemeral_public_key: PublicKey
    iv: Iv
    wrapped_key: WrappedKeyBytes


class CreateRoomRequest(StrictModel):
    name: RoomName
    wrapped_key: WrappedRoomKey


class AddMemberRequest(StrictModel):
    username: Username
    wrapped_key: WrappedRoomKey


class SendMessageRequest(StrictModel):
    kind: Kind = "text"
    mime: Mime | None = None
    iv: Iv
    ciphertext: str

    @model_validator(mode="after")
    def _constrain_by_kind(self) -> "SendMessageRequest":
        """Le même schéma sert au texte et aux médias : les tailles dépendent du type.

        Un message texte reste limité à 8 Ko (taille raisonnable pour du texte) ; images
        et messages vocaux vont jusqu'à 2 Mo. Quel que soit le type, le contenu est toujours
        un texte chiffré en base64 : le serveur ne peut pas le lire.
        """
        raw = _decode_base64(self.ciphertext)
        if len(raw) < GCM_TAG_BYTES + 1:
            raise ValueError("message chiffré trop court")
        if self.kind == "text":
            if self.mime is not None:
                raise ValueError("mime réservé aux médias")
            if len(raw) > MAX_PLAINTEXT_BYTES + GCM_TAG_BYTES:
                raise ValueError("message texte trop long")
        else:
            if self.mime is None:
                raise ValueError("mime requis pour un média")
            if len(raw) > MAX_MEDIA_BYTES + GCM_TAG_BYTES:
                raise ValueError("média trop volumineux")
        return self


class UpdateProfileRequest(StrictModel):
    display_name: DisplayName
    bio: Bio


class AvatarRequest(StrictModel):
    iv: Iv
    ciphertext: AvatarCiphertext


class AvatarEnvelope(StrictModel):
    """Avatar d'un membre, chiffré avec la clé du salon : seul un membre peut regarder."""

    iv: Iv
    ciphertext: str


# ---------- Sorties ----------


class UserPublic(BaseModel):
    id: UUID
    username: str
    public_key: str


class UserSelf(UserPublic):
    display_name: str
    bio: str
    encrypted_private_key: str


class MemberSummary(UserPublic):
    """Membre d'un salon : ajoute son profil, sans jamais exposer ses clés."""

    display_name: str
    bio: str


class LoginResponse(BaseModel):
    user: UserSelf
    csrf_token: str


class CsrfResponse(BaseModel):
    csrf_token: str


class RoomSummary(BaseModel):
    id: UUID
    name: str
    owner_id: UUID
    created_at: str
    member_count: int


class RoomDetail(BaseModel):
    id: UUID
    name: str
    owner_id: UUID
    created_at: str
    members: list[MemberSummary]
    wrapped_key: WrappedRoomKey
    avatars: dict[str, AvatarEnvelope]
    online: dict[str, bool]


class MessageOut(BaseModel):
    id: UUID
    seq: int
    room_id: UUID
    sender_id: UUID
    sender_username: str
    kind: str
    mime: str | None
    iv: str
    ciphertext: str
    created_at: str


class MessagePage(BaseModel):
    messages: list[MessageOut]
    has_more: bool
