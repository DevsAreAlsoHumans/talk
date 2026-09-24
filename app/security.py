import base64
import hashlib
import hmac
import re
import secrets
from typing import Optional

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

_password_hasher = PasswordHasher()
_DUMMY_PASSWORD_HASH = _password_hasher.hash(secrets.token_urlsafe(32))
_BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")


class InvalidBase64Error(ValueError):
    """Levée lorsque la valeur reçue n'est pas du Base64URL strict."""


def hash_password(password: str) -> str:
    return _password_hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    """Vérifie un mot de passe en masquant les erreurs de format du hash."""

    try:
        return _password_hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def verify_password_or_dummy(password_hash: Optional[str], password: str) -> bool:
    """Conserve un coût comparable pour un nom d'utilisateur inconnu."""

    try:
        return _password_hasher.verify(password_hash or _DUMMY_PASSWORD_HASH, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def password_needs_rehash(password_hash: str) -> bool:
    try:
        return _password_hasher.check_needs_rehash(password_hash)
    except InvalidHashError:
        return False


def generate_token(byte_length: int = 32) -> str:
    return secrets.token_urlsafe(byte_length)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def constant_time_equal(left: str, right: str) -> bool:
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


def decode_base64url(value: str, *, expected_bytes: Optional[int] = None) -> bytes:
    """Décode du Base64URL sans caractères superflus."""

    if not value or not _BASE64URL_RE.fullmatch(value):
        raise InvalidBase64Error("La valeur n'est pas du Base64URL valide")

    padding = "=" * ((4 - len(value) % 4) % 4)
    try:
        decoded = base64.b64decode(value + padding, altchars=b"-_", validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise InvalidBase64Error("La valeur n'est pas du Base64URL valide") from exc

    if expected_bytes is not None and len(decoded) != expected_bytes:
        raise InvalidBase64Error(f"La valeur doit faire exactement {expected_bytes} octets")
    return decoded


def encode_base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def split_display_name(value: str) -> tuple[str, str]:
    normalized = " ".join(value.split())
    return normalized, normalized.casefold()
