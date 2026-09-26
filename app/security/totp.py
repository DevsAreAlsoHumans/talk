import secrets

import pyotp

from app.db.redis_client import redis_client

_PENDING_LOGIN_TTL_SECONDS = 5 * 60
_PENDING_LOGIN_PREFIX = "pending_2fa:"


def generate_secret() -> str:
    """Génère un secret TOTP aléatoire (à confirmer avant activation réelle)."""
    return pyotp.random_base32()


def totp_uri(secret: str, email: str) -> str:
    """URI `otpauth://` affichée/scannée côté client (pas de rendu QR serveur)."""
    return pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name="Talk")


def verify_code(secret: str, code: str) -> bool:
    """Vérifie un code TOTP à 6 chiffres, avec une petite tolérance d'horloge."""
    return pyotp.TOTP(secret).verify(code, valid_window=1)


async def create_pending_login(user_id: str) -> str:
    """Crée un jeton de connexion en attente du code 2FA (courte durée de vie)."""
    token = secrets.token_urlsafe(32)
    await redis_client.set(
        f"{_PENDING_LOGIN_PREFIX}{token}", user_id, ex=_PENDING_LOGIN_TTL_SECONDS
    )
    return token


async def get_pending_login(token: str) -> str | None:
    """Consulte un jeton de connexion en attente sans le consommer (retry possible)."""
    return await redis_client.get(f"{_PENDING_LOGIN_PREFIX}{token}")


async def consume_pending_login(token: str) -> None:
    """Supprime un jeton de connexion en attente après vérification réussie du code."""
    await redis_client.delete(f"{_PENDING_LOGIN_PREFIX}{token}")
