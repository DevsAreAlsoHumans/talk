"""Primitives sécurité : Argon2id, sessions signées, cookies.

Le serveur ne stocke que des hash — jamais de mots de passe en clair.
"""

import os
from datetime import UTC, datetime, timedelta
from hmac import compare_digest

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from .config import get_settings

# Argon2id : référence OWASP 2023. Sel aléatoire + mémoire/CPU coûteux.
# Paramètres par défaut de argon2-cffi (t=3, m=65536) > bcrypt en résistance GPU.
_hasher = PasswordHasher()

# Sérialiseur de session signé (HMAC-SHA1) — signature = preuve d'intégrité.
_session = URLSafeTimedSerializer(get_settings().jwt_secret, salt="talk-session")


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    try:
        # Argon2 effectue la comparaison de façon constante par construction.
        return _hasher.verify(hashed, password)
    except (VerificationError, ValueError):
        # Message unique : ne JAMAIS révéler si c'est le format qui échoue.
        return False


def create_session_token(payload: dict[str, str], expires_seconds: int | None = None) -> str:
    """Jetons à signature authentique : falsifier le payload = échec de vérif."""
    settings = get_settings()
    exp = expires_seconds or settings.jwt_expires_seconds
    data = {
        **payload,
        "exp": (datetime.now(UTC) + timedelta(seconds=exp)).timestamp(),
    }
    return _session.dumps(data)


def verify_session_token(token: str, max_age: int | None = None) -> dict | None:
    settings = get_settings()
    max_age = max_age or settings.jwt_expires_seconds
    try:
        # Signature vérifiée + horodatage anti-rejeu (expiration).
        return _session.loads(token, max_age=max_age)
    except (BadSignature, SignatureExpired):
        return None


def new_csrf_token() -> str:
    """32 octets CSPRNG (os.urandom) — imprévisible pour l'attaquant."""
    return os.urandom(32).hex()


def constant_time_eq(a: str, b: str) -> bool:
    """Comparaison à temps constant : évite l'oracle temporel."""
    return compare_digest(a.encode(), b.encode())


def cookie_params(*, http_only: bool) -> dict:
    """Prescription cohérente pour TOUS les cookies de session."""
    settings = get_settings()
    return {
        "secure": settings.cookie_secure,  # prod : HTTPS obligatoire
        "httponly": http_only,
        "samesite": settings.cookie_samesite,  # strict -> anti-CSRF de base
        "domain": settings.cookie_domain,
        "path": "/",
    }
