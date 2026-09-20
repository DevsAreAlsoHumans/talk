"""Hachage des secrets d'authentification avec Argon2id.

Le navigateur n'envoie jamais le mot de passe : il envoie un secret d'authentification
dérivé (PBKDF2 + HKDF, voir README). Le serveur le hache à son tour avec Argon2id, de
sorte qu'une fuite de la base ne permet pas de rejouer directement la connexion.
"""

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

# Paramètres par défaut d'argon2-cffi : Argon2id, profil RFC 9106 « low memory ».
_hasher = PasswordHasher()

# Hash factice utilisé quand l'utilisateur n'existe pas : la vérification prend alors le
# même temps que pour un vrai compte, ce qui empêche de deviner les comptes par le timing.
_DUMMY_HASH = _hasher.hash("secret-factice-pour-egaliser-les-temps")


def hash_secret(secret: str) -> str:
    return _hasher.hash(secret)


def verify_secret(stored_hash: str | None, candidate: str) -> bool:
    """Vérifie `candidate` en temps constant ; travaille même si `stored_hash` est None."""
    try:
        return _hasher.verify(stored_hash or _DUMMY_HASH, candidate) and stored_hash is not None
    except (VerificationError, InvalidHashError):
        return False
