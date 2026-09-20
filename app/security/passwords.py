"""Hachage des mots de passe avec Argon2id.

Argon2id est l'algorithme recommandé par l'énoncé : résistant aux attaques GPU,
et la vérification effectuée par ``argon2-cffi`` est à temps constant
(l'implémentation est fournie par la bibliothèque).
"""

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    """Hache un mot de passe en clair et renvoie son encodage Argon2id."""
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Vérifie un mot de passe contre un hash Argon2id (temps constant).

    Toute erreur (hash invalide, format inconnu) est traitée comme un échec
    de vérification — aucune information n'est exposée à l'appelant.
    """
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, InvalidHashError):
        return False
