import re

from passlib.context import CryptContext

_pwd_context = CryptContext(schemes=["argon2"])

_MIN_LENGTH = 12


def hash_password(password: str) -> str:
    """Hash un mot de passe en clair avec Argon2."""
    return _pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Vérifie qu'un mot de passe en clair correspond au hash stocké."""
    return _pwd_context.verify(password, password_hash)


def validate_password_strength(password: str) -> str | None:
    """Retourne un message d'erreur si le mot de passe est trop faible, sinon None.

    Règle : au moins 12 caractères, une majuscule, une minuscule, un chiffre
    et un caractère spécial.
    """
    if len(password) < _MIN_LENGTH:
        return f"Le mot de passe doit contenir au moins {_MIN_LENGTH} caractères."
    if not re.search(r"[A-Z]", password):
        return "Le mot de passe doit contenir au moins une majuscule."
    if not re.search(r"[a-z]", password):
        return "Le mot de passe doit contenir au moins une minuscule."
    if not re.search(r"\d", password):
        return "Le mot de passe doit contenir au moins un chiffre."
    if not re.search(r"[^A-Za-z0-9]", password):
        return "Le mot de passe doit contenir au moins un caractère spécial."
    return None
