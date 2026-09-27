"""Hachage de mots de passe : scrypt (stdlib), sel aleatoire par compte."""

import hashlib
import hmac
import os

ALGORITHM = "scrypt"
DEFAULT_N = 2**14
DEFAULT_R = 8
DEFAULT_P = 1
KEY_LENGTH = 32


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=DEFAULT_N,
        r=DEFAULT_R,
        p=DEFAULT_P,
        dklen=KEY_LENGTH,
    )
    return f"{ALGORITHM}${DEFAULT_N}${DEFAULT_R}${DEFAULT_P}${salt.hex()}${digest.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    """Comparaison a temps constant ; toute chaine malformee renvoie False."""
    try:
        algorithm, n, r, p, salt_hex, digest_hex = encoded.split("$")
        if algorithm != ALGORITHM:
            return False
        expected = bytes.fromhex(digest_hex)
        candidate = hashlib.scrypt(
            password.encode("utf-8"),
            salt=bytes.fromhex(salt_hex),
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=len(expected),
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(candidate, expected)
