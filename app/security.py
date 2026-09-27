"""Hachage des mots de passe, génération et comparaison de jetons.

Ce module ne contient **aucune** primitive de chiffrement ni de déchiffrement :
le serveur n'a volontairement aucun moyen de lire un message. Il ne manipule que
du hachage et des jetons opaques.

Seule exception, `public_key_thumbprint` : il hache une clé **publique** pour en
produire une empreinte comparable hors bande. Hasher une donnée publique ne
révèle rien.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from starlette.types import Scope

from app.config import get_settings

# 32 octets aléatoires -> 256 bits d'entropie, encodés en 43 caractères URL-safe.
TOKEN_BYTES = 32

_password_hasher = PasswordHasher(
    time_cost=get_settings().argon2_time_cost,
    memory_cost=get_settings().argon2_memory_cost,
    parallelism=get_settings().argon2_parallelism,
)

# Haché factice d'un secret jetable : sert à égaliser le temps de réponse quand
# l'utilisateur n'existe pas, afin d'empêcher l'énumération de comptes.
_DUMMY_HASH = _password_hasher.hash(secrets.token_urlsafe(TOKEN_BYTES))


def hash_password(password: str) -> str:
    """Retourne le haché Argon2id d'un mot de passe."""
    return _password_hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Vérifie un mot de passe. Ne lève jamais.

    Un haché corrompu en base ne doit pas provoquer d'erreur 500 : l'argument
    `UnicodeEncodeError` vient d'`argon2`, qui exige de l'ASCII.
    """
    try:
        return _password_hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError, UnicodeEncodeError):
        return False


def burn_password_verification(password: str) -> None:
    """Exécute une vérification factice pour uniformiser le temps de réponse."""
    verify_password(password, _DUMMY_HASH)


def generate_token() -> str:
    """Retourne un jeton aléatoire URL-safe de 256 bits."""
    return secrets.token_urlsafe(TOKEN_BYTES)


def hash_token(token: str) -> str:
    """Retourne l'empreinte SHA-256 d'un jeton, seule forme stockée en base."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def tokens_equal(left: str, right: str) -> bool:
    """Compare deux jetons en temps constant, tolérant aux entrées arbitraires."""
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


def public_key_thumbprint(canonical_json: str) -> str:
    """Empreinte d'une clé publique, selon le RFC 7638.

    Le serveur ne peut pas déchiffrer un message, mais il doit pouvoir produire
    la même empreinte qu'un client pour permettre une comparaison hors bande.

    L'empreinte sert à vérifier que l'on parle bien de la même clé qu'une
    fois donnée. Elle **ne protège pas** contre un serveur malveillant qui
    substituerait la clé dès le premier échange et afficherait donc une
    empreinte de son propre choix.
    """
    digest = hashlib.sha256(canonical_json.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def is_secure_request(scope: Scope) -> bool:
    """Indique si la requête courante est en HTTPS.

    `X-Forwarded-Proto` n'est lu que si `TRUST_PROXY_HEADERS` est activé : sans
    cette confiance explicite, un client pourrait forger l'en-tête.
    """
    if scope.get("scheme") == "https":
        return True
    if not get_settings().trust_proxy_headers:
        return False
    for name, value in scope.get("headers", []):
        if name == b"x-forwarded-proto":
            return value.split(b",")[0].strip().lower() == b"https"
    return False
