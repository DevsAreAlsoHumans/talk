"""Validateurs Pydantic partagés.

Base64 *standard* uniquement (pas d'urlsafe, padding requis) conformément au
contrat d'intégration : ``base64.b64decode(..., validate=True)``.
"""

from __future__ import annotations

import base64
import binascii


def valid_base64(value: str) -> str:
    """Valide une chaîne base64 standard et la renvoie inchangée.

    Lève ``ValueError`` (→ 422 Pydantic) si la chaîne n'est pas du base64
    valide avec padding.
    """
    try:
        base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("invalid base64 encoding") from exc
    return value
