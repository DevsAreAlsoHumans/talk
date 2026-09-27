"""Nettoyage des entrees : suppression des caracteres de controle, normalisation NFC."""

import html
import re
import unicodedata

_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def sanitize_text(value: str, *, max_length: int) -> str:
    normalized = unicodedata.normalize("NFC", value)
    cleaned = _CONTROL_CHARS.sub("", normalized)
    return cleaned.strip()[:max_length]


def escape_html(value: str) -> str:
    """Defense en profondeur : le rendu JS doit rester en textContent."""
    return html.escape(value, quote=True)
