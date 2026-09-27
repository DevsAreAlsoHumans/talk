"""Schemas de la messagerie chiffree.

Regle centrale : l'API n'accepte ni contenu en clair, ni cle privee.
`extra="forbid"` fait echouer toute tentative d'y ajouter un champ `text`.
"""

from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

# Base64 / base64url : uniquement des jetons, aucun caractere de controle.
B64 = r"^[A-Za-z0-9+/_-]+={0,2}$"
CIPHERTEXT_MAX = 16384
IV_LENGTH = 12  # nonce AES-GCM 96 bits, taille imposee par la norme

StrictModel = ConfigDict(extra="forbid")

PublicKey = Annotated[
    str, StringConstraints(min_length=40, max_length=128, pattern=B64)
]
WrappedKey = Annotated[
    str, StringConstraints(min_length=40, max_length=512, pattern=B64)
]
Ciphertext = Annotated[
    str, StringConstraints(min_length=8, max_length=CIPHERTEXT_MAX, pattern=B64)
]


def _b64_length(value: str) -> int:
    return len(value.rstrip("=")) * 3 // 4


class MessageEnvelopeIn(BaseModel):
    """Ce que le client envoie : uniquement du chiffre, jamais du texte."""

    model_config = StrictModel
    ciphertext: Ciphertext
    iv: Annotated[str, StringConstraints(min_length=IV_LENGTH, max_length=IV_LENGTH, pattern=B64)]
    key_version: Annotated[int, Field(ge=1, le=10_000)]

    @field_validator("iv")
    @classmethod
    def _iv_is_not_trivial(cls, value: str) -> str:
        if _b64_length(value) != IV_LENGTH:
            raise ValueError("Le nonce doit faire 12 octets (96 bits).")
        return value

    @field_validator("ciphertext")
    @classmethod
    def _ciphertext_not_repeating(cls, value: str) -> str:
        if len(set(value)) < 8:
            raise ValueError("Chiffre trop peu varie, probablement invalide.")
        return value


class MessageEnvelopeOut(BaseModel):
    model_config = StrictModel
    id: str
    channel_id: str
    sender_id: str
    ciphertext: str
    iv: str
    key_version: int
    sent_at: datetime
    seq: int


class MessagePage(BaseModel):
    model_config = StrictModel
    messages: list[MessageEnvelopeOut]
    latest_seq: int


class PublicKeyIn(BaseModel):
    model_config = StrictModel
    public_key: PublicKey


class PublicKeyOut(BaseModel):
    model_config = StrictModel
    user_id: str
    username: str
    public_key: str
    version: int


class ChannelKeyIn(BaseModel):
    """`user_id` absent = je depose ma propre cle de canal."""

    model_config = StrictModel
    wrapped_key: WrappedKey
    user_id: Annotated[
        str, StringConstraints(min_length=8, max_length=64, pattern=r"^[a-f0-9]+$")
    ] | None = None


class ChannelKeyOut(BaseModel):
    model_config = StrictModel
    version: int
    wrapped_key: str
    from_user_id: str


class ChannelKeysOut(BaseModel):
    model_config = StrictModel
    keys: dict[str, ChannelKeyOut]
