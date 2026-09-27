"""Schemas de la messagerie chiffree.

Regle centrale : l'API n'accepte ni contenu en clair, ni cle privee.
`extra="forbid"` fait echouer toute tentative d'y ajouter un champ `text`.
"""

from datetime import datetime
from typing import Annotated

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
)

# Base64 / base64url : uniquement des jetons, aucun caractere de controle.
B64 = r"^[A-Za-z0-9+/_-]+={0,2}$"
CIPHERTEXT_MAX = 16384
IV_BYTES = 12  # nonce AES-GCM 96 bits, taille imposee par la norme
IV_B64_LENGTH = 16  # 12 octets encodes en base64

StrictModel = ConfigDict(extra="forbid")

PublicKey = Annotated[str, StringConstraints(min_length=40, max_length=128, pattern=B64)]
WrappedKey = Annotated[str, StringConstraints(min_length=40, max_length=512, pattern=B64)]
Ciphertext = Annotated[str, StringConstraints(min_length=8, max_length=CIPHERTEXT_MAX, pattern=B64)]


def _b64_length(value: str) -> int:
    return len(value.rstrip("=")) * 3 // 4


def _iv_is_iv_bytes(value: str) -> str:
    """Refuse un nonce qui ne fait pas 12 octets une fois decode."""
    if _b64_length(value) != IV_BYTES:
        raise ValueError("Le nonce doit faire 12 octets (96 bits).")
    return value


# Meme contrainte que le nonce d'un message : 12 octets encodes en base64 font
# 16 caracteres, la taille reelle est verifiee sur les octets decodes.
Iv = Annotated[
    str,
    StringConstraints(min_length=IV_B64_LENGTH, max_length=IV_B64_LENGTH, pattern=B64),
    AfterValidator(_iv_is_iv_bytes),
]


class MessageEnvelopeIn(BaseModel):
    """Ce que le client envoie : uniquement du chiffre, jamais du texte."""

    model_config = StrictModel
    ciphertext: Ciphertext
    iv: Iv
    key_version: Annotated[int, Field(ge=1, le=10_000)]

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
    created_at: datetime


class ChannelKeyIn(BaseModel):
    """`user_id` absent = je depose ma propre cle de canal.

    `iv` est le nonce AES-GCM utilise pour emballer la cle de canal. Ce n'est
    pas un secret : il doit etre stocke en clair, sinon le destinataire ne peut
    jamais dechiffrer. Le conserver cote client n'est pas une option.
    """

    model_config = StrictModel
    wrapped_key: WrappedKey
    iv: Iv
    user_id: (
        Annotated[str, StringConstraints(min_length=8, max_length=64, pattern=r"^[a-f0-9]+$")]
        | None
    ) = None


class ChannelKeyOut(BaseModel):
    model_config = StrictModel
    version: int
    wrapped_key: str
    iv: str
    from_user_id: str


class ChannelKeysOut(BaseModel):
    model_config = StrictModel
    keys: dict[str, ChannelKeyOut]
