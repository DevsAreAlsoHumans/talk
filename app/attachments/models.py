from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

# Un message vocal d'une minute en Opus pèse ~80 Ko, ~110 Ko une fois en
# base64. Le plafond laisse de la marge sans permettre d'y loger un film.
MAX_PAYLOAD_B64 = 3_000_000
MAX_DURATION_MS = 120_000


class AttachmentCreate(BaseModel):
    """Pièce jointe chiffrée côté client, comme n'importe quel message.

    Le serveur reçoit des octets chiffrés et un IV : il ne sait pas plus ce
    qu'il stocke ici que pour du texte.
    """

    kind: Literal["audio"] = "audio"
    ciphertext: str = Field(..., min_length=1, max_length=MAX_PAYLOAD_B64)
    iv: str = Field(..., min_length=1, max_length=64)
    # Durée annoncée par le client : sert à afficher « 0:14 » sans avoir à
    # télécharger puis déchiffrer la piste.
    duration_ms: int = Field(..., ge=0, le=MAX_DURATION_MS)
    mime: str = Field(default="audio/webm", max_length=60)


class AttachmentResponse(BaseModel):
    id: str
    kind: str
    duration_ms: int
    mime: str
    size: int
    created_at: datetime


class AttachmentPayload(AttachmentResponse):
    """Réponse de téléchargement : contient le contenu chiffré."""

    ciphertext: str
    iv: str
