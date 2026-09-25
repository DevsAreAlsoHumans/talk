from datetime import datetime

from pydantic import BaseModel, Field, model_validator

# Un message chiffré en base64 : ~4/3 de la taille en clair.
MAX_CIPHERTEXT = 16384


class MessageCreate(BaseModel):
    # Un message vocal n'a pas forcément de texte : le contenu peut donc être
    # vide, mais seulement s'il y a une pièce jointe.
    ciphertext: str = Field(default="", max_length=MAX_CIPHERTEXT)
    iv: str = Field(default="", max_length=64)
    channel_id: str | None = Field(default=None, max_length=64)
    attachment_id: str | None = Field(default=None, max_length=64)

    @model_validator(mode="after")
    def content_or_attachment(self):
        if not self.attachment_id and not (self.ciphertext and self.iv):
            raise ValueError("Un message doit contenir du texte ou une pièce jointe")
        return self


class MessageEdit(BaseModel):
    """Édition : le client rechiffre le nouveau texte avec un IV neuf.

    Le serveur ne peut pas « modifier » un message puisqu'il ne le lit pas ;
    il remplace simplement l'enveloppe chiffrée.
    """

    ciphertext: str = Field(..., min_length=1, max_length=MAX_CIPHERTEXT)
    iv: str = Field(..., min_length=1, max_length=64)


class MessageResponse(BaseModel):
    id: str
    salon_id: str
    channel_id: str | None = None
    sender_id: str
    sender_username: str
    ciphertext: str
    iv: str
    created_at: datetime
    edited_at: datetime | None = None
    deleted: bool = False
    attachment: dict | None = None


class MessagePage(BaseModel):
    """Page de messages avec curseur : évite de charger tout l'historique."""

    messages: list[MessageResponse]
    next_cursor: str | None = None
    has_more: bool = False
