from pydantic import BaseModel


class AttachmentPublic(BaseModel):
    """Pièce jointe chiffrée : le serveur ne connaît que taille/empreinte/iv, jamais le contenu."""

    id: str
    size: int
    sha256: str
    iv: str
