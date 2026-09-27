from pydantic import BaseModel


class AttachmentPublic(BaseModel):
    """Pièce jointe chiffrée : le serveur ne connaît que taille/empreinte/iv/type déclaré,
    jamais le contenu réel (le type est fourni par le client, purement indicatif pour
    l'affichage — impossible à vérifier côté serveur puisque les octets sont chiffrés)."""

    id: str
    size: int
    sha256: str
    iv: str
    content_type: str | None = None
