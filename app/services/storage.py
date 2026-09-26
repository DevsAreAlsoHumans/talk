import uuid
from pathlib import Path

STORAGE_DIR = Path("storage")
STORAGE_DIR.mkdir(parents=True, exist_ok=True)


def save_blob(data: bytes, extension: str = "") -> str:
    """Écrit un blob (chiffré ou non, le stockage ne s'en préoccupe pas) sur disque."""
    blob_id = uuid.uuid4().hex + extension
    blob_path(blob_id).write_bytes(data)
    return blob_id


def blob_path(blob_id: str) -> Path:
    """Chemin sur disque d'un blob, à partir de son identifiant."""
    return STORAGE_DIR / blob_id
