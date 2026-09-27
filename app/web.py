"""Service du frontend statique.

Meme origine que l'API : aucune dependance CDN, ce qui permet de garder une
politique CSP stricte (`script-src 'self'`) et de fonctionner hors ligne.
"""

from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"

router = APIRouter(tags=["frontend"])


@router.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(FRONTEND_DIR / "index.html")


def mount_static(app) -> None:
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")
