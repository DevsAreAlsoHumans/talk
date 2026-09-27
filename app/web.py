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


class RevalidatedStaticFiles(StaticFiles):
    """StaticFiles qui impose la revalidation a chaque requete.

    Sans `Cache-Control`, un navigateur peut servir un module JS perime : le
    correctif est bien livre mais le code tourne encore, et l'erreur affichee
    ne dit rien de sa cause. `no-cache` n'interdit pas le cache, il oblige a
    revalider — l'ETag garde la reponse legere (304 sans corps).
    """

    def file_response(self, *args, **kwargs):
        response = super().file_response(*args, **kwargs)
        response.headers["Cache-Control"] = "no-cache"
        return response


@router.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(FRONTEND_DIR / "index.html")


def mount_static(app) -> None:
    app.mount("/static", RevalidatedStaticFiles(directory=FRONTEND_DIR), name="static")
