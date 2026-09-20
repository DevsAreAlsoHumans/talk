"""Gestion des erreurs : réponses génériques, aucune fuite d'information.

- Les erreurs de validation ne renvoient que les *noms* des champs fautifs, jamais les
  valeurs reçues (qui peuvent contenir des secrets) ;
- toute exception non prévue est journalisée côté serveur et renvoyée en 500 générique,
  sans stack trace.
"""

import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.security.headers import apply_security_headers

logger = logging.getLogger(__name__)


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(RequestValidationError)
    async def handle_validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        fields = sorted(
            {".".join(str(part) for part in error["loc"][1:]) or "requête" for error in exc.errors()}
        )
        return JSONResponse({"detail": "Requête invalide", "fields": fields}, status_code=422)

    @app.exception_handler(Exception)
    async def handle_unexpected_error(request: Request, exc: Exception) -> JSONResponse:
        logger.error("Erreur non gérée sur %s %s", request.method, request.url.path, exc_info=exc)
        response = JSONResponse({"detail": "Erreur interne"}, status_code=500)
        # Les 500 sortent du middleware d'en-têtes : on les applique ici explicitement.
        apply_security_headers(response.headers, request.url.path)
        return response
