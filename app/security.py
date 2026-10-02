"""Sécurité : mots de passe, CSRF, origine, sessions et headers."""

import hmac
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import Cookie, Depends, Header, HTTPException, Request, Response

from app.database import db

# Une session dure 7 jours
SESSION_AGE = 7 * 24 * 60 * 60

# Headers ajoutés sur toutes les réponses
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; "
        "img-src 'self' data:; connect-src 'self'; base-uri 'none'; "
        "form-action 'self'; frame-ancestors 'none'"
    ),
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "X-Content-Type-Options": "nosniff",
    # same-origin et pas no-referrer, sinon le navigateur envoie « Origin: null »
    "Referrer-Policy": "same-origin",
    "X-Frame-Options": "DENY",
    "Cache-Control": "no-store",
}

# Argon2id avec un sel aléatoire (inclus dans le hash)
hasher = PasswordHasher()
# Faux hash utilisé quand le compte n'existe pas : la réponse prend le même temps
DUMMY_HASH = hasher.hash("compte-inexistant")


def hash_password(password: str) -> str:
    return hasher.hash(password)


def check_password(password: str, password_hash: str | None) -> bool:
    try:
        valid = hasher.verify(password_hash or DUMMY_HASH, password)
    except (VerificationError, InvalidHashError):
        return False
    return valid and password_hash is not None


def own_origin(request: Request) -> str:
    return f"{request.url.scheme}://{request.url.netloc}"


# Vérifie que la requête vient bien de notre site (Origin, sinon Referer)
def check_origin(request: Request):
    expected = own_origin(request)
    origin = request.headers.get("origin")
    referer = request.headers.get("referer")
    if origin:
        allowed = origin == expected
    else:
        allowed = bool(referer) and (referer == expected or referer.startswith(expected + "/"))
    if not allowed:
        raise HTTPException(403, "Origine refusée")


# Vérif CSRF : origine OK + le jeton du cookie doit être le même que celui du header
async def csrf(
    request: Request,
    csrf_token: str | None = Cookie(default=None),
    x_csrf_token: str | None = Header(default=None),
):
    check_origin(request)
    if not csrf_token or not x_csrf_token or not hmac.compare_digest(csrf_token, x_csrf_token):
        raise HTTPException(403, "Jeton CSRF absent ou invalide")


# Cookie Secure seulement en HTTPS (sinon ça marche pas en local)
def set_cookie(request: Request, response: Response, name: str, value: str):
    response.set_cookie(
        name, value, secure=request.url.scheme == "https", httponly=True,
        samesite="strict", max_age=SESSION_AGE,
    )


# Nouvelle session à chaque connexion, l'ancienne est supprimée
async def open_session(request: Request, response: Response, database, user_id: str):
    old_token = request.cookies.get("session")
    if old_token:
        await database.delete(f"session:{old_token}")
    token = secrets.token_urlsafe(32)
    await database.set(f"session:{token}", user_id, ex=SESSION_AGE)
    set_cookie(request, response, "session", token)


# Retrouve l'utilisateur grâce au cookie de session, sinon 401
async def current_user(request: Request, database=Depends(db)) -> str:
    session = request.cookies.get("session")
    user_id = await database.get(f"session:{session}") if session else None
    if not user_id:
        raise HTTPException(401, "Connexion requise")
    return user_id
