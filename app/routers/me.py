"""Profil courant : consultation (GET /api/me) et mise à jour (PUT /api/me/profile).

Le surnom (display_name) et la biographie sont des métadonnées visibles de tous, comme
le nom d'utilisateur. L'avatar, lui, est chiffré de bout en bout par salon (voir routes
``/api/rooms/{id}/avatar``) : il n'est jamais vu en clair par le serveur.
"""

from fastapi import APIRouter

from app.deps import AuthDep, UsersDep
from app.schemas import UpdateProfileRequest, UpdateThemeRequest, UserSelf

router = APIRouter(prefix="/api/me", tags=["me"])


@router.get("", response_model=UserSelf)
async def current_profile(auth: AuthDep) -> dict[str, str]:
    return auth.user


@router.put("/profile", response_model=UserSelf)
async def update_profile(body: UpdateProfileRequest, auth: AuthDep, users: UsersDep) -> dict[str, str]:
    return await users.update_profile(auth.user["id"], display_name=body.display_name, bio=body.bio)


@router.put("/theme", response_model=UserSelf)
async def update_theme(body: UpdateThemeRequest, auth: AuthDep, users: UsersDep) -> dict[str, str]:
    return await users.set_theme(auth.user["id"], theme=body.theme)
