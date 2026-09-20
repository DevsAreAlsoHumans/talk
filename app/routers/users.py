from typing import Annotated

from fastapi import APIRouter, HTTPException, Path

from app.deps import AuthDep, UsersDep
from app.schemas import USERNAME_PATTERN, UserPublic

router = APIRouter(prefix="/api/users", tags=["users"])


@router.get("/{username}", response_model=UserPublic)
async def get_user(
    username: Annotated[str, Path(pattern=USERNAME_PATTERN)], _: AuthDep, users: UsersDep
) -> dict:
    """Clé publique d'un utilisateur, nécessaire pour lui envelopper la clé d'un salon."""
    user = await users.get_by_username(username)
    if user is None:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable")
    return user
