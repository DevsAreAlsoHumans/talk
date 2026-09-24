from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.dependencies import get_current_user, get_store, require_csrf
from app.schemas import IdentityKeyInput, normalize_username
from app.storage import IdentityKeyConflictError, IdentityKeyLimitError, RedisStore

router = APIRouter(prefix="/api", tags=["utilisateurs"])


@router.post(
    "/identity/keys",
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_csrf)],
    summary="Enregistrer la clé publique de cet appareil",
)
async def add_identity_key(
    payload: IdentityKeyInput,
    user: dict[str, Any] = Depends(get_current_user),
    store: RedisStore = Depends(get_store),
) -> dict[str, Any]:
    try:
        return await store.add_identity_key(user["id"], payload.model_dump(mode="json"))
    except IdentityKeyConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Cet identifiant de clé correspond déjà à une autre clé",
        ) from exc
    except IdentityKeyLimitError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="La limite de 10 appareils par compte est atteinte",
        ) from exc


@router.get("/users", summary="Rechercher des utilisateurs")
async def search_users(
    query: str = Query(min_length=2, max_length=32),
    current_user: dict[str, Any] = Depends(get_current_user),
    store: RedisStore = Depends(get_store),
) -> dict[str, list[dict[str, Any]]]:
    normalized = query.casefold()
    return {"users": await store.search_users(normalized)}


@router.get(
    "/users/{username}/keys",
    summary="Obtenir les clés publiques d'un utilisateur",
)
async def user_identity_keys(
    username: str,
    current_user: dict[str, Any] = Depends(get_current_user),
    store: RedisStore = Depends(get_store),
) -> dict[str, Any]:
    try:
        normalized = normalize_username(username)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Nom d'utilisateur invalide",
        ) from exc
    user = await store.get_user_by_username(normalized)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Utilisateur introuvable")
    return {
        "user": user,
        "identity_keys": await store.list_identity_keys(user["id"]),
    }
