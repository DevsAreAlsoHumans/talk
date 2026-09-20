"""Routeur des amitiés : demandes, acceptation, liste, retrait.

Les amis servent de contacts « rapides » pour lancer un message privé
(salon à 2 membres chiffré de bout en bout) — aucune métadonnée sensible
supplémentaire : juste l'identité et le statut de la demande.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path, Response, status

from ..db import Database, get_db
from ..deps import get_current_user, require_csrf
from ..models import FriendshipOut, PeerPayload, UserPublic

router = APIRouter(prefix="/api/friends", tags=["friends"])

DbDep = Annotated[Database, Depends(get_db)]
CurrentUser = Annotated[UserPublic, Depends(get_current_user)]


def _friendship_out(me: str, row: dict) -> FriendshipOut:
    other = row["b"] if row["a"] == me else row["a"]
    return FriendshipOut(
        username=other,
        status=row["status"],
        requested_by=row["requester"],
    )


@router.get("", response_model=list[FriendshipOut])
async def list_friends(user: CurrentUser, db: DbDep):
    """Les relations acceptées — la sidebar « Contacts » du client."""
    rows = await db.list_friendships(user.username, status="accepted")
    return [_friendship_out(user.username, r) for r in rows]


@router.get("/requests", response_model=list[FriendshipOut])
async def list_requests(user: CurrentUser, db: DbDep):
    """Demandes en attente (entrantes + sortantes) pour le panel de décision."""
    rows = await db.list_friendships(user.username, status="pending")
    return [_friendship_out(user.username, r) for r in rows]


@router.post("/requests", status_code=status.HTTP_201_CREATED, response_model=FriendshipOut)
async def send_request(
    payload: PeerPayload,
    user: CurrentUser,
    db: DbDep,
    _: None = Depends(require_csrf),
):
    if payload.peer == user.username:
        raise HTTPException(status_code=400, detail="Impossible de s'ajouter soi-même")
    target = await db.get_user_by_username(payload.peer)
    if target is None:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable")
    if await db.get_friendship(user.username, payload.peer) is not None:
        raise HTTPException(status_code=409, detail="Une demande existe déjà")

    row = await db.create_friendship(user.username, payload.peer)
    if row is None:  # course : deux demandes partiées en même temps
        raise HTTPException(status_code=409, detail="Une demande existe déjà")
    return _friendship_out(user.username, row)


@router.post("/requests/{username}/accept", response_model=FriendshipOut)
async def accept_request(
    user: CurrentUser,
    db: DbDep,
    _: None = Depends(require_csrf),
    username: str = Path(min_length=3, max_length=32),
):
    row = await db.get_friendship(user.username, username)
    if row is None:
        raise HTTPException(status_code=404, detail="Aucune demande de cet utilisateur")
    if row["requester"] == user.username:
        # Le demandeur ne peut pas s'auto-accepter ; l'acceptation est idempotente.
        if row["status"] == "accepted":
            return _friendship_out(user.username, row)
        raise HTTPException(
            status_code=400,
            detail="Demande en attente — acceptée par l'autre partie",
        )

    if not await db.accept_friendship(user.username, username):
        raise HTTPException(status_code=404, detail="Aucune demande en attente")
    row = await db.get_friendship(user.username, username)
    return _friendship_out(user.username, row)


@router.delete("/{username}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_friend(
    user: CurrentUser,
    db: DbDep,
    _: None = Depends(require_csrf),
    username: str = Path(min_length=3, max_length=32),
):
    # Retrait idempotent : rien à retirer n'est pas une erreur.
    await db.delete_friendship(user.username, username)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
