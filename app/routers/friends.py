"""Amis : envoyer / accepter / refuser une demande, lister et retirer ses amis.

Les relations d'amitié sont ce qui autorise l'ouverture d'une conversation directe
(voir ``conversations.py``) : on ne peut message un inconnu sans passer par un salon.

Chaque mutation est notifiée en temps réel au(x) concerné(s) par le bus d'événements :
une demande arrive en direct, une acceptation (ou un refus) est annoncée à l'expéditeur.
"""

from typing import Annotated

from fastapi import APIRouter, HTTPException, Path

from app.deps import AuthDep, EventBusDep, FriendsDep, UsersDep
from app.schemas import USERNAME_PATTERN, FriendRequestInput, MemberSummary

router = APIRouter(prefix="/api/friends", tags=["friends"])

Username = Annotated[str, Path(pattern=USERNAME_PATTERN)]


def _public_user(row: dict[str, str]) -> dict[str, str]:
    """Profil partagé avec un ami ou un demandeur : sans jamais exposer les clés."""
    return {
        "id": row["id"],
        "username": row["username"],
        "public_key": row["public_key"],
        "display_name": row["display_name"],
        "bio": row["bio"],
    }


async def _users_for(ids: set[str], users: UsersDep) -> list[dict[str, str]]:
    rows = [await users.get(user_id) for user_id in ids]
    return [_public_user(row) for row in rows if row]


@router.get("", response_model=list[MemberSummary])
async def list_friends(auth: AuthDep, friends: FriendsDep, users: UsersDep) -> list[dict]:
    return await _users_for(await friends.friend_ids(auth.user["id"]), users)


@router.get("/requests", response_model=list[MemberSummary])
async def list_requests(auth: AuthDep, friends: FriendsDep, users: UsersDep) -> list[dict]:
    """Demandes reçues, en attente d'acceptation ou de refus."""
    return await _users_for(await friends.incoming_ids(auth.user["id"]), users)


@router.post("/requests", status_code=201, response_model=MemberSummary)
async def send_request(
    body: FriendRequestInput,
    auth: AuthDep,
    friends: FriendsDep,
    users: UsersDep,
    bus: EventBusDep,
) -> dict:
    target = await users.get_by_username(body.username)
    if target is None:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable")
    if target["id"] == auth.user["id"]:
        raise HTTPException(status_code=400, detail="Vous ne pouvez pas être votre propre ami")

    status = await friends.send_request(auth.user["id"], target["id"])
    if status == "already_friend":
        raise HTTPException(status_code=409, detail="Vous êtes déjà amis")
    if status == "already_pending":
        raise HTTPException(status_code=409, detail="Demande déjà envoyée ou reçue")

    await bus.publish({"type": "friend_request", "from": _public_user(auth.user)}, [target["id"]])
    return _public_user(target)


@router.post("/{username}/accept", response_model=MemberSummary)
async def accept_request(
    username: Username,
    auth: AuthDep,
    friends: FriendsDep,
    users: UsersDep,
    bus: EventBusDep,
) -> dict:
    requester = await users.get_by_username(username)
    if requester is None or not await friends.accept(auth.user["id"], requester["id"]):
        raise HTTPException(status_code=404, detail="Demande introuvable")

    accepter = _public_user(auth.user)
    await bus.publish({"type": "friend_accepted", "user": accepter}, [requester["id"]])
    await bus.publish({"type": "friend_accepted", "user": _public_user(requester)}, [auth.user["id"]])
    return accepter


@router.post("/{username}/decline", status_code=204)
async def decline_request(
    username: Username,
    auth: AuthDep,
    friends: FriendsDep,
    users: UsersDep,
    bus: EventBusDep,
) -> None:
    requester = await users.get_by_username(username)
    if requester is None or not await friends.decline(auth.user["id"], requester["id"]):
        raise HTTPException(status_code=404, detail="Demande introuvable")
    # C'est le demandeur qui doit savoir que sa demande a été refusée.
    await bus.publish({"type": "friend_declined", "user": _public_user(auth.user)}, [requester["id"]])


@router.delete("/{username}", status_code=204)
async def remove_friend(
    username: Username,
    auth: AuthDep,
    friends: FriendsDep,
    users: UsersDep,
) -> None:
    target = await users.get_by_username(username)
    if target is None or not await friends.remove(auth.user["id"], target["id"]):
        raise HTTPException(status_code=404, detail="Utilisateur introuvable")
