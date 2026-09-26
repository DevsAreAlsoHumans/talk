from datetime import UTC, datetime
from typing import Any

from bson import ObjectId
from bson.errors import InvalidId
from fastapi import APIRouter, Depends, HTTPException, status
from pymongo.errors import DuplicateKeyError

from app.db.mongo import db, find_user_by_tag
from app.models.friendship import (
    FriendPublic,
    FriendRequestCreate,
    FriendRequestPublic,
    FriendRequestResult,
)
from app.models.user import PeerPublic
from app.security.sessions import get_current_user_id, require_csrf

router = APIRouter(prefix="/friends", tags=["friends"])


async def _find_peer_or_404(username: str, discriminator: str) -> dict[str, Any]:
    peer = await find_user_by_tag(username, discriminator)
    if peer is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Utilisateur introuvable."
        )
    return peer


async def _find_friendship_either_direction(
    user_id: str, peer_id: str, status_filter: str | None = None
) -> dict[str, Any] | None:
    query: dict[str, Any] = {
        "$or": [
            {"requester_id": user_id, "target_id": peer_id},
            {"requester_id": peer_id, "target_id": user_id},
        ]
    }
    if status_filter is not None:
        query["status"] = status_filter
    return await db.friendships.find_one(query)


async def _get_pending_request_or_404(request_id: str) -> dict[str, Any]:
    try:
        object_id = ObjectId(request_id)
    except InvalidId as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Demande introuvable."
        ) from exc

    request_doc = await db.friendships.find_one({"_id": object_id, "status": "pending"})
    if request_doc is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Demande introuvable.")
    return request_doc


def _to_request_public(
    document: dict[str, Any], user_id: str, peer_document: dict[str, Any]
) -> FriendRequestPublic:
    direction = "outgoing" if document["requester_id"] == user_id else "incoming"
    return FriendRequestPublic(
        id=str(document["_id"]),
        direction=direction,
        peer=PeerPublic.from_document(peer_document),
        created_at=document["created_at"],
    )


@router.post("/requests", response_model=FriendRequestResult, dependencies=[Depends(require_csrf)])
async def send_friend_request(
    payload: FriendRequestCreate, user_id: str = Depends(get_current_user_id)
) -> FriendRequestResult:
    """Envoie une demande d'ami (accepte directement si une demande inverse est déjà pendante)."""
    peer = await _find_peer_or_404(payload.username, payload.discriminator)
    peer_id = str(peer["_id"])
    if peer_id == user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Impossible de s'ajouter soi-même."
        )

    existing = await _find_friendship_either_direction(user_id, peer_id)
    if existing is not None:
        if existing["status"] == "accepted":
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Déjà amis.")
        if existing["requester_id"] == peer_id:
            await db.friendships.update_one(
                {"_id": existing["_id"]},
                {"$set": {"status": "accepted", "resolved_at": datetime.now(UTC)}},
            )
            return FriendRequestResult(status="accepted", peer=PeerPublic.from_document(peer))
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Demande déjà envoyée.")

    try:
        await db.friendships.insert_one(
            {
                "requester_id": user_id,
                "target_id": peer_id,
                "status": "pending",
                "created_at": datetime.now(UTC),
                "resolved_at": None,
            }
        )
    except DuplicateKeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Demande déjà envoyée."
        ) from exc

    return FriendRequestResult(status="pending", peer=PeerPublic.from_document(peer))


@router.get("/requests", response_model=list[FriendRequestPublic])
async def list_friend_requests(
    user_id: str = Depends(get_current_user_id),
) -> list[FriendRequestPublic]:
    """Liste les demandes d'ami en attente (entrantes et sortantes)."""
    cursor = db.friendships.find(
        {"status": "pending", "$or": [{"requester_id": user_id}, {"target_id": user_id}]}
    )
    requests = await cursor.to_list(length=None)
    if not requests:
        return []

    peer_ids = [
        ObjectId(r["target_id"] if r["requester_id"] == user_id else r["requester_id"])
        for r in requests
    ]
    peers = await db.users.find({"_id": {"$in": peer_ids}}).to_list(length=None)
    peers_by_id = {str(peer["_id"]): peer for peer in peers}

    result = []
    for request_doc in requests:
        peer_id = (
            request_doc["target_id"]
            if request_doc["requester_id"] == user_id
            else request_doc["requester_id"]
        )
        peer_document = peers_by_id.get(peer_id)
        if peer_document is not None:
            result.append(_to_request_public(request_doc, user_id, peer_document))
    return result


@router.post(
    "/requests/{request_id}/accept",
    response_model=FriendPublic,
    dependencies=[Depends(require_csrf)],
)
async def accept_friend_request(
    request_id: str, user_id: str = Depends(get_current_user_id)
) -> FriendPublic:
    """Accepte une demande entrante."""
    request_doc = await _get_pending_request_or_404(request_id)
    if request_doc["target_id"] != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Seul le destinataire peut accepter."
        )

    resolved_at = datetime.now(UTC)
    await db.friendships.update_one(
        {"_id": request_doc["_id"]}, {"$set": {"status": "accepted", "resolved_at": resolved_at}}
    )
    peer = await db.users.find_one({"_id": ObjectId(request_doc["requester_id"])})
    return FriendPublic(peer=PeerPublic.from_document(peer), since=resolved_at)


@router.delete(
    "/requests/{request_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_csrf)],
)
async def cancel_or_decline_request(
    request_id: str, user_id: str = Depends(get_current_user_id)
) -> None:
    """Refuse une demande entrante ou annule une demande sortante."""
    request_doc = await _get_pending_request_or_404(request_id)
    if user_id not in (request_doc["requester_id"], request_doc["target_id"]):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Demande introuvable.")
    await db.friendships.delete_one({"_id": request_doc["_id"]})


@router.get("", response_model=list[FriendPublic])
async def list_friends(user_id: str = Depends(get_current_user_id)) -> list[FriendPublic]:
    """Liste les amis (demandes acceptées)."""
    cursor = db.friendships.find(
        {"status": "accepted", "$or": [{"requester_id": user_id}, {"target_id": user_id}]}
    )
    friendships = await cursor.to_list(length=None)
    if not friendships:
        return []

    peer_ids = [
        ObjectId(f["target_id"] if f["requester_id"] == user_id else f["requester_id"])
        for f in friendships
    ]
    peers = await db.users.find({"_id": {"$in": peer_ids}}).to_list(length=None)
    peers_by_id = {str(peer["_id"]): peer for peer in peers}

    result = []
    for friendship in friendships:
        peer_id = (
            friendship["target_id"]
            if friendship["requester_id"] == user_id
            else friendship["requester_id"]
        )
        peer_document = peers_by_id.get(peer_id)
        if peer_document is not None:
            result.append(
                FriendPublic(
                    peer=PeerPublic.from_document(peer_document), since=friendship["resolved_at"]
                )
            )
    return result


@router.delete(
    "/{friend_user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_csrf)],
)
async def remove_friend(friend_user_id: str, user_id: str = Depends(get_current_user_id)) -> None:
    """Révoque une amitié acceptée."""
    friendship = await _find_friendship_either_direction(user_id, friend_user_id, "accepted")
    if friendship is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Amitié introuvable.")
    await db.friendships.delete_one({"_id": friendship["_id"]})
