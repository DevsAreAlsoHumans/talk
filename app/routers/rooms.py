import hashlib
from datetime import UTC, datetime
from typing import Any

from bson import ObjectId
from bson.errors import InvalidId
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from fastapi.responses import FileResponse

from app.db.mongo import db, find_user_by_tag
from app.db.redis_client import redis_client
from app.models.attachment import AttachmentPublic
from app.models.room import (
    GroupRoomCreate,
    MemberRoleUpdate,
    MessageCreate,
    MessagePublic,
    RoomCreate,
    RoomMemberCreate,
    RoomMemberPublic,
    RoomPublic,
)
from app.models.room_key import RoomKeyPublic, RoomKeyRotate
from app.models.user import PeerPublic
from app.security.sessions import get_current_user_id, require_csrf
from app.services.notifications import create_notification
from app.services.realtime import room_channel
from app.services.storage import blob_path, save_blob

router = APIRouter(prefix="/rooms", tags=["rooms"])

_ROLE_RANK = {"member": 0, "admin": 1, "owner": 2}
_MAX_ATTACHMENT_SIZE = 20 * 1024 * 1024


def _to_dm_room_public(room: dict[str, Any], peer_document: dict[str, Any]) -> RoomPublic:
    return RoomPublic(
        id=str(room["_id"]), type="dm", peer=PeerPublic.from_document(peer_document)
    )


async def _fetch_member_documents(members: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    ids = [ObjectId(member["user_id"]) for member in members]
    documents = await db.users.find({"_id": {"$in": ids}}).to_list(length=None)
    return {str(document["_id"]): document for document in documents}


def _to_group_room_public(
    room: dict[str, Any], member_documents: dict[str, dict[str, Any]]
) -> RoomPublic:
    members = [
        RoomMemberPublic(
            user=PeerPublic.from_document(member_documents[member["user_id"]]),
            role=member["role"],
        )
        for member in room["members"]
        if member["user_id"] in member_documents
    ]
    return RoomPublic(
        id=str(room["_id"]),
        type="group",
        name=room["name"],
        members=members,
        key_epoch=room.get("key_epoch", 0),
    )


def _to_attachment_public(document: dict[str, Any]) -> AttachmentPublic:
    return AttachmentPublic(
        id=document["_id"], size=document["size"], sha256=document["sha256"], iv=document["iv"]
    )


def _to_message_public(
    document: dict[str, Any], attachment_document: dict[str, Any] | None = None
) -> MessagePublic:
    return MessagePublic(
        id=str(document["_id"]),
        room_id=document["room_id"],
        sender_id=document["sender_id"],
        ciphertext=document["ciphertext"],
        iv=document["iv"],
        attachment=_to_attachment_public(attachment_document)
        if attachment_document is not None
        else None,
        key_epoch=document.get("key_epoch"),
        created_at=document["created_at"],
    )


async def _find_peer(username: str, discriminator: str) -> dict[str, Any]:
    peer = await find_user_by_tag(username, discriminator)
    if peer is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Utilisateur introuvable."
        )
    return peer


async def _get_membership_or_404(room_id: str, user_id: str) -> dict[str, Any]:
    try:
        object_id = ObjectId(room_id)
    except InvalidId as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Salon introuvable."
        ) from exc

    room = await db.rooms.find_one({"_id": object_id})
    if room is None or user_id not in room["member_ids"]:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Salon introuvable.")
    return room


async def _get_group_or_400(room_id: str, user_id: str) -> dict[str, Any]:
    room = await _get_membership_or_404(room_id, user_id)
    if room["type"] != "group":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cette action ne s'applique qu'aux salons de groupe.",
        )
    return room


def _role_of(room: dict[str, Any], user_id: str) -> str | None:
    for member in room["members"]:
        if member["user_id"] == user_id:
            return member["role"]
    return None


def _require_min_role(room: dict[str, Any], user_id: str, minimum: str) -> str:
    role = _role_of(room, user_id)
    if role is None or _ROLE_RANK[role] < _ROLE_RANK[minimum]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Permission insuffisante."
        )
    return role


@router.post("/dm", response_model=RoomPublic)
async def create_or_get_dm(
    payload: RoomCreate, user_id: str = Depends(get_current_user_id)
) -> RoomPublic:
    """Crée un salon DM avec un pseudo#discriminant, ou renvoie celui qui existe déjà."""
    peer = await _find_peer(payload.username, payload.discriminator)
    peer_id = str(peer["_id"])
    if peer_id == user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Impossible de créer un DM avec soi-même.",
        )

    member_ids = sorted([user_id, peer_id])
    room = await db.rooms.find_one({"type": "dm", "member_ids": member_ids})
    if room is None:
        room_doc: dict[str, Any] = {
            "type": "dm",
            "members": [
                {"user_id": user_id, "role": "member"},
                {"user_id": peer_id, "role": "member"},
            ],
            "member_ids": member_ids,
            "created_at": datetime.now(UTC),
        }
        result = await db.rooms.insert_one(room_doc)
        room_doc["_id"] = result.inserted_id
        room = room_doc

    return _to_dm_room_public(room, peer)


@router.post("/groups", response_model=RoomPublic, status_code=status.HTTP_201_CREATED)
async def create_group_room(
    payload: GroupRoomCreate, user_id: str = Depends(get_current_user_id)
) -> RoomPublic:
    """Crée un salon de groupe ; le créateur en devient owner."""
    room_doc: dict[str, Any] = {
        "type": "group",
        "name": payload.name,
        "members": [{"user_id": user_id, "role": "owner"}],
        "member_ids": [user_id],
        "created_at": datetime.now(UTC),
    }
    result = await db.rooms.insert_one(room_doc)
    room_doc["_id"] = result.inserted_id

    member_documents = await _fetch_member_documents(room_doc["members"])
    return _to_group_room_public(room_doc, member_documents)


@router.post(
    "/{room_id}/members", response_model=RoomPublic, dependencies=[Depends(require_csrf)]
)
async def add_member(
    room_id: str, payload: RoomMemberCreate, user_id: str = Depends(get_current_user_id)
) -> RoomPublic:
    """Ajoute un membre à un salon de groupe (owner/admin uniquement)."""
    room = await _get_group_or_400(room_id, user_id)
    _require_min_role(room, user_id, "admin")

    peer = await _find_peer(payload.username, payload.discriminator)
    peer_id = str(peer["_id"])
    if peer_id in room["member_ids"]:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Déjà membre de ce salon."
        )

    new_member = {"user_id": peer_id, "role": "member"}
    await db.rooms.update_one(
        {"_id": room["_id"]},
        {"$push": {"members": new_member}, "$addToSet": {"member_ids": peer_id}},
    )
    room["members"].append(new_member)
    room["member_ids"].append(peer_id)

    await create_notification(
        peer_id, "room_invite", {"room_id": str(room["_id"]), "room_name": room["name"]}
    )

    member_documents = await _fetch_member_documents(room["members"])
    return _to_group_room_public(room, member_documents)


@router.delete(
    "/{room_id}/members/{target_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_csrf)],
)
async def remove_member(
    room_id: str, target_id: str, user_id: str = Depends(get_current_user_id)
) -> None:
    """Retire un membre (owner/admin) ou quitte soi-même le salon (le owner ne peut pas partir)."""
    room = await _get_group_or_400(room_id, user_id)
    target_role = _role_of(room, target_id)
    if target_role is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Membre introuvable.")

    if target_id == user_id:
        if target_role == "owner":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Le owner ne peut pas quitter son propre salon (limitation assumée).",
            )
    else:
        requester_role = _require_min_role(room, user_id, "admin")
        if _ROLE_RANK[target_role] >= _ROLE_RANK[requester_role]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Impossible de retirer un membre de rang égal ou supérieur.",
            )

    await db.rooms.update_one(
        {"_id": room["_id"]},
        {"$pull": {"members": {"user_id": target_id}, "member_ids": target_id}},
    )


@router.patch(
    "/{room_id}/members/{target_id}",
    response_model=RoomPublic,
    dependencies=[Depends(require_csrf)],
)
async def update_member_role(
    room_id: str,
    target_id: str,
    payload: MemberRoleUpdate,
    user_id: str = Depends(get_current_user_id),
) -> RoomPublic:
    """Change le rôle d'un membre (owner uniquement)."""
    room = await _get_group_or_400(room_id, user_id)
    _require_min_role(room, user_id, "owner")

    if target_id == user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Impossible de changer son propre rôle.",
        )
    target_role = _role_of(room, target_id)
    if target_role is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Membre introuvable.")
    if target_role == "owner":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Impossible de changer le owner."
        )

    await db.rooms.update_one(
        {"_id": room["_id"], "members.user_id": target_id},
        {"$set": {"members.$.role": payload.role}},
    )
    for member in room["members"]:
        if member["user_id"] == target_id:
            member["role"] = payload.role

    member_documents = await _fetch_member_documents(room["members"])
    return _to_group_room_public(room, member_documents)


@router.get("", response_model=list[RoomPublic])
async def list_rooms(user_id: str = Depends(get_current_user_id)) -> list[RoomPublic]:
    """Liste les salons (DM et groupes) de l'utilisateur courant."""
    rooms = await db.rooms.find({"member_ids": user_id}).to_list(length=None)
    if not rooms:
        return []

    all_member_ids = {
        member_id for room in rooms for member_id in room["member_ids"]
    }
    peers = await db.users.find(
        {"_id": {"$in": [ObjectId(member_id) for member_id in all_member_ids]}}
    ).to_list(length=None)
    peers_by_id = {str(peer["_id"]): peer for peer in peers}

    result = []
    for room in rooms:
        if room["type"] == "dm":
            peer_id = next(m for m in room["member_ids"] if m != user_id)
            peer_document = peers_by_id.get(peer_id)
            if peer_document is not None:
                result.append(_to_dm_room_public(room, peer_document))
        else:
            result.append(_to_group_room_public(room, peers_by_id))
    return result


@router.get("/{room_id}/messages", response_model=list[MessagePublic])
async def list_messages(
    room_id: str, user_id: str = Depends(get_current_user_id)
) -> list[MessagePublic]:
    """Historique (chiffré) d'un salon, réservé à ses membres."""
    await _get_membership_or_404(room_id, user_id)

    cursor = db.messages.find({"room_id": room_id}).sort("created_at", 1)
    documents = await cursor.to_list(length=200)

    attachment_ids = [d["attachment_id"] for d in documents if d.get("attachment_id")]
    attachments = await db.attachments.find({"_id": {"$in": attachment_ids}}).to_list(length=None)
    attachments_by_id = {attachment["_id"]: attachment for attachment in attachments}

    return [
        _to_message_public(document, attachments_by_id.get(document.get("attachment_id")))
        for document in documents
    ]


@router.post(
    "/{room_id}/messages",
    response_model=MessagePublic,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_csrf)],
)
async def send_message(
    room_id: str, payload: MessageCreate, user_id: str = Depends(get_current_user_id)
) -> MessagePublic:
    """Stocke un message chiffré et le publie en temps réel aux membres connectés."""
    room = await _get_membership_or_404(room_id, user_id)

    attachment_document = None
    if payload.attachment_id is not None:
        attachment_document = await db.attachments.find_one(
            {"_id": payload.attachment_id, "room_id": room_id}
        )
        if attachment_document is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Pièce jointe invalide pour ce salon.",
            )

    document: dict[str, Any] = {
        "room_id": room_id,
        "sender_id": user_id,
        "ciphertext": payload.ciphertext,
        "iv": payload.iv,
        "attachment_id": payload.attachment_id,
        "key_epoch": payload.key_epoch,
        "created_at": datetime.now(UTC),
    }
    result = await db.messages.insert_one(document)
    document["_id"] = result.inserted_id

    message = _to_message_public(document, attachment_document)
    await redis_client.publish(room_channel(room_id), message.model_dump_json())

    for member_id in room["member_ids"]:
        if member_id != user_id:
            await create_notification(
                member_id, "message", {"room_id": room_id, "sender_id": user_id}
            )

    return message


@router.post(
    "/{room_id}/attachments", response_model=AttachmentPublic, dependencies=[Depends(require_csrf)]
)
async def upload_attachment(
    room_id: str,
    iv: str = Form(...),
    file: UploadFile = File(...),
    user_id: str = Depends(get_current_user_id),
) -> AttachmentPublic:
    """Upload d'une pièce jointe déjà chiffrée (le serveur ne voit que le ciphertext)."""
    await _get_membership_or_404(room_id, user_id)

    data = await file.read()
    if len(data) > _MAX_ATTACHMENT_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Fichier trop volumineux (20 Mo maximum).",
        )

    blob_id = save_blob(data)
    sha256 = hashlib.sha256(data).hexdigest()
    document = {
        "_id": blob_id,
        "room_id": room_id,
        "size": len(data),
        "sha256": sha256,
        "iv": iv,
        "uploader_id": user_id,
        "created_at": datetime.now(UTC),
    }
    await db.attachments.insert_one(document)
    return _to_attachment_public(document)


@router.get("/{room_id}/attachments/{attachment_id}")
async def download_attachment(
    room_id: str, attachment_id: str, user_id: str = Depends(get_current_user_id)
) -> FileResponse:
    """Télécharge le blob chiffré d'une pièce jointe (réservé aux membres du salon)."""
    await _get_membership_or_404(room_id, user_id)

    document = await db.attachments.find_one({"_id": attachment_id, "room_id": room_id})
    path = blob_path(attachment_id) if document is not None else None
    if document is None or path is None or not path.is_file():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Pièce jointe introuvable."
        )
    return FileResponse(path, media_type="application/octet-stream")


@router.post(
    "/{room_id}/keys", response_model=RoomPublic, dependencies=[Depends(require_csrf)]
)
async def rotate_group_key(
    room_id: str, payload: RoomKeyRotate, user_id: str = Depends(get_current_user_id)
) -> RoomPublic:
    """Enregistre une nouvelle rotation de la clé de salon, enveloppée pour chaque membre actuel.

    Le serveur ne voit jamais la clé de salon en clair : il ne fait que stocker, par membre,
    la clé déjà chiffrée côté client (ECDH avec la clé publique de l'auteur de la rotation).
    """
    room = await _get_group_or_400(room_id, user_id)
    _require_min_role(room, user_id, "admin")

    entry_member_ids = {entry.member_id for entry in payload.entries}
    if entry_member_ids != set(room["member_ids"]):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="La rotation doit couvrir exactement tous les membres actuels du salon.",
        )

    new_epoch = room.get("key_epoch", 0) + 1
    await db.rooms.update_one({"_id": room["_id"]}, {"$set": {"key_epoch": new_epoch}})
    room["key_epoch"] = new_epoch

    now = datetime.now(UTC)
    await db.room_keys.insert_many(
        [
            {
                "room_id": room_id,
                "epoch": new_epoch,
                "member_id": entry.member_id,
                "wrapped_key": entry.wrapped_key,
                "wrapped_key_iv": entry.wrapped_key_iv,
                "wrapper_public_key": payload.wrapper_public_key,
                "created_at": now,
            }
            for entry in payload.entries
        ]
    )

    member_documents = await _fetch_member_documents(room["members"])
    return _to_group_room_public(room, member_documents)


@router.get("/{room_id}/keys", response_model=list[RoomKeyPublic])
async def list_group_keys(
    room_id: str, user_id: str = Depends(get_current_user_id)
) -> list[RoomKeyPublic]:
    """Liste, pour l'utilisateur courant, les clés de salon reçues à chaque epoch."""
    await _get_membership_or_404(room_id, user_id)

    cursor = db.room_keys.find({"room_id": room_id, "member_id": user_id}).sort("epoch", 1)
    documents = await cursor.to_list(length=None)
    return [
        RoomKeyPublic(
            epoch=document["epoch"],
            wrapped_key=document["wrapped_key"],
            wrapped_key_iv=document["wrapped_key_iv"],
            wrapper_public_key=document["wrapper_public_key"],
        )
        for document in documents
    ]
