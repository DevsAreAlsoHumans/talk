from typing import Any, Dict, Iterable, List, Sequence, Set

from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.dependencies import get_current_user, get_store, require_csrf
from app.realtime import ConnectionManager
from app.schemas import (
    ChannelCreateRequest,
    KeyEnvelopeInput,
    RoomCreateRequest,
    RoomKeyRotateRequest,
    RoomKeyShareRequest,
    RoomMemberRequest,
)
from app.storage import ChannelAlreadyExistsError, RedisStore

router = APIRouter(prefix="/api/rooms", tags=["salons"])


async def _require_membership(
    store: RedisStore, room_id: str, user_id: str
) -> Dict[str, Any]:
    room = await store.get_room(room_id)
    if room is None or not await store.is_room_member(room_id, user_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Salon introuvable")
    return room


async def _require_owner(
    store: RedisStore, room_id: str, user_id: str
) -> Dict[str, Any]:
    room = await _require_membership(store, room_id, user_id)
    if room["owner_id"] != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Seul le propriétaire peut gérer les clés et les membres",
        )
    return room


async def _resolve_invites(
    store: RedisStore, usernames: Iterable[str]
) -> List[Dict[str, Any]]:
    users: Dict[str, Dict[str, Any]] = {}
    for username in usernames:
        user = await store.get_user_by_username(username)
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Utilisateur introuvable : {username}",
            )
        users[user["id"]] = user
    return list(users.values())


async def _validate_envelopes(
    store: RedisStore,
    member_ids: Set[str],
    envelopes: Sequence[KeyEnvelopeInput],
    *,
    expected_version: int,
    require_every_member: bool,
) -> List[Dict[str, Any]]:
    prepared = [envelope.model_dump(mode="json") for envelope in envelopes]
    fields = {
        (
            item["key_version"],
            item["recipient_id"],
            item["key_id"],
        )
        for item in prepared
    }
    if len(fields) != len(prepared):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="La requête contient des enveloppes de clé en double",
        )

    covered_members: Set[str] = set()
    for member_id in member_ids:
        identity_keys = await store.list_identity_keys(member_id)
        valid_key_ids = {item["key_id"] for item in identity_keys}
        for envelope in prepared:
            if envelope["recipient_id"] != member_id:
                continue
            if envelope["key_version"] != expected_version:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Version de clé de salon incorrecte",
                )
            if envelope["key_id"] not in valid_key_ids:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail="Une enveloppe cible une clé publique inconnue",
                )
            covered_members.add(member_id)

    if any(envelope["recipient_id"] not in member_ids for envelope in prepared):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Une enveloppe cible un utilisateur hors du salon",
        )
    if require_every_member and covered_members != member_ids:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Chaque membre doit recevoir au moins une enveloppe de clé",
        )
    return prepared


def _manager(request: Request) -> ConnectionManager:
    return request.app.state.manager


@router.get("", summary="Lister ses salons")
async def list_rooms(
    user: Dict[str, Any] = Depends(get_current_user),
    store: RedisStore = Depends(get_store),
) -> Dict[str, Any]:
    return {"rooms": await store.list_rooms(user["id"])}


@router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_csrf)],
    summary="Créer un salon chiffré",
)
async def create_room(
    payload: RoomCreateRequest,
    request: Request,
    user: Dict[str, Any] = Depends(get_current_user),
    store: RedisStore = Depends(get_store),
) -> Dict[str, Any]:
    invited_users = await _resolve_invites(
        store, [invite.username for invite in payload.invites]
    )
    members = {user["id"]: user}
    members.update({member["id"]: member for member in invited_users})
    envelopes = await _validate_envelopes(
        store,
        set(members),
        payload.key_envelopes,
        expected_version=1,
        require_every_member=True,
    )
    room, channel = await store.create_room(
        name=payload.name,
        owner_id=user["id"],
        member_ids=list(members),
        key_envelopes=envelopes,
        channel_name=payload.channel_name,
    )
    return {
        "room": room,
        "channels": [channel],
        "members": list(members.values()),
    }


@router.get("/{room_id}", summary="Obtenir un salon")
async def get_room(
    room_id: str,
    user: Dict[str, Any] = Depends(get_current_user),
    store: RedisStore = Depends(get_store),
) -> Dict[str, Any]:
    room = await _require_membership(store, room_id, user["id"])
    return {
        "room": room,
        "members": await store.list_room_members(room_id),
    }


@router.get("/{room_id}/keys", summary="Obtenir les enveloppes de clé")
async def get_room_keys(
    room_id: str,
    user: Dict[str, Any] = Depends(get_current_user),
    store: RedisStore = Depends(get_store),
) -> Dict[str, Any]:
    await _require_membership(store, room_id, user["id"])
    return {"key_envelopes": await store.get_room_keys(room_id)}


@router.post(
    "/{room_id}/members",
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_csrf)],
    summary="Inviter un membre avec la clé du salon",
)
async def add_room_member(
    room_id: str,
    payload: RoomMemberRequest,
    request: Request,
    user: Dict[str, Any] = Depends(get_current_user),
    store: RedisStore = Depends(get_store),
) -> Dict[str, Any]:
    room = await _require_owner(store, room_id, user["id"])
    invited_users = await _resolve_invites(store, [payload.username])
    invited = invited_users[0]
    if await store.is_room_member(room_id, invited["id"]):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Cet utilisateur est déjà membre du salon",
        )
    envelopes = await _validate_envelopes(
        store,
        {invited["id"]},
        payload.key_envelopes,
        expected_version=room["key_version"],
        require_every_member=True,
    )
    await store.add_room_member(room_id, invited["id"], envelopes)
    member_ids = await store.all_room_member_ids(room_id)
    await _manager(request).broadcast_to_users(
        member_ids,
        {"type": "room.member_added", "room_id": room_id, "user_id": invited["id"]},
    )
    return {"room_id": room_id, "member": invited}


@router.post(
    "/{room_id}/keys/share",
    dependencies=[Depends(require_csrf)],
    summary="Partager la clé courante avec de nouveaux appareils",
)
async def share_room_keys(
    room_id: str,
    payload: RoomKeyShareRequest,
    request: Request,
    user: Dict[str, Any] = Depends(get_current_user),
    store: RedisStore = Depends(get_store),
) -> Dict[str, Any]:
    room = await _require_owner(store, room_id, user["id"])
    member_ids = set(await store.all_room_member_ids(room_id))
    envelopes = await _validate_envelopes(
        store,
        member_ids,
        payload.key_envelopes,
        expected_version=room["key_version"],
        require_every_member=False,
    )
    await store.add_room_keys(room_id, envelopes)
    await _manager(request).broadcast_to_users(
        member_ids,
        {"type": "room.keys_shared", "room_id": room_id},
    )
    return {"key_envelopes": envelopes}


@router.post(
    "/{room_id}/keys/rotate",
    dependencies=[Depends(require_csrf)],
    summary="Faire tourner la clé du salon",
)
async def rotate_room_keys(
    room_id: str,
    payload: RoomKeyRotateRequest,
    request: Request,
    user: Dict[str, Any] = Depends(get_current_user),
    store: RedisStore = Depends(get_store),
) -> Dict[str, Any]:
    room = await _require_owner(store, room_id, user["id"])
    member_ids = set(await store.all_room_member_ids(room_id))
    envelopes = await _validate_envelopes(
        store,
        member_ids,
        payload.key_envelopes,
        expected_version=room["key_version"],
        require_every_member=True,
    )
    new_version = await store.rotate_room_keys(room_id, envelopes)
    await _manager(request).broadcast_to_users(
        member_ids,
        {
            "type": "room.keys_rotated",
            "room_id": room_id,
            "key_version": new_version,
        },
    )
    return {"room_id": room_id, "key_version": new_version}


@router.get("/{room_id}/channels", summary="Lister les canaux")
async def list_channels(
    room_id: str,
    user: Dict[str, Any] = Depends(get_current_user),
    store: RedisStore = Depends(get_store),
) -> Dict[str, Any]:
    await _require_membership(store, room_id, user["id"])
    return {"channels": await store.list_channels(room_id)}


@router.post(
    "/{room_id}/channels",
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_csrf)],
    summary="Créer un canal",
)
async def create_channel(
    room_id: str,
    payload: ChannelCreateRequest,
    request: Request,
    user: Dict[str, Any] = Depends(get_current_user),
    store: RedisStore = Depends(get_store),
) -> Dict[str, Any]:
    await _require_membership(store, room_id, user["id"])
    try:
        channel = await store.create_channel(room_id, payload.name)
    except ChannelAlreadyExistsError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Un canal porte déjà ce nom dans ce salon",
        ) from exc
    member_ids = await store.all_room_member_ids(room_id)
    await _manager(request).broadcast_to_users(
        member_ids,
        {
            "type": "channel.created",
            "room_id": room_id,
            "channel": channel,
        },
    )
    return channel
