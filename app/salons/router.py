from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException, status

from app.auth.router import get_current_user
from app.db import get_db
from app.salons.models import (
    ChannelCreate,
    ChannelResponse,
    DirectCreate,
    MemberAdd,
    MemberRemove,
    MemberResponse,
    SalonCreate,
    SalonResponse,
)
from app.salons.service import (
    add_channel,
    add_member,
    create_direct,
    create_salon,
    find_direct,
    get_salon,
    get_user_salons,
    is_member,
    remove_member,
)

router = APIRouter(prefix="/salons", tags=["salons"])


def _format_salon(salon: dict) -> SalonResponse:
    return SalonResponse(
        id=str(salon["_id"]),
        name=salon["name"],
        owner_id=str(salon["owner_id"]),
        members=[
            MemberResponse(
                user_id=str(m["user_id"]),
                username=m["username"],
                encrypted_salon_key=m["encrypted_salon_key"],
                fingerprint=m.get("fingerprint"),
            )
            for m in salon["members"]
        ],
        channels=[
            ChannelResponse(id=str(c["_id"]), name=c["name"], created_at=c["created_at"])
            for c in salon.get("channels", [])
        ],
        key_version=salon.get("key_version", 1),
        is_direct=bool(salon.get("is_direct", False)),
        created_at=salon["created_at"],
    )


def _require_object_id(salon_id: str) -> None:
    if not ObjectId.is_valid(salon_id):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid salon ID")


async def _require_owner(salon_id: str, user: dict) -> dict:
    _require_object_id(salon_id)
    salon = await get_salon(salon_id)
    if not salon:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Salon not found")
    if str(salon["owner_id"]) != str(user["_id"]):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only owner can do this")
    return salon


@router.post("", status_code=status.HTTP_201_CREATED, response_model=SalonResponse)
async def create(data: SalonCreate, user: dict = Depends(get_current_user)):
    salon = await create_salon(data.name, str(user["_id"]), data.encrypted_salon_key)
    return _format_salon(salon)


@router.get("", response_model=list[SalonResponse])
async def list_salons(user: dict = Depends(get_current_user)):
    salons = await get_user_salons(str(user["_id"]))
    return [_format_salon(s) for s in salons]


@router.post("/direct", status_code=status.HTTP_201_CREATED, response_model=SalonResponse)
async def create_direct_conversation(data: DirectCreate, user: dict = Depends(get_current_user)):
    """Ouvre une conversation privée, ou renvoie celle qui existe déjà."""
    if data.username == user["username"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Impossible d'ouvrir une conversation avec soi-même",
        )

    db = get_db()
    target = await db.users.find_one({"username": data.username})
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Utilisateur introuvable")

    # Idempotent : réouvrir une conversation existante ne la duplique pas.
    existing = await find_direct(str(user["_id"]), str(target["_id"]))
    if existing:
        return _format_salon(existing)

    salon = await create_direct(user, target, data.encrypted_salon_key_self, data.encrypted_salon_key_other)
    return _format_salon(salon)


@router.get("/{salon_id}", response_model=SalonResponse)
async def get(salon_id: str, user: dict = Depends(get_current_user)):
    _require_object_id(salon_id)
    salon = await get_salon(salon_id)
    if not salon:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Salon not found")
    if not await is_member(salon_id, str(user["_id"])):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not a member")
    return _format_salon(salon)


@router.post("/{salon_id}/members", status_code=status.HTTP_201_CREATED)
async def add_salon_member(salon_id: str, data: MemberAdd, user: dict = Depends(get_current_user)):
    await _require_owner(salon_id, user)
    added = await add_member(salon_id, data.user_id, data.encrypted_salon_key)
    if not added:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User not found or already member")
    return {"detail": "Member added"}


@router.delete("/{salon_id}/members/{member_id}")
async def remove_salon_member(
    salon_id: str,
    member_id: str,
    data: MemberRemove,
    user: dict = Depends(get_current_user),
):
    salon = await _require_owner(salon_id, user)
    if str(salon["owner_id"]) == member_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Owner cannot be removed")
    removed = await remove_member(salon_id, member_id, [e.model_dump() for e in data.rekey])
    if not removed:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Member not found")
    return {"detail": "Member removed, salon key rotated"}


@router.post("/{salon_id}/channels", status_code=status.HTTP_201_CREATED, response_model=ChannelResponse)
async def create_channel(salon_id: str, data: ChannelCreate, user: dict = Depends(get_current_user)):
    await _require_owner(salon_id, user)
    channel = await add_channel(salon_id, data.name)
    if not channel:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Channel already exists")
    return ChannelResponse(id=str(channel["_id"]), name=channel["name"], created_at=channel["created_at"])


@router.get("/{salon_id}/channels", response_model=list[ChannelResponse])
async def list_channels(salon_id: str, user: dict = Depends(get_current_user)):
    _require_object_id(salon_id)
    if not await is_member(salon_id, str(user["_id"])):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not a member")
    salon = await get_salon(salon_id)
    if not salon:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Salon not found")
    return [
        ChannelResponse(id=str(c["_id"]), name=c["name"], created_at=c["created_at"]) for c in salon.get("channels", [])
    ]
