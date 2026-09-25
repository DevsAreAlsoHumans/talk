"""Notifications : ce que l'utilisateur a manqué, et ce qu'il a déjà lu.

L'état des non-lus est hébergé par le serveur (``repositories/notifications.py``) et non
par le navigateur : il survit ainsi à un refresh, à un onglet fermé ou à un changement de
machine, et il reste cohérent entre plusieurs onglets ou appareils.

Ouvrir un fil (un salon ou une conversation directe) le marque comme lu : le client
signale chaque ouverture, ce qui vide la pastille correspondante et la ligne de
notification associée.
"""

from typing import Annotated

from fastapi import APIRouter, Query

from app.deps import AuthDep, NotificationsDep
from app.repositories.notifications import thread_key
from app.schemas import MarkThreadReadRequest, NotificationFeed

router = APIRouter(prefix="/api/notifications", tags=["notifications"])


@router.get("", response_model=NotificationFeed)
async def list_notifications(
    auth: AuthDep,
    notifications: NotificationsDep,
    limit: Annotated[int, Query(ge=1, le=100)] = 30,
) -> dict:
    """Notifications récentes (les plus nouvelles d'abord) et non-lus par fil."""
    recent, unread, total = await notifications.feed(auth.user["id"], limit=limit)
    return {"notifications": recent, "unread": unread, "unread_total": total}


@router.post("/read", status_code=204)
async def read_thread(body: MarkThreadReadRequest, auth: AuthDep, notifications: NotificationsDep) -> None:
    """Marque un fil comme lu : plus de pastille, notifications du fil passées en « lu »."""
    await notifications.mark_thread_read(auth.user["id"], thread_key(body.thread_kind, str(body.thread_id)))


@router.post("/read-all", status_code=204)
async def read_all(auth: AuthDep, notifications: NotificationsDep) -> None:
    await notifications.mark_all_read(auth.user["id"])
