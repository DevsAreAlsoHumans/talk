"""Messages des salons : historique (polling), envoi, pièces jointes et suppression.

Le serveur ne manipule que du chiffré (nonce + ciphertext, en base64). Après
création, un événement ``new_message`` est diffusé aux abonnés WebSocket ;
après suppression, un événement ``message_deleted``. L'historique est paginable
(``?before=``/``?limit=``) avec un comportement par défaut identique à la v1.

Les images/GIF trop volumineux pour ``POST /messages`` (ciphertext plafonné à
4096 caractères) passent par ``POST /{room_id}/attachments`` : même stockage
``message:{id}`` (nonce + ciphertext, jamais de clair), avec ``kind="image"`` et
un ``mime`` optionnel ; l'événement WS et l'historique sont identiques.
"""

from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Response
from redis import Redis

from app.api.deps import get_current_user, get_room_or_404, require_member
from app.db.redis import get_redis
from app.realtime.hub import InProcessHub, get_hub
from app.repositories import messages
from app.schemas import AttachmentCreate, MessageCreate

router = APIRouter(prefix="/rooms", tags=["messages"])

__all__ = ["router"]


@router.get("/{room_id}/messages", response_model=dict)
def list_messages(
    room_id: str,
    after: int = Query(default=0, ge=0),
    before: int = Query(default=0, ge=0),
    limit: int = Query(default=0, ge=0, le=200),
    user: dict = Depends(get_current_user),
    redis: Redis = Depends(get_redis),
) -> dict:
    """Historique des messages (chiffrés), rétro-compatible.

    - ``?before=<seq>&limit=<n>`` : page des ``n`` messages antérieurs à
      ``seq`` (borne exclusive, rendus dans l'ordre croissant) ;
    - ``?limit=<n>`` seul : les ``n`` derniers messages ;
    - sinon (défauts ou ``?after=``) : comportement v1 exact — ``seq``
      strictement supérieur à ``after``, ``after=0`` = tout l'historique.
    """
    get_room_or_404(redis, room_id)
    require_member(redis, room_id, user["id"])
    if before > 0:
        items = messages.list_messages_before(redis, room_id, before, limit if limit else 50)
    elif limit > 0:
        items = messages.list_last_messages(redis, room_id, limit)
    else:
        items = messages.list_messages_after(redis, room_id, after)
    return {"messages": items}


@router.post("/{room_id}/messages", response_model=dict, status_code=201)
def post_message(
    room_id: str,
    body: MessageCreate,
    background: BackgroundTasks,
    user: dict = Depends(get_current_user),
    redis: Redis = Depends(get_redis),
    hub: InProcessHub = Depends(get_hub),
) -> dict:
    """Crée un message chiffré et diffuse ``new_message`` aux abonnés du salon."""
    get_room_or_404(redis, room_id)
    require_member(redis, room_id, user["id"])
    message = messages.create_message(redis, room_id, user["id"], body.nonce, body.ciphertext)
    background.add_task(
        hub.publish,
        room_id,
        {"type": "new_message", "payload": message},
    )
    return {"message": message}


@router.post("/{room_id}/attachments", response_model=dict, status_code=201)
def post_attachment(
    room_id: str,
    body: AttachmentCreate,
    background: BackgroundTasks,
    user: dict = Depends(get_current_user),
    redis: Redis = Depends(get_redis),
    hub: InProcessHub = Depends(get_hub),
) -> dict:
    """Crée une pièce jointe chiffrée (image) et diffuse ``new_message``.

    Mêmes contrôles d'accès que ``POST /messages`` (auth, 404 salon, 403 membre).
    Le serveur ne stocke que ``nonce`` + ``ciphertext`` (base64) : le champ
    ``kind`` vaut ``"image"`` et ``mime`` (optionnel) est conservé pour que le
    frontend sache comment décoder l'image. La diffusion WebSocket est
    strictement identique à celle d'un message textuel.
    """
    get_room_or_404(redis, room_id)
    require_member(redis, room_id, user["id"])
    message = messages.create_message(
        redis,
        room_id,
        user["id"],
        body.nonce,
        body.ciphertext,
        kind=body.kind,
        mime=body.mime,
    )
    background.add_task(
        hub.publish,
        room_id,
        {"type": "new_message", "payload": message},
    )
    return {"message": message}


@router.delete("/{room_id}/messages/{message_id}", status_code=204)
def delete_message(
    room_id: str,
    message_id: str,
    response: Response,
    background: BackgroundTasks,
    user: dict = Depends(get_current_user),
    redis: Redis = Depends(get_redis),
    hub: InProcessHub = Depends(get_hub),
) -> Response:
    """Supprime un message — auteur uniquement — et diffuse ``message_deleted``.

    La suppression est définitive (hash purgé + retiré du feed). Le compteur
    ``seq`` du salon n'est pas décrémenté (trous de numéros acceptés). La
    réponse est un 204 vide ; l'événement WS est poussé en tâche de fond.

    Le contrôle d'accès est double : être membre du salon de l'URL (403 sinon)
    **et** le message doit appartenir à ce même salon (404 sinon, pour ne pas
    fuir l'existence d'un message hors du salon) ; seul l'auteur peut
    supprimer (403).
    """
    get_room_or_404(redis, room_id)
    require_member(redis, room_id, user["id"])
    message = messages.get_message(redis, message_id)
    if message is None:
        raise HTTPException(status_code=404, detail="Message not found")
    # Le message doit appartenir au salon de l'URL : sans cette vérification,
    # un membre du salon A pourrait supprimer ses messages d'un salon B qu'il
    # a quitté (le contrôle d'auteur seul suffirait). 404 générique : on ne
    # fuite pas l'existence du message hors du salon.
    if message["room_id"] != room_id:
        raise HTTPException(status_code=404, detail="Message not found")
    if message["author_id"] != user["id"]:
        raise HTTPException(status_code=403, detail="Only the author can delete this message")
    messages.delete_message(redis, message_id)
    background.add_task(
        hub.publish,
        room_id,
        {
            "type": "message_deleted",
            "payload": {"room_id": room_id, "id": message_id, "seq": message["seq"]},
        },
    )
    # FastAPI injecte une ``Response`` sans statut : on pose le 204 explicitement
    # avant de la renvoyer (le retour direct d'une Response ignore ``status_code``).
    response.status_code = 204
    return response
