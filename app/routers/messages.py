"""Historique et envoi des messages.

Répartition volontaire des transports :

* l'**historique** se lit en HTTP, avec un curseur. C'est une lecture paginée,
  sans état, qui se prête bien à REST et reste rejouable après un plantage ;
* l'**envoi** passe par le WebSocket déjà ouvert. Un POST HTTP d'envoi aurait
  exigé une seconde connexion, et le retour d'erreur d'un envoi doit arriver
  dans le même flux que les messages des autres.

Le serveur ne déchiffre rien. Il valide la forme du ciphertext, l'associe à un
`sender_id` pris dans la session, puis le relaie tel quel. Il ne peut donc pas
garantir qu'un message est authentique au sens cryptographique : `sender_id`
provient de la session, pas d'une signature.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, status
from pydantic import TypeAdapter, ValidationError
from pymongo.errors import DuplicateKeyError
from starlette.websockets import WebSocketDisconnect

from app.chat_schemas import (
    DEFAULT_HISTORY_LIMIT,
    MAX_HISTORY_LIMIT,
    MessageListOut,
    MessageOut,
    SendIn,
    WsFrameIn,
)
from app.chat_store import ChatStore, to_object_id
from app.deps import (
    get_chat_store,
    get_current_user_ws,
    message_rate_limit_retry_after,
    require_channel_member,
    require_trusted_origin_ws,
)
from app.realtime import connection_manager as manager

router = APIRouter(tags=["messages"])

WS_FRAME_ADAPTER: TypeAdapter[Any] = TypeAdapter(WsFrameIn)

CHANNEL_NOT_FOUND = "Canal introuvable."
CHANNEL_FORBIDDEN = "Accès refusé à ce canal."


@router.get("/channels/{channel_id}/messages", response_model=MessageListOut)
async def list_messages(
    channel_id: str,
    _channel: Annotated[dict[str, Any], Depends(require_channel_member)],
    chat: Annotated[ChatStore, Depends(get_chat_store)],
    limit: Annotated[int, Query(ge=1, le=MAX_HISTORY_LIMIT)] = DEFAULT_HISTORY_LIMIT,
    before: Annotated[str | None, Query()] = None,
) -> MessageListOut:
    """Historique paginé, du plus ancien au plus récent.

    `before` est l'identifiant du message **le plus ancien** déjà reçu : la page
    suivante contient donc les messages plus anciens que lui. Les identifiants
    MongoDB croissent avec le temps, ce qui en fait un curseur naturel et stable,
    là où un décalage sauterait des messages dès qu'un message arrive entre deux
    appels.
    """
    channel_object_id = to_object_id(channel_id)
    cursor = to_object_id(before) if before else None
    if before and cursor is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Curseur invalide.")

    # On demande un message de plus que la page demandée : sa présence prouve
    # qu'il en existe d'plus anciens, sans coût de comptage supplémentaire.
    fetched = await chat.list_messages(channel_object_id, cursor, limit + 1)
    has_more = len(fetched) > limit
    # Le magasin rend les messages du plus ancien au plus récent ; le message
    # surnuméraire est donc le plus ancien et se trouve en tête.
    page = fetched[1:] if has_more else fetched

    return MessageListOut(
        messages=[_to_message_out(document) for document in page], has_more=has_more
    )


@router.websocket("/channels/{channel_id}")
async def channel_socket(
    websocket: WebSocket,
    channel_id: str,
    _origin: Annotated[None, Depends(require_trusted_origin_ws)],
    user: Annotated[dict[str, Any], Depends(get_current_user_ws)],
    chat: Annotated[ChatStore, Depends(get_chat_store)],
) -> None:
    """Point d'entrée temps réel d'un canal : envoi et réception.

    L'origine est vérifiée avant toute lecture en base, et la session avant
    `accept()`. Ces deux refus lèvent une `WebSocketException`, que le client
    reçoit en 1008.

    L'appartenance au canal, elle, est contrôlée après `accept()` : le client
    obtient alors un code applicatif explicite, plus lisible qu'un échec de
    négociation. Vérifier l'origine reste indispensable — un navigateur envoie
    les cookies automatiquement, et une page tierce pourrait donc ouvrir ce
    socket à la place de l'utilisateur.
    """
    await websocket.accept()

    channel_object_id = to_object_id(channel_id)
    channel = await chat.get_channel(channel_object_id) if channel_object_id else None
    if channel is None:
        await websocket.close(code=4404, reason=CHANNEL_NOT_FOUND)
        return
    if user["_id"] not in channel.get("members", []):
        await websocket.close(code=4403, reason=CHANNEL_FORBIDDEN)
        return

    # La connexion ne sert qu'à ce canal : on l'inscrit donc immédiatement, et
    # `disconnect` la retirera de tous les canaux d'un coup à la fermeture.
    await manager.connect(websocket)
    await manager.subscribe(str(channel_object_id), websocket)
    try:
        await _pump(websocket, user, channel_object_id, chat)
    finally:
        await manager.disconnect(websocket)


async def _pump(
    websocket: WebSocket,
    user: dict[str, Any],
    channel_id: Any,
    chat: ChatStore,
) -> None:
    """Boucle de réception : n'accepte que l'envoi de messages.

    Une connexion ne dessert qu'un seul canal, désigné par l'URL. Il n'y a donc
    rien à s'abonner : les trames `subscribe` et `unsubscribe` existent dans le
    protocole pour rendre l'erreur explicite, mais sont refusées ici. Le client
    n'a qu'à ouvrir une connexion par canal.
    """
    while True:
        try:
            raw = await websocket.receive_json()
        except WebSocketDisconnect:
            # Fermeture normale : le client a quitté la page ou perdu le réseau.
            # Ce n'est pas une erreur, et la laisser remonter produirait une
            # trace d'exception pour un événement ordinaire.
            return
        except ValueError:
            await websocket.send_json({"type": "error", "error": "Trame JSON invalide."})
            continue

        try:
            frame = WS_FRAME_ADAPTER.validate_python(raw)
        except ValidationError:
            await websocket.send_json({"type": "error", "error": "Trame invalide."})
            continue

        if not isinstance(frame, SendIn):
            await websocket.send_json(
                {
                    "type": "error",
                    "error": "L'abonnement est implicite : la connexion porte déjà "
                    "l'identifiant du canal.",
                }
            )
            continue

        retry_after = message_rate_limit_retry_after(user["_id"])
        if retry_after:
            await websocket.send_json(
                {
                    "type": "error",
                    "error": "Trop de messages envoyés, réessayez dans un instant.",
                    "retry_after": retry_after,
                }
            )
            continue

        try:
            message = await chat.insert_message(
                channel_id=channel_id,
                sender_id=user["_id"],
                client_id=str(frame.client_id),
                ciphertext=frame.ciphertext,
                iv=frame.iv,
            )
        except DuplicateKeyError:
            # `client_id` déjà connu : le client a réémis sans avoir vu l'accusé
            # de réception. Ce n'est pas une erreur, seulement un doublon évité.
            await websocket.send_json(
                {
                    "type": "ack",
                    "client_id": str(frame.client_id),
                    "duplicate": True,
                }
            )
            continue

        await manager.broadcast(
            channel_id, _to_message_out(message).model_dump(mode="json"), exclude=websocket
        )
        await websocket.send_json({"type": "ack", "client_id": str(frame.client_id)})


def _to_message_out(document: dict[str, Any]) -> MessageOut:
    return MessageOut(
        id=str(document["_id"]),
        channel_id=str(document["channel_id"]),
        sender_id=str(document["sender_id"]),
        client_id=str(document["client_id"]),
        ciphertext=document["ciphertext"],
        iv=document["iv"],
        created_at=document["created_at"],
    )
