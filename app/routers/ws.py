"""WebSocket : événements vers les membres + signalement d'appels vocaux.

Côté serveur → client : nouveaux messages, nouveaux membres, présence, offre/réponse de
call, candidats ICE, fin d'appel.

Côté client → serveur : ``ping`` (garde-veille), et le signalement d'appel (``call_offer``,
``call_answer``, ``ice_candidate``, ``call_end``) qui est *relayé* au destinataire — et
seulement s'ils partagent un salon : on ne peut appeler que des gens avec qui on a un
salon commun, et on ne peut rien faire traverser à un tiers.

Un WebSocket ne passe pas par le jeton CSRF (la poignée de main est un GET) : c'est
l'en-tête ``Origin`` qui protège contre le détournement de WebSocket inter-sites, en
plus du cookie de session (SameSite=Strict).
"""

import json

from fastapi import APIRouter, WebSocket

from app.realtime import Connection
from app.repositories.rooms import RoomRepository
from app.repositories.users import UserRepository
from app.security.csrf import origin_is_allowed
from app.security.sessions import SessionStore, hash_session_id

router = APIRouter()

POLICY_VIOLATION = 1008

SIGNAL_TYPES = {"call_offer", "call_answer", "ice_candidate", "call_end"}


async def _presence_targets(websocket: WebSocket, user_id: str) -> dict[str, set[str]]:
    """Salon → autres membres à prévenir, au moment de la connexion.

    Appelé uniquement quand l'utilisateur *passe en ligne* (première connexion) : à cet
    instant Redis répond normalement. Le résultat est mis en cache pour le rejouer hors
    ligne, afin que la fermeture du socket ne fasse aucune requête Redis.
    """
    state = websocket.app.state
    rooms = RoomRepository(state.redis)
    targets: dict[str, set[str]] = {}
    for room_id in await rooms.room_ids(user_id):
        others = await rooms.member_ids(room_id)
        others.discard(user_id)
        if others:
            targets[room_id] = others
    return targets


async def _broadcast_presence(bus, targets: dict[str, set[str]], user_id: str, *, online: bool) -> None:
    for room_id, others in targets.items():
        await bus.publish(
            {"type": "presence", "room_id": room_id, "user_id": user_id, "online": online},
            others,
        )


@router.websocket("/ws")
async def events_socket(websocket: WebSocket) -> None:
    state = websocket.app.state
    settings = state.settings

    if not origin_is_allowed(websocket.headers.get("origin"), settings.allowed_origins_list):
        await websocket.close(code=POLICY_VIOLATION)
        return

    session_id = websocket.cookies.get(settings.session_cookie_name)
    sessions = SessionStore(state.redis, settings.session_ttl_seconds)
    user_id = await sessions.get_user_id(session_id)
    if user_id is None or session_id is None:
        await websocket.close(code=POLICY_VIOLATION)
        return

    users = UserRepository(state.redis)
    user = await users.get(user_id)
    if user is None:
        await websocket.close(code=POLICY_VIOLATION)
        return

    await websocket.accept()
    manager = state.connection_manager
    connection = Connection(websocket=websocket, user_id=user_id, session_hash=hash_session_id(session_id))
    if manager.add(connection):
        targets = await _presence_targets(websocket, user_id)
        manager.set_presence_targets(user_id, targets)
        await _broadcast_presence(state.event_bus, targets, user_id, online=True)
    try:
        while True:
            message = await websocket.receive()
            if message["type"] == "websocket.disconnect":
                break
            text = message.get("text", "")
            if not text:
                continue
            try:
                data = json.loads(text)
            except (json.JSONDecodeError, TypeError):
                continue
            if data.get("type") == "ping":
                continue  # garde-veille : une connexion ouverte EST la preuve de vie
            if data.get("type") in SIGNAL_TYPES:
                await _relay_signal(websocket, sender=user, body=data)
    finally:
        if manager.remove(connection):
            await _broadcast_presence(
                state.event_bus, manager.pop_presence_targets(user_id), user_id, online=False
            )


async def _relay_signal(websocket: WebSocket, sender: dict[str, str], body: dict) -> None:
    """Relaye un message de signalement WebRTC vers le destinataire, s'ils partagent un salon."""
    state = websocket.app.state
    target_id = body.get("to")
    if not isinstance(target_id, str):
        return
    rooms = RoomRepository(state.redis)

    if not await rooms.has_shared_room(sender["id"], target_id):
        await state.event_bus.publish(
            {"type": "signal_error", "reason": "no_shared_room", "to": target_id}, [sender["id"]]
        )
        return

    if body["type"] == "call_offer" and not state.connection_manager.is_online(target_id):
        target = await (UserRepository(state.redis)).get(target_id)
        await state.event_bus.publish(
            {
                "type": "call_unreachable",
                "to": target_id,
                "to_username": target["username"] if target else "",
            },
            [sender["id"]],
        )
        return

    payload = {key: value for key, value in body.items() if key not in ("type", "to", "from")}
    await state.event_bus.publish(
        {"type": body["type"], "from": sender["id"], "from_username": sender["username"], **payload},
        [target_id],
    )
