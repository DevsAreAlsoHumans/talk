"""Notifications de messages reçus : persistance chez le destinataire + annonce en temps réel.

Point d'entrée unique pour les deux types de fil (salon et conversation directe entre
amis), afin que le déclenchement soit identique partout.

Deux partis pris importants :

- le serveur ne peut pas déchiffrer les messages, donc une notification ne dit **jamais**
  ce qui a été écrit : uniquement qui, où et de quel type d'envoi ;
- l'expéditeur n'est jamais notifié de ses propres messages, sinon il verrait remonter
  sa propre activité.
"""

import asyncio
from collections.abc import Callable, Iterable

from app.realtime import EventBus
from app.repositories.notifications import NotificationRepository

THREAD_ROOM = "room"
THREAD_CONVERSATION = "conv"


async def notify_message_sent(
    notifications: NotificationRepository,
    bus: EventBus,
    *,
    recipients: Iterable[str],
    sender_id: str,
    sender_username: str,
    thread_kind: str,
    thread_id: str,
    thread_label: str | Callable[[str], str],
    message: dict,
) -> None:
    """Enregistre puis diffuse une notification à chaque destinataire concerné.

    ``thread_label`` est le libellé du fil vu par le destinataire. C'est une *indication* :
    un client qui connaît déjà le nom du salon ou de son correspondant lui préfère le sien.
    Passer une fonction permet d'avoir un libellé par destinataire (utile en direct).
    """
    targets = sorted(user_id for user_id in recipients if user_id != sender_id)
    if not targets:
        return
    label_of = thread_label if callable(thread_label) else lambda _user_id: thread_label

    created = await asyncio.gather(
        *(
            notifications.create(
                user_id=user_id,
                kind=thread_kind,
                thread_id=thread_id,
                label=label_of(user_id),
                sender_username=sender_username,
                message_kind=message["kind"],
            )
            for user_id in targets
        )
    )
    for user_id, notification in zip(targets, created, strict=True):
        await bus.publish({"type": "notification", "notification": notification}, [user_id])
