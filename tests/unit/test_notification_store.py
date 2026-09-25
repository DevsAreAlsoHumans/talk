"""Règles internes du stockage des notifications : regroupement des rafales et borne de l'historique.

Ces comportements sont vérifiés au niveau du repository : ce sont des règles de
regroupement dans le temps, indépendantes de l'API et bien plus rapides à éprouver ainsi.
"""

import asyncio
from datetime import UTC, datetime, timedelta

import fakeredis
import pytest

from app.repositories.notifications import (
    COALESCE_WINDOW_SECONDS,
    NOTIFICATION_LIMIT,
    NotificationRepository,
    _is_same_burst,
    thread_key,
)

USER = "user-1"
ROOM = thread_key("room", "11111111-1111-4111-8111-111111111111")
OTHER_ROOM = thread_key("room", "22222222-2222-4222-8222-222222222222")


async def _keys(redis, pattern: str = "notif:user-1*") -> list[str]:
    return sorted([key async for key in redis.scan_iter(pattern)])


def _run(scenario):
    async def runner():
        redis = fakeredis.FakeAsyncRedis(server=fakeredis.FakeServer(), decode_responses=True)
        try:
            return await scenario(NotificationRepository(redis), redis)
        finally:
            await redis.aclose()

    return asyncio.run(runner())


def _message(
    store: NotificationRepository, *, author: str = "alice", key: str = ROOM, label: str = "général"
):
    return store.create(
        user_id=USER,
        kind="room",
        thread_id=key.split(":", 1)[1],
        label=label,
        sender_username=author,
        message_kind="text",
    )


# ---------- Fenêtre de regroupement ----------


def _stamped(age_seconds: float, *, author: str = "alice", read: bool = False) -> dict:
    moment = (datetime.now(UTC) - timedelta(seconds=age_seconds)).isoformat(timespec="milliseconds")
    return {"sender_username": author, "read": read, "created_at": moment}


def test_a_fresh_message_from_the_same_author_joins_the_previous_line():
    now = datetime.now(UTC).isoformat(timespec="milliseconds")
    assert _is_same_burst(_stamped(1), "alice", now) is True


def test_a_message_from_another_author_never_joins():
    now = datetime.now(UTC).isoformat(timespec="milliseconds")
    assert _is_same_burst(_stamped(1, author="alice"), "bob", now) is False


def test_an_already_read_line_never_absorbs_a_new_message():
    now = datetime.now(UTC).isoformat(timespec="milliseconds")
    assert _is_same_burst(_stamped(1, read=True), "alice", now) is False


def test_a_line_that_is_too_old_never_absorbs_a_new_message():
    stale = datetime.now(UTC).isoformat(timespec="milliseconds")
    assert _is_same_burst(_stamped(COALESCE_WINDOW_SECONDS + 1), "alice", stale) is False


# ---------- Regroupement effectif ----------


def test_a_burst_keeps_one_line_and_counts_every_message():
    async def scenario(store, redis):
        for _ in range(3):
            await _message(store)
        recent, unread, total = await store.feed(USER, limit=30)
        return recent, unread, total, await redis.zcard("notif:user-1")

    recent, unread, total, stored = _run(scenario)
    assert len(recent) == 1
    assert recent[0]["count"] == 3
    assert unread == {ROOM: 3}
    assert total == 3
    assert stored == 1  # la ligne a été réécrite, pas dupliquée


def test_a_burst_stops_at_a_sender_change():
    async def scenario(store, _redis):
        await _message(store, author="alice")
        await _message(store, author="bob")
        recent, _, _ = await store.feed(USER, limit=30)
        return recent

    recent = _run(scenario)
    assert [line["sender_username"] for line in recent] == ["bob", "alice"]


def test_a_burst_stops_when_the_thread_has_been_read():
    """Un fil ouvert s'arrête d'accumuler : le message suivant ouvre une ligne neuve, et non lue."""

    async def scenario(store, _redis):
        await _message(store)
        await _message(store)
        await store.mark_thread_read(USER, ROOM)
        reopened = await _message(store)
        recent, unread, _ = await store.feed(USER, limit=30)
        return reopened, recent, unread

    reopened, recent, unread = _run(scenario)
    assert (reopened["count"], reopened["read"]) == (1, False)
    assert [line["count"] for line in recent] == [1, 2]
    assert [line["read"] for line in recent] == [False, True]
    assert unread == {ROOM: 1}


def test_another_thread_never_joins_the_burst():
    async def scenario(store, _redis):
        first = await _message(store, key=ROOM)
        second = await _message(store, key=OTHER_ROOM, label="autre")
        return first, second

    first, second = _run(scenario)
    assert first["id"] != second["id"]
    assert first["count"] == second["count"] == 1


# ---------- Bornes ----------


def test_the_history_is_capped_to_the_latest_notifications():
    async def scenario(store, redis):
        # Un fil distinct par message : aucun regroupement possible, on éprouve bien la troncature.
        for index in range(NOTIFICATION_LIMIT + 5):
            await _message(store, key=thread_key("room", f"room-{index}"))
        return await redis.zcard("notif:user-1"), await store.feed(USER, limit=NOTIFICATION_LIMIT + 10)

    stored, (recent, unread, total) = _run(scenario)
    assert stored == NOTIFICATION_LIMIT
    assert len(recent) == NOTIFICATION_LIMIT
    assert total == NOTIFICATION_LIMIT + 5  # le compte, lui, reste juste
    assert len(unread) == NOTIFICATION_LIMIT + 5


# ---------- Marquer comme lu ----------


def test_reading_a_thread_does_not_touch_the_others():
    async def scenario(store, _redis):
        await _message(store, key=ROOM)
        await _message(store, key=OTHER_ROOM, label="autre")
        await store.mark_thread_read(USER, ROOM)
        return await store.feed(USER, limit=30)

    recent, unread, total = _run(scenario)
    assert unread == {OTHER_ROOM: 1}
    assert total == 1
    assert {line["thread_id"]: line["read"] for line in recent} == {
        ROOM.split(":")[1]: True,
        OTHER_ROOM.split(":")[1]: False,
    }


def test_reading_a_thread_twice_writes_nothing():
    async def scenario(store, redis):
        await _message(store)
        await store.mark_thread_read(USER, ROOM)
        await store.mark_thread_read(USER, ROOM)  # déjà à jour : court-circuit attendu
        return await store.feed(USER, limit=30), await redis.exists("notif:user-1:unread")

    (recent, unread, total), counter_exists = _run(scenario)
    assert (unread, total) == ({}, 0)
    assert recent[0]["read"] is True
    assert counter_exists == 0  # le compteur du fil a complètement disparu


def test_reading_everything_clears_every_counter():
    async def scenario(store, redis):
        await _message(store, key=ROOM)
        await _message(store, key=OTHER_ROOM, label="autre")
        await store.mark_all_read(USER)
        return await store.feed(USER, limit=30), await _keys(redis)

    (recent, unread, total), remaining = _run(scenario)
    assert (unread, total) == ({}, 0)
    assert len(recent) == 2
    assert all(line["read"] for line in recent)
    # Ne restent que l'historique et le compteur de séquence : plus aucun état « non lu ».
    assert remaining == ["notif:user-1", "notif:user-1:seq"]


def test_reading_everything_with_nothing_pending_is_a_no_op():
    async def scenario(store, redis):
        await _message(store)
        await store.mark_all_read(USER)
        before = await _keys(redis)
        await store.mark_all_read(USER)
        return before, await _keys(redis)

    before, after = _run(scenario)
    assert before == after


@pytest.mark.parametrize("thread_id", ["", "pas-un-uuid"])
def test_thread_key_never_collides_between_a_room_and_a_conversation(thread_id):
    assert thread_key("room", thread_id) != thread_key("conv", thread_id)
