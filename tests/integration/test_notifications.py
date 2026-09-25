"""Notifications de messages : ce qu'un destinataire « rate », et ce qu'il a déjà lu.

L'état des non-lus vit côté serveur, pas dans le navigateur : ces tests vérifient donc
surtout deux choses. Que le compte est juste (un message = un non lu, une rafale = une
ligne décomptée, un fil ouvert = zéro), et qu'une notification n'apprend jamais au serveur
ce qu'il n'a pas le droit de savoir.
"""

from tests.helpers import e2e
from tests.helpers.actor import Actor
from tests.helpers.redis_dump import dump_redis

THREAD_ROOM = "room"
THREAD_CONVERSATION = "conv"


def room_with(alice, bob, name: str = "général") -> str:
    """Salon partagé entre Alice et Bob, clé comprise des deux côtés."""
    room_id = alice.create_room(name)
    alice.add_member(room_id, bob)
    bob.load_room_key(room_id)
    return room_id


def friends_with_conv(alice, bob) -> str:
    """Alice et Bob sont amis et ont une conversation directe ouverte des deux côtés."""
    alice.send_friend_request(bob)
    bob.accept_friend(alice)
    conv_id = alice.create_conversation(bob)
    bob.load_conv_key(conv_id)
    return conv_id


# ---------- Création ----------


def test_a_room_message_notifies_the_other_members(alice, bob):
    room_id = room_with(alice, bob)
    alice.send(room_id, "coucou")

    feed = bob.notifications()
    assert feed["unread_total"] == 1
    assert feed["unread"] == {f"{THREAD_ROOM}:{room_id}": 1}
    (notification,) = feed["notifications"]
    assert notification["thread_kind"] == THREAD_ROOM
    assert notification["thread_id"] == room_id
    assert notification["thread_label"] == "général"
    assert notification["sender_username"] == "alice"
    assert notification["kind"] == "text"
    assert notification["count"] == 1
    assert notification["read"] is False


def test_a_direct_message_notifies_the_friend(alice, bob):
    conv_id = friends_with_conv(alice, bob)
    alice.conv_send(conv_id, "on se parle ?")

    feed = bob.notifications()
    assert feed["unread"] == {f"{THREAD_CONVERSATION}:{conv_id}": 1}
    notification = feed["notifications"][0]
    assert notification["thread_kind"] == THREAD_CONVERSATION
    assert notification["thread_id"] == conv_id
    assert notification["sender_username"] == "alice"


def test_the_author_is_never_notified_of_their_own_message(alice, bob):
    room_id = room_with(alice, bob)
    alice.send(room_id, "je me parle à moi-même")

    assert alice.notifications() == {"notifications": [], "unread": {}, "unread_total": 0}
    assert bob.notifications()["unread_total"] == 1


def test_a_non_member_is_never_notified(alice, bob, make_user):
    carol = make_user("carol")  # aucun salon commun avec Alice
    room_id = alice.create_room()
    alice.add_member(room_id, bob)
    alice.send(room_id, "réservé aux membres")

    assert carol.notifications() == {"notifications": [], "unread": {}, "unread_total": 0}
    assert bob.notifications()["unread_total"] == 1


def test_media_messages_are_described_by_their_kind(alice, bob):
    room_id = room_with(alice, bob)
    alice.send_media(room_id, b"\x89PNG sans importance", kind="image", mime="image/png")

    notification = bob.notifications()["notifications"][0]
    assert notification["kind"] == "image"
    # Ni le type MIME ni les données ne sont recopiés : le serveur n'a rien à en faire.
    assert "mime" not in notification


# ---------- Regroupement des rafales ----------


def test_a_burst_from_one_author_becomes_a_single_counted_line(alice, bob):
    room_id = room_with(alice, bob)
    for index in range(3):
        alice.send(room_id, f"message {index}")

    feed = bob.notifications()
    assert len(feed["notifications"]) == 1
    assert feed["notifications"][0]["count"] == 3
    assert feed["unread"] == {f"{THREAD_ROOM}:{room_id}": 3}
    assert feed["unread_total"] == 3


def test_two_authors_in_the_same_thread_give_two_lines(alice, bob, make_user):
    carol = make_user("carol")
    room_id = alice.create_room()
    alice.add_member(room_id, bob)
    bob.load_room_key(room_id)
    alice.add_member(room_id, carol)
    carol.load_room_key(room_id)

    alice.send(room_id, "salut")
    bob.send(room_id, "salut")

    feed = carol.notifications()
    assert len(feed["notifications"]) == 2
    assert {line["sender_username"] for line in feed["notifications"]} == {"alice", "bob"}
    assert feed["unread_total"] == 2


def test_two_threads_are_counted_separately(alice, bob):
    first = room_with(alice, bob, "premier")
    second = room_with(alice, bob, "second")
    alice.send(first, "dans le premier")
    alice.send(second, "dans le second")
    alice.send(second, "encore dans le second")

    feed = bob.notifications()
    assert feed["unread"] == {f"{THREAD_ROOM}:{first}": 1, f"{THREAD_ROOM}:{second}": 2}
    assert feed["unread_total"] == 3


# ---------- Marquer comme lu ----------


def test_opening_a_thread_clears_its_unread_count(alice, bob):
    room_id = room_with(alice, bob)
    other_room = room_with(alice, bob, "autre")
    alice.send(room_id, "à lire")
    alice.send(other_room, "à ne pas lire")

    assert bob.read_thread_notifications(THREAD_ROOM, room_id).status_code == 204

    feed = bob.notifications()
    assert feed["unread"] == {f"{THREAD_ROOM}:{other_room}": 1}
    assert feed["unread_total"] == 1
    # L'historique reste complet : la ligne du salon ouvert passe simplement en « lu ».
    assert len(feed["notifications"]) == 2
    read_flags = {line["thread_id"]: line["read"] for line in feed["notifications"]}
    assert read_flags == {room_id: True, other_room: False}


def test_reading_a_thread_twice_is_harmless(alice, bob):
    room_id = room_with(alice, bob)
    alice.send(room_id, "à lire")
    assert bob.read_thread_notifications(THREAD_ROOM, room_id).status_code == 204
    assert bob.read_thread_notifications(THREAD_ROOM, room_id).status_code == 204
    assert bob.notifications()["unread_total"] == 0


def test_a_message_after_a_read_starts_a_fresh_line(alice, bob):
    """Le fil a été ouvert : le message suivant ne doit pas être fusionné avec une ligne déjà lue."""
    room_id = room_with(alice, bob)
    alice.send(room_id, "premier")
    bob.read_thread_notifications(THREAD_ROOM, room_id)
    alice.send(room_id, "second")

    feed = bob.notifications()
    assert len(feed["notifications"]) == 2
    assert all(line["count"] == 1 for line in feed["notifications"])
    assert feed["unread_total"] == 1
    assert [line["read"] for line in feed["notifications"]] == [False, True]


def test_read_all_clears_every_thread(alice, bob):
    first = room_with(alice, bob, "premier")
    second = room_with(alice, bob, "second")
    alice.send(first, "un")
    alice.send(second, "deux")

    assert bob.read_all_notifications().status_code == 204

    feed = bob.notifications()
    assert feed["unread"] == {}
    assert feed["unread_total"] == 0
    assert all(line["read"] for line in feed["notifications"])


def test_reading_all_with_nothing_pending_does_nothing(alice, bob):
    assert bob.read_all_notifications().status_code == 204
    assert bob.notifications()["unread_total"] == 0


# ---------- Intégrité et confidentialité ----------


def test_notifications_never_contain_the_message_content(alice, bob, raw_redis):
    room_id = room_with(alice, bob)
    secret = "le mot de passe du wifi est PATATE-42"
    alice.send(room_id, secret)

    assert secret not in dump_redis(raw_redis)
    notification = bob.notifications()["notifications"][0]
    serialized = repr(notification)
    assert "ciphertext" not in serialized
    assert "PATATE" not in serialized
    assert set(notification) == {
        "id",
        "seq",
        "thread_kind",
        "thread_id",
        "thread_label",
        "sender_username",
        "kind",
        "count",
        "read",
        "created_at",
        "updated_at",
    }


def test_the_feed_is_truncated_to_its_limit(alice, bob):
    # Un salon par message : le regroupement des rafales ne peut pas entrer en jeu.
    for index in range(4):
        alice.send(room_with(alice, bob, f"salon {index}"), f"message {index}")

    feed = bob.notifications(limit=2)
    assert len(feed["notifications"]) == 2
    # Le compte, lui, reste juste même si l'historique affiché est tronqué.
    assert feed["unread_total"] == 4


def test_feed_limits_are_validated(alice):
    for params in [{"limit": 0}, {"limit": 101}, {"limit": "x"}]:
        assert alice.get("/api/notifications", params=params).status_code == 422


# ---------- Accès et validation ----------


def test_notifications_require_a_session(client, alice):
    anonymous = Actor(client, e2e.Identity.create("anonyme"))
    anonymous.fetch_csrf()  # sans jeton, la CSRF répondrait 403 avant même d'atteindre la session
    body = {"thread_kind": "room", "thread_id": alice.user_id}
    assert anonymous.get("/api/notifications").status_code == 401
    assert anonymous.post("/api/notifications/read", body).status_code == 401
    assert anonymous.post("/api/notifications/read-all").status_code == 401


def test_reading_a_thread_validates_its_kind(alice):
    room_id = alice.create_room()
    for body in [
        {"thread_kind": "salon", "thread_id": room_id},  # .kind hors énumération
        {"thread_kind": "room", "thread_id": "pas-un-uuid"},
        {"thread_kind": "room"},  # champ manquant
        {"thread_kind": "room", "thread_id": room_id, "extra": 1},  # champ inattendu
    ]:
        assert alice.post("/api/notifications/read", body).status_code == 422


def test_a_notification_is_never_addressed_to_someone_else(alice, bob, make_user):
    """Chaque destinataire a son propre compteur : marquer un fil lu n'altère pas celui d'un autre."""
    carol = make_user("carol")
    room_id = alice.create_room()
    alice.add_member(room_id, bob)
    alice.add_member(room_id, carol)
    alice.send(room_id, "bonjour à tous")

    bob.read_thread_notifications(THREAD_ROOM, room_id)

    assert bob.notifications()["unread_total"] == 0
    assert carol.notifications()["unread_total"] == 1


# ---------- Temps réel ----------


def test_the_notification_is_announced_over_the_websocket(alice, bob):
    room_id = room_with(alice, bob)
    with bob.websocket() as bob_socket:
        alice.send(room_id, "en direct")
        # Le message passe d'abord sur le bus, la notification juste après : les deux sont ordonnés.
        assert bob_socket.receive_json()["type"] == "message"
        event = bob_socket.receive_json()

    assert event["type"] == "notification"
    assert event["notification"]["thread_id"] == room_id
    assert event["notification"]["sender_username"] == "alice"
    assert "ciphertext" not in event["notification"]


def test_the_author_receives_no_notification_event(alice, bob, make_user):
    room_id = room_with(alice, bob)
    alice.add_member(room_id, make_user("carol"))
    with alice.websocket() as alice_socket:
        alice.send(room_id, "moi qui parle")
        assert alice_socket.receive_json()["type"] == "message"
        # Un événement qui la concerne suit immédiatement : aucune notification ne s'est intercalée.
        alice.add_member(room_id, make_user("dave"))
        assert alice_socket.receive_json()["type"] == "member_added"

    assert alice.notifications()["notifications"] == []
