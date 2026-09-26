def room_channel(room_id: str) -> str:
    """Nom du canal Redis pub/sub utilisé pour diffuser les messages d'un salon."""
    return f"room:{room_id}"


def notification_channel(user_id: str) -> str:
    """Nom du canal Redis pub/sub utilisé pour diffuser les notifications d'un utilisateur."""
    return f"notifications:{user_id}"
