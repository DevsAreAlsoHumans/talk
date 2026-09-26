def room_channel(room_id: str) -> str:
    """Nom du canal Redis pub/sub utilisé pour diffuser les messages d'un salon."""
    return f"room:{room_id}"
