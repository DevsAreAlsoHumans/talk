from datetime import datetime
from typing import Any

from pydantic import BaseModel


class NotificationPublic(BaseModel):
    """Notification exposée au client (message/demande d'ami/invitation à un salon)."""

    id: str
    type: str
    payload: dict[str, Any]
    read: bool
    created_at: datetime
