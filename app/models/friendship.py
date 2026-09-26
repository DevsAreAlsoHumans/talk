from datetime import datetime

from pydantic import BaseModel, Field

from app.models.user import PeerPublic


class FriendRequestCreate(BaseModel):
    """Cible d'une demande d'ami : pseudo + discriminant façon Discord."""

    username: str
    discriminator: str = Field(pattern=r"^\d{4}$")


class FriendRequestPublic(BaseModel):
    """Demande d'ami en attente, du point de vue de l'utilisateur courant."""

    id: str
    direction: str  # "incoming" ou "outgoing"
    peer: PeerPublic
    created_at: datetime


class FriendPublic(BaseModel):
    """Amitié acceptée."""

    peer: PeerPublic
    since: datetime


class FriendRequestResult(BaseModel):
    """Résultat de l'envoi d'une demande : en attente, ou acceptée directement (réciprocité)."""

    status: str  # "pending" ou "accepted"
    peer: PeerPublic
