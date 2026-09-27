from pydantic import BaseModel, Field, model_validator
from typing import Optional
from datetime import datetime
from enum import Enum


class UserRole(str, Enum):
    """Rôles utilisateur dans le système."""
    MEMBER = "member"
    MODERATOR = "moderator"
    ADMIN = "admin"


class UserCreate(BaseModel):
    """Schéma pour l'inscription."""
    username: str
    email: str
    password: str


class UserLogin(BaseModel):
    """Schéma pour la connexion."""
    email: str
    password: str


class User(BaseModel):
    """Modèle utilisateur."""
    id: str
    username: str
    email: str
    created_at: datetime
    role: UserRole = UserRole.MEMBER


class UserResponse(BaseModel):
    """Réponse API utilisateur (sans mot de passe)."""
    id: str
    username: str
    email: str
    created_at: datetime
    role: UserRole
    access_token: Optional[str] = None


class RoomType(str, Enum):
    """Types de salons/chaînes."""
    SERVER = "server"
    CHANNEL = "channel"
    DIRECT = "direct"
    GROUP = "group"


class RoomCreate(BaseModel):
    """Schéma pour créer un salon."""
    name: str
    description: Optional[str] = None
    room_type: RoomType = RoomType.CHANNEL
    is_private: bool = False
    parent_server: Optional[str] = None
    member_ids: list[str] = Field(default_factory=list)
    member_identifiers: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_room_structure(self):
        if self.room_type == RoomType.SERVER and self.parent_server:
            raise ValueError("Un serveur ne peut pas avoir de serveur parent")
        if self.room_type == RoomType.CHANNEL and not self.parent_server:
            raise ValueError("Un salon doit appartenir à un serveur")
        invited_members = self.member_ids + self.member_identifiers
        if self.room_type == RoomType.DIRECT and len(invited_members) != 1:
            raise ValueError("Un message direct doit cibler exactement un membre")
        if self.room_type == RoomType.GROUP and not invited_members:
            raise ValueError("Un groupe doit avoir au moins un membre invité")
        return self


class MemberAdd(BaseModel):
    """Membre à ajouter par identifiant, email ou nom d'utilisateur."""
    identifier: str = Field(min_length=1)


class Room(BaseModel):
    """Modèle salon/canal."""
    id: str
    name: str
    description: Optional[str] = None
    room_type: RoomType
    is_private: bool = False
    parent_server: Optional[str] = None
    created_by: str
    created_at: datetime
    member_count: int = 0


class RoomResponse(BaseModel):
    """Réponse API salon."""
    id: str
    name: str
    description: Optional[str] = None
    room_type: RoomType
    is_private: bool = False
    parent_server: Optional[str] = None
    created_by: str
    created_at: datetime
    member_count: int = 0


class MemberRole(str, Enum):
    """Rôles de membre dans un salon."""
    OWNER = "owner"
    MODERATOR = "moderator"
    MEMBER = "member"


class RoomMember(BaseModel):
    """Membre d'un salon."""
    id: str
    room_id: str
    user_id: str
    role: MemberRole = MemberRole.MEMBER
    joined_at: datetime


class MessageType(str, Enum):
    """Types de messages."""
    TEXT = "text"
    FILE = "file"
    IMAGE = "image"
    SYSTEM = "system"


class MessageCreate(BaseModel):
    """Schéma pour créer un message."""
    room_id: str
    content: str  # Contenu chiffré pour E2E
    message_type: MessageType = MessageType.TEXT
    parent_message_id: Optional[str] = None
    encrypted: bool = True  # Le message est-il chiffré E2E ?


class Message(BaseModel):
    """Modèle message."""
    id: str
    room_id: str
    user_id: str
    author_username: Optional[str] = None
    content: str
    message_type: MessageType = MessageType.TEXT
    parent_message_id: Optional[str] = None
    encrypted: bool = True
    created_at: datetime


class MessageResponse(BaseModel):
    """Réponse API message."""
    id: str
    room_id: str
    user_id: str
    content: str
    message_type: MessageType
    encrypted: bool = True
    created_at: datetime


class ErrorResponse(BaseModel):
    """Réponse d'erreur standardisée."""
    error: str
    detail: Optional[str] = None