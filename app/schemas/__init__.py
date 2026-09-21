"""Schémas Pydantic de l'API (auth, salons, messages)."""

from app.schemas.auth import (
    USERNAME_PATTERN,
    AuthResponse,
    ChangePasswordRequest,
    LoginRequest,
    ProfileUpdate,
    RegisterRequest,
    UserPublic,
    valid_public_key,
)
from app.schemas.messages import AttachmentCreate, Message, MessageCreate
from app.schemas.rooms import KeyWrapRequest, MemberPublic, Room, RoomCreate, RoomKeyView

__all__ = [
    "USERNAME_PATTERN",
    "AttachmentCreate",
    "AuthResponse",
    "ChangePasswordRequest",
    "KeyWrapRequest",
    "LoginRequest",
    "MemberPublic",
    "Message",
    "MessageCreate",
    "ProfileUpdate",
    "RegisterRequest",
    "Room",
    "RoomCreate",
    "RoomKeyView",
    "UserPublic",
    "valid_public_key",
]
