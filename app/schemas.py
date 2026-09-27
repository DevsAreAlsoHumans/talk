"""Schemas Pydantic stricts (entrees refusees a la moindre cle inconnue)."""

from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

USERNAME_PATTERN = r"^[a-z0-9_]+$"
USERNAME_MIN = 3
USERNAME_MAX = 32
PASSWORD_MIN = 12
PASSWORD_MAX = 128

Username = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        to_lower=True,
        min_length=USERNAME_MIN,
        max_length=USERNAME_MAX,
        pattern=USERNAME_PATTERN,
    ),
]

Password = Annotated[str, StringConstraints(min_length=PASSWORD_MIN, max_length=PASSWORD_MAX)]

StrictModel = ConfigDict(extra="forbid", str_strip_whitespace=True)


class RegisterRequest(BaseModel):
    model_config = StrictModel
    username: Username
    password: Password


class LoginRequest(BaseModel):
    model_config = StrictModel
    username: Username
    password: Password


class UserPublic(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    username: str
    created_at: datetime


class SessionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    user: UserPublic
    csrf_token: str


class CsrfResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    csrf_token: str = Field(min_length=1, max_length=256)


class MessageResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    detail: str = Field(max_length=200)


# --- Salons et canaux -----------------------------------------------------

SalonName = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=3,
        max_length=48,
        pattern=r"^[A-Za-z0-9 _-]+$",
    ),
]
ChannelName = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        to_lower=True,
        min_length=2,
        max_length=48,
        pattern=r"^[a-z0-9_-]+$",
    ),
]
Topic = Annotated[str, StringConstraints(strip_whitespace=True, max_length=200)]
Role = Literal["owner", "moderator", "member"]
ChannelKind = Literal["text", "private"]


class SalonCreate(BaseModel):
    model_config = StrictModel
    name: SalonName


class SalonUpdate(BaseModel):
    model_config = StrictModel
    name: SalonName


class SalonPublic(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    name: str
    owner_id: str
    role: Role | None = None
    member_count: int = 0
    created_at: datetime


class ChannelCreate(BaseModel):
    model_config = StrictModel
    name: ChannelName
    topic: Topic = ""
    kind: ChannelKind = "text"


class ChannelUpdate(BaseModel):
    model_config = StrictModel
    name: ChannelName | None = None
    topic: Topic | None = None


class ChannelPublic(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    salon_id: str
    name: str
    topic: str = ""
    kind: ChannelKind
    created_at: datetime


class MemberAdd(BaseModel):
    model_config = StrictModel
    username: Annotated[str, StringConstraints(strip_whitespace=True, to_lower=True, max_length=32)]


class MemberRoleUpdate(BaseModel):
    model_config = StrictModel
    role: Literal["moderator", "member"]


class MemberPublic(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    username: str
    role: Role


class MemberList(BaseModel):
    model_config = ConfigDict(extra="forbid")
    members: list[MemberPublic]
