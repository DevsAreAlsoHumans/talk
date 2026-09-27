"""Schemas Pydantic stricts (entrees refusees a la moindre cle inconnue)."""

from datetime import datetime
from typing import Annotated

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
