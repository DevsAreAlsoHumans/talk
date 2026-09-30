from datetime import datetime

from pydantic import BaseModel, Field, field_validator


class Credentials(BaseModel):
    username: str = Field(min_length=3, max_length=32, pattern=r"^[a-zA-Z0-9_.-]+$")
    password: str = Field(min_length=12, max_length=128)


class NamePayload(BaseModel):
    name: str = Field(min_length=1, max_length=64)

    @field_validator("name")
    @classmethod
    def normalize_name(cls, value: str) -> str:
        normalized = " ".join(value.split())
        if not normalized:
            raise ValueError("name cannot be empty")
        return normalized


class PublicKeyPayload(BaseModel):
    public_key: str = Field(min_length=32, max_length=4096)


class EncryptedMessagePayload(BaseModel):
    ciphertext: str = Field(min_length=1, max_length=100_000)
    nonce: str = Field(min_length=8, max_length=256)
    key_version: str = Field(min_length=1, max_length=128)


class UserResponse(BaseModel):
    id: str
    username: str
    public_key: str | None


class ServerResponse(BaseModel):
    id: str
    name: str
    owner_id: str


class ChannelResponse(BaseModel):
    id: str
    server_id: str
    name: str


class MessageResponse(BaseModel):
    id: str
    channel_id: str
    sender_id: str
    ciphertext: str
    nonce: str
    key_version: str
    created_at: datetime
