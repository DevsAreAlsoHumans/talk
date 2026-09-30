from collections import defaultdict
from typing import Annotated

from fastapi import (
    Cookie,
    Depends,
    FastAPI,
    Header,
    HTTPException,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles

from app.config import settings
from app.schemas import (
    ChannelResponse,
    Credentials,
    EncryptedMessagePayload,
    MessageResponse,
    NamePayload,
    PublicKeyPayload,
    ServerResponse,
    UserResponse,
)
from app.security import create_session, delete_session, get_session, hash_password, verify_password
from app.store import Message, store

app = FastAPI(title="talk", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.allowed_origin],
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Content-Type", "X-CSRF-Token"],
)

connections: dict[str, set[WebSocket]] = defaultdict(set)


def current_session(session_id: Annotated[str | None, Cookie(alias="talk_session")] = None):
    session = get_session(session_id)
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required"
        )
    return session


def csrf_protected(
    session=Depends(current_session),
    csrf_token: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
):
    if not csrf_token or not __import__("secrets").compare_digest(csrf_token, session.csrf_token):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid CSRF token")
    return session


def set_session_cookie(response, session_id: str, csrf_token: str) -> None:
    response.set_cookie(
        "talk_session",
        session_id,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
        max_age=settings.session_ttl_seconds,
    )
    response.set_cookie(
        "talk_csrf",
        csrf_token,
        httponly=False,
        secure=settings.cookie_secure,
        samesite="lax",
        max_age=settings.session_ttl_seconds,
    )


@app.get("/health", tags=["system"])
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/auth/register", response_model=UserResponse, status_code=201, tags=["auth"])
async def register(credentials: Credentials, response: Response) -> UserResponse:
    if store.get_user_by_username(credentials.username.lower()):
        raise HTTPException(status_code=409, detail="Username already exists")
    user = store.create_user(credentials.username.lower(), hash_password(credentials.password))
    session_id, session = create_session(user.id)
    set_session_cookie(response, session_id, session.csrf_token)
    return UserResponse.model_validate(user, from_attributes=True)


@app.post("/api/auth/login", response_model=UserResponse, tags=["auth"])
async def login(credentials: Credentials, response: Response) -> UserResponse:
    user = store.get_user_by_username(credentials.username.lower())
    if user is None or not verify_password(credentials.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    session_id, session = create_session(user.id)
    set_session_cookie(response, session_id, session.csrf_token)
    return UserResponse.model_validate(user, from_attributes=True)


@app.post("/api/auth/logout", status_code=204, tags=["auth"])
async def logout(
    response: Response,
    session=Depends(current_session),
    session_id: Annotated[str | None, Cookie(alias="talk_session")] = None,
    csrf_token: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
) -> None:
    if not csrf_token or not __import__("secrets").compare_digest(csrf_token, session.csrf_token):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")
    delete_session(session_id)
    response.delete_cookie("talk_session")
    response.delete_cookie("talk_csrf")


@app.get("/api/auth/me", response_model=UserResponse, tags=["auth"])
async def me(session=Depends(current_session)) -> UserResponse:
    user = store.get_user(session.user_id)
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication required")
    return UserResponse.model_validate(user, from_attributes=True)


@app.post("/api/keys", response_model=UserResponse, tags=["keys"])
async def publish_key(payload: PublicKeyPayload, session=Depends(csrf_protected)) -> UserResponse:
    user = store.update_public_key(session.user_id, payload.public_key)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return UserResponse.model_validate(user, from_attributes=True)


@app.get("/api/servers", response_model=list[ServerResponse], tags=["servers"])
async def list_servers(session=Depends(current_session)) -> list[ServerResponse]:
    return [
        ServerResponse.model_validate(server, from_attributes=True)
        for server in store.list_servers(session.user_id)
    ]


@app.post("/api/servers", response_model=ServerResponse, status_code=201, tags=["servers"])
async def create_server(payload: NamePayload, session=Depends(csrf_protected)) -> ServerResponse:
    server = store.create_server(payload.name, session.user_id)
    return ServerResponse.model_validate(server, from_attributes=True)


@app.post("/api/servers/{server_id}/members/{user_id}", status_code=204, tags=["servers"])
async def add_member(server_id: str, user_id: str, session=Depends(csrf_protected)) -> None:
    server = store.get_server(server_id)
    if server is None or server.owner_id != session.user_id:
        raise HTTPException(status_code=403, detail="Only the owner can add members")
    if not store.add_member(server_id, user_id):
        raise HTTPException(status_code=404, detail="User not found")


@app.get(
    "/api/servers/{server_id}/channels", response_model=list[ChannelResponse], tags=["channels"]
)
async def list_channels(server_id: str, session=Depends(current_session)) -> list[ChannelResponse]:
    server = store.get_server(server_id)
    if server is None or session.user_id not in server.members:
        raise HTTPException(status_code=404, detail="Server not found")
    return [
        ChannelResponse.model_validate(channel, from_attributes=True)
        for channel in store.list_channels(server_id)
    ]


@app.post(
    "/api/servers/{server_id}/channels",
    response_model=ChannelResponse,
    status_code=201,
    tags=["channels"],
)
async def create_channel(
    server_id: str, payload: NamePayload, session=Depends(csrf_protected)
) -> ChannelResponse:
    server = store.get_server(server_id)
    if server is None or session.user_id not in server.members:
        raise HTTPException(status_code=404, detail="Server not found")
    channel = store.create_channel(server_id, payload.name)
    if channel is None:
        raise HTTPException(status_code=404, detail="Server not found")
    return ChannelResponse.model_validate(channel, from_attributes=True)


def accessible_channel(channel_id: str, user_id: str):
    channel = store.get_channel(channel_id)
    server = store.get_server(channel.server_id) if channel else None
    if channel is None or server is None or user_id not in server.members:
        raise HTTPException(status_code=404, detail="Channel not found")
    return channel


@app.get(
    "/api/channels/{channel_id}/messages", response_model=list[MessageResponse], tags=["messages"]
)
async def list_messages(channel_id: str, session=Depends(current_session)) -> list[MessageResponse]:
    accessible_channel(channel_id, session.user_id)
    return [
        MessageResponse.model_validate(message, from_attributes=True)
        for message in store.list_messages(channel_id)
    ]


@app.post(
    "/api/channels/{channel_id}/messages",
    response_model=MessageResponse,
    status_code=201,
    tags=["messages"],
)
async def create_message(
    channel_id: str, payload: EncryptedMessagePayload, session=Depends(csrf_protected)
) -> MessageResponse:
    accessible_channel(channel_id, session.user_id)
    message = store.add_message(
        Message(
            id=__import__("uuid").uuid4().hex,
            channel_id=channel_id,
            sender_id=session.user_id,
            ciphertext=payload.ciphertext,
            nonce=payload.nonce,
            key_version=payload.key_version,
        )
    )
    result = MessageResponse.model_validate(message, from_attributes=True)
    for connection in list(connections[channel_id]):
        await connection.send_json(result.model_dump(mode="json"))
    return result


@app.websocket("/ws/channels/{channel_id}")
async def channel_socket(websocket: WebSocket, channel_id: str) -> None:
    session = get_session(websocket.cookies.get("talk_session"))
    if session is None or accessible_channel_for_socket(channel_id, session.user_id) is None:
        await websocket.close(code=4401)
        return
    await websocket.accept()
    connections[channel_id].add(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        connections[channel_id].discard(websocket)


def accessible_channel_for_socket(channel_id: str, user_id: str):
    channel = store.get_channel(channel_id)
    server = store.get_server(channel.server_id) if channel else None
    if channel is None or server is None or user_id not in server.members:
        return None
    return channel


if __import__("pathlib").Path("frontend").exists():
    app.mount("/static", StaticFiles(directory="frontend"), name="static")

    @app.get("/", include_in_schema=False)
    async def index() -> FileResponse:
        return FileResponse("frontend/index.html")
