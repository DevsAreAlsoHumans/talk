import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, VerifyMismatchError

from app.config import settings

password_hasher = PasswordHasher()


@dataclass
class Session:
    user_id: str
    csrf_token: str
    expires_at: datetime


sessions: dict[str, Session] = {}


def hash_password(password: str) -> str:
    return password_hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return password_hasher.verify(password_hash, password)
    except (VerificationError, VerifyMismatchError):
        return False


def create_session(user_id: str) -> tuple[str, Session]:
    session_id = secrets.token_urlsafe(32)
    session = Session(
        user_id=user_id,
        csrf_token=secrets.token_urlsafe(24),
        expires_at=datetime.now(UTC) + timedelta(seconds=settings.session_ttl_seconds),
    )
    sessions[session_id] = session
    return session_id, session


def get_session(session_id: str | None) -> Session | None:
    if not session_id:
        return None
    session = sessions.get(session_id)
    if session is None or session.expires_at <= datetime.now(UTC):
        sessions.pop(session_id, None)
        return None
    return session


def delete_session(session_id: str | None) -> None:
    if session_id:
        sessions.pop(session_id, None)
