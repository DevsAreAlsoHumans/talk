from fastapi import HTTPException, Request, status

from app.config import Settings
from app.storage import RedisStore


def client_identifier(request: Request) -> str:
    if request.client is None:
        return "unknown"
    return request.client.host


async def enforce_rate_limit(
    request: Request,
    store: RedisStore,
    settings: Settings,
    *,
    scope: str,
    limit: int,
    window_seconds: int,
) -> None:
    allowed, retry_after = await store.check_rate_limit(
        scope, client_identifier(request), limit, window_seconds
    )
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Trop de tentatives. Réessayez plus tard.",
            headers={"Retry-After": str(retry_after)},
        )
