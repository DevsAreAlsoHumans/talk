"""Rate limiting in-memory, fenêtre glissante par clé (IP + chemin).

L'app tourne en monoprocesseur 1 worker (voir Dockerfile) : un état Python
en mémoire est exact et suffisant. La limite cible les endpoints de
connexion/inscription (anti force-brute) sans enfermer les autres routes.
"""

import asyncio
import time
from collections import defaultdict, deque
from collections.abc import Callable

from fastapi import HTTPException, Request, status

MAX_REQUESTS = 10
WINDOW_SECONDS = 60

_hits: dict[str, deque[float]] = defaultdict(deque)
_lock = asyncio.Lock()


def reset_rate_limits() -> None:
    """Vide l'état — réservé aux tests."""
    _hits.clear()


async def _check(key: str, limit: int, window_seconds: int) -> None:
    now = time.monotonic()
    async with _lock:
        queue = _hits[key]
        # Oublie les horodatages hors fenêtre avant de compter.
        while queue and now - queue[0] > window_seconds:
            queue.popleft()
        if len(queue) >= limit:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Trop de requêtes, réessayez dans une minute.",
            )
        queue.append(now)


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        # Derrière un proxy : le premier saut est le vrai client.
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def rate_limit(limit: int = MAX_REQUESTS, window_seconds: int = WINDOW_SECONDS) -> Callable:
    """Dépendance FastAPI : limite par (IP, chemin) dans une fenêtre glissante."""

    async def dependency(request: Request) -> None:
        await _check(f"{_client_ip(request)}|{request.url.path}", limit, window_seconds)

    return dependency
