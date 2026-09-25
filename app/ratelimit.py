"""Limitation de débit en mémoire (fenêtre glissante).

Protège les endpoints sensibles contre le brute-force et le spam.
Implémentation volontairement sans dépendance externe : une simple
fenêtre glissante par clé (IP + route), purgée à la volée.
"""

import time
from collections import defaultdict, deque

from fastapi import HTTPException, Request, status

_buckets: dict[str, deque[float]] = defaultdict(deque)


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def reset() -> None:
    """Vide tous les compteurs (utilisé par les tests)."""
    _buckets.clear()


def hit(key: str, limit: int, window: int) -> tuple[bool, int]:
    """Enregistre un appel. Retourne (autorisé, secondes avant réessai)."""
    now = time.monotonic()
    bucket = _buckets[key]
    while bucket and now - bucket[0] >= window:
        bucket.popleft()
    if len(bucket) >= limit:
        retry_after = int(window - (now - bucket[0])) + 1
        return False, retry_after
    bucket.append(now)
    return True, 0


def enforce(request: Request, scope: str, limit: int, window: int) -> None:
    """Applique la limite ou lève une 429 avec l'en-tête Retry-After."""
    key = f"{scope}:{_client_ip(request)}"
    allowed, retry_after = hit(key, limit, window)
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Trop de tentatives. Réessayez dans un instant.",
            headers={"Retry-After": str(retry_after)},
        )
