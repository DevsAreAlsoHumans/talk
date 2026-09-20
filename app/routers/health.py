from fastapi import APIRouter, HTTPException

from app.deps import RedisDep

router = APIRouter(prefix="/api", tags=["health"])


@router.get("/health")
async def health(redis: RedisDep) -> dict[str, str]:
    try:
        await redis.ping()
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Service indisponible") from exc
    return {"status": "ok"}
