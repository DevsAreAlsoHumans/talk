from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.db.mongo import client as mongo_client
from app.db.mongo import ensure_indexes
from app.db.redis_client import redis_client
from app.routers import auth


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    await ensure_indexes()
    yield
    await redis_client.aclose()
    mongo_client.close()


app = FastAPI(title="Talk", lifespan=lifespan)
app.include_router(auth.router)


@app.get("/health")
def health() -> dict[str, str]:
    """Vérifie que l'API répond (utilisé par Docker/CI)."""
    return {"status": "ok"}
