from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.auth import router as auth_router
from app.db import mongo

FRONTEND_DIR = Path(__file__).resolve().parents[1] / "frontend"


@asynccontextmanager
async def lifespan(app: FastAPI):
    await mongo.connect()
    yield
    await mongo.close()


app = FastAPI(title="talk", lifespan=lifespan)

app.include_router(auth_router)


@app.get("/api/status")
async def root():
    return {"status": "ok", "service": "talk"}


@app.get("/health")
async def health():
    await mongo.ping()
    return {"status": "healthy", "database": "mongodb"}


if FRONTEND_DIR.is_dir():
    app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")