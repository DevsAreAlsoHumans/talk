from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.auth import router as auth_router
from app.db import mongo


@asynccontextmanager
async def lifespan(app: FastAPI):
    await mongo.connect()
    yield
    await mongo.close()


app = FastAPI(title="talk", lifespan=lifespan)

app.include_router(auth_router)


@app.get("/")
async def root():
    return {"status": "ok", "service": "talk"}


@app.get("/health")
async def health():
    await mongo.ping()
    return {"status": "healthy", "database": "mongodb"}