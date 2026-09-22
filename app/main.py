from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.db import mongo


@asynccontextmanager
async def lifespan(app: FastAPI):
    await mongo.connect()
    yield
    await mongo.close()


app = FastAPI(title="talk", lifespan=lifespan)


@app.get("/")
async def root():
    return {"status": "ok", "service": "talk"}


@app.get("/health")
async def health():
    await mongo.ping()
    return {"status": "healthy", "database": "mongodb"}