"""Connexion à Redis."""

import os
from contextlib import asynccontextmanager

import redis.asyncio as redis
from fastapi import FastAPI, Request


# Connexion à Redis au démarrage, fermée à l'arrêt
@asynccontextmanager
async def lifespan(application: FastAPI):
    application.state.redis = redis.from_url(
        os.getenv("REDIS_URL", "redis://localhost:6379/0"), decode_responses=True
    )
    yield
    await application.state.redis.aclose()


# Donne la connexion Redis (remplacée par un faux Redis dans les tests)
def db(request: Request):
    return request.app.state.redis
