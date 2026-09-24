import os

os.environ["MONGODB_DBNAME"] = "Talk_test"

import httpx
import pytest_asyncio

from app.db import mongo
from app.main import app

BASE_URL = "http://127.0.0.1:8000"


@pytest_asyncio.fixture(autouse=True)
async def _clean_database():
    async with app.router.lifespan_context(app):
        for collection in ["Users", "Sessions", "Conversations", "Messages"]:
            await mongo.db.drop_collection(collection)
        yield
    await mongo.close()


@pytest_asyncio.fixture
async def client():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url=BASE_URL
    ) as async_client:
        yield async_client


@pytest_asyncio.fixture
async def make_client():
    clients = []

    def factory():
        transport = httpx.ASGITransport(app=app)
        new_client = httpx.AsyncClient(transport=transport, base_url=BASE_URL)
        clients.append(new_client)
        return new_client

    yield factory
    for created in clients:
        await created.aclose()


async def csrf(client):
    await client.get("/api/auth/csrf")
    return client.cookies.get("talk_csrf_token")


def auth_headers(token):
    return {
        "Content-Type": "application/json",
        "X-CSRF-Token": token,
        "Origin": BASE_URL,
    }