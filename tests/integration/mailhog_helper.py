import asyncio
import os
from typing import Any

import httpx

MAILHOG_API_URL = os.environ.get("MAILHOG_API_URL", "http://localhost:8025")


async def wait_for_mail(to: str, timeout: float = 5.0) -> dict[str, Any]:
    """Interroge l'API Mailhog jusqu'à recevoir un email adressé à `to`."""
    deadline = asyncio.get_event_loop().time() + timeout
    async with httpx.AsyncClient() as client:
        while True:
            response = await client.get(f"{MAILHOG_API_URL}/api/v2/messages")
            response.raise_for_status()
            for item in response.json().get("items", []):
                recipients = [f"{rcpt['Mailbox']}@{rcpt['Domain']}" for rcpt in item["To"]]
                if to in recipients:
                    return item
            if asyncio.get_event_loop().time() >= deadline:
                raise AssertionError(f"Aucun email reçu pour {to} dans le délai imparti.")
            await asyncio.sleep(0.2)
