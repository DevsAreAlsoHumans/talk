"""Analytics interne, sans cookie et sans service tiers.

Choix RGPD : aucune donnée personnelle n'est stockée.
- Pas d'adresse IP en clair : seulement un identifiant de visite haché
  (IP + User-Agent + sel + date du jour), tronqué à 16 caractères et
  impossible à relier à une personne au-delà de 24 h.
- Pas de cookie, pas d'identifiant persistant, pas de transfert hors UE.
- Respect de l'en-tête `Do Not Track` et du consentement de la bannière.

Conséquence : cette mesure d'audience est anonyme au sens de la CNIL
et ne nécessite pas de consentement — il est demandé quand même.
"""

import hashlib
from datetime import datetime, timezone

from fastapi import APIRouter, Request, Response, status
from pydantic import BaseModel, Field

from app.config import settings
from app.db import get_db
from app.ratelimit import hit

router = APIRouter(prefix="/api/analytics", tags=["analytics"])

ALLOWED_EVENTS = {"pageview", "cta_click", "signup_started", "signup_completed", "login_completed"}
ALLOWED_PATHS = {"/", "/index.html", "/cgu.html", "/rgpd.html", "/404.html", "/app.html"}


class AnalyticsEvent(BaseModel):
    event: str = Field(..., min_length=1, max_length=40)
    path: str = Field(default="/", max_length=200)
    referrer_host: str = Field(default="", max_length=100)
    screen: str = Field(default="", max_length=20)


def visitor_hash(request: Request) -> str:
    """Identifiant de visite anonyme, renouvelé chaque jour."""
    ip = request.headers.get("x-forwarded-for", "")
    if ip:
        ip = ip.split(",")[0].strip()
    elif request.client:
        ip = request.client.host
    ua = request.headers.get("user-agent", "")
    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    raw = f"{settings.analytics_salt}|{ip}|{ua}|{day}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


@router.post("/event", status_code=status.HTTP_204_NO_CONTENT)
async def track(event: AnalyticsEvent, request: Request):
    if not settings.analytics_enabled:
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    # Respect du signal Do Not Track / Global Privacy Control.
    if request.headers.get("dnt") == "1" or request.headers.get("sec-gpc") == "1":
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    if event.event not in ALLOWED_EVENTS:
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    allowed, _ = hit(f"analytics:{visitor_hash(request)}", 60, 60)
    if not allowed:
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    db = get_db()
    if db is None:
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    await db.analytics.insert_one(
        {
            "event": event.event,
            "path": event.path if event.path in ALLOWED_PATHS else "other",
            "referrer_host": event.referrer_host[:100],
            "screen": event.screen,
            "visitor": visitor_hash(request),
            "created_at": datetime.now(timezone.utc),
        }
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/summary")
async def summary():
    """Agrégats publics : volumes uniquement, aucune donnée individuelle."""
    db = get_db()
    if db is None:
        return {"events": [], "visitors": 0}
    pipeline = [
        {"$group": {"_id": "$event", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 20},
    ]
    events = [{"event": row["_id"], "count": row["count"]} async for row in db.analytics.aggregate(pipeline)]
    visitors = len(await db.analytics.distinct("visitor"))
    return {"events": events, "visitors": visitors}
