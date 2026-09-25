from app.db import get_db


async def test_pageview_is_recorded(csrf_client):
    response = await csrf_client.post(
        "/api/analytics/event",
        json={"event": "pageview", "path": "/", "screen": "desktop"},
    )
    assert response.status_code == 204

    rows = await get_db().analytics.find({}).to_list(length=10)
    assert len(rows) == 1
    assert rows[0]["event"] == "pageview"


async def test_no_raw_ip_is_stored(csrf_client):
    await csrf_client.post(
        "/api/analytics/event",
        json={"event": "pageview", "path": "/"},
        headers={"x-forwarded-for": "203.0.113.42"},
    )
    row = await get_db().analytics.find_one({})
    assert "203.0.113.42" not in str(row)
    # L'identifiant de visite est un condensé tronqué, non réversible.
    assert len(row["visitor"]) == 16


async def test_do_not_track_is_respected(csrf_client):
    response = await csrf_client.post(
        "/api/analytics/event",
        json={"event": "pageview", "path": "/"},
        headers={"DNT": "1"},
    )
    assert response.status_code == 204
    assert await get_db().analytics.count_documents({}) == 0


async def test_global_privacy_control_is_respected(csrf_client):
    await csrf_client.post(
        "/api/analytics/event",
        json={"event": "pageview", "path": "/"},
        headers={"Sec-GPC": "1"},
    )
    assert await get_db().analytics.count_documents({}) == 0


async def test_unknown_event_is_ignored(csrf_client):
    await csrf_client.post("/api/analytics/event", json={"event": "exfiltrate", "path": "/"})
    assert await get_db().analytics.count_documents({}) == 0


async def test_arbitrary_path_is_bucketed(csrf_client):
    await csrf_client.post(
        "/api/analytics/event",
        json={"event": "pageview", "path": "/secret/user/42"},
    )
    row = await get_db().analytics.find_one({})
    assert row["path"] == "other"


async def test_analytics_requires_csrf(client):
    response = await client.post("/api/analytics/event", json={"event": "pageview"})
    assert response.status_code == 403


async def test_summary_returns_aggregates_only(csrf_client):
    await csrf_client.post("/api/analytics/event", json={"event": "pageview", "path": "/"})
    await csrf_client.post("/api/analytics/event", json={"event": "cta_click", "path": "/"})

    body = (await csrf_client.get("/api/analytics/summary")).json()
    assert body["visitors"] == 1
    assert {e["event"] for e in body["events"]} == {"pageview", "cta_click"}
    assert "visitor" not in str(body["events"])
