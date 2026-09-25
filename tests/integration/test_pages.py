"""Pages statiques, en-têtes de sécurité et page 404 personnalisée."""

import pytest


@pytest.mark.parametrize(
    "path",
    ["/", "/app.html", "/cgu.html", "/rgpd.html", "/404.html", "/robots.txt", "/sitemap.xml"],
)
async def test_static_pages_are_served(client, path):
    response = await client.get(path)
    assert response.status_code == 200


@pytest.mark.parametrize(
    "asset",
    ["/style.css", "/site.js", "/app.js", "/favicon.svg", "/favicon.ico", "/og-image.png", "/site.webmanifest"],
)
async def test_assets_are_served(client, asset):
    """Aucun lien cassé : chaque ressource référencée par les pages existe."""
    response = await client.get(asset)
    assert response.status_code == 200


async def test_unknown_page_returns_custom_404(client):
    response = await client.get("/page-qui-nexiste-pas", headers={"accept": "text/html"})
    assert response.status_code == 404
    assert "text/html" in response.headers["content-type"]
    assert "Ronyme" in response.text
    assert "404" in response.text


async def test_unknown_api_route_returns_json(client):
    response = await client.get("/auth/inconnu", headers={"accept": "application/json"})
    assert response.status_code == 404
    assert response.json()["detail"]


async def test_security_headers_are_complete(client):
    response = await client.get("/health")
    headers = response.headers
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
    assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]
    assert "interest-cohort=()" in headers["Permissions-Policy"]


async def test_csp_blocks_inline_scripts(client):
    """La CSP ne doit jamais autoriser 'unsafe-inline' sur les scripts."""
    csp = (await client.get("/health")).headers["Content-Security-Policy"]
    assert "'unsafe-inline'" not in csp
    assert "'unsafe-eval'" not in csp


@pytest.mark.parametrize("page", ["/", "/cgu.html", "/rgpd.html", "/404.html", "/app.html"])
async def test_pages_have_title_and_description(client, page):
    html = (await client.get(page)).text
    assert "<title>" in html
    assert 'name="description"' in html
    assert 'property="og:image"' in html
    assert 'rel="icon"' in html


@pytest.mark.parametrize("page", ["/", "/cgu.html", "/rgpd.html", "/404.html"])
async def test_pages_have_no_inline_style_or_script(client, page):
    """La CSP interdit l'inline : on vérifie que le HTML ne s'y appuie pas."""
    html = (await client.get(page)).text
    assert ' style="' not in html
    assert "<script>" not in html
