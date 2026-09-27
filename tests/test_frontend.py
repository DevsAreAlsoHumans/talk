"""Non-regression du frontend : presence des fichiers, absence d'injection HTML."""

from pathlib import Path

from fastapi.testclient import TestClient

from app.web import FRONTEND_DIR

JS_FILES = sorted(FRONTEND_DIR.rglob("*.js"))


def _sources() -> dict[str, str]:
    return {str(path.relative_to(FRONTEND_DIR)): path.read_text() for path in JS_FILES}


def test_index_is_served(client: TestClient) -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "<title>talk" in response.text


def test_static_assets_are_served(client: TestClient) -> None:
    for path in ("/static/styles.css", "/static/js/app.js", "/static/js/crypto.js"):
        assert client.get(path).status_code == 200, path


def test_no_inner_html_in_frontend() -> None:
    """Un rendu par innerHTML rouvrirait la faille XSS : on l'interdit."""
    for name, source in _sources().items():
        assert "innerHTML" not in source, name
        assert "outerHTML" not in source, name
        assert "insertAdjacentHTML" not in source, name
        assert "document.write" not in source, name


def test_unsafe_evaluation_is_absent() -> None:
    for name, source in _sources().items():
        assert "eval(" not in source, name
        assert "new Function(" not in source, name


def test_no_external_resource_is_referenced() -> None:
    """CSP stricte : aucune ressource distante, donc aucun CDN."""
    html = (FRONTEND_DIR / "index.html").read_text()
    assert 'src="http' not in html
    assert 'href="http' not in html
    for name, source in _sources().items():
        assert "http://" not in source, name
        assert "https://" not in source, name


def test_index_has_no_inline_script() -> None:
    html = (FRONTEND_DIR / "index.html").read_text()
    assert "<script>" not in html
    assert "onclick=" not in html
    assert "javascript:" not in html


def test_csp_allows_only_own_assets(client: TestClient) -> None:
    csp = client.get("/").headers["Content-Security-Policy"]
    assert "script-src 'self'" in csp
    assert "unsafe-inline" not in csp
    assert "unsafe-eval" not in csp


def test_frontend_uses_text_content_for_user_data() -> None:
    sources = _sources()
    assert "textContent" in sources["js/dom.js"]
    assert sources["js/dom.js"].count("textContent") >= 3


def test_crypto_module_only_uses_webcrypto() -> None:
    source = _sources()["js/crypto.js"]
    assert "crypto.subtle" in source
    assert "AES-GCM" in source
    assert "ECDH" in source
    assert "createHash" not in source


def test_frontend_directory_is_packaged() -> None:
    assert Path(FRONTEND_DIR / "index.html").is_file()
    assert Path(FRONTEND_DIR / "styles.css").is_file()
    assert len(JS_FILES) >= 6
