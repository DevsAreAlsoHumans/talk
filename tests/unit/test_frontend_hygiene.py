"""Garde-fous statiques sur le frontend : pas d'API dangereuse, pas de code inline (CSP)."""

import re
from pathlib import Path

import pytest

FRONTEND = Path(__file__).resolve().parents[2] / "frontend"
JS_FILES = sorted((FRONTEND / "js").glob("*.js"))

FORBIDDEN = [
    "innerHTML",
    "outerHTML",
    "insertAdjacentHTML",
    "document.write",
    "eval(",
    "new Function",
    "setTimeout('",
]


@pytest.mark.parametrize("path", JS_FILES, ids=lambda path: path.name)
def test_no_dangerous_dom_or_code_execution_api(path):
    source = path.read_text(encoding="utf-8")
    for pattern in FORBIDDEN:
        assert pattern not in source, f"{pattern} interdit dans {path.name} (risque XSS)"


@pytest.mark.parametrize("path", JS_FILES, ids=lambda path: path.name)
def test_secrets_are_never_written_to_web_storage(path):
    source = path.read_text(encoding="utf-8")
    for storage in ["localStorage", "sessionStorage", "indexedDB", "document.cookie"]:
        assert storage not in source, f"{storage} interdit dans {path.name} : les clés restent en mémoire"


def test_the_html_page_has_no_inline_script_style_or_event_handler():
    html = (FRONTEND / "index.html").read_text(encoding="utf-8")
    assert not re.search(r"<script(?![^>]*\bsrc=)", html), "script inline interdit par la CSP"
    assert "<style" not in html
    assert not re.search(r"\sstyle=", html)
    assert not re.search(r"\son[a-z]+=", html), "gestionnaire d'événement inline interdit par la CSP"
    assert "http://" not in html and "https://" not in html, "aucune ressource externe (CSP)"


def test_stylesheet_loads_no_external_resource():
    css = (FRONTEND / "style.css").read_text(encoding="utf-8")
    assert "@import" not in css
    assert not re.search(r"url\(\s*['\"]?https?:", css)
