###############################################################################
# talk — chat chiffré de bout en bout (FastAPI + Redis)
#
# Une seule image pour deux usages (voir docker-compose.yml) :
#   - service "app"  : sert l'API (/api), le WebSocket (/ws) et le frontend
#                      statique (/) via uvicorn ;
#   - service "test" : exécute la suite pytest (deps dev installées dans
#                      cette image, opérées via `docker compose run --rm test`).
###############################################################################

FROM python:3.12-slim

# Bonnes pratiques Python en conteneur :
#   - PYTHONUNBUFFERED=1        : logs uvicorn/pytest visibles en direct ;
#   - PYTHONDONTWRITEBYTECODE=1 : pas de .pyc (l'utilisateur non-root ne
#                                 pourrait pas écrire dans /app, détenu par root) ;
#   - PIP_NO_CACHE_DIR=1        : image plus légère (deps installées sans cache).
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Utilisateur non-root (moindre privilège) — déclaré tôt, activé en fin de
# Dockerfile pour que l'installation des dépendances se fasse en root.
RUN useradd --create-home appuser

WORKDIR /app

# ----------------------------------------------------------------------------
# Étape 1 — dépendances (cache de layer efficace)
# pyproject.toml + app/ suffisent à `pip install -e ".[dev]"` : le `RUN pip`
# n'est ré-exécuté que si l'un de ces deux fichiers change.
# ----------------------------------------------------------------------------
COPY pyproject.toml /app/pyproject.toml
COPY app/ /app/app/
RUN pip install --no-cache-dir -e ".[dev]"

# ----------------------------------------------------------------------------
# Étape 2 — code runtime ET suite de tests
# Le contexte est filtré par .dockerignore (pas de .venv, .git, caches…).
# `tests/` (pyproject.toml : testpaths=["tests"]) est incluse dès qu'elle
# existe : l'image sert aussi au service compose `test`.
# ----------------------------------------------------------------------------
COPY . /app/

# Port HTTP exposé (uvicorn, mono-process : largement suffisant ici).
EXPOSE 8000

# Healthcheck : GET /api/health (le endpoint vérifie aussi le ping Redis).
# urllib est utilisé car l'image slim ne contient ni curl ni wget.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=3)"

# Bascule sur l'utilisateur non-root : tout ce qui suit s'exécute sans droits.
USER appuser

# Démarrage : uvicorn charge `app.main:app` (instance créée par create_app()).
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]