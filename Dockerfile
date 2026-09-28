# syntax=docker/dockerfile:1
# ==============================================================
# STAGE 1 — dépendances (prod + dev) — base de l'image "test"
# ==============================================================
FROM python:3.12-slim AS deps

# Options dures : pas de cache pip, pas de bytecode -> image minimale
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# COPY uniquement les requirements d'abord : le cache Docker n'est
# invalidé que quand les dépendances changent (builds CI rapides)
COPY requirements.txt requirements-dev.txt ./
RUN pip install -r requirements-dev.txt

# Code source + tests requis pour le service "test" (target deps)
COPY app/ ./app/
COPY tests/ ./tests/
COPY pyproject.toml ./

# ==============================================================
# STAGE 2 — runtime (code + dépendances, sans outils dev)
# ==============================================================
FROM python:3.12-slim AS runtime

# Utilisateur non-root : confine l'impact d'une éventuelle RCE
RUN useradd --create-home -u 1000 appuser

WORKDIR /app

# Site-packages du stage 1 (uvicorn invoqué via -m, pas besoin des binaires)
COPY --from=deps /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --chown=appuser:appuser --from=deps /app/app ./app
# Frontend vanilla servi par FastAPI (CSP 'self') — la webapp vit dans l'image
COPY --chown=appuser:appuser frontend ./frontend
COPY --chown=appuser:appuser pyproject.toml ./

USER appuser

EXPOSE 8000

# Healthcheck sans curl (image slim) — /health doit répondre 200
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2).status == 200 else 1)"]

# --workers 1 : l'état WebSocket et les textures chiffrées vivent en mémoire ;
# plusieurs workers les dupliqueraient (fuite de surface + incohérences)
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]