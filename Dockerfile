# syntax=docker/dockerfile:1

# ---------- Base : Python + dépendances d'exécution ----------
FROM python:3.12-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /srv
# Utilisateur non privilégié : le processus ne tourne jamais en root.
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin talk && chown talk:talk /srv
COPY requirements.txt .
RUN pip install -r requirements.txt

# ---------- Test : linter + tests (docker compose run --rm test) ----------
FROM base AS test
COPY requirements-dev.txt .
RUN pip install -r requirements-dev.txt
COPY --chown=talk:talk pyproject.toml ./
COPY --chown=talk:talk app ./app
COPY --chown=talk:talk frontend ./frontend
COPY --chown=talk:talk tests ./tests
USER talk
CMD ["sh", "-c", "ruff check . && ruff format --check . && pytest --cov --cov-fail-under=90"]

# ---------- Runtime : image finale, minimale ----------
FROM base AS runtime
COPY app ./app
COPY frontend ./frontend
USER talk
EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=5 \
  CMD python -c "import sys, urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=2).status == 200 else 1)"
CMD ["uvicorn", "app.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--ws-max-size", "4194304", "--no-server-header"]
