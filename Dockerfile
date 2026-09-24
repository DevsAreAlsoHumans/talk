# syntax=docker/dockerfile:1.7

FROM python:3.12-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1
WORKDIR /app

FROM base AS builder
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
COPY requirements.txt ./
RUN pip install --upgrade pip && pip install -r requirements.txt

FROM builder AS test
ENV RUFF_CACHE_DIR=/tmp/ruff-cache
COPY requirements-dev.txt ./
RUN pip install -r requirements-dev.txt
COPY app ./app
COPY frontend ./frontend
COPY tests ./tests
COPY pyproject.toml ./
CMD ["sh", "-c", "ruff check . && ruff format --check . && pytest -q -p no:cacheprovider"]

FROM builder AS runtime
RUN groupadd --gid 10001 talk \
    && useradd --uid 10001 --gid talk --create-home --shell /usr/sbin/nologin talk
COPY --from=builder /opt/venv /opt/venv
COPY --chown=talk:talk app ./app
COPY --chown=talk:talk frontend ./frontend
USER talk
EXPOSE 8000
HEALTHCHECK --interval=20s --timeout=3s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=2)"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
