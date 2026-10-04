# Base commune : Python léger + dépendances de l'app
FROM python:3.12-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /code
# Dépendances d'abord pour profiter du cache Docker
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY frontend ./frontend

# Image de test : ajoute les outils de dev et les tests
FROM base AS test
COPY requirements-dev.txt pyproject.toml ./
RUN pip install --no-cache-dir -r requirements-dev.txt
COPY tests ./tests
CMD ["sh", "-c", "ruff check app tests && pytest -q --cov=app --cov-report=term-missing"]

# Image finale : tourne avec un utilisateur sans droits root
FROM base AS app
RUN useradd --system --no-create-home talk
USER talk
EXPOSE 8000
# Docker vérifie que l'API répond
HEALTHCHECK --interval=10s --timeout=3s --retries=5 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/csrf')"
# Lance l'API sur le port 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
