# syntax=docker/dockerfile:1
#
# Image de l'application « talk ».
#   docker compose up              -> lance l'app + MongoDB
#   docker compose run --rm test   -> lance la suite de tests
#
# Choix : python:3.12-slim plutôt que « latest », pour un build
# reproductible (le tag est figé) et une image nettement plus légère.

FROM python:3.12-slim

# Bonnes pratiques Python en conteneur :
#   PYTHONDONTWRITEBYTECODE  pas de .pyc écrits dans l'image
#   PYTHONUNBUFFERED         logs visibles immédiatement par `docker compose logs`
#   PIP_NO_CACHE_DIR         pas de cache pip embarqué (image plus petite)
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Les dépendances sont installées AVANT de copier le code.
# Docker met en cache chaque couche : les ~200 Mo de dépendances ne sont
# réinstallés que si requirements.txt change, et non à chaque modification
# du code applicatif. C'est le principal levier de vitesse du build.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Le .env est volontairement exclu (voir .dockerignore) : les secrets
# arrivent par variables d'environnement au lancement, jamais dans l'image.
COPY app ./app
COPY frontend ./frontend
COPY tests ./tests
COPY pytest.ini ./

# security by design : l'application ne tourne jamais en root.
RUN useradd --create-home --shell /usr/sbin/nologin --uid 10001 talkuser \
    && chown -R talkuser:talkuser /app
USER talkuser

EXPOSE 8000

# 0.0.0.0 est indispensable : par défaut uvicorn n'écoute que sur
# 127.0.0.1 à l'intérieur du conteneur, et le navigateur de l'hôte
# ne pourrait alors pas joindre l'application.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
