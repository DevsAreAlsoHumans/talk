# Mise en place

## Prérequis

- Python 3.11 ou plus (3.12 utilisé en CI et dans l'image Docker)
- Redis 7 (ou n'importe quel service Redis managed)
- Docker et Docker Compose, si vous passez par les conteneurs

## Avec Docker

```bash
cp .env.example .env      # SESSION_SECRET est obligatoire
docker compose up         -d
docker compose run --rm test
```

`docker compose up` démarre l'application sur `http://localhost:8000` et Redis
sur le réseau interne du projet. Le secret de session n'est jamais commité.

## Sans Docker

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env
redis-server &
uvicorn app.main:app --reload
```

L'application est alors disponible sur `http://localhost:8000` et sert à la fois
l'API et le frontend.

## Variables d'environnement

| Variable | Défaut | Rôle |
|----------|--------|------|
| `SESSION_SECRET` | *(dev)* | Signature des sessions. **Obligatoire en production.** |
| `REDIS_URL` | `redis://localhost:6379/0` | Connexion Redis |
| `DEBUG` | `false` | Mode debug FastAPI |
| `COOKIE_SECURE` | `false` | Passer à `true` derrière HTTPS |
| `COOKIE_SAMESITE` | `lax` | Politique de cookie de session |
| `CORS_ORIGINS` | vide | Origines autorisées, séparées par des virgules |
| `RATE_LIMIT_LOGIN_MAX` | `10` | Tentatives de connexion par fenêtre |
| `RATE_LIMIT_LOGIN_WINDOW` | `300` | Durée de la fenêtre, en secondes |
| `RATE_LIMIT_MESSAGE_MAX` | `30` | Messages par fenêtre et par compte |
| `RATE_LIMIT_MESSAGE_WINDOW` | `10` | Durée de la fenêtre, en secondes |

## Tests et linter

```bash
ruff check .              # lint
pytest                    # tests unitaires et intégration
pytest --cov=app          # avec couverture
```

Les tests utilisent `fakeredis` : aucun Redis n'est nécessaire pour les lancer.
La CI lance les deux commandes sur chaque push et chaque pull request.

## Premiers pas

1. Créer un compte sur `/` (pseudo en minuscules, mot de passe de 12 caractères minimum).
2. Créer un salon : un canal `general` est généré automatiquement.
3. Inviter un second membre depuis le salon.
4. Le créateur distribue la clé du canal, chiffrée pour chaque membre.
5. Écrire un message : il est chiffré dans le navigateur avant de partir.

## Dépannage

| Symptôme | Cause probable |
|----------|----------------|
| `SESSION_SECRET doit être defini` au démarrage | `.env` absent ou variable non exportée |
| `ConnectionError` sur `/health` | Redis arrêté, ou `REDIS_URL` incorrecte |
| Le destinataire voit « message illisible » | Clé de canal absente pour ce membre : le salon doit la redistribuer |
| 429 sur `/auth/login` | Fenêtre de limitation dépassée, attendre `Retry-After` |
| 403 sur une mutation | Jeton CSRF absent : appeler `GET /auth/csrf` avant toute écriture |
