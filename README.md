# talk

> **Chat chiffré de bout en bout — un croisement entre Discord et Telegram WebApp.**

Application de messagerie qui combine le modèle de **Discord** (serveurs, salons, canaux, multi-utilisateurs) et le côté **webapp léger de Telegram** (interface accessible depuis le navigateur, sans installation). Les utilisateurs s'authentifient, rejoignent des salons et échangent des messages **sans que le serveur puisse jamais lire le contenu en clair** (chiffrement de bout en bout côté client).

Sujet d'examen `SDV DEV 2026`.

## Stack

| Couche | Technologie |
|--------|-------------|
| Backend | Python + FastAPI |
| Stockage | Redis ou MongoDB |
| Frontend | HTML + CSS + JavaScript vanilla |
| Temps réel | WebSocket / polling court |
| CI | GitHub Actions |
| Déploiement | Docker + docker-compose |

## Fonctionnalités

- Authentification (inscription, connexion, sessions sécurisées, mots de passe hachés).
- Salons et canaux de discussion multi-utilisateurs, proche d'un serveur Discord.
- Messages chiffrés de bout en bout, **jamais stockés en clair**.
- Mise à jour en temps réel ou quasi temps réel.
- Interface web légère et utilisable, style webapp.

## Sécurité

- Protection CSRF effective sur toutes les mutations.
- Prévention des injections SQL et NoSQL.
- Chiffrement de bout en bout côté client (clés jamais transmises au serveur).
- Validation stricte des entrées, anti-XSS, headers de sécurité, sessions sécurisées.

## Démarrer avec Docker

```bash
docker compose up              # lance l'application (app + Redis/MongoDB)
docker compose run --rm test   # lance les tests (unitaires + intégration)
```

La **CI GitHub Actions** exécute les tests et le linter à chaque push / pull request.

## État du projet

**Étape 2 — authentification : terminée.**

Le dépôt contient :

- l'application FastAPI (`app/main.py`) avec un endpoint de santé `GET /health` qui répond `{"status": "ok"}` ;
- le service MongoDB dans `docker-compose.yml` ;
- le frontend statique (HTML / CSS / JS vanilla) affiché sur `/` ;
- l'authentification : inscription, connexion, déconnexion, sessions serveur, protection CSRF, en-têtes de sécurité et point d'entrée WebSocket authentifié ;
- les tests pytest (unitaires et intégration contre le vrai MongoDB), le linter Ruff et la CI.

Aucune messagerie, aucun salon et aucun chiffrement de bout en bout ne sont encore implémentés : le WebSocket se limite à confirmer l'identité de l'utilisateur connecté.

### Authentification

| Route | Description |
|-------|-------------|
| `GET /auth/csrf` | Bootstrap : crée au besoin une session anonyme et pose les cookies `talk_session` et `talk_csrf`. Idempotent. |
| `POST /auth/register` | Crée un compte (argon2, mot de passe de 12 caractères minimum) puis ouvre une session. |
| `POST /auth/login` | Vérifie les identifiants puis ouvre une session. |
| `POST /auth/logout` | Supprime la session serveur et efface les cookies. |
| `GET /auth/me` | Retourne l'utilisateur de la session courante. |
| `WS /ws` | Écho de l'identité, authentifié par cookie, origine vérifiée. |

Toutes les mutations exigent l'en-tête `X-CSRF-Token`, alimenté par le cookie
`talk_csrf` que le frontend lit en JavaScript.

### Sécurité mise en œuvre

- **Mots de passe** : Argon2id (`argon2-cffi`), sel par utilisateur, jamais stockés en clair.
- **Sessions** : jeton opaque de 256 bits, conservé uniquement sous forme d'empreinte SHA-256 ; rotation des jetons à chaque connexion ; expiration vérifiée en base et purgée par un index TTL MongoDB.
- **Cookies** : `talk_session` en `HttpOnly`, `talk_csrf` accessible au JavaScript, tous deux `SameSite=Lax` et `Secure` en production.
- **CSRF** : double soumission liée à la session, comparaison en temps constant ; l'en-tête `talk_csrf` n'est efficace que combiné au cookie de session, que le JavaScript ne peut pas lire.
- **Anti-énumération** : message unique pour identifiant inconnu et mot de passe erroné, et hachage factice pour égaliser le temps de réponse.
- **Anti-brute-force** : fenêtre glissante en mémoire, indexée sur le couple (IP, identifiant) et sur l'IP — jamais sur le seul identifiant, pour ne pas permettre le verrouillage volontaire d'un compte.
- **Injection NoSQL** : schémas Pydantic stricts (`extra="forbid"`, types `str`) : un opérateur comme `{"$ne": null}` est rejeté en 422 avant d'atteindre MongoDB.
- **En-têtes** : CSP stricte, `nosniff`, `DENY`, `Referrer-Policy`, `Permissions-Policy`, HSTS en HTTPS. L'en-tête `Server` est masqué.
- **WebSocket** : cookie de session revalidé et origine strictement vérifiée avant `accept()` ; fermeture en 1008 sinon.

### Configuration

| Variable | Défaut | Rôle |
|----------|--------|------|
| `MONGO_URL` | `mongodb://mongo:27017` | Connexion MongoDB |
| `MONGO_DB_NAME` | `talk` | Base utilisée |
| `APP_ORIGINS` | `http://localhost:8000,http://127.0.0.1:8000` | Origines autorisées (WebSocket) |
| `ENV` | `development` | `production` active `Secure` et impose `https` |
| `COOKIE_SECURE` | `true` si `ENV=production` | Attribut `Secure` des cookies |
| `TRUST_PROXY_HEADERS` | `false` | Lire `X-Forwarded-Proto` derrière un reverse proxy |
| `SESSION_TTL_SECONDS` | `604800` | Durée d'une session authentifiée (7 jours) |
| `ANONYMOUS_SESSION_TTL_SECONDS` | `3600` | Durée d'une session anonyme (bootstrap CSRF) |
| `ARGON2_TIME_COST` / `ARGON2_MEMORY_COST` / `ARGON2_PARALLELISM` | `3` / `65536` / `4` | Paramètres Argon2id |

Limite connue : le MongoDB de `docker-compose.yml` n'a ni identifiant ni mot de passe.
C'est acceptable en développement et en intégration continue, pas en production.

### Démarrage

```bash
docker compose up              # API + MongoDB → http://localhost:8000
docker compose run --rm test   # tests pytest + linter Ruff
```

`docker compose run --rm test` démarre MongoDB et attend son healthcheck : les
tests d'intégration s'exécutent contre la vraie base `talk_test`, isolée de `talk`.

### Sans Docker

Python **3.13** est requis (voir `.python-version`, aligné sur le `Dockerfile` et la CI).

```bash
python3.13 -m venv .venv
source .venv/bin/activate      # Windows : .venv\Scripts\activate
pip install -r requirements.txt -r requirements-dev.txt
python -m pytest               # tests
ruff check . && ruff format --check .   # linter
uvicorn app.main:app --reload  # API sur http://localhost:8000
```

### Arborescence

```
app/
├── __init__.py
├── main.py          # lifespan, middlewares, route API puis montage du frontend
├── config.py        # configuration lue depuis l'environnement
├── db.py            # client MongoDB asynchrone et index
├── security.py      # Argon2id, génération et comparaison des jetons
├── schemas.py       # validation des entrées, représentation des sorties
├── store.py         # persistance des utilisateurs et des sessions
├── deps.py          # CSRF, utilisateur courant, WebSocket, anti-brute-force
├── middleware.py    # en-têtes de sécurité
└── routers/
    └── auth.py      # csrf, register, login, logout, me, ws
frontend/
├── index.html
├── css/style.css
└── js/app.js
tests/
├── conftest.py
├── test_health.py
├── test_auth.py
├── test_csrf.py
├── test_security_headers.py
├── test_nosql_injection.py
├── test_ws_auth.py
└── test_password_hashing.py
.github/workflows/ci.yml
Dockerfile
docker-compose.yml
requirements.txt / requirements-dev.txt
pyproject.toml   # configuration Ruff + pytest
```

## Mode de travail sur ce dépôt

- Travail **individuel** : chaque étudiant développe son projet sur **sa propre branche** (`etudiant/<nom>-<prenom>`).
- **Ne jamais casser les branches des autres** (pas de force-push, reset, réécriture ni suppression des branches d'autrui).
- La branche `main` sert de référence ; les projets sont rendus sur les branches étudiantes avec **CI verte**.

## Structure d'un projet rendu

```
Dockerfile                # image de l'application
docker-compose.yml        # app + base de données
.github/workflows/*.yml   # pipeline CI (tests + linter)
app/                      # backend FastAPI
frontend/                 # HTML/CSS/JS vanilla + chiffrement côté client
tests/                    # tests unitaires + intégration / non-régression
README.md                 # documentation (fonctionnement, sécurité, mise en place)
```

## Ressources

- Dépôt : <https://github.com/DevsAreAlsoHumans/talk>

---

*Projet pédagogique — année 2026.*