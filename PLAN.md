# PLAN D'ACTION — Application de chat chiffré de bout en bout (branche `etudiant/barraud-teddy`)

## Objectif
Construire de zéro l'application décrite dans `EXAMEN.md` : chat type Discord chiffré de bout en bout (E2E), backend FastAPI + Redis, frontend vanilla, WebSocket temps réel, CI verte, Docker.

**Seuils à verrouiller :** note ≥ 12/20, Sécurité ≥ 2/5, Tests ≥ 1,5/3, CI verte, docker fonctionnel, aucun secret committé, E2E réel (jamais de clair ni de clé côté serveur), pas de casse des branches des autres étudiants.

---

## 1. Décisions techniques (choix à justifier dans le README)

| Choix | Décision | Justification |
|-------|----------|---------------|
| Stockage | **Redis** | Sessions avec TTL natifs, pub/sub temps réel, modèle simple clé/valeur type serveur Discord. Chiffrement des données au repos non requis (tout est chiffré côté client). |
| Réalité temps réel | **WebSocket** + repli polling court (3 s) en JS | WebSocket natif de FastAPI/Starlette ; fallback si connexion perdue. |
| Hachage mots de passe | **Argon2id** (`argon2-cffi`) | Algorithme recommandé par l'énoncé, résistant GPU. |
| Chiffrement E2E côté client | **AES-256-GCM** (messages) + **RSA-OAEP-256** (wrapping de la clé de salon) via **WebCrypto** | Modèle « clé de salon symétrique enveloppée pour chaque membre » exigé. Nonce 12 octets unique par message (anti-réutilisation de clé). |
| CSRF | Token par session (dans Redis) + header `X-CSRF-Token` + vérification `Origin`/`Referer` | Couvre **toutes** les mutations **y compris register/login**. |
| Sécurité session | Cookie `session` : `HttpOnly`, `Secure` (si HTTPS), `SameSite=Lax` ; session stockée en Redis ; **rotation** à la connexion. | |
| Tests | `pytest` + `httpx` + **fakeredis** | Tests exécutables sans Redis externe (CI et docker simples, stables). |
| Linter | **ruff** (`ruff check` + `ruff format --check`) | Inclus dans la CI, zéro erreur bloquante. |

---

## 2. Structure du dépôt à créer

```
Dockerfile
docker-compose.yml
.dockerignore
.github/workflows/ci.yml
pyproject.toml                # métadonnées + deps + config ruff/pytest
app/
  main.py                     # factory FastAPI, middlewares, routes, /api/health
  config.py                   # settings pydantic (env, SECRET_KEY, REDIS_URL…)
  security/
    passwords.py              # Argon2id hash/verify
    csrf.py                   # middleware CSRF (token + Origin/Referer)
    headers.py                # middleware headers de sécurité (CSP, XFO, nosniff…)
    sessions.py               # create/validate/rotate/destroy, cookie
    ratelimit.py              # rate-limit login/register (Redis)
  db/redis.py                 # client Redis + dépendance get_redis()
  repositories/
    users.py  sessions.py  rooms.py  messages.py
  schemas/                    # Pydantic stricts (auth, rooms, messages)
  api/
    deps.py                   # current_user (session obligatoire)
    auth.py  rooms.py  messages.py  csrf.py  (users.py: clés publiques)
  realtime/
    hub.py                    # diffusion in-process aux WebSockets
    ws.py                     # endpoint /ws authentifié par cookie session
frontend/
  index.html  css/style.css
  js/api.js  crypto.js  auth.js  rooms.js  chat.js  main.js
tests/
  conftest.py                 # fixtures app/AsyncClient/redis fake + helpers membres
  unit/  (passwords, csrf, validation, crypto_reference)
  integration/  (auth, rooms, messages, security, websocket)
  helpers/crypto_client.py    # référence Python du client (RSA-OAEP wrap, AES-GCM)
README.md                     # personnel : présentation, architecture, sécurité, docker, tests
```

---

## 3. Contrat d'API public

| Méthode | Route | Rôle | CSRF requis |
|---|---|---|---|
| GET | `/api/csrf` | crée une session anonyme, renvoie `{csrf_token}` | non |
| POST | `/api/auth/register` | `{username, password, public_key}` → 201 `{user, csrf_token}` (rotation session) | oui |
| POST | `/api/auth/login` | `{username, password}` → `{user, csrf_token}` (rotation session) | oui |
| POST | `/api/auth/logout` | détruit la session | oui |
| GET | `/api/me` | profil + salons de l'utilisateur connecté | non |
| GET | `/api/users/{username}` | profil public (id, username, public_key) | non |
| GET | `/api/rooms` | salons dont l'utilisateur est membre | non |
| POST | `/api/rooms` | `{name}` → 201 `{room}` (l'utilisateur créateur devient membre) | oui |
| GET | `/api/rooms/{id}/members` | liste membres (id, username, public_key) | non |
| POST | `/api/rooms/{id}/join` | l'utilisateur rejoint un salon | oui |
| POST | `/api/rooms/{room_id}/keys` | `{target_user_id, wrapped_key}` — enregistre la copie enveloppée de la clé de salon | oui |
| GET | `/api/rooms/{id}/messages?after=<id>` | historique (ciphertext + meta) / polling | non |
| POST | `/api/rooms/{id}/messages` | `{nonce, ciphertext}` → 201 (message chiffré uniquement) | oui |
| WS | `/ws` | connexion temps réel (auth cookie session, vérif Origin) | — |

**Formats cryptographiques (contrat JS ↔ tests Python) :**
- Clé publique utilisateur : `RSA-OAEP-256`, encodée **SPKI base64** (max 1000 caractères).
- Clé de salon : 32 octets aléatoires. Copie enveloppée = chiffrement RSA-OAEP-256, base64.
- Message : AES-256-GCM, **nonce 12 octets unique** généré côté client, `{nonce: b64, ciphertext: b64}`. L'AEAD garantit intégrité/authenticité (tag inclus dans le ciphertext).

---

## 4. Sécurité (imposée par l'examen)

1. **CSRF** — middleware global : toute mutation (POST/PUT/PATCH/DELETE) exige `X-CSRF-Token` == token de session **et** `Origin`/`Referer` autorisée. Exception : `GET /api/csrf` (et routes GET).
2. **Anti-injection** — aucun opérateur d'entrée utilisateur exécuté ; Redis manipulé via clés typées (`user:{id}`, `room:{id}`, `msg:{id}`…), validation stricte Pydantic (types, longueurs, formats) avant tout accès stockage. Aucune requête dynamique à partir d'input.
3. **Mots de passe** — Argon2id, jamais en clair, aucune comparaison non constante.
4. **E2E** — le serveur ne reçoit que `ciphertext`, `nonce`, `wrapped_key`. Jamais de clé privée ni de clair ; la clé privée ne quitte jamais le navigateur (stockée localement, protégée par une clé dérivée du mot de passe via PBKDF2).
5. **Validation** — Pydantic stricts + limites de taille (username 3–32, password 8–128, public_key ≤ 1000, messages ≤ 4096 octets) ; rendu XSS-safe côté front (**textContent**, jamais innerHTML).
6. **Headers** — CSP (`default-src 'self'`, `script-src 'self'`, `style-src 'self'`, `connect-src 'self' ws: wss:`), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Strict-Transport-Security` (si HTTPS), `Permissions-Policy`.
7. **Sessions & secrets** — cookie HttpOnly/Secure/SameSite ; `SECRET_KEY`, `REDIS_URL` via environnement (jamais commités) ; `.env` déjà ignoré.
8. **Erreurs** — handler global → réponses génériques, aucune stack trace exposée.
9. **Bonus** — rate-limit login/register (10 essais / 15 min), rotation de session à la connexion, nonce unique par message.

---

## 5. Docker

- `Dockerfile` : base `python:3.12-slim`, copie `pyproject.toml` + code, `pip install --no-cache-dir`, utilisateur **non-root**, CMD `uvicorn app.main:app --host 0.0.0.0 --port 8000`.
- `docker-compose.yml` :
  - service `redis` : `redis:7-alpine` + **healthcheck** (`redis-cli ping`) ;
  - service `app` : build `.`, `depends_on: redis (condition: service_healthy)`, healthcheck `/api/health`, port `8000:8000` ;
  - service `test` : même image, commande `pytest` → `docker compose run --rm test`.
- `.dockerignore` : `.git`, `__pycache__`, `.venv`, `tests/__pycache__`…
- Endpoint `GET /api/health` → `{"status":"ok","redis":"ok"} `.

## 6. CI — `.github/workflows/ci.yml`

Déclenchée sur **push** et **pull_request**. Jobs :
1. `lint` : `pip install ruff` → `ruff check .` + `ruff format --check .`
2. `test` : Python 3.12, `pip install -e ".[dev]"`, `pytest -v` (fakeredis, aucun service externe)
3. `docker-build` : `docker build` (sanity check de l'image)

## 7. Tests (objectif : bloc Tests ≥ 2,5/3)

- **Unitaires** : Argon2 (hash/verify/false), CSRF (token valide/invalide/absent, mauvaise origine), validation Pydantic (usernames invalides, messages trop grands, clé publique invalide), logique métier salons (création, ajout, membres), crypto de référence (wrap/unwrap, nonce unique).
- **Intégration** : register → login → création salon → envoi → réception → historique (juste après un membre joint + wrapped key) ; cas d'erreur (401, 403, 404, 409, 429) ; cas sécurité (mutation sans CSRF → 403, CSRF absent sur login → 403, accès salon non membre → 403, message sans clair/injection d'opérateurs Redis → rejet, brute-force login → 429) ; WebSocket (connexion non authentifiée → rejet, diffusion message).
- Le fichier `tests/helpers/crypto_client.py` **imite le navigateur** côté Python pour valider le contrat E2E de bout en bout.

## 8. Ordre d'exécution & responsabilités

| # | Tâche | Responsable | Dépend de |
|---|-------|-------------|-----------|
| 1 | Squelette projet + pyproject + sécurité (Argon2, CSRF, headers, sessions, rate-limit) | Développeur Backend | PLAN |
| 2 | Repos Redis + schémas + API (auth, rooms, messages, keys, health) + hub WS | Développeur Backend | 1 |
| 3 | Frontend (HTML/CSS/JS + crypto.js WebCrypto + UI) | Développeur Frontend | Contrat §3 |
| 4 | Tests unitaires + intégration (+ helpers crypto client) | Développeur Backend + QA | 1, 2 |
| 5 | Dockerfile + docker-compose + .dockerignore + CI | Développeur DevOps | 1, 2, 4 |
| 6 | README personnel détaillé | Développeur Doc | 2, 3, 4, 5 |
| 7 | Revue QA : ruff, pytest, `docker compose up` + `docker compose run --rm test`, revue manuelle parcours | QA | 2, 3, 4, 5 |
| 8 | Commit réguliers tout au long + push final branche, vérif CI verte | Orchestrateur | 7 |

**Règles Git** : commits petits et descriptifs après chaque milestone ; travail **uniquement** sur `etudiant/barraud-teddy` ; aucun force-push/réécriture ; aucun secret committé.