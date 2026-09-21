# talk — Chat chiffré de bout en bout

> Application de messagerie type **Discord** avec **chiffrement de bout en bout** : le serveur ne
> peut jamais lire le contenu des messages, ni accéder aux clés permettant de les déchiffrer.

**Projet d'examen `SDV DEV 2026`** — branche `etudiant/barraud-teddy`.

---

## 1. Présentation

`talk` permet à des utilisateurs de s'authentifier, de rejoindre des **salons** (création, liste,
membres) et d'échanger des messages en temps réel — le tout **chiffré de bout en bout côté client**.

Le chiffrement est réalisé **dans le navigateur** avec l'API Web Crypto :

- chaque utilisateur possède une **paire de clés RSA-OAEP-256** générée à l'inscription ;
- chaque salon possède une **clé symétrique AES-256-GCM** aléatoire ;
- les messages sont chiffrés avec la clé du salon (nonce unique de 12 octets par message) ;
- la clé de salon est **enveloppée** (chiffrée) pour chaque membre avec sa clé publique, puis
  stockée côté serveur — le serveur n'a **jamais** accès à la clé en clair ni à une clé privée.

```
┌───────────────────────────┐      ┌──────────────────────────────┐      ┌─────────────┐
│  Navigateur (WebCrypto)   │      │  Backend FastAPI (app/)      │      │    Redis    │
│                           │      │                              │      │             │
│  · paire RSA (privée     ════════╪═  clé publique uniquement    ╪══════╪═ users      │
│    jamais transmise)      │      │  · sessions (cookie HttpOnly)│      │  sessions   │
│  · chiffre/déchiffre      │      │  · CSRF + headers sécurité   │      │  rooms      │
│    AES-GCM (client)       │      │  · stockage chiffré uniquement│      │  messages   │
└───────────────────────────┘      └──────────────────────────────┘      └─────────────┘
```

---

## 2. Stack & architecture

| Couche | Technologie | Justification |
|--------|-------------|---------------|
| Backend | **Python 3.12 + FastAPI** | Framework imposé par l'énoncé ; validation Pydantic native, WebSocket intégré, montage statique simple. |
| Stockage | **Redis 7** | Sessions persistantes avec **TTL natif** (0 effort de purge), indexation simple (sets, sorted sets, hashs), idée « serveur Discord » légère. *Alternative MongoDB écartée : surdimensionnée ici, aucun document complexe à stocker.* |
| Temps réel | **WebSocket** (+ repli **polling court 3 s**) | Natif Starlette, latence quasi nulle ; si la connexion WebSocket tombe, le client bascule en polling court sans perte (`?after=<seq>`). |
| Frontend | **HTML + CSS + JavaScript vanilla** (aucun framework) | Imposé par l'énoncé ; page unique légère servie par FastAPI (même origine → pas de CORS). |
| CI | **GitHub Actions** (lint + tests + build docker) | Imposé : CI seule, pas de CD. |
| Conteneurisation | **Docker + docker-compose** | App + Redis orchestrés, service `test` dédié. |

### Organisation du code

```
app/                     # Backend FastAPI
  main.py                # factory, middlewares, static, /api/health
  config.py              # settings depuis l'environnement
  security/              # Argon2id, CSRF, headers, sessions, rate-limit
  db/                    # client Redis + dépendance get_redis()
  repositories/          # users, sessions, rooms, messages (accès Redis)
  schemas/               # contrats Pydantic stricts
  api/                   # endpoints (auth, rooms, messages, users, csrf)
  realtime/              # hub in-process + endpoint /ws
frontend/                # HTML/CSS/JS vanilla (WebCrypto), servi à la racine
tests/                   # 117 tests : unitaires + intégration + sécurité
  helpers/crypto_client.py   # « navigateur de référence » en Python (validé contre le contrat E2E)
```

### Modèle de chiffrement de bout en bout (détaillé)

1. **Inscription** : le navigateur génère `RSA-OAEP-256` (2048 bits). La **clé publique** (SPKI
   base64) est envoyée au serveur. La **clé privée** (JWK) est stockée *localement* (localStorage),
   chiffrée par une clé dérivée du mot de passe (**PBKDF2**, 100 000 itérations, AES-256-GCM) —
   elle **ne quitte jamais** le navigateur.
2. **Création d'un salon** : le client génère une clé de salon (32 octets), s'enveloppe sa propre
   copie avec sa clé publique, et la transmet au serveur (`POST /api/rooms/{id}/keys`).
3. **Ajout d'un membre** : un membre déjà présent déchiffre sa copie de la clé de salon, la
   ré-enveloppe avec la **clé publique** du nouveau membre, et la transmet au serveur. L'adhérent
   reçoit sa copie via un événement temps réel `room_key` (ou via le bouton « Actualiser clés »).
4. **Messages** : `AES-256-GCM` avec la clé de salon, **nonce/IV de 12 octets aléatoire et unique
   par message** (l'AEAD garantit confidentialité *et* intégrité/authenticité du message).

> Le serveur ne stocke que : `ciphertext`, `nonce`, `wrapped_key`, métadonnées (auteur, date, seq).
> Le test `test_no_plaintext_stored_in_redis` le prouve en scannant l'intégralité du stockage.

---

## 3. API publique

| Méthode | Route | Rôle |
|---|---|---|
| GET | `/api/csrf` | Crée une session anonyme, renvoie `{csrf_token}` |
| POST | `/api/auth/register` | Inscription `{username, password, public_key}` → `{user, csrf_token}` |
| POST | `/api/auth/login` | Connexion → `{user, csrf_token}` |
| POST | `/api/auth/logout` | Déconnexion (session détruite, cookie effacé) |
| GET | `/api/me` | Profil + salons de l'utilisateur connecté |
| GET | `/api/users/{username}` | Profil public (id, username, public_key) |
| GET/POST | `/api/rooms` | Liste / création de salon |
| GET | `/api/rooms/{id}/members` | Membres d'un salon (avec clés publiques) |
| POST | `/api/rooms/{id}/join` | Rejoindre un salon |
| POST | `/api/rooms/{room_id}/keys` | Enregistrer une copie enveloppée de la clé de salon |
| GET | `/api/rooms/{id}/messages?after=<seq>` | Historique chiffré (ou reprise de connexion) |
| POST | `/api/rooms/{id}/messages` | Envoyer `{nonce, ciphertext}` |
| WS | `/ws` | Temps réel : `new_message`, `member_joined`, `room_key` |

---

## 4. Sécurité — security by design

| Exigence | Implémentation |
|---|---|
| **CSRF** | Middleware global : **toute mutation** (POST/PUT/PATCH/DELETE) exige le header `X-CSRF-Token` égal au token de session **et** la vérification de l'origine (`Origin`/`Referer`). Couvre l'**authentification** (register/login). |
| **Injections SQL / NoSQL** | Aucune requête construite à partir d'entrées utilisateur ; clés Redis typées sans opérateurs, validation stricte Pydantic en amont (types, longueurs, formats, `extra="forbid"`). Tentatives d'injection testées et rejetées (usage prévu, usernames avec `*`, `;`, `$`, espaces…). |
| **Mots de passe** | **Argon2id** (`argon2-cffi`), hachage à sens unique, jamais stockés en clair, comparaison à temps constant. |
| **E2E** | Clés privées et clair **jamais** transmis au serveur (§2). Nonce unique par message. Vérifié par tests de non-fuites de keys. |
| **Validation & anti-XSS** | Pydantic stricts, limites (pseudo 3–32, mdp 8–128, message ≤ 4 Ko, clé publique ≤ 1000), rendu front 100 % `textContent` (aucun `innerHTML` avec données utilisateur). |
| **Headers** | CSP (`default-src 'self'`, `connect-src 'self' ws: wss:`), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Permissions-Policy` restreinte, `X-XSS-Protection: 0`, HSTS (si HTTPS). |
| **Sessions & secrets** | Cookie `HttpOnly` + `SameSite=Lax` (+ `Secure` en production), **rotation de session** à chaque connexion (anti-fixation), session stockée en Redis avec TTL 7 j. Secrets via variables d'environnement, **jamais commités** (`.env` ignoré). |
| **Erreurs** | Handler global : réponses génériques `{"detail": "..."}`, aucune stack trace exposée (testé). |
| **Bonus** | Rate-limit connexion/inscription (10 essais / 15 min → 429), anti-réutilisation de clé (nonce unique), WebSocket vérifiant cookie + origine (rejet 4401/1008), **server-push uniquement** : le serveur est le seul émetteur d'événements WS (un client ne peut pas injecter de faux messages) et un client ne s'abonne qu'aux salons dont il est membre. |

---

## 5. Démarrage rapide (Docker)

Prérequis : Docker + Docker Compose (plugin `docker compose` ou `docker-compose`).

```bash
docker compose up          # lance l'application sur http://localhost:8000 (app + Redis)
docker compose run --rm test   # exécute toute la suite de tests
```

Variables d'environnement utiles (avec défauts depuis `docker-compose.yml`) :

| Variable | Défaut | Rôle |
|---|---|---|
| `REDIS_URL` | `redis://redis:6379/0` | Adresse Redis |
| `SECRET_KEY` | `dev-only-secret-change-me` | **À changer en production** (via GitHub secrets / env) |
| `COOKIE_SECURE` | `false` (dev) | Passer à `true` en HTTPS |

## 6. Sans Docker (développement)

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
docker run -d --rm -p 6379:6379 redis:7-alpine   # ou un Redis local
.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Puis ouvrir **http://localhost:8000**.

## 7. Tests & qualité

```bash
.venv/bin/pytest -v                 # 117 tests (unitaires + intégration + sécurité)
.venv/bin/ruff check .              # linter — 0 erreur
.venv/bin/ruff format --check .     # formatage — conforme
```

Couverture des tests :

- **Unitaires** : Argon2 (hash/verify, no plaintext), CSRF (token absent/invalide, origine),
  validation Pydantic (usernames, mots de passe, clés publiques SPKI RSA ≥ 2048, base64 stricts),
  logique métier (unicité, séquences de messages, salons, clés enveloppées).
- **Intégration** : parcours complet **register → login → création de salon → (enveloppement de
  clé) → envoi chiffré → réception → historique → déchiffrement interopérable**, polling,
  erreurs (401/403/404/409/422/429) et cas sécurité (CSRF absent, injections rejetées, accès
  non autorisés, non-fuite de texte clair, WebSocket non authentifié…).

La **CI** (`.github/workflows/ci.yml`) exécute à chaque push / pull request : `ruff check` +
`ruff format`, la suite `pytest` complète, et une vérification du build Docker.

---

## 8. Notes & limites assumées

- **Un compte par navigateur** : la clé privée est chiffrée dans le localStorage du navigateur.
  Si le stockage local est vidé, la clé privée est perdue et les anciens messages deviennent
  indéchiffrables — c'est la **contrepartie voulue du chiffrement de bout en bout** (documenté
  dans l'interface elle-même).
- **Rejoindre un salon** : un nouvel arrivant obtient sa copie de clé quand un membre présent
  ré-enveloppe la clé pour lui (automatique via l'événement `member_joined`, ou via le bouton
  « Actualiser clés »). L'historique antérieur à l'obtention de la clé reste chiffré.

---

## 9. Rendu

- Branche : **`etudiant/barraud-teddy`** (CE projet).
- CI : verte sur la branche (lint + 117 tests + build docker).
- Licence : Apache 2.0 (fichier `LICENSE`).
- Énoncé du sujet : `EXAMEN.md` (référence).