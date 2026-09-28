# Talk

> **Chat chiffré de bout en bout — un croisement entre Discord et Telegram WebApp.**

Talk combine le modèle de **Discord** (salons = serveurs, canaux par salon, multi-utilisateurs) et le côté **webapp légère de Telegram** (0 installation, navigateur). Les utilisateurs s'authentifient, rejoignent des salons et échangent des messages **sans que le serveur puisse jamais lire le contenu en clair** : le chiffrement est de bout en bout, entièrement côté client.

Sujet d'examen `SDV DEV 2026`.

## Fonctionnalités

- **Authentification** : inscription, connexion, sessions signées (JWT), mots de passe hachés Argon2id.
- **Salons (modèle Discord)** : création, invitation de membres, liste des salons de l'utilisateur.
- **Canaux** : chaque salon naît avec un canal `#general` ; les membres peuvent créer/retirer d'autres canaux (propriétaire) et chaque canal a son propre fil de messages et sa propre séquence.
- **Chiffrement de bout en bout côté client** : une clé de salon AES-256-GCM générée dans le navigateur, enveloppée individuellement pour chaque membre (ECDH P-256 via Web Crypto). Le serveur ne stocke et ne relaie **que du ciphertext**.
- **Temps réel** : WebSocket par salon + présence (join/leave) ; reconnexion avec backoff.
- **Webapp légère** : HTML + CSS + JavaScript vanilla, aucun framework ni dépendance front.

## Sécurité

- **CSRF** : toute mutation exige un jeton double-submit (`X-CSRF-Token` ↔ cookie `talk_csrf`, SameSite=strict, rotation à chaque ré-authentification).
- **Injections NoSQL/SQL** : validation stricte Pydantic en amont (regex, longueurs bornées, caractères de contrôle interdits) ; tous les identifiants passent par `ObjectId.is_valid`/`get_channel` appartenant au salon (anti-crosstalk). Les opérateurs NoSQL (`$ne`, `$gt`…) sont refusés ou renvoient 404/401 indifférenciés.
- **E2EE** : les clés (privée ECDH, clé de salon) **ne quittent jamais le navigateur** (IndexedDB non-extractable). Le serveur voit uniquement des blobs opaques.
- **Anti-XSS** : rendu 100 % `textContent` (aucun `innerHTML`), CSP `default-src 'self'`.
- **Headers de sécurité** : CSP, `nosniff`, `X-Frame-Options`, `Referrer-Policy`, `X-Content-Type-Options` posés par middleware.
- **Sessions** : cookie `HttpOnly` signé, `Secure` configurables, durée limitée.

## Mise en place

### Docker (recommandé)

```bash
docker compose up              # app + MongoDB, puis http://localhost:8000
docker compose run --rm test   # tests unitaires + intégration + lint
```

### Local (dev, sans Docker)

```bash
python -m venv .venv
.venv\Scripts\activate            # PowerShell ; `source .venv/bin/activate` sous Unix
pip install -r requirements-dev.txt
# MongoDB sur localhost:27017 (ou régler TALK_MONGODB_URI dans .env)
.venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

Voir `.env` pour les réglages (préfixe `TALK_`).

### Tests

```bash
ruff check app/ tests/        # linter + bandit (app) + imports
python -m pytest tests/ -v    # 80+ tests, BDD en mémoire (aucun Mongo requis)
```

## Structure du dépôt

```
Dockerfile                # image runtime (app + frontend), multi-stage
docker-compose.yml        # app + MongoDB (+ service test)
.github/workflows/ci.yml  # CI : push & PR → lint + tests + build image
app/                      # backend FastAPI (auth, salons, canaux, clés, WS)
frontend/                 # HTML/CSS/JS vanilla + chiffrement côté client
tests/                    # tests unitaires + intégration / non-régression
```

- `app/models.py` : validation stricte des entrées (Pydantic).
- `app/security.py` : Argon2id + jetons de session.
- `app/realtime.py` : `ConnectionManager` (broadcast par salon, présence).
- `app/routers/` : `auth`, `rooms`, `channels`, `keys`, `ws`.
- `frontend/js/` : `crypto.js` (Web Crypto E2EE), `api.js` (fetch + CSRF), `ws.js` (socket), `ui.js` (rendu XSS-safe), `app.js` (orchestration).

## Protocole WebSocket

Hors-main : JSON `{"channel": "<id>", "payload": "<blob chiffré>"}`.
Le serveur vérifie la session, l'appartenance au salon, que `channel` appartient bien à ce salon, respecte le plafond de taille (`64 Ko`), puis **relaie le blob tel quel** aux autres membres — il ne le lit ni ne le déchiffre jamais.

| Fermeture | Signification |
|---|---|
| `4401` | session absente/invalide ou non-membre |
| `4402` | enveloppe mal formée ou canal inconnu du salon |
| `4409` | payload trop volumineux |

## Mode de travail

- Branche étudiante : `etudiant/<nom>-<prenom>` (ici `etudiant/lescoat-gabin`).
- `main` sert de référence : jamais de force-push, reset, réécriture ou suppression des branches d'autrui.
- CI GitHub Actions : **verte sur chaque push / pull request**.