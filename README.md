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

**Étape 3 — messagerie chiffrée de bout en bout : terminée.**

Le dépôt contient :

- l'application FastAPI (`app/main.py`) avec un endpoint de santé `GET /health` qui répond `{"status": "ok"}` ;
- le service MongoDB dans `docker-compose.yml` ;
- le frontend statique (HTML / CSS / JS vanilla) affiché sur `/` ;
- l'authentification : inscription, connexion, déconnexion, sessions serveur, protection CSRF, en-têtes de sécurité et point d'entrée WebSocket authentifié ;
- la messagerie : salons, adhésion, distribution de clé de salon et messages chiffrés, en temps réel par WebSocket ;
- les tests pytest (unitaires et intégration contre le vrai MongoDB), les tests JavaScript, un test de bout en bout pilotant le vrai client contre le vrai serveur, le linter Ruff et la CI.

### Messagerie chiffrée

Chaque navigateur possède une paire RSA-OAEP-2048 générée localement. La clé
privée est conservée sous forme de `CryptoKey` **non extractible** dans IndexedDB ;
seule la clé publique est publiée sur le serveur. Le JWK privé n'est jamais
stocké ni transmis.

Les messages sont chiffrés en **AES-256-GCM** avec un IV aléatoire de 12 octets.
Le contenu clair n'est lié à aucun champ de l'API : le serveur ne reçoit que le
ciphertext, l'IV et l'identifiant de l'expéditeur.

L'adhésion à un salon se fait en deux temps, volontairement séparés : le serveur
ajoute le membre, puis **le créateur du salon** emballe la clé de salon avec la
clé publique du nouvel arrivant. Le serveur ne peut pas le faire, et ne voit
jamais cette clé.

Le créateur est le seul habilité à administrer son salon : **lui seul** peut
ajouter ou retirer un membre, et déposer une enveloppe de clé. Cette règle est
vérifiée côté serveur, à partir de l'identité de session : un membre ordinaire
et un tiers sont refusés sur ces trois routes, même en appelant directement
l'API. Elle protège la distribution : le dépôt d'une enveloppe étant « premier
arrivé, premier servi » et jamais écrasé, un membre qui pourrait en déposer une
pour un tiers lui imposerait sa propre clé de salon, que le destinataire
déchiffrerait sans erreur en ne pouvant plus lire aucun message chiffré avec la
vraie. Le créateur ne peut pas non plus se retirer lui-même : un canal sans
créateur n'aurait plus personne pour l'administrer ni distribuer sa clé. La
lecture de sa propre enveloppe, elle, reste ouverte à tout membre.

| Route | Description |
|-------|-------------|
| `GET /keys/me` | Clé publique publiée et empreinte RFC 7638. |
| `PUT /keys/me` | Publie la clé publique. Le remplacement est **refusé** (409) : c'est ce qui empêche un navigateur de créer une nouvelle paire et de ne plus pouvoir lire ses canaux. |
| `GET /channels` | Canaux de l'utilisateur. |
| `POST /channels` | Crée un canal. Exige une clé publique déjà publiée (409 sinon). |
| `GET /channels/{id}` | Détail d'un canal, avec la clé publique de chaque membre et son `created_by`. |
| `POST /channels/{id}/members` | Ajoute un membre par identifiant. **Créateur du canal uniquement.** |
| `DELETE /channels/{id}/members/{user_id}` | Retire un membre. **Créateur du canal uniquement.** |
| `POST /channels/{id}/keys` | Dépose une enveloppe de clé de salon (idempotent). **Créateur du canal uniquement.** |
| `GET /channels/{id}/keys/me` | Enveloppe destinée à l'utilisateur courant. Tout membre. |
| `GET /channels/{id}/messages` | Historique chiffré, du plus ancien au plus récent, paginé. |
| `WS /channels/{id}` | Envoi d'un message chiffré, diffusion aux autres membres du canal. |

### Limites assumées du chiffrement

Ces limites sont inhérentes au modèle choisi et non des défauts d'implémentation.
Il vaut mieux les écrire que les laisser découvrir.

- **Aucune rotation de clé.** La clé de salon reste la même tant que le canal
  existe. Ajouter un membre plus tard exige donc de pouvoir rouvrir cette clé.
- **La clé de salon est extractible dans le navigateur.** Web Crypto refuse
  d'exportKey ou de wrapKey une clé non extractible : sans extractibilité, aucune
  clé ne pourrait être partagée, et le chiffrement de bout en bout serait
  impossible à utiliser. La clé privée RSA, elle, reste non extractible. La
  conséquence est qu'un script hostile exécuté dans la page (XSS) peut exfiltrer
  une clé de salon et lire les messages futurs de ce canal.
- **Pas de forward secrecy.** La clé de salon est partagée par tous les membres
  du canal. Quiconque l'obtient peut lire tous les messages passés du canal.
- **L'auteur n'est pas authentifié cryptographiquement.** `sender_id` provient de
  la session, donc le serveur ne peut pas l'attribuer à quelqu'un d'autre ; mais
  un membre ayant la clé de salon peut forger un message au nom d'un autre. Aucun
  message n'est signé.
- **Pas de protection contre la substitution de clé.** Aucune identité n'est
  vérifiée automatiquement. L'empreinte de clé affichée dans l'interface sert
  à une comparaison **hors bande**, entre participants.
- **Retirer un membre ne le prive pas de la clé** qu'il a déjà reçue. Il ne peut
  plus recevoir les enveloppes futures.
- **Premier message vulnérable à la substitution.** Un attaquant qui contrôle
  le canal de l'échange initial de clé peut s'y insérer. Aucun protocole de
  vérification n'est mis en œuvre.
- **Un seul processus applicatif.** La diffusion WebSocket tient en mémoire : le
  passage à plusieurs workers exigerait un bus (Redis en pub/sub).

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
- **Clés** : RSA-OAEP-2048 / SHA-256, `extractable: false` pour la clé privée ; AES-256-GCM avec IV de 12 octets, tiré au hasard par `crypto.getRandomValues`.
- **Données authentifiées** : le chiffrement lie le ciphertext au canal et à l'expéditeur par un AAD au format exact `talk:v1:{channel_id}:{sender_id}`. Un message rejoué dans un autre canal, ou attribué à un autre auteur, est rejeté par GCM.
- **Validation des enveloppes** : taille bornée, base64 strict, JWK public sans composant privée, taille de modulus limitée à 2048 ou 3072 bits.
- **Anti-déchiffrement par le serveur** : le serveur ne reçoit aucun secret. Il ne peut ni lire un message, ni produire une clé de salon, ni fabriquer une enveloppe.
- **Dépôt idempotent** : réémettre une enveloppe pour le même membre ne remplace rien et ne crée pas de doublon.
- **Anti-abus** : fenêtre glissante en mémoire limitant le débit d'envoi par utilisateur et par canal.
- **Clés privées** : jamais sérialisées. Elles vivent dans IndexedDB sous forme de `CryptoKey`, ce qui exclut le vol par simple lecture du magasin.

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
docker compose --profile e2e run --rm e2e   # test de bout en bout
```

`docker compose run --rm test` démarre MongoDB et attend son healthcheck : les
tests d'intégration s'exécutent contre la vraie base `talk_test`, isolée de `talk`.

`docker compose --profile e2e run --rm e2e` démarre l'application, attend sa
santé, puis exécute `tests_e2e/protocol.test.mjs` avec Node. Ce test utilise le
**vrai `frontend/js/crypto.js`** contre le **vrai serveur** : c'est le seul
endroit où un désaccord entre le client et l'API se révèle, les tests Python
n'exploitant que des formes synthétiques. Il ne couvre ni IndexedDB ni le rendu,
qui exigeraient un navigateur.

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
├── chat_schemas.py  # JWK, canaux, enveloppes, messages, trames WebSocket
├── store.py         # persistance des utilisateurs et des sessions
├── chat_store.py    # persistance des canaux, enveloppes et messages
├── security.py      # Argon2id, jetons, empreinte RFC 7638
├── deps.py          # CSRF, utilisateur, adhésion, anti-brute-force
├── middleware.py    # en-têtes de sécurité
├── realtime.py      # diffusion WebSocket en mémoire
└── routers/
    ├── auth.py          # csrf, register, login, logout, me, ws
    ├── keys.py          # clé publique de l'utilisateur
    ├── channels.py      # liste, création, détail
    ├── members.py       # adhésion et retrait
    ├── channel_keys.py  # dépôt et lecture des enveloppes
    └── messages.py      # historique et WebSocket d'envoi
frontend/
├── index.html
├── css/style.css
└── js/
    ├── app.js      # authentification et amorçage
    ├── api.js      # fetch, CSRF, WebSocket
    ├── chat.js     # salons, membres, envoi, rendu
    ├── crypto.js   # RSA, AES-GCM, AAD, emballage de clé
    ├── keystore.js # IndexedDB : identité et clés de salon
    └── *.test.mjs  # tests Web Crypto
tests/
├── conftest.py
├── test_health.py
├── test_auth.py
├── test_csrf.py
├── test_security_headers.py
├── test_nosql_injection.py
├── test_ws_auth.py
├── test_password_hashing.py
├── test_keys.py       # clé publique et empreinte
├── test_channels.py   # canaux et adhésion
├── test_messages.py   # historique, limites, chiffrement
└── test_realtime.py   # WebSocket et diffusion
tests_e2e/
└── protocol.test.mjs  # vrai client contre vrai serveur
.github/workflows/ci.yml
Dockerfile
docker-compose.yml
package.json      # scripts de test, aucune dépendance
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