# talk

> **Chat chiffré de bout en bout — un croisement entre Discord et Telegram WebApp.**

Talk est une messagerie web légère organisée en salons et canaux. Le chiffrement des
messages est réalisé dans le navigateur : le serveur conserve uniquement des enveloppes
chiffrées et ne reçoit ni le texte en clair, ni la clé symétrique du salon, ni la clé privée
RSA d’un appareil.

Sujet d’examen `SDV DEV 2026`.

## Fonctionnalités

- inscription, connexion et révocation de session ;
- salons, canaux et membres ;
- messages en temps réel par WebSocket ;
- chiffrement de bout en bout côté client ;
- interface responsive HTML/CSS/JavaScript vanilla ;
- recherche d’utilisateurs et partage des clés par appareil ;
- protection CSRF, validation des entrées et en-têtes de sécurité ;
- tests Python et tests cryptographiques JavaScript ;
- image Docker et CI GitHub Actions.

## Stack

| Couche | Technologie |
|--------|-------------|
| Backend | Python 3.12 + FastAPI |
| Stockage | Redis 7 avec persistance AOF |
| Frontend | HTML, CSS et JavaScript vanilla |
| Temps réel | WebSocket |
| Authentification | Argon2id, cookie opaque et CSRF lié à la session |
| Chiffrement | Web Crypto : AES-GCM 256 et RSA-OAEP-256 |
| Tests | pytest, fakeredis et Node test runner |
| CI | GitHub Actions |
| Déploiement | Docker et Docker Compose |

## Démarrage avec Docker

Prérequis : Docker avec le plugin Compose.

```bash
cp .env.example .env
docker compose up --build
```

Ouvrir ensuite <http://localhost:8000>.

Pour arrêter l’application :

```bash
docker compose down
```

Pour supprimer également les données Redis locales :

```bash
docker compose down -v
```

### Lancer les tests

```bash
docker compose run --rm test
```

La commande exécute le linter, le contrôle de format et les tests backend. Les tests
frontend sont aussi exécutés par la CI :

```bash
npm --prefix frontend test
```

## Développement local

Prérequis : Python 3.12+, Node.js 22+ et Redis 7+.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
```

Lancer Redis localement, puis démarrer FastAPI :

```bash
export REDIS_URL=redis://localhost:6379/0
uvicorn app.main:app --reload
```

Les tests backend utilisent `fakeredis` et ne modifient pas une base Redis existante :

```bash
pytest -q
ruff check .
ruff format --check .
```

La documentation interactive de l’API est disponible sur
<http://localhost:8000/docs> hors production.

## Configuration

La configuration est lue depuis les variables d’environnement et le fichier `.env`.

| Variable | Défaut | Description |
|----------|--------|-------------|
| `ENVIRONMENT` | `development` | Utiliser `production` avec HTTPS pour désactiver la documentation et activer HSTS. |
| `REDIS_URL` | `redis://localhost:6379/0` | URL Redis utilisée hors Compose. |
| `REDIS_PASSWORD` | `talk-dev-password` | Mot de passe Redis local ; le changer impérativement hors développement. |
| `COOKIE_SECURE` | `false` | À passer à `true` en production lorsque le site utilise HTTPS. |
| `ALLOWED_ORIGINS` | origines locales | Origines HTTP et WebSocket autorisées, séparées par des virgules. |
| `ALLOWED_HOSTS` | hôtes locaux | En-têtes `Host` acceptés, séparés par des virgules. |
| `SESSION_TTL_SECONDS` | `604800` | Durée absolue d’une session. |
| `CSRF_TTL_SECONDS` | `900` | Durée du jeton CSRF avant rafraîchissement. |

En production, placer l’application derrière un reverse proxy HTTPS et configurer au minimum :

```dotenv
ENVIRONMENT=production
COOKIE_SECURE=true
ALLOWED_ORIGINS=https://talk.example.fr
ALLOWED_HOSTS=talk.example.fr
REDIS_PASSWORD=un-mot-de-passe-long-et-aleatoire
```

Ne jamais exposer Redis publiquement. Si son mot de passe contient des caractères
spéciaux, encoder la valeur dans l’URL Redis ou utiliser une URL fournie par le
fournisseur.

## Fonctionnement du chiffrement

### 1. Identité de l’appareil

Lors de la première connexion d’un compte sur un navigateur, l’application :

1. génère une paire RSA-OAEP 3072 bits avec SHA-256 ;
2. conserve la clé privée **non exportable** dans IndexedDB ;
3. envoie uniquement la clé publique au serveur ;
4. conserve la clé de salon déchiffrée uniquement en mémoire.

Une paire distincte est créée pour chaque compte sur le même navigateur.

### 2. Clé d’un salon

Le propriétaire génère une clé AES-GCM aléatoire de 256 bits. Cette clé est enveloppée
séparément avec la clé publique de chaque appareil membre en RSA-OAEP-256. Le serveur stocke
les enveloppes chiffrées, jamais la clé AES en clair.

Les enveloppes sont versionnées. Le propriétaire peut distribuer la version courante à un
nouvel appareil ou faire tourner la clé du salon. Les anciennes versions restent disponibles
pour déchiffrer l’historique déjà reçu.

### 3. Messages

Chaque message utilise :

- une clé AES-GCM de la version courante ;
- un nonce aléatoire de 96 bits ;
- un tag d’authentification de 128 bits ;
- des données authentifiées contenant le protocole, le salon, le canal, l’identifiant du
  message, l’expéditeur et la version de clé.

Un message déplacé vers un autre salon, un nonce modifié ou un ciphertext altéré est donc
rejeté par Web Crypto.

## Modèle de sécurité

Le serveur peut connaître :

- les comptes et noms affichés ;
- les membres, salons, canaux et clés publiques ;
- les horodatages, tailles, destinataires et enveloppes des messages ;
- les adresses IP vues par l’infrastructure.

Le serveur ne connaît pas :

- le contenu des messages en clair ;
- les clés AES de salon en clair ;
- les clés privées RSA des appareils.

Mesures implémentées :

- mots de passe hachés avec Argon2id ;
- jetons de session aléatoires, stockés sous forme de hash SHA-256 ;
- cookies `HttpOnly`, `SameSite=Strict` et `Secure` en production ;
- jeton CSRF aléatoire lié à la session et contrôle de l’origine ;
- schémas stricts avec rejet des champs inconnus et des tailles excessives ;
- autorisations vérifiées pour chaque salon, canal, message et enveloppe ;
- WebSocket authentifié par cookie et origine exacte ;
- CSP sans `unsafe-inline` ni `unsafe-eval` ;
- rendu des messages via `textContent` afin de neutraliser le HTML injecté ;
- absence de sessions, messages ou clés privées dans `localStorage` ;
- diffusion temps réel limitée aux membres du salon.

## Limites connues

Talk est un prototype pédagogique de chiffrement de bout en bout, pas un système de messagerie
résistant à un serveur malveillant :

- un serveur qui contrôle le JavaScript servi peut tenter de modifier le client ou lire
  les données après leur déchiffrement ;
- la substitution de clés publiques n’est pas détectée sans vérification d’empreinte hors
  bande ;
- il n’existe pas de secret forward : la compromission d’un appareil autorisé donne accès
  aux messages des versions de clés qu’il possède ;
- un nouveau membre reçoit la version courante et peut donc lire les messages de cette
  version, y compris ceux antérieurs à son arrivée ;
- la rotation de clé ne révoque pas une clé copiée et ne supprime pas l’historique déjà
  téléchargé ;
- les métadonnées ne sont pas masquées ;
- la diffusion WebSocket en mémoire convient à un déploiement mono-processus ; plusieurs
  workers nécessiteraient un bus pub/sub distribué.

## Structure

```text
app/
  api/                  routes FastAPI
  config.py             configuration d’environnement
  dependencies.py       sessions, utilisateurs et CSRF
  realtime.py           diffusion WebSocket
  schemas.py            validation Pydantic
  security.py           Argon2id, tokens et Base64URL
  storage.py            accès Redis
frontend/
  assets/styles.css     interface responsive
  js/api.js             client HTTP et CSRF
  js/app.js             application web
  js/crypto.js          Web Crypto et IndexedDB
  tests/                tests Web Crypto
 tests/                  tests API, sécurité et intégration
 .github/workflows/      CI
 Dockerfile              images runtime et test
 docker-compose.yml      application, Redis et tests
```

## API principale

| Méthode | Route | Usage |
|---------|-------|-------|
| `GET` | `/api/auth/csrf` | Initialiser la protection CSRF. |
| `POST` | `/api/auth/register` | Créer un compte et son identité cryptographique. |
| `POST` | `/api/auth/login` | Ouvrir une session. |
| `GET` | `/api/auth/me` | Obtenir l’utilisateur courant. |
| `POST` | `/api/auth/logout` | Révoquer la session. |
| `POST` | `/api/identity/keys` | Enregistrer la clé publique d’un appareil. |
| `GET/POST` | `/api/rooms` | Lister ou créer des salons. |
| `GET/POST` | `/api/rooms/{room_id}/channels` | Lister ou créer des canaux. |
| `GET/POST` | `/api/rooms/{room_id}/keys/...` | Partager ou faire tourner la clé. |
| `GET/POST` | `/api/channels/{channel_id}/messages` | Lire ou stocker des enveloppes chiffrées. |
| `WS` | `/api/ws` | Recevoir les événements temps réel. |

## Travail Git

Chaque étudiant travaille sur `etudiant/<nom>-<prenom>`. Ne jamais réécrire `main` ni la
branche d’un autre étudiant : pas de `force-push`, `reset --hard` ou suppression distante.

## Licence

Licence Apache 2.0 — voir [LICENSE](LICENSE).
