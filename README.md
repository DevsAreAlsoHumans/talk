# talk — chat chiffré de bout en bout

Application de messagerie proche de Discord : on crée un compte, on ajoute des **amis**, on rejoint des
**salons** où chacun a un **grade** (chef, sous-chef, membre), on discute en quasi temps réel — et **le
serveur ne peut jamais lire les messages**. Ils sont chiffrés dans le navigateur avant l'envoi et ne sont
déchiffrés que dans le navigateur des membres du salon ou des deux participants d'une **conversation
directe** (entre amis). On peut aussi partager des **images**, envoyer des **messages vocaux**, compléter
son **profil** (surnom, biographie, avatar) et **s'appeler en vocal** entre membres d'un salon.

**Stack :** Python 3.12 · FastAPI · Redis · HTML/CSS/JavaScript vanilla (WebCrypto) · Docker · GitHub Actions.

---

## 1. Lancer l'application

```bash
docker compose up            # application + Redis, sur http://localhost:8000
docker compose run --rm test # linter + tests unitaires et d'intégration (contre un vrai Redis)
```

Ouvrez <http://localhost:8000>, créez deux comptes (dans deux navigateurs ou une fenêtre privée), créez un
salon avec le premier, ajoutez le second par son nom d'utilisateur : les messages s'affichent en direct.
Envoyez une **demande d'ami** au second, acceptez-la : vous pourrez ouvrir une **conversation directe**
chiffrée rien qu'à deux, et le chef d'un salon pourra nommer des **sous-chefs** ou ajouter des membres.

Configuration (variables d'environnement, voir [`.env.example`](./.env.example) ; le fichier `.env` n'est jamais commité) :

| Variable | Rôle | Défaut |
|---|---|---|
| `SECRET_KEY` | Clé de signature des jetons CSRF (≥ 32 caractères). Absente : clé éphémère générée au démarrage | *(éphémère)* |
| `REDIS_URL` | Connexion Redis | `redis://redis:6379/0` (compose) |
| `ALLOWED_ORIGINS` | Origines autorisées pour les mutations et le WebSocket | `http://localhost:8000,http://127.0.0.1:8000` |
| `COOKIE_SECURE` | Cookies `Secure` | `true` |

**Cookies `Secure` en HTTP :** Chrome et Firefox les acceptent sur `http://localhost`. Sous Safari, ou pour un
accès en HTTP sur un autre hôte, lancez avec `COOKIE_SECURE=false docker compose up` (développement uniquement).
En production, placez l'application derrière un reverse proxy HTTPS.

---

## 2. Architecture

```
app/                         Backend FastAPI
  main.py                    Assemblage : middlewares, routeurs, fichiers statiques, cycle de vie
  config.py                  Réglages lus dans l'environnement (aucun secret dans le code)
  schemas.py                 Schémas Pydantic stricts (entrées ET sorties)
  deps.py                    Dépendances FastAPI (Redis, utilisateur authentifié…)
  errors.py                  Erreurs génériques (pas de fuite d'information)
  realtime.py                WebSockets + diffusion via Redis pub/sub
  security/                  passwords (Argon2id) · sessions · csrf · headers · rate_limit
  repositories/              Accès Redis : users · rooms · messages
  routers/                   auth · users · rooms · messages · ws · health
frontend/                    HTML + CSS + JS vanilla, servi par FastAPI
  js/crypto.js               TOUT le chiffrement (WebCrypto), sans dépendance ni DOM
  js/api.js                  Client REST (jeton CSRF automatique)
  js/app.js · dom.js         Interface
tests/                       unit/ · integration/ · js/ (crypto navigateur) · ui/ (interface de bout en bout)
Dockerfile · docker-compose.yml · .github/workflows/ci.yml
```

Séparation des responsabilités : les *routeurs* ne font que valider, autoriser et orchestrer ; les
*repositories* sont les seuls à parler à Redis ; `security/` ne dépend d'aucune route ; le serveur ne
contient **aucun code de chiffrement de messages** — il ne peut donc pas en faire.

Flux d'un message :

```
Navigateur A ── chiffre (AES-GCM) ──► POST /api/rooms/{id}/messages ──► Redis (texte chiffré)
                                              │
                                              └─► Redis pub/sub ──► WebSocket ──► Navigateur B ── déchiffre
```

---

## 3. Chiffrement de bout en bout

Tout est implémenté dans [`frontend/js/crypto.js`](./frontend/js/crypto.js) avec l'API WebCrypto du navigateur.

1. **Dérivation depuis le mot de passe.** `PBKDF2-SHA256` (600 000 itérations, sel = `talk-e2e-v1:<pseudo>`), puis
   `HKDF-SHA256` produit **deux clés indépendantes** : une *clé d'enveloppe* (qui ne quitte jamais le navigateur)
   et un *secret d'authentification*. **Le serveur ne reçoit jamais le mot de passe**, seulement le secret
   d'authentification, qu'il hache à son tour avec Argon2id.
2. **Identité.** À l'inscription, le navigateur génère une paire de clés **ECDH P-256**. La clé publique est
   publiée ; la clé privée est chiffrée (AES-GCM) avec la clé d'enveloppe avant d'être confiée au serveur, qui ne
   stocke donc qu'un blob illisible. Elle permet de retrouver ses clés depuis n'importe quel appareil avec le
   mot de passe. Une fois déchiffrée, elle est réimportée **non extractable** : le JavaScript ne peut plus la lire.
3. **Clé de salon.** Le créateur génère une clé **AES-256** aléatoire. Pour chaque membre, elle est *enveloppée* :
   ECDH entre une clé éphémère et la clé publique du membre → HKDF → AES-GCM. Le serveur stocke une enveloppe par
   membre ; seule la clé privée du membre l'ouvre. Pour ajouter quelqu'un, le propriétaire (dont le navigateur
   détient la clé du salon) l'enveloppe pour la clé publique du nouveau membre.
4. **Messages.** AES-GCM avec la clé du salon **ou de la conversation directe**, **IV aléatoire de 12 octets par
   message**, données authentifiées (AAD) = `<id du fil>:<id de l'expéditeur>` : un message ne peut être ni modifié,
   ni rejoué dans un autre fil, ni attribué à quelqu'un d'autre sans que le déchiffrement échoue. Les **images** et
   **messages vocaux** sont chiffrés avec la même clé (AAD identique), jusqu'à 2 Mo de contenu (images
   ré-échantillonnées côté navigateur au besoin) ; les miniatures privilégiées sont un second message image.
5. **Anti-réutilisation d'IV.** Le serveur mémorise les IV vus dans chaque fil (salon, conversation directe) et
   refuse (409) tout message qui en réutilise un : réutiliser un IV avec AES-GCM ruinerait la confidentialité.
6. **Conversations directes et amis.** Une conversation est une clé AES-256 qui suit exactement le même protocole
   d'enveloppement qu'un salon, mais chiffrée pour **deux** participants seulement. À la création, l'inviteur
   génère la clé, l'enveloppe pour lui-même puis pour l'ami ; seule la clé privée de chacun des deux l'ouvre.
   Une conversation **ne peut être ouverte qu'entre amis** (une seule par paire : la seconde tentative renvoie 409)
   et un événement n'est publié qu'aux deux participants.
7. **Profil.** Surnom et biographie sont des métadonnées **en clair** (visibles dans la liste des membres,
   comme un pseudo). L'**avatar**, en revanche, est chiffré avec la clé de chaque salon (AES-GCM, IV réservé
   à l'avatar) et stocké propre à chaque salon : seul un membre d'un salon peut regarder l'avatar d'un de ses
   membres.

Le serveur voit passer : clés publiques, enveloppes de clés, IV, texte chiffré. Il ne voit jamais : mot de passe,
clé d'enveloppe, clé privée, clé de salon, texte clair, contenu des images/vocaux, avatars.

**Interopérabilité vérifiée.** `tests/helpers/e2e.py` réimplémente le protocole en Python (bibliothèque
`cryptography`). La CI vérifie dans les deux sens que ce que produit le vrai code du navigateur est lisible par
cette implémentation, et inversement.

---

## 4. Sécurité (security by design)

| Menace | Mesure | Où |
|---|---|---|
| **CSRF** | Jeton *double-submit* signé HMAC-SHA256 et **lié à la session**, exigé sur **toutes** les requêtes POST/PUT/PATCH/DELETE (inscription et connexion comprises) par un middleware : impossible d'oublier une route. Comparaison en temps constant. Cookies `SameSite=Strict`. | `security/csrf.py` |
| **CSRF / détournement de WebSocket** | Contrôle de l'`Origin` (repli sur `Referer`) sur les mutations ; `Origin` exigé pour le WebSocket. | `security/csrf.py`, `routers/ws.py` |
| **Injection SQL** | Aucune base SQL : rien à injecter. | — |
| **Injection NoSQL / Redis** | Schémas Pydantic en mode strict (`extra="forbid"`, pas de coercition) : un objet `{"$ne": null}` à la place d'une chaîne est rejeté ; nom d'utilisateur limité à `[a-z0-9_]{3,32}` (aucun séparateur ni motif ne peut entrer dans une clé Redis) ; identifiants de salon validés comme UUID ; jamais de `KEYS`, `EVAL` ni de commande construite avec une entrée utilisateur. | `schemas.py`, `repositories/` |
| **Mots de passe** | Le navigateur envoie un secret dérivé ; le serveur le hache avec **Argon2id** (sel aléatoire, comparaison en temps constant). Un utilisateur inconnu déclenche quand même une vérification factice (pas de fuite par le temps de réponse). | `security/passwords.py` |
| **Chiffrement de bout en bout** | Voir §3. Tests : la base Redis entière est fouillée, ni texte clair ni clé n'y figurent. | `frontend/js/crypto.js` |
| **Validation des entrées** | Schémas stricts sur toutes les API, base64 décodé et longueurs exactes vérifiées, clés publiques validées comme points P-256, messages texte ≤ 8 Ko, images et vocaux ≤ 2 Mo, avatars entre 48 octets et 512 Ko (un avatar est une vraie image : les fragments minuscules sont refusés). | `schemas.py` |
| **Présence / appels** | La présence est diffusée par salon et par conversation directe ; le relais d'appel (`call_offer`, `call_answer`, `ICE`, `call_end`) n'achemine le signal qu'entre membres d'un même salon **ou amis**, le serveur ne voit pas les flux et refuse d'appeler quelqu'un avec qui on n'a aucun lien. La liste des membres cibles de la présence est précalculée à la connexion : la fermeture d'un WebSocket ne fait **aucune** requête Redis, l'événement « hors ligne » étant rejoué depuis un cache. | `routers/ws.py`, `realtime.py` |
| **XSS** | Contenu toujours inséré comme *texte* (jamais `innerHTML`, contrôlé par un test), CSP `script-src 'self'` sans `unsafe-inline`, aucune ressource externe. | `frontend/js/dom.js`, `security/headers.py` |
| **En-têtes** | `Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options`, `Referrer-Policy: no-referrer`, `Strict-Transport-Security`, `Permissions-Policy`, `Cross-Origin-Opener-Policy`, `Cross-Origin-Resource-Policy`, `Cache-Control: no-store` sur l'API. Aucun en-tête CORS n'est jamais émis. | `security/headers.py` |
| **Sessions** | Identifiant aléatoire de 256 bits ; Redis ne stocke que son empreinte SHA-256 ; cookie `HttpOnly`, `Secure`, `SameSite=Strict`, préfixe `__Host-` ; expiration 8 h ; **rotation à chaque connexion** (anti-fixation) ; destruction côté serveur à la déconnexion (les WebSockets ouverts sont fermés). | `security/sessions.py`, `routers/auth.py` |
| **Secrets** | Uniquement par variables d'environnement / secrets GitHub ; `.env` ignoré par Git ; `SECRET_KEY` < 32 caractères refusée. | `config.py`, `.gitignore` |
| **Erreurs** | Réponses génériques, jamais de stack trace ni de valeur saisie (les erreurs de validation ne listent que les *noms* de champs) ; connexion : même message pour « inconnu » et « mauvais secret ». | `errors.py` |
| **Force brute / abus** | Limitation de débit dans Redis : connexion (5/min par IP+compte, 20/min par IP), inscription (20/h par IP), messages (30/10 s par utilisateur). | `security/rate_limit.py` |
| **Amitié / conversations** | Ajouter un ami est toujours réciproque (double acceptation) ; une conversation directe n'est créable qu'entre amis (403 sinon) et une seule existe par paire (409). Accéder à une conversation ou à son historique exige d'en être membre, sinon 404 — y compris pour ne pas révéler son existence. Changer les grades est réservé au chef du salon ; ajouter un membre, au chef et aux sous-chefs. | `routers/friends.py`, `routers/conversations.py`, `routers/rooms.py` |
| **Confidentialité de l'existence** | Un salon (ou une conversation) inexistant et un salon (ou une conversation) dont on n'est pas membre donnent la même réponse (404). | `routers/rooms.py`, `routers/conversations.py` |
| **Docker** | Utilisateur non root, système de fichiers en lecture seule, `cap_drop: ALL`, `no-new-privileges`, Redis sur un réseau interne non exposé. | `Dockerfile`, `docker-compose.yml` |

La documentation interactive de FastAPI (`/docs`) est désactivée : surface d'attaque en moins.

---

## 5. Choix techniques

- **Redis plutôt que MongoDB.** Le modèle est simple (utilisateurs, ensembles de membres, fil de messages ordonné) et
  Redis apporte gratuitement ce dont l'application a besoin : sessions avec expiration (TTL), compteurs de
  limitation de débit, `SET NX` pour l'unicité atomique des pseudos, sorted sets pour l'historique paginé, pub/sub
  pour le temps réel. Un seul composant à sécuriser et à opérer.
- **WebSocket + Redis pub/sub.** Les routes HTTP publient l'événement sur un canal Redis, chaque instance le relaie à
  ses WebSockets : le temps réel fonctionne avec plusieurs workers. Le client se reconnecte seul (délai croissant)
  et rattrape les messages manqués. L'envoi passe par REST (donc par le CSRF), le WebSocket ne sert qu'à recevoir.
  En filet de sécurité, la liste des amis et des demandes est rafraîchie quand l'onglet redevient visible et toutes
  les 60 s : un événement perdu (socket mort, onglet en arrière-plan) finit par s'afficher sans refresh manuel.
  La taille de trame est portée à **4 Mo** (`--ws-max-size 4194304`) pour que le relais de présence et de signalisation
  tienne largement dans une trame, même avec des réseaux clients lents.
- **WebRTC pour les appels.** Les échanges vocaux sont **de bout en bout** (`RTCPeerConnection` direct entre les deux
  navigateurs, DTLSSRTP natif) ; le serveur se contente de relayer le signal ICE/SDP par son WebSocket — il voit des
  descriptions et des candidats, jamais l'audio. Un appel n'est accepté qu'entre membres d'un salon ou amis.
- **Argon2id** : recommandé par l'OWASP, résistant aux GPU (mémoire dure). **PBKDF2 600 000 itérations** côté navigateur :
  seul algorithme de dérivation lente disponible nativement dans WebCrypto, au niveau recommandé par l'OWASP.
- **AES-GCM** : chiffrement authentifié natif WebCrypto, aucune dépendance côté navigateur.
- **CSRF en middleware** plutôt qu'en dépendance par route : la protection est *par défaut* et ne dépend pas de la
  mémoire du développeur.
- **Aucun framework front, aucune dépendance npm dans l'application** : le code exécuté dans le navigateur est
  entièrement lisible dans `frontend/`. (`package.json` ne sert qu'aux tests.)
- **Un secret d'authentification dérivé plutôt que le mot de passe** : sans cela, le serveur verrait le mot de passe
  à chaque connexion et pourrait dériver la clé qui protège la clé privée — le « bout en bout » serait une façade.
- **Session tenue au refresh sans saisie du mot de passe** : la clé de déverrouillage (dérivée du mot de passe) est
  conservée en `sessionStorage` uniquement. Elle ne déchiffre que la clé privée renvoyée par le serveur avec un cookie
  de session HttpOnly (inaccessible au JavaScript) ; elle est purgée à la déconnexion, à l'expiration de la session et à
  la fermeture de l'onglet. `localStorage`/`indexedDB` ne sont jamais utilisés : rien ne survit à l'onglet.

### Modèle de données Redis

| Clé | Type | Contenu |
|---|---|---|
| `user:{id}` | hash | pseudo, hash Argon2id, clé publique, clé privée *chiffrée*, surnom, biographie |
| `username:{pseudo}` | string | id (réservation atomique, unicité) |
| `session:{sha256}` | string (TTL) | id utilisateur |
| `room:{id}` | hash | nom, propriétaire, date |
| `room:{id}:members` | set | ids des membres |
| `room:{id}:keys` | hash | id membre → clé de salon *enveloppée* |
| `room:{id}:messages` | sorted set | messages chiffrés (score = numéro de séquence) |
| `room:{id}:ivs` · `room:{id}:seq` | set · entier | IV déjà vus · compteur de séquence |
| `room:{id}:avatars` | hash | id membre → avatar *chiffré avec la clé du salon* |
| `room:{id}:roles` | hash | id membre → grade (`owner` · `co` · `member`) |
| `user:{id}:rooms` | set | salons d'un utilisateur |
| `friend:{id}:list` · `requests` · `outgoing` | set | amis confirmés · demandes reçues · demandes envoyées |
| `conv:{id}` | hash | date de création |
| `conv:{id}:members` · `conv:{id}:keys` · `conv:{id}:messages` · `conv:{id}:ivs` · `conv:{id}:seq` | set · hash · sorted set · set · entier | mêmes structure et garanties que salons, sur deux membres |
| `conv:pair:{min}:{max}` | string(→conv id) | unicité : une seule conversation par paire d'amis |
| `user:{id}:convs` | set | conversations directes d'un utilisateur |
| `rl:*` | string (TTL) | compteurs de limitation de débit |

### API

| Méthode | Route | Rôle |
|---|---|---|
| GET | `/api/health` | Santé (ping Redis) |
| GET | `/api/csrf` | Jeton CSRF lié à la session courante |
| POST | `/api/auth/register` · `/login` · `/logout` | Inscription, connexion, déconnexion |
| GET | `/api/auth/me` | Utilisateur courant |
| GET · PUT | `/api/users/{pseudo}` · `/api/me/profile` | Clé publique d'un utilisateur · mettre à jour surnom et biographie |
| PUT | `/api/me/theme` | Préférence d'affichage du compte : `dark` ou `light` |
| GET · POST | `/api/rooms` | Lister · créer un salon (avec la clé enveloppée pour soi) |
| GET | `/api/rooms/{id}` | Détail : membres, ma clé enveloppée, présence, avatars chiffrés |
| POST | `/api/rooms/{id}/members` | Ajouter un membre (chef ou sous-chef ; fournit la clé enveloppée pour lui) |
| POST | `/api/rooms/{id}/roles` | Nommer un sous-chef ou rétrograder un membre (chef uniquement) |
| PUT | `/api/rooms/{id}/avatar` | Enregistrer son avatar chiffré (clé du salon) |
| GET · POST | `/api/rooms/{id}/messages` | Historique paginé (`before`, `limit`) · envoyer un message chiffré (`kind`: `text`, `image`, `voice`) |
| GET · POST | `/api/friends` · `/api/friends/requests` | Lister ses amis · envoyer une demande (ou lister les demandes reçues) |
| POST · POST · DELETE | `/api/friends/{pseudo}/accept` · `/decline` · `DELETE /api/friends/{pseudo}` | Accepter · refuser · retirer un ami |
| GET · POST | `/api/conversations` | Lister ses conversations · en créer une avec un ami (clés enveloppées pour les deux) |
| GET | `/api/conversations/{id}` | Détail d'une conversation (ma clé enveloppée, le correspondant) |
| GET · POST | `/api/conversations/{id}/messages` | Historique paginé · envoyer un message chiffré (mêmes `kind`/limites que les salons) |
| WS | `/ws` | Événements temps réel (`message`, `dm`, `member_added`, `presence`, `presence_dm`, `friend_request`, `friend_accepted`, `friend_declined`, `role_changed`, `call_offer`, `call_answer`, `ice_candidate`, `call_end`) |

---

## 6. Tests

```bash
docker compose run --rm test                  # ruff + pytest (couverture ≥ 90 %) contre un vrai Redis
```

Sans Docker :

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
pytest --cov                                   # fakeredis par défaut ; TEST_REDIS_URL=redis://localhost:6379/15 pour un vrai Redis
node --test tests/js/crypto.test.mjs           # chiffrement du navigateur (Node ≥ 20)
ruff check . && ruff format --check .
```

| Niveau | Contenu |
|---|---|
| `tests/unit/` | Hachage Argon2id · jetons CSRF (signature, liaison à la session) et origine · protocole de chiffrement (aller-retour, altération, mauvaise clé, rejeu dans un autre salon, IV uniques) · schémas (injections, formats, tailles) · limitation de débit · hygiène du frontend (pas d'`innerHTML`, pas de code inline, pas de `localStorage`/`indexedDB` ; seule la clé de déverrouillage est conservée en `sessionStorage`, dans `app.js`) · interopérabilité JS ↔ Python |
| `tests/integration/` | Parcours complet *inscription → connexion → salon → ajout de membre → envoi → réception → historique* · **vérification que Redis ne contient ni texte clair ni clé** · amis (demande, acceptation, refus, retrait) · conversations directes (création chiffrée, réservée aux amis, une par paire, messages/IV/limitation de débit) · grades (chef → sous-chef, droits) · pagination · WebSocket · contrôle d'accès (non-membre, non-propriétaire) · CSRF absent/invalide/lié à une autre session, origine étrangère · injections · en-têtes, cookies, erreurs génériques, CORS absent · limitation de débit · rotation et destruction de session |
| `tests/js/` | Le vrai `crypto.js` sous Node : dérivation, enveloppes de clés, messages, clés non extractables, empreintes, lecture de vecteurs produits par Python |
| `tests/ui/` | Le vrai frontend (`app.js`) piloté dans jsdom contre un vrai serveur et un vrai Redis, avec deux utilisateurs |

**Tests de l'interface** (nécessitent Node ≥ 20 et un serveur en marche) :

```bash
npm ci
uvicorn app.main:create_app --factory --port 8000 &     # avec REDIS_URL et ALLOWED_ORIGINS=http://localhost:8000
npm run test:ui                                         # TALK_REDIS_DB=<n> ajoute la fouille de Redis (redis-cli requis)
```

> Le test d'interface simule un navigateur (jsdom) : il ne remplace pas un essai manuel sur Chrome/Firefox,
> notamment pour la mise en page.

Les clés et valeurs présentes dans `tests/` (ex. `TEST_SECRET_KEY`) sont des constantes de test sans valeur.

---

## 7. Intégration continue

`.github/workflows/ci.yml` s'exécute à chaque *push* et *pull request* :

1. **lint** — `ruff check` + `ruff format --check` ;
2. **tests** — génération des vecteurs d'interopérabilité, tests JavaScript, `pytest` avec couverture (seuil 90 %) contre un Redis réel ;
3. **ui** — démarre le serveur et exécute le test d'interface ;
4. **docker** — `docker compose build`, `docker compose run --rm test`, puis démarrage de l'application et contrôle de santé.

Secret optionnel : `SECRET_KEY` (secret GitHub) ; sans lui, une clé éphémère est générée.

---

## 8. Développement local

```bash
docker run --rm -p 6379:6379 redis:7-alpine &
export REDIS_URL=redis://localhost:6379/0
uvicorn app.main:create_app --factory --reload
```

---

## 9. Limites connues

- **Métadonnées visibles du serveur** : pseudos, noms et membres des salons, dates et tailles des messages. Seul le contenu est chiffré.
- **Confiance dans les clés publiques.** Le serveur fournit la clé publique d'un utilisateur au moment de l'ajout ; un serveur malveillant pourrait en substituer une. Les **empreintes** affichées dans la liste des membres permettent de le détecter en les comparant hors bande ; il n'y a pas de vérification automatique.
- **Le code JavaScript vient du serveur** : un serveur compromis pourrait servir un client piégé. C'est une limite inhérente au chiffrement de bout en bout dans une page web (une extension ou une application native la lèverait).
- **Pas de rotation de clé de salon** ni de retrait de membre (non demandés) : un ancien membre garderait la clé d'un salon. Une seule clé par salon : pas de secret futur (forward secrecy) comme dans Signal.
- **Clé de déverrouillage en `sessionStorage`** : compromis de confort pour rester connecté au refresh. Elle reste
  confinée à l'onglet (fermeture = purge) et ne vaut rien sans le cookie de session HttpOnly. Un XSS reste malgré tout
  un compromis complet — comme dans toute page web chiffrée (voir ci-dessus).
- **Mot de passe perdu = données perdues** (par construction) ; le changement de mot de passe n'est pas implémenté.
- **Limitation de débit par adresse IP** : derrière un reverse proxy, configurer les en-têtes de confiance d'uvicorn (`--proxy-headers`, `--forwarded-allow-ips`).
- **Taille des trames WebSocket** : 4 Mo (paramètre uvicorn `--ws-max-size`). Un média plus gros que ~2 Mo chiffré est refusé (422) ; le navigateur limite déjà à 2 Mo après ré-échantillonnage.
- **Appels vocaux** : point à point (WebRTC) — le serveur relaie le signal, pas l'audio ; derrière un NAT symétrique sans serveur TURN, l'appel peut échouer. Pas de salle de conférence (uniquement à deux).
- **CSP et WebSocket** : `connect-src 'self'` couvre le WebSocket du même hôte dans les navigateurs récents (Safari ancien : à vérifier).
