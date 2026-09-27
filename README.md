# talk

Application de discussion **chiffrée de bout en bout**, inspirée de Discord : les
utilisateurs s'authentifient, créent des serveurs, y ouvrent des canaux et
échangent des messages que le serveur ne peut pas lire.

Tout le chiffrement se fait dans le navigateur. Le serveur ne reçoit que des
messages chiffrés et des enveloppes de clé qu'il est incapable d'ouvrir : il ne
détient aucun secret, et ne peut ni déchiffrer un message, ni fabriquer une clé
de salon.

## Stack

| Couche | Technologie |
|--------|-------------|
| Backend | Python 3.13 + FastAPI |
| Stockage | MongoDB 7 |
| Frontend | HTML + CSS + JavaScript vanilla (aucun framework) |
| Temps réel | WebSocket |
| Tests | pytest (intégration contre le vrai MongoDB), `node --test` (Web Crypto) |
| CI | GitHub Actions |
| Déploiement | Docker + docker-compose |

### Pourquoi MongoDB

Le choix suit la forme des données, pas une préférence générale.

- **Des données documentaires.** Utilisateurs, serveurs, canaux, enveloppes de
  clé et messages sont des objets à identité propre, lus et modifiés presque
  toujours par leur identifiant. Ils se décrivent naturellement comme des
  documents imbriqués : un serveur contient sa liste de membres, un canal son
  `server_id`, un message son ciphertext et son IV.
- **Des recherches couvertes par des index.** Les accès de l'application sont
  connus et peu nombreux : l'appartenance d'un utilisateur à ses serveurs
  (`members.user_id`), les canaux d'un serveur (`server_id`), l'historique d'un
  canal paginé par curseur (`_id`), les enveloppes d'un couple
  (canal, membre, version). Chacun correspond à un index simple ou composé, et
  se vérifie par un test qui interroge le vrai document Mongo.
- **Un démarrage simple sous Docker.** L'image officielle `mongo:7` suffit, avec
  un healthcheck et un volume nommé, sans configuration supplémentaire.

Le projet n'a pas de dépendance à l'un ou l'autre moteur : c'est le modèle
documentaire et les requêtes ci-dessus qui ont départagé. Le choix resterait
discutable avec un modèle différent.

## Fonctionnalités

- **Authentification** : inscription, connexion, déconnexion, sessions serveur,
  mots de passe Argon2id, protection CSRF, en-têtes de sécurité.
- **Serveurs et canaux** : création de serveurs, adhésion et retrait de membres,
  création de canaux, liste et consultation, le tout administré par le seul
  créateur du serveur.
- **Messagerie chiffrée** : envoi, réception et historique paginé. Le serveur ne
  stocke ni texte clair, ni clé de salon.
- **Temps réel** : un message envoyé apparaît chez les autres membres du canal
  sans rechargement, par WebSocket.
- **Interface web** : vanilla HTML/CSS/JS, servie par l'API sur `/`, sans
  installation.

## État du projet

L'application est complète : le modèle de données, l'authentification, la
messagerie chiffrée et le temps réel sont en place, et le dépôt est testable
d'une commande.

Le dépôt contient :

- l'application FastAPI (`app/main.py`) avec un endpoint de santé `GET /health` qui répond `{"status": "ok"}` ;
- le service MongoDB dans `docker-compose.yml` ;
- le frontend statique (HTML / CSS / JS vanilla) affiché sur `/` ;
- l'authentification : inscription, connexion, déconnexion, sessions serveur, protection CSRF, en-têtes de sécurité et point d'entrée WebSocket authentifié ;
- la messagerie : salons, adhésion, distribution de clé de salon et messages chiffrés, en temps réel par WebSocket ;
- les serveurs : création, adhésion, retrait, et les canaux qu'ils contiennent ; l'appartenance y est gérée, un canal n'a plus de membres ;
- les tests pytest (unitaires et intégration contre le vrai MongoDB), les tests JavaScript, un test de bout en bout pilotant le vrai client contre le vrai serveur, le linter Ruff et la CI.

### Messagerie chiffrée

Chaque navigateur possède une paire RSA-OAEP-2048 générée localement. La clé
privée est conservée sous forme de `CryptoKey` **non extractible** dans IndexedDB ;
seule la clé publique est publiée sur le serveur. Le JWK privé n'est jamais
stocké ni transmis.

Les messages sont chiffrés en **AES-256-GCM** avec un IV aléatoire de 12 octets.
Le contenu clair n'est lié à aucun champ de l'API : le serveur ne reçoit que le
ciphertext, l'IV et l'identifiant de l'expéditeur.

L'appartenance appartient au **serveur**, jamais au canal. Un canal ne contient
que son `server_id` : il n'a ni `members`, ni `created_by`, et l'API ne renvoie
rien de tel. Toute autorisation descend donc le canal jusqu'à son serveur, et
c'est `server.members` qui décide. Cette règle est écrite une seule fois, dans
`require_channel_server`, et toutes les routes l'utilisent telle quelle.

L'adhésion à un salon se fait en deux temps, volontairement séparés : le serveur
ajoute le membre, puis **le créateur du serveur** emballe la clé de salon avec la
clé publique du nouvel arrivant. Le serveur ne peut pas le faire, et ne voit
jamais cette clé.

Le créateur du serveur est le seul habilité à l'administrer : **lui seul** peut
ajouter ou retirer un membre, créer un canal, et déposer une enveloppe de clé.
Cette règle est vérifiée côté serveur, à partir de l'identité de session : un
membre ordinaire et un tiers sont refusés sur ces routes, même en appelant
directement l'API. Elle protège la distribution : le dépôt d'une enveloppe étant
« premier arrivé, premier servi » et jamais écrasé, un membre qui pourrait en
déposer une pour un tiers lui imposerait sa propre clé de salon, que le
destinataire déchiffrerait sans erreur en ne pouvant plus lire aucun message
chiffré avec la vraie.

Le créateur ne peut pas se retirer lui-même : un serveur sans créateur n'aurait
plus personne pour l'administrer. Le refus ne dépend pas du nombre de membres.
La lecture de sa propre enveloppe, elle, reste ouverte à tout membre du serveur.

Un retrait porte sur **tous** les canaux du serveur à la fois, et emporte les
enveloppes de clé de salon du membre retiré. Il ne lui retire pas la clé qu'il
possède déjà localement : le serveur ne peut pas le faire, et sans rotation de
clé, il pourrait encore déchiffrer ce qui lui parviendrait.

| Route | Description |
|-------|-------------|
| `GET /keys/me` | Clé publique publiée et empreinte RFC 7638. |
| `PUT /keys/me` | Publie la clé publique. Le remplacement est **refusé** (409) : c'est ce qui empêche un navigateur de créer une nouvelle paire et de ne plus pouvoir lire ses canaux. |
| `GET /channels` | Canaux accessibles, tous serveurs confondus. Liste plate, conservée pour la reprise après fermeture de navigateur. |
| `GET /channels/{id}` | Détail d'un canal : son `server_id` et rien d'autre sur l'appartenance. |
| `POST /channels/{id}/keys` | Dépose une enveloppe de clé de salon (idempotent). **Créateur du serveur parent uniquement.** |
| `GET /channels/{id}/keys/me` | Enveloppe destinée à l'utilisateur courant. Tout membre du serveur parent. |
| `GET /channels/{id}/messages` | Historique chiffré, du plus ancien au plus récent, paginé. |
| `WS /channels/{id}` | Envoi d'un message chiffré, diffusion aux autres membres du serveur. |
| `GET /servers` | Serveurs dont l'utilisateur est membre. |
| `POST /servers` | Crée un serveur et en fait son créateur le premier membre. |
| `GET /servers/{id}` | Détail d'un serveur, avec l'ancienneté d'adhésion et la clé publique de chaque membre. |
| `GET /servers/{id}/channels` | Canaux du serveur. Membres du serveur uniquement. |
| `POST /servers/{id}/channels` | Crée un canal dans le serveur. Exige une clé publique déjà publiée (409 sinon). **Créateur du serveur uniquement.** |
| `POST /servers/{id}/members` | Ajoute un membre par nom d'utilisateur. Le serveur résout le nom ; un nom inconnu est un 404. **Créateur du serveur uniquement.** |
| `DELETE /servers/{id}/members/{user_id}` | Retire un membre, et ses enveloppes sur tous les canaux du serveur. **Créateur du serveur uniquement.** |

### Serveurs

Un canal appartient à un serveur, et un serveur ne quitte pas un canal : c'est le
sens de la hiérarchie. Retirer quelqu'un d'un serveur le retire de tous ses
canaux, ce qui n'aurait pas de sens au niveau d'un canal.

Ce qui est garanti :

- Le créateur vient **de la session**, jamais du corps de la requête. `created_by`
  et `joined_at` y sont refusés (422) : le premier décide de la propriété, le
  second de l'ancienneté, donc du successeur par défaut.
- Le créateur rejoint automatiquement le serveur, avec un `joined_at` généré par
  le serveur et stocké en `datetime`.
- `GET /servers`, `GET /servers/{id}` et `GET /servers/{id}/channels` ne
  renvoient que les serveurs et canaux dont l'appelant est membre : 403 pour un
  tiers, 404 pour un identifiant mal formé ou un serveur absent.
- L'adhésion est idempotente : réinviter quelqu'un ne crée pas de second
  sous-document, le filtre portant sur `members.user_id` et non sur `members`.
- Un serveur ne détient aucun secret : ni clé de salon, ni texte chiffré, ni
  haché de mot de passe. La clé publique d'un membre y figure pour permettre
  l'emballage des clés de salon.
- `client_ref` est unique **par serveur**, pas par auteur : c'est le serveur qui
  fabrique le canal. L'ancien index unique `(created_by, client_ref)` est
  explicitement supprimé au démarrage, faute de quoi il dégraderait la contrainte
  en une unicité globale de `client_ref`.

### Données antérieures à la migration

La migration vers le modèle `Serveur → Canal` ne conserve pas les canaux issus du
modèle précédent. Les documents `channels` qui ne portent pas de `server_id` ont
été supprimés, et aucun code ne les supporte : le contrat est que tout document de
`channels` possède un `server_id`, que `POST /servers/{id}/channels` garantit à
chaque création. Une base issue de l'ancien modèle doit être vidée de ses canaux
avant d'être utilisée — un canal orphelin n'est ni listable, ni lisible, et son
accès direct renvoie une erreur. Aucun script de reprise de ces données n'est
fourni : leur contenu n'a pas vocation à survivre au changement de modèle.

Ce qui n'existe pas encore : le transfert de propriété, le départ volontaire du
créateur, et la suppression d'un serveur. Aucune de ces trois opérations n'a de
règle arbitrée, et les ouvrir à moitié laisserait un serveur sans personne pour
l'administrer.

### Limites assumées du chiffrement

Ces limites sont inhérentes au modèle choisi et non des défauts d'implémentation.
Il vaut mieux les écrire que les laisser découvrir.

- **Aucune rotation de clé, et une enveloppe déposée est définitive.** La clé de
  salon reste la même tant que le canal existe. Ajouter un membre plus tard exige
  donc de pouvoir rouvrir cette clé. Concrètement, un dépôt d'enveloppe ne
  remplace rien : le premier dépôt pour un couple (canal, membre) gagne, et une
  enveloppe fausse ou obsolète reste en place, sans moyen de la corriger par
  l'API. Seule une rotation de clé, non implémentée, le permettrait.
- **Rejoindre un serveur ouvre l'historique de tous ses canaux.** L'accès à
  `GET /channels/{id}/messages` ne dépend que de l'appartenance au serveur, et
  cette appartenance n'a pas de date d'effet : un nouveau membre peut donc lire
  retroactivement les messages déjà écrits dans les canaux du serveur. Il ne peut
  toutefois pas les déchiffrer sans les enveloppes correspondantes, que le
  créateur doit déposer canal par canal (voir ci-dessous).
- **La clé de salon est extractible dans le navigateur.** Web Crypto refuse
  d'exportKey ou de wrapKey une clé non extractible : sans extractibilité, aucune
  clé ne pourrait être partagée, et le chiffrement de bout en bout serait
  impossible à utiliser. La clé privée RSA, elle, reste non extractible. La
  conséquence est qu'un script hostile exécuté dans la page (XSS) peut exfiltrer
  une clé de salon et lire les messages futurs de ce canal.
- **Pas de forward secrecy.** La clé de salon est partagée par tous les membres
  d'un canal, donc par tous les membres du serveur qui y ont accès. Quiconque
  l'obtient peut lire tous les messages passés de ce canal.
- **L'auteur n'est pas authentifié cryptographiquement.** `sender_id` provient de
  la session, donc le serveur ne peut pas l'attribuer à quelqu'un d'autre ; mais
  un membre ayant la clé de salon peut forger un message au nom d'un autre. Aucun
  message n'est signé.
- **Pas de protection contre la substitution de clé.** Aucune identité n'est
  vérifiée automatiquement. L'empreinte de clé affichée dans l'interface sert
  à une comparaison **hors bande**, entre participants.
- **Retirer un membre ne le prive pas de la clé** qu'il a déjà reçue. Il perd
  l'accès à tous les canaux du serveur et ne peut plus recevoir d'enveloppe
  future, mais ce qu'il possède localement lui suffit à déchiffrer ce qui lui
  parviendrait encore.
- **L'appartenance n'est pas vérifiée en continu.** Le retrait est contrôlé à
  chaque requête et à chaque ouverture de WebSocket, pas à chaque trame. Côté
  serveur, le retrait purge bien les enveloppes du membre sur tous les canaux du
  serveur, immédiatement ; mais une connexion WebSocket déjà ouverte n'est pas
  évincée et continue d'émettre et de recevoir tant qu'elle reste ouverte. La
  fermer exigerait une lecture de base par message, ce qui n'a pas lieu d'être
  tant qu'aucune rotation de clé n'est en jeu.
- **L'ajout d'un membre demande une enveloppe par canal.** L'appartenance se
  règle au niveau du serveur, mais la clé de salon est propre à chaque canal :
  après `POST /servers/{id}/members`, le créateur doit déposer une enveloppe sur
  chacun des canaux auxquels le nouveau membre doit accéder, via
  `POST /channels/{id}/keys`. Tant que ce dépôt n'a pas eu lieu, le nouveau
  membre est membre du serveur sans pouvoir déchiffrer aucun de ses messages.
- **Premier message vulnérable à la substitution.** Un attaquant qui contrôle
  le canal de l'échange initial de clé peut s'y insérer. Aucun protocole de
  vérification n'est mis en œuvre.
- **Un seul processus applicatif.** La diffusion WebSocket tient en mémoire : le
  passage à plusieurs workers exigerait un bus (Redis en pub/sub).

### Authentification

| Route | Description |
|-------|-------------|
| `GET /auth/csrf` | Bootstrap : crée au besoin une session anonyme et pose les cookies `talk_session` et `talk_csrf`. Idempotent. |
| `POST /auth/register` | Crée un compte (Argon2id, mot de passe de 12 caractères minimum) puis ouvre une session. |
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
- **CSRF** : double soumission liée à la session, comparaison en temps constant ; le jeton `X-CSRF-Token` n'est efficace que combiné au cookie de session, que le JavaScript ne peut pas lire.
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
docker compose run --rm test   # suite pytest (base talk_test)
docker compose --profile e2e run --rm e2e   # test de bout en bout
```

Le linter ne fait pas partie du service `test` : c'est `ruff`, à lancer
séparément (voir « Tests et intégration continue »).

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

### Tests et intégration continue

| Commande | Ce qu'elle lance |
|----------|------------------|
| `docker compose run --rm test` | Les 210 tests pytest, contre le vrai MongoDB (base `talk_test`) |
| `docker compose run --rm -v "$PWD:/work" -w /work app ruff check .` | Le linter |
| `docker compose run --rm -v "$PWD:/work" -w /work app ruff format --check .` | Le contrôle de format |
| `node --test frontend/js/*.test.mjs` | Les 38 tests Web Crypto |
| `docker compose --profile e2e run --rm e2e` | Les 17 tests de bout en bout |

La **CI GitHub Actions** (`.github/workflows/ci.yml`) rejoue exactement cela sur
chaque push et chaque pull request, en quatre tâches indépendantes : `ruff` puis
`pytest`, les tests JavaScript, le bout en bout dans Docker, et une vérification
de cohérence du `docker-compose`. MongoDB y est un service dedié, et l'image
`app` est reconstruite pour le bout en bout. La CI ne publie aucune image.

### Arborescence

```
app/
├── __init__.py
├── main.py          # lifespan, middlewares, route API puis montage du frontend
├── config.py        # configuration lue depuis l'environnement
├── db.py            # client MongoDB asynchrone et index
├── security.py      # Argon2id, jetons de session, empreinte RFC 7638
├── schemas.py       # validation des entrées, représentation des sorties
├── chat_schemas.py  # JWK, canaux, enveloppes, messages, serveurs, trames WebSocket
├── store.py         # persistance des utilisateurs et des sessions
├── chat_store.py    # persistance des canaux, enveloppes, messages et serveurs
├── deps.py          # CSRF, utilisateur, adhésion, anti-brute-force
├── middleware.py    # en-têtes de sécurité
├── realtime.py      # diffusion WebSocket en mémoire
└── routers/
    ├── auth.py          # csrf, register, login, logout, me, ws
    ├── keys.py          # clé publique de l'utilisateur
    ├── channels.py      # liste plate, canaux d'un serveur, création, détail
    ├── channel_keys.py  # dépôt et lecture des enveloppes
    ├── messages.py      # historique et WebSocket d'envoi
    └── servers.py       # serveurs, adhésion et retrait de membres
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
├── test_servers.py    # serveurs : création, lecture, isolation, ancienneté
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
