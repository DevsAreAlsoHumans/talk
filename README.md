<div align="center">

<img src="frontend/favicon.svg" width="72" height="72" alt="">

# Ronyme

**Messagerie de groupe chiffrée de bout en bout.**
Un croisement entre Discord et la webapp Telegram — sans que le serveur puisse jamais lire vos messages.

Projet d'examen `SDV DEV 2026` — branche `etudiant/Liuaga-Avazeri`

</div>

---

## Sommaire

- [Le principe](#le-principe)
- [Stack technique](#stack-technique)
- [Démarrage](#démarrage)
- [Architecture](#architecture)
- [Sécurité](#sécurité)
- [Le site public](#le-site-public)
- [Conformité RGPD](#conformité-rgpd)
- [Accessibilité](#accessibilité)
- [API](#api)
- [Configuration](#configuration)
- [Tests](#tests)
- [Intégration continue](#intégration-continue)
- [Limites connues](#limites-connues)
- [Licence](#licence)

---

## Le principe

Ronyme reprend le modèle de Discord — des **salons** qui contiennent des **canaux**
thématiques — et le sert comme une webapp légère, sans installation.

La différence tient en une phrase : **tout le chiffrement se passe dans le navigateur.**
Le serveur reçoit du texte chiffré, le stocke, le rediffuse, et n'a jamais les clés
permettant de le lire. Une copie complète de la base de données ne livrerait aucun
message en clair.

```
Navigateur A                    Serveur                    Navigateur B
────────────                    ───────                    ────────────
message clair
    │
    ├─ chiffre (AES-256-GCM)
    │
    └──── texte chiffré ──────►  stocke  ──── texte chiffré ────►│
                                 diffuse                          │
                                                    déchiffre ────┤
                                                                  │
                                                          message clair
```

---

## Stack technique

| Couche | Technologie | Pourquoi |
|--------|-------------|----------|
| Backend | Python 3.12 + FastAPI | Asynchrone natif, validation par Pydantic |
| Base de données | MongoDB 7 (Motor) | Documents imbriqués adaptés aux salons/membres |
| Frontend | HTML + CSS + JavaScript vanilla | Aucune dépendance, aucun script tiers |
| Chiffrement | WebCrypto API (RSA-2048 + AES-256-GCM) | Implémentation native du navigateur, auditée |
| Temps réel | WebSocket natif FastAPI | Diffusion instantanée, reconnexion automatique |
| Authentification | JWT + Argon2id | Argon2id recommandé par l'ANSSI |
| Tests | pytest + pytest-asyncio | 153 tests unitaires et d'intégration |
| Linter | ruff | Lint + format en un seul outil |
| CI | GitHub Actions | Lint, tests et build Docker à chaque push |
| Conteneurisation | Docker + docker-compose | `docker compose up` et c'est parti |

---

## Démarrage

### Avec Docker (recommandé)

```bash
docker compose up
```

L'application est disponible sur **http://localhost:8000**.

Pour lancer la suite de tests :

```bash
docker compose run --rm test
```

### En local

Prérequis : Python 3.12 et une instance MongoDB accessible.

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload
```

---

## Architecture

```
app/                      Backend FastAPI
├── main.py               Application, en-têtes de sécurité, page 404, montage statique
├── config.py             Configuration par variables d'environnement
├── db.py                 Connexion MongoDB et index
├── security.py           Protection CSRF : origine + double-submit cookie
├── ratelimit.py          Limitation de débit en fenêtre glissante
├── analytics.py          Mesure d'audience anonyme, sans cookie ni tiers
├── auth/                 Inscription, connexion, JWT, suppression de compte
├── salons/               Salons, membres, canaux, rotation des clés
├── messages/             Messages chiffrés, pagination, WebSocket
└── crypto/               Validation des clés publiques

frontend/                 Interface web, sans framework ni dépendance
├── index.html            Page d'accueil publique (un seul CTA)
├── app.html              Application : authentification et chat
├── cgu.html              Conditions générales d'utilisation
├── rgpd.html             Politique de confidentialité
├── 404.html              Page d'erreur personnalisée
├── style.css             Système de design (jetons, thème sombre, composants)
├── site.js               Consentement, mesure d'audience, navigation
├── app.js                Chiffrement, appels API, WebSocket, interface du chat
├── favicon.svg/.ico      Icônes du site
├── og-image.png          Aperçu pour les réseaux sociaux (1200 × 630)
├── site.webmanifest      Manifeste PWA
├── robots.txt            Directives d'indexation
└── sitemap.xml           Plan du site

tests/
├── unit/                 Modèles, chiffrement, CSRF, limitation de débit
└── integration/          Parcours complets : authentification, salons, messages, pages
```

---

## Sécurité

### Chiffrement de bout en bout

1. **Inscription** — le navigateur génère une paire RSA-2048 via WebCrypto.
   La clé privée est chiffrée avec une clé dérivée du mot de passe
   (PBKDF2, 210 000 itérations) puis rangée dans le `localStorage`.
   **Seule la clé publique est envoyée au serveur.**

2. **Création d'un salon** — une clé AES-256 est tirée au hasard côté client,
   chiffrée avec la clé publique RSA du créateur, puis stockée chiffrée.

3. **Ajout d'un membre** — le propriétaire récupère la clé publique du nouveau
   membre et lui chiffre la clé du salon. Chaque membre possède sa propre copie
   chiffrée de la même clé.

4. **Messages** — chiffrés en AES-256-GCM avec un IV aléatoire de 96 bits à
   chaque envoi. Le serveur ne stocke que `ciphertext` et `iv`.

5. **Retrait d'un membre** — la clé du salon est régénérée et redistribuée aux
   membres restants ; le compteur `key_version` est incrémenté. L'ancien membre
   ne peut plus déchiffrer les messages postés après son départ.

### Protection CSRF : deux défenses indépendantes

Une mutation doit franchir **deux** contrôles, chacun suffisant à lui seul.

1. **Vérification d'origine.** L'en-tête `Origin` — ou `Referer` à défaut —
   doit désigner ce site. Un navigateur renseigne toujours `Origin` sur une
   requête de mutation et interdit à un script de le falsifier. Une requête
   dépourvue des deux en-têtes est **refusée**, conformément à la
   recommandation OWASP, plutôt qu'acceptée par défaut.
2. **Double-submit cookie.** Un jeton aléatoire de 256 bits doit être présent
   à la fois dans un cookie et dans l'en-tête `x-csrf-token`. Un site tiers
   peut déclencher l'envoi du cookie, mais la politique de même origine
   l'empêche de le lire pour reconstituer l'en-tête. La comparaison se fait
   en temps constant.

Le contrôle d'origine est évalué en premier : une requête venue d'ailleurs est
écartée sans que le jeton soit seulement examiné.

### Mesures complémentaires

| Menace | Contre-mesure |
|--------|---------------|
| CSRF | Double défense : vérification d'origine (`Origin`, repli `Referer`) **et** cookie double-submit `SameSite=Strict`, sur toutes les mutations |
| Injection NoSQL | Validation Pydantic stricte : un `{"$gt": ""}` est rejeté en 422 |
| XSS | CSP sans `unsafe-inline`, `textContent` partout, jamais `innerHTML` |
| Force brute | 5 connexions / 5 min, 3 inscriptions / h, 30 messages / min par IP |
| Spam d'inscription | Champ-piège (*honeypot*) invisible, rejeté côté serveur |
| Clickjacking | `X-Frame-Options: DENY` et `frame-ancestors 'none'` |
| Fuite de referrer | `Referrer-Policy: strict-origin-when-cross-origin` |
| Vol de session | Jeton d'accès de 15 min, jeton de rafraîchissement révocable en base |
| Déni de service applicatif | Messages plafonnés à 16 Ko, pagination bornée à 100 éléments |
| Pistage navigateur | `Permissions-Policy` bloquant caméra, micro, géolocalisation et FLoC |

La politique de sécurité de contenu est volontairement stricte :

```
default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:;
font-src 'self'; connect-src 'self' ws: wss:; frame-ancestors 'none';
base-uri 'self'; form-action 'self'
```

Aucun `unsafe-inline`, aucun `unsafe-eval`, aucun domaine tiers. Le site n'utilise
donc ni police Google, ni CDN, ni balise `<style>` ou `<script>` en ligne.

---

## Le site public

En plus de l'application, le dépôt contient un site vitrine complet.

| Élément | Détail |
|---------|--------|
| **Un seul CTA** | *« Créer mon compte chiffré »* — un unique bouton principal sur la page d'accueil, conformément au principe « une page, une action » |
| **Métadonnées** | `<title>` et `description` uniques par page, URL canonique, `og:*` et `twitter:card` complets |
| **Image de partage** | `og-image.png`, 1200 × 630, **53 Ko** après quantification en palette |
| **Favicon** | SVG vectoriel + `.ico` multi-tailles (16/32/48) + `apple-touch-icon` 180 px |
| **PWA** | `site.webmanifest` avec icônes 192 et 512 px, installable sur mobile |
| **Page 404** | Page personnalisée servie avec le bon code HTTP, avec deux issues claires |
| **Indexation** | `robots.txt` et `sitemap.xml` ; l'application et l'API sont exclues |
| **Pages légales** | CGU et politique de confidentialité rédigées, liées depuis chaque pied de page |

### Poids des images

Toutes les images sont générées et compressées à la construction :

| Fichier | Taille | Technique |
|---------|--------|-----------|
| `favicon.svg` | 0,4 Ko | Vectoriel, mis à l'échelle sans perte |
| `favicon.ico` | 3,1 Ko | Trois tailles, rendu par suréchantillonnage |
| `icon-192.png` | 1,8 Ko | Palette 32 couleurs |
| `apple-touch-icon.png` | 5,1 Ko | PNG optimisé |
| `icon-512.png` | 6,0 Ko | Palette 32 couleurs |
| `og-image.png` | 53,5 Ko | Palette 128 couleurs + diffusion d'erreur |

Total des ressources graphiques : **environ 70 Ko**.

---

## Conformité RGPD

- **Un seul cookie**, `csrf_token`, strictement nécessaire : exempté de
  consentement au titre de l'article 82 de la loi Informatique et Libertés.
- **Bannière de consentement** avec « Refuser » aussi accessible qu'« Accepter »,
  comme l'exige la CNIL. Le choix est révocable depuis la page de confidentialité.
- **Mesure d'audience développée en interne**, sans cookie et sans transfert :
  l'identifiant de visite est une empreinte SHA-256 tronquée de
  `IP + navigateur + secret + date du jour`. Renouvelée chaque jour, elle rend
  tout suivi durable impossible. **L'adresse IP n'est jamais stockée.**
- **`Do Not Track` et `Global Privacy Control` respectés** : aucun événement
  n'est enregistré si l'un des deux est actif, même après acceptation.
- **Expiration automatique** des données d'audience au bout de 13 mois
  (durée maximale recommandée par la CNIL), via un index TTL MongoDB.
- **Droit à l'effacement** implémenté : `DELETE /auth/me` supprime le compte,
  les messages, les appartenances et les salons détenus.
- **Aucun transfert hors Union européenne**, aucun sous-traitant publicitaire.

---

## Accessibilité

Le thème sombre a été construit à partir de jetons de couleur dont les contrastes
sont vérifiés :

| Couple | Ratio | Niveau |
|--------|-------|--------|
| Texte principal / fond | 17,9:1 | AAA |
| Texte secondaire / fond | 9,3:1 | AAA |
| Texte discret / fond | 5,5:1 | AA |
| Liens / fond | 8,1:1 | AAA |
| Blanc / bouton principal | 5,2:1 | AA |
| Messages d'erreur / surface | 6,6:1 | AA |
| Bordures de champs / surface | 3,5:1 | AA (non textuel) |

Également pris en charge :

- lien d'évitement vers le contenu principal ;
- anneaux de focus visibles, jamais supprimés ;
- cibles tactiles d'au moins 44 × 44 px ;
- libellés visibles sur tous les champs, jamais des `placeholder` seuls ;
- erreurs annoncées via `aria-live`, focus déplacé sur le premier champ fautif ;
- l'état de connexion combine couleur **et** texte — jamais la couleur seule ;
- `prefers-reduced-motion` et `prefers-contrast` respectés ;
- champs à 16 px pour éviter le zoom automatique sur iOS.

---

## API

### Authentification

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| `POST` | `/auth/signup` | Inscription (limitée à 3/h, champ-piège anti-spam) |
| `POST` | `/auth/login` | Connexion (limitée à 5 / 5 min) |
| `POST` | `/auth/logout` | Déconnexion et révocation des jetons |
| `POST` | `/auth/refresh` | Renouvellement du jeton d'accès |
| `GET` | `/auth/me` | Profil de l'utilisateur connecté |
| `DELETE` | `/auth/me` | Suppression du compte (RGPD art. 17) |
| `GET` | `/auth/users/{username}/public-key` | Clé publique d'un utilisateur |

### Salons et canaux

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| `POST` | `/salons` | Créer un salon (canal `général` créé automatiquement) |
| `GET` | `/salons` | Lister mes salons |
| `GET` | `/salons/{id}` | Détail d'un salon |
| `POST` | `/salons/{id}/members` | Ajouter un membre |
| `DELETE` | `/salons/{id}/members/{user_id}` | Retirer un membre et faire tourner la clé |
| `POST` | `/salons/{id}/channels` | Créer un canal |
| `GET` | `/salons/{id}/channels` | Lister les canaux |

### Messages

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| `GET` | `/salons/{id}/messages` | Historique paginé (`limit`, `before`, `channel_id`) |
| `POST` | `/salons/{id}/messages` | Envoyer un message (limité à 30/min) |
| `WS` | `/ws/{salon_id}?token=JWT` | Flux temps réel |

La pagination fonctionne par curseur sur l'`_id` MongoDB, ce qui reste performant
quel que soit le volume — contrairement à un `skip` classique :

```http
GET /salons/{id}/messages?limit=50
→ { "messages": [...], "next_cursor": "65f...", "has_more": true }

GET /salons/{id}/messages?limit=50&before=65f...
```

### Mesure d'audience

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| `POST` | `/api/analytics/event` | Enregistrer un événement anonyme |
| `GET` | `/api/analytics/summary` | Agrégats publics (volumes uniquement) |

---

## Configuration

Toutes les valeurs se règlent par variables d'environnement.

| Variable | Défaut | Description |
|----------|--------|-------------|
| `MONGODB_URL` | `mongodb://localhost:27017` | URL de connexion MongoDB |
| `MONGODB_DB` | `ronyme` | Nom de la base |
| `JWT_SECRET` | `change-me-in-production` | Secret de signature des JWT |
| `JWT_ACCESS_EXPIRE_MINUTES` | `15` | Durée du jeton d'accès |
| `JWT_REFRESH_EXPIRE_DAYS` | `7` | Durée du jeton de rafraîchissement |
| `PUBLIC_URL` | `http://localhost:8000` | URL publique (active `Secure` sur les cookies en HTTPS) |
| `ANALYTICS_ENABLED` | `true` | Active la mesure d'audience |
| `ANALYTICS_SALT` | `change-me-analytics-salt` | Sel de l'empreinte de visite |
| `RATE_LIMIT_LOGIN` | `5` | Connexions autorisées par fenêtre |
| `RATE_LIMIT_LOGIN_WINDOW` | `300` | Fenêtre de connexion, en secondes |
| `RATE_LIMIT_SIGNUP` | `3` | Inscriptions autorisées par fenêtre |
| `RATE_LIMIT_SIGNUP_WINDOW` | `3600` | Fenêtre d'inscription, en secondes |
| `RATE_LIMIT_MESSAGE` | `30` | Messages autorisés par fenêtre |
| `RATE_LIMIT_MESSAGE_WINDOW` | `60` | Fenêtre des messages, en secondes |

> **En production**, `JWT_SECRET` et `ANALYTICS_SALT` doivent impérativement être
> remplacés. Le fichier `.env` n'est pas versionné.

---

## Tests

```bash
# Suite complète
python -m pytest tests/ -v

# Tests unitaires seuls (aucune base requise)
python -m pytest tests/unit -v

# Linter et formatage
ruff check app/ tests/
ruff format --check app/ tests/
```

**153 tests** répartis ainsi :

| Fichier | Couvre |
|---------|--------|
| `unit/test_auth_service.py` | Hachage Argon2, création et décodage des JWT |
| `unit/test_crypto.py` | Validation des clés publiques |
| `unit/test_csrf.py` | Jetons CSRF et vérification d'origine (domaines sosies, repli Referer) |
| `unit/test_models.py` | Validation Pydantic, refus des injections NoSQL |
| `unit/test_ratelimit.py` | Fenêtre glissante, isolation par clé et par IP |
| `integration/test_auth_flow.py` | Inscription, connexion, rafraîchissement, déconnexion |
| `integration/test_salons_flow.py` | Création, appartenance, contrôle d'accès |
| `integration/test_channels_flow.py` | Canaux, retrait de membre, rotation des clés |
| `integration/test_messages_flow.py` | Envoi, pagination par curseur, filtrage par canal |
| `integration/test_antispam.py` | Champ-piège, plafonds de débit |
| `integration/test_analytics.py` | Anonymat, respect de DNT et GPC |
| `integration/test_security.py` | CSRF, vérification d'origine, injections, jetons expirés |
| `integration/test_pages.py` | Pages statiques, liens, 404, en-têtes, absence d'inline |

---

## Intégration continue

Le pipeline GitHub Actions exécute trois tâches à chaque `push` et chaque *pull request* :

1. **lint** — `ruff check` et `ruff format --check` ;
2. **test** — la suite complète, avec un service MongoDB 7 ;
3. **docker** — construction de l'image.

---

## Limites connues

Ce projet est pédagogique ; ces limites sont assumées et documentées.

- **La clé privée ne suit pas l'utilisateur.** Elle vit dans le `localStorage`
  d'un navigateur. Se connecter depuis un autre appareil suppose de la transporter
  manuellement. Une vraie application proposerait un export chiffré.
- **Pas de confidentialité persistante par message.** La clé de salon tourne au
  départ d'un membre, mais pas à chaque message comme le ferait le protocole Signal.
- **Les métadonnées restent visibles.** Le serveur ignore le contenu, mais sait qui
  écrit, quand, et dans quel salon.
- **La limitation de débit est en mémoire.** Elle suffit pour une instance unique ;
  une répartition sur plusieurs serveurs demanderait Redis.
- **Pas de modération de contenu possible**, par construction : le chiffrement de
  bout en bout l'interdit techniquement.

---

## Licence

[Apache 2.0](LICENSE)
