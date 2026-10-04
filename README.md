# Talk

Webapp de discussion chiffrée de bout en bout, en salons et canaux (proche de Discord). Projet **SDV DEV 2026** : FastAPI, Redis et JavaScript sans framework.

Le serveur ne voit jamais le texte des messages ni les clés qui permettent de les lire : tout est chiffré et déchiffré dans le navigateur.

## Démarrer

Il faut Docker avec Compose :

```bash
docker compose up --build
```

Ouvrir <http://localhost:8000>, puis :

1. Créer deux comptes (deux navigateurs, ou une fenêtre privée). Chaque compte doit s’être connecté une fois pour avoir sa clé.
2. Avec le premier compte, créer un salon (`+` à gauche).
3. Dans « Membres », cliquer sur `+` et taper l’identifiant du second compte.
4. Les messages apparaissent chez tous les membres en 2,5 secondes environ. Les nouveaux salons apparaissent en 10 secondes environ.

Le créateur d’un salon peut ajouter des canaux, ajouter et retirer des membres.

## Tests

```bash
docker compose --profile test run --rm test
```

Cette commande lance Ruff puis les tests de l’API avec la couverture. Les tests du chiffrement se lancent avec Node :

```bash
node --test "tests/*.test.js"
```

La CI GitHub Actions lance tout à chaque push et pull request : Ruff, les tests Python (couverture minimale 90 %), les tests Node et la construction de l’image Docker. Les tests n’ont besoin d’aucun service : ils utilisent un faux Redis en mémoire.

| Fichier | Ce qui est testé |
|---|---|
| `tests/test_security.py` | Argon2, CSRF, vérification d’origine, headers, cookies, erreurs génériques |
| `tests/test_auth.py` | inscription, connexion, déconnexion, sessions, limite de tentatives, entrées invalides, essais d’injection |
| `tests/test_members.py` | clés publiques, ajout et retrait de membres, droits du créateur |
| `tests/test_servers.py` | parcours complet entre deux comptes, accès refusés, messages en clair refusés, historique |
| `tests/crypto.test.js` | chiffrement : partage de la clé de salon, aller-retour, nonce unique, mauvaise clé, message modifié ou déplacé |

## Architecture

```text
Navigateur                      Serveur FastAPI                  Redis
app.js     interface      --->  security.py  CSRF, origine,  --->  comptes, sessions
crypto.js  RSA + AES-GCM        sessions, limite tentatives        salons, membres
clé privée (localStorage)       routes/  comptes, salons,          clés de salon chiffrées
                                messages                           messages chiffrés
   les messages et les clés de salon ne quittent le navigateur que chiffrés
```

```text
app/main.py                 création de l’app, headers de sécurité, gestion des erreurs
app/routes/accounts.py      inscription, connexion, déconnexion, clés publiques
app/routes/servers.py       salons, membres, clés de salon, canaux
app/routes/messages.py      messages chiffrés
app/security.py             Argon2, CSRF + origine, sessions, limite de tentatives
app/permissions.py          vérifie membre / créateur / canal du bon salon
app/models.py               schémas Pydantic (validation des entrées)
app/database.py             connexion Redis
frontend/crypto.js          chiffrement (Web Crypto)
frontend/app.js             interface
tests/                      tests Python (pytest) et tests du chiffrement (Node)
Dockerfile                  image de test + image finale non-root avec healthcheck
docker-compose.yml          application, Redis, service de test
.github/workflows/ci.yml    ruff, tests, couverture, build Docker
```

## Chiffrement de bout en bout

1. **Clés de l’utilisateur.** À la première connexion, le navigateur crée une paire de clés **RSA-OAEP 2048** (SHA-256). La clé privée reste dans le navigateur (`localStorage`). Seule la clé publique est envoyée au serveur.
2. **Clé de salon.** À la création d’un salon, le navigateur crée une clé **AES-GCM 256 bits**. Il l’envoie au serveur uniquement chiffrée (« enveloppée ») avec la clé publique du créateur.
3. **Ajout d’un membre.** Le créateur récupère la clé publique du nouveau membre, enveloppe la clé du salon avec et l’envoie. Le serveur garde une copie chiffrée par membre, qu’il ne peut pas ouvrir.
4. **Messages.** Chaque message est chiffré avec AES-GCM, un nonce aléatoire de 96 bits par message, et l’identifiant du canal en données authentifiées : un message modifié ou déplacé dans un autre canal est refusé au déchiffrement.

Le serveur stocke donc : des clés publiques, des clés de salon enveloppées et des messages chiffrés. Jamais de texte ni de clé utilisable.

## Sécurité

- **Mots de passe** : **Argon2id** avec sel aléatoire. Si le compte n’existe pas, un faux hash est vérifié pour que la réponse prenne le même temps, et le message d’erreur est le même.
- **Limite de tentatives** : après 5 échecs de connexion pour un même identifiant depuis la même adresse IP, la connexion est bloquée 15 minutes (compteur dans Redis avec expiration).
- **Sessions** : jeton aléatoire stocké dans Redis (7 jours), cookie `HttpOnly`, `SameSite=Strict` et `Secure` en HTTPS. Nouvelle session à chaque connexion, l’ancienne est supprimée. La déconnexion supprime la session côté serveur.
- **CSRF** : toutes les requêtes qui modifient des données (inscription et connexion comprises) doivent venir de notre site (`Origin`, sinon `Referer`) et porter un jeton CSRF identique à celui du cookie.
- **Contrôle d’accès** : chaque route vérifie la session, l’appartenance au salon et, pour les canaux et les membres, que l’utilisateur est le créateur.
- **Injections** : pas de SQL. Toutes les entrées passent par des schémas Pydantic stricts (types, tailles, format, champs en trop refusés) : un objet comme `{"$gt": ""}` est refusé. Les clés Redis sont construites avec des identifiants générés par le serveur ou validés par une expression régulière.
- **XSS** : les messages et les noms sont affichés avec `textContent`, jamais interprétés comme du HTML. CSP stricte (`default-src 'none'`, scripts du site uniquement).
- **Headers** : CSP, HSTS, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Cross-Origin-Opener-Policy`, `Cross-Origin-Resource-Policy`. Pas d’en-tête CORS.
- **Erreurs** : messages génériques (« Données invalides », « Erreur interne »), sans détail ni trace. Pages `/docs` désactivées.
- **Secrets** : le projet n’a besoin d’aucun secret. `REDIS_URL` peut être fourni en variable d’environnement.
- **Docker** : l’application tourne avec un utilisateur sans droits root.

## Choix techniques

- **Redis plutôt que MongoDB** : les données sont simples (comptes, ensembles de membres, listes de messages) et Redis a déjà les bonnes structures (`HASH`, `SET`, `LIST`). Il gère aussi l’expiration automatique (`EX`), parfaite pour les sessions et le compteur de tentatives. Une seule base sert donc pour les données et les sessions. Les données sont gardées sur disque grâce à l’option `appendonly`.
- **Polling toutes les 2,5 s plutôt que WebSocket** : accepté par le sujet, beaucoup plus simple, et toutes les requêtes passent par les mêmes contrôles (session, CSRF, droits).
- **RSA-OAEP + AES-GCM** : disponibles nativement dans Web Crypto, sans bibliothèque externe. RSA sert uniquement à partager la clé du salon, AES-GCM chiffre et authentifie les messages.
- **Argon2id** : recommandé par l’OWASP pour les mots de passe, résistant aux attaques par GPU.

## Limites connues

- Les noms de salons et de canaux, les auteurs et les dates restent visibles du serveur.
- La clé privée est liée au navigateur : sur un nouvel appareil, une nouvelle paire est créée et le créateur doit ajouter à nouveau le membre pour lui redonner la clé du salon.
- Retirer un membre lui retire l’accès aux messages côté serveur, mais la clé du salon n’est pas changée (pas de rotation).
- Le serveur fournit les clés publiques et le code JavaScript : un serveur activement malveillant pourrait les remplacer. Le chiffrement protège contre la lecture des données stockées ou interceptées.
- La limite de tentatives se base sur l’adresse IP vue par l’application : derrière un proxy, il faudrait lire l’IP réelle.
- En production, le HTTPS est indispensable (Web Crypto et cookies `Secure`).
