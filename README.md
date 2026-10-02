# Talk

Webapp de discussion en salons et canaux. Projet pédagogique **SDV DEV 2026** : FastAPI, Redis et JavaScript sans framework.

## Démarrer

Il faut Docker avec Compose :

```bash
docker compose up --build
```

Ouvrir <http://localhost:8000>. Créer deux comptes dans deux navigateurs (ou avec une fenêtre privée), créer un salon et envoyer son lien d’invitation à l’autre compte. Le créateur peut ajouter des canaux. Les messages apparaissent chez tous les membres en environ 2,5 secondes.

```bash
docker compose --profile test run --rm test
```

Cette commande lance Ruff puis les tests de l’API avec la couverture. Les tests du chiffrement côté navigateur se lancent avec Node :

```bash
node --test "tests/*.test.js"
```

La CI GitHub Actions lance tout à chaque push et pull request : Ruff, les tests Python (couverture minimale 90 %), les tests Node et la construction de l’image Docker. Aucun service externe n’est nécessaire : les tests utilisent un faux Redis en mémoire.

| Fichier | Ce qui est testé |
|---|---|
| `tests/test_security.py` | hachage Argon2, CSRF, vérification d’origine, headers, cookies, erreurs génériques |
| `tests/test_auth.py` | inscription, connexion, déconnexion, sessions, entrées invalides, essais d’injection |
| `tests/test_servers.py` | parcours complet entre deux comptes, accès refusés, messages en clair refusés, historique |
| `tests/crypto.test.js` | chiffrement AES-GCM : aller-retour, nonce unique, mauvaise clé, message modifié ou déplacé |

## Fonctionnement

- Les mots de passe sont hachés avec **Argon2id** (sel aléatoire inclus). Si le compte n’existe pas, un faux hash est vérifié pour que la réponse prenne le même temps. Les sessions sont des jetons aléatoires conservés dans Redis (7 jours) et envoyés dans un cookie `HttpOnly`, `SameSite=Strict` (et `Secure` en HTTPS). Une nouvelle session est créée à chaque connexion et l’ancienne est supprimée.
- Les requêtes qui modifient des données (y compris inscription et connexion) doivent venir de notre site (en-tête `Origin`, sinon `Referer`) et porter un jeton CSRF identique au cookie. L’API vérifie aussi l’appartenance au salon et, pour créer un canal, le compte créateur.
- Le navigateur crée une clé AES-256 aléatoire pour chaque salon. Il chiffre chaque message avec AES-GCM et un nonce aléatoire de 96 bits. L’identifiant du canal est inclus dans les données authentifiées.
- La clé reste dans le stockage local du navigateur. Le lien d’invitation la contient dans son **fragment** (`#`), que le navigateur n’envoie pas au serveur. Il faut transmettre ce lien par un canal privé. Si la clé locale est perdue, il faut récupérer à nouveau l’invitation.
- Redis conserve les utilisateurs, salons, membres, canaux et messages chiffrés. Les 100 derniers messages d’un canal sont affichés et actualisés toutes les 2,5 secondes.
- Toutes les entrées passent par des schémas Pydantic stricts (types, tailles, format, champs en trop refusés) : un objet comme `{"$gt": ""}` est refusé. Les clés Redis sont construites avec des identifiants générés par le serveur.
- Les messages sont affichés comme texte, sans interpréter leur HTML. Chaque réponse porte une CSP stricte, HSTS, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy` et `Cross-Origin-Opener-Policy`.
- Les erreurs renvoient un message générique (« Données invalides », « Erreur interne »), sans détail ni trace.

**Limites connues :** les noms de salons et canaux, auteurs et dates restent visibles du serveur. Tous les membres d’un salon partagent la même clé : un membre ayant reçu l’invitation peut lire l’historique. Il n’y a pas de rotation ni de révocation des clés. L’application JavaScript étant livrée par le serveur, un serveur activement malveillant pourrait modifier ce code ; le chiffrement protège contre la lecture passive des messages stockés ou transmis au serveur. En production, servir l’application en HTTPS est indispensable pour Web Crypto et la confidentialité des liens.

## Structure

```text
app/main.py                 création de l’app, headers, gestion des erreurs
app/routes.py               routes : comptes, salons, canaux, messages
app/security.py             Argon2, CSRF + origine, sessions, headers
app/models.py               schémas Pydantic (validation des entrées)
app/database.py             connexion Redis
frontend/crypto.js          chiffrement AES-GCM (Web Crypto)
frontend/app.js             interface
tests/                      tests Python (pytest) et tests du chiffrement (Node)
Dockerfile                  image de l’application
docker-compose.yml          application, Redis, commande de test
.github/workflows/ci.yml    tests et linter
```

Le projet ne nécessite aucune valeur secrète de configuration. `REDIS_URL` peut être fourni à l’application pour choisir le serveur Redis.
