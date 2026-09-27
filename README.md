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

## Exécuter les tests

```bash
# Lancer les tests avec pytest directement
pytest tests/ -v

# Lancer les tests avec Docker Compose
docker compose run --rm test

# Lancer les tests avec couverture
docker compose run --rm test pytest --cov=app --cov-report=term-missing

# Lancer le test manuel inclus dans le dépôt
python run_tests.py
```

La **CI GitHub Actions** exécute les tests et le linter à chaque push / pull request.

## Déploiement

```bash
# Construire l'image Docker
docker build -t talk-app:latest .

# Lancer le conteneur
docker run -d -p 8000:8000 talk-app:latest

# Avec Docker Compose
docker compose up -d
```

Le déploiement en production s'effectue via Docker ou Docker Compose. L'application écoute sur le port 8000 par défaut.

### Déploiement sur plateforme cloud

- **Docker Hub / GitHub Container Registry** : Pousser l'image vers un registry distant
- **Railway / Render / Fly.io** : Utiliser le Dockerfile existant pour le déploiement
- **Variables d'environnement** :
  - `REDIS_HOST` : Hôte Redis (par défaut redis en Docker Compose)
  - `REDIS_PORT` : Port Redis (par défaut 6379)
  - `DEBUG` : Mode debug (true/false)

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