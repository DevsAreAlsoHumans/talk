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

## État de l'implémentation

La première version exécutable contient :

- une API FastAPI avec healthcheck ;
- inscription, connexion, session HttpOnly et protection CSRF ;
- création d'espaces, de canaux et contrôle d'accès par membre ;
- messages transmis sous forme de ciphertext, avec diffusion WebSocket ;
- chiffrement AES-GCM déclenché côté navigateur avec Web Crypto ;
- interface HTML/CSS/JavaScript vanilla responsive ;
- tests pytest, lint Ruff, Bandit et configuration Docker/CI.

Les tests locaux utilisent le store mémoire pour rester rapides et isolés. Docker Compose active le store MongoDB avec `USE_MONGO=true` et persiste les utilisateurs, espaces, canaux et messages chiffrés dans le volume Mongo.

### Développement local

```bash
python -m venv .venv
.venv\\Scripts\\Activate.ps1
python -m pip install -e ".[test,lint]"
python -m pytest -q
python -m ruff check app tests
python -m bandit -r app -q
uvicorn app.main:app --reload
```

L'application est ensuite disponible sur <http://localhost:8000>. Le lancement Docker prévu par le sujet reste :

```bash
docker compose up --build
docker compose run --rm test
```