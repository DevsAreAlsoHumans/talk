# Guide de deploiement de Talk

Ce document decrit l'installation, les tests et le deploiement de l'application Talk.

## 1. Architecture

- Backend : FastAPI avec Uvicorn
- Frontend : HTML, CSS et JavaScript vanilla
- Temps reel : WebSocket
- Stockage : Redis 7
- Conteneurisation : Docker et Docker Compose
- Version Python cible : Python 3.11
- Port HTTP de l'application : `8000`
- Port Redis : `6379`

Les espaces sont stockés dans Redis par type : serveurs, salons, groupes et messages directs. Les salons sont toujours rattachés à un serveur. Les messages directs sont masqués individuellement lors d'une suppression et réapparaissent lors d'une recréation avec le même utilisateur.

## 2. Prerequis

### Installation recommandee

- Linux, macOS ou Windows avec WSL2
- Docker Engine 24 ou plus recent
- Docker Compose v2
- Git
- Au moins 2 Go de RAM disponibles pour Docker

Verifier les outils :

```bash
git --version
docker --version
docker compose version
```

Sous Linux, l'utilisateur doit pouvoir utiliser Docker sans erreur de permission :

```bash
sudo usermod -aG docker "$USER"
newgrp docker
docker ps
```

Si `docker ps` est encore refuse, fermez puis rouvrez votre session utilisateur.

## 3. Recuperer le projet

```bash
git clone <URL_DU_DEPOT>
cd talk
```

Pour deployer une branche precise :

```bash
git fetch --all
git checkout <nom-de-branche>
git pull origin <nom-de-branche>
```

## 4. Configuration

Les parametres sont definis dans `app/config.py` et peuvent etre fournis par des variables d'environnement.

Variables disponibles :

| Variable | Valeur par defaut | Description |
|---|---:|---|
| `APP_NAME` | `talk` | Nom du service |
| `DEBUG` | `false` | Active ou desactive le mode debug |
| `SEED_ADMIN` | `false` | Cree le compte de demonstration au demarrage |
| `HOST` | `0.0.0.0` | Adresse d'ecoute |
| `PORT` | `8000` | Port HTTP |
| `REDIS_HOST` | `127.0.0.1` | Hote Redis local ; Compose utilise `redis` |
| `REDIS_PORT` | `6379` | Port Redis |
| `REDIS_DB` | `0` | Numero de base Redis |
| `REDIS_PASSWORD` | vide | Mot de passe Redis |
| `SECRET_KEY` | generee automatiquement | Cle de signature JWT |
| `ALGORITHM` | `HS256` | Algorithme JWT |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `10080` | Duree de validite du token |
| `BCRYPT_ROUNDS` | `12` | Cout du hachage des mots de passe |
| `CSRF_SECRET` | generee automatiquement | Secret CSRF |
| `SESSION_COOKIE_SECURE` | `false` | Passer a `true` avec HTTPS |
| `SESSION_COOKIE_HTTPONLY` | `true` | Interdit l'acces JavaScript au cookie de session |
| `SESSION_COOKIE_SAMESITE` | `lax` | Politique SameSite |
| `RATE_LIMIT_REQUESTS` | `100` | Nombre de requetes autorisees |
| `RATE_LIMIT_WINDOW` | `60` | Fenetre du rate limiting en secondes |

Generer des secrets robustes :

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

### Important pour la production

Les services `app` du `docker-compose.yml` recoivent actuellement `REDIS_HOST`, `REDIS_PORT` et `DEBUG`. Pour conserver les memes secrets apres un redemarrage, injecter au minimum `SECRET_KEY`, `CSRF_SECRET` et `REDIS_PASSWORD` dans le service `app` ou utiliser des secrets Docker.

Ne jamais committer un fichier `.env` contenant des secrets. Exemple de variables a utiliser dans un environnement de production :

```text
DEBUG=false
SECRET_KEY=<cle-secrete-longue-et-aleatoire>
CSRF_SECRET=<secret-csrf-long-et-aleatoire>
REDIS_PASSWORD=<mot-de-passe-redis>
SESSION_COOKIE_SECURE=true
```

Le fichier `.env` est ignore par Git. Les secrets doivent etre fournis par le gestionnaire de secrets de la plateforme ou par l'environnement d'execution.

### Compte administrateur de demonstration

Le Compose de test active `SEED_ADMIN=true` et cree automatiquement ce compte si Redis ne le contient pas encore :

```text
Identifiant : Admin
Mot de passe : admin
Email       : admin@talk.local
```

Ce compte est reserve au developpement local. Desactiver `SEED_ADMIN` et creer un compte administrateur avec un mot de passe unique avant toute exposition publique.

## 5. Tests avant deploiement

### Avec Docker Compose

Le service de test installe les dependances du projet et demarre Redis :

```bash
docker compose run --rm test
```

Avec couverture :

```bash
docker compose run --rm test pytest tests/ -v --cov=app --cov-report=term-missing
```

Lint et verification syntaxique :

```bash
docker compose run --rm test ruff check app/ tests/ run_tests.py
```

Le test manuel :

```bash
docker compose run --rm test python run_tests.py
```

### Environnement Python local

Python 3.11 est recommande, car il correspond a la CI et au Dockerfile :

```bash
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Dependances installees par `requirements.txt` :

- `fastapi==0.109.0`
- `uvicorn[standard]==0.27.0`
- `redis==5.0.1`
- `python-multipart==0.0.6`
- `passlib[bcrypt]==1.7.4`
- `python-jose[cryptography]==3.3.0`
- `pydantic==2.5.3`
- `pydantic-settings==2.1.0`
- `httpx==0.26.0`
- `pytest==7.4.4`
- `pytest-asyncio==0.23.3`
- `pytest-cov==4.1.0`
- `ruff==0.1.14`

Commandes locales :

```bash
pytest tests/ -v
pytest tests/ -v --cov=app --cov-report=term-missing
ruff check app/ tests/ run_tests.py
python run_tests.py
```

Pour les tests d'integration locaux, Redis doit etre demarre et accessible sur `REDIS_HOST`/`REDIS_PORT`.

## 6. Construire l'image Docker

Construire l'image :

```bash
docker build -t talk-app:latest .
```

Tester l'import de l'application dans l'image :

```bash
docker run --rm talk-app:latest python -c "from app.main import app; print(app.title)"
```

## 7. Deployer avec Docker Compose

Construire et demarrer l'application ainsi que Redis :

```bash
docker compose up -d --build
```

Verifier l'etat des services :

```bash
docker compose ps
```

Consulter les logs :

```bash
docker compose logs -f app
docker compose logs -f redis
```

Verifier l'endpoint de sante :

```bash
curl -f http://localhost:8000/health
```

Reponse attendue :

```json
{"status":"healthy","service":"talk"}
```

L'interface et l'API sont alors accessibles a l'adresse :

```text
http://localhost:8000
```

FastAPI sert directement `frontend/index.html`, `frontend/app.js` et `frontend/style.css` à la racine. Aucun second serveur statique n'est nécessaire avec Docker Compose.

Après connexion, sélectionner un serveur charge ses salons. Le titre d'un salon suit le format `Serveur / Salon`; les groupes et messages directs restent indépendants. La zone de conversation est vidée lorsqu'aucun espace n'est sélectionné.

## 8. Mise a jour d'une version deja deployee

```bash
git pull origin <nom-de-branche>
docker compose build --no-cache
docker compose up -d

docker compose ps
curl -f http://localhost:8000/health
```

Ne supprimer le volume Redis qu'en connaissance de cause :

```bash
docker volume ls
docker volume inspect talk_redis_data
```

## 9. Arret et nettoyage

Arreter les conteneurs en conservant les donnees Redis :

```bash
docker compose down
```

Arreter les conteneurs et supprimer le volume Redis :

```bash
docker compose down -v
```

Supprimer l'image locale :

```bash
docker image rm talk-app:latest
```

## 10. Sauvegarde Redis

Sauvegarder les donnees Redis depuis le conteneur :

```bash
docker compose exec redis redis-cli BGSAVE
docker compose cp redis:/data/dump.rdb ./redis-backup-$(date +%Y%m%d-%H%M%S).rdb
```

Avant toute mise a jour importante, verifier que le fichier de sauvegarde existe et est lisible.

## 11. Exposition en production

Le Compose fourni est adapte au developpement et a un deploiement simple. Pour une exposition Internet :

1. Placer un reverse proxy HTTPS devant l'application, par exemple Nginx ou Traefik.
2. Activer `SESSION_COOKIE_SECURE=true`.
3. Ne pas exposer le port Redis `6379` publiquement.
4. Restreindre CORS a l'origine frontend attendue au lieu de `*`.
5. Fournir `SECRET_KEY`, `CSRF_SECRET` et `REDIS_PASSWORD` via un gestionnaire de secrets.
6. Configurer une sauvegarde Redis reguliere.
7. Surveiller `/health`, les logs et l'espace disque.

Les connexions WebSocket doivent etre proxifiees vers `/ws` avec les en-tetes Upgrade et Connection conserves.

## 12. CI GitHub Actions

La CI se trouve dans `.github/workflows/ci.yml`. Elle utilise Python 3.11 et execute :

- Ruff sur `app/`, `frontend/` et `tests/`.
- Mypy sur le projet.
- Pytest.
- La construction de l'image Docker.

Avant un push :

```bash
ruff check app/ frontend/ tests/
pytest tests/ -v
git diff --check
git status
```

Un deploiement doit etre effectue uniquement apres une CI verte et une reponse valide de `/health`.

## 13. Depannage

### Permission Docker refusee

```bash
sudo usermod -aG docker "$USER"
newgrp docker
docker ps
```

### Le port 8000 est deja utilise

Identifier le processus :

```bash
ss -ltnp | grep ':8000'
```

Ou modifier le port expose dans Compose, par exemple `8080:8000`, puis ouvrir `http://localhost:8080`.

### L'application ne joint pas Redis

```bash
docker compose ps
docker compose logs redis
docker compose exec redis redis-cli ping
```

La reponse attendue est `PONG`.

### Reinitialiser les conteneurs

```bash
docker compose down
docker compose up -d --build
```

Utiliser `docker compose`, avec un `c` minuscule, dans la derniere commande.
