# talk

> **Chat chiffré de bout en bout — un croisement entre Discord et Telegram WebApp.**

Application de messagerie qui combine le modèle de **Discord** (serveurs, salons, canaux, multi-utilisateurs) et le côté **webapp léger de Telegram** (interface accessible depuis le navigateur, sans installation). Les utilisateurs s'authentifient, rejoignent des salons et échangent des messages **sans que le serveur puisse jamais lire le contenu en clair** (chiffrement de bout en bout côté client).

Sujet d'examen `SDV DEV 2026`.

## Stack

| Couche | Technologie |
|--------|-------------|
| Backend | Python + FastAPI |
| Stockage | MongoDB |
| Frontend | HTML + CSS + JavaScript vanilla |
| Temps réel | WebSocket / polling court |
| CI | GitHub Actions |
| Déploiement | Docker + docker-compose |

## Fonctionnalités

- Authentification (inscription, connexion, sessions sécurisées, mots de passe hachés, 2fa, mot de passe oublié, mot de passe fort obligatoire).
- Salons et canaux de discussion multi-utilisateurs et privé entre 2 utilisateur, proche d'un serveur Discord.
- Système d'amis avec invitation, invitation unique, révocation, liste des amis (ajout par pseudo ou #ID comme sur Discord).
- Messages chiffrés de bout en bout, **jamais stockés en clair**.
- Mise à jour en temps réel ou quasi temps réel via WebSocket.
- Notifications de nouveaux messages, d'invitation, d'amis, d'échange de salon.
- Interface web légère et utilisable, style webapp.
- Badge en ligne/hors ligne.
- Système de role et permissions pour les salons.
- Image de profil et avatar (utilise les "Characters" de https://www.dicebear.com/styles/ ou une image personnalisée importée).
- Pouvoir envoyer des images, des gifs, des vidéos, des fichiers (chiffrés de bout en bout, **jamais stockés en clair**).

## Sécurité

- Protection CSRF effective sur toutes les mutations.
- Prévention des injections SQL et NoSQL.
- Chiffrement de bout en bout côté client (clés jamais transmises au serveur).
- Validation stricte des entrées, anti-XSS, headers de sécurité, sessions sécurisées.
- Protection contre **brute force** pour les connections avec désactivation du compte après trois tentatives + mail d'alerte.

## Démarrer avec Docker

```bash
docker compose up              # lance l'application (app + Redis/MongoDB)
docker compose run --rm test   # lance les tests (unitaires + intégration)
```

La **CI GitHub Actions** exécute les tests et le linter à chaque push / pull request.

## Mode de travail sur ce dépôt

- Travail **individuel** : chaque étudiant développe son projet sur **sa propre branche** (`etudiant/bellini-romain`).
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