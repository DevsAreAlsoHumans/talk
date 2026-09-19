# ENONCÉ DE L'EXAMEN — Chat chiffré de bout en bout

> Repository partagé : **https://github.com/DevsAreAlsoHumans/talk**
> Chaque étudiant travaille sur **sa propre branche**.

## 1. Contexte

Vous devez développer, à partir de zéro, une **application de chat chiffré de bout en bout**, proche de Discord (salons, canaux, messages, utilisateurs connectés). Le projet doit être mené comme un vrai projet logiciel : versionné, testé, documenté, et intégré en continu sur **GitHub Actions (CI)**.

## 2. Objectifs

1. Produire une application fonctionnelle de chat E2E (register/login, salons, canaux, envoi/réception de messages chiffrés).
2. Prouver que le code est **sûr** (security by design), **testé** (unités + intégration, non-régression) et **intégré en continu**.
3. Fournir un **projet dockerisé** et un **README** permettant de mettre en place et tester l'application facilement.

## 3. Stack technique imposée

| Couche | Technologie |
|--------|-------------|
| Backend | **Python + FastAPI** |
| Stockage | **Redis** ou **MongoDB** (au choix) |
| Frontend | **HTML + CSS + JS vanilla** (pas de framework) |
| Intégration continue | **GitHub Actions (CI uniquement)** |

## 4. Exigences fonctionnelles

- Création de compte / authentification (mots de passe hachés, sessions sécurisées).
- Salons / canaux de discussion (multi-utilisateurs, proche d'un serveur Discord).
- Échanges de messages en temps réel ou quasi temps réel.
- **Chiffrement de bout en bout** des messages (clés par utilisateur/salon, jamais de texte clair en base).

## 5. Exigences de sécurité — security by design

La sécurité est traitée dès la conception, pas en fin de projet :

- Protection **CSRF** (token anti-CSRF sur toutes les mutations).
- Prévention **injection SQL** (requêtes paramétrées / ODM sûr) et injection NoSQL (Redis/MongoDB).
- Hachage des mots de passe (ex. Argon2 / bcrypt).
- Chiffrement de bout en bout des messages.
- Validation stricte des entrées (Pydantic), protection XSS côté affichage.
- Headers de sécurité (CSP, COOP, HSTS…), sessions sécurisées, gestion des secrets.
- Gestion des erreurs sans fuite d'information.

## 6. Exigences qualité

- **Versioning git** : commits réguliers, messages clairs, petites unités de travail.
- **Tests** :
  - Tests **unitaires** (chiffrement, sécurité, modèles, logique métier).
  - Tests **d'intégration / non-régression** (API complète, auth, messages, flux de bout en bout).
- **GitHub Actions** : pipeline CI lançant les tests, conclusion **verte (résultat concluant)**. Le CD n'est pas demandé.
- **Docker** : conteneurisation de l'app (et de Redis/MongoDB) pour simplifier les tests et la mise en place (`docker compose up`).
- **README clair** : fonctionnement, architecture, sécurité, mise en place, lancement des tests.
- **Compréhension** : chaque fonctionnalité livrée doit être validée humainement et compréhensible à minima (code lisible, nommage clair).

## 7. Organisation sur le dépôt Git

> **https://github.com/DevsAreAlsoHumans/talk**

- **Chaque étudiant crée sa propre branche** (ex. `etudiant/nom-prenom` ou `etudiant/<github-user>`) et y travaille uniquement.
- **Ne pas casser les branches des autres étudiants** :
  - ne jamais forcer de push/reset sur une branche qui n'est pas la vôtre ;
  - ne jamais réécrire l'historique partagé (pas de `push --force` sur les branches des autres) ;
  - récupérer les mises à jour de la branche commune sans écraser le travail des autres ;
  - faire sa revue/correction uniquement sur sa propre branche, via des **pull requests propres**.
- Pas de CD : seule la CI est évaluée.
- Le README final de chaque branche doit rester clair et fonctionnel (le README de la branche principale sert de référence pour l'énoncé).

## 8. Livrables

- Dépôt git avec historique de commits régulier et clair.
- Branche personnelle dédiée, sans casse des branches des autres.
- Application dockerisée (docker-compose).
- Pipeline GitHub Actions (CI) vert.
- Suite de tests unitaires + intégration.
- README complet.

---

# GRILLE DE NOTATION

Total : **100 points**

## 1. Fonctionnalités (25 pts)

| Critère | Pts |
|---------|-----|
| Authentification (register/login, sessions, déconnexion) | 5 |
| Salons et canaux (création, liste, messages) | 5 |
| Envoi/réception de messages chiffrés de bout en bout | 10 |
| Expérience proche de Discord (UX de base avec HTML/CSS/JS vanilla) | 5 |

## 2. Sécurité — security by design (25 pts)

| Critère | Pts |
|---------|-----|
| Protection CSRF (tokens sur toutes les mutations) | 5 |
| Anti-injection SQL / NoSQL | 5 |
| Hachage des mots de passe (Argon2/bcrypt) | 3 |
| Chiffrement de bout en bout correctement implémenté (jamais de texte clair persistant) | 5 |
| Validation des entrées + anti-XSS | 3 |
| Headers/mécanismes de sécurité (CSP, sessions sécurisées, secrets) | 4 |

## 3. Tests (20 pts)

| Critère | Pts |
|---------|-----|
| Tests unitaires (chiffrement, sécurité, logique métier) | 8 |
| Tests d'intégration / non-régression (parcours API complets) | 8 |
| Couverture des cas sécurité (CSRF, injections, accès non autorisés) | 4 |

## 4. CI / GitHub Actions (10 pts)

| Critère | Pts |
|---------|-----|
| Pipeline CI qui lance les tests sur chaque push/PR | 5 |
| Résultat concluant (build + tests verts, potentiellement coverage) | 5 |

## 5. Docker & Mise en place (10 pts)

| Critère | Pts |
|---------|-----|
| Application conteneurisée (Dockerfile(s) propres) | 4 |
| Orchestration (`docker-compose` : app + Redis/MongoDB) | 4 |
| Simplicité de lancement et de test | 2 |

## 6. Versioning Git (5 pts)

| Critère | Pts |
|---------|-----|
| Commits réguliers, clairs, petites unités de travail | 3 |
| Branche personnelle propre, sans casse des branches des autres | 2 |

## 7. Documentation (5 pts)

| Critère | Pts |
|---------|-----|
| README clair : fonctionnement, architecture, sécurité, mise en place, tests | 5 |

## 8. Présentation / Soutenance (20 pts)

| Critère | Pts |
|---------|-----|
| Compréhension du code (à minima) — architecture, sécurité, chiffrement | 10 |
| Justification des choix techniques et de sécurité | 5 |
| Démonstration de fonctionnement (app lancée, tests verts, CI verte) | 5 |

> **Seuil de validation :** 60/100, avec un minimum de **10/25 en sécurité** et **10/20 en tests** exigé pour valider la partie technique.

## Pénalités

| Manquement | Malus |
|------------|-------|
| Absence de chiffrement de bout en bout (texte clair en base) | −10 pts |
| Absence de protection CSRF ou vulnérabilité injectable démontrée | −10 pts |
| Branche d'un autre étudiant cassée (force-push, réécriture, suppression) | −10 pts |
| CI non fournie ou rouge | −5 pts |
| Absence de dockerisation | −5 pts |
| README inexistant ou incompréhensible | −5 pts |
| Énorme commit unique / absence d'historique cohérent | −3 pts |