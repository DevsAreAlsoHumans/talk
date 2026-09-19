# ENONCÉ DE L'EXAMEN — Application de chat chiffré de bout en bout

<table>
<tr><th>Dépôt de travail</th><td>https://github.com/DevsAreAlsoHumans/talk</td></tr>
<tr><th>Modalité</th><td>Travail <b>individuel</b> — chaque étudiant sur <b>sa propre branche</b></td></tr>
<tr><th>Rendu</th><td>Branche personnelle poussée sur le dépôt, CI verte, README à jour</td></tr>
<tr><th>Barème</th><td><b>Notation sur 20</b> — seuil de validation : <b>12/20</b> (détails en fin de document)</td></tr>
</table>

---

## 1. Contexte

Vous devez développer, à partir de zéro, une **application de chat chiffré de bout en bout**, proche de Discord : des utilisateurs s'authentifient, rejoignent des salons, échangent des messages, le tout **sans que le serveur puisse jamais lire le contenu des messages en clair**.

Le projet doit être mené comme un vrai projet logiciel professionnel : versionné, testé, intégré en continu, sécurisé dès la conception (**security by design**), et dockerisé pour être facilement testable.

## 2. Modalités de travail — règles Git impératives

Dépôt partagé : **https://github.com/DevsAreAlsoHumans/talk**

- **Travail individuel** : chaque étudiant développe **son propre projet** sur **sa propre branche**.
- **Nommage de branche recommandé** : `etudiant/<nom>-<prenom>` (ex. `etudiant/smith-john`).
- **Le README de la branche `main` sert de référence pour l'énoncé** ; elle ne reçoit que des corrections du sujet (pas les projets des étudiants).
- **Ne jamais casser les branches des autres étudiants** :
  - interdiction de `push --force`, `reset`, `rebase`, suppression ou réécriture d'une branche qui n'est pas la vôtre ;
  - ne jamais modifier directement une branche d'un autre étudiant ;
  - pour collaborer, utiliser des **pull requests propres** sans écraser le travail d'autrui ;
  - récupérer les mises à jour de la branche `main` en la fusionnant/rébaselant sans jamais altérer l'historique des autres.
- **Pas de CD** : seule la **CI (GitHub Actions)** est évaluée.

## 3. Stack technique imposée

| Couche | Technologie imposée |
|--------|---------------------|
| Backend | **Python + FastAPI** |
| Stockage | **Redis** ou **MongoDB** (au choix, justifié dans le README) — pare-feux pour stocker aussi les données de session |
| Frontend | **HTML + CSS + JavaScript vanilla** (aucun framework front) |
| Réal-time | WebSocket ou long-polling ou polling court (quasi temps réel accepté) |
| Intégration continue | **GitHub Actions** — CI uniquement (pas de CD) |
| Conteneurisation | **Docker + docker-compose** |

## 4. Fonctionnalités attendues (minimum)

1. **Authentification** : inscription, connexion, déconnexion, session sécurisée, mots de passe hachés.
2. **Salons / canaux** : création, liste, consultation, ajout de membres — proche d'un serveur Discord.
3. **Messagerie chiffrée de bout en bout** : envoi, réception, historique des messages **jamais stockés en clair**.
4. **Temps réel (ou quasi temps réel)** : un message envoyé apparaît chez les autres membres sans rechargement manuel.
5. **Frontend vanilla** : interface simple et utilisable (liste des salons, fil de messages, zone de saisie).

## 5. Exigences de sécurité — security by design

La sécurité doit être pensée **dès la conception**, pas ajoutée à la fin. Points **obligatoires** :

- **CSRF** : token anti-CSRF vérifié sur **toutes** les requêtes qui modifient l'état (POST/PUT/PATCH/DELETE), y compris l'authentification ; vérification de l'origine (`Origin`/`Referer`).
- **Injections** : prévention **injection SQL** (requêtes paramétrées / ORM-ODM sûr) **et** injection NoSQL pour Redis/MongoDB (validation stricte des types, jamais d'opérateurs issus de l'entrée utilisateur).
- **Mots de passe** : hachage fort à sens unique (**Argon2** recommandé, ou bcrypt), jamais de mot de passe stocké en clair ni de comparaison non constante.
- **Chiffrement de bout en bout** : les messages sont chiffrés **côté client** ; le serveur **ne doit jamais avoir accès au texte en clair ni aux clés permettant de le déchiffrer**. Modèle attendu (au choix, à documenter) : clé de salon symétrique enveloppée (wrapping) pour chaque membre, clés privées jamais transmises au serveur, IV/nonce unique par message (AES-GCM, XChaCha20…).
- **Validation des entrées** : schémas stricts (Pydantic) sur toutes les API, limites de taille, protection **XSS** côté affichage.
- **Headers de sécurité** : CSP, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Strict-Transport-Security`, navigation/coopérativité adaptées.
- **Sessions & secrets** : cookie de session `HttpOnly`, `Secure`, `SameSite` ; clés secrètes via variables d'environnement / secrets GitHub, **jamais commitées**.
- **Gestion des erreurs** : réponses génériques (pas de fuite d'information, pas de stack trace exposée).
- **Protections complémentaires appréciées** : rate-limiting (login), en-têtes CORS absents/stricts, rotation de session à la connexion, anti-réutilisation de clé.

## 6. Exigences qualité & tests

- **Versioning** : commits **réguliers** (tout au long du projet, pas seulement en fin), messages **clairs et descriptifs**, **petites unités de travail**.
- **Tests unitaires** : chiffrement/déchiffrement, sécurité (hachage, CSRF, validation), logique métier.
- **Tests d'intégration / non-régression** : parcours API complets (register → login → création de salon → envoi → réception → historique), cas d'erreur et cas de sécurité (accès non autorisé, tokens invalides, CSRF absent…).
- **Preuve de non-régression** : la CI doit **tout** lancer et être **verte** sur la branche personnelle.
- **Docker** : `Dockerfile` et `docker-compose.yml` (app + base de données) ; l'application doit se lancer et se tester simplement (`docker compose up`, puis `docker compose run --rm test` par exemple).
- **Compréhension** : le code rendu sur la branche doit **se comprendre sans explication orale** — lisible, nommage explicite, aucune logique obscure (voir grille, section 8).

## 7. Rendu — livrables attendus

Sur **votre branche personnelle** du dépôt :

1. Historique de commits régulier et clair.
2. Code complet de l'application (backend + frontend).
3. `Dockerfile` + `docker-compose.yml`.
4. Suite de tests (unitaires + intégration) exécutables.
5. Pipeline `.github/workflows/*.yml` (CI) **verte**.
6. **README** à jour et personnel : présentation, architecture, fonctionnement, sécurité, mise en place (docker), lancement des tests, choix techniques justifiés.

---

# GRILLE DE NOTATION

> **Notation sur /20.** Chaque critère est noté par pas de **0,25 point**
> (valeurs possibles : 0 — 0,25 — 0,5 — 0,75 — 1 — 1,25 — 1,5 — 1,75 — 2 — etc.)
> Seuil de validation : **12/20**, avec minimas par bloc (voir plus bas).

## 1. Fonctionnalités — 5 pts

| Critère | Pts |
|---------|-----|
| Authentification complète (inscription, connexion, déconnexion, sessions) | 1,25 |
| Salons / canaux (création, liste, gestion des membres) | 1 |
| Chiffrement de bout en bout des messages (envoi/réception/historique) | 2 |
| Expérience proche de Discord, frontend vanilla fonctionnel et utilisable | 0,75 |

## 2. Sécurité — security by design — 5 pts

| Critère | Pts |
|---------|-----|
| Protection CSRF effective sur toutes les mutations + vérification d'origine | 1 |
| Anti-injection SQL et NoSQL | 1 |
| Hachage des mots de passe robuste (Argon2/bcrypt) | 0,5 |
| E2E correctement implémenté : jamais de texte clair ni de clé de déchiffrement côté serveur | 1 |
| Validation stricte des entrées + anti-XSS | 0,75 |
| Headers de sécurité, sessions sécurisées, gestion des secrets | 0,75 |

## 3. Tests — 3 pts

| Critère | Pts |
|---------|-----|
| Tests unitaires (chiffrement, sécurité, logique métier) | 1 |
| Tests d'intégration / non-régression (parcours complets + cas d'erreur) | 1,25 |
| Couverture des cas sécurité (CSRF, injections, accès non autorisés) | 0,75 |

**Minimal exigé : 1,5/3** (sinon la validation de la partie technique n'est pas acquise).

## 4. CI / GitHub Actions — 1,5 pt

| Critère | Pts |
|---------|-----|
| Pipeline CI lançant les tests à chaque push / pull request | 0,75 |
| Résultat concluant et **vert** sur la branche personnelle (build + tests, idéalement coverage) | 0,75 |

## 5. Docker & mise en place — 1,5 pt

| Critère | Pts |
|---------|-----|
| Application conteneurisée (Dockerfile(s) propres, bonnes pratiques) | 0,5 |
| Orchestration `docker-compose` (app + Redis/MongoDB, healthchecks) | 0,5 |
| Simplicité de lancement et de test (documenté, fonctionnel) | 0,5 |

## 6. Versioning Git — 1 pt

| Critère | Pts |
|---------|-----|
| Commits réguliers, clairs, petits et cohérents (tout au long du projet) | 0,5 |
| Branche personnelle propre, sans casse des branches des autres étudiants | 0,5 |

## 7. Documentation — 1 pt

| Critère | Pts |
|---------|-----|
| README clair et complet : fonctionnement, architecture, sécurité, mise en place, tests | 1 |

## 8. Qualité & clarté du code (jugée sur la branche) — 2 pts

| Critère | Pts |
|---------|-----|
| Architecture claire et compréhensible (modules, séparation des responsabilités) | 0,75 |
| Code lisible, nommage explicite, sans logique obscure | 0,75 |
| Choix techniques et de sécurité justifiés dans le README | 0,5 |

---

## Seuil de validation

- **Note globale ≥ 12/20** ;
- **et** au moins **2/5 en Sécurité** ;
- **et** au moins **1,5/3 en Tests**.

## Pénalités (malus sur la note globale)

| Manquement | Malus |
|------------|-------|
| Absence de chiffrement de bout en bout (texte clair en base) | **−2 pts** |
| Absence de protection CSRF, ou vulnérabilité injectable démontrée | **−2 pts** |
| Branche d'un autre étudiant cassée (force-push, réécriture, suppression) | **−2 pts** |
| Secret (token, clé, .env…) committé dans le dépôt | **−1 pt** |
| CI absente ou rouge sur la branche rendue | **−1 pt** |
| Absence de dockerisation | **−1 pt** |
| README inexistant ou incompréhensible | **−1 pt** |
| Historique en un seul énorme commit / commits illisibles | **−0,5 pt** |