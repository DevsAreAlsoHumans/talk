# ENONCÉ DE L'EXAMEN — Application de chat chiffré de bout en bout

<table>
<tr><th>Dépôt de travail</th><td>https://github.com/DevsAreAlsoHumans/talk</td></tr>
<tr><th>Modalité</th><td>Travail <b>individuel</b> — chaque étudiant sur <b>sa propre branche</b></td></tr>
<tr><th>Rendu</th><td>Branche personnelle poussée sur le dépôt, CI verte, README à jour</td></tr>
<tr><th>Barème</th><td><b>100 points</b> — seuil de validation : 60/100 (détails en fin de document)</td></tr>
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
- **Compréhension** : le code livré doit être **lisible, nommé clairement, sans logique obscure** — chaque étudiant doit être capable de **l'expliquer** (voir grille).

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

**Total : 100 points** — Seuil de validation : **60/100**.

## 1. Fonctionnalités — 25 pts

| Critère | Pts |
|---------|-----|
| Authentification complète (inscription, connexion, déconnexion, sessions) | 5 |
| Salons / canaux (création, liste, gestion des membres) | 5 |
| Chiffrement de bout en bout des messages (envoi/réception) | 10 |
| Expérience proche de Discord, frontend vanilla fonctionnel et utilisable | 5 |

## 2. Sécurité — security by design — 25 pts

| Critère | Pts |
|---------|-----|
| Protection CSRF effective sur toutes les mutations + vérification d'origine | 5 |
| Anti-injection SQL et NoSQL | 5 |
| Hachage des mots de passe robuste (Argon2/bcrypt) | 3 |
| E2E correctement implémenté : jamais de texte clair ni de clé de déchiffrement stockés côté serveur | 5 |
| Validation stricte des entrées + anti-XSS | 3 |
| Headers de sécurité, sessions sécurisées, gestion des secrets | 4 |

## 3. Tests — 20 pts

| Critère | Pts |
|---------|-----|
| Tests unitaires (chiffrement, sécurité, logique métier) | 8 |
| Tests d'intégration / non-régression (parcours complets + cas d'erreur) | 8 |
| Couverture des cas sécurité (CSRF, injections, accès non autorisés) | 4 |

**Minimal exigé : 10/20** (sinon la validation de la partie technique n'est pas acquise).

## 4. CI / GitHub Actions — 10 pts

| Critère | Pts |
|---------|-----|
| Pipeline CI lançant les tests à chaque push / pull request | 5 |
| Résultat concluant et **vert** sur la branche personnelle (build + tests, idéalement coverage) | 5 |

## 5. Docker & mise en place — 10 pts

| Critère | Pts |
|---------|-----|
| Application conteneurisée (Dockerfile(s) propres, bonnes pratiques) | 4 |
| Orchestration `docker-compose` (app + Redis/MongoDB, healthchecks) | 4 |
| Simplicité de lancement et de test (documenté, fonctionnel) | 2 |

## 6. Versioning Git — 5 pts

| Critère | Pts |
|---------|-----|
| Commits réguliers, clairs, petits et cohérents (tout au long du projet) | 3 |
| Branche personnelle propre, sans casse des branches des autres étudiants | 2 |

## 7. Documentation — 5 pts

| Critère | Pts |
|---------|-----|
| README clair et complet : fonctionnement, architecture, sécurité, mise en place, tests | 5 |

## 8. Présentation / soutenance — 20 pts

| Critère | Pts |
|---------|-----|
| Compréhension du code (architecture, sécurité, chiffrement) **à minima** | 10 |
| Justification des choix techniques et de sécurité | 5 |
| Démonstration de fonctionnement (app lancée, tests verts, CI verte) | 5 |

---

## Seuil de validation

- **Note globale ≥ 60/100** ;
- **et** au moins **10/25 en Sécurité** ;
- **et** au moins **10/20 en Tests**.

## Pénalités (malus sur la note globale)

| Manquement | Malus |
|------------|-------|
| Absence de chiffrement de bout en bout (texte clair en base) | **−10 pts** |
| Absence de protection CSRF, ou vulnérabilité injectable démontrée | **−10 pts** |
| Branche d'un autre étudiant cassée (force-push, réécriture, suppression) | **−10 pts** |
| CI absente ou rouge sur la branche rendue | **−5 pts** |
| Absence de dockerisation | **−5 pts** |
| README inexistant ou incompréhensible | **−5 pts** |
| Historique en un seul énorme commit / commits illisibles | **−3 pts** |
| Secret (token, clé, .env…) committé dans le dépôt | **−5 pts** |