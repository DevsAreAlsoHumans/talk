# FEATURES.md — Plan d'évolution « talk » v2 (branche `etudiant/barraud-teddy`)

> Document de traçabilité de la deuxième itération : nouvelles fonctionnalités,
> contract API, décisions techniques. Chaque évolution est **rétro-compatible**
> avec le contrat v1 (rien ne casse : les **142 tests**, dont les 118 initiaux,
> restent verts).

---

## 1. Direction produit (pourquoi ces fonctionnalités)

L'application v1 couvrait le périmètre imposé par l'examen (auth, salons, E2E,
temps réel, docker). Cette itération améliore l'**expérience proche de Discord**
et la **robustesse quotidienne** :

| Besoin utilisateur | Fonctionnalité livrée | Bloc de la grille |
|---|---|---|
| « Qui est là / qui est en ligne ? » | **Présence en ligne** temps réel | Fonctionnalités · Frontend |
| « J'ai 3 messages en attente dans tel salon » | **Compteur de non-lus** par salon | Fonctionnalités · Frontend |
| « Je ne veux plus être dans ce salon » | **Quitter un salon** (clé enveloppée purgée, salon vide supprimé) | Fonctionnalités · Sécurité |
| « J'ai envoyé une bêtise » | **Suppression d'un message** par son auteur | Fonctionnalités |
| « Chattez avec des dizaines de messages » | **Pagination de l'historique** (`before`/`limit`) | Fonctionnalités |
| « Je veux changer de mot de passe » | **Changement de mot de passe** (ré-enveloppement local de la clé privée) | Fonctionnalités · Sécurité |
| Aspect visuel v1 trop sommaire | **Refonte design « Discord-like » moderne** (tokens CSS, transitions, accessibilité, responsive) | Frontend · Qualité |

---

## 2. Contrat d'API v2 (ajouts — tout ce qui existait reste identique)

| Méthode | Route | Rôle | CSRF |
|---|---|---|---|
| POST | `/api/rooms/{id}/leave` | Quitte un salon : retire le membre, **purgé sa copie de clé enveloppée** (`HDEL`), le désabonne du hub ; si c'était le dernier membre → **le salon est supprimé** (messages inclus) | oui |
| DELETE | `/api/rooms/{room_id}/messages/{message_id}` | Supprime un message (auteur uniquement, sinon 403). Les `seq` sont **conservés** (trous OK : `ZREVRANGEBYSCORE`/`ZRANGEBYSCORE` et dedup front par `id`). Événement `message_deleted` | oui |
| GET | `/api/rooms/{id}/messages` | **Enrichi** : `?before=<seq>` → page de `limit` messages antérieurs ; `?limit=<n>` seul → les `n` derniers ; `?after=` et l'absence de paramètres = comportement v1 | non |
| POST | `/api/auth/change-password` | `{old_password, new_password}` → vérifie `old_password` (Argon2), ré-hache et met à jour | oui |
| GET | `/api/rooms/{id}/members` | **Enrichi** : chaque membre porte désormais `online: bool` (champ additionnel, les champs existants sont inchangés) | non |

### Nouveaux événements WebSocket (le serveur reste l'unique émetteur)

| type | payload | moment |
|---|---|---|
| `presence` | `{user_id, online}` | passage 0→1 connexion, 1→0 déconnexion (compté par onglet) |
| `member_left` | `{room_id, member: {id, username}}` | après un `leave` |
| `message_deleted` | `{room_id, id, seq}` | après un DELETE |

Le serveur **ignore** toujours toute trame client autre que `subscribe`/`unsubscribe`.

---

## 3. Décisions techniques v2

1. **Présence** : compteur par utilisateur `presence:count:{user_id}` (INCR à
   l'accept WS, DECR au `finally`, suppression à zéro). Solide multi-onglets,
   observable dans Redis, aucune tâche de fond. L'état « en ligne » est calculé
   par `SISMEMBER`-like (`GET`/parse) dans `rooms.list_members`.
2. **Salon vide** : `remove_member` + purge (`room:{id}`, `:members`, `:keys`,
   `:messages`, `:seq`, `message:*` du feed) dans une pipeline — le salon
   disparaît réellement (`get_room` → None).
3. **Delete message** : `ZREM` + `DEL message:{id}`, le compteur `:seq` n'est
   **pas** décrémenté (les trous sont acceptés par le tri et la dédup).
4. **Pagination** : `ZREVRANGEBYSCORE` exclusif borné par `before`, liste
   inversée pour l'affichage croissant ; sans doublon avec `after` (priorité
   `before` > `after` > `limit` > tout).
5. **Change-password** : vérification `old_password` via Argon2 avant mise à
   jour ; côté client la clé privée JWK est **ré-chiffrée** (PBKDF2+AES-GCM)
   avec la nouvelle clé dérivée avant `localStorage.setItem`.

### Impacts mesurés sur les tests v1
- `tests/unit/test_repository.py::test_room_members_public_fields` : le set
  attendu gagne `online` (assertion légitimement mise à jour).
- Aucun autre test v1 modifié : les nouveaux paramètres (`before`/`limit`) ont
  des défauts qui reproduisent exactement le comportement v1.
- Le nombre total de tests passe de **118** à **142** : 24 nouveaux tests
  (`test_presence_flow.py`, `test_leave_room.py`, `test_delete_message.py`,
  `test_pagination.py`, `test_change_password.py`) — plus le correctif de
  scopage `room_id` du `DELETE /messages/{id}` (non-régression incluse dans
  `test_delete_message.py`).

---

## 4. Frontend — design system v2 (anti-vibe-code)

- **Tokens de design** documentés en tête de `frontend/css/style.css` :
  palette, espacements, rayons, ombres, durées de transition, `color-scheme:
  dark`. Aucun inline style (CSP `style-src 'self'`).
- **Layout** calqué sur Discord : sidebar sombre (header user + actions,
  groupe « Salons », items avec `#` et badge non-lus), colonne principale avec
  en-tête de salon, fil de messages **avec avatars** et regroupement visuel,
  panneau membres à droite avec **pastille de présence** (en ligne d'abord),
  zone de saisie « pill ».
- **Composants** : modales accessibles (focus, `aria`), dropdowns contextuels
  (message : supprimer ; salon : quitter), toasts animés, bouton « Charger des
  messages précédents », états vides soignés.
- **Accessibilité / performance** : `prefers-reduced-motion`, états `:focus-visible`,
  `aria-live` sur le fil, sélection propre du DOM (jamais d'`innerHTML`),
  transitions sur `transform`/`opacity` uniquement (pas de layout thrash).

---

## 5. Ordre d'exécution & responsabilités

| # | Tâche | Responsable | Dépend de |
|---|-------|-------------|-----------|
| 1 | Plan d'évolution (ce document) | Orchestrateur | — |
| 2 | Backend A : présence + leave (+ hub `attach_user`/`unsubscribe_user_room`, repo) + tests | Développeur Backend A | 1 |
| 3 | Backend B : delete message + pagination + tests | Développeur Backend B | 1 |
| 4 | Backend C : change-password + tests | Développeur Backend C | 1 |
| 5 | Frontend : design system + features (non-lus, présence, leave, delete, pagination, change-password) | Développeur Frontend | 2, 3, 4 |
| 6 | Revue QA : ruff, pytest complet, contrat E2E, cohérence DOM/JS, README | QA | 2, 3, 4, 5 |
| 7 | README à jour (nouvelles fonctionnalités + design + compteur de tests) | Doc | 5, 6 |
| 8 | Commits + push branche | Orchestrateur | 6, 7 |

**Règles** : uniquement sur `etudiant/barraud-teddy` ; ajouts rétro-compatibles
(un message échoué n'est pas un argument pour casser le contrat v1) ; chaque
feature livrée avec ses tests et sa mise à jour README.