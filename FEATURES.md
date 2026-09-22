# FEATURES.md — Plan d'évolution « Télécord » (ex-talk) v2, v3, v3.1 & v4 (branche `etudiant/barraud-teddy`)

> Document de traçabilité des itérations 2, 3, 3.1 et 4 : nouvelles fonctionnalités,
> contrats API, décisions techniques. Chaque évolution est **rétro-compatible**
> avec le contrat v1 (rien ne casse : les **161 tests**, dont les 118 initiaux,
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

---

## 6. Itération v3 — confort Discord : regroupement, images E2E, menu Paramètres

### 6.1 Direction produit

| Besoin utilisateur | Fonctionnalité livrée | Bloc de la grille |
|---|---|---|
| « Les avatars se répètent pour mes messages successifs » | **Groupement visuel corrigé** : l'avatar et le pseudo ne s'affichent que sur le **premier** message d'une série consécutive du même auteur (texte resté aligné) | Frontend |
| « J'aimerais partager des images/GIF » | **Envoi et affichage d'images/GIF** chiffrés de bout en bout (AES-256-GCM avec la clé du salon ; le serveur ne stocke que `nonce`+`ciphertext` ; rendu côté client en `data:` URL) | Fonctionnalités · Sécurité |
| « Le coin réglages ne sert qu'à changer le mot de passe » | **Menu « Paramètres »** complet : profil (avatar + pseudo), copie d'identifiant, changement de mot de passe, déconnexion | Frontend · Fonctionnalités |

### 6.2 Contrat d'API v3 (ajouts — rien d'existant ne change)

| Méthode | Route | Rôle | CSRF |
|---|---|---|---|
| POST | `/api/rooms/{id}/attachments` | `{kind: "image", mime?, nonce, ciphertext}` → 201 `{"message": ...}`. `kind` **doit** être `"image"` ; `mime` optionnel (≤ 64 car., préfixe `image/` obligatoire) ; `ciphertext` b64 strict ≤ `MAX_ATTACHMENT_B64` = 6 000 000 (≈ 4,5 Mo décodés ; le client plafonne à **4 Mo**). Rôles identiques à `POST /messages` (auth, membre). Événement WS `new_message` diffusé | oui |

**Champs `kind`/`mime` sur chaque message** (GET `/messages`, WS `new_message`) :
- `kind`: `"text"` (défaut) ou `"image"` — `mime`: `null` (défaut) ou `image/*`.
- **Rétro-compatibilité totale** : anciens messages sans ces champs → `kind="text"`, `mime=null` (défauts servis à l'hydratation) ; réponse `Message` inchangée pour le texte.
- La suppression (`DELETE /messages/{id}`), la pagination et la déduplication ne changent pas : une image est un message comme un autre.

### 6.3 Décisions techniques v3

1. **Le serveur ne voit jamais l'image** : seul `{nonce, ciphertext}` (base64) + les
   métadonnées `kind`/`mime` transitent et sont stockés. Le déchiffrement a lieu dans le
   navigateur (WebCrypto `decryptBytes`), le rendu utilise une `data:` URL — autorisée par
   la CSP `img-src 'self' data:`.
2. **Regroupement** : la logique JS (`message--grouped` / `message--group-start`) existait mais
   le sélecteur CSS ciblait `.message-avatar`, classe jamais posée (réelle : `.avatar--message`).
   Sélecteur corrigé + `visibility: hidden` : l'avatar est masqué **sans perdre sa colonne**,
   le texte des messages groupés reste aligné sur le premier (façon Discord).
3. **Menu Paramètres** : remplace la paire de boutons (clé / déconnexion) par un menu
   (`ui.openMenu` étendu avec `separator` et `header`), composé d'un en-tête profil non
   cliquable, « Copier mon identifiant », « Changer le mot de passe » (réutilise
   `openPasswordModal()` exposée par auth.js) et « Se déconnecter » (comportement conservé).
4. **Client image** : limite 4 Mo binaires (marge sous la limite serveur b64), types `image/*`
   acceptés (PNG/JPEG/GIF/WebP), re-sélection du même fichier possible (reset de l'input),
   anti-doublon identique à l'envoi texte (course WS gérée via `seenIds`).

### 6.4 Tests ajoutés (v3)

`tests/integration/test_attachments.py` — **7 nouveaux tests** : image chiffrée créée et
présente dans l'historique ; image sans `mime` (rien stocké ni renvoyé) ; rétro-compat
message texte (`kind="text"`, shape v1 conservée) ; non-membre → 403 ; `ciphertext` > limite
→ 422 ; `kind`/`mime` invalides ou champ inconnu → 422 (`extra="forbid"`) ; diffusion WS
`new_message` avec `kind="image"` chez un abonné.

- **Aucun test v1 modifié** : aucun n'assere un set exact de clés d'un message.
- Le nombre total de tests passe de **142** à **149** (7 nouveaux).

### 6.5 Smoke test réalisé sur le serveur réel (uvicorn + fakeredis)

Register → salon → clé enveloppée (RSA-OAEP) → `POST /attachments` (PNG simulé chiffré en
AES-256-GCM) → 201 `kind="image"`/`mime="image/png"` → présent dans `GET /messages` →
**déchiffrement E2E restituant les octets d'origine** → non-membre → 403 → message texte
`kind="text"`, `mime=null`. Les trois premières tentatives de script ont échoué pour des
raisons de **script** (Origin `testserver` du helper vs serveur réel ; nonce dupliqué), jamais
le produit.

### 6.6 Correctifs v3.1 (retours utilisateur)

| Problème signalé | Cause | Correctif |
|---|---|---|
| « Les messages groupés (2ᵉ, 3ᵉ…) sont trop grands » | L'avatar groupé était masqué en `visibility: hidden` mais **restait dans le flux flex** (38×38) → chaque ligne groupée faisait au minimum 38 px | `display: none` + `padding-left: calc(38px + 0.85rem)` sur `.message-body` : la ligne épouse la hauteur du texte et reste alignée sous le corps du premier message |
| « Après rechargement de la page, plus accès au salon » | Les clés de salon ne vivent qu'en mémoire (`crypto.roomKeys`) et aucun chemin ne les restaurait ; le serveur n'exposait que l'**écriture** (`POST /keys`) | Nouvel endpoint de lecture + restauration automatique (voir ci-dessous) |

**Nouvel endpoint v3.1 — restauration des clés :**

| Méthode | Route | Rôle | CSRF |
|---|---|---|---|
| GET | `/api/rooms/{id}/keys` | Renvoie **la copie enveloppée du membre courant** : `{"room_id": "<id>", "wrapped_key": "<base64>"\|null}` — `null` si aucune copie à son nom ; 403 non-membre, 404 salon inconnu. La copie est chiffrée RSA-OAEP pour sa clé publique : même vue par un autre membre, elle resterait illisible | non |

- **Frontend** : `rooms.restoreRoomKeys()` (appelé après `/api/me` au boot) récupère les copies
  enveloppées de **tous** les salons et les dé-chiffre avec la clé privée locale ; restauration
  opportuniste dans `selectRoom` si un salon est ouvert avant la fin du balayage. Le premier
  salon ouvert s'affiche donc **directement déchiffré** après un F5.
- Comportements conservés : membre sans copie à son nom → messages « verrouillés » (un autre
  membre doit partager via « Actualiser clés » ou l'événement `room_key`) ; `refreshCurrentRoomKeys`
  (ré-enveloppement *pour les autres*) inchangé.

**Tests v3.1** — `tests/integration/test_room_keys.py` (3 nouveaux) : récupération exacte de sa
copie enveloppée ; `null` avant partage puis **déchiffrement bout-en-bout** après partage (unwrap
+ relecture du message = preuve de la restauration) ; non-membre → 403. Total : **152 tests**.
Smoke test sur le serveur réel : nouvelle session (simulation de rechargement) → `GET /keys` →
`unwrap` → clé identique à celle du salon → message chiffré relu à l'identique.

---

## 7. Itération 4 (v4) — Markdown, édition de messages, profils « Discord-like », marque « Télécord »

### 7.1 Direction produit

| Besoin utilisateur | Fonctionnalité livrée | Bloc de la grille |
|---|---|---|
| « Je veux mettre en forme mes messages (Discord) » | **Rendu Markdown** dans le fil : gras, italique, souligné, barré, code inline/blocs, citations, titres, listes, liens `http(s)` seuls | Fonctionnalités · Sécurité |
| « J'ai écrit une bêtise, je veux corriger mon message » | **Édition d'un message** par son auteur (re-chiffré de bout en bout, badge « · modifié », diffusion temps réel) | Fonctionnalités |
| « Je veux un profil à la Discord » | **Fiche profil** (avatar, `display_name`, `@username`, id copiable, « À propos ») + **personnalisation** (`display_name`, `about`) depuis le menu Paramètres | Fonctionnalités |
| « talk, c'est pas très fun » | **Rebranding « Télécord »** : nom affiché sur le site (page d'accueil, onglet, sidebar) | — |

### 7.2 Contrat d'API v4 (ajouts — rien d'existant ne change)

| Méthode | Route | Rôle | CSRF |
|---|---|---|---|
| PATCH | `/api/rooms/{room_id}/messages/{message_id}` | Éditer un message : `{nonce, ciphertext}` **sur le même modèle que `POST /messages`** (nouvelle version chiffrée du texte). Auteur uniquement (403 sinon) ; 404 si message inconnu ou d'un autre salon ; `created_at`/`seq`/`kind`/`mime` **préservés** ; le hash gagne `edited: 1`. Réponse 200 `{"message": {...}}` (avec `edited: true`) + événement WS **`message_updated`** (payload = message complet) | oui |
| PATCH | `/api/me` | Profil public : `{display_name?: str\|null (≤ 32), about?: str\|null (≤ 500)}`, `extra="forbid"`, strip, **vide → `null`**, **champ omis → inchangé** (`model_fields_set`). Réponse 200 `{"user": <to_public>}` | oui |

**Évolutions de forme (additives, rétro-compatibles) :**
- `Message` gagne `edited: bool` (`false` par défaut ; les anciens messages hydratés valent `false`),
  présent dans `GET /messages` et les événements WS.
- `UserPublic` / `MemberPublic` / `/api/me` / `/api/users/{username}` / `/members` gagnent
  `display_name: str\|null` et `about: str\|null` — profil d'**identité publique** (comme le
  pseudo : **non chiffré**, volontairement).

### 7.3 Décisions techniques v4

1. **Édition = re-chiffrement** : le client déchiffre le message (clé du salon), modifie le
   texte, puis le **re-chiffre en AES-256-GCM** (nouveau nonce) — le serveur ne reçoit, comme
   toujours, que `{nonce, ciphertext}`. Rétro-compat totale : la suppression, la pagination, la
   déduplication et le regroupement ne changent pas (même `id`/`seq`/`created_at`).
2. **`message_updated`** : la mise à jour est remplacée **par `id`** dans le fil (pas de
   réordonnancement) ; l'éditeur local ferme sa session d'édition après le 200 ; l'événement WS
   met à jour les autres clients de façon idempotente.
3. **Markdown sandboxé** : parseur **DOM pur** (`markdown.js`) — jamais d'`innerHTML` avec du
   texte utilisateur, blocs `fences`/citations/titres/listes + inline `***`/`**`/`*`/`__`/`~~`/
   `` ` ``/`[label](url)`/échappement `\x`. **Seuls les liens `http:`/`https:` deviennent des
   `<a>`** (href par propriété ; `javascript:`/`data:`/`vbscript:` et le HTML brut restent du
   texte littéral). Validé par 20 cas unitaires + un fuzz de 5 000 entrées hostiles (0 exception,
   0 href dangereux).
4. **Profil** : sur clic d'un avatar (message) ou d'une ligne de membre, ou « Mon profil » du
   menu Paramètres → modale popout `profile.js` ; composants DOM, aucune ressource externe.
   L'avatar (lette + teinte) reste dérivé du **username** pour rester stable ; le `display_name`
   n'est que cosmétique (le login reste l'identifiant unique).
5. **Rebranding** : la marque affichée devient **« Télécord »** (titre, logo d'accueil,
   `BASE_TITLE`, en-tête CSS). Les identifiants internes du produit (`talk.*` du localStorage,
   nom du paquet, services Docker) sont **conservés** : renommer les clés localStorage aurait
   rendu illisibles les clés privées existantes des utilisateurs.

### 7.4 Tests ajoutés (v4)

`tests/integration/test_edit_message.py` — **5 nouveaux tests** : édition par l'auteur avec
preuve E2E (nouveau ciphertext dans `GET /messages`, `edited: true`, **déchiffrement du nouveau
texte**, `created_at`/`seq` strictement inchangés) ; non-auteur → 403 ; message inconnu ou d'un
autre salon → 404 ; corps invalide (ciphertext trop long, champ inconnu) → 422 ; diffusion WS
`message_updated` chez un abonné.

`tests/integration/test_profile.py` — **4 nouveaux tests** : mise à jour de son propre profil
reflétée sur `/api/me`, `/api/users/{username}` et `/api/rooms/{id}/members` ; validations
(longueurs > 32/500 → 422, champ inconnu → 422, vide → `null`, trim) ; non authentifié → 401 ;
comptes neufs → `display_name`/`about` à `null`.

- **Aucun test v1 cassé** : seules deux assertions de `tests/unit/test_repository.py` et des
  shapes dans `test_auth_flow.py`/`test_rooms_flow.py` ont été **adaptées** (forme publique
  désormais additive).
- Le nombre total de tests passe de **152** à **161** (9 nouveaux).

### 7.5 Smoke test v4 sur le serveur réel (uvicorn + fakeredis)

Rebranding (« Télécord » servi sur `/`) → register → création de salon + enveloppement de clé →
`GET /keys` restitue la copie (dé-wrappe à l'identique) → envoi chiffré → **PATCH d'édition**
(`edited: true`, `created_at`/`seq` intacts, nouveau texte re-déchiffrable) → édition par un
non-auteur → 403 → `PATCH /api/me` (`display_name`/`about` visibles sur `/api/me`,
`/api/users/{username}`, `/members`) → validations 422 (longueurs, champ inconnu) et effacement
par `""` → `null`.