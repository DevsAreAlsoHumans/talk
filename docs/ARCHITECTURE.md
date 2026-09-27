# Architecture

## Arborescence

```
app/
  main.py              création de l'application, middlewares, routeurs
  config.py            settings pydantic-settings (variables d'environnement)
  db.py                client Redis injectable (facilite les tests)
  schemas.py           schémas d'authentification, salons et canaux
  schemas_chat.py      schémas de messagerie et de clés (interdit le clair)
  web.py               service du frontend statique
  ws.py                WebSocket par canal, diffusion des enveloppes
  api/
    deps.py            session courante, garde CSRF, contrôle d'accès
    auth.py            inscription, connexion, déconnexion, session
    salons.py          salons, canaux, appartenance, rôles
    keys.py            échange de clés publiques et de clés de canal
    messages.py        envoi, historique, repli par polling
  repositories/        accès Redis, un module par agrégat
    users.py           comptes, index par pseudo
    salons.py          salons, canaux, rôles, clés de Redis
    keys.py            clés publiques, clés de canal
    messages.py        envelopes, journal paginé, rétention
  security/            modules de sécurité isolés et testables
    passwords.py       scrypt, sel par compte
    sessions.py        jetons opaques, cookies httpOnly
    csrf.py            double soumission, liée à la session
    ratelimit.py       compteur à fenêtre glissante
    headers.py         en-têtes de sécurité
    sanitize.py        normalisation des entrées
frontend/
  index.html, styles.css
  js/crypto.js         Web Crypto : ECDH, HKDF, AES-GCM
  js/api.js            client HTTP, jeton CSRF
  js/dom.js            construction DOM sans injection HTML
  js/state.js          état applicatif et cycle de vie des clés
  js/views/            salons, canaux, messages, temps réel
tests/                 pytest, fakeredis
```

## Choix structurants

**Redis comme base, pas comme cache.** Aucune donnée n'est recomputable : un
cache invaliderait l'historique. Le modèle est un ensemble de clés, de hashes et
d'ensembles ordonnés, chaque repository délimitant ses préfixes.

**Repositories séparés des routes.** Les routes valident les entrées et
autorisent ; les repositories ne connaissent que Redis. Ce découpage rend le
chiffrement testable sans HTTP et l'API testable sans base.

**Dépendances injectées.** Toutes les routes reçoivent leur client Redis par
`Depends(get_redis)`. Les tests remplacent la dépendance par `fakeredis` : aucun
conteneur n'est requis.

**Front sans build.** Pas de bundler, pas de dépendance npm, pas de CDN. Des
modules ES natifs et une CSP stricte (`script-src 'self'`) restent possibles.

## Flux d'un message

```
navigateur                      serveur (Redis)
    |  chiffrement AES-GCM local
    |  POST /channels/{id}/messages  --->  validation stricte de l'enveloppe
    |                                        stockage de {ciphertext, iv}
    |  <-- 201 + enveloppe             --->  diffusion WebSocket /ws/channels/{id}
    |  déchiffrement local
```

Le serveur valide la *forme* de l'enveloppe (base64, taille de nonce, absence
de champ `text`) et rien de plus : il n'a aucun moyen de lire le contenu.

## Temps réel

Deux mécanismes, un même payload.

1. **WebSocket** (`/ws/channels/{channel_id}`) : le canal principal. Une
   diffusion par salon, authentifiée par le cookie de session, avec vérification
   de l'origine.
2. **Polling court** (`/channels/{id}/messages/poll?after=<seq>`) : le repli
   automatique si le WebSocket se ferme. Le client rappelle l'endpoint toutes
   les 3 secondes avec la dernière séquence connue ; une réponse vide ne coûte
   qu'un aller-retour.

`GET /channels/{id}/messages` sert l'historique paginé vers le haut
(`before=<seq>`), indispensable au rechargement de la page.

## Rétention

Chaque canal conserve ses 500 dernières enveloppes (`MESSAGE_RETENTION`). Au-delà,
les plus anciennes sont retirées du journal trié et supprimées. Cette borne
limite la mémoire et évite qu'un salon devienne un stockage illimité.

## Portée connue

Le gestionnaire de connexions est en mémoire : il couvre un processus uvicorn.
Pour plusieurs workers, la diffusion doit passer par un Redis Pub/Sub. Ce point
est documenté dans `app/ws.py`.
