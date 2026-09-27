# Référence de l'API

Base : `/`. Toutes les réponses sont en JSON. La documentation interactive est
disponible sur `/docs` en mode développement.

## Authentification

Toute mutation exige l'en-tête `X-CSRF-Token`, dont la valeur est celle du
cookie `csrf_token`. Appeler `GET /auth/csrf` une fois au démarrage.

| Méthode | Chemin | Corps | Retour |
|---------|--------|-------|--------|
| `GET` | `/auth/csrf` | — | `{ csrf_token }` + cookie |
| `POST` | `/auth/register` | `{ username, password }` | `201` `{ user, csrf_token }` |
| `POST` | `/auth/login` | `{ username, password }` | `200` `{ user, csrf_token }` |
| `POST` | `/auth/logout` | — | `200` `{ detail }` |
| `GET` | `/auth/me` | — | `200` `{ id, username, created_at }` |

`username` : 3 à 32 caractères, minuscules, chiffres et tirets bas.
`password` : 12 à 128 caractères. Toute clé supplémentaire est refusée (`422`).

## Salons et canaux

| Méthode | Chemin | Droits | Rôle |
|---------|--------|--------|------|
| `POST` | `/salons` | authentifié | Crée le salon, l'appelant devient `owner` |
| `GET` | `/salons` | authentifié | Salons dont l'appelant est membre |
| `GET` | `/salons/{id}` | membre | Détail et rôle |
| `PATCH` | `/salons/{id}` | modérateur | Renomme |
| `DELETE` | `/salons/{id}` | propriétaire | Supprime salon, canaux et clés |
| `GET` | `/salons/{id}/members` | membre | Liste avec rôles |
| `POST` | `/salons/{id}/members` | modérateur | Invite par pseudo |
| `PATCH` | `/salons/{id}/members/{user_id}` | propriétaire | Change le rôle (`moderator`/`member`) |
| `DELETE` | `/salons/{id}/members/{user_id}` | modérateur | Retire (le propriétaire est protégé) |
| `POST` | `/salons/{id}/channels` | modérateur | Crée un canal `text` ou `private` |
| `GET` | `/salons/{id}/channels` | membre | Canaux visibles |
| `GET` | `/channels/{id}` | membre | Détail |
| `PATCH` | `/channels/{id}` | modérateur | Renomme ou change de sujet |
| `DELETE` | `/channels/{id}` | modérateur | Supprime (le dernier est protégé) |
| `GET` | `/channels/{id}/members` | membre | Accès d'un canal privé |
| `POST` | `/channels/{id}/members` | modérateur | Autorise sur un canal privé |
| `DELETE` | `/channels/{id}/members/{user_id}` | modérateur | Révoque l'accès |

Un salon non accessible renvoie `404`, jamais `403` : la réponse ne révèle pas
l'existence de la ressource.

## Clés

| Méthode | Chemin | Droits | Rôle |
|---------|--------|--------|------|
| `PUT` | `/keys` | authentifié | Publie la clé publique, rotation comprise |
| `GET` | `/keys/{user_id}` | salon partagé | Clé publique d'un collègue |
| `PUT` | `/channels/{id}/key` | membre (tiers : modérateur) | Dépose une clé de canal chiffrée |
| `GET` | `/channels/{id}/key` | membre | Sa propre copie |
| `GET` | `/channels/{id}/keys` | membre | Copies de tous les membres |

```jsonc
// PUT /keys
{ "public_key": "base64url" }

// PUT /channels/{id}/key — sans user_id, on dépose pour soi
{ "wrapped_key": "base64url", "user_id": "hex facultatif" }

// GET /channels/{id}/key
{ "version": 1, "wrapped_key": "base64url", "from_user_id": "hex" }
```

## Messages

| Méthode | Chemin | Rôle |
|---------|--------|------|
| `POST` | `/channels/{id}/messages` | Envoie une enveloppe chiffrée |
| `GET` | `/channels/{id}/messages?before=&limit=` | Historique, du plus ancien au plus récent |
| `GET` | `/channels/{id}/messages/poll?after=&limit=` | Repli temps réel, incrémental |

```jsonc
// Requête d'envoi — il n'existe aucun champ texte
{ "ciphertext": "base64url", "iv": "12 octets en base64url", "key_version": 1 }
```

```jsonc
// Réponse
{ "id": "hex", "channel_id": "hex", "sender_id": "hex",
  "ciphertext": "...", "iv": "...", "key_version": 1,
  "sent_at": "2026-01-01T12:00:00+00:00", "seq": 42 }
```

`GET /channels/{id}/messages/poll?after=42` renvoie les messages de séquence
supérieure à 42. Une liste vide signifie « rien de nouveau », ce qui rend le
repli par polling très peu coûteux.

## WebSocket

`ws://<hôte>/ws/channels/{channel_id}`

Authentification par le cookie de session, origine vérifiée. Trames reçues :

```jsonc
{ "type": "ready", "channel_id": "hex", "user_id": "hex", "latest_seq": 42 }
{ "type": "message", "message": { /* enveloppe */ } }
{ "type": "error", "code": "invalid_envelope", "detail": "…" }
```

Codes d'erreur : `invalid_envelope`, `too_large`, `rate_limited`. Code de
fermeture `1008` si la session est absente, l'origine étrangère ou le canal
inaccessible.

## Codes d'erreur

| Code | Signification |
|------|---------------|
| `401` | Session absente ou expirée |
| `403` | Jeton CSRF invalide, droits insuffisants, origine rejetée |
| `404` | Ressource inexistante **ou** non accessible |
| `409` | Conflit : pseudo pris, nom de canal déjà utilisé |
| `422` | Validation d'entrée échouée |
| `429` | Limitation dépassée, en-tête `Retry-After` fourni |
