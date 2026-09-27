# Sécurité

## Menaces couvertes

| Menace | Mesure | Où |
|--------|--------|-----|
| Mot de passe en clair en base | scrypt, sel aléatoire par compte | `app/security/passwords.py` |
| Vol de session par cookie | cookie `httpOnly`, `SameSite`, `Secure` en production | `app/security/sessions.py` |
| Requête forgée cross-site | double soumission CSRF, liée à la session | `app/security/csrf.py` |
| Injection SQL / NoSQL | pas de SQL ; pseudo validé par motif, identifiants jamais interpolés | `app/repositories/users.py`, `app/schemas.py` |
| XSS stocké ou réfléchi | rendu `textContent` uniquement, CSP stricte, échappement serveur | `frontend/js/dom.js`, `app/security/headers.py` |
| Clicjacking | `X-Frame-Options: DENY`, `frame-ancestors 'none'` | `app/security/headers.py` |
| Brute force sur les comptes | compteur Redis par IP, fenêtre glissante | `app/security/ratelimit.py` |
| Énumération de comptes | message d'erreur unique, hachage exécuté même si l'utilisateur n'existe pas | `app/api/auth.py` |
| Vol de session par WebSocket | vérification de l'origine, authentification par cookie | `app/ws.py` |
| Fuite d'un message en clair | chiffrement côté client, aucun champ texte en API | `frontend/js/crypto.js`, `app/schemas_chat.py` |
| Écrasement d'une clé de canal | écriture du slot d'un tiers réservée aux modérateurs | `app/api/keys.py` |
| Divulgation d'existence | 404 et non 403 sur salon, canal et clé publique | `app/api/deps.py` |
| Déni de service par messages | limitation par compte, taille d'enveloppe bornée | `app/api/messages.py`, `app/ws.py` |

## Mots de passe

`hashlib.scrypt` avec `n=2^14, r=8, p=1`, sel de 16 octets par compte. Le format
stocké est `scrypt$n$r$p$sel$empreinte`. La vérification utilise
`hmac.compare_digest` et renvoie `False` sur toute chaîne malformée, sans lever.

La connexion hache systématiquement, même quand le compte n'existe pas, avec
une empreinte factice : la réponse ne distingue pas « compte absent » de « mot de
passe faux ».

## Sessions

Jeton opaque de 256 bits (`secrets.token_urlsafe`), stocké côté serveur dans
Redis avec une durée de vie de 7 jours. Le cookie ne contient rien d'exploitable
et ne peut pas être forgé. La déconnexion supprime l'entrée Redis.

## CSRF

Toute mutation exige un jeton que l'attaquant ne peut pas lire :

- `GET /auth/csrf` pose un cookie `csrf_token` **non** `httpOnly` ;
- le client le renvoie dans l'en-tête `X-CSRF-Token` ;
- le serveur compare cookie et en-tête à temps constant, puis vérifie que le
  jeton existe en Redis.

Une fois la session établie, le jeton est indexé par session : un jeton obtenu
avant la connexion ne fonctionne plus après.

## En-têtes

`X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`,
`Permissions-Policy`, `Cross-Origin-Opener-Policy`,
`X-Permitted-Cross-Domain-Policies` et une CSP sans `unsafe-inline` ni
`unsafe-eval`. `Strict-Transport-Security` s'ajoute en HTTPS.

## Validation des entrées

`ConfigDict(extra="forbid")` sur tous les schémas : un champ inconnu est refusé
plutôt que silencieusement ignoré. Les longueurs et les motifs sont contraints par
type (`StringConstraints`), pas par une vérification manuelle dispersée.

C'est ce qui rend le chiffrement vérifiable : le schéma de message ne définit que
`ciphertext`, `iv` et `key_version`. Ajouter `text` est un `422`.

## Limites connues

- Le gestionnaire WebSocket est en mémoire : un déploiement multi-workers
  diffuserait seulement vers les connexions du processus local.
- Les clés de canal ne sont pas révoquées lorsqu'un membre quitte un salon privé.
- Pas de vérification de signatures : l'intégrité est assurée par le tag
  AES-GCM, pas par une identité cryptographique.
- La rétention est un nettoyage physique, sans journalisation.
