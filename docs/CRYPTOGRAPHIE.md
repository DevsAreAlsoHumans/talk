# Chiffrement de bout en bout

Tout le chiffrement se fait dans le navigateur, avec l'API Web Crypto. Le
serveur ne détient aucun secret capable d'ouvrir un message.

## Vue d'ensemble

```
compte A                          serveur                        compte B
   │                                │                                │
   │ clé ECDH P-256 (privée locale)│                                │
   │── PUT /keys ─────────────────►│ clé publique A                 │
   │                                │◄── GET /keys/<A> ──────────────│
   │                                │                                │
   │ tire une clé de canal K (256 bits, aléatoire)                  │
   │── chiffre K pour B ───────────►│ store {wrapped, from: A}       │
   │                                │◄── GET /channels/{c}/key ─────│
   │ déchiffre K avec (privA, pubB)│                                │
   │── AES-GCM(texte) ─────────────►│ ne voit que du base64         │
   │                                │── AES-GCM(déchiffrement) ────►│
```

## Identité : ECDH P-256

Chaque compte possède une paire de clés ECDH sur la courbe NIST P-256.

- La clé privée est générée dans le navigateur, exportée en JWK et rangée dans
  `localStorage`. Elle n'est jamais transmise.
- La clé publique, exportée brute puis encodée en base64url, est publiée par
  `PUT /keys`. Le serveur la stocke et incrémente sa version.

Une rotation est possible : republier une clé bumps sa version, ce qui permet
d'invalider les enveloppes chiffrées pour l'ancienne.

## Clé de canal : AES-256-GCM

Chaque canal possède une clé aléatoire de 256 bits. Elle ne quitte jamais le
navigateur sous forme claire.

Pour chaque membre disposant d'une clé publique, le créateur de la clé produit
une copie chiffrée :

1. secret partagé = `ECDH(privA, pubB)` ;
2. clé d'empaquetage = `HKDF-SHA256(secret, salt=0, info="talk-channel-v1")` ;
3. `wrapped = AES-GCM(clé de canal, iv=12 octets aléatoires)`.

Chaque copie est déposée dans le slot du **destinataire** et porte l'identifiant
de l'expéditeur, champ `from_user_id`. C'est ce champ qui permet au destinataire
de savoir avec quelle clé publique il doit dériver le secret.

Le déchiffrement est le même calcul vu par l'autre partie :
`ECDH(privB, pubA)` redonne le même secret, donc la même clé.

## Messages : AES-GCM

```
{ ciphertext = AES-GCM(clé de canal, nonce 12 octets, texte),
  iv         = nonce,
  key_version = version de la clé de canal utilisée }
```

AES-GCM est un chiffrement authentifié : le tag d'authentification garantit à la
fois la confidentialité et l'intégrité. Une altération du texte chiffré ou du
nonce fait échouer le déchiffrement, sans clé de signature séparée.

## Ce que le serveur ne peut pas faire

| Le serveur veut… | Pourquoi c'est impossible |
|------------------|---------------------------|
| Lire un message | Il ne possède que `ciphertext` et `iv` ; la clé de canal n'existe que chiffrée par membre |
| Retrouver la clé de canal | Chaque copie est sous une clé dérivée d'un ECDH dont il ignore la moitié privée |
| Usurper un compte | Il n'a pas la clé privée, et AES-GCM authentifie le contenu |
| Décoder le contenu en base64 | Le base64 est un transport, pas un chiffrement |

## Distribution d'un nouveau membre

1. Un modérateur invite le membre dans le salon.
2. Le modérateur appelle `GET /channels/{c}/keys` pour vérifier les slots
   existants, et `GET /keys/<id>` pour lire la clé publique du nouvel arrivant.
3. Il chiffre la clé de canal qu'il détient pour le nouveau membre, puis dépose
   la copie via `PUT /channels/{c}/key` en précisant `user_id`.

**Pourquoi cette restriction ?** Si n'importe quel membre pouvait écrire le slot
d'un autre, il y déposerait une clé qu'il connaît. La victime déchiffrerait
alors avec une clé imposée par l'attaquant, qui pourrait lire ses messages
suivants. L'écriture du slot d'un tiers est donc réservée aux modérateurs du
salon, et le serveur refuse toute cible qui n'est pas membre.

## Format d'encodage

Tout est en base64url sans remplissage (`-` et `_` au lieu de `+` et `/`), ce qui
reste compatible avec le motif de validation du serveur :
`^[A-Za-z0-9+/_-]+={0,2}$`. Un nonce de 12 octets est vérifié côté serveur :
c'est la taille imposée par la norme GCM, pas une convention arbitraire.

## Limites

- Pas de signalement ni de révocation de clé : un membre exclu d'un salon privé
  conserve les enveloppes déjà reçues.
- Pas de forward secrecy : la clé de canal ayant été compromise, tous les
  messages du canal sont déchiffrables.
- L'empreinte de clé affichée dans l'interface est une commodité de
  comparaison visuelle, pas une vérification formelle.
