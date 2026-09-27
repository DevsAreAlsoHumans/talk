"""Validation des canaux, des enveloppes de clé et des messages chiffrés.

Aucune des valeurs décrites ici n'est secrète pour le serveur : ce sont des
ciphertexts, des enveloppes et des clés publiques. Elles sont néanmoins
validées strictement, pour quatre raisons :

* une valeur qui n'est pas une chaîne ne peut pas être interprétée comme un
  opérateur MongoDB (`{"$ne": null}`) ;
* des bornes de taille empêchent un membre de s'attribuer un stockage arbitraire ;
* le format du vecteur d'initialisation est vérifié avant écriture, afin qu'un
  client fautif ne rende pas son propre message indéchiffrable ;
* les membres `n` et `e` d'un JWK doivent porter leur encodage canonique, sans
  quoi une seule clé pourrait recevoir deux empreintes différentes (voir
  `_decode_base64url`).

Le serveur ne déchiffre rien : il valide des formes, jamais du contenu.
"""

from __future__ import annotations

import base64
import binascii
import re
from datetime import datetime
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.schemas import normalize_username

# 4 000 caractères côté client. Le pire cas en UTF-8 (caractères hors du plan
# multilingue de base) est de 4 octets par caractère, plus 16 octets de balise
# d'authentification, ce qui reste très en deçà de la limite serveur.
MAX_PLAINTEXT_LENGTH = 4000
MAX_CIPHERTEXT_BASE64 = 24000
MIN_CIPHERTEXT_BYTES = 17  # 1 octet utile au minimum + balise de 128 bits
IV_BYTES = 12  # taille recommandée par NIST SP 800-38D pour GCM

# Sortie de RSA-OAEP-2048 : 256 octets. La fourchette couvre aussi 3072 bits.
MIN_WRAPPED_KEY_BYTES = 128
MAX_WRAPPED_KEY_BYTES = 512

CHANNEL_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _-]{0,63}$")


def _normalize_name(value: str) -> str:
    """Normalise et valide le nom d'une entité nommée : canal ou serveur.

    Les deux obéissent à la **même** règle, appliquée ici une seule fois. Un
    serveur n'a aucune raison d'accepter un nom qu'un canal refuse : il contient
    des canaux, et l'homogénéité évite que l'ergonomie de saisie diverge selon
    l'entité visée. Le message ne nomme donc ni l'un ni l'autre, ce qui le rend
    valable pour les deux.
    """
    normalized = value.strip()
    if not CHANNEL_NAME_PATTERN.fullmatch(normalized):
        raise ValueError(
            "Le nom doit faire 1 à 64 caractères : lettres, chiffres, espace, "
            "tiret ou tiret bas, et commencer par un caractère alphanumérique."
        )
    return normalized


# Composantes d'une clé privée RSA. Une seule présence suffit à indiquer qu'un
# client tente de faire transiter sa clé privée.
PRIVATE_JWK_MEMBERS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth"})

# Seul algorithme correspondant à la configuration du MVP.
ALLOWED_JWK_ALG = "RSA-OAEP-256"

MAX_PUBLIC_KEY_MODULUS_BYTES = (256, 384)  # 2048 ou 3072 bits


def _decode_base64(value: str, field: str) -> bytes:
    """Décode du base64 en refusant tout caractère hors alphabet."""
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"{field} n'est pas du base64 valide.") from exc


def _encode_base64url(data: bytes) -> str:
    """Encode en base64url sans remplissage : la forme canonique des JWK."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _decode_base64url(value: str, field: str) -> bytes:
    """Décode du base64url, en vérifiant que l'entrée en est la forme canonique.

    `base64.urlsafe_b64decode` est volontairement permissif : il reconstitue le
    remplissage, tolère l'alphabet standard (`+`, `/`) et ignore purement et
    simplement les caractères hors alphabet. Un même module RSA peut donc être
    présenté de plusieurs façons, toutes décodant vers les mêmes octets.

    C'est inacceptable ici. L'empreinte du RFC 7638 hache les **chaînes** `e`,
    `kty` et `n`, pas les entiers qu'elles représentent : deux encodages de la
    même clé donneraient deux empreintes différentes, et la clé déjà enregistrée
    serait refusée comme si elle en était une autre — un verrou définitif, le
    MVP n'ayant aucune rotation. Le décodage canonique se vérifie donc en
    réencodant : la valeur doit être exactement celle que produit
    `_encode_base64url` sur ses propres octets.

    Ce contrôle est plus large que le simple rejet de `+`, `/` et `=` : il
    refuse aussi les caractères superflus, les espaces et les sauts de ligne
    insérés, que le décodeur aurait silencieusement ignorés.
    """
    if not value:
        raise ValueError(f"{field} est vide.")
    padding = "=" * (-len(value) % 4)
    try:
        decoded = base64.urlsafe_b64decode(value + padding)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"{field} n'est pas du base64url valide.") from exc
    if _encode_base64url(decoded) != value:
        raise ValueError(
            f"{field} n'est pas dans l'encodage base64url canonique : ni remplissage "
            f"« = », ni alphabet standard « + » et « / », ni caractère superflu."
        )
    return decoded


class PublicJwk(BaseModel):
    """Clé publique RSA, dans la forme produite par `exportKey("jwk", ...)`."""

    model_config = ConfigDict(extra="forbid")

    kty: str
    n: str
    e: str
    # Certains navigateurs exportent `alg` et `ext`, d'autres non. Les accepter
    # comme absents, mais ne pas les réémettre à `null` : un `null` n'est pas un
    # membre JWK valide et ferait échouer une comparaison côté client.
    alg: str | None = Field(default=None, exclude_if=lambda value: value is None)
    ext: bool | None = Field(default=None, exclude_if=lambda value: value is None)

    @model_validator(mode="before")
    @classmethod
    def _reject_private_key(cls, value: Any) -> Any:
        """Refuse explicitement toute composante de clé privée.

        `extra="forbid"` suffirait à la rejeter, mais le message d'erreur
        explicite évite qu'un client comprenne mal ce qui lui est reproché.
        """
        if isinstance(value, dict):
            leaked = PRIVATE_JWK_MEMBERS.intersection(value)
            if leaked:
                listed = ", ".join(sorted(leaked))
                raise ValueError(
                    f"Une clé privée ne doit jamais être transmise au serveur "
                    f"(composante(s) : {listed})."
                )
        return value

    @field_validator("kty")
    @classmethod
    def _validate_kty(cls, value: str) -> str:
        if value != "RSA":
            raise ValueError("Seules les clés RSA sont acceptées.")
        return value

    @field_validator("alg")
    @classmethod
    def _validate_alg(cls, value: str | None) -> str | None:
        if value is not None and value != ALLOWED_JWK_ALG:
            raise ValueError(f"L'algorithme doit être {ALLOWED_JWK_ALG}.")
        return value

    @field_validator("n")
    @classmethod
    def _validate_modulus(cls, value: str) -> str:
        # Le décodage refuse déjà toute écriture non canonique : la taille est
        # donc celle des octets réellement reçus, et non celle d'un décodage
        # tolérant qui aurait absorbé du remplissage ou des caractères en trop.
        decoded = _decode_base64url(value, "n")
        if len(decoded) not in MAX_PUBLIC_KEY_MODULUS_BYTES:
            raise ValueError(
                "Le module doit faire "
                + " or ".join(str(size) for size in MAX_PUBLIC_KEY_MODULUS_BYTES)
                + " octets."
            )
        return value

    @field_validator("e")
    @classmethod
    def _validate_exponent(cls, value: str) -> str:
        decoded = _decode_base64url(value, "e")
        if not 1 <= len(decoded) <= 8:
            raise ValueError("L'exposant public est de taille incohérente.")
        return value

    def canonical_json(self) -> str:
        """Sérialisation canonique du RFC 7638, source de l'empreinte.

        Seuls les membres obligatoires sont retenus, triés lexicographiquement,
        sans espace : deux implémentations indépendantes obtiennent donc la même
        empreinte.
        """
        members = {"e": self.e, "kty": self.kty, "n": self.n}
        return "{" + ",".join(f'"{name}":"{members[name]}"' for name in sorted(members)) + "}"


class PublicKeyIn(BaseModel):
    """Corps de publication d'une clé publique."""

    model_config = ConfigDict(extra="forbid")

    public_key_jwk: PublicJwk


class PublicKeyOut(BaseModel):
    """Clé publique de l'utilisateur courant."""

    public_key_jwk: PublicJwk
    fingerprint: str
    key_version: int


class ChannelCreateIn(BaseModel):
    """Corps de création d'un canal.

    Aucun secret n'est transmis ici : la clé de salon n'est ni générée, ni
    reçue à cette étape. Elle reste dans le navigateur du créateur, qui la
    déposera ensuite sous forme d'enveloppe chiffrée.
    """

    model_config = ConfigDict(extra="forbid")

    name: str
    client_ref: UUID

    @field_validator("name")
    @classmethod
    def _validate_name(cls, value: str) -> str:
        return _normalize_name(value)


class ChannelOut(BaseModel):
    """Représentation d'un canal.

    Le canal expose `server_id` et rien d'autre sur l'appartenance. Ni
    `members`, ni `created_by` : cette information appartient au serveur parent,
    et le renvoi serait une copie destinée à diverger. L'interface remonte au
    serveur par `server_id` quand elle a besoin de savoir qui peut lire le canal.

    `client_ref` reste exposé : c'est la référence locale qui permet au
    navigateur de retrouver un canal créé juste avant une fermeture inattendue.
    """

    id: str
    name: str
    server_id: str
    created_at: Any
    client_ref: str


class MemberRefIn(BaseModel):
    """Corps d'ajout d'un membre à un serveur.

    Le corps ne contient qu'un `username`, et c'est délibéré. L'interface ne
    connaît qu'un nom : c'est ce que l'utilisateur sait écrire, et c'est ce que
    l'inscription produit. Le `user_id` interne n'est exposé nulle part à un tiers
    — `/auth/me` ne renvoie que le sien — donc un client n'a matériellement aucun
    `user_id` à envoyer, et l'exiger rendait la route inutilisable depuis
    l'interface.

    Le `username` n'est donc pas une désignation du membre, c'est une **résolution
    que le serveur effectue** : `get_user_by_username` fait foi, et l'appelant ne
    peut pas inventer une identité. Exposer à la place une route de recherche
    aurait donné le même service en laissant énumérer les comptes existants ; ici,
    seule une tentative d'adhésion répond, et elle est déjà réservée au créateur.

    Ni `user_id` ni `created_by` ne sont acceptés : `extra="forbid"` refuse le
    premier, qui ferait de l'identifiant une désignation falsifiable, et le
    second, qui déciderait qui administre. L'identité de l'appelant vient de la
    session, comme partout ailleurs.

    Le motif du nom n'est pas validé, à l'instar de `LoginIn` : un identifiant
    malformé doit répondre « introuvable » comme un identifiant inconnu, et non
    révéler par un 422 qu'un compte existe. La longueur est néanmoins bornée à
    celle d'un nom réellement enregistrable, pour qu'un corps arbitrairement long
    n'atteigne jamais la base.
    """

    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=1, max_length=32)

    @field_validator("username")
    @classmethod
    def _normalize_username(cls, value: str) -> str:
        # Même normalisation que l'inscription et la connexion : sans elle,
        # « Carol » ne retrouverait pas « carol », et l'adhésion échouerait sur une
        # simple différence de casse ou d'espace.
        return normalize_username(value)


class ServerCreateIn(BaseModel):
    """Corps de création d'un serveur.

    Le corps ne contient qu'un nom, et c'est délibéré :

    * `created_by` est refusé, comme tout champ inconnu (`extra="forbid"`). Le
      créateur ne peut venir que de la session ; l'accepter ici rendrait
      l'identité du serveur falsifiable par le client ;
    * `joined_at` est refusé pour la même raison : l'ordre d'adhésion décide du
      successeur du créateur, il ne peut donc pas être choisi par celui qui
      rejoint ;
    * aucun `client_ref` n'est requis, contrairement à un canal. Un serveur ne
      détient aucune clé : celle-ci naît avec son premier canal, et c'est ce
      canal-là qui a besoin d'une référence locale pour être repris après une
      fermeture du navigateur.
    """

    model_config = ConfigDict(extra="forbid")

    name: str

    @field_validator("name")
    @classmethod
    def _validate_name(cls, value: str) -> str:
        # Même règle que pour un canal : voir `_normalize_name`.
        return _normalize_name(value)


class ServerMemberOut(BaseModel):
    """Membre d'un serveur, avec son ancienneté d'adhésion.

    `joined_at` est la donnée qui permet de désigner le membre le plus ancien,
    donc le successeur du créateur si celui-ci part sans avoir choisi de
    successeur.

    La clé publique est exposée pour la même raison qu'elle l'est dans la
    représentation d'un canal avant la migration, et selon les mêmes modalités :
    à terme, emballer la clé de salon d'un canal pour ce membre se fait dans le
    navigateur d'un autre membre du serveur, ce qui suppose d'en connaître la clé
    publique. Une clé publique n'est pas un secret, et le haché du mot de passe
    n'est jamais chargé : la projection de `users_by_ids` l'exclut explicitement.
    """

    user_id: str
    username: str
    joined_at: datetime
    public_key_fingerprint: str | None = None
    public_key_jwk: PublicJwk | None = None


class ServerOut(BaseModel):
    """Représentation d'un serveur.

    Aucun matériel cryptographique n'y figure : ni clé de salon, ni clé privée,
    ni texte chiffré. Le serveur n'en détient aucun.
    """

    id: str
    name: str
    created_at: datetime
    created_by: str
    members: list[ServerMemberOut]


class ChannelKeyIn(BaseModel):
    """Corps de dépôt d'une enveloppe de clé de salon.

    `wrapped_key` est le résultat de `RSA-OAEP(cle_publique_du_destinataire,
    cle_de_salon)`. Le serveur le relaie sans jamais pouvoir l'ouvrir.
    """

    model_config = ConfigDict(extra="forbid")

    user_id: str
    wrapped_key: str

    @field_validator("wrapped_key")
    @classmethod
    def _validate_wrapped_key(cls, value: str) -> str:
        decoded = _decode_base64(value, "wrapped_key")
        if not MIN_WRAPPED_KEY_BYTES <= len(decoded) <= MAX_WRAPPED_KEY_BYTES:
            raise ValueError("L'enveloppe de clé a une taille incohérente.")
        return value


class ChannelKeyOut(BaseModel):
    """Enveloppe de clé de salon destinée à l'utilisateur courant."""

    channel_id: str
    key_version: int
    wrapped_key: str
    created_at: Any


class MessageOut(BaseModel):
    """Message chiffré, tel qu'il est stocké et transmis."""

    id: str
    channel_id: str
    sender_id: str
    client_id: str
    ciphertext: str
    iv: str
    created_at: Any


class MessageListOut(BaseModel):
    """Historique chiffré d'un canal, du plus ancien au plus récent."""

    messages: list[MessageOut]
    has_more: bool


def validate_iv(value: str) -> str:
    """Vérifie le format du vecteur d'initialisation AES-GCM.

    Douze octets exactement : c'est la taille pour laquelle GCM n'impose pas
    une dérivation supplémentaire de l'IV par le mécanisme de double hachage.
    """
    decoded = _decode_base64(value, "iv")
    if len(decoded) != IV_BYTES:
        raise ValueError(f"Le vecteur d'initialisation doit faire {IV_BYTES} octets.")
    return value


def validate_ciphertext(value: str) -> str:
    """Vérifie la forme du ciphertext sans jamais chercher à le comprendre."""
    if len(value) > MAX_CIPHERTEXT_BASE64:
        raise ValueError("Le message chiffré est trop volumineux.")
    decoded = _decode_base64(value, "ciphertext")
    if len(decoded) < MIN_CIPHERTEXT_BYTES:
        raise ValueError("Le message chiffré est trop court pour être valide.")
    return value


class SendIn(BaseModel):
    """Trame d'envoi d'un message chiffré.

    `extra="forbid"` : un champ inconnu est refusé plutôt qu'ignoré. Un client
    qui croit avoir transmis `sender_id` doit apprendre que ce n'est pas ainsi
    que ça marche, et non observer un message enregistré sous une autre
    identité sans jamais le savoir.
    """

    model_config = ConfigDict(extra="forbid")

    type: Literal["send"]
    channel_id: str
    client_id: UUID
    iv: str
    ciphertext: str

    @field_validator("iv")
    @classmethod
    def _validate_iv(cls, value: str) -> str:
        return validate_iv(value)

    @field_validator("ciphertext")
    @classmethod
    def _validate_ciphertext(cls, value: str) -> str:
        return validate_ciphertext(value)


class SubscribeIn(BaseModel):
    """Trame d'abonnement à un canal. Refusée par le serveur, voir `messages`."""

    model_config = ConfigDict(extra="forbid")

    type: Literal["subscribe"]
    channel_id: str


class UnsubscribeIn(BaseModel):
    """Trame de désabonnement. Refusée par le serveur, voir `messages`."""

    model_config = ConfigDict(extra="forbid")

    type: Literal["unsubscribe"]
    channel_id: str


WsFrameIn = Annotated[
    SendIn | SubscribeIn | UnsubscribeIn,
    Field(discriminator="type"),
]

MAX_HISTORY_LIMIT = 100
DEFAULT_HISTORY_LIMIT = 50
MessageCursor = str | None
