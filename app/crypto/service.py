"""Validation des clés publiques et calcul d'empreintes.

L'empreinte (« numéro de sécurité », comme chez Signal) répond à une limite
que le chiffrement de bout en bout ne couvre pas à lui seul : c'est le serveur
qui distribue les clés publiques. Un serveur malveillant pourrait donc remettre
**sa propre clé** à la place de celle du correspondant, déchiffrer, relire et
rechiffrer — une attaque de l'intercepteur, invisible côté client.

La parade ne peut pas être technique seule : deux personnes comparent leurs
empreintes par un canal indépendant (de vive voix, téléphone, en personne). Si
elles correspondent, aucune clé n'a été substituée.

L'empreinte est donc toujours **recalculée côté client** à partir de la clé
réellement utilisée. La version serveur sert à l'affichage et aux tests ; s'y
fier seule n'aurait aucun sens, puisque c'est précisément le serveur dont on
cherche à se prémunir.
"""

import base64
import hashlib

BEGIN_MARKER = "-----BEGIN PUBLIC KEY-----"
END_MARKER = "-----END PUBLIC KEY-----"

# 12 groupes de 5 chiffres, comme le numéro de sécurité de Signal :
# assez court pour être lu à voix haute, assez long pour être infalsifiable.
FINGERPRINT_GROUPS = 12
FINGERPRINT_GROUP_SIZE = 5


def validate_public_key_format(key: str | None) -> bool:
    if not key:
        return False
    stripped = key.strip()
    return stripped.startswith(BEGIN_MARKER) and stripped.endswith(END_MARKER)


def public_key_bytes(key: str) -> bytes | None:
    """Extrait le corps DER d'une clé PEM, ou None si elle est mal formée."""
    if not validate_public_key_format(key):
        return None
    body = key.strip().removeprefix(BEGIN_MARKER).removesuffix(END_MARKER)
    body = "".join(body.split())
    try:
        return base64.b64decode(body, validate=True)
    except (ValueError, base64.binascii.Error):
        return None


def key_fingerprint(key: str | None) -> str | None:
    """Empreinte lisible d'une clé publique, ou None si elle est invalide.

    Format : 12 groupes de 5 chiffres séparés par des espaces, dérivés du
    SHA-256 de la clé. Deux clés différentes donnent deux empreintes
    différentes ; la même clé donne toujours la même empreinte.
    """
    if key is None:
        return None
    raw = public_key_bytes(key)
    if raw is None:
        return None

    digest = hashlib.sha256(raw).digest()
    # Chaque groupe consomme 2 octets, ramenés à 5 chiffres décimaux.
    needed = FINGERPRINT_GROUPS * 2
    material = (digest * ((needed // len(digest)) + 1))[:needed]

    groups = []
    for i in range(FINGERPRINT_GROUPS):
        chunk = int.from_bytes(material[i * 2 : i * 2 + 2], "big")
        groups.append(str(chunk % 100000).zfill(FINGERPRINT_GROUP_SIZE))
    return " ".join(groups)
