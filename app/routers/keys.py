"""Clé publique de l'utilisateur courant.

Ce routeur est le seul endroit où une clé entre dans le système, et il n'accepte
que la **moitié publique** d'une paire RSA. Toute composante privée présentée
dans le corps est rejetée explicitement par le schéma, avant d'atteindre la base.

Remplacement d'une clé : refusé tant qu'aucune procédure de ré-emballage global
des enveloppes n'existe. Accepter une clé différente romprait de façon
irréversible l'invariant « toute enveloppe déposée est déchiffrable par son
destinataire », sans que le serveur soit capable de le réparer. Republier la clé
déjà enregistrée est en revanche accepté, pour qu'un client ayant perdu sa clé
après l'avoir publiée puisse se rattraper.

Ce refus vaut aussi sous concurrence. Lire la clé avant d'écrire ne suffit pas :
deux publications simultanées peuvent toutes deux constater qu'aucune clé
n'existe, et la seule opération qui tranche est l'écriture atomique elle-même.
Son issue est donc relue avant tout succès, pour qu'aucun client ne reçoive une
confirmation d'enregistrement qui n'a pas eu lieu.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status

from app.chat_schemas import PublicJwk, PublicKeyIn, PublicKeyOut
from app.deps import get_current_user, get_store, require_csrf
from app.security import public_key_thumbprint
from app.store import PUBLIC_KEY_VERSION, UserStore

router = APIRouter(tags=["clés"])

NO_PUBLIC_KEY = "Aucune clé publique publiée."

KEY_CONFLICT = (
    "Cette clé publique ne peut pas remplacer celle déjà enregistrée. "
    "Le remplacement est désactivé tant qu'aucune procédure de "
    "ré-emballage des enveloppes n'est disponible."
)


@router.get("/keys/me", response_model=PublicKeyOut)
async def read_public_key(
    user: Annotated[dict[str, Any], Depends(get_current_user)],
    store: Annotated[UserStore, Depends(get_store)],
) -> PublicKeyOut:
    """Renvoie la clé publique de l'utilisateur courant.

    Répond 404 tant qu'aucune clé n'a été publiée : c'est ce qui déclenche la
    génération côté client.
    """
    document = await store.get_public_key(user["_id"])
    if document is None or "public_key" not in document:
        raise HTTPException(status.HTTP_404_NOT_FOUND, NO_PUBLIC_KEY)
    return _to_public_key_out(document["public_key"])


@router.put("/keys/me", response_model=PublicKeyOut)
async def publish_public_key(
    payload: PublicKeyIn,
    _session: Annotated[dict[str, Any], Depends(require_csrf)],
    user: Annotated[dict[str, Any], Depends(get_current_user)],
    store: Annotated[UserStore, Depends(get_store)],
) -> PublicKeyOut:
    """Publie la clé publique de l'utilisateur courant.

    L'empreinte est calculée par le serveur à partir de la forme canonique du
    RFC 7638 : le client et le serveur obtiennent donc la même valeur, et le
    serveur n'expose rien d'autre que du public.

    La lecture préalable n'est qu'un fast path : elle règle le cas séquentiel
    sans écriture. Elle ne peut pas servir de garde-fou à elle seule, car une
    requête concurrente peut enregistrer une clé entre cette lecture et
    l'écriture qui suit. C'est pourquoi l'issue de l'opération atomique est
    relue, et qu'aucun succès n'est annoncé avant de l'avoir vérifiée.
    """
    jwk = payload.public_key_jwk
    fingerprint = public_key_thumbprint(jwk.canonical_json())

    existing = await store.get_public_key(user["_id"])
    current = existing.get("public_key") if existing else None

    if current is not None:
        if current["fingerprint"] != fingerprint:
            raise HTTPException(status.HTTP_409_CONFLICT, KEY_CONFLICT)
        # Même clé : succès idempotent, utile après un échec d'écriture locale.
        return _to_public_key_out(current)

    written = await store.save_public_key(user["_id"], jwk.model_dump(mode="json"), fingerprint)
    if not written:
        # Une requête concurrente a enregistré une clé pendant la fenêtre
        # ci-dessus. `save_public_key` a alors eu raison de ne rien écraser, et
        # son refus est la seule information fiable : la relure désigne la clé
        # réellement retenue, et l'écart avec la nôtre décide de la réponse.
        settled = await store.get_public_key(user["_id"])
        current = settled.get("public_key") if settled else None
        if current is not None and current["fingerprint"] == fingerprint:
            # Deux requêtes concurrentes portant la même clé : la seconde est un
            # succès idempotent, pas un conflit.
            return _to_public_key_out(current)
        raise HTTPException(status.HTTP_409_CONFLICT, KEY_CONFLICT)

    return PublicKeyOut(public_key_jwk=jwk, fingerprint=fingerprint, key_version=PUBLIC_KEY_VERSION)


def _to_public_key_out(stored: dict[str, Any]) -> PublicKeyOut:
    return PublicKeyOut(
        public_key_jwk=PublicJwk.model_validate(stored["jwk"]),
        fingerprint=stored["fingerprint"],
        key_version=stored["version"],
    )
