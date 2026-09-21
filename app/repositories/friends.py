"""Accès Redis aux relations d'amitié.

Clés :
  friend:{id}:requests   set   demandes reçues, en attente d'acceptation
  friend:{id}:outgoing   set   demandes envoyées par cet utilisateur
  friend:{id}:list       set   amis acceptés

Regles : une demande se crée dans les deux sens (``outgoing`` de l'expéditeur,
``requests`` du destinataire) et ne devient une amitié que lorsque le destinataire
l'accepte (alors : entrée dans ``list`` des deux côtés).
"""

from redis.asyncio import Redis


class FriendRepository:
    def __init__(self, redis: Redis) -> None:
        self._redis = redis

    def _requests(self, user_id: str) -> str:
        return f"friend:{user_id}:requests"

    def _outgoing(self, user_id: str) -> str:
        return f"friend:{user_id}:outgoing"

    def _list(self, user_id: str) -> str:
        return f"friend:{user_id}:list"

    async def is_friend(self, first_id: str, second_id: str) -> bool:
        return bool(await self._redis.sismember(self._list(first_id), second_id))

    async def friend_ids(self, user_id: str) -> set[str]:
        return set(await self._redis.smembers(self._list(user_id)))

    async def incoming_ids(self, user_id: str) -> set[str]:
        return set(await self._redis.smembers(self._requests(user_id)))

    async def outgoing_ids(self, user_id: str) -> set[str]:
        return set(await self._redis.smembers(self._outgoing(user_id)))

    async def send_request(self, from_id: str, to_id: str) -> str:
        """Crée une demande ; renvoie ``ok``, ``already_friend`` ou ``already_pending``."""
        if await self.is_friend(from_id, to_id):
            return "already_friend"
        if await self._redis.sismember(self._outgoing(from_id), to_id):
            return "already_pending"
        if await self._redis.sismember(self._requests(from_id), to_id):
            return "already_pending"  # c'est l'autre qui a déjà demandé en premier
        await self._redis.sadd(self._outgoing(from_id), to_id)
        await self._redis.sadd(self._requests(to_id), from_id)
        return "ok"

    async def accept(self, user_id: str, requester_id: str) -> bool:
        """Accepte une demande reçue ; False s'il n'y avait rien à accepter."""
        if not await self._redis.sismember(self._requests(user_id), requester_id):
            return False
        async with self._redis.pipeline(transaction=True) as pipe:
            pipe.srem(self._requests(user_id), requester_id)
            pipe.srem(self._outgoing(requester_id), user_id)
            pipe.sadd(self._list(user_id), requester_id)
            pipe.sadd(self._list(requester_id), user_id)
            await pipe.execute()
        return True

    async def decline(self, user_id: str, requester_id: str) -> bool:
        """Refuse une demande reçue ; False s'il n'y avait rien à refuser."""
        if not await self._redis.sismember(self._requests(user_id), requester_id):
            return False
        await self._redis.srem(self._requests(user_id), requester_id)
        await self._redis.srem(self._outgoing(requester_id), user_id)
        return True

    async def remove(self, first_id: str, second_id: str) -> bool:
        """Révoque une amitié dans les deux sens (et nettoie d'éventuelles demandes)."""
        if not await self.is_friend(first_id, second_id):
            return False
        async with self._redis.pipeline(transaction=True) as pipe:
            pipe.srem(self._list(first_id), second_id)
            pipe.srem(self._list(second_id), first_id)
            pipe.srem(self._requests(first_id), second_id)
            pipe.srem(self._requests(second_id), first_id)
            pipe.srem(self._outgoing(first_id), second_id)
            pipe.srem(self._outgoing(second_id), first_id)
            await pipe.execute()
        return True
