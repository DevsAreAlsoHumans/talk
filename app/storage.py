import json
import time
from collections.abc import Iterable, Sequence
from typing import Any, Optional, Union
from uuid import uuid4

from redis.asyncio import Redis
from redis.exceptions import WatchError


class UsernameAlreadyExistsError(Exception):
    pass


class IdentityKeyConflictError(Exception):
    pass


class IdentityKeyLimitError(Exception):
    pass


class ChannelAlreadyExistsError(Exception):
    pass


class DuplicateMessageError(Exception):
    pass


class ConcurrentRoomUpdateError(Exception):
    pass


class MessageRejectedError(Exception):
    pass


class RedisStore:
    """Couche d'accès Redis. Les identifiants sont générés par l'API."""

    _MIGRATE_USERNAME_INDEX_SCRIPT = """
    if redis.call('EXISTS', KEYS[1]) == 1 then
        local names = redis.call('SMEMBERS', KEYS[1])
        for _, name in ipairs(names) do
            local user_id = redis.call('GET', 'talk:username:' .. name)
            if user_id then
                redis.call('ZADD', KEYS[2], 0, name)
            end
        end
        redis.call('DEL', KEYS[1])
    end
    return 1
    """

    _REGISTER_USER_SCRIPT = """
    if redis.call('GET', KEYS[1]) then
        return 0
    end
    redis.call('HSET', KEYS[2],
        'id', ARGV[1],
        'username', ARGV[2],
        'username_normalized', ARGV[3],
        'display_name', ARGV[4],
        'password_hash', ARGV[5],
        'created_at', ARGV[6])
    redis.call('HSET', KEYS[3], ARGV[7], ARGV[8])
    redis.call('ZADD', KEYS[4], 0, ARGV[3])
    redis.call('SET', KEYS[1], ARGV[1])
    return 1
    """

    _ADD_IDENTITY_KEY_SCRIPT = """
    local current = redis.call('HGET', KEYS[1], ARGV[1])
    if current and current ~= ARGV[2] then
        return 0
    end
    if redis.call('HLEN', KEYS[1]) >= tonumber(ARGV[3]) then
        return -1
    end
    redis.call('HSET', KEYS[1], ARGV[1], ARGV[2])
    return 1
    """

    _RATE_LIMIT_SCRIPT = """
    local current = redis.call('INCR', KEYS[1])
    if current == 1 then
        redis.call('EXPIRE', KEYS[1], ARGV[1])
    end
    local ttl = redis.call('TTL', KEYS[1])
    return {current, ttl}
    """

    _CREATE_SESSION_SCRIPT = """
    redis.call('HSET', KEYS[1],
        'user_id', ARGV[1],
        'csrf_token', ARGV[2],
        'csrf_expires_at', ARGV[3],
        'expires_at', ARGV[4])
    redis.call('EXPIRE', KEYS[1], ARGV[5])
    return 1
    """

    _SAVE_MESSAGE_SCRIPT = """
    local version = redis.call('HGET', KEYS[1], 'key_version')
    if not version or tonumber(version) ~= tonumber(ARGV[2]) then
        return {-1, 0}
    end
    if redis.call('SISMEMBER', KEYS[2], ARGV[1]) ~= 1 then
        return {-1, 0}
    end
    if redis.call('EXISTS', KEYS[3]) == 1 then
        return {0, 0}
    end
    local sequence = redis.call('INCR', KEYS[4])
    redis.call('HSET', KEYS[3],
        'client_id', ARGV[3],
        'sender_id', ARGV[1],
        'room_id', ARGV[4],
        'channel_id', ARGV[5],
        'algorithm', ARGV[6],
        'key_version', ARGV[7],
        'ciphertext', ARGV[8],
        'nonce', ARGV[9],
        'created_at', ARGV[10],
        'sequence', sequence)
    redis.call('ZADD', KEYS[5], sequence, ARGV[3])
    return {1, sequence}
    """

    def __init__(self, redis_client: Redis) -> None:
        self.redis = redis_client

    @staticmethod
    def _user_key(user_id: str) -> str:
        return f"talk:user:{user_id}"

    @staticmethod
    def _username_key(username: str) -> str:
        return f"talk:username:{username}"

    @staticmethod
    def _identity_keys_key(user_id: str) -> str:
        return f"talk:user:{user_id}:identity_keys"

    @staticmethod
    def _session_key(token_hash: str) -> str:
        return f"talk:session:{token_hash}"

    @staticmethod
    def _room_key(room_id: str) -> str:
        return f"talk:room:{room_id}"

    @staticmethod
    def _room_members_key(room_id: str) -> str:
        return f"talk:room:{room_id}:members"

    @staticmethod
    def _room_keys_key(room_id: str) -> str:
        return f"talk:room:{room_id}:key_envelopes"

    @staticmethod
    def _user_rooms_key(user_id: str) -> str:
        return f"talk:user:{user_id}:rooms"

    @staticmethod
    def _channel_key(channel_id: str) -> str:
        return f"talk:channel:{channel_id}"

    @staticmethod
    def _room_channels_key(room_id: str) -> str:
        return f"talk:room:{room_id}:channels"

    @staticmethod
    def _channel_name_key(room_id: str, normalized_name: str) -> str:
        return f"talk:room:{room_id}:channel_name:{normalized_name}"

    @staticmethod
    def _message_key(client_id: str) -> str:
        return f"talk:message:{client_id}"

    @staticmethod
    def _channel_sequence_key(channel_id: str) -> str:
        return f"talk:channel:{channel_id}:sequence"

    @staticmethod
    def _channel_messages_key(channel_id: str) -> str:
        return f"talk:channel:{channel_id}:messages"

    @staticmethod
    def _serialize_user(record: dict[str, str]) -> dict[str, Any]:
        return {
            "id": record["id"],
            "username": record["username"],
            "display_name": record["display_name"],
            "created_at": int(record["created_at"]),
        }

    @staticmethod
    def _serialize_identity(record: Union[str, dict[str, Any]]) -> dict[str, Any]:
        payload = json.loads(record) if isinstance(record, str) else record
        return {
            "key_id": payload["key_id"],
            "device_name": payload["device_name"],
            "public_key": payload["public_key"],
            "created_at": int(payload["created_at"]),
        }

    @staticmethod
    def _serialize_room(record: dict[str, str]) -> dict[str, Any]:
        return {
            "id": record["id"],
            "name": record["name"],
            "owner_id": record["owner_id"],
            "key_version": int(record.get("key_version", "1")),
            "created_at": int(record["created_at"]),
        }

    @staticmethod
    def _serialize_channel(record: dict[str, str]) -> dict[str, Any]:
        return {
            "id": record["id"],
            "room_id": record["room_id"],
            "name": record["name"],
            "created_at": int(record["created_at"]),
        }

    @staticmethod
    def _serialize_message(record: dict[str, str]) -> dict[str, Any]:
        return {
            "client_id": record["client_id"],
            "sender_id": record["sender_id"],
            "room_id": record["room_id"],
            "channel_id": record["channel_id"],
            "algorithm": record["algorithm"],
            "key_version": int(record["key_version"]),
            "ciphertext": record["ciphertext"],
            "nonce": record["nonce"],
            "created_at": int(record["created_at"]),
            "sequence": int(record["sequence"]),
        }

    async def ping(self) -> bool:
        return bool(await self.redis.ping())

    async def register_user(
        self,
        *,
        username: str,
        display_name: str,
        password_hash: str,
        identity_key: dict[str, Any],
    ) -> dict[str, Any]:
        user_id = str(uuid4())
        created_at = int(time.time() * 1000)
        identity_payload = json.dumps(
            {
                "key_id": str(identity_key["key_id"]),
                "device_name": identity_key["device_name"],
                "public_key": identity_key["public_key"],
                "created_at": created_at,
            },
            separators=(",", ":"),
            sort_keys=True,
        )
        await self.redis.eval(
            self._MIGRATE_USERNAME_INDEX_SCRIPT,
            2,
            "talk:usernames",
            "talk:usernames:v2",
        )
        result = await self.redis.eval(
            self._REGISTER_USER_SCRIPT,
            4,
            self._username_key(username),
            self._user_key(user_id),
            self._identity_keys_key(user_id),
            "talk:usernames:v2",
            user_id,
            username,
            username,
            display_name,
            password_hash,
            created_at,
            str(identity_key["key_id"]),
            identity_payload,
        )
        if int(result) != 1:
            raise UsernameAlreadyExistsError
        user = await self.get_user(user_id)
        if user is None:
            raise RuntimeError("Utilisateur introuvable après création")
        return user

    async def get_user(self, user_id: str) -> Optional[dict[str, Any]]:
        record = await self.redis.hgetall(self._user_key(user_id))
        return self._serialize_user(record) if record else None

    async def get_user_by_username(self, username: str) -> Optional[dict[str, Any]]:
        user_id = await self.redis.get(self._username_key(username))
        if not user_id:
            return None
        return await self.get_user(user_id)

    async def get_user_credentials(self, user_id: str) -> Optional[dict[str, str]]:
        return await self.redis.hgetall(self._user_key(user_id)) or None

    async def list_identity_keys(self, user_id: str) -> list[dict[str, Any]]:
        records = await self.redis.hgetall(self._identity_keys_key(user_id))
        keys = [self._serialize_identity(record) for record in records.values()]
        return sorted(keys, key=lambda item: (item["created_at"], item["key_id"]))

    async def add_identity_key(self, user_id: str, identity_key: dict[str, Any]) -> dict[str, Any]:
        keys_key = self._identity_keys_key(user_id)
        key_id = str(identity_key["key_id"])
        existing_payload = await self.redis.hget(keys_key, key_id)
        if existing_payload:
            existing = self._serialize_identity(existing_payload)
            if (
                existing["device_name"] == identity_key["device_name"]
                and existing["public_key"] == identity_key["public_key"]
            ):
                return existing

        created_at = int(time.time() * 1000)
        payload = json.dumps(
            {
                "key_id": key_id,
                "device_name": identity_key["device_name"],
                "public_key": identity_key["public_key"],
                "created_at": created_at,
            },
            separators=(",", ":"),
            sort_keys=True,
        )
        result = await self.redis.eval(
            self._ADD_IDENTITY_KEY_SCRIPT,
            1,
            keys_key,
            key_id,
            payload,
            10,
        )
        if int(result) == -1:
            raise IdentityKeyLimitError
        if int(result) != 1:
            raise IdentityKeyConflictError
        record = await self.redis.hget(keys_key, key_id)
        if not record:
            raise RuntimeError("Clé d'identité introuvable après création")
        return self._serialize_identity(record)

    async def create_session(
        self,
        *,
        token_hash: str,
        user_id: str,
        csrf_token: str,
        csrf_expires_at: int,
        expires_at: int,
    ) -> None:
        ttl_seconds = max(1, expires_at - int(time.time()))
        await self.redis.eval(
            self._CREATE_SESSION_SCRIPT,
            1,
            self._session_key(token_hash),
            user_id,
            csrf_token,
            csrf_expires_at,
            expires_at,
            ttl_seconds,
        )

    async def update_session_csrf(
        self, token_hash: str, csrf_token: str, csrf_expires_at: int
    ) -> bool:
        return bool(
            await self.redis.hset(
                self._session_key(token_hash),
                mapping={
                    "csrf_token": csrf_token,
                    "csrf_expires_at": csrf_expires_at,
                },
            )
        )

    async def get_session(self, token_hash: str) -> Optional[dict[str, Any]]:
        record = await self.redis.hgetall(self._session_key(token_hash))
        if not record:
            return None
        if int(record.get("expires_at", "0")) <= int(time.time()):
            await self.delete_session(token_hash)
            return None
        return {
            "user_id": record["user_id"],
            "csrf_token": record["csrf_token"],
            "csrf_expires_at": int(record.get("csrf_expires_at", "0")),
            "expires_at": int(record["expires_at"]),
        }

    async def delete_session(self, token_hash: str) -> None:
        await self.redis.delete(self._session_key(token_hash))

    async def check_rate_limit(
        self, scope: str, identifier: str, limit: int, window_seconds: int
    ) -> tuple[bool, int]:
        window = int(time.time()) // window_seconds
        key = f"talk:rate:{scope}:{identifier}:{window}"
        result = await self.redis.eval(self._RATE_LIMIT_SCRIPT, 1, key, window_seconds)
        count, retry_after = int(result[0]), int(result[1])
        return count <= limit, max(1, retry_after)

    async def create_room(
        self,
        *,
        name: str,
        owner_id: str,
        member_ids: Sequence[str],
        key_envelopes: Sequence[dict[str, Any]],
        channel_name: str,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        room_id = str(uuid4())
        channel_id = str(uuid4())
        created_at = int(time.time() * 1000)
        normalized_channel = channel_name.casefold()
        channel_name_key = self._channel_name_key(room_id, normalized_channel)
        if not await self.redis.set(channel_name_key, channel_id, nx=True):
            raise ChannelAlreadyExistsError

        try:
            async with self.redis.pipeline(transaction=True) as pipeline:
                pipeline.hset(
                    self._room_key(room_id),
                    mapping={
                        "id": room_id,
                        "name": name,
                        "owner_id": owner_id,
                        "key_version": 1,
                        "created_at": created_at,
                    },
                )
                pipeline.sadd(self._room_members_key(room_id), *member_ids)
                for member_id in member_ids:
                    pipeline.sadd(self._user_rooms_key(member_id), room_id)
                pipeline.hset(
                    self._channel_key(channel_id),
                    mapping={
                        "id": channel_id,
                        "room_id": room_id,
                        "name": channel_name,
                        "name_normalized": normalized_channel,
                        "created_at": created_at,
                    },
                )
                pipeline.sadd(self._room_channels_key(room_id), channel_id)
                for envelope in key_envelopes:
                    pipeline.hset(
                        self._room_keys_key(room_id),
                        self._envelope_field(envelope),
                        json.dumps(envelope, separators=(",", ":"), sort_keys=True),
                    )
                await pipeline.execute()
        except Exception:
            await self.redis.delete(channel_name_key)
            raise

        room = await self.get_room(room_id)
        channel = await self.get_channel(channel_id)
        if room is None or channel is None:
            raise RuntimeError("Salon ou canal introuvable après création")
        return room, channel

    @staticmethod
    def _envelope_field(envelope: dict[str, Any]) -> str:
        return f"{int(envelope['key_version'])}:{envelope['recipient_id']}:{envelope['key_id']}"

    async def get_room(self, room_id: str) -> Optional[dict[str, Any]]:
        record = await self.redis.hgetall(self._room_key(room_id))
        return self._serialize_room(record) if record else None

    async def is_room_member(self, room_id: str, user_id: str) -> bool:
        return bool(await self.redis.sismember(self._room_members_key(room_id), user_id))

    async def list_rooms(self, user_id: str) -> list[dict[str, Any]]:
        room_ids = sorted(await self.redis.smembers(self._user_rooms_key(user_id)))
        if not room_ids:
            return []
        async with self.redis.pipeline(transaction=False) as pipeline:
            for room_id in room_ids:
                pipeline.hgetall(self._room_key(room_id))
            records = await pipeline.execute()
        rooms = [self._serialize_room(record) for record in records if record]
        return sorted(rooms, key=lambda room: (room["created_at"], room["id"]))

    async def list_room_members(self, room_id: str) -> list[dict[str, Any]]:
        user_ids = sorted(await self.redis.smembers(self._room_members_key(room_id)))
        if not user_ids:
            return []
        async with self.redis.pipeline(transaction=False) as pipeline:
            for user_id in user_ids:
                pipeline.hgetall(self._user_key(user_id))
            records = await pipeline.execute()
        members = [self._serialize_user(record) for record in records if record]
        return sorted(members, key=lambda user: (user["display_name"].casefold(), user["id"]))

    async def add_room_member(
        self,
        room_id: str,
        user_id: str,
        key_envelopes: Sequence[dict[str, Any]],
        *,
        expected_version: int,
    ) -> bool:
        room_key = self._room_key(room_id)
        members_key = self._room_members_key(room_id)
        try:
            async with self.redis.pipeline(transaction=True) as pipeline:
                await pipeline.watch(room_key, members_key)
                current_version = await pipeline.hget(room_key, "key_version")
                if current_version != str(expected_version):
                    await pipeline.unwatch()
                    raise ConcurrentRoomUpdateError
                if await pipeline.sismember(members_key, user_id):
                    await pipeline.unwatch()
                    return False
                pipeline.multi()
                pipeline.sadd(members_key, user_id)
                pipeline.sadd(self._user_rooms_key(user_id), room_id)
                for envelope in key_envelopes:
                    pipeline.hset(
                        self._room_keys_key(room_id),
                        self._envelope_field(envelope),
                        json.dumps(envelope, separators=(",", ":"), sort_keys=True),
                    )
                results = await pipeline.execute()
            return bool(results[0])
        except WatchError as exc:
            raise ConcurrentRoomUpdateError from exc

    async def add_room_keys(
        self,
        room_id: str,
        key_envelopes: Sequence[dict[str, Any]],
        *,
        expected_version: int,
    ) -> None:
        if not key_envelopes:
            return
        room_key = self._room_key(room_id)
        try:
            async with self.redis.pipeline(transaction=True) as pipeline:
                await pipeline.watch(room_key)
                current_version = await pipeline.hget(room_key, "key_version")
                if current_version != str(expected_version):
                    await pipeline.unwatch()
                    raise ConcurrentRoomUpdateError
                pipeline.multi()
                for envelope in key_envelopes:
                    pipeline.hset(
                        self._room_keys_key(room_id),
                        self._envelope_field(envelope),
                        json.dumps(envelope, separators=(",", ":"), sort_keys=True),
                    )
                await pipeline.execute()
        except WatchError as exc:
            raise ConcurrentRoomUpdateError from exc

    async def rotate_room_keys(
        self,
        room_id: str,
        key_envelopes: Sequence[dict[str, Any]],
        *,
        expected_version: int,
    ) -> int:
        room_key = self._room_key(room_id)
        try:
            async with self.redis.pipeline(transaction=True) as pipeline:
                await pipeline.watch(room_key)
                current_raw = await pipeline.hget(room_key, "key_version")
                if current_raw != str(expected_version):
                    await pipeline.unwatch()
                    raise ConcurrentRoomUpdateError
                new_version = expected_version + 1
                prepared = []
                for envelope in key_envelopes:
                    updated = dict(envelope)
                    updated["key_version"] = new_version
                    prepared.append(updated)
                pipeline.multi()
                pipeline.hset(room_key, "key_version", new_version)
                for envelope in prepared:
                    pipeline.hset(
                        self._room_keys_key(room_id),
                        self._envelope_field(envelope),
                        json.dumps(envelope, separators=(",", ":"), sort_keys=True),
                    )
                await pipeline.execute()
            return new_version
        except WatchError as exc:
            raise ConcurrentRoomUpdateError from exc

    async def get_room_keys(self, room_id: str) -> list[dict[str, Any]]:
        records = await self.redis.hgetall(self._room_keys_key(room_id))
        envelopes = [json.loads(record) for record in records.values()]
        return sorted(
            envelopes,
            key=lambda item: (
                int(item["key_version"]),
                item["recipient_id"],
                item["key_id"],
            ),
        )

    async def create_channel(self, room_id: str, name: str) -> dict[str, Any]:
        channel_id = str(uuid4())
        created_at = int(time.time() * 1000)
        normalized_name = name.casefold()
        name_key = self._channel_name_key(room_id, normalized_name)
        if not await self.redis.set(name_key, channel_id, nx=True):
            raise ChannelAlreadyExistsError
        try:
            async with self.redis.pipeline(transaction=True) as pipeline:
                pipeline.hset(
                    self._channel_key(channel_id),
                    mapping={
                        "id": channel_id,
                        "room_id": room_id,
                        "name": name,
                        "name_normalized": normalized_name,
                        "created_at": created_at,
                    },
                )
                pipeline.sadd(self._room_channels_key(room_id), channel_id)
                await pipeline.execute()
        except Exception:
            await self.redis.delete(name_key)
            raise
        channel = await self.get_channel(channel_id)
        if channel is None:
            raise RuntimeError("Canal introuvable après création")
        return channel

    async def get_channel(self, channel_id: str) -> Optional[dict[str, Any]]:
        record = await self.redis.hgetall(self._channel_key(channel_id))
        return self._serialize_channel(record) if record else None

    async def list_channels(self, room_id: str) -> list[dict[str, Any]]:
        channel_ids = sorted(await self.redis.smembers(self._room_channels_key(room_id)))
        if not channel_ids:
            return []
        async with self.redis.pipeline(transaction=False) as pipeline:
            for channel_id in channel_ids:
                pipeline.hgetall(self._channel_key(channel_id))
            records = await pipeline.execute()
        channels = [self._serialize_channel(record) for record in records if record]
        return sorted(channels, key=lambda channel: (channel["created_at"], channel["id"]))

    async def save_message(
        self, message: dict[str, Any], *, expected_version: int
    ) -> tuple[bool, int]:
        client_id = str(message["client_id"])
        result = await self.redis.eval(
            self._SAVE_MESSAGE_SCRIPT,
            5,
            self._room_key(str(message["room_id"])),
            self._room_members_key(str(message["room_id"])),
            self._message_key(client_id),
            self._channel_sequence_key(str(message["channel_id"])),
            self._channel_messages_key(str(message["channel_id"])),
            str(message["sender_id"]),
            expected_version,
            client_id,
            str(message["room_id"]),
            str(message["channel_id"]),
            str(message["algorithm"]),
            int(message["key_version"]),
            str(message["ciphertext"]),
            str(message["nonce"]),
            int(message["created_at"]),
        )
        status = int(result[0])
        if status == -1:
            raise MessageRejectedError
        return status == 1, int(result[1])

    async def get_message(self, client_id: str) -> Optional[dict[str, Any]]:
        record = await self.redis.hgetall(self._message_key(client_id))
        return self._serialize_message(record) if record else None

    async def list_messages(
        self, channel_id: str, *, before: Optional[int], limit: int
    ) -> tuple[list[dict[str, Any]], Optional[int]]:
        maximum = before - 1 if before is not None else 0
        entries: Iterable[tuple[str, float]] = await self.redis.zrevrange(
            self._channel_messages_key(channel_id),
            maximum,
            limit - 1,
            withscores=True,
        )
        entries_list = list(entries)
        client_ids = [client_id for client_id, _ in entries_list]
        if not client_ids:
            return [], None
        async with self.redis.pipeline(transaction=False) as pipeline:
            for client_id in client_ids:
                pipeline.hgetall(self._message_key(client_id))
            records = await pipeline.execute()
        messages = [self._serialize_message(record) for record in records if record]
        messages.reverse()
        next_cursor = min(message["sequence"] for message in messages)
        return messages, next_cursor if len(messages) == limit else None

    async def search_users(self, query: str, limit: int = 20) -> list[dict[str, Any]]:
        minimum = f"[{query}"
        maximum = f"[{query}\xff"
        await self.redis.eval(
            self._MIGRATE_USERNAME_INDEX_SCRIPT,
            2,
            "talk:usernames",
            "talk:usernames:v2",
        )
        usernames = await self.redis.zrangebylex(
            "talk:usernames:v2", minimum, maximum, start=0, num=limit
        )
        if not usernames:
            return []
        async with self.redis.pipeline(transaction=False) as pipeline:
            for username in usernames:
                pipeline.get(self._username_key(username))
            user_ids = [user_id for user_id in await pipeline.execute() if user_id]
        if not user_ids:
            return []
        async with self.redis.pipeline(transaction=False) as pipeline:
            for user_id in user_ids:
                pipeline.hgetall(self._user_key(user_id))
            records = await pipeline.execute()
        users = [self._serialize_user(record) for record in records if record]
        return sorted(users, key=lambda user: user["username"])

    async def all_room_member_ids(self, room_id: str) -> list[str]:
        return sorted(await self.redis.smembers(self._room_members_key(room_id)))
