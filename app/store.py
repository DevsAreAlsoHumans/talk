from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import uuid4

from pymongo import MongoClient

from app.config import settings


@dataclass
class User:
    id: str
    username: str
    password_hash: str
    public_key: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass
class Server:
    id: str
    name: str
    owner_id: str
    members: set[str] = field(default_factory=set)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass
class Channel:
    id: str
    server_id: str
    name: str
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass
class Message:
    id: str
    channel_id: str
    sender_id: str
    ciphertext: str
    nonce: str
    key_version: str
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))


class MemoryStore:
    def __init__(self) -> None:
        self.users: dict[str, User] = {}
        self.servers: dict[str, Server] = {}
        self.channels: dict[str, Channel] = {}
        self.messages: dict[str, list[Message]] = {}

    def create_user(self, username: str, password_hash: str) -> User:
        user = User(id=str(uuid4()), username=username, password_hash=password_hash)
        self.users[user.id] = user
        return user

    def get_user_by_username(self, username: str) -> User | None:
        return next((user for user in self.users.values() if user.username == username), None)

    def get_user(self, user_id: str) -> User | None:
        return self.users.get(user_id)

    def update_public_key(self, user_id: str, public_key: str) -> User | None:
        user = self.users.get(user_id)
        if user:
            user.public_key = public_key
        return user

    def create_server(self, name: str, owner_id: str) -> Server:
        server = Server(id=str(uuid4()), name=name, owner_id=owner_id, members={owner_id})
        self.servers[server.id] = server
        return server

    def get_server(self, server_id: str) -> Server | None:
        return self.servers.get(server_id)

    def list_servers(self, user_id: str) -> list[Server]:
        return [server for server in self.servers.values() if user_id in server.members]

    def add_member(self, server_id: str, user_id: str) -> bool:
        server = self.servers.get(server_id)
        if server is None or user_id not in self.users:
            return False
        server.members.add(user_id)
        return True

    def create_channel(self, server_id: str, name: str) -> Channel | None:
        if server_id not in self.servers:
            return None
        channel = Channel(id=str(uuid4()), server_id=server_id, name=name)
        self.channels[channel.id] = channel
        self.messages[channel.id] = []
        return channel

    def get_channel(self, channel_id: str) -> Channel | None:
        return self.channels.get(channel_id)

    def list_channels(self, server_id: str) -> list[Channel]:
        return [channel for channel in self.channels.values() if channel.server_id == server_id]

    def add_message(self, message: Message) -> Message:
        self.messages.setdefault(message.channel_id, []).append(message)
        return message

    def list_messages(self, channel_id: str, limit: int = 100) -> list[Message]:
        return self.messages.get(channel_id, [])[-limit:]


class MongoStore:
    def __init__(self) -> None:
        self.client = MongoClient(settings.mongo_url, serverSelectionTimeoutMS=3000)
        self.database = self.client[settings.mongo_database]
        self.users = self.database.users
        self.servers = self.database.servers
        self.channels = self.database.channels
        self.messages = self.database.messages
        self.users.create_index("username", unique=True)
        self.servers.create_index("members")
        self.channels.create_index("server_id")
        self.messages.create_index([("channel_id", 1), ("created_at", 1)])

    @staticmethod
    def _user(document: dict | None) -> User | None:
        if document is None:
            return None
        return User(
            id=document["_id"],
            username=document["username"],
            password_hash=document["password_hash"],
            public_key=document.get("public_key"),
            created_at=document["created_at"],
        )

    @staticmethod
    def _server(document: dict | None) -> Server | None:
        if document is None:
            return None
        return Server(
            id=document["_id"],
            name=document["name"],
            owner_id=document["owner_id"],
            members=set(document.get("members", [])),
            created_at=document["created_at"],
        )

    @staticmethod
    def _channel(document: dict | None) -> Channel | None:
        if document is None:
            return None
        return Channel(
            id=document["_id"],
            server_id=document["server_id"],
            name=document["name"],
            created_at=document["created_at"],
        )

    @staticmethod
    def _message(document: dict | None) -> Message | None:
        if document is None:
            return None
        return Message(
            id=document["_id"],
            channel_id=document["channel_id"],
            sender_id=document["sender_id"],
            ciphertext=document["ciphertext"],
            nonce=document["nonce"],
            key_version=document["key_version"],
            created_at=document["created_at"],
        )

    def create_user(self, username: str, password_hash: str) -> User:
        user = User(id=str(uuid4()), username=username, password_hash=password_hash)
        self.users.insert_one({"_id": user.id, **user.__dict__})
        return user

    def get_user_by_username(self, username: str) -> User | None:
        return self._user(self.users.find_one({"username": username}))

    def get_user(self, user_id: str) -> User | None:
        return self._user(self.users.find_one({"_id": user_id}))

    def update_public_key(self, user_id: str, public_key: str) -> User | None:
        self.users.update_one({"_id": user_id}, {"$set": {"public_key": public_key}})
        return self.get_user(user_id)

    def create_server(self, name: str, owner_id: str) -> Server:
        server = Server(id=str(uuid4()), name=name, owner_id=owner_id, members={owner_id})
        self.servers.insert_one(
            {"_id": server.id, **server.__dict__, "members": list(server.members)}
        )
        return server

    def get_server(self, server_id: str) -> Server | None:
        return self._server(self.servers.find_one({"_id": server_id}))

    def list_servers(self, user_id: str) -> list[Server]:
        return [self._server(document) for document in self.servers.find({"members": user_id})]

    def add_member(self, server_id: str, user_id: str) -> bool:
        if self.get_server(server_id) is None or self.get_user(user_id) is None:
            return False
        self.servers.update_one({"_id": server_id}, {"$addToSet": {"members": user_id}})
        return True

    def create_channel(self, server_id: str, name: str) -> Channel | None:
        if self.get_server(server_id) is None:
            return None
        channel = Channel(id=str(uuid4()), server_id=server_id, name=name)
        self.channels.insert_one({"_id": channel.id, **channel.__dict__})
        return channel

    def get_channel(self, channel_id: str) -> Channel | None:
        return self._channel(self.channels.find_one({"_id": channel_id}))

    def list_channels(self, server_id: str) -> list[Channel]:
        return [
            self._channel(document) for document in self.channels.find({"server_id": server_id})
        ]

    def add_message(self, message: Message) -> Message:
        self.messages.insert_one({"_id": message.id, **message.__dict__})
        return message

    def list_messages(self, channel_id: str, limit: int = 100) -> list[Message]:
        cursor = self.messages.find({"channel_id": channel_id}).sort("created_at", -1).limit(limit)
        return list(reversed([self._message(document) for document in cursor]))


store = MongoStore() if settings.use_mongo else MemoryStore()
