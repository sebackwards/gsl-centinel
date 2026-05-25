"""
MongoDB connection for ephemeral token storage.

Password reset tokens are short-lived and high-throughput during incidents.
A document store with TTL indexes is the standard pattern for this kind of
ephemeral data — keeps the relational DB clean and leverages MongoDB's
native expiration capabilities.
"""

from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase

from app.config import settings

_client: AsyncIOMotorClient | None = None
_db: AsyncIOMotorDatabase | None = None


async def init_mongo():
    """Initialize MongoDB connection and indexes."""
    global _client, _db
    _client = AsyncIOMotorClient(settings.MONGO_URL)
    _db = _client[settings.MONGO_DB_NAME]
    await _db.password_resets.create_index("expires_at", expireAfterSeconds=0)


async def get_mongo_db() -> AsyncIOMotorDatabase:
    """FastAPI dependency for MongoDB access."""
    global _db
    if _db is None:
        await init_mongo()
    return _db


async def close_mongo():
    global _client, _db
    if _client:
        _client.close()
        _client = None
        _db = None
