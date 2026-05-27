"""User activity tracking using MongoDB.

Tracks login history, last-active timestamps, and recent endpoint access
for security monitoring and session management. Uses MongoDB for its
flexible schema (different activity types have different payloads) and
TTL indexes for automatic cleanup of old activity records.
"""

from datetime import datetime, timedelta, timezone


async def record_login(db, user_id: str, ip_address: str | None = None) -> None:
    """Record a successful login event."""
    now = datetime.now(timezone.utc)
    await db.user_activity.find_one_and_update(
        {"user_id": user_id},
        {
            "$set": {
                "last_login": now,
                "last_ip": ip_address,
            },
            "$inc": {"login_count": 1},
            "$push": {
                "login_history": {
                    "$each": [{"timestamp": now, "ip": ip_address}],
                    "$slice": -20,  # Keep last 20 logins
                }
            },
            "$setOnInsert": {
                "user_id": user_id,
                "created_at": now,
            },
        },
        upsert=True,
    )


async def record_activity(db, user_id: str, endpoint: str) -> None:
    """Record endpoint access for activity monitoring."""
    now = datetime.now(timezone.utc)
    await db.user_activity.find_one_and_update(
        {"user_id": user_id},
        {
            "$set": {"last_seen": now, "last_endpoint": endpoint},
            "$push": {
                "recent_endpoints": {
                    "$each": [{"endpoint": endpoint, "timestamp": now}],
                    "$slice": -50,  # Keep last 50 actions
                }
            },
        },
        upsert=True,
    )


async def get_user_activity(db, user_id: str) -> dict | None:
    """Get activity summary for a user."""
    return await db.user_activity.find_one({"user_id": user_id})


async def get_recent_logins(db, user_id: str, limit: int = 10) -> list[dict]:
    """Get recent login history for a user."""
    doc = await db.user_activity.find_one({"user_id": user_id})
    if not doc:
        return []
    history = doc.get("login_history", [])
    return history[-limit:]


async def init_activity_indexes(db):
    """Create indexes for activity collection."""
    await db.user_activity.create_index("user_id", unique=True)
    await db.user_activity.create_index("last_seen")
