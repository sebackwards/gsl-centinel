from datetime import datetime, timedelta, timezone

from app.config import settings


async def check_rate_limit(
    db,
    user_id: str,
    endpoint: str,
    max_requests: int = 100,
    window_seconds: int = 60,
) -> dict:
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(seconds=window_seconds)

    doc = await db.rate_limits.find_one_and_update(
        {
            "user_id": user_id,
            "endpoint": endpoint,
            "window_start": {"$gte": window_start},
        },
        {
            "$inc": {"count": 1},
            "$setOnInsert": {
                "user_id": user_id,
                "endpoint": endpoint,
                "window_start": now,
                "expires_at": now + timedelta(seconds=window_seconds),
            },
        },
        upsert=True,
        return_document=True,
    )

    count = doc.get("count", 1) if doc else 1
    allowed = count <= max_requests
    remaining = max(0, max_requests - count)
    reset_at = doc.get("expires_at", now + timedelta(seconds=window_seconds)) if doc else now + timedelta(seconds=window_seconds)

    return {
        "allowed": allowed,
        "remaining": remaining,
        "reset_at": reset_at,
    }


async def get_rate_limit_status(db, user_id: str, endpoint: str) -> dict | None:
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(seconds=60)

    doc = await db.rate_limits.find_one({
        "user_id": user_id,
        "endpoint": endpoint,
        "window_start": {"$gte": window_start},
    })
    return doc


async def init_rate_limit_indexes(db):
    await db.rate_limits.create_index("expires_at", expireAfterSeconds=0)
