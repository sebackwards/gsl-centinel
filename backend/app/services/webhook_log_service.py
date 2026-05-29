import logging
from datetime import datetime, timezone
from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase

logger = logging.getLogger(__name__)


async def log_webhook_delivery(
    db: AsyncIOMotorDatabase,
    config_id: str,
    config_name: str,
    retry_auth_ref: str | None,
    event_type: str,
    ticket_key: str,
    status: str,
    error: str | None = None,
) -> None:
    await db.webhook_deliveries.insert_one({
        "config_id": config_id,
        "config_name": config_name,
        "retry_auth_ref": retry_auth_ref,
        "event_type": event_type,
        "ticket_key": ticket_key,
        "status": status,
        "error": error,
        "delivered_at": datetime.now(timezone.utc),
    })


async def get_delivery_logs(
    db: AsyncIOMotorDatabase,
    filter_params: dict[str, Any],
    limit: int = 50,
) -> list[dict]:
    _BLOCKED_OPS = {"$ne", "$gt", "$lt", "$gte", "$lte", "$in", "$nin", "$exists"}

    query = {}
    for key, value in filter_params.items():
        if value is not None:
            if isinstance(value, dict):
                if any(op in value for op in _BLOCKED_OPS):
                    logger.warning(f"Blocked operator in filter key '{key}': {list(value.keys())}")
                    continue
            query[key] = value

    results = []
    cursor = db.webhook_deliveries.find(query).sort("delivered_at", -1).limit(limit)
    async for doc in cursor:
        doc.pop("_id", None)
        results.append(doc)
    return results


async def get_delivery_status(
    db: AsyncIOMotorDatabase,
    config_name: str,
) -> dict | None:
    doc = await db.webhook_deliveries.find_one(
        {"config_name": config_name},
        sort=[("delivered_at", -1)],
    )
    if doc:
        doc.pop("_id", None)
    return doc
