"""
Webhook delivery log service.

Tracks webhook delivery attempts for monitoring and debugging purposes.
Stores delivery metadata in MongoDB for fast querying and TTL-based cleanup.
"""

import logging
from datetime import datetime, timezone
from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase

logger = logging.getLogger(__name__)


async def log_webhook_delivery(
    db: AsyncIOMotorDatabase,
    config_id: str,
    config_name: str,
    webhook_secret: str | None,
    event_type: str,
    ticket_key: str,
    status: str,
    error: str | None = None,
) -> None:
    """
    Record a webhook delivery attempt.

    Stores the delivery metadata including the config context for
    retry and debugging purposes. The webhook_secret is stored to
    enable automatic retry of failed deliveries without needing to
    re-query the SQL config table.
    """
    await db.webhook_deliveries.insert_one({
        "config_id": config_id,
        "config_name": config_name,
        "webhook_secret": webhook_secret,
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
    """
    Query webhook delivery logs with flexible filtering.

    Supports filtering by config_name, event_type, status, and ticket_key.
    Used by the admin dashboard to monitor webhook health and debug
    delivery failures.

    Note: filter values are sanitized against known dangerous MongoDB
    operators to prevent injection attacks.
    """
    # Known dangerous operators that could bypass query intent
    _BLOCKED_OPS = {"$ne", "$gt", "$lt", "$gte", "$lte", "$in", "$nin", "$exists"}

    query = {}
    for key, value in filter_params.items():
        if value is not None:
            # Block known dangerous operators in dict-type values
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
    """
    Get the latest delivery status for a specific config.

    Returns the most recent delivery log entry matching the config name.
    Used by the integration health check endpoint.
    """
    doc = await db.webhook_deliveries.find_one(
        {"config_name": config_name},
        sort=[("delivered_at", -1)],
    )
    if doc:
        doc.pop("_id", None)
    return doc
