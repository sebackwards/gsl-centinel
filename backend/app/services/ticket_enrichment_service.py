import logging
from typing import Any

import httpx
from motor.motor_asyncio import AsyncIOMotorDatabase

logger = logging.getLogger(__name__)


async def get_cached_ticket(
    db: AsyncIOMotorDatabase,
    ticket_key: Any,
) -> dict | None:
    doc = await db.ticket_cache.find_one({"key": ticket_key})
    if doc:
        doc.pop("_id", None)
    return doc


async def enrich_from_ticket(
    db: AsyncIOMotorDatabase,
    ticket_key: Any,
) -> dict | None:
    ticket = await get_cached_ticket(db, ticket_key)
    if not ticket:
        return None

    enrichment = {
        "ticket_key": ticket.get("key"),
        "summary": ticket.get("summary"),
        "status": ticket.get("status"),
        "priority": ticket.get("priority"),
        "labels": ticket.get("labels", []),
    }

    self_url = ticket.get("self_url")
    if self_url:
        from app.services.jira_service import validate_url_ssrf, SSRFProtectionError
        try:
            validate_url_ssrf(self_url)
        except SSRFProtectionError as e:
            logger.warning(f"Blocked invalid self_url for {ticket_key}: {e}")
            return enrichment

        try:
            async with httpx.AsyncClient(
                timeout=10.0,
                follow_redirects=True,
                max_redirects=5,
            ) as client:
                response = await client.get(
                    self_url,
                    headers={"Accept": "application/json"},
                )
            enrichment["fetched_url"] = str(response.url)
            if response.status_code == 200:
                live_data = response.json()
                fields = live_data.get("fields", {})
                enrichment["status"] = fields.get("status", {}).get("name", enrichment["status"])
                enrichment["resolution"] = fields.get("resolution", {}).get("name") if fields.get("resolution") else None
                enrichment["updated"] = fields.get("updated")
                logger.info(f"Enriched ticket {ticket_key} from live API")
        except Exception as e:
            logger.warning(f"Failed to fetch live data for {ticket_key}: {e}")

    return enrichment


async def store_ticket_in_cache(
    db: AsyncIOMotorDatabase,
    ticket_data: dict,
) -> None:
    key = ticket_data.get("key")
    if not key:
        return

    await db.ticket_cache.find_one_and_update(
        {"key": key},
        {"$set": ticket_data},
        upsert=True,
    )
