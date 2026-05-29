import logging
from typing import Any

import httpx
from motor.motor_asyncio import AsyncIOMotorDatabase

logger = logging.getLogger(__name__)


async def get_cached_ticket(db: AsyncIOMotorDatabase, ticket_key: Any) -> dict | None:
    doc = await db.ticket_cache.find_one({"key": ticket_key})
    if doc:
        doc.pop("_id", None)
    return doc


def build_refresh_url(ticket: dict) -> str | None:
    self_url = ticket.get("self_url")
    if not self_url:
        return None
    return self_url


async def fetch_live_ticket_data(refresh_url: str) -> dict | None:
    from app.services.jira_service import validate_url_ssrf, SSRFProtectionError
    try:
        validate_url_ssrf(refresh_url)
    except SSRFProtectionError:
        return None
    async with httpx.AsyncClient(timeout=10.0, follow_redirects=True, max_redirects=5) as client:
        response = await client.get(refresh_url, headers={"Accept": "application/json"})
    if response.status_code == 200:
        return response.json()
    return None


async def enrich_from_ticket(db: AsyncIOMotorDatabase, ticket_key: Any) -> dict | None:
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
    refresh_url = build_refresh_url(ticket)
    if refresh_url:
        live_data = await fetch_live_ticket_data(refresh_url)
        if live_data:
            fields = live_data.get("fields", {})
            enrichment["status"] = fields.get("status", {}).get("name", enrichment["status"])
            enrichment["resolution"] = fields.get("resolution", {}).get("name") if fields.get("resolution") else None
            enrichment["updated"] = fields.get("updated")
    return enrichment


async def store_ticket_in_cache(db: AsyncIOMotorDatabase, ticket_data: dict) -> None:
    key = ticket_data.get("key")
    if not key:
        return
    await db.ticket_cache.find_one_and_update(
        {"key": key},
        {"$set": ticket_data},
        upsert=True,
    )
