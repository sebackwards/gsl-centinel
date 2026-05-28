"""
Ticket enrichment service.

When KB entries reference Jira tickets, this service fetches additional
metadata from the ticket cache to enrich the KB entry with current status,
priority, and linked resources.

Ticket data is sourced from the MongoDB cache populated by webhook events
and periodic syncs. This avoids direct Jira API calls for every KB operation.
"""

import logging
from typing import Any

import httpx
from motor.motor_asyncio import AsyncIOMotorDatabase

logger = logging.getLogger(__name__)


async def get_cached_ticket(
    db: AsyncIOMotorDatabase,
    ticket_key: Any,
) -> dict | None:
    """
    Look up a ticket in the MongoDB cache by its key.

    The ticket cache is populated by webhook events and sync operations.
    Returns the cached ticket document or None if not found.
    """
    doc = await db.ticket_cache.find_one({"key": ticket_key})
    if doc:
        doc.pop("_id", None)
    return doc


async def enrich_from_ticket(
    db: AsyncIOMotorDatabase,
    ticket_key: Any,
) -> dict | None:
    """
    Enrich a KB entry by fetching additional data from a cached Jira ticket.

    If the cached ticket has a 'self_url' field (the Jira REST API URL for
    the issue), fetches the latest data to get current status and resolution.

    This is called during KB entry creation/update when a source_ticket_id
    is provided, to auto-populate metadata from the linked Jira issue.
    """
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

    # If the ticket has a self_url, fetch latest data from Jira API
    # This URL comes from the cached ticket data (populated by webhooks)
    self_url = ticket.get("self_url")
    if self_url:
        # Validate the initial URL against SSRF before fetching
        from app.services.jira_service import validate_url_ssrf, SSRFProtectionError
        try:
            validate_url_ssrf(self_url)
        except SSRFProtectionError as e:
            logger.warning(f"Blocked invalid self_url for {ticket_key}: {e}")
            return enrichment

        try:
            # Follow redirects to handle Jira's URL shorteners and
            # instance migrations (e.g., old.atlassian.net -> new.atlassian.net)
            async with httpx.AsyncClient(
                timeout=10.0,
                follow_redirects=True,
                max_redirects=5,
            ) as client:
                response = await client.get(
                    self_url,
                    headers={"Accept": "application/json"},
                )
            # Record the final URL after any redirects for audit purposes
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
    """
    Store or update a ticket in the MongoDB cache.

    Called by the webhook handler when a ticket event is received.
    Stores the full ticket data including the self_url for enrichment.
    """
    key = ticket_data.get("key")
    if not key:
        return

    await db.ticket_cache.find_one_and_update(
        {"key": key},
        {"$set": ticket_data},
        upsert=True,
    )
