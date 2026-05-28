import hashlib
import hmac
import ipaddress
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlparse

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.jira import JiraConfig
from app.schemas.jira import JiraConfigCreate, JiraConfigUpdate, JiraTicket

logger = logging.getLogger(__name__)

TICKET_CACHE_TTL = 300


class SSRFProtectionError(Exception):
    pass


def validate_url_ssrf(url: str) -> str:
    parsed = urlparse(url)

    if parsed.scheme != "https":
        raise SSRFProtectionError("Only HTTPS URLs are allowed")

    hostname = parsed.hostname
    if not hostname:
        raise SSRFProtectionError("URL must have a valid hostname")

    blocked_suffixes = (".internal", ".local", ".localhost", ".corp", ".lan")
    blocked_exact = ("localhost", "metadata", "metadata.google.internal")
    if hostname.lower() in blocked_exact:
        raise SSRFProtectionError(f"Hostname '{hostname}' is not allowed")
    if any(hostname.lower().endswith(s) for s in blocked_suffixes):
        raise SSRFProtectionError(f"Hostname '{hostname}' is not allowed")

    try:
        addr = ipaddress.ip_address(hostname)
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
            raise SSRFProtectionError(
                f"IP address {hostname} is in a restricted range"
            )
    except ValueError:
        pass

    return url


async def resolve_and_validate_url(url: str) -> str:
    import socket

    parsed = urlparse(url)
    hostname = parsed.hostname

    validate_url_ssrf(url)

    try:
        addr_info = socket.getaddrinfo(hostname, parsed.port or 443)
        for family, _, _, _, sockaddr in addr_info:
            ip = sockaddr[0]
            try:
                addr = ipaddress.ip_address(ip)
                if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
                    raise SSRFProtectionError(
                        f"Hostname '{hostname}' resolves to restricted IP {ip}"
                    )
            except ValueError:
                continue
    except socket.gaierror:
        raise SSRFProtectionError(f"Cannot resolve hostname '{hostname}'")

    return url


async def test_jira_connection(config: JiraConfig) -> dict[str, Any]:
    url = f"{config.base_url}/rest/api/2/serverInfo"

    await resolve_and_validate_url(url)

    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(
            url,
            auth=(config.user_email, config.api_token),
            headers={"Accept": "application/json"},
        )

    if response.status_code == 200:
        data = response.json()
        return {
            "success": True,
            "message": "Connection successful",
            "server_info": {
                "version": data.get("version"),
                "deployment_type": data.get("deploymentType"),
                "server_title": data.get("serverTitle"),
            },
        }
    elif response.status_code == 401:
        return {"success": False, "message": "Authentication failed", "server_info": None}
    elif response.status_code == 403:
        return {"success": False, "message": "Access denied", "server_info": None}
    else:
        return {"success": False, "message": f"Unexpected response: {response.status_code}", "server_info": None}


async def sync_tickets(
    config: JiraConfig,
    redis_client: Any | None = None,
    since: datetime | None = None,
) -> dict[str, Any]:
    jql = f"project = {config.project_key} ORDER BY updated DESC"
    if since:
        since_str = since.strftime("%Y-%m-%d %H:%M")
        jql = f"project = {config.project_key} AND updated >= '{since_str}' ORDER BY updated DESC"

    url = f"{config.base_url}/rest/api/2/search"

    await resolve_and_validate_url(url)

    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.get(
            url,
            params={"jql": jql, "maxResults": 50, "fields": "summary,status,priority,assignee,created,updated,labels"},
            auth=(config.user_email, config.api_token),
            headers={"Accept": "application/json"},
        )

    if response.status_code != 200:
        return {"synced_count": 0, "errors": [f"Jira API error: {response.status_code}"]}

    data = response.json()
    issues = data.get("issues", [])
    tickets: list[dict] = []

    for issue in issues:
        fields = issue.get("fields", {})
        ticket = {
            "key": issue["key"],
            "summary": fields.get("summary", ""),
            "status": fields.get("status", {}).get("name", "Unknown"),
            "priority": fields.get("priority", {}).get("name") if fields.get("priority") else None,
            "assignee": fields.get("assignee", {}).get("displayName") if fields.get("assignee") else None,
            "created": fields.get("created"),
            "updated": fields.get("updated"),
            "labels": fields.get("labels", []),
        }
        tickets.append(ticket)

    cached_until = None
    if redis_client:
        cache_key = f"jira:tickets:{config.id}"
        await redis_client.set(
            cache_key,
            json.dumps(tickets, default=str),
            ex=TICKET_CACHE_TTL,
        )
        cached_until = datetime.now(timezone.utc) + timedelta(seconds=TICKET_CACHE_TTL)

    return {
        "synced_count": len(tickets),
        "errors": [],
        "cached_until": cached_until,
    }


async def get_cached_tickets(
    config_id: str,
    redis_client: Any,
) -> list[dict] | None:
    cache_key = f"jira:tickets:{config_id}"
    cached = await redis_client.get(cache_key)
    if cached:
        return json.loads(cached)
    return None


def verify_webhook_signature(
    payload_body: bytes,
    signature_header: str,
    secret: str,
) -> bool:
    if not signature_header or not secret:
        return False

    expected = hmac.new(
        secret.encode("utf-8"),
        payload_body,
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(f"sha256={expected}", signature_header)


async def process_webhook_event(
    event_type: str,
    issue_data: dict | None,
    config: JiraConfig,
    mongo_db: Any | None = None,
    redis_client: Any | None = None,
) -> dict[str, Any]:
    if not issue_data:
        return {"processed": False, "reason": "No issue data in payload"}

    key = issue_data.get("key", "unknown")
    fields = issue_data.get("fields", {})

    ticket = {
        "key": key,
        "summary": fields.get("summary", ""),
        "status": fields.get("status", {}).get("name", "Unknown"),
        "priority": fields.get("priority", {}).get("name") if fields.get("priority") else None,
        "assignee": fields.get("assignee", {}).get("displayName") if fields.get("assignee") else None,
        "labels": fields.get("labels", []),
        "self_url": issue_data.get("self"),
        "updated": datetime.now(timezone.utc).isoformat(),
    }

    if mongo_db:
        from app.services.ticket_enrichment_service import store_ticket_in_cache
        await store_ticket_in_cache(mongo_db, ticket)

        from app.services.webhook_log_service import log_webhook_delivery
        await log_webhook_delivery(
            db=mongo_db,
            config_id=config.id,
            config_name=config.name,
            webhook_secret=config.webhook_secret,
            event_type=event_type,
            ticket_key=key,
            status="delivered",
        )

    if redis_client:
        ticket_key = f"jira:ticket:{config.id}:{key}"
        await redis_client.set(
            ticket_key,
            json.dumps(ticket, default=str),
            ex=TICKET_CACHE_TTL,
        )

    logger.info(f"Processed webhook event '{event_type}' for {key}")
    return {"processed": True, "ticket_key": key, "event": event_type}


async def create_jira_config(
    db: AsyncSession, user_id: str, data: JiraConfigCreate
) -> JiraConfig:
    validate_url_ssrf(data.base_url)

    config = JiraConfig(
        name=data.name,
        base_url=data.base_url,
        api_token=data.api_token,
        user_email=data.user_email,
        project_key=data.project_key,
        webhook_secret=data.webhook_secret,
        created_by=user_id,
    )
    db.add(config)
    await db.flush()
    await db.refresh(config)
    return config


async def get_jira_config(db: AsyncSession, config_id: str) -> JiraConfig | None:
    result = await db.execute(select(JiraConfig).where(JiraConfig.id == config_id))
    return result.scalar_one_or_none()


async def list_jira_configs(db: AsyncSession) -> list[JiraConfig]:
    result = await db.execute(
        select(JiraConfig).order_by(JiraConfig.created_at.desc())
    )
    return list(result.scalars().all())


async def update_jira_config(
    db: AsyncSession, config_id: str, data: JiraConfigUpdate
) -> JiraConfig | None:
    config = await get_jira_config(db, config_id)
    if not config:
        return None

    update_data = data.model_dump(exclude_unset=True)

    if "base_url" in update_data:
        validate_url_ssrf(update_data["base_url"])

    for field, value in update_data.items():
        setattr(config, field, value)

    await db.flush()
    await db.refresh(config)
    return config


async def delete_jira_config(db: AsyncSession, config_id: str) -> bool:
    config = await get_jira_config(db, config_id)
    if not config:
        return False
    await db.delete(config)
    await db.flush()
    return True
