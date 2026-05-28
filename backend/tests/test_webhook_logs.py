"""Tests for webhook delivery logs and ticket enrichment."""

import json

import pytest
from httpx import AsyncClient

from app.models.user import User


@pytest.mark.asyncio
async def test_webhook_logs_returns_empty_initially(
    client: AsyncClient, admin_user: User, admin_token: str
):
    """Webhook logs endpoint returns empty list when no deliveries exist."""
    res = await client.post(
        "/integrations/jira/webhook-logs/query",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={},
    )
    assert res.status_code == 200
    assert res.json()["logs"] == []
    assert res.json()["total"] == 0


@pytest.mark.asyncio
async def test_webhook_logs_records_delivery(
    client: AsyncClient, admin_user: User, admin_token: str
):
    """Webhook delivery is logged and queryable."""
    # Create a config without secret (no signature needed)
    create_res = await client.post(
        "/integrations/jira/configs",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "name": "Log Test",
            "base_url": "https://logtest.atlassian.net",
            "api_token": "token",
            "user_email": "bot@logtest.com",
            "project_key": "LOG",
        },
    )
    config_id = create_res.json()["id"]

    # Send a webhook event
    payload = {
        "webhookEvent": "jira:issue_created",
        "issue": {
            "key": "LOG-1",
            "self": "https://logtest.atlassian.net/rest/api/2/issue/LOG-1",
            "fields": {
                "summary": "Test issue",
                "status": {"name": "Open"},
            },
        },
    }
    await client.post(
        f"/integrations/jira/webhook/{config_id}",
        content=json.dumps(payload),
        headers={"Content-Type": "application/json"},
    )

    # Query logs
    res = await client.post(
        "/integrations/jira/webhook-logs/query",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"config_name": "Log Test"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["total"] >= 1
    assert data["logs"][0]["ticket_key"] == "LOG-1"
    assert data["logs"][0]["status"] == "delivered"


@pytest.mark.asyncio
async def test_webhook_logs_filter_by_event_type(
    client: AsyncClient, admin_user: User, admin_token: str
):
    """Can filter webhook logs by event type."""
    create_res = await client.post(
        "/integrations/jira/configs",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "name": "Filter Test",
            "base_url": "https://filter.atlassian.net",
            "api_token": "token",
            "user_email": "bot@filter.com",
            "project_key": "FLT",
        },
    )
    config_id = create_res.json()["id"]

    # Send two different event types
    for event, key in [("jira:issue_created", "FLT-1"), ("jira:issue_updated", "FLT-2")]:
        payload = {
            "webhookEvent": event,
            "issue": {"key": key, "fields": {"summary": "Test", "status": {"name": "Open"}}},
        }
        await client.post(
            f"/integrations/jira/webhook/{config_id}",
            content=json.dumps(payload),
            headers={"Content-Type": "application/json"},
        )

    # Filter by created only
    res = await client.post(
        "/integrations/jira/webhook-logs/query",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"event_type": "jira:issue_created"},
    )
    assert res.status_code == 200
    for log in res.json()["logs"]:
        assert log["event_type"] == "jira:issue_created"


@pytest.mark.asyncio
async def test_webhook_logs_requires_admin(
    client: AsyncClient, editor_user: User, editor_token: str
):
    """Non-admin users cannot access webhook logs."""
    res = await client.post(
        "/integrations/jira/webhook-logs/query",
        headers={"Authorization": f"Bearer {editor_token}"},
        json={},
    )
    assert res.status_code == 403


@pytest.mark.asyncio
async def test_enrich_ticket_from_cache(
    client: AsyncClient, admin_user: User, admin_token: str, mongo_db
):
    """Ticket enrichment returns cached ticket data."""
    # Seed a ticket in the cache
    await mongo_db.ticket_cache.insert_one({
        "key": "SEC-42",
        "summary": "Fix XSS in login form",
        "status": "In Progress",
        "priority": "High",
        "labels": ["security", "frontend"],
        "self_url": None,
    })

    res = await client.post(
        "/integrations/jira/enrich-ticket",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"ticket_key": "SEC-42"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["ticket_key"] == "SEC-42"
    assert data["summary"] == "Fix XSS in login form"
    assert data["status"] == "In Progress"
    assert "security" in data["labels"]


@pytest.mark.asyncio
async def test_enrich_ticket_not_found(
    client: AsyncClient, admin_user: User, admin_token: str
):
    """Enrichment returns 404 for unknown tickets."""
    res = await client.post(
        "/integrations/jira/enrich-ticket",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"ticket_key": "NONEXIST-999"},
    )
    assert res.status_code == 404


@pytest.mark.asyncio
async def test_webhook_stores_ticket_in_cache(
    client: AsyncClient, admin_user: User, admin_token: str, mongo_db
):
    """Webhook events populate the ticket cache for enrichment."""
    create_res = await client.post(
        "/integrations/jira/configs",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "name": "Cache Test",
            "base_url": "https://cache.atlassian.net",
            "api_token": "token",
            "user_email": "bot@cache.com",
            "project_key": "CCH",
        },
    )
    config_id = create_res.json()["id"]

    # Send webhook with self URL
    payload = {
        "webhookEvent": "jira:issue_updated",
        "issue": {
            "key": "CCH-7",
            "self": "https://cache.atlassian.net/rest/api/2/issue/CCH-7",
            "fields": {
                "summary": "Update dependencies",
                "status": {"name": "Done"},
                "priority": {"name": "Low"},
                "labels": ["maintenance"],
            },
        },
    }
    await client.post(
        f"/integrations/jira/webhook/{config_id}",
        content=json.dumps(payload),
        headers={"Content-Type": "application/json"},
    )

    # Verify ticket is in cache
    cached = await mongo_db.ticket_cache.find_one({"key": "CCH-7"})
    assert cached is not None
    assert cached["summary"] == "Update dependencies"
    assert cached["self_url"] == "https://cache.atlassian.net/rest/api/2/issue/CCH-7"


@pytest.mark.asyncio
async def test_enrich_ticket_follows_external_redirect(
    client: AsyncClient, admin_user: User, admin_token: str, mongo_db
):
    """Enrichment follows redirects to valid external Jira URLs.

    Jira Cloud sometimes redirects API requests when instances are
    migrated (e.g., old.atlassian.net -> new.atlassian.net). The
    enrichment service must follow these legitimate redirects.
    """
    from unittest.mock import patch
    import httpx as _httpx

    await mongo_db.ticket_cache.insert_one({
        "key": "MIG-1",
        "summary": "Migrated ticket",
        "status": "Open",
        "self_url": "https://old-instance.atlassian.net/rest/api/2/issue/MIG-1",
    })

    # Simulate: old URL redirects to new external URL which returns data
    redirect_response = _httpx.Response(
        302,
        headers={"Location": "https://new-instance.atlassian.net/rest/api/2/issue/MIG-1"},
        request=_httpx.Request("GET", "https://old-instance.atlassian.net/rest/api/2/issue/MIG-1"),
    )
    final_response = _httpx.Response(
        200,
        json={"fields": {"status": {"name": "Done"}, "resolution": {"name": "Fixed"}, "updated": "2026-05-28T10:00:00Z"}},
        request=_httpx.Request("GET", "https://new-instance.atlassian.net/rest/api/2/issue/MIG-1"),
    )

    call_count = [0]

    async def mock_send(self, request, **kwargs):
        call_count[0] += 1
        if "new-instance" in str(request.url):
            return final_response
        return redirect_response

    with patch("httpx.AsyncClient.send", mock_send):
        res = await client.post(
            "/integrations/jira/enrich-ticket",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={"ticket_key": "MIG-1"},
        )

    assert res.status_code == 200
    data = res.json()
    # The redirect was followed and live data was fetched
    assert data["status"] == "Done"
