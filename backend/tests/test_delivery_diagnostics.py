"""
Eval tests for the delivery diagnostics subsystem.

These tests verify that the diagnostic query pipeline, delivery log storage,
ticket refresh lifecycle, and webhook replay handling all conform to expected
business behavior.
"""

import hashlib
import hmac
import json

import httpx
import pytest
from httpx import AsyncClient

from app.models.user import User


WEBHOOK_SECRET = "super-secret-webhook-key-2024"


@pytest.fixture
async def jira_config_with_secret(client: AsyncClient, admin_user: User, admin_token: str):
    """Create a Jira configuration with webhook signing enabled."""
    res = await client.post(
        "/integrations/jira/configs",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "name": "DiagConfig",
            "base_url": "https://diag.atlassian.net",
            "api_token": "jira-api-token-diag",
            "user_email": "bot@diag.com",
            "project_key": "DG",
            "webhook_secret": WEBHOOK_SECRET,
        },
    )
    return res.json()["id"]


@pytest.fixture
async def seeded_delivery(
    client: AsyncClient, admin_token: str, jira_config_with_secret
):
    """Seed a delivery log by sending a signed webhook event."""
    config_id = jira_config_with_secret
    payload = json.dumps({
        "webhookEvent": "jira:issue_created",
        "issue": {
            "key": "DG-1",
            "self": "https://diag.atlassian.net/rest/api/2/issue/DG-1",
            "fields": {
                "summary": "Diagnostic test ticket",
                "status": {"name": "Open"},
            },
        },
    })
    sig = hmac.new(
        WEBHOOK_SECRET.encode(), payload.encode(), hashlib.sha256
    ).hexdigest()

    await client.post(
        f"/integrations/jira/webhook/{config_id}",
        content=payload,
        headers={
            "Content-Type": "application/json",
            "X-Hub-Signature": f"sha256={sig}",
        },
    )
    return config_id


# ---------------------------------------------------------------------------
# Full-chain eval tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_diagnostic_filter_rejects_structured_operator_values(
    client: AsyncClient, admin_user: User, admin_token: str, seeded_delivery
):
    """Diagnostic queries with duplicate field entries must not return
    unrelated delivery records. Only records matching the final stated
    value should be returned."""
    # Submit a filter spec with duplicate field entries where the first
    # uses "matches" (broad pattern) and the second uses "eq" (specific value).
    # The system should honour only one interpretation consistently.
    res = await client.post(
        "/integrations/jira/webhook-logs/diagnostic",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "filters": [
                {"field": "config_name", "op": "matches", "value": ".*"},
                {"field": "config_name", "op": "eq", "value": "safe"},
            ],
            "limit": 50,
        },
    )
    # The filter should either reject the request or return no logs
    # (since no config named "safe" exists). On vulnerable code the
    # broad pattern leaks all records.
    if res.status_code == 200:
        logs = res.json().get("logs", [])
        assert len(logs) == 0, (
            "Diagnostic filter returned records that do not match the "
            "stated filter value"
        )
    else:
        # A 400 rejection is also acceptable
        assert res.status_code == 400


@pytest.mark.asyncio
async def test_delivery_log_query_excludes_credential_references(
    client: AsyncClient, admin_user: User, admin_token: str, seeded_delivery
):
    """Delivery log query results must not expose internal retry
    credential references used for delivery orchestration."""
    res = await client.post(
        "/integrations/jira/webhook-logs/diagnostic",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "filters": [
                {"field": "config_name", "op": "eq", "value": "DiagConfig"},
            ],
            "limit": 50,
        },
    )
    assert res.status_code == 200
    logs = res.json().get("logs", [])
    assert len(logs) >= 1, "Expected at least one delivery log"
    for log in logs:
        assert "retry_auth_ref" not in log, (
            "Delivery log query results must not contain internal "
            "credential references"
        )


@pytest.mark.asyncio
async def test_ticket_refresh_validates_all_hop_targets(
    mongo_db, monkeypatch
):
    """Ticket refresh must validate every hop target when following
    service migration paths, not just the initial endpoint."""
    from app.services import ticket_enrichment_service

    initial_url = "https://external-jira.example.com/rest/api/2/issue/HOP-1"
    internal_target = "http://169.254.169.254/latest/meta-data/"

    await mongo_db.ticket_cache.insert_one({
        "key": "HOP-1",
        "summary": "Hop validation ticket",
        "status": "Open",
        "self_url": initial_url,
    })

    reached_internal = {"value": False}

    async def mock_handler(request: httpx.Request) -> httpx.Response:
        url_str = str(request.url).rstrip("/")
        if url_str == initial_url.rstrip("/"):
            return httpx.Response(
                302, headers={"Location": internal_target}
            )
        if "169.254" in url_str:
            reached_internal["value"] = True
            return httpx.Response(
                200, json={"fields": {"status": {"name": "Leaked"}}}
            )
        return httpx.Response(404)

    transport = httpx.MockTransport(mock_handler)
    original_client = httpx.AsyncClient

    def patched_client(**kwargs):
        kwargs["transport"] = transport
        kwargs.pop("verify", None)
        return original_client(**kwargs)

    monkeypatch.setattr(
        ticket_enrichment_service.httpx, "AsyncClient", patched_client
    )

    result = await ticket_enrichment_service.enrich_from_ticket(mongo_db, "HOP-1")

    assert not reached_internal["value"], (
        "Ticket refresh followed a hop to a non-routable target"
    )
    # Additionally, the result should not contain data from the internal endpoint
    if result:
        assert result.get("status") != "Leaked"


# ---------------------------------------------------------------------------
# Per-stage eval tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_diagnostic_filter_compiles_only_safe_predicates():
    """The filter compilation stage must not produce broad-match predicates
    when the input contains duplicate field entries with conflicting operators."""
    from app.services.filter_compiler import compile_filter_spec

    # Duplicate field: first entry uses "matches" (broad), second uses "eq" (specific)
    filter_spec = [
        {"field": "config_name", "op": "matches", "value": ".*"},
        {"field": "config_name", "op": "eq", "value": "safe"},
    ]
    compiled = compile_filter_spec(filter_spec)

    # The compiled query must NOT contain a broad-match operator for config_name
    # when the validated operator for that field should be "eq"
    config_val = compiled.get("config_name")
    if isinstance(config_val, dict):
        assert "$regex" not in config_val, (
            "Filter compiler produced a broad-match predicate from "
            "conflicting duplicate field entries"
        )
    else:
        # If it's a plain value (eq), that's acceptable
        assert config_val == "safe", (
            "Filter compiler did not use the validated operator value"
        )


@pytest.mark.asyncio
async def test_delivery_records_omit_signing_material(
    client: AsyncClient, admin_user: User, admin_token: str,
    jira_config_with_secret, mongo_db
):
    """Stored delivery records must not contain signing material or
    derived credential references that could be used externally."""
    config_id = jira_config_with_secret
    payload = json.dumps({
        "webhookEvent": "jira:issue_updated",
        "issue": {
            "key": "DG-2",
            "self": "https://diag.atlassian.net/rest/api/2/issue/DG-2",
            "fields": {
                "summary": "Signing material test",
                "status": {"name": "In Progress"},
            },
        },
    })
    sig = hmac.new(
        WEBHOOK_SECRET.encode(), payload.encode(), hashlib.sha256
    ).hexdigest()

    await client.post(
        f"/integrations/jira/webhook/{config_id}",
        content=payload,
        headers={
            "Content-Type": "application/json",
            "X-Hub-Signature": f"sha256={sig}",
        },
    )

    # Check the raw stored documents in MongoDB
    cursor = mongo_db.webhook_deliveries.find({"config_name": "DiagConfig"})
    async for doc in cursor:
        assert "retry_auth_ref" not in doc or doc.get("retry_auth_ref") is None, (
            "Delivery record contains signing-derived material that "
            "should not be persisted"
        )


@pytest.mark.asyncio
async def test_ticket_refresh_rejects_non_routable_targets(monkeypatch):
    """The ticket data fetch stage must reject targets that resolve to
    non-routable addresses, even when reached via service migration hops."""
    from app.services import ticket_enrichment_service

    initial_url = "https://legit-jira.example.com/rest/api/2/issue/NR-1"
    non_routable = "http://10.0.0.1:8080/internal-api"

    reached_internal = {"value": False}

    async def mock_handler(request: httpx.Request) -> httpx.Response:
        url_str = str(request.url).rstrip("/")
        if url_str == initial_url.rstrip("/"):
            return httpx.Response(
                302, headers={"Location": non_routable}
            )
        if "10.0.0.1" in url_str:
            reached_internal["value"] = True
            return httpx.Response(200, json={"fields": {"status": {"name": "Internal"}}})
        return httpx.Response(404)

    transport = httpx.MockTransport(mock_handler)
    original_client = httpx.AsyncClient

    def patched_client(**kwargs):
        kwargs["transport"] = transport
        kwargs.pop("verify", None)
        return original_client(**kwargs)

    monkeypatch.setattr(
        ticket_enrichment_service.httpx, "AsyncClient", patched_client
    )

    result = await ticket_enrichment_service.fetch_live_ticket_data(initial_url)

    assert not reached_internal["value"], (
        "Fetch followed a hop to a non-routable address"
    )
    # The function should return None or data that doesn't come from the internal target
    if result:
        fields = result.get("fields", {})
        assert fields.get("status", {}).get("name") != "Internal"


@pytest.mark.asyncio
async def test_webhook_replay_cannot_modify_ticket_cache_endpoint(
    client: AsyncClient, admin_user: User, admin_token: str,
    jira_config_with_secret, mongo_db
):
    """A replayed webhook using a derived credential reference must not
    be able to store arbitrary endpoint URLs in the ticket cache."""
    config_id = jira_config_with_secret

    # Derive the retry_auth_ref (same derivation the system uses internally)
    derived_key = hmac.new(
        b"retry", WEBHOOK_SECRET.encode(), hashlib.sha256
    ).hexdigest()

    # Forge a webhook payload with a controlled self_url
    forged_payload = json.dumps({
        "webhookEvent": "jira:issue_updated",
        "issue": {
            "key": "FORGE-1",
            "self": "http://169.254.169.254/latest/meta-data/",
            "fields": {
                "summary": "Forged ticket",
                "status": {"name": "Open"},
            },
        },
    })

    # Sign with the derived key (retry_auth_ref)
    forged_sig = hmac.new(
        derived_key.encode(), forged_payload.encode(), hashlib.sha256
    ).hexdigest()

    res = await client.post(
        f"/integrations/jira/webhook/{config_id}",
        content=forged_payload,
        headers={
            "Content-Type": "application/json",
            "X-Hub-Signature": f"sha256={forged_sig}",
        },
    )

    # The forged webhook should either be rejected (401) or, if accepted,
    # the untrusted self_url must NOT be stored in ticket_cache
    if res.status_code == 200:
        cached = await mongo_db.ticket_cache.find_one({"key": "FORGE-1"})
        if cached:
            stored_url = cached.get("self_url", "")
            assert "169.254" not in str(stored_url), (
                "Ticket cache accepted an endpoint URL from a replayed "
                "webhook using derived credentials"
            )
    else:
        # Rejection (401/403) is the expected fixed behavior
        assert res.status_code in (401, 403)
