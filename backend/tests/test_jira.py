import hashlib
import hmac
import json

import pytest
from httpx import AsyncClient

from app.models.user import User


@pytest.mark.asyncio
async def test_admin_can_create_jira_config(
    client: AsyncClient, admin_user: User, admin_token: str
):
    res = await client.post(
        "/integrations/jira/configs",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "name": "Production Jira",
            "base_url": "https://mycompany.atlassian.net",
            "api_token": "secret-token-123",
            "user_email": "bot@mycompany.com",
            "project_key": "SEC",
        },
    )
    assert res.status_code == 201
    data = res.json()
    assert data["name"] == "Production Jira"
    assert data["base_url"] == "https://mycompany.atlassian.net"
    assert data["project_key"] == "SEC"
    assert data["is_active"] is True
    assert "api_token" not in data


@pytest.mark.asyncio
async def test_editor_cannot_create_jira_config(
    client: AsyncClient, editor_user: User, editor_token: str
):
    res = await client.post(
        "/integrations/jira/configs",
        headers={"Authorization": f"Bearer {editor_token}"},
        json={
            "name": "Test",
            "base_url": "https://test.atlassian.net",
            "api_token": "token",
            "user_email": "bot@test.com",
            "project_key": "TST",
        },
    )
    assert res.status_code == 403


@pytest.mark.asyncio
async def test_admin_can_list_jira_configs(
    client: AsyncClient, admin_user: User, admin_token: str
):
    await client.post(
        "/integrations/jira/configs",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "name": "Test Jira",
            "base_url": "https://test.atlassian.net",
            "api_token": "token",
            "user_email": "bot@test.com",
            "project_key": "TST",
        },
    )

    res = await client.get(
        "/integrations/jira/configs",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["total"] >= 1
    assert len(data["configs"]) >= 1


@pytest.mark.asyncio
async def test_admin_can_update_jira_config(
    client: AsyncClient, admin_user: User, admin_token: str
):
    create_res = await client.post(
        "/integrations/jira/configs",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "name": "Old Name",
            "base_url": "https://old.atlassian.net",
            "api_token": "token",
            "user_email": "bot@old.com",
            "project_key": "OLD",
        },
    )
    config_id = create_res.json()["id"]

    res = await client.put(
        f"/integrations/jira/configs/{config_id}",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"name": "New Name", "project_key": "NEW"},
    )
    assert res.status_code == 200
    assert res.json()["name"] == "New Name"
    assert res.json()["project_key"] == "NEW"


@pytest.mark.asyncio
async def test_admin_can_delete_jira_config(
    client: AsyncClient, admin_user: User, admin_token: str
):
    create_res = await client.post(
        "/integrations/jira/configs",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "name": "To Delete",
            "base_url": "https://delete.atlassian.net",
            "api_token": "token",
            "user_email": "bot@delete.com",
            "project_key": "DEL",
        },
    )
    config_id = create_res.json()["id"]

    res = await client.delete(
        f"/integrations/jira/configs/{config_id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert res.status_code == 204

    res = await client.get(
        f"/integrations/jira/configs/{config_id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert res.status_code == 404


@pytest.mark.asyncio
async def test_ssrf_blocks_localhost(
    client: AsyncClient, admin_user: User, admin_token: str
):
    res = await client.post(
        "/integrations/jira/configs",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "name": "Evil",
            "base_url": "https://localhost:8080",
            "api_token": "token",
            "user_email": "bot@evil.com",
            "project_key": "EVL",
        },
    )
    assert res.status_code == 400
    assert "not allowed" in res.json()["detail"].lower()


@pytest.mark.asyncio
async def test_ssrf_blocks_internal_ip(
    client: AsyncClient, admin_user: User, admin_token: str
):
    res = await client.post(
        "/integrations/jira/configs",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "name": "Evil",
            "base_url": "https://192.168.1.1",
            "api_token": "token",
            "user_email": "bot@evil.com",
            "project_key": "EVL",
        },
    )
    assert res.status_code == 400
    assert "restricted" in res.json()["detail"].lower()


@pytest.mark.asyncio
async def test_ssrf_blocks_metadata_endpoint(
    client: AsyncClient, admin_user: User, admin_token: str
):
    res = await client.post(
        "/integrations/jira/configs",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "name": "Evil",
            "base_url": "https://169.254.169.254",
            "api_token": "token",
            "user_email": "bot@evil.com",
            "project_key": "EVL",
        },
    )
    assert res.status_code == 400


@pytest.mark.asyncio
async def test_ssrf_blocks_internal_domain(
    client: AsyncClient, admin_user: User, admin_token: str
):
    for domain in ["https://jira.internal", "https://jira.corp", "https://service.local"]:
        res = await client.post(
            "/integrations/jira/configs",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={
                "name": "Evil",
                "base_url": domain,
                "api_token": "token",
                "user_email": "bot@evil.com",
                "project_key": "EVL",
            },
        )
        assert res.status_code == 400, f"Expected 400 for {domain}, got {res.status_code}"


@pytest.mark.asyncio
async def test_ssrf_blocks_http_scheme(
    client: AsyncClient, admin_user: User, admin_token: str
):
    res = await client.post(
        "/integrations/jira/configs",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "name": "Evil",
            "base_url": "http://mycompany.atlassian.net",
            "api_token": "token",
            "user_email": "bot@evil.com",
            "project_key": "EVL",
        },
    )
    assert res.status_code == 400 or res.status_code == 422


@pytest.mark.asyncio
async def test_valid_external_url_is_accepted(
    client: AsyncClient, admin_user: User, admin_token: str
):
    res = await client.post(
        "/integrations/jira/configs",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "name": "Valid Jira",
            "base_url": "https://mycompany.atlassian.net",
            "api_token": "token",
            "user_email": "bot@mycompany.com",
            "project_key": "SEC",
        },
    )
    assert res.status_code == 201


@pytest.mark.asyncio
async def test_webhook_processes_valid_event(
    client: AsyncClient, admin_user: User, admin_token: str
):
    create_res = await client.post(
        "/integrations/jira/configs",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "name": "Webhook Test",
            "base_url": "https://webhook.atlassian.net",
            "api_token": "token",
            "user_email": "bot@webhook.com",
            "project_key": "WBH",
        },
    )
    config_id = create_res.json()["id"]

    payload = {
        "webhookEvent": "jira:issue_updated",
        "issue_event_type_name": "issue_generic",
        "issue": {
            "key": "WBH-123",
            "fields": {
                "summary": "Fix login bug",
                "status": {"name": "In Progress"},
                "priority": {"name": "High"},
                "assignee": {"displayName": "Alice"},
                "labels": ["security", "urgent"],
            },
        },
    }

    res = await client.post(
        f"/integrations/jira/webhook/{config_id}",
        content=json.dumps(payload),
        headers={"Content-Type": "application/json"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["processed"] is True
    assert data["ticket_key"] == "WBH-123"


@pytest.mark.asyncio
async def test_webhook_rejects_invalid_signature(
    client: AsyncClient, admin_user: User, admin_token: str
):
    create_res = await client.post(
        "/integrations/jira/configs",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "name": "Signed Webhook",
            "base_url": "https://signed.atlassian.net",
            "api_token": "token",
            "user_email": "bot@signed.com",
            "project_key": "SIG",
            "webhook_secret": "my-secret-key",
        },
    )
    config_id = create_res.json()["id"]

    payload = json.dumps({"webhookEvent": "jira:issue_created", "issue": {"key": "SIG-1", "fields": {}}})

    res = await client.post(
        f"/integrations/jira/webhook/{config_id}",
        content=payload,
        headers={
            "Content-Type": "application/json",
            "X-Hub-Signature": "sha256=invalid",
        },
    )
    assert res.status_code == 401


@pytest.mark.asyncio
async def test_webhook_requires_signature_when_secret_configured(
    client: AsyncClient, admin_user: User, admin_token: str
):
    create_res = await client.post(
        "/integrations/jira/configs",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "name": "Requires Sig",
            "base_url": "https://reqsig.atlassian.net",
            "api_token": "token",
            "user_email": "bot@reqsig.com",
            "project_key": "RSG",
            "webhook_secret": "another-secret",
        },
    )
    config_id = create_res.json()["id"]

    payload = json.dumps({"webhookEvent": "jira:issue_created", "issue": {"key": "RSG-1", "fields": {}}})

    res = await client.post(
        f"/integrations/jira/webhook/{config_id}",
        content=payload,
        headers={"Content-Type": "application/json"},
    )
    assert res.status_code == 401


@pytest.mark.asyncio
async def test_webhook_accepts_valid_signature(
    client: AsyncClient, admin_user: User, admin_token: str
):
    secret = "valid-webhook-secret"
    create_res = await client.post(
        "/integrations/jira/configs",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "name": "Valid Sig",
            "base_url": "https://valsig.atlassian.net",
            "api_token": "token",
            "user_email": "bot@valsig.com",
            "project_key": "VSG",
            "webhook_secret": secret,
        },
    )
    config_id = create_res.json()["id"]

    payload = json.dumps({"webhookEvent": "jira:issue_updated", "issue": {"key": "VSG-42", "fields": {"summary": "Test", "status": {"name": "Done"}}}})
    payload_bytes = payload.encode("utf-8")

    sig = hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()

    res = await client.post(
        f"/integrations/jira/webhook/{config_id}",
        content=payload,
        headers={
            "Content-Type": "application/json",
            "X-Hub-Signature": f"sha256={sig}",
        },
    )
    assert res.status_code == 200
    assert res.json()["processed"] is True


@pytest.mark.asyncio
async def test_connection_test_returns_failure_for_unreachable(
    client: AsyncClient, admin_user: User, admin_token: str
):
    create_res = await client.post(
        "/integrations/jira/configs",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "name": "Conn Test",
            "base_url": "https://conntest.atlassian.net",
            "api_token": "token",
            "user_email": "bot@conntest.com",
            "project_key": "CNT",
        },
    )
    config_id = create_res.json()["id"]

    res = await client.post(
        f"/integrations/jira/configs/{config_id}/test",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is False
    assert "message" in data
