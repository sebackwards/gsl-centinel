import json

import pytest
from httpx import AsyncClient

from app.models.user import User


@pytest.mark.asyncio
async def test_diagnostic_endpoint_returns_logs_for_valid_filter(
    client: AsyncClient, admin_user: User, admin_token: str
):
    """Admin can query delivery logs via the diagnostic endpoint with a valid filter."""
    create_res = await client.post(
        "/integrations/jira/configs",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "name": "DiagHappy",
            "base_url": "https://diaghappy.atlassian.net",
            "api_token": "token",
            "user_email": "bot@diaghappy.com",
            "project_key": "DH",
        },
    )
    config_id = create_res.json()["id"]

    payload = {
        "webhookEvent": "jira:issue_created",
        "issue": {
            "key": "DH-1",
            "self": "https://diaghappy.atlassian.net/rest/api/2/issue/DH-1",
            "fields": {
                "summary": "Happy path ticket",
                "status": {"name": "Open"},
            },
        },
    }
    await client.post(
        f"/integrations/jira/webhook/{config_id}",
        content=json.dumps(payload),
        headers={"Content-Type": "application/json"},
    )

    res = await client.post(
        "/integrations/jira/webhook-logs/diagnostic",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "filters": [
                {"field": "config_name", "op": "eq", "value": "DiagHappy"}
            ],
            "limit": 10,
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["total"] >= 1
    assert data["logs"][0]["config_name"] == "DiagHappy"
