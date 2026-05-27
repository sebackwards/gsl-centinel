"""Tests for user activity tracking and rate limiting."""
import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_login_records_activity(client: AsyncClient, admin_user, mongo_db):
    """Successful login should record activity in MongoDB."""
    resp = await client.post(
        "/auth/login",
        json={"username": "admin", "password": "admin123"},
    )
    assert resp.status_code == 200

    # Check activity was recorded
    activity = await mongo_db.user_activity.find_one({"user_id": admin_user.id})
    assert activity is not None
    assert activity.get("login_count", 0) >= 1


@pytest.mark.asyncio
async def test_rate_limit_blocks_excessive_attempts(client: AsyncClient, admin_user):
    """Too many login attempts should return 429."""
    # Make 11 attempts (limit is 10 per 5 minutes)
    for i in range(11):
        resp = await client.post(
            "/auth/login",
            json={"username": "admin", "password": "wrong"},
        )
        if resp.status_code == 429:
            break
    assert resp.status_code == 429
    assert "Too many" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_activity_endpoint_returns_data(
    client: AsyncClient, admin_token: str, admin_user, mongo_db
):
    """GET /auth/me/activity returns user activity."""
    # First login to generate activity
    await client.post(
        "/auth/login",
        json={"username": "admin", "password": "admin123"},
    )

    resp = await client.get(
        "/auth/me/activity",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "login_count" in data


@pytest.mark.asyncio
async def test_activity_endpoint_requires_auth(client: AsyncClient):
    """GET /auth/me/activity requires authentication."""
    resp = await client.get("/auth/me/activity")
    assert resp.status_code == 401
