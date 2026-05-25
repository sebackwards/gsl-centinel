import pytest
from httpx import AsyncClient

from app.models.user import User


@pytest.mark.asyncio
async def test_login_valid_credentials(client: AsyncClient, admin_user: User):
    response = await client.post(
        "/auth/login",
        json={"username": "admin", "password": "admin123"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"


@pytest.mark.asyncio
async def test_login_invalid_password(client: AsyncClient, admin_user: User):
    response = await client.post(
        "/auth/login",
        json={"username": "admin", "password": "wrongpassword"},
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid credentials"


@pytest.mark.asyncio
async def test_login_unknown_user(client: AsyncClient):
    response = await client.post(
        "/auth/login",
        json={"username": "nonexistent", "password": "whatever"},
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid credentials"


@pytest.mark.asyncio
async def test_protected_route_without_token(client: AsyncClient):
    response = await client.get("/admin/users")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_protected_route_with_valid_token(
    client: AsyncClient, admin_user: User, admin_token: str
):
    response = await client.get(
        "/admin/users",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_api_key_authentication(client: AsyncClient, admin_user: User):
    response = await client.get(
        "/admin/users",
        headers={"X-API-Key": admin_user.api_key},
    )
    assert response.status_code == 200
