import pytest
from httpx import AsyncClient

from app.models.user import User


@pytest.mark.asyncio
async def test_admin_can_list_users(
    client: AsyncClient, admin_user: User, admin_token: str
):
    response = await client.get(
        "/admin/users",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "users" in data
    assert "total" in data
    assert data["total"] >= 1


@pytest.mark.asyncio
async def test_admin_can_create_user(
    client: AsyncClient, admin_user: User, admin_token: str
):
    response = await client.post(
        "/admin/users",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "username": "newuser",
            "email": "newuser@gsl.local",
            "password": "newpass123",
            "role": "consumer",
        },
    )
    assert response.status_code == 201
    data = response.json()
    assert data["username"] == "newuser"
    assert data["email"] == "newuser@gsl.local"
    assert data["role"] == "consumer"
    assert "id" in data


@pytest.mark.asyncio
async def test_admin_can_update_user(
    client: AsyncClient, admin_user: User, consumer_user: User, admin_token: str
):
    response = await client.put(
        f"/admin/users/{consumer_user.id}",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"role": "editor"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["role"] == "editor"


@pytest.mark.asyncio
async def test_admin_can_delete_user(
    client: AsyncClient, admin_user: User, consumer_user: User, admin_token: str
):
    response = await client.delete(
        f"/admin/users/{consumer_user.id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 204


@pytest.mark.asyncio
async def test_editor_cannot_manage_users(
    client: AsyncClient, editor_user: User, editor_token: str
):
    response = await client.get(
        "/admin/users",
        headers={"Authorization": f"Bearer {editor_token}"},
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_consumer_cannot_manage_users(
    client: AsyncClient, consumer_user: User, consumer_token: str
):
    response = await client.get(
        "/admin/users",
        headers={"Authorization": f"Bearer {consumer_token}"},
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_create_user_duplicate_username(
    client: AsyncClient, admin_user: User, admin_token: str
):
    await client.post(
        "/admin/users",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "username": "duplicate",
            "email": "dup1@gsl.local",
            "password": "pass123",
            "role": "consumer",
        },
    )
    response = await client.post(
        "/admin/users",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "username": "duplicate",
            "email": "dup2@gsl.local",
            "password": "pass123",
            "role": "consumer",
        },
    )
    assert response.status_code in (400, 409, 422, 500)


@pytest.mark.asyncio
async def test_create_user_duplicate_email(
    client: AsyncClient, admin_user: User, admin_token: str
):
    await client.post(
        "/admin/users",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "username": "user_a",
            "email": "same@gsl.local",
            "password": "pass123",
            "role": "consumer",
        },
    )
    response = await client.post(
        "/admin/users",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "username": "user_b",
            "email": "same@gsl.local",
            "password": "pass123",
            "role": "consumer",
        },
    )
    assert response.status_code in (400, 409, 422, 500)
