"""Tests for the password reset flow using MongoDB token storage."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_forgot_password_returns_success_for_existing_user(
    client: AsyncClient, admin_user
):
    """Requesting a reset for a valid email returns success."""
    res = await client.post(
        "/auth/forgot-password",
        json={"email": "admin@gsl.local"},
    )
    assert res.status_code == 200
    assert "reset link" in res.json()["message"].lower() or "sent" in res.json()["message"].lower()


@pytest.mark.asyncio
async def test_forgot_password_returns_success_for_unknown_email(client: AsyncClient):
    """Returns success even for unknown emails (prevents enumeration)."""
    res = await client.post(
        "/auth/forgot-password",
        json={"email": "nobody@example.com"},
    )
    assert res.status_code == 200


@pytest.mark.asyncio
async def test_verify_valid_reset_token(client: AsyncClient, admin_user, mongo_db):
    """A valid token returns valid=True."""
    from app.services.password_reset_service import create_reset_token

    token = await create_reset_token(mongo_db, admin_user.id, admin_user.email)

    res = await client.post(
        "/auth/verify-reset-token",
        json={"token": token},
    )
    assert res.status_code == 200
    assert res.json()["valid"] is True


@pytest.mark.asyncio
async def test_verify_invalid_token_returns_400(client: AsyncClient):
    """An invalid token returns 400."""
    res = await client.post(
        "/auth/verify-reset-token",
        json={"token": "nonexistent-token-value"},
    )
    assert res.status_code == 400


@pytest.mark.asyncio
async def test_reset_password_with_valid_token(
    client: AsyncClient, admin_user, mongo_db, db_session
):
    """A valid token allows password reset."""
    from app.services.password_reset_service import create_reset_token

    token = await create_reset_token(mongo_db, admin_user.id, admin_user.email)

    res = await client.post(
        "/auth/reset-password",
        json={"token": token, "new_password": "newpassword123"},
    )
    assert res.status_code == 200
    assert "successfully" in res.json()["message"].lower()


@pytest.mark.asyncio
async def test_reset_password_token_cannot_be_reused(
    client: AsyncClient, admin_user, mongo_db
):
    """A token can only be used once."""
    from app.services.password_reset_service import create_reset_token

    token = await create_reset_token(mongo_db, admin_user.id, admin_user.email)

    # First use succeeds
    res1 = await client.post(
        "/auth/reset-password",
        json={"token": token, "new_password": "newpassword123"},
    )
    assert res1.status_code == 200

    # Second use fails
    res2 = await client.post(
        "/auth/reset-password",
        json={"token": token, "new_password": "anotherpassword"},
    )
    assert res2.status_code == 400


@pytest.mark.asyncio
async def test_reset_password_rejects_short_password(
    client: AsyncClient, admin_user, mongo_db
):
    """Password must be at least 8 characters."""
    from app.services.password_reset_service import create_reset_token

    token = await create_reset_token(mongo_db, admin_user.id, admin_user.email)

    res = await client.post(
        "/auth/reset-password",
        json={"token": token, "new_password": "short"},
    )
    assert res.status_code == 400
    assert "8 characters" in res.json()["detail"]
