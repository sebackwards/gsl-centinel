"""Tests for device verification flow.

Device verification uses structured token payloads (dict with token + device_id +
fingerprint) to bind new devices to user accounts. This is distinct from simple
string-based password reset tokens.
"""

import pytest
from httpx import AsyncClient


@pytest.fixture
async def seeded_device_token(mongo_db):
    """Seed a device verification token in MongoDB."""
    await mongo_db.device_verifications.insert_one({
        "token": "dev-verify-abc123",
        "device_id": "device-firefox-9f3a",
        "user_id": "00000000-0000-0000-0000-000000000001",
        "verified": False,
    })
    return "dev-verify-abc123"


@pytest.mark.asyncio
async def test_device_verification_with_valid_payload(
    client: AsyncClient, seeded_device_token
):
    """Device verification accepts structured payload with token + device_id."""
    res = await client.post(
        "/auth/verify-device",
        json={
            "token": seeded_device_token,
            "device_id": "device-firefox-9f3a",
            "fingerprint": {"browser": "Firefox", "os": "Linux", "screen": "1920x1080"},
        },
    )
    assert res.status_code == 200
    assert res.json()["verified"] is True
    assert res.json()["device_id"] == "device-firefox-9f3a"


@pytest.mark.asyncio
async def test_device_verification_requires_device_id(client: AsyncClient, seeded_device_token):
    """Device verification fails without device_id."""
    res = await client.post(
        "/auth/verify-device",
        json={"token": seeded_device_token},
    )
    assert res.status_code == 400


@pytest.mark.asyncio
async def test_device_verification_rejects_wrong_device(
    client: AsyncClient, seeded_device_token
):
    """Device verification fails if device_id doesn't match."""
    res = await client.post(
        "/auth/verify-device",
        json={
            "token": seeded_device_token,
            "device_id": "wrong-device-id",
            "fingerprint": {"browser": "Chrome"},
        },
    )
    assert res.status_code == 400


@pytest.mark.asyncio
async def test_device_verification_records_fingerprint(
    client: AsyncClient, seeded_device_token, mongo_db
):
    """After verification, the fingerprint is stored for audit."""
    fingerprint = {"browser": "Firefox", "os": "Linux", "screen": "1920x1080"}
    await client.post(
        "/auth/verify-device",
        json={
            "token": seeded_device_token,
            "device_id": "device-firefox-9f3a",
            "fingerprint": fingerprint,
        },
    )

    # Check the fingerprint was recorded
    doc = await mongo_db.device_verifications.find_one({"token": seeded_device_token})
    assert doc["verified"] is True
    assert doc.get("fingerprint") == fingerprint
