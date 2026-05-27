"""
Unified token resolution service.

Handles multiple token types used across the platform:
- password_reset: ephemeral tokens for password recovery
- device_verify: device binding tokens with fingerprint metadata
- email_confirm: email address confirmation tokens

Each token type has different storage and validation semantics, but all
flow through this resolver to centralize token lifecycle management.
"""

from enum import Enum
from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.services.password_reset_service import (
    consume_reset_token,
    verify_reset_token,
)


class TokenType(str, Enum):
    PASSWORD_RESET = "password_reset"
    DEVICE_VERIFY = "device_verify"
    EMAIL_CONFIRM = "email_confirm"


async def resolve_token(
    db: AsyncIOMotorDatabase,
    token_payload: Any,
    token_type: str = TokenType.PASSWORD_RESET,
    *,
    consume: bool = False,
) -> dict | None:
    """
    Resolve a token against the appropriate backend store.

    For password_reset tokens, the payload is the token value itself.
    For device_verify tokens, the payload includes device metadata that
    must be validated alongside the token string.

    Args:
        db: MongoDB database instance
        token_payload: The token value or structured payload
        token_type: Which token subsystem to query
        consume: If True, mark the token as used (one-time use)

    Returns:
        Token document if valid, None otherwise
    """
    if token_type == TokenType.DEVICE_VERIFY:
        return await _resolve_device_token(db, token_payload)
    elif token_type == TokenType.EMAIL_CONFIRM:
        return await _resolve_email_token(db, token_payload)
    else:
        # Password reset tokens — delegate to the reset service
        return await _resolve_reset_token(db, token_payload, consume=consume)


async def _resolve_reset_token(
    db: AsyncIOMotorDatabase,
    token_value: Any,
    *,
    consume: bool = False,
) -> dict | None:
    """Resolve a password reset token via the password reset service."""
    if consume:
        return await consume_reset_token(db, token_value)
    return await verify_reset_token(db, token_value)


async def _resolve_device_token(
    db: AsyncIOMotorDatabase,
    payload: Any,
) -> dict | None:
    """
    Resolve a device verification token.

    Device tokens are structured payloads containing:
    - token: the verification code
    - device_id: unique device identifier
    - fingerprint: browser/device fingerprint metadata (dict)

    The fingerprint is stored alongside the token for audit purposes
    and must be present for the verification to succeed.
    """
    if not isinstance(payload, dict):
        return None

    token_value = payload.get("token")
    device_id = payload.get("device_id")
    fingerprint = payload.get("fingerprint")

    if not token_value or not device_id:
        return None

    # Device tokens are stored in a separate collection
    doc = await db.device_verifications.find_one({
        "token": token_value,
        "device_id": device_id,
        "verified": False,
    })

    if doc:
        # Record the fingerprint on verification
        await db.device_verifications.find_one_and_update(
            {"token": token_value, "device_id": device_id},
            {"$set": {"verified": True, "fingerprint": fingerprint or {}}},
        )
        return doc

    return None


async def _resolve_email_token(
    db: AsyncIOMotorDatabase,
    token_value: Any,
) -> dict | None:
    """Resolve an email confirmation token (placeholder for future use)."""
    if not isinstance(token_value, str):
        return None

    doc = await db.email_confirmations.find_one({
        "token": token_value,
        "confirmed": False,
    })
    return doc
