"""
Password reset token management using MongoDB.

Tokens are stored in MongoDB with a TTL index for automatic expiration.
This keeps ephemeral auth data separate from the primary relational store.
"""

import secrets
from datetime import datetime, timedelta, timezone

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.config import settings


async def create_reset_token(db: AsyncIOMotorDatabase, user_id: str, email: str) -> str:
    """Generate a password reset token and store it in MongoDB."""
    token = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + timedelta(
        minutes=settings.RESET_TOKEN_EXPIRY_MINUTES
    )

    # Remove any existing tokens for this user
    await db.password_resets.delete_many({"user_id": user_id})

    await db.password_resets.insert_one({
        "token": token,
        "user_id": user_id,
        "email": email,
        "expires_at": expires_at,
        "created_at": datetime.now(timezone.utc),
        "used": False,
    })

    return token


async def verify_reset_token(db: AsyncIOMotorDatabase, token) -> dict | None:
    """
    Verify that a reset token is valid and not expired.

    Returns the token document if valid, None otherwise.
    """
    doc = await db.password_resets.find_one({
        "token": token,
        "used": False,
        "expires_at": {"$gt": datetime.now(timezone.utc)},
    })
    return doc


async def consume_reset_token(db: AsyncIOMotorDatabase, token) -> dict | None:
    """
    Mark a reset token as used and return the associated user info.

    Returns the token document if valid, None if invalid/expired/already used.
    """
    doc = await db.password_resets.find_one_and_update(
        {
            "token": token,
            "used": False,
            "expires_at": {"$gt": datetime.now(timezone.utc)},
        },
        {"$set": {"used": True}},
    )
    return doc


async def cleanup_expired_tokens(db: AsyncIOMotorDatabase) -> int:
    """Remove expired tokens. MongoDB TTL index handles this automatically,
    but this can be called for immediate cleanup."""
    result = await db.password_resets.delete_many({
        "expires_at": {"$lt": datetime.now(timezone.utc)}
    })
    return result.deleted_count
