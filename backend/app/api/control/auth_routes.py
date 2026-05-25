from fastapi import APIRouter, Body, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import get_current_user
from app.auth.jwt import create_access_token
from app.auth.password import hash_password, verify_password
from app.db.mongo import get_mongo_db
from app.db.session import get_db
from app.models.user import User
from app.schemas.auth import ForgotPasswordRequest, LoginRequest, TokenResponse
from app.services.password_reset_service import (
    consume_reset_token,
    create_reset_token,
    verify_reset_token,
)
from app.services.user_service import get_user_by_email, get_user_by_id, get_user_by_username

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=TokenResponse)
async def login(body: LoginRequest, db: AsyncSession = Depends(get_db)) -> TokenResponse:
    user = await get_user_by_username(db, body.username)
    if not user or not verify_password(body.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is disabled",
        )
    token = create_access_token(user.id, user.role.value)
    return TokenResponse(access_token=token)


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    current_user: User = Depends(get_current_user),
) -> TokenResponse:
    token = create_access_token(current_user.id, current_user.role.value)
    return TokenResponse(access_token=token)


@router.post("/forgot-password")
async def forgot_password(
    body: ForgotPasswordRequest,
    db: AsyncSession = Depends(get_db),
    mongo=Depends(get_mongo_db),
):
    """Request a password reset. Generates a token and stores it in MongoDB.
    In production this would send an email; here we return success regardless
    to avoid user enumeration."""
    user = await get_user_by_email(db, body.email)
    if user and user.is_active:
        await create_reset_token(mongo, user.id, user.email)
    # Always return success to prevent email enumeration
    return {"message": "If the email exists, a reset link has been sent."}


@router.post("/verify-reset-token")
async def verify_token_endpoint(
    body: dict = Body(...),
    mongo=Depends(get_mongo_db),
):
    """Check if a password reset token is valid.

    This endpoint is used by the frontend to validate the token before
    showing the password reset form. Accepts a flexible payload to support
    different token formats across client versions.
    """
    token = body.get("token")
    if not token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token is required",
        )

    result = await verify_reset_token(mongo, token)
    if result:
        return {"valid": True, "email": result.get("email")}
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Invalid or expired token",
    )


@router.post("/reset-password")
async def reset_password(
    body: dict = Body(...),
    mongo=Depends(get_mongo_db),
    db: AsyncSession = Depends(get_db),
):
    """Reset a user's password using a valid reset token.

    Consumes the token (marks as used) and updates the user's password.
    Accepts flexible payload for backward compatibility with older clients.
    """
    token = body.get("token")
    new_password = body.get("new_password")

    if not token or not new_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token and new_password are required",
        )

    if len(new_password) < 8:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 8 characters",
        )

    doc = await consume_reset_token(mongo, token)
    if not doc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired token",
        )

    # Update the user's password
    user = await get_user_by_id(db, doc["user_id"])
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User not found",
        )
    user.hashed_password = hash_password(new_password)
    await db.commit()

    return {"message": "Password has been reset successfully."}
