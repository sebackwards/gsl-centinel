from fastapi import APIRouter, Body, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import get_current_user
from app.auth.jwt import create_access_token
from app.auth.password import hash_password, verify_password
from app.db.mongo import get_mongo_db
from app.db.session import get_db
from app.models.user import User
from app.schemas.auth import ForgotPasswordRequest, LoginRequest, TokenResponse
from app.services.password_reset_service import create_reset_token
from app.services.token_resolver import TokenType, resolve_token
from app.services.user_service import get_user_by_email, get_user_by_id, get_user_by_username

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=TokenResponse)
async def login(body: LoginRequest, db: AsyncSession = Depends(get_db)) -> TokenResponse:
    # Rate limit login attempts
    try:
        from app.services.rate_limiter import check_rate_limit
        mongo_db = await get_mongo_db()
        limit_result = await check_rate_limit(mongo_db, body.username, "/auth/login", max_requests=10, window_seconds=300)
        if not limit_result["allowed"]:
            raise HTTPException(status_code=429, detail="Too many login attempts. Try again later.")
    except HTTPException:
        raise
    except Exception:
        pass  # Rate limiting is non-critical

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

    # Track login activity
    try:
        from app.services.activity_tracker import record_login
        mongo = await get_mongo_db()
        await record_login(mongo, user.id, None)
    except Exception:
        pass  # Activity tracking is non-critical

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
    both simple token strings and structured device-bound tokens via the
    unified token resolver.
    """
    token_value = body.get("token")
    if not token_value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token is required",
        )

    # Determine token type from payload context
    token_type = body.get("token_type", TokenType.PASSWORD_RESET)

    result = await resolve_token(mongo, token_value, token_type)
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
    Accepts flexible payload for backward compatibility with older clients
    and to support device-bound reset flows.
    """
    token_value = body.get("token")
    new_password = body.get("new_password")

    if not token_value or not new_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token and new_password are required",
        )

    if len(new_password) < 8:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 8 characters",
        )

    # Resolve and consume the token via the unified resolver
    token_type = body.get("token_type", TokenType.PASSWORD_RESET)
    doc = await resolve_token(mongo, token_value, token_type, consume=True)
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


@router.post("/verify-device")
async def verify_device(
    body: dict = Body(...),
    mongo=Depends(get_mongo_db),
):
    """Verify a device binding token.

    Device verification tokens are structured payloads that include
    the token, device_id, and an optional browser fingerprint. This
    endpoint is called after a user confirms a new device via email link.

    The fingerprint metadata is recorded for audit trail purposes.
    """
    token_payload = {
        "token": body.get("token"),
        "device_id": body.get("device_id"),
        "fingerprint": body.get("fingerprint"),
    }

    if not token_payload["token"] or not token_payload["device_id"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token and device_id are required",
        )

    result = await resolve_token(
        mongo, token_payload, TokenType.DEVICE_VERIFY
    )
    if result:
        return {"verified": True, "device_id": result.get("device_id")}
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Invalid or expired device token",
    )


@router.get("/me/activity")
async def get_my_activity(
    current_user: User = Depends(get_current_user),
    mongo=Depends(get_mongo_db),
):
    """Get the current user's recent activity and login history."""
    from app.services.activity_tracker import get_user_activity
    activity = await get_user_activity(mongo, current_user.id)
    if not activity:
        return {"login_count": 0, "last_login": None, "recent_logins": []}
    return {
        "login_count": activity.get("login_count", 0),
        "last_login": activity.get("last_login"),
        "last_seen": activity.get("last_seen"),
        "recent_logins": activity.get("login_history", [])[-5:],
    }
