from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import require_admin
from app.db.session import get_db
from app.models.user import User
from app.schemas.user import UserCreate, UserListResponse, UserResponse, UserUpdate
from app.services.user_service import (
    create_user,
    delete_user,
    get_user_by_id,
    list_users,
    update_user,
)

router = APIRouter(prefix="/admin/users", tags=["admin"])


@router.get("", response_model=UserListResponse)
async def get_users(
    skip: int = 0,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_admin),
) -> UserListResponse:
    users, total = await list_users(db, skip=skip, limit=limit)
    return UserListResponse(
        users=[UserResponse.model_validate(u) for u in users],
        total=total,
    )


@router.post("", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_new_user(
    body: UserCreate,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_admin),
) -> UserResponse:
    from sqlalchemy.exc import IntegrityError

    try:
        user = await create_user(db, body)
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username or email already exists",
        )
    return UserResponse.model_validate(user)


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_admin),
) -> UserResponse:
    user = await get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )
    return UserResponse.model_validate(user)


@router.put("/{user_id}", response_model=UserResponse)
async def update_existing_user(
    user_id: str,
    body: UserUpdate,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_admin),
) -> UserResponse:
    user = await update_user(db, user_id, body)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )
    return UserResponse.model_validate(user)


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def soft_delete_user(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_admin),
) -> None:
    deleted = await delete_user(db, user_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )
