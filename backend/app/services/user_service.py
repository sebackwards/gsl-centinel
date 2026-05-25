import secrets

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.password import hash_password
from app.models.user import User
from app.schemas.user import UserCreate, UserUpdate


async def create_user(db: AsyncSession, data: UserCreate) -> User:
    user = User(
        username=data.username,
        email=data.email,
        hashed_password=hash_password(data.password),
        role=data.role,
    )
    db.add(user)
    await db.flush()
    await db.refresh(user)
    return user


async def get_user_by_id(db: AsyncSession, user_id: str) -> User | None:
    result = await db.execute(select(User).where(User.id == user_id))
    return result.scalar_one_or_none()


async def get_user_by_username(db: AsyncSession, username: str) -> User | None:
    result = await db.execute(select(User).where(User.username == username))
    return result.scalar_one_or_none()


async def get_user_by_api_key(db: AsyncSession, api_key: str) -> User | None:
    result = await db.execute(select(User).where(User.api_key == api_key))
    return result.scalar_one_or_none()


async def get_user_by_email(db: AsyncSession, email: str) -> User | None:
    result = await db.execute(select(User).where(User.email == email))
    return result.scalar_one_or_none()


async def list_users(
    db: AsyncSession, skip: int = 0, limit: int = 50
) -> tuple[list[User], int]:
    count_result = await db.execute(select(func.count(User.id)))
    total = count_result.scalar_one()

    result = await db.execute(select(User).offset(skip).limit(limit))
    users = list(result.scalars().all())
    return users, total


async def update_user(db: AsyncSession, user_id: str, data: UserUpdate) -> User | None:
    user = await get_user_by_id(db, user_id)
    if not user:
        return None
    update_data = data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(user, field, value)
    await db.flush()
    await db.refresh(user)
    return user


async def delete_user(db: AsyncSession, user_id: str) -> bool:
    user = await get_user_by_id(db, user_id)
    if not user:
        return False
    user.is_active = False
    await db.flush()
    return True


async def generate_api_key(db: AsyncSession, user_id: str) -> str:
    user = await get_user_by_id(db, user_id)
    if not user:
        raise ValueError("User not found")
    api_key = secrets.token_hex(32)
    user.api_key = api_key
    await db.flush()
    return api_key
