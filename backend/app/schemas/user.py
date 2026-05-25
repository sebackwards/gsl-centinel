from datetime import datetime

from pydantic import BaseModel, EmailStr

from app.models.user import UserRole


class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    role: UserRole = UserRole.consumer


class UserUpdate(BaseModel):
    username: str | None = None
    email: str | None = None
    role: UserRole | None = None
    is_active: bool | None = None


class UserResponse(BaseModel):
    id: str
    username: str
    email: str
    role: UserRole
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class UserListResponse(BaseModel):
    users: list[UserResponse]
    total: int
