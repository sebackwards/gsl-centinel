"""Jira integration schemas for request/response validation."""
from datetime import datetime

from pydantic import BaseModel, Field, field_validator


class JiraConfigCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    base_url: str = Field(..., min_length=1, max_length=500)
    api_token: str = Field(..., min_length=1)
    user_email: str = Field(..., min_length=1, max_length=255)
    project_key: str = Field(..., min_length=1, max_length=20, pattern="^[A-Z][A-Z0-9_]+$")
    webhook_secret: str | None = None

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, v: str) -> str:
        """Ensure the base URL is a valid HTTPS Jira instance URL."""
        v = v.rstrip("/")
        if not v.startswith("https://"):
            raise ValueError("Jira base URL must use HTTPS")
        return v


class JiraConfigUpdate(BaseModel):
    name: str | None = None
    base_url: str | None = None
    api_token: str | None = None
    user_email: str | None = None
    project_key: str | None = None
    webhook_secret: str | None = None
    is_active: bool | None = None

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, v: str | None) -> str | None:
        if v is None:
            return v
        v = v.rstrip("/")
        if not v.startswith("https://"):
            raise ValueError("Jira base URL must use HTTPS")
        return v


class JiraConfigResponse(BaseModel):
    id: str
    name: str
    base_url: str
    user_email: str
    project_key: str
    is_active: bool
    last_sync_at: datetime | None
    created_by: str
    created_at: datetime
    updated_at: datetime | None

    model_config = {"from_attributes": True}


class JiraConfigListResponse(BaseModel):
    configs: list[JiraConfigResponse]
    total: int


class JiraTestConnectionResponse(BaseModel):
    success: bool
    message: str
    server_info: dict | None = None


class JiraTicket(BaseModel):
    key: str
    summary: str
    status: str
    priority: str | None = None
    assignee: str | None = None
    created: datetime | None = None
    updated: datetime | None = None
    labels: list[str] = []


class JiraSyncResponse(BaseModel):
    synced_count: int
    errors: list[str] = []
    cached_until: datetime | None = None


class JiraWebhookPayload(BaseModel):
    """Incoming Jira webhook event payload."""
    webhook_event: str = Field(..., alias="webhookEvent")
    issue_event_type: str | None = Field(None, alias="issue_event_type_name")
    issue: dict | None = None
    user: dict | None = None
    timestamp: int | None = None

    model_config = {"populate_by_name": True}
