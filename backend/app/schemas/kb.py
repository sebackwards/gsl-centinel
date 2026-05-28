from datetime import datetime

from pydantic import BaseModel, Field


class KBEntryCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=255)
    summary: str = Field(..., min_length=1)
    content: str = Field(..., min_length=1)
    category: str = Field(..., min_length=1, max_length=100)
    severity: str = Field(default="medium", pattern="^(critical|high|medium|low|info)$")
    cwe: str | None = None
    source_ticket_id: str | None = None


class KBEntryUpdate(BaseModel):
    title: str | None = None
    summary: str | None = None
    content: str | None = None
    category: str | None = None
    severity: str | None = None
    cwe: str | None = None
    source_ticket_id: str | None = None


class KBEntryResponse(BaseModel):
    id: str
    title: str
    summary: str
    content: str
    category: str
    cwe: str | None
    severity: str
    source_ticket_id: str | None
    created_by: str
    created_at: datetime
    updated_at: datetime | None

    model_config = {"from_attributes": True}


class KBEntryListResponse(BaseModel):
    entries: list[KBEntryResponse]
    total: int


class KBSearchRequest(BaseModel):
    query: str = Field(..., min_length=1)
    limit: int = Field(default=5, ge=1, le=20)
    category: str | None = None


class KBSearchResult(BaseModel):
    entry_id: str
    entry_title: str
    chunk_content: str
    chunk_type: str
    score: float


class KBSearchResponse(BaseModel):
    results: list[KBSearchResult]
    query: str
