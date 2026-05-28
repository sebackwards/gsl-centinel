from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import get_current_user, require_editor
from app.db.session import get_db
from app.models.user import User
from app.schemas.kb import (
    KBEntryCreate,
    KBEntryListResponse,
    KBEntryResponse,
    KBEntryUpdate,
    KBSearchRequest,
    KBSearchResponse,
)
from app.services.kb.kb_service import (
    create_entry,
    delete_entry,
    get_entry,
    list_entries,
    search_entries,
    update_entry,
)

router = APIRouter(prefix="/api/v1/kb", tags=["knowledge-base"])


@router.get("/entries", response_model=KBEntryListResponse)
async def list_kb_entries(
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    category: str | None = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    entries, total = await list_entries(db, skip=skip, limit=limit, category=category)
    return KBEntryListResponse(
        entries=[KBEntryResponse.model_validate(e) for e in entries],
        total=total,
    )


@router.get("/entries/{entry_id}", response_model=KBEntryResponse)
async def get_kb_entry(
    entry_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    entry = await get_entry(db, entry_id)
    if not entry:
        raise HTTPException(status_code=404, detail="Entry not found")
    return KBEntryResponse.model_validate(entry)


@router.post("/entries", response_model=KBEntryResponse, status_code=201)
async def create_kb_entry(
    body: KBEntryCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_editor),
):
    entry = await create_entry(db, current_user.id, body)
    return KBEntryResponse.model_validate(entry)


@router.put("/entries/{entry_id}", response_model=KBEntryResponse)
async def update_kb_entry(
    entry_id: str,
    body: KBEntryUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_editor),
):
    entry = await update_entry(db, entry_id, current_user.id, current_user.role.value, body)
    if not entry:
        raise HTTPException(status_code=404, detail="Entry not found")
    return KBEntryResponse.model_validate(entry)


@router.delete("/entries/{entry_id}", status_code=204)
async def delete_kb_entry(
    entry_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_editor),
):
    deleted = await delete_entry(db, entry_id, current_user.id, current_user.role.value)
    if not deleted:
        raise HTTPException(status_code=404, detail="Entry not found")


@router.post("/search", response_model=KBSearchResponse)
async def search_kb(
    body: KBSearchRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    results = await search_entries(db, body.query, body.limit, body.category)
    return KBSearchResponse(results=results, query=body.query)
