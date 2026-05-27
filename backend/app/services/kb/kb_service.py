"""Knowledge Base CRUD service."""
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.kb import KBEntry
from app.schemas.kb import KBEntryCreate, KBEntryUpdate


async def create_entry(
    db: AsyncSession, user_id: str, data: KBEntryCreate
) -> KBEntry:
    """Create a new KB entry."""
    entry = KBEntry(
        title=data.title,
        summary=data.summary,
        content=data.content,
        category=data.category,
        severity=data.severity,
        cwe=data.cwe,
        source_ticket_id=data.source_ticket_id,
        created_by=user_id,
    )
    db.add(entry)
    await db.flush()
    await db.refresh(entry)
    return entry


async def get_entry(db: AsyncSession, entry_id: str) -> KBEntry | None:
    """Get a single KB entry by ID."""
    result = await db.execute(select(KBEntry).where(KBEntry.id == entry_id))
    return result.scalar_one_or_none()


async def list_entries(
    db: AsyncSession,
    skip: int = 0,
    limit: int = 20,
    category: str | None = None,
) -> tuple[list[KBEntry], int]:
    """List KB entries with pagination and optional category filter."""
    query = select(KBEntry)
    count_query = select(func.count()).select_from(KBEntry)

    if category:
        query = query.where(KBEntry.category == category)
        count_query = count_query.where(KBEntry.category == category)

    query = query.order_by(KBEntry.created_at.desc()).offset(skip).limit(limit)

    result = await db.execute(query)
    entries = list(result.scalars().all())

    count_result = await db.execute(count_query)
    total = count_result.scalar() or 0

    return entries, total


async def update_entry(
    db: AsyncSession,
    entry_id: str,
    user_id: str,
    user_role: str,
    data: KBEntryUpdate,
) -> KBEntry | None:
    """Update a KB entry. Editors and admins can update any entry."""
    entry = await get_entry(db, entry_id)
    if not entry:
        return None

    update_data = data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(entry, field, value)

    await db.flush()
    await db.refresh(entry)
    return entry


async def delete_entry(
    db: AsyncSession,
    entry_id: str,
    user_id: str,
    user_role: str,
) -> bool:
    """Delete a KB entry. Editors and admins can delete."""
    entry = await get_entry(db, entry_id)
    if not entry:
        return False

    await db.delete(entry)
    await db.flush()
    return True


async def search_entries(
    db: AsyncSession,
    query: str,
    limit: int = 5,
    category: str | None = None,
) -> list[dict]:
    """Simple text search on KB entries using LIKE.

    Returns matching entries as search results. Vector search will be added later.
    """
    search_term = f"%{query}%"
    stmt = (
        select(KBEntry)
        .where(
            or_(
                KBEntry.title.ilike(search_term),
                KBEntry.summary.ilike(search_term),
                KBEntry.content.ilike(search_term),
            )
        )
    )

    if category:
        stmt = stmt.where(KBEntry.category == category)

    stmt = stmt.limit(limit)
    result = await db.execute(stmt)
    entries = result.scalars().all()

    return [
        {
            "entry_id": entry.id,
            "entry_title": entry.title,
            "chunk_content": entry.summary,
            "chunk_type": "root",
            "score": 1.0,
        }
        for entry in entries
    ]
