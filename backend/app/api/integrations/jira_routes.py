"""Jira integration API routes.

Provides endpoints for managing Jira connections, syncing tickets,
and receiving webhook events from Jira Cloud/Server instances.
"""

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import require_admin, get_current_user
from app.db.session import get_db
from app.models.user import User
from app.schemas.jira import (
    JiraConfigCreate,
    JiraConfigListResponse,
    JiraConfigResponse,
    JiraConfigUpdate,
    JiraSyncResponse,
    JiraTestConnectionResponse,
)
from app.services.jira_service import (
    SSRFProtectionError,
    create_jira_config,
    delete_jira_config,
    get_jira_config,
    list_jira_configs,
    process_webhook_event,
    sync_tickets,
    test_jira_connection,
    update_jira_config,
    verify_webhook_signature,
)

router = APIRouter(prefix="/integrations/jira", tags=["jira"])


@router.post("/configs", response_model=JiraConfigResponse, status_code=201)
async def create_config(
    data: JiraConfigCreate,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Create a new Jira integration configuration. Admin only."""
    try:
        config = await create_jira_config(db, current_user.id, data)
    except SSRFProtectionError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid URL: {e}",
        )
    return config


@router.get("/configs", response_model=JiraConfigListResponse)
async def list_configs(
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """List all Jira configurations. Admin only."""
    configs = await list_jira_configs(db)
    return JiraConfigListResponse(configs=configs, total=len(configs))


@router.get("/configs/{config_id}", response_model=JiraConfigResponse)
async def get_config(
    config_id: str,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Get a specific Jira configuration. Admin only."""
    config = await get_jira_config(db, config_id)
    if not config:
        raise HTTPException(status_code=404, detail="Configuration not found")
    return config


@router.put("/configs/{config_id}", response_model=JiraConfigResponse)
async def update_config(
    config_id: str,
    data: JiraConfigUpdate,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Update a Jira configuration. Admin only."""
    try:
        config = await update_jira_config(db, config_id, data)
    except SSRFProtectionError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid URL: {e}",
        )
    if not config:
        raise HTTPException(status_code=404, detail="Configuration not found")
    return config


@router.delete("/configs/{config_id}", status_code=204)
async def delete_config(
    config_id: str,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Delete a Jira configuration. Admin only."""
    deleted = await delete_jira_config(db, config_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Configuration not found")


@router.post("/configs/{config_id}/test", response_model=JiraTestConnectionResponse)
async def test_connection(
    config_id: str,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Test connectivity to the configured Jira instance. Admin only."""
    config = await get_jira_config(db, config_id)
    if not config:
        raise HTTPException(status_code=404, detail="Configuration not found")

    try:
        result = await test_jira_connection(config)
    except SSRFProtectionError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"URL blocked by security policy: {e}",
        )
    except Exception as e:
        return JiraTestConnectionResponse(
            success=False, message=f"Connection failed: {str(e)}"
        )
    return JiraTestConnectionResponse(**result)


@router.post("/configs/{config_id}/sync", response_model=JiraSyncResponse)
async def trigger_sync(
    config_id: str,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Trigger a ticket sync from Jira. Admin only."""
    config = await get_jira_config(db, config_id)
    if not config:
        raise HTTPException(status_code=404, detail="Configuration not found")
    if not config.is_active:
        raise HTTPException(status_code=400, detail="Configuration is disabled")

    try:
        result = await sync_tickets(config, redis_client=None, since=config.last_sync_at)
    except SSRFProtectionError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"URL blocked by security policy: {e}",
        )
    except Exception as e:
        return JiraSyncResponse(synced_count=0, errors=[str(e)])

    # Update last_sync timestamp
    from datetime import datetime, timezone
    config.last_sync_at = datetime.now(timezone.utc)
    await db.flush()

    return JiraSyncResponse(**result)


@router.post("/webhook/{config_id}")
async def receive_webhook(
    config_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    x_hub_signature: str | None = Header(None, alias="X-Hub-Signature"),
):
    """
    Receive and process a Jira webhook event.

    This endpoint is called by Jira when issues are created, updated,
    or deleted. The webhook signature is verified if a secret is configured.
    """
    config = await get_jira_config(db, config_id)
    if not config:
        raise HTTPException(status_code=404, detail="Configuration not found")
    if not config.is_active:
        raise HTTPException(status_code=400, detail="Configuration is disabled")

    body = await request.body()

    # Verify webhook signature if secret is configured
    if config.webhook_secret:
        if not x_hub_signature:
            raise HTTPException(status_code=401, detail="Missing webhook signature")
        if not verify_webhook_signature(body, x_hub_signature, config.webhook_secret):
            raise HTTPException(status_code=401, detail="Invalid webhook signature")

    # Parse and process the event
    import json
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    event_type = payload.get("webhookEvent", "unknown")
    issue_data = payload.get("issue")

    # Get MongoDB for ticket cache and delivery logging
    from app.db.mongo import get_mongo_db
    mongo_db = await get_mongo_db()

    result = await process_webhook_event(
        event_type=event_type,
        issue_data=issue_data,
        config=config,
        mongo_db=mongo_db,
        redis_client=None,
    )

    return result


@router.post("/webhook-logs/query")
async def query_webhook_logs(
    request: Request,
    current_user: User = Depends(require_admin),
):
    """
    Query webhook delivery logs with flexible filtering.

    Accepts a JSON body with filter criteria. Supports filtering by
    config_name, event_type, status, and ticket_key. Used by the admin
    monitoring dashboard for complex queries and aggregations.

    Example body:
        {"config_name": "Production Jira", "status": "delivered"}
    """
    from app.db.mongo import get_mongo_db
    from app.services.webhook_log_service import get_delivery_logs

    mongo_db = await get_mongo_db()

    body = await request.json()
    filter_params = {}
    for key in ("config_name", "event_type", "status", "ticket_key"):
        value = body.get(key)
        if value is not None:
            filter_params[key] = value

    limit = body.get("limit", 50)
    logs = await get_delivery_logs(mongo_db, filter_params, limit=limit)
    return {"logs": logs, "total": len(logs)}


@router.get("/webhook-logs/status/{config_name}")
async def get_webhook_status(
    config_name,
    current_user: User = Depends(require_admin),
):
    """
    Get the latest webhook delivery status for a specific integration.

    Returns the most recent delivery log entry for the named config,
    including delivery timestamp and any error details.
    """
    from app.db.mongo import get_mongo_db
    from app.services.webhook_log_service import get_delivery_status

    mongo_db = await get_mongo_db()
    status = await get_delivery_status(mongo_db, config_name)
    if not status:
        raise HTTPException(status_code=404, detail="No delivery logs found")
    return status


@router.post("/enrich-ticket")
async def enrich_ticket(
    request: Request,
    current_user: User = Depends(get_current_user),
):
    """
    Enrich a KB entry with data from a linked Jira ticket.

    Looks up the ticket in the local cache (populated by webhooks/syncs)
    and fetches the latest status from the ticket's API URL if available.

    This endpoint is called by the KB editor when linking a ticket to
    provide auto-populated metadata.
    """
    from app.db.mongo import get_mongo_db
    from app.services.ticket_enrichment_service import enrich_from_ticket

    body = await request.json()
    ticket_key = body.get("ticket_key")
    if not ticket_key:
        raise HTTPException(status_code=400, detail="ticket_key is required")

    mongo_db = await get_mongo_db()
    enrichment = await enrich_from_ticket(mongo_db, ticket_key)
    if not enrichment:
        raise HTTPException(status_code=404, detail="Ticket not found in cache")
    return enrichment
