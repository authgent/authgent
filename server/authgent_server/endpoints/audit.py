"""GET /audit — Query audit log with filtering and pagination."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from authgent_server.dependencies import get_db_session
from authgent_server.models.audit_log import AuditLog

router = APIRouter(tags=["audit"])


class AuditLogEntry(BaseModel):
    id: str
    timestamp: datetime
    action: str
    actor: str | None = None
    subject: str | None = None
    client_id: str | None = None
    ip_address: str | None = None
    trace_id: str | None = None
    metadata: dict | None = None

    model_config = {"from_attributes": True}


class AuditLogResponse(BaseModel):
    items: list[AuditLogEntry]
    total: int
    offset: int
    limit: int


@router.get("/audit", response_model=AuditLogResponse)
async def list_audit_logs(
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=200),
    action: str | None = Query(default=None, description="Filter by action (e.g. token.issued)"),
    actor: str | None = Query(default=None, description="Filter by actor"),
    client_id: str | None = Query(default=None, description="Filter by client_id"),
    since: str | None = Query(
        default=None, description="ISO 8601 timestamp — only events after this time"
    ),
    db: AsyncSession = Depends(get_db_session),
) -> AuditLogResponse:
    """Query the audit log with filtering, pagination, and time-range support."""
    stmt = select(AuditLog)
    count_stmt = select(func.count()).select_from(AuditLog)

    if action:
        stmt = stmt.where(AuditLog.action == action)
        count_stmt = count_stmt.where(AuditLog.action == action)
    if actor:
        stmt = stmt.where(AuditLog.actor == actor)
        count_stmt = count_stmt.where(AuditLog.actor == actor)
    if client_id:
        stmt = stmt.where(AuditLog.client_id == client_id)
        count_stmt = count_stmt.where(AuditLog.client_id == client_id)
    if since:
        try:
            since_dt = datetime.fromisoformat(since.replace("Z", "+00:00"))
        except ValueError:
            since_dt = datetime.now(UTC)
        stmt = stmt.where(AuditLog.timestamp >= since_dt)
        count_stmt = count_stmt.where(AuditLog.timestamp >= since_dt)

    stmt = stmt.order_by(AuditLog.timestamp.desc()).offset(offset).limit(limit)

    result = await db.execute(stmt)
    logs = list(result.scalars().all())

    count_result = await db.execute(count_stmt)
    total = count_result.scalar() or 0

    items = [
        AuditLogEntry(
            id=log.id,
            timestamp=log.timestamp,
            action=log.action,
            actor=log.actor,
            subject=log.subject,
            client_id=log.client_id,
            ip_address=log.ip_address,
            trace_id=log.trace_id,
            metadata=log.metadata_,
        )
        for log in logs
    ]

    return AuditLogResponse(items=items, total=total, offset=offset, limit=limit)
