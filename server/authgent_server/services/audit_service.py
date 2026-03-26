"""Audit service — event emission via EventEmitter provider."""

from __future__ import annotations

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from authgent_server.providers.events import DatabaseEventEmitter
from authgent_server.providers.protocols import AuditEvent, EventEmitter

logger = structlog.get_logger()


class AuditService:
    def __init__(self, emitter: EventEmitter | None = None):
        self._emitter = emitter or DatabaseEventEmitter()

    async def log(
        self,
        db: AsyncSession,
        action: str,
        *,
        actor: str | None = None,
        subject: str | None = None,
        client_id: str | None = None,
        ip_address: str | None = None,
        trace_id: str | None = None,
        metadata: dict | None = None,
    ) -> None:
        """Log an audit event. Fail-open: errors are logged but don't propagate."""
        if isinstance(self._emitter, DatabaseEventEmitter):
            self._emitter.set_session(db)

        event = AuditEvent(
            action=action,
            actor=actor,
            subject=subject,
            client_id=client_id,
            ip_address=ip_address,
            trace_id=trace_id,
            metadata=metadata or {},
        )

        try:
            await self._emitter.emit(event)
        except Exception as e:
            logger.error("audit_log_failed", action=action, error=str(e))
