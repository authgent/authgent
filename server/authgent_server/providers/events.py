"""Event emitter implementations — database audit log + future OTel."""

from __future__ import annotations

from datetime import UTC, datetime

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from authgent_server.models.audit_log import AuditLog
from authgent_server.providers.protocols import AuditEvent

logger = structlog.get_logger()


class DatabaseEventEmitter:
    """Writes audit events to the audit_log table. Fail-open: errors are logged
    but do not block the request."""

    def __init__(self, db: AsyncSession | None = None):
        self._db = db

    def set_session(self, db: AsyncSession) -> None:
        self._db = db

    async def emit(self, event: AuditEvent) -> None:
        if self._db is None:
            logger.warning("event_emitter_no_session", action=event.action)
            return

        try:
            log_entry = AuditLog(
                action=event.action,
                actor=event.actor,
                subject=event.subject,
                client_id=event.client_id,
                ip_address=event.ip_address,
                trace_id=event.trace_id,
                span_id=event.span_id,
                metadata_=event.metadata,
                timestamp=datetime.now(UTC),
            )
            self._db.add(log_entry)
            await self._db.flush()
        except Exception as e:
            # Fail-open: audit failure must not block token issuance
            logger.error("audit_emit_failed", action=event.action, error=str(e))


class LogEventEmitter:
    """Emits events as structured log entries. Useful for dev/testing."""

    async def emit(self, event: AuditEvent) -> None:
        logger.info(
            "audit_event",
            action=event.action,
            actor=event.actor,
            subject=event.subject,
            client_id=event.client_id,
        )
