"""Audit log model — append-only event log."""

from datetime import UTC, datetime

from sqlalchemy import JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from authgent_server.models.base import Base, ULIDMixin


class AuditLog(ULIDMixin, Base):
    __tablename__ = "audit_log"

    timestamp: Mapped[datetime] = mapped_column(
        default=lambda: datetime.now(UTC)
    )
    action: Mapped[str] = mapped_column(String(50), nullable=False)
    actor: Mapped[str | None] = mapped_column(String(255), nullable=True)
    subject: Mapped[str | None] = mapped_column(String(255), nullable=True)
    client_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    trace_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    span_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    metadata_: Mapped[dict | None] = mapped_column("metadata", JSON, nullable=True)
