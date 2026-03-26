"""Step-up request model for HITL authorization."""

from datetime import datetime, timezone

from sqlalchemy import JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from authgent_server.models.base import Base, ULIDMixin


class StepUpRequest(ULIDMixin, Base):
    __tablename__ = "stepup_requests"

    agent_id: Mapped[str] = mapped_column(String(255), nullable=False)
    action: Mapped[str] = mapped_column(String(255), nullable=False)
    scope: Mapped[str] = mapped_column(Text, nullable=False)
    resource: Mapped[str | None] = mapped_column(String(255), nullable=True)
    delegation_chain_snapshot: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="pending")
    approved_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(nullable=True)
    expires_at: Mapped[datetime] = mapped_column(nullable=False)
    metadata_: Mapped[dict | None] = mapped_column("metadata", JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        default=lambda: datetime.now(timezone.utc)
    )
