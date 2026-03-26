"""Consent model — tracks human consent grants for auth code flow."""

from datetime import UTC, datetime

from sqlalchemy import ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from authgent_server.models.base import Base, ULIDMixin


class Consent(ULIDMixin, Base):
    __tablename__ = "consents"
    __table_args__ = (
        UniqueConstraint(
            "subject",
            "client_id",
            "resource",
            name="uq_consent_subject_client_resource",
        ),
    )

    subject: Mapped[str] = mapped_column(String(255), nullable=False)
    client_id: Mapped[str] = mapped_column(
        String(255), ForeignKey("oauth_clients.client_id"), nullable=False
    )
    scope: Mapped[str] = mapped_column(Text, nullable=False)
    resource: Mapped[str | None] = mapped_column(Text, nullable=True)
    granted_at: Mapped[datetime] = mapped_column(default=lambda: datetime.now(UTC))
    expires_at: Mapped[datetime | None] = mapped_column(nullable=True)
