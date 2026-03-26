"""Refresh token model with family tracking for reuse detection."""

from datetime import datetime, timezone

from sqlalchemy import Boolean, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from authgent_server.models.base import Base


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    jti: Mapped[str] = mapped_column(String(255), primary_key=True)
    client_id: Mapped[str] = mapped_column(
        String(255), ForeignKey("oauth_clients.client_id"), nullable=False
    )
    subject: Mapped[str | None] = mapped_column(String(255), nullable=True)
    scope: Mapped[str | None] = mapped_column(Text, nullable=True)
    resource: Mapped[str | None] = mapped_column(Text, nullable=True)
    family_id: Mapped[str] = mapped_column(String(255), nullable=False)
    dpop_jkt: Mapped[str | None] = mapped_column(String(255), nullable=True)
    used: Mapped[bool] = mapped_column(Boolean, default=False)
    expires_at: Mapped[datetime] = mapped_column(nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        default=lambda: datetime.now(timezone.utc)
    )
