"""Device code model for RFC 8628 Device Authorization Grant."""

from datetime import datetime, timezone

from sqlalchemy import ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from authgent_server.models.base import Base


class DeviceCode(Base):
    __tablename__ = "device_codes"

    device_code: Mapped[str] = mapped_column(String(255), primary_key=True)
    user_code: Mapped[str] = mapped_column(String(20), unique=True, nullable=False)
    client_id: Mapped[str] = mapped_column(
        String(255), ForeignKey("oauth_clients.client_id"), nullable=False
    )
    scope: Mapped[str | None] = mapped_column(Text, nullable=True)
    resource: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="pending")
    subject: Mapped[str | None] = mapped_column(String(255), nullable=True)
    interval: Mapped[int] = mapped_column(Integer, default=5)
    expires_at: Mapped[datetime] = mapped_column(nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        default=lambda: datetime.now(timezone.utc)
    )
