"""Signing key model — ES256 key pairs for JWT signing."""

from datetime import UTC, datetime

from sqlalchemy import JSON, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from authgent_server.models.base import Base


class SigningKey(Base):
    __tablename__ = "signing_keys"
    __table_args__ = (Index("ix_signing_keys_status", "status"),)

    kid: Mapped[str] = mapped_column(String(255), primary_key=True)
    algorithm: Mapped[str] = mapped_column(String(10), default="ES256")
    private_key_pem: Mapped[str] = mapped_column(Text, nullable=False)
    public_key_jwk: Mapped[dict] = mapped_column(JSON, nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="active")
    created_at: Mapped[datetime] = mapped_column(default=lambda: datetime.now(UTC))
    rotated_at: Mapped[datetime | None] = mapped_column(nullable=True)
