"""Token blocklist model for revoked tokens."""

from datetime import datetime, timezone

from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column

from authgent_server.models.base import Base


class TokenBlocklist(Base):
    __tablename__ = "token_blocklist"

    jti: Mapped[str] = mapped_column(String(255), primary_key=True)
    expires_at: Mapped[datetime] = mapped_column(nullable=False)
    revoked_at: Mapped[datetime] = mapped_column(
        default=lambda: datetime.now(timezone.utc)
    )
    reason: Mapped[str | None] = mapped_column(String(50), nullable=True)
