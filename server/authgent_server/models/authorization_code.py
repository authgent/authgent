"""Authorization code model for auth code + PKCE flow."""

from datetime import datetime

from sqlalchemy import Boolean, ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from authgent_server.models.base import Base


class AuthorizationCode(Base):
    __tablename__ = "authorization_codes"
    __table_args__ = (Index("ix_authorization_codes_expires_at", "expires_at"),)

    code: Mapped[str] = mapped_column(String(255), primary_key=True)
    client_id: Mapped[str] = mapped_column(
        String(255), ForeignKey("oauth_clients.client_id"), nullable=False
    )
    redirect_uri: Mapped[str] = mapped_column(Text, nullable=False)
    scope: Mapped[str | None] = mapped_column(Text, nullable=True)
    resource: Mapped[str | None] = mapped_column(Text, nullable=True)
    code_challenge: Mapped[str] = mapped_column(String(255), nullable=False)
    code_challenge_method: Mapped[str] = mapped_column(String(10), default="S256")
    subject: Mapped[str | None] = mapped_column(String(255), nullable=True)
    nonce: Mapped[str | None] = mapped_column(String(255), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(nullable=False)
    used: Mapped[bool] = mapped_column(Boolean, default=False)
