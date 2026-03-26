"""OAuth client model — authoritative table for all OAuth credentials."""

from datetime import UTC, datetime

from sqlalchemy import JSON, Boolean, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from authgent_server.models.base import Base


class OAuthClient(Base):
    __tablename__ = "oauth_clients"

    client_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    client_secret_hash: Mapped[str] = mapped_column(String(512), nullable=False)
    previous_secret_hash: Mapped[str | None] = mapped_column(String(512), nullable=True)
    previous_secret_expires: Mapped[datetime | None] = mapped_column(nullable=True)
    client_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    grant_types: Mapped[list | None] = mapped_column(JSON, nullable=True)
    redirect_uris: Mapped[list | None] = mapped_column(JSON, nullable=True)
    scope: Mapped[str | None] = mapped_column(Text, nullable=True)
    allowed_resources: Mapped[list | None] = mapped_column(JSON, nullable=True)
    may_act_subs: Mapped[list | None] = mapped_column(JSON, nullable=True)
    metadata_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    token_endpoint_auth_method: Mapped[str | None] = mapped_column(
        String(50), default="client_secret_post"
    )
    dpop_bound_access_tokens: Mapped[bool] = mapped_column(Boolean, default=False)
    agent_id: Mapped[str | None] = mapped_column(
        String(26), ForeignKey("agents.id"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        default=lambda: datetime.now(UTC)
    )

    # Relationships
    agent: Mapped["Agent | None"] = relationship(  # noqa: F821
        back_populates="oauth_client", foreign_keys=[agent_id]
    )
