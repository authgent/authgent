"""Agent identity model — metadata and lifecycle."""

from sqlalchemy import JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from authgent_server.models.base import Base, TimestampMixin, ULIDMixin


class Agent(ULIDMixin, TimestampMixin, Base):
    __tablename__ = "agents"

    oauth_client_id: Mapped[str | None] = mapped_column(
        String(255), unique=True, nullable=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    owner: Mapped[str | None] = mapped_column(String(255), nullable=True)
    allowed_scopes: Mapped[list | None] = mapped_column(JSON, nullable=True)
    capabilities: Mapped[list | None] = mapped_column(JSON, nullable=True)
    allowed_exchange_targets: Mapped[list | None] = mapped_column(JSON, nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="active")
    metadata_: Mapped[dict | None] = mapped_column("metadata", JSON, nullable=True)

    # OIDC-A compatible fields
    agent_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    agent_model: Mapped[str | None] = mapped_column(String(255), nullable=True)
    agent_version: Mapped[str | None] = mapped_column(String(50), nullable=True)
    agent_provider: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Agent Bill of Materials
    bill_of_materials: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    # Attestation fields
    attestation_level: Mapped[str | None] = mapped_column(String(20), nullable=True)
    code_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Relationship
    oauth_client: Mapped["OAuthClient | None"] = relationship(  # noqa: F821
        back_populates="agent",
        foreign_keys="OAuthClient.agent_id",
    )
