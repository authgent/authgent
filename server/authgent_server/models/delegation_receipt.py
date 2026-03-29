"""Delegation receipt model — signed receipts for chain splicing prevention."""

from datetime import UTC, datetime

from sqlalchemy import Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from authgent_server.models.base import Base, ULIDMixin


class DelegationReceipt(ULIDMixin, Base):
    __tablename__ = "delegation_receipts"
    __table_args__ = (
        Index("ix_delegation_receipts_token_jti", "token_jti"),
        Index("ix_delegation_receipts_parent_jti", "parent_token_jti"),
        Index("ix_delegation_receipts_created_at", "created_at"),
    )

    token_jti: Mapped[str] = mapped_column(String(255), nullable=False)
    parent_token_jti: Mapped[str] = mapped_column(String(255), nullable=False)
    actor_id: Mapped[str] = mapped_column(String(255), nullable=False)
    receipt_jwt: Mapped[str] = mapped_column(Text, nullable=False)
    chain_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(default=lambda: datetime.now(UTC))
