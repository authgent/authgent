"""Delegation receipt model — signed receipts for chain splicing prevention."""

from datetime import UTC, datetime

from sqlalchemy import String, Text
from sqlalchemy.orm import Mapped, mapped_column

from authgent_server.models.base import Base, ULIDMixin


class DelegationReceipt(ULIDMixin, Base):
    __tablename__ = "delegation_receipts"

    token_jti: Mapped[str] = mapped_column(String(255), nullable=False)
    parent_token_jti: Mapped[str] = mapped_column(String(255), nullable=False)
    actor_id: Mapped[str] = mapped_column(String(255), nullable=False)
    receipt_jwt: Mapped[str] = mapped_column(Text, nullable=False)
    chain_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(default=lambda: datetime.now(UTC))
