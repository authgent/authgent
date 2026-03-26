"""SQLAlchemy declarative base with ULID and timestamp mixins."""

from datetime import datetime, timezone

from sqlalchemy import String, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from ulid import ULID


class Base(DeclarativeBase):
    pass


class ULIDMixin:
    """Mixin that provides a ULID primary key."""

    id: Mapped[str] = mapped_column(
        String(26), primary_key=True, default=lambda: str(ULID())
    )


class TimestampMixin:
    """Mixin that provides created_at and updated_at timestamps."""

    created_at: Mapped[datetime] = mapped_column(
        default=lambda: datetime.now(timezone.utc),
    )
    updated_at: Mapped[datetime] = mapped_column(
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )
