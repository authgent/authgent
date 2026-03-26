"""Shared utility functions."""

from __future__ import annotations

from datetime import UTC, datetime


def utcnow() -> datetime:
    """Return timezone-aware UTC now."""
    return datetime.now(UTC)


def ensure_aware(dt: datetime) -> datetime:
    """Ensure a datetime is timezone-aware (UTC). SQLite returns naive datetimes."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt


def is_expired(expires_at: datetime) -> bool:
    """Check if a timestamp is in the past, handling naive/aware comparison."""
    return ensure_aware(expires_at) < utcnow()
