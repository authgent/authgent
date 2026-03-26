"""Async SQLAlchemy engine and session factory."""

from __future__ import annotations

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from authgent_server.config import Settings

_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def get_engine(settings: Settings) -> AsyncEngine:
    """Create or return the async engine based on settings."""
    global _engine
    if _engine is not None:
        return _engine

    if "sqlite" in settings.database_url:
        from sqlalchemy.pool import StaticPool

        _engine = create_async_engine(
            settings.database_url,
            echo=settings.debug,
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
    else:
        _engine = create_async_engine(
            settings.database_url,
            echo=settings.debug,
            pool_pre_ping=True,
            pool_size=5,
            max_overflow=10,
        )
    return _engine


def get_session_factory(settings: Settings) -> async_sessionmaker[AsyncSession]:
    """Create or return the async session factory."""
    global _session_factory
    if _session_factory is not None:
        return _session_factory

    engine = get_engine(settings)
    _session_factory = async_sessionmaker(engine, expire_on_commit=False)
    return _session_factory


async def get_db(settings: Settings | None = None) -> AsyncGenerator[AsyncSession, None]:
    """Yields an async session. Rolls back on exception, always closes."""
    from authgent_server.config import get_settings

    if settings is None:
        settings = get_settings()

    factory = get_session_factory(settings)
    async with factory() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def reset_engine() -> None:
    """Dispose engine and reset globals — for testing or shutdown."""
    global _engine, _session_factory
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _session_factory = None
