"""FastAPI app factory with lifespan, middleware, and cleanup tasks."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from datetime import UTC, datetime

import structlog
from fastapi import FastAPI
from sqlalchemy import text

from authgent_server.config import Settings, get_settings
from authgent_server.db import get_engine, get_session_factory
from authgent_server.endpoints import api_router
from authgent_server.errors import AuthgentError
from authgent_server.middleware.cors import setup_cors
from authgent_server.middleware.error_handler import (
    authgent_error_handler,
    unhandled_exception_handler,
)
from authgent_server.middleware.rate_limit import RateLimitMiddleware
from authgent_server.middleware.request_id import RequestIdMiddleware
from authgent_server.models.base import Base
from authgent_server.services.jwks_service import JWKSService

logger = structlog.get_logger()

# Cleanup queries — explicit per-table, no string interpolation
_CLEANUP_QUERIES = {
    "token_blocklist": text("DELETE FROM token_blocklist WHERE expires_at < :now"),
    "authorization_codes": text("DELETE FROM authorization_codes WHERE expires_at < :now"),
    "device_codes": text("DELETE FROM device_codes WHERE expires_at < :now"),
    "refresh_tokens": text("DELETE FROM refresh_tokens WHERE expires_at < :now"),
    "stepup_requests": text(
        "UPDATE stepup_requests SET status = 'expired' "
        "WHERE expires_at < :now AND status = 'pending'"
    ),
    "audit_log": text("DELETE FROM audit_log WHERE timestamp < :now"),
    "delegation_receipts": text("DELETE FROM delegation_receipts WHERE created_at < :now"),
}

# Cleanup intervals in seconds
_CLEANUP_INTERVALS = {
    "token_blocklist": 3600,
    "authorization_codes": 900,
    "device_codes": 900,
    "refresh_tokens": 3600,
    "stepup_requests": 60,
    "audit_log": 86400,  # daily — retains 90 days
    "delegation_receipts": 86400,  # daily — retains 30 days
}

# Retention offsets for tables without an expires_at column (seconds before :now)
_CLEANUP_RETENTION = {
    "audit_log": 90 * 86400,  # 90 days
    "delegation_receipts": 30 * 86400,  # 30 days
}


async def _cleanup_loop(
    table: str,
    interval: int,
    shutdown: asyncio.Event,
    session_factory: object,
) -> None:
    """Background cleanup task for expired records."""
    query = _CLEANUP_QUERIES[table]
    retention = _CLEANUP_RETENTION.get(table, 0)
    while not shutdown.is_set():
        try:
            from datetime import timedelta

            cutoff = datetime.now(UTC) - timedelta(seconds=retention)
            async with session_factory() as session:  # type: ignore[operator]
                await session.execute(query, {"now": cutoff})
                await session.commit()
        except Exception as e:
            logger.warning("cleanup_failed", table=table, error=str(e))
        try:
            await asyncio.wait_for(shutdown.wait(), timeout=interval)
            break
        except TimeoutError:
            continue


def _configure_logging(debug: bool = False) -> None:
    """Configure structlog with JSON output and secret redaction."""
    from authgent_server.logging import configure_logging

    configure_logging(debug=debug, json_output=not debug)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:  # type: ignore[type-arg]
    """Server lifecycle — startup and shutdown."""
    settings = get_settings()
    _configure_logging(settings.debug)

    engine = get_engine(settings)
    session_factory = get_session_factory(settings)

    # Create tables (for dev/SQLite — production uses Alembic)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Ensure signing key exists
    jwks = JWKSService(settings)
    async with session_factory() as session:
        await jwks.get_active_key(session)

    # Start background cleanup tasks
    shutdown_event = asyncio.Event()
    cleanup_tasks = [
        asyncio.create_task(_cleanup_loop(table, interval, shutdown_event, session_factory))
        for table, interval in _CLEANUP_INTERVALS.items()
    ]

    logger.info(
        "server_started",
        host=settings.host,
        port=settings.port,
        database=settings.database_url.split("://")[0],
    )

    yield

    # Shutdown
    logger.info("server_shutting_down")
    shutdown_event.set()
    done, pending = await asyncio.wait(cleanup_tasks, timeout=5.0)
    for task in pending:
        task.cancel()
    await engine.dispose()
    logger.info("server_stopped")


def create_app(settings: Settings | None = None) -> FastAPI:
    """App factory — creates and configures the FastAPI application."""
    if settings is None:
        settings = get_settings()

    app = FastAPI(
        title="authgent",
        description="The open-source identity provider for AI agents",
        version="0.1.0",
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # Error handlers
    app.add_exception_handler(AuthgentError, authgent_error_handler)  # type: ignore[arg-type]
    app.add_exception_handler(Exception, unhandled_exception_handler)  # type: ignore[arg-type]

    # Middleware (order matters — outermost first)
    app.add_middleware(RequestIdMiddleware)
    setup_cors(app, settings)
    app.add_middleware(
        RateLimitMiddleware,
        rate=settings.token_rate_limit,
        paths=["/token"],
    )

    # Routes
    app.include_router(api_router)

    return app
