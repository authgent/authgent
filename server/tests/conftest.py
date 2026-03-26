"""Test fixtures — in-memory SQLite, test client, pre-generated keys."""

from __future__ import annotations

import os
from collections.abc import AsyncGenerator

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

# Set test env vars before importing app modules
os.environ["AUTHGENT_SECRET_KEY"] = (
    "test-secret-key-for-unit-tests-only-64chars-long-padding-here!!"
)
os.environ["AUTHGENT_DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"
os.environ["AUTHGENT_CONSENT_MODE"] = "auto_approve"
os.environ["AUTHGENT_REGISTRATION_POLICY"] = "open"
os.environ["AUTHGENT_SERVER_URL"] = "http://localhost:8000"

from authgent_server.config import reset_settings
from authgent_server.dependencies import reset_providers
from authgent_server.models.base import Base


@pytest_asyncio.fixture
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    """In-memory SQLite async session."""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    async with session_factory() as session:
        yield session

    await engine.dispose()


@pytest.fixture
def test_client(db_session: AsyncSession) -> TestClient:
    """FastAPI test client with overridden DB dependency."""
    reset_settings()
    reset_providers()

    from authgent_server.app import create_app
    from authgent_server.dependencies import get_db_session

    app = create_app()

    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db_session] = override_get_db
    return TestClient(app)


@pytest.fixture
def test_keys() -> dict:
    """Pre-generated ES256 key pair for deterministic tests."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    return {"private": private_key, "public": private_key.public_key()}
