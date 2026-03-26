"""Health check endpoints — liveness and readiness probes."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from authgent_server.dependencies import get_db_session

router = APIRouter(tags=["health"])


@router.get("/health")
async def health() -> dict:
    """Liveness probe — process is running."""
    return {"status": "ok"}


@router.get("/ready")
async def ready(db: AsyncSession = Depends(get_db_session)) -> dict:
    """Readiness probe — DB reachable, signing key exists."""
    checks: dict = {"status": "ready", "db": "ok", "keys": "ok"}
    try:
        await db.execute(text("SELECT 1"))
    except Exception as e:
        checks["db"] = f"error: {e}"
        checks["status"] = "not_ready"
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=503, content=checks)  # type: ignore[return-value]

    try:
        from authgent_server.models.signing_key import SigningKey
        from sqlalchemy import select
        result = await db.execute(
            select(SigningKey).where(SigningKey.status == "active").limit(1)
        )
        if result.scalar_one_or_none() is None:
            checks["keys"] = "no active signing key"
            checks["status"] = "not_ready"
    except Exception as e:
        checks["keys"] = f"error: {e}"
        checks["status"] = "not_ready"

    if checks["status"] != "ready":
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=503, content=checks)  # type: ignore[return-value]

    return checks
