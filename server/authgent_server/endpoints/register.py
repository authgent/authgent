"""POST /register — Dynamic Client Registration (RFC 7591)."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from authgent_server.dependencies import get_client_service, get_db_session
from authgent_server.schemas.client import RegisterRequest, RegisterResponse
from authgent_server.services.client_service import ClientService

router = APIRouter(tags=["registration"])


@router.post("/register", response_model=RegisterResponse, status_code=201)
async def register_client(
    request: RegisterRequest,
    db: AsyncSession = Depends(get_db_session),
    client_service: ClientService = Depends(get_client_service),
) -> RegisterResponse:
    """Register a new OAuth client (Dynamic Client Registration, RFC 7591)."""
    return await client_service.register_client(db, request)
