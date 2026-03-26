"""Common schemas — error responses, pagination, validation constants."""

from __future__ import annotations

import re

from pydantic import BaseModel, Field

MAX_STRING_LENGTH = 2048
MAX_SCOPE_LENGTH = 512
MAX_REDIRECT_URIS = 10
SCOPE_PATTERN = re.compile(r"^[a-zA-Z0-9_:.\-]+$")


class ErrorResponse(BaseModel):
    """RFC 9457 Problem Details JSON."""

    type: str = "https://authgent.dev/errors/server-error"
    title: str = "Server Error"
    status: int = 500
    detail: str = ""
    instance: str = ""
    error_code: str = "server_error"


class OAuthErrorResponse(BaseModel):
    """RFC 6749 §5.2 error response for /token endpoint."""

    error: str
    error_description: str = ""


class PaginationParams(BaseModel):
    offset: int = Field(default=0, ge=0)
    limit: int = Field(default=20, ge=1, le=100)


class PaginatedResponse(BaseModel):
    items: list = Field(default_factory=list)
    total: int = 0
    offset: int = 0
    limit: int = 20
