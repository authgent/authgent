"""Token endpoint request/response schemas."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    scope: str | None = None
    refresh_token: str | None = None
    # RFC 8693 token exchange fields
    issued_token_type: str | None = None


class TokenExchangeResponse(TokenResponse):
    issued_token_type: str = "urn:ietf:params:oauth:token-type:access_token"


class TokenIntrospectionResponse(BaseModel):
    active: bool
    scope: str | None = None
    client_id: str | None = None
    username: str | None = None
    token_type: str | None = None
    exp: int | None = None
    iat: int | None = None
    sub: str | None = None
    aud: str | None = None
    iss: str | None = None
    jti: str | None = None
    act: dict[str, Any] | None = None
