"""OAuth client registration schemas."""

from __future__ import annotations

from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator

from authgent_server.schemas.common import MAX_REDIRECT_URIS, MAX_SCOPE_LENGTH, SCOPE_PATTERN


class RegisterRequest(BaseModel):
    client_name: str = Field(max_length=255)
    grant_types: list[str] = Field(default=["client_credentials"])
    redirect_uris: list[str] = Field(default_factory=list, max_length=MAX_REDIRECT_URIS)
    scope: str = Field(default="", max_length=MAX_SCOPE_LENGTH)
    token_endpoint_auth_method: str = "client_secret_post"
    dpop_bound_access_tokens: bool = False
    allowed_resources: list[str] = Field(default_factory=list)

    @field_validator("redirect_uris")
    @classmethod
    def validate_redirect_uris(cls, uris: list[str]) -> list[str]:
        for uri in uris:
            parsed = urlparse(uri)
            if parsed.fragment:
                raise ValueError("redirect_uri must not contain a fragment")
            if parsed.query:
                raise ValueError("redirect_uri must not contain query parameters")
            if parsed.scheme not in ("https", "http"):
                raise ValueError("redirect_uri must use HTTP(S)")
            if parsed.scheme == "http" and parsed.hostname not in (
                "localhost",
                "127.0.0.1",
            ):
                raise ValueError("redirect_uri must use HTTPS (except localhost)")
        return uris

    @field_validator("scope")
    @classmethod
    def validate_scope(cls, v: str) -> str:
        if not v:
            return v
        for s in v.split():
            if not SCOPE_PATTERN.match(s):
                raise ValueError(f"Invalid scope character in: {s}")
        return v

    @field_validator("grant_types")
    @classmethod
    def validate_grant_types(cls, v: list[str]) -> list[str]:
        valid = {
            "client_credentials",
            "authorization_code",
            "refresh_token",
            "urn:ietf:params:oauth:grant-type:token-exchange",
            "urn:ietf:params:oauth:grant-type:device_code",
        }
        for gt in v:
            if gt not in valid:
                raise ValueError(f"Unsupported grant type: {gt}")
        return v


class RegisterResponse(BaseModel):
    client_id: str
    client_secret: str
    client_name: str
    grant_types: list[str]
    redirect_uris: list[str]
    scope: str
    token_endpoint_auth_method: str
    dpop_bound_access_tokens: bool
