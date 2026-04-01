"""OAuth client registration schemas."""

from __future__ import annotations

from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator, model_validator

from authgent_server.schemas.common import MAX_REDIRECT_URIS, MAX_SCOPE_LENGTH, SCOPE_PATTERN


class RegisterRequest(BaseModel):
    client_name: str = Field(max_length=255)
    grant_types: list[str] = Field(default=["client_credentials"])
    redirect_uris: list[str] = Field(default_factory=list, max_length=MAX_REDIRECT_URIS)
    scope: str = Field(default="", max_length=MAX_SCOPE_LENGTH)
    token_endpoint_auth_method: str = "client_secret_post"
    dpop_bound_access_tokens: bool = False
    allowed_resources: list[str] = Field(default_factory=list)
    # RFC 7591 §2 — client public key for asymmetric auth (private_key_jwt, DPoP)
    jwks_uri: str | None = Field(default=None, max_length=2048)
    jwks: dict | None = Field(default=None)
    # RFC 7591 §2 — informational metadata
    client_uri: str | None = Field(default=None, max_length=2048)
    contacts: list[str] = Field(default_factory=list)

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

    @field_validator("jwks_uri")
    @classmethod
    def validate_jwks_uri(cls, v: str | None) -> str | None:
        if not v:
            return v
        parsed = urlparse(v)
        if parsed.scheme not in ("https", "http"):
            raise ValueError("jwks_uri must use HTTP(S)")
        if parsed.scheme == "http" and parsed.hostname not in ("localhost", "127.0.0.1"):
            raise ValueError("jwks_uri must use HTTPS (except localhost)")
        return v

    @field_validator("jwks")
    @classmethod
    def validate_jwks(cls, v: dict | None) -> dict | None:
        if not v:
            return v
        if "keys" not in v or not isinstance(v["keys"], list):
            raise ValueError("jwks must contain a 'keys' array (RFC 7517 §5)")
        return v

    @field_validator("client_uri")
    @classmethod
    def validate_client_uri(cls, v: str | None) -> str | None:
        if not v:
            return v
        parsed = urlparse(v)
        if parsed.scheme not in ("https", "http"):
            raise ValueError("client_uri must use HTTP(S)")
        return v

    @model_validator(mode="after")
    def check_jwks_mutual_exclusion(self) -> RegisterRequest:
        """RFC 7591 §2: jwks_uri and jwks MUST NOT both be present."""
        if self.jwks_uri and self.jwks:
            raise ValueError("jwks_uri and jwks must not both be provided (RFC 7591 §2)")
        return self


class RegisterResponse(BaseModel):
    client_id: str
    client_secret: str
    client_name: str
    grant_types: list[str]
    redirect_uris: list[str]
    scope: str
    token_endpoint_auth_method: str
    dpop_bound_access_tokens: bool
    jwks_uri: str | None = None
    jwks: dict | None = None
    client_uri: str | None = None
    contacts: list[str] = Field(default_factory=list)
