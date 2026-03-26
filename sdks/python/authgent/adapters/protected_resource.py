"""RFC 9728 — OAuth 2.0 Protected Resource Metadata generator.

Generates the /.well-known/oauth-protected-resource JSON document
that MCP servers and API servers should serve to advertise their
authorization requirements to clients.

Usage:
    from authgent.adapters.protected_resource import ProtectedResourceMetadata

    metadata = ProtectedResourceMetadata(
        resource="https://mcp-server.example.com",
        authorization_servers=["http://localhost:8000"],
        scopes_supported=["tools:execute", "db:read", "db:write"],
    )

    # In FastAPI:
    @app.get("/.well-known/oauth-protected-resource")
    def protected_resource():
        return metadata.to_dict()

    # Or generate as JSON string:
    json_str = metadata.to_json()
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field


@dataclass
class ProtectedResourceMetadata:
    """RFC 9728 Protected Resource Metadata document.

    Attributes:
        resource: The protected resource identifier (URL).
        authorization_servers: List of authorization server URLs that can issue
            tokens accepted by this resource.
        scopes_supported: Scopes this resource understands.
        bearer_methods_supported: Token presentation methods supported.
        resource_signing_alg_values_supported: Signing algorithms accepted.
        resource_documentation: URL to human-readable documentation.
        resource_policy_uri: URL to the resource's policy.
        resource_tos_uri: URL to the resource's terms of service.
        dpop_signing_alg_values_supported: DPoP signing algorithms accepted.
    """

    resource: str
    authorization_servers: list[str]
    scopes_supported: list[str] = field(default_factory=list)
    bearer_methods_supported: list[str] = field(
        default_factory=lambda: ["header"]
    )
    resource_signing_alg_values_supported: list[str] = field(
        default_factory=lambda: ["ES256"]
    )
    resource_documentation: str | None = None
    resource_policy_uri: str | None = None
    resource_tos_uri: str | None = None
    dpop_signing_alg_values_supported: list[str] | None = None

    def to_dict(self) -> dict:
        """Generate the RFC 9728 metadata document as a dictionary."""
        doc: dict = {
            "resource": self.resource,
            "authorization_servers": self.authorization_servers,
        }
        if self.scopes_supported:
            doc["scopes_supported"] = self.scopes_supported
        if self.bearer_methods_supported:
            doc["bearer_methods_supported"] = self.bearer_methods_supported
        if self.resource_signing_alg_values_supported:
            doc["resource_signing_alg_values_supported"] = (
                self.resource_signing_alg_values_supported
            )
        if self.resource_documentation:
            doc["resource_documentation"] = self.resource_documentation
        if self.resource_policy_uri:
            doc["resource_policy_uri"] = self.resource_policy_uri
        if self.resource_tos_uri:
            doc["resource_tos_uri"] = self.resource_tos_uri
        if self.dpop_signing_alg_values_supported:
            doc["dpop_signing_alg_values_supported"] = (
                self.dpop_signing_alg_values_supported
            )
        return doc

    def to_json(self, indent: int = 2) -> str:
        """Generate the RFC 9728 metadata document as a JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    def fastapi_route(self) -> dict:
        """Return the metadata dict, suitable as a FastAPI route return value."""
        return self.to_dict()
