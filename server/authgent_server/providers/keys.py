"""Default key provider — database-backed signing keys."""

from __future__ import annotations


class DatabaseKeyProvider:
    """Keys stored in signing_keys table, encrypted at rest.
    Actual key operations are handled by JWKSService which uses this
    provider indirectly through the DB layer."""

    async def get_signing_key(self) -> dict:
        raise NotImplementedError("Use JWKSService directly for key operations")

    async def get_verification_keys(self) -> list[dict]:
        raise NotImplementedError("Use JWKSService directly for key operations")
