"""JWKS fetcher with TTL cache — fetches public keys from authgent-server or any OIDC issuer."""

from __future__ import annotations

import asyncio
import time
from typing import Any

import httpx

from authgent.errors import InvalidTokenError


class JWKSFetcher:
    """Fetches and caches JWKS. Uses asyncio.Lock to prevent thundering-herd."""

    def __init__(self, issuer: str, cache_ttl: int = 300):
        self._issuer = issuer.rstrip("/")
        self._cache_ttl = cache_ttl
        self._keys: dict[str, Any] = {}
        self._last_fetch: float = 0
        self._refresh_lock = asyncio.Lock()

    def _is_stale(self) -> bool:
        return (time.monotonic() - self._last_fetch) > self._cache_ttl

    async def get_key(self, kid: str) -> dict:
        """Get a JWK by kid. Auto-fetches and caches."""
        if kid in self._keys and not self._is_stale():
            return self._keys[kid]

        await self._refresh()

        if kid not in self._keys:
            # Key rotation: one forced re-fetch
            await self._refresh(force=True)

        if kid not in self._keys:
            raise InvalidTokenError(f"Unknown signing key: {kid}")

        return self._keys[kid]

    async def _refresh(self, force: bool = False) -> None:
        async with self._refresh_lock:
            if not force and not self._is_stale():
                return

            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    f"{self._issuer}/.well-known/jwks.json",
                    timeout=10.0,
                )
                resp.raise_for_status()
                jwks = resp.json()

            self._keys = {k["kid"]: k for k in jwks.get("keys", [])}
            self._last_fetch = time.monotonic()

    async def get_all_keys(self) -> dict[str, dict]:
        """Return all cached keys, refreshing if stale."""
        if self._is_stale():
            await self._refresh()
        return dict(self._keys)
