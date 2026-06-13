"""Async cache abstraction with Redis or in-process backend.

Public scanner caches (DCR-mirror probe, per-target scan results) live
in process memory by default. When ``AUTHGENT_REDIS_URL`` is set, the
same cache interface backs to Redis instead, so a multi-worker uvicorn
deployment behind a load balancer shares scan results across workers.

Usage::

    from authgent_server.cache import get_cache
    cache = get_cache()
    await cache.set("scan:https://mcp.example.com", findings_json, ttl=3600)
    cached = await cache.get("scan:https://mcp.example.com")

Falls back to in-process dict when ``redis`` is not installed or
``redis_url`` is unset. The fallback is intentional: the scanner is
useful as a single-binary CLI/server even without Redis, and tests
should not require a Redis container.
"""

from __future__ import annotations

import asyncio
import time
from typing import Protocol


class AsyncCache(Protocol):
    """Minimal async cache interface."""

    async def get(self, key: str) -> str | None: ...
    async def set(self, key: str, value: str, ttl: int) -> None: ...
    async def clear(self) -> None: ...


class _MemoryCache:
    """In-process TTL cache; default backend when no Redis configured."""

    def __init__(self) -> None:
        self._data: dict[str, tuple[float, str]] = {}
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> str | None:
        async with self._lock:
            entry = self._data.get(key)
            if entry is None:
                return None
            expires_at, value = entry
            if time.time() >= expires_at:
                self._data.pop(key, None)
                return None
            return value

    async def set(self, key: str, value: str, ttl: int) -> None:
        async with self._lock:
            self._data[key] = (time.time() + ttl, value)

    async def clear(self) -> None:
        async with self._lock:
            self._data.clear()


class _RedisCache:
    """Redis-backed cache. Lazy-imports redis so tests run without it."""

    def __init__(self, url: str) -> None:
        from redis.asyncio import from_url

        self._client = from_url(  # type: ignore[no-untyped-call]
            url, encoding="utf-8", decode_responses=True
        )

    async def get(self, key: str) -> str | None:
        result = await self._client.get(key)
        return result if result is None else str(result)

    async def set(self, key: str, value: str, ttl: int) -> None:
        await self._client.set(key, value, ex=ttl)

    async def clear(self) -> None:
        await self._client.flushdb()


_cache: AsyncCache | None = None


def get_cache() -> AsyncCache:
    """Return the process-wide cache instance.

    First call selects backend based on ``settings.redis_url``. Once
    chosen, the backend persists for the process lifetime. Test code
    that needs a fresh cache must call :func:`reset_cache` first.
    """
    global _cache
    if _cache is not None:
        return _cache
    from authgent_server.config import get_settings

    settings = get_settings()
    if settings.redis_url:
        try:
            _cache = _RedisCache(settings.redis_url)
        except ImportError:
            # Fallback to in-process cache when redis is not installed.
            _cache = _MemoryCache()
    else:
        _cache = _MemoryCache()
    return _cache


def reset_cache() -> None:
    """Drop the cached backend reference so the next ``get_cache()``
    rebuilds it. Used by tests that monkeypatch settings."""
    global _cache
    _cache = None
