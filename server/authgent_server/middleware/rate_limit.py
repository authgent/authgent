"""In-memory sliding window rate limiter."""

from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import Callable

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response


class RateLimitMiddleware(BaseHTTPMiddleware):
    MAX_KEYS = 10_000

    def __init__(
        self,
        app: object,
        rate: int = 100,
        window: int = 60,
        key_func: Callable[[Request], str] | None = None,
        paths: list[str] | None = None,
    ):
        super().__init__(app)  # type: ignore[arg-type]
        self.rate = rate
        self.window = window
        self.key_func = key_func or (lambda r: r.client.host if r.client else "unknown")
        self.paths = paths
        self._counters: dict[str, deque[float]] = defaultdict(deque)
        self._request_count = 0

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        # Only rate limit specified paths
        if self.paths and not any(request.url.path.startswith(p) for p in self.paths):
            return await call_next(request)

        key = self.key_func(request)
        now = time.monotonic()

        # Evict stale entries periodically
        self._request_count += 1
        if self._request_count % 100 == 0:
            self._evict_stale(now)

        # Sliding window check
        window = self._counters[key]
        cutoff = now - self.window
        while window and window[0] < cutoff:
            window.popleft()

        if len(window) >= self.rate:
            retry_after = int(window[0] + self.window - now) + 1
            return JSONResponse(
                status_code=429,
                content={
                    "type": "https://authgent.dev/errors/rate-limited",
                    "title": "Too Many Requests",
                    "status": 429,
                    "detail": f"Rate limit exceeded. Try again in {retry_after}s.",
                },
                headers={"Retry-After": str(retry_after)},
            )

        window.append(now)
        return await call_next(request)

    def _evict_stale(self, now: float) -> None:
        cutoff = now - self.window
        stale = [k for k, v in self._counters.items() if not v or v[-1] < cutoff]
        for k in stale:
            del self._counters[k]
        if len(self._counters) > self.MAX_KEYS:
            excess = len(self._counters) - self.MAX_KEYS
            for k in list(self._counters)[:excess]:
                del self._counters[k]
