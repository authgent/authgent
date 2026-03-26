"""Request ID + W3C Trace Context propagation middleware."""

from __future__ import annotations

import structlog
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response
from ulid import ULID


class RequestIdMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        # Extract or generate request ID
        request_id = request.headers.get("X-Request-ID") or str(ULID())

        # Extract trace context
        traceparent = request.headers.get("traceparent", "")
        trace_id = ""
        if traceparent:
            parts = traceparent.split("-")
            if len(parts) >= 2:
                trace_id = parts[1]

        # Bind to structlog context
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(
            request_id=request_id,
            trace_id=trace_id,
        )

        # Store in request state for endpoints
        request.state.request_id = request_id
        request.state.trace_id = trace_id

        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response
