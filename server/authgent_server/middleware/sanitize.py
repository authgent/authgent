"""Input sanitization middleware — strips null bytes and other dangerous characters.

Uses a pure-ASGI middleware (not BaseHTTPMiddleware) so it intercepts the
raw body bytes *before* Starlette's form parser, which would otherwise crash
on null bytes.
"""

from __future__ import annotations

import json
from collections.abc import MutableMapping
from typing import Any

from starlette.types import ASGIApp, Receive, Scope, Send


class InputSanitizationMiddleware:
    """Reject requests containing null bytes in the body.

    Null bytes in form data can crash uvicorn/h11 at the protocol level.
    This pure-ASGI middleware buffers incoming body chunks and rejects
    requests that contain \\x00 before the app ever sees them.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Check content-type from headers
        headers = dict(
            (k.lower(), v)
            for k, v in (
                (h[0].decode("latin-1"), h[1].decode("latin-1")) for h in scope.get("headers", [])
            )
        )
        content_type = headers.get("content-type", "")

        needs_check = (
            "application/x-www-form-urlencoded" in content_type
            or "multipart/form-data" in content_type
        )

        if not needs_check:
            await self.app(scope, receive, send)
            return

        # Consume the body and check for null bytes
        body = b""
        has_null = False
        while True:
            message = await receive()
            chunk = message.get("body", b"")
            body += chunk
            if b"\x00" in chunk:
                has_null = True
            if not message.get("more_body", False):
                break

        # Also check for URL-encoded null (%00) which Starlette will decode
        if not has_null and b"%00" in body.lower():
            has_null = True

        if has_null:
            error_body = json.dumps(
                {
                    "error": "invalid_request",
                    "error_description": "Request body contains invalid characters",
                }
            ).encode()
            await send(
                {
                    "type": "http.response.start",
                    "status": 400,
                    "headers": [
                        [b"content-type", b"application/json"],
                        [b"content-length", str(len(error_body)).encode()],
                    ],
                }
            )
            await send({"type": "http.response.body", "body": error_body})
            return

        # Replay the buffered body to the app
        body_sent = False

        async def replay_receive() -> MutableMapping[str, Any]:
            nonlocal body_sent
            if not body_sent:
                body_sent = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        await self.app(scope, replay_receive, send)
