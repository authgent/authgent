"""CAEP transmitter — signed SET push delivery for the session-revoked event.

Implements a narrow slice of two specs, chosen because they are what a
relying party actually needs to *receive* a real-time revocation signal:

  - RFC 8417 (Security Event Token): the SET is a JWT with iss/iat/jti/aud
    and an "events" claim keyed by event-type URI.
  - CAEP 1.0 final (https://openid.net/specs/openid-caep-1_0-final.html):
    the session-revoked event type
    (https://schemas.openid.net/secevent/caep/event-type/session-revoked)
    and the RFC 9493 subject-identifier format used inside it.
  - RFC 8935 (Push-Based SET Token Delivery Using HTTP): the SET is POSTed
    directly to a receiver's endpoint. No polling, no ack/negative-ack
    receipt protocol beyond an HTTP status code.

Explicitly NOT implemented (see docs/security-advisories/
2026-08-caep-transmitter-prototype.md for the full list):
  - SSF stream management / registration API (no negotiation of delivery
    method, no per-stream configuration, no stream status endpoint).
  - Any CAEP event type other than session-revoked (no
    credential-change, no assurance-level-change, no token-claims-change).
  - Receiver-address storage as a first-class, per-agent registration
    concept. Receivers are a flat, server-wide list from Settings.

Delivery pattern (HMAC signing, retry+backoff) deliberately mirrors
authgent_server.providers.hitl.WebhookHITLProvider so the two push-delivery
mechanisms in this codebase share one shape.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass
from datetime import UTC, datetime

import httpx
import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from authgent_server.config import Settings
from authgent_server.services.jwks_service import JWKSService

logger = structlog.get_logger()

# CAEP 1.0 final §2.1 event-type URI for session-revoked.
SESSION_REVOKED_EVENT_TYPE = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"

# RFC 9493 §3.1 subject identifier format for an OAuth client/actor id.
# There is no registered RFC 9493 subject-identifier format specifically
# for "oauth client_id" as of this writing, so this prototype uses the
# generic "opaque" format (RFC 9493 §3.5) carrying the token's jti and the
# delegation actor/client id in a "sub_id" style envelope. This is a
# deliberate, documented choice, not a spec-compliant claim of a
# standardized format.
SUBJECT_FORMAT_OPAQUE = "opaque"


@dataclass
class DeliveryResult:
    receiver_url: str
    delivered: bool
    status_code: int | None
    attempts: int
    error: str | None = None
    # Wall-clock seconds spent attempting this single receiver, measured by
    # the transmitter (does not include receiver-side verification time).
    elapsed_seconds: float = 0.0


def build_session_revoked_set(
    *,
    issuer: str,
    audience: str | list[str],
    actor_id: str,
    client_id: str,
    jti: str,
    reason: str,
) -> dict:
    """Build the (unsigned) RFC 8417 SET claim set for a CAEP session-revoked event.

    Returns a plain dict of JWT claims ready to pass to JWKSService.sign_jwt.
    """
    now = datetime.now(UTC)
    return {
        "iss": issuer,
        "aud": audience,
        "iat": int(now.timestamp()),
        "jti": f"set_{secrets.token_urlsafe(24)}",
        "events": {
            SESSION_REVOKED_EVENT_TYPE: {
                "subject": {
                    "format": SUBJECT_FORMAT_OPAQUE,
                    "actor_id": actor_id,
                    "client_id": client_id,
                    "jti": jti,
                },
                "reason": reason,
                "event_timestamp": int(now.timestamp()),
            }
        },
    }


class CAEPTransmitter:
    """Signs and pushes CAEP session-revoked SETs to configured receivers.

    Configuration (via Settings):
      - caep_receiver_urls: comma-separated receiver endpoint list
      - caep_hmac_secret: HMAC-SHA256 signing key for the push-delivery body
        (this is separate from the SET's own JWT signature; it lets a
        receiver cheaply reject a forged POST before doing JWT verification)
      - caep_retries / caep_backoff / caep_timeout: mirror
        WebhookHITLProvider's retry shape
    """

    def __init__(
        self,
        jwks: JWKSService,
        settings: Settings,
        receiver_urls: list[str] | None = None,
        hmac_secret: str | None = None,
        retries: int | None = None,
        backoff: str | None = None,
        timeout: float | None = None,
    ):
        self._jwks = jwks
        self._settings = settings
        self._receiver_urls = (
            receiver_urls if receiver_urls is not None else settings.caep_receiver_url_list
        )
        self._hmac_secret = (
            hmac_secret if hmac_secret is not None else settings.caep_hmac_secret
        )
        self._retries = retries if retries is not None else settings.caep_retries
        backoff_str = backoff if backoff is not None else settings.caep_backoff
        self._backoff = [float(s.strip()) for s in backoff_str.split(",")]
        self._timeout = timeout if timeout is not None else settings.caep_timeout

    def _sign_delivery_body(self, body: bytes) -> str:
        """HMAC-SHA256 over the push-delivery HTTP body (transport-level signature,
        distinct from the SET's own JWS signature)."""
        if not self._hmac_secret:
            return ""
        return hmac.new(self._hmac_secret.encode(), body, hashlib.sha256).hexdigest()

    async def transmit_session_revoked(
        self,
        db: AsyncSession,
        *,
        actor_id: str,
        client_id: str,
        jti: str,
        reason: str,
    ) -> list[DeliveryResult]:
        """Build, sign, and push a session-revoked SET to every configured receiver.

        Delivers to all receivers concurrently; each receiver gets its own
        independent retry+backoff loop so one slow/down receiver cannot
        delay delivery to the others.
        """
        if not self._receiver_urls:
            logger.info(
                "caep_transmit_skipped_no_receivers",
                jti=jti,
                actor_id=actor_id,
            )
            return []

        claims = build_session_revoked_set(
            issuer=self._settings.server_url,
            audience=self._receiver_urls,
            actor_id=actor_id,
            client_id=client_id,
            jti=jti,
            reason=reason,
        )
        set_jwt = await self._jwks.sign_jwt(
            db, claims, headers={"typ": "secevent+jwt"}
        )
        body = set_jwt.encode()
        signature = self._sign_delivery_body(body)

        results = await asyncio.gather(
            *[self._deliver_one(url, body, signature, claims["jti"]) for url in self._receiver_urls]
        )
        return list(results)

    async def _deliver_one(
        self, url: str, body: bytes, signature: str, set_jti: str
    ) -> DeliveryResult:
        headers = {
            "Content-Type": "application/secevent+jwt",
            "X-Authgent-Event": "caep.session-revoked",
            "X-Authgent-SET-JTI": set_jti,
        }
        if signature:
            headers["X-Authgent-Signature-256"] = f"sha256={signature}"

        start = time.perf_counter()
        last_error: str | None = None
        for attempt in range(self._retries + 1):
            try:
                async with httpx.AsyncClient(timeout=self._timeout) as client:
                    resp = await client.post(url, content=body, headers=headers)
                    if resp.status_code < 300:
                        elapsed = time.perf_counter() - start
                        logger.info(
                            "caep_set_delivered",
                            receiver=url,
                            set_jti=set_jti,
                            status_code=resp.status_code,
                            attempt=attempt + 1,
                            elapsed_seconds=elapsed,
                        )
                        return DeliveryResult(
                            receiver_url=url,
                            delivered=True,
                            status_code=resp.status_code,
                            attempts=attempt + 1,
                            elapsed_seconds=elapsed,
                        )
                    last_error = f"HTTP {resp.status_code}: {resp.text[:200]}"
                    logger.warning(
                        "caep_set_http_error",
                        receiver=url,
                        set_jti=set_jti,
                        status_code=resp.status_code,
                        attempt=attempt + 1,
                    )
            except Exception as e:  # noqa: BLE001 — retried/logged, not swallowed silently
                last_error = str(e)
                logger.warning(
                    "caep_set_delivery_failed",
                    receiver=url,
                    set_jti=set_jti,
                    error=last_error,
                    attempt=attempt + 1,
                )

            if attempt < self._retries:
                backoff_secs = (
                    self._backoff[attempt] if attempt < len(self._backoff) else self._backoff[-1]
                )
                await asyncio.sleep(backoff_secs)

        elapsed = time.perf_counter() - start
        logger.error(
            "caep_set_delivery_exhausted",
            receiver=url,
            set_jti=set_jti,
            retries=self._retries,
            last_error=last_error,
        )
        return DeliveryResult(
            receiver_url=url,
            delivered=False,
            status_code=None,
            attempts=self._retries + 1,
            error=last_error,
            elapsed_seconds=elapsed,
        )
