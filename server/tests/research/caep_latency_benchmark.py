"""CAEP transmitter latency benchmark: real transmit-to-verified wall-clock time.

Research artifact backing the CAEP magazine column. Not part of the default
CI regression suite (real network sockets, real wall-clock timing — not
appropriate to run on every commit). Run explicitly:

    cd server && source .venv/bin/activate
    python tests/research/caep_latency_benchmark.py

Methodology
-----------
For each receiver count N in RECEIVER_COUNTS:

  1. Start N independent asyncio TCP servers on 127.0.0.1, each a minimal
     but real HTTP/1.1 receiver (not a mock/stub): it parses the request
     line and headers, reads the body by Content-Length, verifies the
     HMAC-SHA256 transport signature (X-Authgent-Signature-256) against a
     shared secret, then verifies the SET's own JWS signature (RFC 8417/
     ES256) using the transmitting server's real public key, fetched once
     from JWKSService.get_jwks_document at benchmark start (the same JWK
     material a relying party would fetch from GET /.well-known/jwks.json;
     the benchmark does not count that one-time fetch against the timed
     window, since a production receiver would keep a warm JWKS cache —
     see sdks/python/authgent/jwks.py's JWKSFetcher for the equivalent
     production-side caching behavior).
  2. Record t0 = time.perf_counter() immediately before calling
     TokenService.flag_compromised (the "compromise flagged" instant).
  3. Each receiver records its own perf_counter() timestamp at the instant
     both signature checks pass (the "receiver has verified and recorded
     the SET" instant), appended to a shared in-process list.
  4. All receivers and the transmitter run in the SAME asyncio event loop
     / process, so all perf_counter() reads share one clock — no
     cross-machine clock-skew correction is needed or applied.
  5. Latency per receiver = verified_timestamp - t0. Reported: min, median,
     max (the max is "time until the SLOWEST of the N receivers had
     verified the SET"), and mean.
  6. Each N is run REPEAT_COUNT times; all raw per-run figures are saved,
     not just aggregates.

What this does NOT measure: network latency across a real WAN (everything
is on 127.0.0.1), receiver-side business-logic processing after
verification (e.g. actually tearing down a session), or the one-time JWKS
fetch. It also does not model receiver downtime/retry latency — this
benchmark's receivers always respond 200 on the first attempt.

Baseline comparison: AUTHGENT_ACCESS_TOKEN_TTL default is 900 seconds (15
minutes) — authgent_server/config.py:31 (`access_token_ttl: int = 900`).
That is the wait-for-natural-expiry baseline this benchmark's numbers are
compared against in the column: a relying party doing local, stateless JWT
signature verification (no introspection call) has no way to learn of a
revocation before that TTL elapses, per the documented limitation in
docs/security-advisories/2026-08-non-cascading-revocation.md.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import statistics
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

logging.getLogger("structlog").setLevel(logging.WARNING)
os.environ.setdefault("AUTHGENT_DEBUG", "false")

os.environ.setdefault(
    "AUTHGENT_SECRET_KEY",
    "benchmark-secret-key-not-for-production-use-64chars-padding-here!!",
)
os.environ.setdefault("AUTHGENT_DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("AUTHGENT_SERVER_URL", "http://localhost:8000")

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import jwt as pyjwt  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine  # noqa: E402

from authgent_server.config import Settings  # noqa: E402
from authgent_server.models.base import Base  # noqa: E402
from authgent_server.services.audit_service import AuditService  # noqa: E402
from authgent_server.services.delegation_service import DelegationService  # noqa: E402
from authgent_server.services.jwks_service import JWKSService  # noqa: E402
from authgent_server.services.token_service import TokenService  # noqa: E402

RECEIVER_COUNTS = [1, 10, 50, 100, 250]
REPEAT_COUNT = 5
HMAC_SECRET = "benchmark-hmac-shared-secret"
BASE_PORT = 18100


def _jwk_to_public_key(jwk: dict) -> ec.EllipticCurvePublicKey:
    x = base64.urlsafe_b64decode(jwk["x"] + "==")
    y = base64.urlsafe_b64decode(jwk["y"] + "==")
    numbers = ec.EllipticCurvePublicNumbers(
        x=int.from_bytes(x, "big"), y=int.from_bytes(y, "big"), curve=ec.SECP256R1()
    )
    return numbers.public_key()


class VerifyingReceiver:
    """A minimal, real HTTP/1.1 server that verifies an incoming SET push.

    Not a mock: it does genuine socket I/O, genuine HMAC verification, and
    genuine JWS signature verification against the transmitter's real
    public key.
    """

    def __init__(self, port: int, public_keys: dict[str, ec.EllipticCurvePublicKey]):
        self.port = port
        self._public_keys = public_keys
        self.verified_at: list[float] = []
        self._server: asyncio.AbstractServer | None = None

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", self.port)

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            headers: dict[str, str] = {}
            # Request line
            await reader.readline()
            while True:
                line = await reader.readline()
                if line in (b"\r\n", b""):
                    break
                if b":" in line:
                    k, v = line.decode().split(":", 1)
                    headers[k.strip().lower()] = v.strip()

            content_length = int(headers.get("content-length", "0"))
            body = await reader.readexactly(content_length) if content_length else b""

            ok = self._verify(body, headers)

            status = "200 OK" if ok else "400 Bad Request"
            response = f"HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            writer.write(response.encode())
            await writer.drain()
        finally:
            writer.close()

    def _verify(self, body: bytes, headers: dict[str, str]) -> bool:
        sig_header = headers.get("x-authgent-signature-256", "")
        expected = hmac.new(HMAC_SECRET.encode(), body, hashlib.sha256).hexdigest()
        if not sig_header.startswith("sha256="):
            return False
        if not hmac.compare_digest(sig_header[7:], expected):
            return False

        try:
            unverified = pyjwt.get_unverified_header(body.decode())
            kid = unverified.get("kid")
            public_key = self._public_keys.get(kid)
            if public_key is None:
                return False
            pyjwt.decode(
                body.decode(),
                public_key,
                algorithms=["ES256"],
                options={"verify_aud": False},
            )
        except Exception:
            return False

        self.verified_at.append(time.perf_counter())
        return True


async def _run_one(n_receivers: int, transmitter_settings: Settings) -> dict:
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:", connect_args={"check_same_thread": False}
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    jwks = JWKSService(transmitter_settings)
    async with session_factory() as db:
        await jwks.get_active_key(db)
        jwks_doc = await jwks.get_jwks_document(db)
    public_keys = {k["kid"]: _jwk_to_public_key(k) for k in jwks_doc["keys"]}

    ports = [BASE_PORT + i for i in range(n_receivers)]
    receivers = [VerifyingReceiver(p, public_keys) for p in ports]
    for r in receivers:
        await r.start()

    receiver_urls = [f"http://127.0.0.1:{p}/receive" for p in ports]
    transmitter_settings.caep_receiver_urls = ",".join(receiver_urls)
    transmitter_settings.caep_hmac_secret = HMAC_SECRET

    audit = AuditService()
    delegation = DelegationService(transmitter_settings)
    token_service = TokenService(
        settings=transmitter_settings, jwks=jwks, delegation=delegation, audit=audit
    )

    async with session_factory() as db:
        t0 = time.perf_counter()
        results = await token_service.flag_compromised(
            db,
            jti="tok_benchmark_jti",
            reason="benchmark",
            client_id="bench-client",
            actor_id="bench-actor",
        )
        delivered = sum(1 for r in results if r.delivered)

    latencies = []
    for r in receivers:
        for v in r.verified_at:
            latencies.append(v - t0)

    for r in receivers:
        await r.stop()
    await engine.dispose()

    return {
        "n_receivers": n_receivers,
        "delivered": delivered,
        "verified": len(latencies),
        "latencies_seconds": sorted(latencies),
    }


async def main() -> None:
    settings = Settings(
        secret_key=os.environ["AUTHGENT_SECRET_KEY"],
        database_url="sqlite+aiosqlite:///:memory:",
        server_url="http://localhost:8000",
        caep_retries=1,
        caep_backoff="0.1",
        caep_timeout=5.0,
    )

    all_runs = []
    for n in RECEIVER_COUNTS:
        run_results = []
        for _ in range(REPEAT_COUNT):
            result = await _run_one(n, settings)
            run_results.append(result)
        all_lat = [lat for r in run_results for lat in r["latencies_seconds"]]
        summary = {
            "n_receivers": n,
            "repeat_count": REPEAT_COUNT,
            "runs": run_results,
            "aggregate_seconds": {
                "min": min(all_lat) if all_lat else None,
                "median": statistics.median(all_lat) if all_lat else None,
                "mean": statistics.mean(all_lat) if all_lat else None,
                "max": max(all_lat) if all_lat else None,
            },
        }
        all_runs.append(summary)
        agg = summary["aggregate_seconds"]
        print(
            f"N={n:4d}  min={agg['min'] * 1000:8.3f}ms  "
            f"median={agg['median'] * 1000:8.3f}ms  "
            f"mean={agg['mean'] * 1000:8.3f}ms  "
            f"max={agg['max'] * 1000:8.3f}ms"
        )

    output = {
        "generated_at": datetime.now(UTC).isoformat(),
        "methodology": (
            "See module docstring in "
            "server/tests/research/caep_latency_benchmark.py. "
            "All timestamps taken from time.perf_counter() in a single "
            "process/event loop; transmitter and receivers share one clock. "
            "Receivers are real asyncio TCP servers performing genuine HMAC "
            "and ES256 JWS verification, not mocks."
        ),
        "receiver_counts_tested": RECEIVER_COUNTS,
        "repeat_count": REPEAT_COUNT,
        "token_ttl_baseline_seconds": 900,
        "token_ttl_baseline_source": (
            "authgent_server/config.py:31 (access_token_ttl default). "
            "This is the codebase's own default, not an external assumption."
        ),
        "results": all_runs,
    }

    out_path = Path(__file__).with_name("caep_latency_results.json")
    out_path.write_text(json.dumps(output, indent=2))
    print(f"\nRaw results written to {out_path}")


if __name__ == "__main__":
    asyncio.run(main())
