"""GET /tokens/inspect — Decode any JWT and show delegation chain (no verification required)."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime

from fastapi import APIRouter, Query
from pydantic import BaseModel

router = APIRouter(tags=["tokens"])


class ActorInfo(BaseModel):
    sub: str
    act: "ActorInfo | None" = None


class DelegationChainInfo(BaseModel):
    depth: int
    actors: list[str]
    human_root: bool


class TokenInspectResponse(BaseModel):
    valid: bool
    claims: dict | None = None
    delegation_chain: DelegationChainInfo | None = None
    dpop_bound: bool = False
    dpop_jkt: str | None = None
    expired: bool | None = None
    expires_at: str | None = None
    issued_at: str | None = None
    time_remaining_seconds: int | None = None
    error: str | None = None


def _decode_jwt_payload(token: str) -> dict | None:
    """Decode JWT payload without signature verification."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        payload = parts[1]
        payload += "=" * (4 - len(payload) % 4)
        decoded = base64.urlsafe_b64decode(payload)
        return json.loads(decoded)
    except Exception:
        return None


def _extract_delegation_chain(claims: dict) -> DelegationChainInfo | None:
    """Extract flat list of actors from nested act claims."""
    act = claims.get("act")
    if not act or not isinstance(act, dict):
        return None

    actors: list[str] = []
    current = act
    while current and isinstance(current, dict):
        actors.append(current.get("sub", "unknown"))
        current = current.get("act")

    # Check if the chain has a human root
    sub = claims.get("sub", "")
    human_root = str(sub).startswith("user:")

    return DelegationChainInfo(
        depth=len(actors),
        actors=actors,
        human_root=human_root,
    )


@router.get("/tokens/inspect", response_model=TokenInspectResponse)
async def inspect_token(
    token: str = Query(..., description="JWT access token to inspect"),
) -> TokenInspectResponse:
    """Decode any JWT and return claims, delegation chain, expiry status.

    This endpoint does NOT verify the token signature — it is for inspection
    and visualization only. Use POST /introspect for cryptographic verification.

    Unlike POST /introspect (RFC 7662), this works on expired and revoked tokens too.
    """
    claims = _decode_jwt_payload(token)
    if claims is None:
        return TokenInspectResponse(
            valid=False,
            error="Could not decode JWT payload — not a valid JWT",
        )

    # Expiry check
    exp = claims.get("exp")
    iat = claims.get("iat")
    expired = None
    expires_at = None
    issued_at = None
    time_remaining = None

    if isinstance(exp, (int, float)):
        exp_dt = datetime.fromtimestamp(exp, tz=UTC)
        expires_at = exp_dt.isoformat()
        now = datetime.now(UTC)
        expired = exp_dt < now
        if not expired:
            time_remaining = int((exp_dt - now).total_seconds())

    if isinstance(iat, (int, float)):
        issued_at = datetime.fromtimestamp(iat, tz=UTC).isoformat()

    # DPoP binding
    cnf = claims.get("cnf")
    dpop_bound = False
    dpop_jkt = None
    if cnf and isinstance(cnf, dict):
        dpop_jkt = cnf.get("jkt")
        dpop_bound = dpop_jkt is not None

    # Delegation chain
    delegation_chain = _extract_delegation_chain(claims)

    return TokenInspectResponse(
        valid=True,
        claims=claims,
        delegation_chain=delegation_chain,
        dpop_bound=dpop_bound,
        dpop_jkt=dpop_jkt,
        expired=expired,
        expires_at=expires_at,
        issued_at=issued_at,
        time_remaining_seconds=time_remaining,
    )
