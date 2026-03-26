"""Core token verification — framework-agnostic."""

from __future__ import annotations

import base64

import jwt
from cryptography.hazmat.primitives.asymmetric import ec

from authgent.errors import InvalidTokenError
from authgent.jwks import JWKSFetcher
from authgent.models import AgentIdentity

# Module-level JWKS fetcher cache (keyed by issuer)
_fetchers: dict[str, JWKSFetcher] = {}


def _get_fetcher(issuer: str) -> JWKSFetcher:
    if issuer not in _fetchers:
        _fetchers[issuer] = JWKSFetcher(issuer)
    return _fetchers[issuer]


def _jwk_to_public_key(jwk: dict) -> ec.EllipticCurvePublicKey:
    """Convert JWK dict to cryptography public key."""
    x = base64.urlsafe_b64decode(jwk["x"] + "==")
    y = base64.urlsafe_b64decode(jwk["y"] + "==")
    pub_numbers = ec.EllipticCurvePublicNumbers(
        x=int.from_bytes(x, "big"),
        y=int.from_bytes(y, "big"),
        curve=ec.SECP256R1(),
    )
    return pub_numbers.public_key()


async def verify_token(
    token: str,
    issuer: str,
    audience: str | None = None,
    jwks_fetcher: JWKSFetcher | None = None,
) -> AgentIdentity:
    """Verify a JWT token against the issuer's JWKS.

    Args:
        token: The JWT access token string.
        issuer: The expected issuer (authgent server URL or external IdP URL).
        audience: Expected audience claim. None to skip audience validation.
        jwks_fetcher: Optional custom JWKS fetcher. Uses cached fetcher if None.

    Returns:
        AgentIdentity with verified claims.

    Raises:
        InvalidTokenError: If verification fails.
    """
    fetcher = jwks_fetcher or _get_fetcher(issuer)

    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.DecodeError as e:
        raise InvalidTokenError(f"Malformed JWT: {e}")

    kid = unverified_header.get("kid")
    if not kid:
        raise InvalidTokenError("Token missing kid header")

    # Fetch public key
    jwk = await fetcher.get_key(kid)
    public_key = _jwk_to_public_key(jwk)

    # Verify signature + standard claims
    options: dict = {}
    if audience is None:
        options["verify_aud"] = False

    try:
        claims = jwt.decode(
            token,
            public_key,
            algorithms=["ES256"],
            issuer=issuer,
            audience=audience,
            options=options,
        )
    except jwt.ExpiredSignatureError:
        raise InvalidTokenError("Token has expired")
    except jwt.InvalidIssuerError:
        raise InvalidTokenError(f"Invalid issuer: expected {issuer}")
    except jwt.InvalidAudienceError:
        raise InvalidTokenError(f"Invalid audience: expected {audience}")
    except jwt.InvalidTokenError as e:
        raise InvalidTokenError(f"Token verification failed: {e}")

    # Warn if token is very large (deep delegation chains)
    token_size = len(token)
    if token_size > 4096:
        import warnings

        warnings.warn(
            f"Token size ({token_size} bytes) exceeds 4KB — "
            "may exceed reverse proxy header limits with deep delegation chains",
            stacklevel=2,
        )

    return AgentIdentity.from_claims(claims)
