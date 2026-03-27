"""Token service — grant handlers, token issuance, exchange, refresh."""

from __future__ import annotations

import base64
import hashlib
import secrets
from datetime import UTC, datetime, timedelta

import structlog
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from authgent_server.config import Settings
from authgent_server.errors import (
    InvalidGrant,
    InvalidRequest,
    TokenRevoked,
    UnsupportedGrantType,
)
from authgent_server.models.authorization_code import AuthorizationCode
from authgent_server.models.device_code import DeviceCode
from authgent_server.models.refresh_token import RefreshToken
from authgent_server.models.token_blocklist import TokenBlocklist
from authgent_server.providers.protocols import ClaimEnricher
from authgent_server.schemas.token import TokenResponse
from authgent_server.services.audit_service import AuditService
from authgent_server.services.delegation_service import DelegationService
from authgent_server.services.external_oidc import (
    ACCESS_TOKEN_TYPE,
    ID_TOKEN_TYPE,
    ExternalIDTokenVerifier,
)
from authgent_server.services.jwks_service import JWKSService
from authgent_server.utils import is_expired, utcnow

logger = structlog.get_logger()


def _generate_jti() -> str:
    return f"tok_{secrets.token_urlsafe(24)}"


class TokenService:
    def __init__(
        self,
        settings: Settings,
        jwks: JWKSService,
        delegation: DelegationService,
        audit: AuditService,
        claim_enricher: ClaimEnricher | None = None,
        external_oidc: ExternalIDTokenVerifier | None = None,
    ):
        self._settings = settings
        self._jwks = jwks
        self._delegation = delegation
        self._audit = audit
        self._enricher = claim_enricher
        self._external_oidc = external_oidc

    async def issue_token(
        self,
        db: AsyncSession,
        grant_type: str,
        client_id: str,
        *,
        scope: str | None = None,
        resource: str | None = None,
        subject: str | None = None,
        code: str | None = None,
        code_verifier: str | None = None,
        redirect_uri: str | None = None,
        refresh_token_value: str | None = None,
        subject_token: str | None = None,
        subject_token_type: str | None = None,
        audience: str | None = None,
        device_code: str | None = None,
        dpop_jkt: str | None = None,
        ip_address: str | None = None,
    ) -> TokenResponse:
        """Dispatch to the appropriate grant handler."""
        handlers = {
            "client_credentials": self._handle_client_credentials,
            "authorization_code": self._handle_authorization_code,
            "refresh_token": self._handle_refresh_token,
            "urn:ietf:params:oauth:grant-type:token-exchange": self._handle_token_exchange,
            "urn:ietf:params:oauth:grant-type:device_code": self._handle_device_code,
        }

        handler = handlers.get(grant_type)
        if not handler:
            raise UnsupportedGrantType(f"Unsupported grant type: {grant_type}")

        return await handler(
            db=db,
            client_id=client_id,
            scope=scope,
            resource=resource,
            subject=subject,
            code=code,
            code_verifier=code_verifier,
            redirect_uri=redirect_uri,
            refresh_token_value=refresh_token_value,
            subject_token=subject_token,
            subject_token_type=subject_token_type,
            audience=audience,
            device_code=device_code,
            dpop_jkt=dpop_jkt,
            ip_address=ip_address,
        )

    async def _handle_client_credentials(
        self, db: AsyncSession, client_id: str, **kwargs: object
    ) -> TokenResponse:
        """client_credentials grant — agent authenticates with client_id/secret."""
        scope = kwargs.get("scope") or ""
        resource = kwargs.get("resource")
        dpop_jkt = kwargs.get("dpop_jkt")

        ttl = self._settings.client_credentials_ttl or self._settings.access_token_ttl
        now = utcnow()
        jti = _generate_jti()

        claims: dict = {
            "iss": self._settings.server_url,
            "sub": f"client:{client_id}",
            "aud": resource or self._settings.server_url,
            "exp": int((now + timedelta(seconds=ttl)).timestamp()),
            "iat": int(now.timestamp()),
            "jti": jti,
            "scope": str(scope),
            "client_id": client_id,
        }

        if dpop_jkt:
            claims["cnf"] = {"jkt": dpop_jkt}

        claims = await self._enrich_claims(claims, client_id, None, "client_credentials")
        access_token = await self._jwks.sign_jwt(db, claims)

        await self._audit.log(
            db,
            "token.issued",
            actor=client_id,
            subject=claims["sub"],
            client_id=client_id,
            ip_address=str(kwargs.get("ip_address", "")),
            metadata={"grant_type": "client_credentials", "jti": jti},
        )

        return TokenResponse(
            access_token=access_token,
            token_type="DPoP" if dpop_jkt else "Bearer",
            expires_in=ttl,
            scope=str(scope),
        )

    async def _handle_authorization_code(
        self, db: AsyncSession, client_id: str, **kwargs: object
    ) -> TokenResponse:
        """authorization_code grant — exchange code for tokens."""
        code = kwargs.get("code")
        code_verifier = kwargs.get("code_verifier")
        redirect_uri = kwargs.get("redirect_uri")
        dpop_jkt = kwargs.get("dpop_jkt")

        if not code or not code_verifier:
            raise InvalidRequest("code and code_verifier are required")

        # Atomic CAS: mark code as used
        stmt = (
            update(AuthorizationCode)
            .where(
                AuthorizationCode.code == str(code),
                AuthorizationCode.used == False,  # noqa: E712
                AuthorizationCode.expires_at > datetime.now(UTC),
                AuthorizationCode.client_id == client_id,
            )
            .values(used=True)
            .returning(AuthorizationCode)
        )
        result = await db.execute(stmt)
        auth_code = result.scalar_one_or_none()

        if auth_code is None:
            raise InvalidGrant("Authorization code is invalid, expired, or already used")

        # PKCE verification
        if auth_code.code_challenge_method == "S256":
            challenge = hashlib.sha256(str(code_verifier).encode()).digest()
            expected = base64.urlsafe_b64encode(challenge).rstrip(b"=").decode()
            if expected != auth_code.code_challenge:
                raise InvalidGrant("PKCE code_verifier does not match code_challenge")
        else:
            raise InvalidGrant(
                f"Unsupported code_challenge_method: {auth_code.code_challenge_method}"
            )

        # Verify redirect_uri matches
        if redirect_uri and str(redirect_uri) != auth_code.redirect_uri:
            raise InvalidGrant("redirect_uri does not match")

        # Issue access token
        ttl = self._settings.auth_code_access_ttl or self._settings.access_token_ttl
        now = utcnow()
        jti = _generate_jti()

        claims: dict = {
            "iss": self._settings.server_url,
            "sub": auth_code.subject or f"client:{client_id}",
            "aud": auth_code.resource or self._settings.server_url,
            "exp": int((now + timedelta(seconds=ttl)).timestamp()),
            "iat": int(now.timestamp()),
            "jti": jti,
            "scope": auth_code.scope or "",
            "client_id": client_id,
        }

        if dpop_jkt:
            claims["cnf"] = {"jkt": dpop_jkt}

        claims = await self._enrich_claims(claims, client_id, None, "authorization_code")
        access_token = await self._jwks.sign_jwt(db, claims)

        # Issue refresh token
        refresh_jti = _generate_jti()
        family_id = secrets.token_urlsafe(16)
        refresh_record = RefreshToken(
            jti=refresh_jti,
            client_id=client_id,
            subject=auth_code.subject,
            scope=auth_code.scope,
            resource=auth_code.resource,
            family_id=family_id,
            dpop_jkt=str(dpop_jkt) if dpop_jkt else None,
            expires_at=utcnow() + timedelta(seconds=self._settings.refresh_token_ttl),
        )
        db.add(refresh_record)
        await db.commit()

        await self._audit.log(
            db,
            "token.issued",
            actor=auth_code.subject,
            subject=auth_code.subject,
            client_id=client_id,
            ip_address=str(kwargs.get("ip_address", "")),
            metadata={"grant_type": "authorization_code", "jti": jti},
        )

        return TokenResponse(
            access_token=access_token,
            token_type="DPoP" if dpop_jkt else "Bearer",
            expires_in=ttl,
            scope=auth_code.scope or "",
            refresh_token=refresh_jti,
        )

    async def _handle_refresh_token(
        self, db: AsyncSession, client_id: str, **kwargs: object
    ) -> TokenResponse:
        """refresh_token grant — rotate and reissue."""
        refresh_token_value = kwargs.get("refresh_token_value")
        dpop_jkt = kwargs.get("dpop_jkt")
        resource = kwargs.get("resource")

        if not refresh_token_value:
            raise InvalidRequest("refresh_token is required")

        # Look up refresh token
        stmt = select(RefreshToken).where(
            RefreshToken.jti == str(refresh_token_value),
            RefreshToken.client_id == client_id,
        )
        result = await db.execute(stmt)
        rt = result.scalar_one_or_none()

        if rt is None:
            raise InvalidGrant("Refresh token not found")

        if is_expired(rt.expires_at):
            raise InvalidGrant("Refresh token expired")

        # Check resource binding
        if resource and rt.resource and str(resource) != rt.resource:
            raise InvalidGrant("Resource does not match refresh token binding")

        # REUSE DETECTION: if already used, revoke entire family
        if rt.used:
            logger.warning(
                "refresh_token_reuse_detected",
                jti=rt.jti,
                family_id=rt.family_id,
                client_id=client_id,
            )
            # Revoke all tokens in family
            await db.execute(
                update(RefreshToken).where(RefreshToken.family_id == rt.family_id).values(used=True)
            )
            await db.commit()

            await self._audit.log(
                db,
                "token.replay_detected",
                client_id=client_id,
                metadata={"family_id": rt.family_id, "jti": rt.jti},
            )
            raise InvalidGrant("Refresh token has already been used (replay detected)")

        # Atomic CAS: mark current token as used
        cas_stmt = (
            update(RefreshToken)
            .where(
                RefreshToken.jti == rt.jti,
                RefreshToken.used == False,  # noqa: E712
            )
            .values(used=True)
        )
        cas_result = await db.execute(cas_stmt)
        if cas_result.rowcount == 0:
            raise InvalidGrant("Refresh token race condition — token already consumed")

        # Issue new refresh token in same family
        now = utcnow()
        new_refresh_jti = _generate_jti()
        new_refresh = RefreshToken(
            jti=new_refresh_jti,
            client_id=client_id,
            subject=rt.subject,
            scope=rt.scope,
            resource=rt.resource,
            family_id=rt.family_id,
            dpop_jkt=str(dpop_jkt) if dpop_jkt else rt.dpop_jkt,
            expires_at=utcnow() + timedelta(seconds=self._settings.refresh_token_ttl),
        )
        db.add(new_refresh)

        # Issue new access token
        ttl = self._settings.access_token_ttl
        jti = _generate_jti()

        claims: dict = {
            "iss": self._settings.server_url,
            "sub": rt.subject or f"client:{client_id}",
            "aud": rt.resource or self._settings.server_url,
            "exp": int((now + timedelta(seconds=ttl)).timestamp()),
            "iat": int(now.timestamp()),
            "jti": jti,
            "scope": rt.scope or "",
            "client_id": client_id,
        }

        if dpop_jkt:
            claims["cnf"] = {"jkt": dpop_jkt}

        access_token = await self._jwks.sign_jwt(db, claims)
        await db.commit()

        return TokenResponse(
            access_token=access_token,
            token_type="DPoP" if dpop_jkt else "Bearer",
            expires_in=ttl,
            scope=rt.scope or "",
            refresh_token=new_refresh_jti,
        )

    async def _handle_token_exchange(
        self, db: AsyncSession, client_id: str, **kwargs: object
    ) -> TokenResponse:
        """RFC 8693 token exchange — delegation chain construction.

        Supports two subject_token_type values:
        - access_token (default): exchange an authgent-issued token
        - id_token: exchange an external IdP token (Auth0/Clerk/Okta)
        """
        subject_token = kwargs.get("subject_token")
        subject_token_type = str(kwargs.get("subject_token_type") or ACCESS_TOKEN_TYPE)
        audience_target = kwargs.get("audience")
        scope = kwargs.get("scope")
        dpop_jkt = kwargs.get("dpop_jkt")

        if not subject_token:
            raise InvalidRequest("subject_token is required for token exchange")
        if not audience_target:
            raise InvalidRequest("audience is required for token exchange")

        # Dispatch on subject_token_type (RFC 8693 §2.1)
        if subject_token_type == ID_TOKEN_TYPE:
            parent_claims = await self._verify_external_id_token(str(subject_token))
        elif subject_token_type == ACCESS_TOKEN_TYPE:
            parent_claims = await self.verify_and_check_blocklist(db, str(subject_token))
        else:
            raise InvalidRequest(f"Unsupported subject_token_type: {subject_token_type}")

        # Build delegation claims
        requested_scopes = str(scope).split() if scope else []
        delegated_claims = self._delegation.build_delegated_claims(
            parent_claims=parent_claims,
            actor_id=f"client:{client_id}",
            target_audience=str(audience_target),
            requested_scopes=requested_scopes,
        )

        # Issue new token
        ttl = self._settings.exchange_token_ttl
        now = utcnow()
        jti = _generate_jti()

        claims: dict = {
            "iss": self._settings.server_url,
            **delegated_claims,
            "exp": int((now + timedelta(seconds=ttl)).timestamp()),
            "iat": int(now.timestamp()),
            "jti": jti,
            "client_id": client_id,
        }

        if dpop_jkt:
            claims["cnf"] = {"jkt": dpop_jkt}

        claims = await self._enrich_claims(claims, client_id, None, "token_exchange")
        access_token = await self._jwks.sign_jwt(db, claims)

        await self._audit.log(
            db,
            "token.exchanged",
            actor=f"client:{client_id}",
            subject=claims.get("sub"),
            client_id=client_id,
            metadata={
                "grant_type": "token_exchange",
                "subject_token_type": subject_token_type,
                "jti": jti,
                "parent_jti": parent_claims.get("jti"),
                "audience": str(audience_target),
                "human_root": parent_claims.get("human_root", False),
            },
        )

        return TokenResponse(
            access_token=access_token,
            token_type="DPoP" if dpop_jkt else "Bearer",
            expires_in=ttl,
            scope=" ".join(requested_scopes),
            issued_token_type="urn:ietf:params:oauth:token-type:access_token",
        )

    async def _verify_external_id_token(self, token: str) -> dict:
        """Verify an external id_token via the ExternalIDTokenVerifier.

        Returns normalized claims suitable for delegation chain construction.
        The returned claims include 'sub' as 'user:{idp_sub}' and
        'human_root': True so downstream delegation recognizes
        this as a human-rooted chain.
        """
        if self._external_oidc is None:
            raise InvalidRequest(
                "External id_token exchange is not configured. Set AUTHGENT_TRUSTED_OIDC_ISSUERS."
            )
        verified = await self._external_oidc.verify_id_token(token)

        # Build parent_claims compatible with delegation service
        return {
            "sub": verified["sub"],
            "scope": "",  # id_tokens don't carry scopes; client requests scopes
            "idp_iss": verified["idp_iss"],
            "idp_sub": verified["idp_sub"],
            "human_root": True,
        }

    async def _handle_device_code(
        self, db: AsyncSession, client_id: str, **kwargs: object
    ) -> TokenResponse:
        """urn:ietf:params:oauth:grant-type:device_code — RFC 8628 §3.4.

        Polls the device_codes table; issues a token if the code is approved.
        """
        device_code_value = kwargs.get("device_code") or kwargs.get("code")
        if not device_code_value:
            raise InvalidRequest("device_code is required")

        stmt = select(DeviceCode).where(
            DeviceCode.device_code == str(device_code_value),
            DeviceCode.client_id == client_id,
        )
        result = await db.execute(stmt)
        record = result.scalar_one_or_none()

        if not record:
            raise InvalidGrant("Unknown device code")

        if is_expired(record.expires_at):
            raise InvalidGrant("Device code expired")

        if record.status == "denied":
            raise InvalidGrant("Device authorization request was denied")

        if record.status != "approved":
            raise InvalidGrant("authorization_pending")

        # Atomic CAS: mark as consumed
        cas = (
            update(DeviceCode)
            .where(
                DeviceCode.device_code == str(device_code_value),
                DeviceCode.status == "approved",
            )
            .values(status="consumed")
        )
        cas_result = await db.execute(cas)
        if cas_result.rowcount == 0:
            raise InvalidGrant("Device code already consumed")
        await db.commit()

        # Issue token (same as client_credentials but with device subject)
        return await self._handle_client_credentials(
            db=db,
            client_id=client_id,
            scope=record.scope,
            subject=record.subject,
            **{
                k: v
                for k, v in kwargs.items()
                if k not in ("device_code", "code", "scope", "subject")
            },
        )

    async def revoke_token(self, db: AsyncSession, token: str, client_id: str) -> None:
        """Revoke a token by adding its JTI to the blocklist."""
        try:
            claims = await self._jwks.verify_jwt(db, token)
        except Exception:
            # RFC 7009: revocation of invalid tokens is not an error
            return

        jti = claims.get("jti")
        if not jti:
            return

        # Add to blocklist
        blocklist_entry = TokenBlocklist(
            jti=jti,
            expires_at=datetime.fromtimestamp(claims.get("exp", 0), tz=UTC),
            reason="user_revoke",
        )
        db.add(blocklist_entry)

        try:
            await db.commit()
        except Exception:
            await db.rollback()
            # Already revoked — idempotent
            return

        await self._audit.log(
            db,
            "token.revoked",
            client_id=client_id,
            metadata={"jti": jti},
        )

    async def is_token_revoked(self, db: AsyncSession, jti: str) -> bool:
        """Check if a token JTI is in the blocklist."""
        stmt = select(TokenBlocklist).where(TokenBlocklist.jti == jti)
        result = await db.execute(stmt)
        return result.scalar_one_or_none() is not None

    async def verify_and_check_blocklist(
        self, db: AsyncSession, token: str, audience: str | None = None
    ) -> dict:
        """Verify a JWT and ensure it hasn't been revoked."""
        claims = await self._jwks.verify_jwt(db, token, audience)
        jti = claims.get("jti")
        if jti and await self.is_token_revoked(db, jti):
            raise TokenRevoked(f"Token {jti} has been revoked")
        return claims

    async def _enrich_claims(
        self,
        claims: dict,
        client_id: str,
        agent_id: str | None,
        grant_type: str,
    ) -> dict:
        """Run ClaimEnricher if configured. Fail-open: enricher errors don't block issuance."""
        if self._enricher is None:
            return claims
        try:
            return await self._enricher.enrich(claims, client_id, agent_id, grant_type)
        except Exception as e:
            logger.warning(
                "claim_enricher_failed",
                error=str(e),
                client_id=client_id,
                grant_type=grant_type,
            )
            return claims
