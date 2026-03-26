"""GET/POST /authorize — Authorization Code + PKCE flow with consent page."""

from __future__ import annotations

import hashlib
import hmac as hmac_mod
import os
import secrets
import time
from datetime import timedelta

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from jinja2 import Environment, FileSystemLoader
from sqlalchemy.ext.asyncio import AsyncSession

from authgent_server.config import Settings, get_settings
from authgent_server.dependencies import (
    get_client_service,
    get_consent_service,
    get_db_session,
)
from authgent_server.errors import InvalidClient, InvalidRequest
from authgent_server.models.authorization_code import AuthorizationCode
from authgent_server.services.client_service import ClientService
from authgent_server.services.consent_service import ConsentService
from authgent_server.utils import utcnow

router = APIRouter(tags=["authorization"])


def _generate_csrf_token(session_id: str, csrf_key: bytes) -> str:
    ts = str(int(time.time()))
    sig = hmac_mod.new(csrf_key, f"{session_id}:{ts}".encode(), hashlib.sha256).hexdigest()
    return f"{ts}.{sig}"


def _validate_csrf_token(token: str, session_id: str, csrf_key: bytes, max_age: int = 600) -> bool:
    try:
        ts, sig = token.split(".", 1)
        if int(time.time()) - int(ts) > max_age:
            return False
    except (ValueError, TypeError):
        return False
    expected = hmac_mod.new(csrf_key, f"{session_id}:{ts}".encode(), hashlib.sha256).hexdigest()
    return hmac_mod.compare_digest(sig, expected)


@router.get("/authorize")
async def authorize_get(
    request: Request,
    response_type: str = "",
    client_id: str = "",
    redirect_uri: str = "",
    scope: str = "",
    state: str = "",
    code_challenge: str = "",
    code_challenge_method: str = "S256",
    resource: str = "",
    nonce: str = "",
    db: AsyncSession = Depends(get_db_session),
    client_service: ClientService = Depends(get_client_service),
    settings: Settings = Depends(get_settings),
) -> Response:
    """Authorization endpoint — show consent page or auto-approve."""
    if response_type != "code":
        raise InvalidRequest("response_type must be 'code'")
    if not client_id:
        raise InvalidRequest("client_id is required")
    if not code_challenge:
        raise InvalidRequest("code_challenge is required (PKCE mandatory)")
    if code_challenge_method != "S256":
        raise InvalidRequest("Only S256 code_challenge_method is supported")
    if not redirect_uri:
        raise InvalidRequest("redirect_uri is required")

    client = await client_service.get_client(db, client_id)
    if not client:
        raise InvalidClient(f"Client not found: {client_id}")

    # Validate redirect_uri
    if client.redirect_uris and redirect_uri not in client.redirect_uris:
        raise InvalidRequest("redirect_uri not registered for this client")

    # Auto-approve mode (dev only)
    if settings.consent_mode == "auto_approve":
        auth_code = secrets.token_urlsafe(32)
        code_record = AuthorizationCode(
            code=auth_code,
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=scope,
            resource=resource,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            subject="auto_approved_user",
            nonce=nonce or None,
            expires_at=utcnow() + timedelta(seconds=settings.authorization_code_ttl),
        )
        db.add(code_record)
        await db.commit()

        sep = "&" if "?" in redirect_uri else "?"
        location = f"{redirect_uri}{sep}code={auth_code}"
        if state:
            location += f"&state={state}"
        return RedirectResponse(url=location, status_code=302)

    # Render consent page
    session_id = secrets.token_urlsafe(16)
    csrf_token = _generate_csrf_token(session_id, settings._csrf_key)

    templates_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates")
    env = Environment(loader=FileSystemLoader(templates_dir), autoescape=True)
    template = env.get_template("consent.html")

    html = template.render(
        client_name=client.client_name or client_id,
        resource=resource,
        scopes=scope.split() if scope else [],
        scope=scope,
        csrf_token=csrf_token,
        client_id=client_id,
        redirect_uri=redirect_uri,
        state=state,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        response_type=response_type,
        nonce=nonce,
    )

    response = HTMLResponse(content=html)
    response.set_cookie(
        "authgent_session",
        session_id,
        httponly=True,
        samesite="lax",
        max_age=600,
    )
    return response


@router.post("/authorize")
async def authorize_post(
    request: Request,
    db: AsyncSession = Depends(get_db_session),
    consent_service: ConsentService = Depends(get_consent_service),
    settings: Settings = Depends(get_settings),
) -> Response:
    """Process consent form submission."""
    form = await request.form()
    action = form.get("action")
    client_id = str(form.get("client_id", ""))
    redirect_uri = str(form.get("redirect_uri", ""))
    scope = str(form.get("scope", ""))
    state = str(form.get("state", ""))
    code_challenge = str(form.get("code_challenge", ""))
    code_challenge_method = str(form.get("code_challenge_method", "S256"))
    resource = str(form.get("resource", ""))
    nonce = str(form.get("nonce", ""))
    csrf_token = str(form.get("csrf_token", ""))

    # CSRF validation
    session_id = request.cookies.get("authgent_session", "")
    if not _validate_csrf_token(csrf_token, session_id, settings._csrf_key):
        raise InvalidRequest("Invalid CSRF token")

    sep = "&" if "?" in redirect_uri else "?"

    if action == "deny":
        return RedirectResponse(
            url=f"{redirect_uri}{sep}error=access_denied&state={state}",
            status_code=302,
        )

    if action != "allow":
        raise InvalidRequest(f"Invalid consent action: {action}")

    # Grant consent and issue authorization code
    # TODO: In production, use authenticated user identity
    subject = "consent_user"

    await consent_service.grant_consent(db, subject, client_id, scope, resource or None)

    auth_code = secrets.token_urlsafe(32)
    code_record = AuthorizationCode(
        code=auth_code,
        client_id=client_id,
        redirect_uri=redirect_uri,
        scope=scope,
        resource=resource,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        subject=subject,
        nonce=nonce or None,
        expires_at=utcnow() + timedelta(seconds=settings.authorization_code_ttl),
    )
    db.add(code_record)
    await db.commit()

    location = f"{redirect_uri}{sep}code={auth_code}"
    if state:
        location += f"&state={state}"
    return RedirectResponse(url=location, status_code=302)
