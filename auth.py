"""
Globus Auth (OIDC) integration for gating the dashboard pages behind a
NERSC login, while leaving the GitHub webhook POST endpoint untouched.

Session policy (see config.SessionConfig):
- max_age_seconds: hard cap on how long a session is valid, regardless of activity.
- idle_timeout_seconds: session is invalidated if there's been no authenticated
  request within this window, even if max_age_seconds hasn't been reached.
"""

import logging
import secrets
import time
from typing import Any, Optional
from urllib.parse import urlencode

import httpx

from litestar import Router, get
from litestar.connection import ASGIConnection
from litestar.exceptions import NotAuthorizedException
from litestar.handlers.base import BaseRouteHandler
from litestar.params import Parameter
from litestar.response import Redirect
from litestar.datastructures import State

from config import config


@get("/auth/login")
async def login(request: Any, next: str = "/") -> Redirect:
    """Redirect the user to Globus Auth to log in."""
    state_token = secrets.token_urlsafe(24)
    request.session["oauth_state"] = state_token
    request.session["post_login_redirect"] = next

    params = {
        "client_id": config.globus.client_id,
        "response_type": "code",
        "scope": "openid profile email",
        "redirect_uri": config.globus.redirect_uri,
        "state": state_token,
    }
    url = f"{config.globus.auth_base}/v2/oauth2/authorize?{urlencode(params)}"
    return Redirect(url)


@get("/auth/callback")
async def callback(
    request: Any,
    code: str,
    oauth_state: Optional[str] = Parameter(query="state", default=None), # Rename 'state' to avoid reserve kwarg conflict
) -> Redirect:
    """Handle the redirect back from Globus Auth after login."""
    expected_state = request.session.get("oauth_state")
    if not oauth_state or not expected_state or oauth_state != expected_state:
        logging.warning("Globus auth callback: state mismatch, possible CSRF attempt.")
        raise NotAuthorizedException("Invalid login state, please try again.")

    async with httpx.AsyncClient() as client:
        token_resp = await client.post(
            f"{config.globus.auth_base}/v2/oauth2/token",
            data={
                "code": code,
                "redirect_uri": config.globus.redirect_uri,
                "grant_type": "authorization_code",
            },
            auth=(config.globus.client_id, config.globus.client_secret),
        )
        token_resp.raise_for_status()
        tokens = token_resp.json()

        userinfo_resp = await client.get(
            f"{config.globus.auth_base}/v2/oauth2/userinfo",
            headers={"Authorization": f"Bearer {tokens['access_token']}"},
        )
        userinfo_resp.raise_for_status()
        userinfo = userinfo_resp.json()

    identity_provider = userinfo.get("identity_provider")
    if config.globus.nersc_identity_provider_id and identity_provider != config.globus.nersc_identity_provider_id:
        logging.warning(
            f"Rejected login from identity provider {identity_provider}: not NERSC."
        )
        raise NotAuthorizedException("Login must be performed with a NERSC identity.")

    now = time.time()
    request.session["user"] = {
        "sub": userinfo.get("sub"),
        "email": userinfo.get("email"),
        "name": userinfo.get("name"),
        "username": userinfo.get("preferred_username"),
    }
    request.session["authenticated_at"] = now
    request.session["last_seen"] = now

    redirect_to = request.session.pop("post_login_redirect", "/") or "/"
    request.session.pop("oauth_state", None)

    logging.info(f"User {userinfo.get('preferred_username')} logged in via Globus/NERSC.")
    return Redirect(redirect_to)


@get("/auth/logout")
async def logout(request: Any) -> Redirect:
    """Clear the session."""
    request.session.clear()
    return Redirect("/")


def require_login(connection: ASGIConnection, _: BaseRouteHandler) -> None:
    """
    Guard for route handlers. Enforces:
    - a logged-in user is present in the session
    - the session hasn't exceeded config.session.max_age_seconds since login
    - the session hasn't been idle longer than config.session.idle_timeout_seconds

    On success, refreshes the idle clock.
    """
    session = connection.session
    user = session.get("user")
    authenticated_at = session.get("authenticated_at")
    last_seen = session.get("last_seen")

    if not user or authenticated_at is None or last_seen is None:
        raise NotAuthorizedException("Login required")

    now = time.time()

    if now - authenticated_at > config.session.max_age_seconds:
        session.clear()
        raise NotAuthorizedException("Session expired, please log in again")

    if now - last_seen > config.session.idle_timeout_seconds:
        session.clear()
        raise NotAuthorizedException("Session expired due to inactivity, please log in again")

    session["last_seen"] = now


auth_router = Router(path="/", route_handlers=[login, callback, logout])
