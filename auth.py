"""
Globus Auth (OIDC) integration for gating the dashboard pages behind a
NERSC login, while leaving the GitHub webhook POST endpoint untouched.

Session policy:
- MAX_SESSION_AGE: hard cap on how long a session is valid, regardless of activity.
- IDLE_TIMEOUT: session is invalidated if there's been no authenticated
  request within this window, even if MAX_SESSION_AGE hasn't been reached.
"""

import logging
import os
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


def _read_secret_file(file_path: str) -> str:
    """Read a secret value from a file (matches the pattern used elsewhere in app.py)."""
    try:
        with open(file_path, "r") as f:
            return f.read().strip()
    except Exception as e:
        logging.error(f"Error reading secret file {file_path}: {e}")
        return ""


# --- Configuration (paths to secret files, matching WEBHOOK_SECRET/client_id/private_key style) ---
GLOBUS_CLIENT_ID_FILE = os.getenv("GLOBUS_CLIENT_ID_FILE", "")
GLOBUS_CLIENT_SECRET_FILE = os.getenv("GLOBUS_CLIENT_SECRET_FILE", "")
SESSION_SECRET_FILE = os.getenv("SESSION_SECRET_FILE", "")

GLOBUS_REDIRECT_URI = os.getenv("GLOBUS_REDIRECT_URI", "https://localhost:8000/auth/callback")
GLOBUS_AUTH_BASE = "https://auth.globus.org"

# The Globus identity provider UUID for NERSC logins. Confirm the exact
# value with NERSC/Globus docs or a support ticket before deploying.
NERSC_IDENTITY_PROVIDER_ID = os.getenv("NERSC_IDENTITY_PROVIDER_ID", "")

# --- Session timeout policy ---
MAX_SESSION_AGE = int(os.getenv("MAX_SESSION_AGE_SECONDS", str(8 * 60 * 60)))  # 8 hours
IDLE_TIMEOUT = int(os.getenv("IDLE_TIMEOUT_SECONDS", str(30 * 60)))  # 30 minutes


def get_globus_client_id() -> str:
    return _read_secret_file(GLOBUS_CLIENT_ID_FILE)


def get_globus_client_secret() -> str:
    return _read_secret_file(GLOBUS_CLIENT_SECRET_FILE)


def get_session_secret() -> bytes:
    secret = _read_secret_file(SESSION_SECRET_FILE)
    if not secret:
        # Fail loudly in production rather than silently running with a
        # throwaway key that invalidates on every restart / differs per worker.
        raise RuntimeError(
            "SESSION_SECRET_FILE is not configured or unreadable. "
            "Set SESSION_SECRET_FILE to a file containing a random 32+ byte secret."
        )
    return secret.encode("utf-8")


@get("/auth/login")
async def login(request: Any, next: str = "/") -> Redirect:
    """Redirect the user to Globus Auth to log in."""
    state_token = secrets.token_urlsafe(24)
    request.session["oauth_state"] = state_token
    request.session["post_login_redirect"] = next

    params = {
        "client_id": get_globus_client_id(),
        "response_type": "code",
        "scope": "openid profile email",
        "redirect_uri": GLOBUS_REDIRECT_URI,
        "state": state_token,
    }
    url = f"{GLOBUS_AUTH_BASE}/v2/oauth2/authorize?{urlencode(params)}"
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
            f"{GLOBUS_AUTH_BASE}/v2/oauth2/token",
            data={
                "code": code,
                "redirect_uri": GLOBUS_REDIRECT_URI,
                "grant_type": "authorization_code",
            },
            auth=(get_globus_client_id(), get_globus_client_secret()),
        )
        token_resp.raise_for_status()
        tokens = token_resp.json()

        userinfo_resp = await client.get(
            f"{GLOBUS_AUTH_BASE}/v2/oauth2/userinfo",
            headers={"Authorization": f"Bearer {tokens['access_token']}"},
        )
        userinfo_resp.raise_for_status()
        userinfo = userinfo_resp.json()

    identity_provider = userinfo.get("identity_provider")
    if NERSC_IDENTITY_PROVIDER_ID and identity_provider != NERSC_IDENTITY_PROVIDER_ID:
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
    - the session hasn't exceeded MAX_SESSION_AGE since login
    - the session hasn't been idle longer than IDLE_TIMEOUT

    On success, refreshes the idle clock.
    """
    session = connection.session
    user = session.get("user")
    authenticated_at = session.get("authenticated_at")
    last_seen = session.get("last_seen")

    if not user or authenticated_at is None or last_seen is None:
        raise NotAuthorizedException("Login required")

    now = time.time()

    if now - authenticated_at > MAX_SESSION_AGE:
        session.clear()
        raise NotAuthorizedException("Session expired, please log in again")

    if now - last_seen > IDLE_TIMEOUT:
        session.clear()
        raise NotAuthorizedException("Session expired due to inactivity, please log in again")

    session["last_seen"] = now


auth_router = Router(path="/", route_handlers=[login, callback, logout])
