"""
Globus Auth (OIDC) integration for gating the dashboard pages behind a
NERSC login, while leaving the GitHub webhook POST endpoint untouched.

After Globus authentication, every guarded route additionally requires
membership in the NERSC unix group config.ldap.user_group; the admission
configuration routes (admission.py) stack a second guard requiring
config.ldap.admin_group. Membership is checked live (with a short in-process
LDAP cache), so group removals take effect without touching the session.

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
from anyio import to_thread

from litestar import Router, get
from litestar.connection import ASGIConnection
from litestar.exceptions import NotAuthorizedException, ServiceUnavailableException
from litestar.handlers.base import BaseRouteHandler
from litestar.params import Parameter
from litestar.response import Redirect
from litestar.datastructures import State

from config import config
from ldap_auth import LDAPAuthorizer, LDAPAuthorizationError


# Process-wide authorizer; reads LDAPSettings from the environment/config once.
_ldap_authorizer = LDAPAuthorizer()


async def _user_in_ldap_group(connection: ASGIConnection, group: str) -> None:
    """
    Check that the logged-in session user is a member of `group`. Raises
    NotAuthorizedException if not, ServiceUnavailableException if LDAP itself
    is unreachable (fail closed, but distinguishable from "not a member").

    Runs the blocking LDAP lookup in a worker thread so a cache miss (a real
    network round trip) doesn't stall the event loop.
    """
    user = connection.session.get("user") or {}
    username = user.get("username")
    if not username:
        # Should be unreachable behind require_login, which guarantees a user.
        raise NotAuthorizedException("No username associated with this session")

    try:
        groups = await to_thread.run_sync(_ldap_authorizer.groups_for_user, username)
    except LDAPAuthorizationError as exc:
        logging.error(f"LDAP group lookup failed for {username}: {exc}")
        raise ServiceUnavailableException(
            "Authorization service unavailable, please try again shortly."
        )

    if group not in groups:
        logging.warning(
            f"Denied {username}: not a member of unix group {group!r}."
        )
        raise NotAuthorizedException(
            "Your account is not authorized to access this resource."
        )


def require_ldap_group(group: str):
    """
    Build a Litestar guard requiring membership in the given unix group.
    Passes through for any logged-in user when the admin gate is disabled
    (config.ldap.require_admin_group=False) — the admission routes use this
    factory with the admin group, and there is no runtime route that uses it
    with the user group.
    """

    async def guard(connection: ASGIConnection, _: BaseRouteHandler) -> None:
        if not config.ldap.require_admin_group:
            return
        await _user_in_ldap_group(connection, group)

    return guard




async def require_login(connection: ASGIConnection, _: BaseRouteHandler) -> None:
    """
    Guard for route handlers. Enforces:
    - a logged-in user is present in the session
    - the session hasn't exceeded config.session.max_age_seconds since login
    - the session hasn't been idle longer than config.session.idle_timeout_seconds
    - the user is a member of the required NERSC unix group
      (config.ldap.user_group), unless config.ldap.require_user_group is False

    On success, refreshes the idle clock.
    """
    session = connection.session

    if config.globus.disable_auth:
        if not session.get("user"):
            session["user"] = {"username": "dev-user"}
        return

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

    if config.ldap.require_user_group:
        await _user_in_ldap_group(connection, config.ldap.user_group)


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
        "identity_provider": identity_provider,
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


def session_user_context(request: Any) -> dict:
    """Build the template context for the logged-in user.

    Returns an empty dict if there's no logged-in user, so it can be
    unconditionally merged into any Template context.

    `is_admin` reflects the same policy as the admin guard: membership of
    config.ldap.admin_group via a live LDAP check (backed by the short
    in-process cache), or unconditionally True when
    config.ldap.require_admin_group is False. It is NOT a session attribute —
    group grants/revocations take effect within LDAP_CACHE_TTL_SECONDS without
    re-login. It is a UI hint only; actual authorization is enforced by the
    guards.
    """
    user = request.session.get("user")
    if not user or not user.get("username"):
        return {"auth_user": None, "is_admin": False}
    if not config.ldap.require_admin_group:
        # Gate disabled: every authenticated user passes the admin guard, so
        # the UI must match or the admission link would hide while the page
        # is actually open.
        return {"auth_user": user, "is_admin": True}
    try:
        groups = _ldap_authorizer.groups_for_user(user["username"])
    except LDAPAuthorizationError:
        logging.warning(
            f"LDAP lookup failed while building UI context for "
            f"{user['username']}; rendering as non-admin."
        )
        return {"auth_user": user, "is_admin": False}
    return {"auth_user": user, "is_admin": config.ldap.admin_group in groups}



auth_router = Router(path="/", route_handlers=[login, callback, logout])
