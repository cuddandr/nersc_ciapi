"""
Centralized application configuration.

Reads every environment variable the app depends on exactly once at
startup, validates what it can, and exposes a single frozen, typed
`Config` instance (`config`) for the rest of the application to import.

Mutable policy data (the job-admission config) is NOT part of this
object; it lives in MongoDB and is managed by mongodb.py.

Usage:
    from config import config

    print(config.mongodb.url)
    print(config.globus.client_id)  # secret file already read & cached
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from functools import lru_cache


class ConfigError(RuntimeError):
    """Raised when required configuration is missing or invalid."""


def _read_secret_file(file_path: str) -> str:
    """Read a secret value from a file, stripped of surrounding whitespace.

    Returns an empty string (and logs) if the path is unset or unreadable,
    so callers/validators can decide whether that's fatal.
    """
    if not file_path:
        return ""
    try:
        with open(file_path, "r") as f:
            return f.read().strip()
    except OSError as e:
        logging.error(f"Error reading secret file {file_path}: {e}")
        return ""


def _getenv_bool(name: str, default: bool = False) -> bool:
    """Parse a boolean-ish environment variable (1/true/yes/on)."""
    raw = os.getenv(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _getenv_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except ValueError:
        raise ConfigError(f"{name} must be an integer, got {raw!r}")


# --------------------------------------------------------------------------
# Sub-configs, grouped by concern
# --------------------------------------------------------------------------



@dataclass(frozen=True)
class MongoConfig:
    url: str
    db: str
    user: str
    password: str


@dataclass(frozen=True)
class GlobusConfig:
    """Globus Auth (OIDC) settings used by auth.py."""

    disable_auth: bool
    client_id_file: str
    client_secret_file: str
    redirect_uri: str
    auth_base: str
    nersc_identity_provider_id: str

    # Secrets are read once here (at Config construction time) rather than
    # on every request, matching the "read once at startup" contract.
    client_id: str = field(repr=False)
    client_secret: str = field(repr=False)


@dataclass(frozen=True)
class SessionConfig:
    """Cookie/session policy shared by auth.py and the Litestar session middleware."""

    secret_file: str
    secret: bytes = field(repr=False)
    max_age_seconds: int  # hard cap on session lifetime regardless of activity
    idle_timeout_seconds: int  # session invalidated after this much inactivity


@dataclass(frozen=True)
class WebhookConfig:
    secret_file: str
    secret: str = field(repr=False)
    verify_ip: bool


@dataclass(frozen=True)
class HPCConfig:
    cluster: str
    token_url: str
    # Path to the default admission config. Used ONLY to seed MongoDB the
    # first time the app runs; the DB copy is the authoritative policy after
    # that. The parsed contents are NOT stored here — see mongodb.py.
    admission_conf_file: str


@dataclass(frozen=True)
class AppConfig:
    tzinfo: str


@dataclass(frozen=True)
class LDAPConfig:
    """NERSC LDAP unix-group settings used by auth.py guards (via ldap_auth.py)."""

    url: str
    search_base: str
    user_group: str
    admin_group: str
    require_user_group: bool
    require_admin_group: bool
    connect_timeout_seconds: float
    read_timeout_seconds: float
    cache_ttl_seconds: float
    ca_cert_file: str


# --------------------------------------------------------------------------
# Top-level config
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Config:
    mongodb: MongoConfig
    globus: GlobusConfig
    session: SessionConfig
    webhook: WebhookConfig
    hpc: HPCConfig
    ldap: LDAPConfig
    app: AppConfig


    @classmethod
    def from_env(cls) -> "Config":
        mongodb = MongoConfig(
            url=os.getenv("MONGODB_URL", "mongodb://localhost:27017"),
            db=os.getenv("MONGODB_DB", "github_webhooks"),
            user=os.getenv("MONGODB_USER", ""),
            password=os.getenv("MONGODB_PASS", ""),
        )

        globus_client_id_file = os.getenv("GLOBUS_CLIENT_ID_FILE", "")
        globus_client_secret_file = os.getenv("GLOBUS_CLIENT_SECRET_FILE", "")
        globus = GlobusConfig(
            disable_auth=_getenv_bool("GLOBUS_DISABLE_AUTH", False),
            client_id_file=globus_client_id_file,
            client_secret_file=globus_client_secret_file,
            redirect_uri=os.getenv("GLOBUS_REDIRECT_URI", "https://localhost:8000/auth/callback"),
            auth_base="https://auth.globus.org",
            nersc_identity_provider_id=os.getenv("NERSC_IDENTITY_PROVIDER_ID", ""),
            client_id=_read_secret_file(globus_client_id_file),
            client_secret=_read_secret_file(globus_client_secret_file),
        )

        session_secret_file = os.getenv("SESSION_SECRET_FILE", "")
        session_secret = _read_secret_file(session_secret_file)
        session = SessionConfig(
            secret_file=session_secret_file,
            secret=session_secret.encode("utf-8"),
            max_age_seconds=_getenv_int("MAX_SESSION_AGE_SECONDS", 8 * 60 * 60),
            idle_timeout_seconds=_getenv_int("IDLE_TIMEOUT_SECONDS", 30 * 60),
        )

        webhook_secret_file = os.getenv("WEBHOOK_SECRET", "")
        webhook = WebhookConfig(
            secret_file=webhook_secret_file,
            secret=_read_secret_file(webhook_secret_file),
            verify_ip=_getenv_bool("VERIFY_IP", False),
        )

        hpc = HPCConfig(
            cluster=os.getenv("HPC_CLUSTER", "perlmutter"),
            token_url=os.getenv("TOKEN_URL", "https://oidc.nersc.gov/c2id/token"),
            admission_conf_file=os.getenv("ADMISSION_CONF_FILE", "configs/admission.yaml"),
        )

        ldap = LDAPConfig(
            url=os.getenv("LDAP_URL", "ldaps://ldap.nersc.gov"),
            search_base=os.getenv(
                "LDAP_SEARCH_BASE",
                "ou=PosixGroup,ou=perlmutter,ou=Host,o=ldapsvc,dc=nersc,dc=gov",
            ),
            user_group=os.getenv("LDAP_USER_GROUP", ""),
            admin_group=os.getenv("LDAP_ADMIN_GROUP", ""),
            require_user_group=_getenv_bool("LDAP_REQUIRE_USER_GROUP", True),
            require_admin_group=_getenv_bool("LDAP_REQUIRE_ADMIN_GROUP", True),
            connect_timeout_seconds=float(
                os.getenv("LDAP_CONNECT_TIMEOUT_SECONDS", "5")
            ),
            read_timeout_seconds=float(os.getenv("LDAP_READ_TIMEOUT_SECONDS", "5")),
            cache_ttl_seconds=float(os.getenv("LDAP_CACHE_TTL_SECONDS", "60")),
            ca_cert_file=os.getenv("LDAP_CA_CERT_FILE", ""),
        )

        app = AppConfig(
            tzinfo=os.getenv("TZINFO", "US/Pacific"),
        )

        config = cls(
            mongodb=mongodb,
            globus=globus,
            session=session,
            webhook=webhook,
            hpc=hpc,
            ldap=ldap,
            app=app,
        )
        config.validate()
        return config

    def validate(self) -> None:
        """Fail loudly at startup rather than surfacing confusing errors later."""
        errors: list[str] = []

        # Session secret is required for the cookie session backend to be
        # usable/stable across restarts and workers.
        if not self.session.secret:
            errors.append(
                "SESSION_SECRET_FILE is not configured or unreadable. "
                "Set SESSION_SECRET_FILE to a file containing a random 32+ byte secret."
            )

        if self.globus.disable_auth:
            logging.warning(
                "GLOBUS_DISABLE_AUTH is set; Globus authentication is disabled!"
                "The web UI will be visable to anyone with the url."
            )

        # Globus login can't function without a client id/secret.
        if not self.globus.client_id:
            errors.append(
                "GLOBUS_CLIENT_ID_FILE is not configured or unreadable."
            )
        if not self.globus.client_secret:
            errors.append(
                "GLOBUS_CLIENT_SECRET_FILE is not configured or unreadable."
            )

        if self.session.max_age_seconds <= 0:
            errors.append("MAX_SESSION_AGE_SECONDS must be a positive integer.")
        if self.session.idle_timeout_seconds <= 0:
            errors.append("IDLE_TIMEOUT_SECONDS must be a positive integer.")
        if self.session.idle_timeout_seconds > self.session.max_age_seconds:
            errors.append(
                "IDLE_TIMEOUT_SECONDS should not exceed MAX_SESSION_AGE_SECONDS."
            )

        if not self.hpc.admission_conf_file:
            logging.warning(
                "ADMISSION_CONF_FILE is not set; the MongoDB admission policy "
                "will have no seed source."
            )

        if not self.webhook.secret:
            logging.warning(
                "WEBHOOK_SECRET is not configured or unreadable; incoming webhook "
                "signatures will NOT be verified."
            )

        if not self.globus.nersc_identity_provider_id:
            logging.warning(
                "NERSC_IDENTITY_PROVIDER_ID is not set; any Globus identity "
                "will be accepted for login."
            )

        # An unset group name must be a startup error rather than an open
        # gate: every guard below fails closed on LDAP errors, but an empty
        # group string would make the membership check meaningless. The
        # LDAP_REQUIRE_*_GROUP=False escape hatch (for staging/testing before
        # the groups are provisioned) suppresses both the gate and this check,
        # loudly.
        if self.ldap.require_user_group and not self.ldap.user_group:
            errors.append(
                "LDAP_USER_GROUP is not set; Globus-authenticated paths "
                "would have no unix-group gate. Set LDAP_USER_GROUP or "
                "disable the gate with LDAP_REQUIRE_USER_GROUP=false."
            )
        if self.ldap.require_admin_group and not self.ldap.admin_group:
            errors.append(
                "LDAP_ADMIN_GROUP is not set; the admission configuration "
                "endpoints would have no admin unix-group gate. Set "
                "LDAP_ADMIN_GROUP or disable the gate with "
                "LDAP_REQUIRE_ADMIN_GROUP=false."
            )

        if not self.ldap.require_user_group:
            logging.warning(
                "LDAP_REQUIRE_USER_GROUP=false: the unix-group gate on all "
                "authenticated paths is DISABLED — any Globus-authenticated "
                "user passes."
            )
        if not self.ldap.require_admin_group:
            logging.warning(
                "LDAP_REQUIRE_ADMIN_GROUP=false: the admin unix-group gate "
                "on the admission configuration endpoints is DISABLED — any "
                "Globus-authenticated user can view/edit the admission config."
            )

        if errors:
            message = "Invalid configuration:\n" + "\n".join(f"  - {e}" for e in errors)
            raise ConfigError(message)


@lru_cache(maxsize=1)
def get_config() -> Config:
    """Return the process-wide Config singleton, building it on first use."""
    return Config.from_env()


# Eagerly construct the singleton at import time so that misconfiguration
# fails fast at startup instead of on the first request that needs it.
config: Config = get_config()
