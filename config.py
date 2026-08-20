"""
Centralized application configuration.

Reads every environment variable the app depends on exactly once at
startup, validates what it can, and exposes a single frozen, typed
`Config` instance (`config`) for the rest of the application to import.

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

import yaml


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


def _read_yaml_file(file_path: str) -> dict:
    """Read and parse a YAML config file, e.g. the job-admission config.

    Returns an empty dict (and logs) if the path is unset, unreadable, or
    doesn't parse, so validate() can decide whether that's fatal.
    """
    if not file_path:
        return {}
    try:
        with open(file_path, "r") as f:
            return yaml.safe_load(f) or {}
    except (OSError, yaml.YAMLError) as e:
        logging.error(f"Error reading YAML config {file_path}: {e}")
        return {}


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
    admission_conf_file: str
    # Parsed contents of admission_conf_file (cluster credentials, the
    # per-repo/branch admission policy, and authorized IP ranges). Read once
    # here so every module that needs cluster credentials (webhook admission
    # in app.py, the Slurm queue in queue.py) shares one copy.
    admission_conf: dict = field(repr=False)


@dataclass(frozen=True)
class AppConfig:
    tzinfo: str


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

        admission_conf_file = os.getenv("ADMISSION_CONF_FILE", "configs/admission.yaml")
        hpc = HPCConfig(
            cluster=os.getenv("HPC_CLUSTER", "perlmutter"),
            token_url=os.getenv("TOKEN_URL", "https://oidc.nersc.gov/c2id/token"),
            admission_conf_file=admission_conf_file,
            admission_conf=_read_yaml_file(admission_conf_file),
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

        if not self.hpc.admission_conf:
            errors.append(
                f"Admission config file {self.hpc.admission_conf_file!r} is missing, "
                "unreadable, or empty."
            )
        elif "clusters" not in self.hpc.admission_conf:
            errors.append("Admission config is missing the required 'clusters' key.")
        elif self.hpc.cluster not in self.hpc.admission_conf["clusters"]:
            errors.append(
                f"Admission config has no entry under 'clusters' for "
                f"HPC_CLUSTER={self.hpc.cluster!r}."
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
