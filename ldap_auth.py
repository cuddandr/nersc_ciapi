"""
LDAP group authorization for NERSC unix groups.

After a user has authenticated via Globus (see auth.py), this module answers
"which of the configured NERSC posix groups is this username a member of?"
It performs no authentication of its own — it must only ever be called with a
username that was established by the Globus login flow.

Design (mirrors aqdrop-server/api/ldap_auth.py):
- ldaps:// only, server certificate validated against the system CA bundle
  (or LDAP_CA_CERT_FILE).
- A single posixGroup subtree search per (uncached) user, filtered down to the
  configured groups only, with memberUid matching the escaped username.
- Results cached in-process for LDAP_CACHE_TTL_SECONDS; membership checks are
  cheap and frequent, and a short TTL means group removals take effect quickly
  without any session invalidation.
- Fails closed: any LDAP connectivity/protocol error raises
  LDAPAuthorizationError, which guards translate into a denial.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
import ssl
import threading
import time
from typing import Callable
from urllib.parse import urlparse

import ldap3
from ldap3.utils.conv import escape_filter_chars


class LDAPAuthorizationError(RuntimeError):
    pass


@dataclass(frozen=True)
class LDAPSettings:
    url: str = "ldaps://ldap.nersc.gov"
    search_base: str = "ou=PosixGroup,ou=perlmutter,ou=Host,o=ldapsvc,dc=nersc,dc=gov"
    user_group: str = ""
    admin_group: str = ""
    connect_timeout_seconds: float = 5.0
    read_timeout_seconds: float = 5.0
    cache_ttl_seconds: float = 60.0
    ca_cert_file: str | None = None

    @classmethod
    def from_environment(cls) -> "LDAPSettings":
        return cls(
            url=os.getenv("LDAP_URL", cls.url),
            search_base=os.getenv("LDAP_SEARCH_BASE", cls.search_base),
            user_group=os.getenv("LDAP_USER_GROUP", cls.user_group),
            admin_group=os.getenv("LDAP_ADMIN_GROUP", cls.admin_group),
            connect_timeout_seconds=float(
                os.getenv("LDAP_CONNECT_TIMEOUT_SECONDS", cls.connect_timeout_seconds)
            ),
            read_timeout_seconds=float(
                os.getenv("LDAP_READ_TIMEOUT_SECONDS", cls.read_timeout_seconds)
            ),
            cache_ttl_seconds=float(
                os.getenv("LDAP_CACHE_TTL_SECONDS", cls.cache_ttl_seconds)
            ),
            ca_cert_file=os.getenv("LDAP_CA_CERT_FILE") or None,
        )

    @property
    def allowed_groups(self) -> frozenset[str]:
        return frozenset({self.user_group, self.admin_group})


ConnectionFactory = Callable[[LDAPSettings], ldap3.Connection]


def _create_connection(settings: LDAPSettings) -> ldap3.Connection:
    parsed = urlparse(settings.url)
    if parsed.scheme != "ldaps" or not parsed.hostname:
        raise LDAPAuthorizationError("LDAP_URL must be an ldaps:// URL")

    tls = ldap3.Tls(
        validate=ssl.CERT_REQUIRED,
        ca_certs_file=settings.ca_cert_file,
    )
    server = ldap3.Server(
        parsed.hostname,
        port=parsed.port or 636,
        use_ssl=True,
        tls=tls,
        connect_timeout=settings.connect_timeout_seconds,
        get_info=ldap3.NONE,
    )
    return ldap3.Connection(
        server,
        auto_bind=True,
        # ldap3 2.6 packs this value into a native integer socket option on Linux.
        receive_timeout=max(1, int(settings.read_timeout_seconds)),
        raise_exceptions=True,
    )


class LDAPAuthorizer:
    def __init__(
        self,
        settings: LDAPSettings | None = None,
        connection_factory: ConnectionFactory = _create_connection,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.settings = settings or LDAPSettings.from_environment()
        self._connection_factory = connection_factory
        self._clock = clock
        self._cache: dict[str, tuple[float, frozenset[str]]] = {}
        self._cache_lock = threading.Lock()

    def groups_for_user(
        self,
        username: str,
        *,
        bypass_cache: bool = False,
    ) -> frozenset[str]:
        if not username:
            raise LDAPAuthorizationError("Cannot authorize an empty username")

        now = self._clock()
        if not bypass_cache:
            with self._cache_lock:
                cached = self._cache.get(username)
                if cached is not None and cached[0] > now:
                    return cached[1]

        groups = self._query_groups(username)
        with self._cache_lock:
            self._cache[username] = (
                now + self.settings.cache_ttl_seconds,
                groups,
            )
        return groups

    def clear_cache(self) -> None:
        with self._cache_lock:
            self._cache.clear()

    def _query_groups(self, username: str) -> frozenset[str]:
        escaped_username = escape_filter_chars(username)
        group_filter = "".join(
            f"(cn={escape_filter_chars(group)})"
            for group in sorted(self.settings.allowed_groups)
        )
        search_filter = f"(&(memberUid={escaped_username})(|{group_filter}))"

        connection: ldap3.Connection | None = None
        try:
            connection = self._connection_factory(self.settings)
            success = connection.search(
                search_base=self.settings.search_base,
                search_filter=search_filter,
                search_scope=ldap3.SUBTREE,
                attributes=["cn"],
                time_limit=max(1, int(self.settings.read_timeout_seconds)),
            )
            if not success and connection.result.get("result") != 0:
                raise LDAPAuthorizationError("LDAP group search failed")

            groups: set[str] = set()
            for entry in connection.entries:
                value = entry["cn"].value
                if isinstance(value, str) and value in self.settings.allowed_groups:
                    groups.add(value)
            return frozenset(groups)
        except LDAPAuthorizationError:
            raise
        except Exception as exc:
            raise LDAPAuthorizationError("LDAP group lookup failed") from exc
        finally:
            if connection is not None:
                try:
                    connection.unbind()
                except Exception:
                    pass
