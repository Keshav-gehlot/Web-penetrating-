from __future__ import annotations

import os
import re
from urllib.parse import urlsplit, urlunsplit


def _normalize_database_url(value: str) -> str:
    """Ensure SQLAlchemy async engines receive an asyncpg PostgreSQL URL."""
    value = value.strip()
    if value.startswith("postgresql://"):
        return "postgresql+asyncpg://" + value[len("postgresql://"):]
    if value.startswith("postgres://"):
        return "postgresql+asyncpg://" + value[len("postgres://"):]
    return value


def _replace_database_name(value: str, database_name: str) -> str:
    parts = urlsplit(value)
    if not parts.scheme or not parts.netloc:
        return value
    return urlunsplit(
        (parts.scheme, parts.netloc, "/" + database_name, parts.query, parts.fragment)
    )


def _same_database_server(left: str, right: str) -> bool:
    a, b = urlsplit(left), urlsplit(right)
    return bool(a.scheme and a.netloc and b.scheme and b.netloc and a.netloc == b.netloc)


class Settings:
    APP_NAME = os.getenv("PHANTOM_APP_NAME", "PHANTOM Security API")
    DATABASE_URL = _normalize_database_url(
        os.getenv(
            "DATABASE_URL",
            "postgresql+asyncpg://postgres:postgres@localhost:5432/phantom",
        )
    )

    # The authentication store has its own PostgreSQL database name. On Railway's
    # current resource-limited plan this is a separate logical database on the
    # existing Postgres instance. When a separate Postgres service is available,
    # PHANTOM_AUTH_DATABASE_URL can point to that service directly.
    AUTH_DATABASE_NAME = os.getenv("PHANTOM_AUTH_DATABASE_NAME", "phantom_auth").strip()
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", AUTH_DATABASE_NAME):
        raise RuntimeError("PHANTOM_AUTH_DATABASE_NAME contains invalid characters")

    _AUTH_DATABASE_URL_ENV = os.getenv("PHANTOM_AUTH_DATABASE_URL", "").strip()
    if _AUTH_DATABASE_URL_ENV:
        _normalized_auth_env = _normalize_database_url(_AUTH_DATABASE_URL_ENV)
        if _same_database_server(_normalized_auth_env, DATABASE_URL):
            AUTH_DATABASE_URL = _replace_database_name(
                _normalized_auth_env, AUTH_DATABASE_NAME
            )
            AUTH_DATABASE_SAME_SERVER = True
        else:
            AUTH_DATABASE_URL = _normalized_auth_env
            AUTH_DATABASE_SAME_SERVER = False
    else:
        AUTH_DATABASE_URL = _replace_database_name(DATABASE_URL, AUTH_DATABASE_NAME)
        AUTH_DATABASE_SAME_SERVER = True

    AUTH_DATABASE_ADMIN_DATABASE = os.getenv(
        "PHANTOM_AUTH_ADMIN_DATABASE", "postgres"
    ).strip()

    CORS_ORIGINS = [
        x.strip()
        for x in os.getenv(
            "PHANTOM_CORS_ORIGINS", "http://localhost:5173"
        ).split(",")
        if x.strip()
    ]
    AUTH_SECRET = os.getenv("PHANTOM_AUTH_SECRET", "change-this-development-secret")
    BOOTSTRAP_EMAIL = os.getenv(
        "PHANTOM_BOOTSTRAP_EMAIL", "admin@phantom.local"
    )
    BOOTSTRAP_PASSWORD = os.getenv(
        "PHANTOM_BOOTSTRAP_PASSWORD", "change-me-before-production"
    )
    BOOTSTRAP_ROLE = os.getenv("PHANTOM_BOOTSTRAP_ROLE", "owner")
    ENVIRONMENT = os.getenv("PHANTOM_ENV", "development").lower()
    SESSION_HOURS = max(1, int(os.getenv("PHANTOM_SESSION_HOURS", "12")))
    SCAN_MODULE_TIMEOUT_SECONDS = max(
        5, int(os.getenv("PHANTOM_SCAN_MODULE_TIMEOUT_SECONDS", "120"))
    )
    SCAN_TOTAL_TIMEOUT_SECONDS = max(
        30, int(os.getenv("PHANTOM_SCAN_TOTAL_TIMEOUT_SECONDS", "900"))
    )
    SCAN_MAX_MODULES = max(1, int(os.getenv("PHANTOM_SCAN_MAX_MODULES", "32")))
    MAX_CONCURRENT_SCANS = max(
        1, int(os.getenv("PHANTOM_MAX_CONCURRENT_SCANS", "2"))
    )
    SCAN_REQUEST_BUDGET = max(
        1, int(os.getenv("PHANTOM_SCAN_REQUEST_BUDGET", "250"))
    )
    SCAN_MAX_REDIRECTS = max(
        0, int(os.getenv("PHANTOM_SCAN_MAX_REDIRECTS", "3"))
    )
    SCAN_HTTP_TIMEOUT_SECONDS = max(
        1, int(os.getenv("PHANTOM_SCAN_HTTP_TIMEOUT_SECONDS", "8"))
    )
    SCAN_CONNECT_TIMEOUT_SECONDS = max(
        1, int(os.getenv("PHANTOM_SCAN_CONNECT_TIMEOUT_SECONDS", "5"))
    )
    SCAN_MAX_RESPONSE_BYTES = max(
        65536, int(os.getenv("PHANTOM_SCAN_MAX_RESPONSE_BYTES", "2097152"))
    )
    JOB_LEASE_SECONDS = max(
        30, int(os.getenv("PHANTOM_JOB_LEASE_SECONDS", "900"))
    )
    MAX_JOB_ATTEMPTS = max(
        1, int(os.getenv("PHANTOM_MAX_JOB_ATTEMPTS", "3"))
    )
    WS_TICKET_TTL_SECONDS = max(
        30, int(os.getenv("PHANTOM_WS_TICKET_TTL_SECONDS", "60"))
    )


settings = Settings()

if settings.ENVIRONMENT in {"production", "prod"} and settings.AUTH_SECRET == "change-this-development-secret":
    raise RuntimeError("PHANTOM_AUTH_SECRET must be replaced before production startup")
if settings.ENVIRONMENT in {"production", "prod"} and settings.BOOTSTRAP_PASSWORD == "change-me-before-production":
    raise RuntimeError("PHANTOM_BOOTSTRAP_PASSWORD must be replaced before production startup")
