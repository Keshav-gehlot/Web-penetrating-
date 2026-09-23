from __future__ import annotations

import os


def _normalize_database_url(value: str) -> str:
    """Ensure SQLAlchemy async engines receive an asyncpg PostgreSQL URL."""
    value = value.strip()
    if value.startswith("postgresql://"):
        return "postgresql+asyncpg://" + value[len("postgresql://"):]
    if value.startswith("postgres://"):
        return "postgresql+asyncpg://" + value[len("postgres://"):]
    return value


class Settings:
    APP_NAME = os.getenv("PHANTOM_APP_NAME", "PHANTOM Security API")
    DATABASE_URL = _normalize_database_url(
        os.getenv(
            "DATABASE_URL",
            "postgresql+asyncpg://postgres:postgres@localhost:5432/phantom",
        )
    )
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
    ).strip().lower()
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
