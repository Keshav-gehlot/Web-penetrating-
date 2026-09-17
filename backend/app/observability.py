from __future__ import annotations

from typing import Any
from uuid import uuid4

from .database import SessionLocal
from .models import OperationalEvent

_ALLOWED_SEVERITIES = {"debug", "info", "warning", "error", "critical"}
_MAX_MESSAGE_LENGTH = 2000
_MAX_METADATA_KEYS = 40
_MAX_METADATA_VALUE_LENGTH = 1000


def _sanitize_metadata(metadata: dict[str, Any] | None) -> dict[str, Any]:
    if not metadata:
        return {}
    result: dict[str, Any] = {}
    for key, value in list(metadata.items())[:_MAX_METADATA_KEYS]:
        safe_key = str(key)[:128]
        if isinstance(value, (str, int, float, bool)) or value is None:
            result[safe_key] = str(value)[:_MAX_METADATA_VALUE_LENGTH] if isinstance(value, str) else value
        else:
            result[safe_key] = str(value)[:_MAX_METADATA_VALUE_LENGTH]
    return result


async def record_operational_event(
    event_type: str,
    message: str,
    severity: str = "info",
    workspace_id: str | None = None,
    scan_id: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> None:
    """Best-effort operational telemetry; telemetry failures must not break security workflows."""
    normalized_severity = str(severity).lower()
    safe_severity = normalized_severity if normalized_severity in _ALLOWED_SEVERITIES else "info"
    try:
        async with SessionLocal() as db:
            db.add(
                OperationalEvent(
                    id=str(uuid4()),
                    event_type=str(event_type)[:64],
                    message=str(message)[:_MAX_MESSAGE_LENGTH],
                    severity=safe_severity,
                    workspace_id=workspace_id,
                    scan_id=scan_id,
                    db_metadata=_sanitize_metadata(metadata),
                )
            )
            await db.commit()
    except Exception:
        return
