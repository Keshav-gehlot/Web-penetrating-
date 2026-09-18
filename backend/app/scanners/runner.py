from __future__ import annotations

import asyncio
import time

from . import modules as scanner_modules
from .modules import MODULES, PROFILES
from .runtime import bounded_get, bounded_snapshot, ensure_runtime
from .trust_audit import web_trust_audit
from ..config import settings

MODULES.setdefault("web_trust_audit", web_trust_audit)
PROFILES.setdefault("trust", ["web_trust_audit"])
scanner_modules.get = bounded_get
scanner_modules.http_snapshot = bounded_snapshot


def json_safe(value):
    if isinstance(value, dict):
        return {str(k): json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [json_safe(v) for v in value]
    return value


async def run_module(
    name: str,
    target: str,
    runtime_id: str | None = None,
    scope: dict[str, object] | None = None,
) -> dict:
    if name not in MODULES:
        raise KeyError(f"Unknown scanner module: {name}")
    ensure_runtime(runtime_id or f"module:{name}:{target}", scope=scope)
    started = time.monotonic()
    runtime = ensure_runtime(runtime_id or f"module:{name}:{target}", scope=scope)
    request_before = runtime.requests
    try:
        result = await asyncio.wait_for(MODULES[name](target), timeout=settings.SCAN_MODULE_TIMEOUT_SECONDS)
        result = json_safe(result)
        elapsed_ms = round((time.monotonic() - started) * 1000, 1)
        for item in result.get("findings", []):
            evidence = dict(item.get("evidence") or {})
            evidence.setdefault("schema_version", "1.0")
            evidence.setdefault("target", target)
            evidence.setdefault("request_count", runtime.requests - request_before)
            item["evidence"] = evidence
            item.setdefault("provenance", {"module": name, "method": "passive_or_safe_probe", "version": "2.1"})
        result["metrics"] = {"duration_ms": elapsed_ms, "requests": runtime.requests - request_before, "finding_count": len(result.get("findings", []))}
        return result
    except asyncio.TimeoutError:
        return {"module": name, "status": "timeout", "error": f"Module exceeded {settings.SCAN_MODULE_TIMEOUT_SECONDS}s execution budget", "findings": [], "metrics": {"duration_ms": round((time.monotonic() - started) * 1000, 1), "requests": runtime.requests - request_before}}
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        return {"module": name, "status": "error", "error": str(exc), "findings": [], "metrics": {"duration_ms": round((time.monotonic() - started) * 1000, 1), "requests": runtime.requests - request_before}}


async def run_profile(
    profile: str,
    target: str,
    scope: dict[str, object] | None = None,
) -> list[dict]:
    names = PROFILES.get(profile)
    if names is None:
        raise ValueError(f"Unknown scan profile: {profile}")
    if len(names) > settings.SCAN_MAX_MODULES:
        raise ValueError(f"Profile exceeds the maximum of {settings.SCAN_MAX_MODULES} modules")
    runtime_id = f"profile:{profile}:{target}"
    ensure_runtime(runtime_id, scope=scope)
    return list(await asyncio.gather(*(run_module(name, target, runtime_id=runtime_id, scope=scope) for name in names)))
