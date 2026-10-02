from __future__ import annotations

import asyncio
import time

from . import modules as scanner_modules
from .modules import MODULES, PROFILES, authenticated_crawl
from .runtime import ScanAuth, bounded_get, bounded_options, bounded_snapshot, configure_runtime, ensure_runtime
from .trust_audit import web_trust_audit
from ..config import settings

MODULES.setdefault("web_trust_audit", web_trust_audit)
PROFILES.setdefault("trust", ["web_trust_audit"])
scanner_modules.get = bounded_get
scanner_modules.http_snapshot = bounded_snapshot
scanner_modules.bounded_options = bounded_options


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
    auth: ScanAuth | None = None,
) -> dict:
    if name not in MODULES:
        raise KeyError(f"Unknown scanner module: {name}")
    started = time.monotonic()
    runtime = configure_runtime(runtime_id or f"module:{name}:{target}", scope=scope, auth=auth)
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



async def run_authorization_comparison(
    target: str,
    primary: ScanAuth,
    comparison: ScanAuth,
    runtime_id: str,
    scope: dict[str, object] | None = None,
) -> dict:
    """Compare two explicitly configured identities using read-only same-origin crawling."""
    started = time.monotonic()
    configure_runtime(runtime_id, scope=scope, auth=primary)
    primary_result = await authenticated_crawl(target)
    primary_routes = {
        str(item.get("url")): item for item in primary_result.get("observed", [])
        if item.get("url")
    }
    configure_runtime(runtime_id, scope=scope, auth=comparison)
    comparison_result = await authenticated_crawl(target)
    comparison_routes = {
        str(item.get("url")): item for item in comparison_result.get("observed", [])
        if item.get("url")
    }
    findings = []
    for url in sorted(set(primary_routes) & set(comparison_routes))[:100]:
        left_status = int(primary_routes[url].get("status", 0))
        right_status = int(comparison_routes[url].get("status", 0))
        if (200 <= left_status < 400 and right_status in {401, 403}) or (200 <= right_status < 400 and left_status in {401, 403}):
            findings.append({
                "module": "authorization_comparison",
                "title": "Candidate authorization response differential",
                "severity": "info",
                "description": "Two explicitly configured identities received materially different read-only authorization responses for the same route. This is a candidate differential and does not establish an authorization bypass.",
                "remediation": "Review the route's intended role policy and verify the observed response differential with an authorized application owner.",
                "evidence": {
                    "url": url,
                    "primary_status": left_status,
                    "comparison_status": right_status,
                    "primary_identity": "configured-primary",
                    "comparison_identity": "configured-comparison",
                    "method": "GET",
                    "forms_submitted": False,
                    "javascript_executed": False,
                },
                "confidence": 0.7,
                "provenance": {"module": "authorization_comparison", "method": "read_only_identity_comparison", "version": "1.0"},
            })
    return {
        "module": "authorization_comparison",
        "timestamp": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
        "findings": findings[:100],
        "metrics": {
            "duration_ms": round((time.monotonic() - started) * 1000, 1),
            "primary_routes": len(primary_routes),
            "comparison_routes": len(comparison_routes),
            "differential_count": len(findings),
        },
        "note": "Read-only comparison; no privilege escalation or state-changing requests performed.",
    }

async def run_profile(
    profile: str,
    target: str,
    scope: dict[str, object] | None = None,
    auth: ScanAuth | None = None,
) -> list[dict]:
    names = PROFILES.get(profile)
    if names is None:
        raise ValueError(f"Unknown scan profile: {profile}")
    if len(names) > settings.SCAN_MAX_MODULES:
        raise ValueError(f"Profile exceeds the maximum of {settings.SCAN_MAX_MODULES} modules")
    runtime_id = f"profile:{profile}:{target}"
    configure_runtime(runtime_id, scope=scope, auth=auth)
    return list(await asyncio.gather(*(run_module(name, target, runtime_id=runtime_id, scope=scope, auth=auth) for name in names)))
