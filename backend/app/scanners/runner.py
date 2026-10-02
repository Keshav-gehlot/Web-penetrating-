from __future__ import annotations

import asyncio
from . import modules as scanner_modules
from .modules import MODULES, PROFILES
from .runtime import bounded_get, bounded_snapshot, ensure_runtime
from .trust_audit import web_trust_audit
from .coverage import web_vulnerability_coverage
from .vulnerability_modules import run_vulnerability_module, vulnerability_module_registry
from ..config import settings

MODULES.setdefault("web_trust_audit", web_trust_audit)
PROFILES.setdefault("trust", ["web_trust_audit"])

async def _web_vulnerability_coverage(target: str):
    response = await scanner_modules.http_snapshot(target)
    findings, coverage = web_vulnerability_coverage(response, target)
    return {"module": "web_vulnerability_coverage", "coverage": coverage, "findings": findings}

MODULES.setdefault("web_vulnerability_coverage", _web_vulnerability_coverage)
PROFILES["standard"] = tuple(dict.fromkeys((*PROFILES.get("standard", ()), "web_vulnerability_coverage")))
PROFILES["deep"] = tuple(dict.fromkeys((*PROFILES.get("deep", ()), "web_vulnerability_coverage")))
for _module_name in vulnerability_module_registry():
    MODULES.setdefault(_module_name, lambda target, _name=_module_name: run_vulnerability_module(_name, target))
scanner_modules.get = bounded_get
scanner_modules.http_snapshot = bounded_snapshot


def json_safe(value):
    if isinstance(value, dict):
        return {str(k): json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [json_safe(v) for v in value]
    return value


async def run_module(name: str, target: str, runtime_id: str | None = None) -> dict:
    if name not in MODULES:
        raise KeyError(f"Unknown scanner module: {name}")
    ensure_runtime(runtime_id or f"module:{name}:{target}")
    try:
        result = await asyncio.wait_for(MODULES[name](target), timeout=settings.SCAN_MODULE_TIMEOUT_SECONDS)
        return json_safe(result)
    except asyncio.TimeoutError:
        return {"module":name,"status":"timeout","error":f"Module exceeded {settings.SCAN_MODULE_TIMEOUT_SECONDS}s execution budget","findings":[]}
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        return {"module":name,"status":"error","error":str(exc),"findings":[]}


async def run_profile(profile: str, target: str) -> list[dict]:
    names = PROFILES.get(profile)
    if names is None:
        raise ValueError(f"Unknown scan profile: {profile}")
    if len(names) > settings.SCAN_MAX_MODULES:
        raise ValueError(f"Profile exceeds the maximum of {settings.SCAN_MAX_MODULES} modules")
    runtime_id = f"profile:{profile}:{target}"
    ensure_runtime(runtime_id)
    return list(await asyncio.gather(*(run_module(name, target, runtime_id=runtime_id) for name in names)))
