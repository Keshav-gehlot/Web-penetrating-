from __future__ import annotations

import asyncio
from .modules import MODULES, PROFILES
from .trust_audit import web_trust_audit
from ..config import settings

MODULES.setdefault("web_trust_audit", web_trust_audit)
PROFILES.setdefault("trust", ["web_trust_audit"])


def json_safe(value):
    if isinstance(value, dict):
        return {str(k): json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [json_safe(v) for v in value]
    return value


async def run_module(name: str, target: str) -> dict:
    if name not in MODULES:
        raise KeyError(f"Unknown scanner module: {name}")
    try:
        result = await asyncio.wait_for(
            MODULES[name](target),
            timeout=settings.SCAN_MODULE_TIMEOUT_SECONDS,
        )
        return json_safe(result)
    except asyncio.TimeoutError:
        return {
            "module": name,
            "status": "timeout",
            "error": f"Module exceeded {settings.SCAN_MODULE_TIMEOUT_SECONDS}s execution budget",
            "findings": [],
        }
    except Exception as exc:
        return {"module": name, "status": "error", "error": str(exc), "findings": []}


async def run_profile(profile: str, target: str) -> list[dict]:
    names = PROFILES.get(profile)
    if names is None:
        raise ValueError(f"Unknown scan profile: {profile}")
    if len(names) > settings.SCAN_MAX_MODULES:
        raise ValueError(f"Profile exceeds the maximum of {settings.SCAN_MAX_MODULES} modules")
    return list(await asyncio.gather(*(run_module(name, target) for name in names)))
