from __future__ import annotations
import asyncio
from .modules import MODULES, PROFILES


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
        result = await MODULES[name](target)
        return json_safe(result)
    except Exception as exc:
        return {"module": name, "status": "error", "error": str(exc), "findings": []}


async def run_profile(profile: str, target: str) -> list[dict]:
    names = PROFILES.get(profile)
    if names is None:
        raise ValueError(f"Unknown scan profile: {profile}")
    results = await asyncio.gather(*(run_module(name, target) for name in names))
    return list(results)
