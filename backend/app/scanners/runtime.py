from __future__ import annotations

import contextvars
from dataclasses import dataclass
from urllib.parse import urljoin

import httpx

from ..config import settings

@dataclass
class ScanRuntime:
    scope_id: str
    requests: int = 0

_CURRENT: contextvars.ContextVar[ScanRuntime | None] = contextvars.ContextVar("phantom_scan_runtime", default=None)


def ensure_runtime(scope_id: str) -> ScanRuntime:
    current = _CURRENT.get()
    if current is None or current.scope_id != scope_id:
        current = ScanRuntime(scope_id=scope_id)
        _CURRENT.set(current)
    return current


def _consume_request() -> None:
    runtime = _CURRENT.get()
    if runtime is None:
        return
    runtime.requests += 1
    if runtime.requests > settings.SCAN_REQUEST_BUDGET:
        raise RuntimeError(f"Scan request budget of {settings.SCAN_REQUEST_BUDGET} exceeded")


async def bounded_get(target: str, path: str = "") -> httpx.Response:
    _consume_request()
    url = urljoin(target.rstrip("/") + "/", path.lstrip("/"))
    async with httpx.AsyncClient(follow_redirects=False, timeout=httpx.Timeout(settings.SCAN_HTTP_TIMEOUT_SECONDS, connect=settings.SCAN_CONNECT_TIMEOUT_SECONDS), headers={"User-Agent":"PHANTOM/2.0 authorized-security-assessment"}) as client:
        response = await client.get(url)
    if len(response.content) > settings.SCAN_MAX_RESPONSE_BYTES:
        raise RuntimeError(f"Response exceeded {settings.SCAN_MAX_RESPONSE_BYTES} byte safety limit")
    return response


async def bounded_snapshot(target: str) -> httpx.Response:
    _consume_request()
    async with httpx.AsyncClient(follow_redirects=True, max_redirects=settings.SCAN_MAX_REDIRECTS, timeout=httpx.Timeout(settings.SCAN_HTTP_TIMEOUT_SECONDS, connect=settings.SCAN_CONNECT_TIMEOUT_SECONDS), headers={"User-Agent":"PHANTOM/2.0 authorized-security-assessment"}) as client:
        response = await client.get(target)
    if len(response.content) > settings.SCAN_MAX_RESPONSE_BYTES:
        raise RuntimeError(f"Response exceeded {settings.SCAN_MAX_RESPONSE_BYTES} byte safety limit")
    return response
