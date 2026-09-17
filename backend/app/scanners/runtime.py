from __future__ import annotations

import contextvars
import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

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

def _assert_public_host(url: str) -> None:
    host = urlparse(url).hostname
    if not host:
        raise RuntimeError("Request target has no hostname")
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(host, None)}
    except socket.gaierror as exc:
        raise RuntimeError(f"DNS resolution failed for scanner target: {host}") from exc
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            raise RuntimeError("Outbound scanner request resolved to a non-public address")

async def bounded_get(target: str, path: str = "") -> httpx.Response:
    _consume_request()
    url = urljoin(target.rstrip("/") + "/", path.lstrip("/"))
    _assert_public_host(url)
    async with httpx.AsyncClient(follow_redirects=False, timeout=httpx.Timeout(settings.SCAN_HTTP_TIMEOUT_SECONDS, connect=settings.SCAN_CONNECT_TIMEOUT_SECONDS), headers={"User-Agent":"PHANTOM/2.0 authorized-security-assessment"}) as client:
        response = await client.get(url)
    if len(response.content) > settings.SCAN_MAX_RESPONSE_BYTES:
        raise RuntimeError(f"Response exceeded {settings.SCAN_MAX_RESPONSE_BYTES} byte safety limit")
    return response

async def bounded_snapshot(target: str) -> httpx.Response:
    _consume_request()
    _assert_public_host(target)
    async with httpx.AsyncClient(follow_redirects=True, max_redirects=settings.SCAN_MAX_REDIRECTS, timeout=httpx.Timeout(settings.SCAN_HTTP_TIMEOUT_SECONDS, connect=settings.SCAN_CONNECT_TIMEOUT_SECONDS), headers={"User-Agent":"PHANTOM/2.0 authorized-security-assessment"}) as client:
        response = await client.get(target)
    _assert_public_host(str(response.url))
    if len(response.content) > settings.SCAN_MAX_RESPONSE_BYTES:
        raise RuntimeError(f"Response exceeded {settings.SCAN_MAX_RESPONSE_BYTES} byte safety limit")
    return response
