from __future__ import annotations

import base64
import contextvars
import ipaddress
import socket
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

import httpx

from ..config import settings

@dataclass
class ScanAuth:
    kind: str
    secret: str
    username: str|None = None
    header_name: str|None = None

    def headers(self) -> dict[str,str]:
        if self.kind=="bearer":
            return {"Authorization":f"Bearer {self.secret}"}
        if self.kind=="api_key":
            return {self.header_name or "X-API-Key":self.secret}
        if self.kind=="basic":
            raw=f"{self.username or ''}:{self.secret}".encode("utf-8")
            return {"Authorization":"Basic "+base64.b64encode(raw).decode("ascii")}
        raise RuntimeError("Unsupported scanner authentication kind")

@dataclass
class ScanRuntime:
    scope_id: str
    requests: int = 0
    auth: ScanAuth|None = None

_CURRENT: contextvars.ContextVar[ScanRuntime | None] = contextvars.ContextVar("phantom_scan_runtime", default=None)

def ensure_runtime(scope_id: str, auth: ScanAuth|None=None) -> ScanRuntime:
    current = _CURRENT.get()
    if current is None or current.scope_id != scope_id:
        current = ScanRuntime(scope_id=scope_id,auth=auth)
        _CURRENT.set(current)
    elif auth is not None:
        current.auth=auth
    return current

def configure_runtime(scope_id: str, auth: ScanAuth|None=None) -> ScanRuntime:
    return ensure_runtime(scope_id,auth)

def _consume_request() -> None:
    runtime = _CURRENT.get()
    if runtime is None:
        return
    runtime.requests += 1
    if runtime.requests > settings.SCAN_REQUEST_BUDGET:
        raise RuntimeError(f"Scan request budget of {settings.SCAN_REQUEST_BUDGET} exceeded")

def _headers() -> dict[str,str]:
    runtime=_CURRENT.get()
    headers={"User-Agent":"PHANTOM/2.0 authorized-security-assessment"}
    if runtime and runtime.auth:
        headers.update(runtime.auth.headers())
    return headers

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
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
            raise RuntimeError("Outbound scanner request resolved to a non-public address")

async def bounded_get(target: str, path: str = "") -> httpx.Response:
    _consume_request()
    url = urljoin(target.rstrip("/") + "/", path.lstrip("/"))
    _assert_public_host(url)
    async with httpx.AsyncClient(follow_redirects=False, timeout=httpx.Timeout(settings.SCAN_HTTP_TIMEOUT_SECONDS, connect=settings.SCAN_CONNECT_TIMEOUT_SECONDS), headers=_headers()) as client:
        response = await client.get(url)
    if len(response.content) > settings.SCAN_MAX_RESPONSE_BYTES:
        raise RuntimeError(f"Response exceeded {settings.SCAN_MAX_RESPONSE_BYTES} byte safety limit")
    return response

async def bounded_snapshot(target: str) -> httpx.Response:
    current = target
    async with httpx.AsyncClient(
        follow_redirects=False,
        timeout=httpx.Timeout(settings.SCAN_HTTP_TIMEOUT_SECONDS, connect=settings.SCAN_CONNECT_TIMEOUT_SECONDS),
        headers=_headers(),
    ) as client:
        for _ in range(settings.SCAN_MAX_REDIRECTS + 1):
            _consume_request()
            _assert_public_host(current)
            response = await client.get(current)
            if len(response.content) > settings.SCAN_MAX_RESPONSE_BYTES:
                raise RuntimeError(f"Response exceeded {settings.SCAN_MAX_RESPONSE_BYTES} byte safety limit")
            if response.status_code not in {301, 302, 303, 307, 308}:
                return response
            location = response.headers.get("location")
            if not location:
                return response
            current = urljoin(current, location)
        raise RuntimeError(f"Redirect limit of {settings.SCAN_MAX_REDIRECTS} exceeded")
