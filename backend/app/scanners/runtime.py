from __future__ import annotations

import contextvars
import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

import httpx

from ..config import settings
from ..security_scope import default_port_for_url, scope_host_allowed, scope_path_allowed, scope_port_allowed


@dataclass
class ScanRuntime:
    scope_id: str
    requests: int = 0
    scope: dict[str, object] | None = None


_CURRENT: contextvars.ContextVar[ScanRuntime | None] = contextvars.ContextVar("phantom_scan_runtime", default=None)


def ensure_runtime(scope_id: str, scope: dict[str, object] | None = None) -> ScanRuntime:
    current = _CURRENT.get()
    if current is None or current.scope_id != scope_id:
        current = ScanRuntime(scope_id=scope_id, scope=scope)
        _CURRENT.set(current)
    elif scope is not None:
        current.scope = scope
    return current


def _consume_request() -> None:
    runtime = _CURRENT.get()
    if runtime is None:
        return
    runtime.requests += 1
    budget = settings.SCAN_REQUEST_BUDGET
    if runtime.scope is not None:
        budget = min(budget, int(runtime.scope.get("max_requests", budget)))
    if runtime.requests > budget:
        raise RuntimeError(f"Scan request budget of {budget} exceeded")


def _resolve_public_addresses(host: str) -> list[str]:
    try:
        addresses = sorted({item[4][0] for item in socket.getaddrinfo(host, None)})
    except socket.gaierror as exc:
        raise RuntimeError(f"DNS resolution failed for scanner target: {host}") from exc
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            raise RuntimeError("Outbound scanner request resolved to a non-public address")
    return addresses


def _assert_public_host(url: str) -> None:
    host = urlparse(url).hostname
    if not host:
        raise RuntimeError("Request target has no hostname")
    _resolve_public_addresses(host)


def _assert_scope_url(url: str) -> None:
    runtime = _CURRENT.get()
    if runtime is None or runtime.scope is None:
        return
    parsed = urlparse(url)
    host = parsed.hostname
    if not host or not scope_host_allowed(host, runtime.scope):
        raise RuntimeError("Outbound scanner request is outside the authorized workspace scope")
    port = default_port_for_url(url)
    if not scope_port_allowed(port, runtime.scope):
        raise RuntimeError(f"Outbound scanner port {port} is not allowed by the workspace scope")
    if not scope_path_allowed(parsed.path or "/", runtime.scope):
        raise RuntimeError("Outbound scanner path is blocked by the workspace scope")


def bounded_resolve(host: str) -> list[str]:
    runtime = _CURRENT.get()
    if runtime is not None and runtime.scope is not None and not scope_host_allowed(host, runtime.scope):
        raise RuntimeError("Outbound DNS lookup is outside the authorized workspace scope")
    _consume_request()
    return _resolve_public_addresses(host)


def scoped_tcp_socket(host: str, port: int) -> socket.socket:
    runtime = _CURRENT.get()
    if runtime is not None and runtime.scope is not None:
        if not scope_host_allowed(host, runtime.scope):
            raise RuntimeError("Outbound scanner connection is outside the authorized workspace scope")
        if not scope_port_allowed(port, runtime.scope):
            raise RuntimeError(f"Outbound scanner port {port} is not allowed by the workspace scope")
    _consume_request()
    addresses = _resolve_public_addresses(host)
    last_error: OSError | None = None
    for address in addresses:
        try:
            return socket.create_connection((address, port), timeout=settings.SCAN_CONNECT_TIMEOUT_SECONDS)
        except OSError as exc:
            last_error = exc
    if last_error is not None:
        raise last_error
    raise OSError(f"Unable to connect to {host}:{port}")


async def bounded_get(target: str, path: str = "") -> httpx.Response:
    _consume_request()
    url = urljoin(target.rstrip("/") + "/", path.lstrip("/"))
    _assert_scope_url(url)
    _assert_public_host(url)
    async with httpx.AsyncClient(
        follow_redirects=False,
        timeout=httpx.Timeout(settings.SCAN_HTTP_TIMEOUT_SECONDS, connect=settings.SCAN_CONNECT_TIMEOUT_SECONDS),
        headers={"User-Agent": "PHANTOM/2.0 authorized-security-assessment"},
    ) as client:
        response = await client.get(url)
    if len(response.content) > settings.SCAN_MAX_RESPONSE_BYTES:
        raise RuntimeError(f"Response exceeded {settings.SCAN_MAX_RESPONSE_BYTES} byte safety limit")
    return response


async def bounded_snapshot(target: str) -> httpx.Response:
    runtime = _CURRENT.get()
    redirect_limit = settings.SCAN_MAX_REDIRECTS
    if runtime is not None and runtime.scope is not None:
        redirect_limit = min(redirect_limit, int(runtime.scope.get("max_redirects", redirect_limit)))

    current_url = target
    async with httpx.AsyncClient(
        follow_redirects=False,
        timeout=httpx.Timeout(settings.SCAN_HTTP_TIMEOUT_SECONDS, connect=settings.SCAN_CONNECT_TIMEOUT_SECONDS),
        headers={"User-Agent": "PHANTOM/2.0 authorized-security-assessment"},
    ) as client:
        for _ in range(redirect_limit + 1):
            _consume_request()
            _assert_scope_url(current_url)
            _assert_public_host(current_url)
            response = await client.get(current_url)
            if len(response.content) > settings.SCAN_MAX_RESPONSE_BYTES:
                raise RuntimeError(f"Response exceeded {settings.SCAN_MAX_RESPONSE_BYTES} byte safety limit")
            if response.status_code not in {301, 302, 303, 307, 308} or not response.headers.get("location"):
                _assert_scope_url(str(response.url))
                _assert_public_host(str(response.url))
                return response
            current_url = urljoin(current_url, response.headers["location"])

    raise RuntimeError(f"Redirect chain exceeded {redirect_limit} hops")


def bounded_connect(host: str, port: int) -> None:
    sock = scoped_tcp_socket(host, port)
    sock.close()
