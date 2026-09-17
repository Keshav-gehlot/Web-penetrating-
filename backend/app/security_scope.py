from __future__ import annotations

import ipaddress
import re
import socket
from urllib.parse import urlparse

from fastapi import HTTPException

ALLOWED_SCHEMES = {"http", "https"}
_HOST_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?$")


class ScopeViolation(ValueError):
    """Raised when a target or outbound request is outside the workspace scope."""


def normalize_target(value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError("Target is required")
    if not value.startswith(("http://", "https://")):
        value = "https://" + value
    parsed = urlparse(value)
    if parsed.scheme not in ALLOWED_SCHEMES or not parsed.hostname:
        raise ValueError("Target must be a valid HTTP(S) hostname or URL")
    if parsed.username or parsed.password:
        raise ValueError("Target credentials are not allowed")
    if parsed.fragment:
        raise ValueError("Target fragments are not allowed")
    return value.rstrip("/")


def _public_addresses(host: str) -> list[str]:
    try:
        addresses = sorted({item[4][0] for item in socket.getaddrinfo(host, None)})
    except socket.gaierror as exc:
        raise HTTPException(400, f"DNS resolution failed for target: {host}") from exc
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            raise HTTPException(400, "Target resolves to a non-public address")
    return addresses


def validate_target(value: str) -> dict[str, object]:
    try:
        normalized = normalize_target(value)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc

    host = urlparse(normalized).hostname
    assert host is not None
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            raise HTTPException(400, "Private, loopback, link-local, multicast, reserved, or local targets are not allowed")
        return {"target": normalized, "host": host, "is_ip": True}

    host = host.rstrip(".").lower()
    if host in {"localhost", "localhost.localdomain"} or host.endswith(".local"):
        raise HTTPException(400, "Local targets are not allowed")

    _public_addresses(host)
    return {"target": normalized, "host": host, "is_ip": False}


def resolve_public_host(host: str) -> list[str]:
    host = host.strip().rstrip(".")
    if not host or len(host) > 253:
        raise HTTPException(400, "Invalid hostname")
    if any(ch.isspace() for ch in host):
        raise HTTPException(400, "Invalid hostname")
    return _public_addresses(host)


def normalize_scope_entry(value: str) -> str:
    entry = value.strip().lower().rstrip(".")
    if not entry:
        raise ValueError("Scope entries cannot be empty")
    if "/" in entry:
        try:
            network = ipaddress.ip_network(entry, strict=False)
        except ValueError as exc:
            raise ValueError(f"Invalid CIDR scope entry: {value}") from exc
        if network.is_private or network.is_loopback or network.is_link_local or network.is_multicast or network.is_reserved or network.is_unspecified:
            raise ValueError("Private, loopback, link-local, multicast, reserved, and unspecified networks cannot be authorized")
        return str(network)
    if entry.startswith("*."):
        hostname = entry[2:]
        if not hostname or not _HOST_LABEL.fullmatch(hostname):
            raise ValueError(f"Invalid wildcard hostname: {value}")
        return f"*.{hostname}"
    try:
        ip = ipaddress.ip_address(entry)
    except ValueError:
        if not _HOST_LABEL.fullmatch(entry):
            raise ValueError(f"Invalid hostname scope entry: {value}")
        return entry
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        raise ValueError("Private, loopback, link-local, multicast, reserved, and unspecified IPs cannot be authorized")
    return str(ip)


def normalize_path_rule(value: str) -> str:
    rule = value.strip()
    if not rule:
        raise ValueError("Path rules cannot be empty")
    if not rule.startswith("/") or "#" in rule:
        raise ValueError(f"Invalid path rule: {value}")
    return rule


def validate_scope_policy(
    policy: dict[str, object], *, max_concurrency: int, max_requests: int, max_redirects: int
) -> dict[str, object]:
    authorized = [normalize_scope_entry(str(x)) for x in policy.get("authorized_targets", [])]
    excluded = [normalize_scope_entry(str(x)) for x in policy.get("excluded_targets", [])]
    if policy.get("enabled") and not authorized:
        raise ValueError("At least one authorized target is required when the scope is enabled")
    if len(set(authorized)) != len(authorized):
        raise ValueError("Authorized target entries must be unique")
    if len(set(excluded)) != len(excluded):
        raise ValueError("Excluded target entries must be unique")
    ports = sorted({int(x) for x in policy.get("allowed_ports", [])})
    if not ports or any(port < 1 or port > 65535 for port in ports):
        raise ValueError("Allowed ports must contain values between 1 and 65535")
    allowed_paths = [normalize_path_rule(str(x)) for x in policy.get("allowed_paths", ["/"])]
    blocked_paths = [normalize_path_rule(str(x)) for x in policy.get("blocked_paths", [])]
    if max_requests < 1:
        raise ValueError("max_requests must be positive")
    if max_concurrency < 1:
        raise ValueError("max_concurrency must be positive")
    if max_redirects < 0:
        raise ValueError("max_redirects cannot be negative")
    if policy.get("enabled") and policy.get("authorization_acknowledged") is not True:
        raise ValueError("Authorization acknowledgement is required before enabling a scope")
    return {
        "authorized_targets": authorized,
        "excluded_targets": excluded,
        "allowed_ports": ports,
        "allowed_paths": allowed_paths or ["/"],
        "blocked_paths": blocked_paths,
    }


def _entry_matches_host(entry: str, host: str) -> bool:
    host = host.rstrip(".").lower()
    if entry.startswith("*."):
        suffix = entry[2:]
        return host.endswith("." + suffix) and host != suffix
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return entry == host
    try:
        if "/" in entry:
            return ip in ipaddress.ip_network(entry, strict=False)
        return str(ip) == entry
    except ValueError:
        return False


def scope_host_allowed(host: str, scope: dict[str, object]) -> bool:
    normalized = host.rstrip(".").lower()
    if any(_entry_matches_host(str(entry), normalized) for entry in scope.get("excluded_targets", [])):
        return False
    return any(_entry_matches_host(str(entry), normalized) for entry in scope.get("authorized_targets", []))


def default_port_for_url(url: str) -> int:
    parsed = urlparse(url)
    if parsed.port:
        return parsed.port
    return 443 if parsed.scheme == "https" else 80


def scope_port_allowed(port: int, scope: dict[str, object]) -> bool:
    return port in {int(x) for x in scope.get("allowed_ports", [])}


def scope_path_allowed(path: str, scope: dict[str, object]) -> bool:
    path = path or "/"
    blocked = [str(x) for x in scope.get("blocked_paths", [])]
    if any(path == rule or path.startswith(rule.rstrip("/") + "/") for rule in blocked):
        return False
    allowed = [str(x) for x in scope.get("allowed_paths", ["/"])]
    return any(path == rule or path.startswith(rule.rstrip("/") + "/") or rule == "/" for rule in allowed)


def validate_target_against_scope(value: str, scope: dict[str, object]) -> dict[str, object]:
    if not scope.get("enabled"):
        raise ScopeViolation("Workspace assessment scope is disabled")
    if not scope.get("authorization_acknowledged"):
        raise ScopeViolation("Workspace assessment authorization has not been acknowledged")
    normalized = normalize_target(value)
    parsed = urlparse(normalized)
    host = (parsed.hostname or "").rstrip(".").lower()
    if not scope_host_allowed(host, scope):
        raise ScopeViolation(f"Target host '{host}' is outside the authorized workspace scope")
    port = default_port_for_url(normalized)
    if not scope_port_allowed(port, scope):
        raise ScopeViolation(f"Target port {port} is not allowed by the workspace scope")
    if not scope_path_allowed(parsed.path or "/", scope):
        raise ScopeViolation(f"Target path '{parsed.path or '/'}' is blocked by the workspace scope")
    return {"target": normalized, "host": host, "port": port}


def scope_snapshot(scope) -> dict[str, object]:
    return {
        "id": scope.id if scope else None,
        "workspace_id": scope.workspace_id if scope else None,
        "enabled": bool(scope and scope.enabled),
        "authorized_targets": list(scope.authorized_targets or []) if scope else [],
        "excluded_targets": list(scope.excluded_targets or []) if scope else [],
        "allowed_ports": [int(x) for x in (scope.allowed_ports or [])] if scope else [80, 443],
        "allowed_paths": list(scope.allowed_paths or ["/"]) if scope else ["/"],
        "blocked_paths": list(scope.blocked_paths or []) if scope else [],
        "max_requests": int(scope.max_requests) if scope else 250,
        "max_concurrency": int(scope.max_concurrency) if scope else 1,
        "max_redirects": int(scope.max_redirects) if scope else 3,
        "authorization_acknowledged": bool(scope and scope.authorization_acknowledged),
        "authorization_acknowledged_at": scope.authorization_acknowledged_at.isoformat() if scope and scope.authorization_acknowledged_at else None,
        "acknowledged_by": scope.acknowledged_by if scope else None,
        "created_at": scope.created_at.isoformat() if scope and scope.created_at else None,
        "updated_at": scope.updated_at.isoformat() if scope and scope.updated_at else None,
    }
