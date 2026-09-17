from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

from fastapi import HTTPException

ALLOWED_SCHEMES = {"http", "https"}


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
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            raise HTTPException(400, "Private, loopback, link-local, multicast, reserved, or local targets are not allowed")
        return {"target": normalized, "host": host, "is_ip": True}
    except ValueError:
        pass

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
