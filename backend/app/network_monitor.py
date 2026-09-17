from __future__ import annotations

import ipaddress
import os
import socket
import time
from dataclasses import dataclass, field
from threading import Lock
from typing import Any

import psutil


UNSAFE_PORTS = {
    21: 2,
    23: 3,
    25: 1,
    110: 1,
    139: 2,
    445: 3,
    3389: 3,
    3306: 2,
    5432: 2,
    6379: 2,
    27017: 2,
}

PRIVATE_SERVICE_PORTS = {22, 53, 80, 443, 8080, 8443}


@dataclass
class ConnectionMemory:
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)


class NetworkMonitor:
    """Native OS network observability using psutil; no capture daemon or IPC."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._connections: dict[str, ConnectionMemory] = {}
        self._previous_bytes = psutil.net_io_counters()
        self._previous_time = time.monotonic()

    @staticmethod
    def _address(ip: str | None) -> dict[str, Any] | None:
        if not ip:
            return None
        try:
            obj = ipaddress.ip_address(ip)
            return {
                "ip": ip,
                "version": obj.version,
                "private": obj.is_private,
                "loopback": obj.is_loopback,
                "link_local": obj.is_link_local,
                "multicast": obj.is_multicast,
            }
        except ValueError:
            return {"ip": ip}

    @staticmethod
    def _risk(local: str | None, remote: str | None, port: int | None, status: str) -> tuple[str, int, list[str]]:
        score = 0
        reasons: list[str] = []
        remote_obj = None
        try:
            remote_obj = ipaddress.ip_address(remote) if remote else None
        except ValueError:
            pass
        if port in UNSAFE_PORTS:
            score += UNSAFE_PORTS[port]
            reasons.append(f"sensitive service port {port}")
        if remote_obj and not (remote_obj.is_private or remote_obj.is_loopback or remote_obj.is_link_local):
            if port in {21, 23, 139, 445, 3389}:
                score += 2
                reasons.append("sensitive service exposed to an external address")
        if status == "LISTEN" and (local or "").startswith(("0.0.0.0:", "[::]:")):
            score += 2
            reasons.append("service listens on all interfaces")
        if score >= 5:
            return "high", score, reasons
        if score >= 3:
            return "medium", score, reasons
        if score >= 1:
            return "low", score, reasons
        return "info", 0, reasons

    def snapshot(self, include_listening: bool = True) -> dict[str, Any]:
        now = time.time()
        rows: list[dict[str, Any]] = []
        new_connections: list[dict[str, Any]] = []
        try:
            connections = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, OSError):
            connections = []

        with self._lock:
            for conn in connections:
                status = conn.status or "NONE"
                if not include_listening and status == psutil.CONN_LISTEN:
                    continue
                local = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None
                remote = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None
                key = f"{local}|{remote}|{status}|{conn.pid or 0}"
                memory = self._connections.get(key)
                is_new = memory is None
                if memory is None:
                    memory = ConnectionMemory(first_seen=now, last_seen=now)
                    self._connections[key] = memory
                else:
                    memory.last_seen = now
                remote_ip = conn.raddr.ip if conn.raddr else None
                remote_port = conn.raddr.port if conn.raddr else None
                local_ip = conn.laddr.ip if conn.laddr else None
                risk, risk_score, reasons = self._risk(local, remote_ip, remote_port or (conn.laddr.port if conn.laddr else None), status)
                process_name = None
                executable = None
                if conn.pid:
                    try:
                        process = psutil.Process(conn.pid)
                        process_name = process.name()
                        try:
                            executable = process.exe()
                        except (psutil.AccessDenied, psutil.NoSuchProcess):
                            pass
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass
                suspicious_path = False
                if executable:
                    lowered = executable.lower()
                    suspicious_path = any(part in lowered for part in ("\\temp\\", "/tmp/", "\\downloads\\", "/downloads/"))
                    if suspicious_path:
                        risk = "high" if risk in {"info", "low", "medium"} else risk
                        reasons.append("process executable is located in a temporary/download directory")
                row = {
                    "key": key,
                    "status": status,
                    "pid": conn.pid,
                    "process": process_name,
                    "executable": executable,
                    "local": local,
                    "remote": remote,
                    "local_address": self._address(local_ip),
                    "remote_address": self._address(remote_ip),
                    "first_seen": memory.first_seen,
                    "last_seen": memory.last_seen,
                    "new": is_new,
                    "risk": risk,
                    "risk_score": risk_score,
                    "risk_reasons": reasons,
                }
                rows.append(row)
                if is_new:
                    new_connections.append(row)

            cutoff = now - 3600
            self._connections = {k: v for k, v in self._connections.items() if v.last_seen >= cutoff}

        counters = psutil.net_io_counters(pernic=True)
        total = psutil.net_io_counters()
        current = time.monotonic()
        dt = max(current - self._previous_time, 0.001)
        previous = self._previous_bytes
        self._previous_bytes = total
        self._previous_time = current
        return {
            "timestamp": now,
            "hostname": socket.gethostname(),
            "platform": os.name,
            "connection_count": len(rows),
            "new_connection_count": len(new_connections),
            "connections": rows,
            "new_connections": new_connections,
            "network_io": {
                "bytes_sent": total.bytes_sent,
                "bytes_recv": total.bytes_recv,
                "packets_sent": total.packets_sent,
                "packets_recv": total.packets_recv,
                "send_bytes_per_second": max(0, round((total.bytes_sent - previous.bytes_sent) / dt, 2)),
                "recv_bytes_per_second": max(0, round((total.bytes_recv - previous.bytes_recv) / dt, 2)),
                "interfaces": {
                    name: {
                        "bytes_sent": value.bytes_sent,
                        "bytes_recv": value.bytes_recv,
                        "packets_sent": value.packets_sent,
                        "packets_recv": value.packets_recv,
                    }
                    for name, value in counters.items()
                },
            },
            "vpn_interfaces": self._vpn_interfaces(),
        }

    @staticmethod
    def _vpn_interfaces() -> list[str]:
        names: list[str] = []
        try:
            interfaces = psutil.net_if_addrs()
            for name in interfaces:
                lowered = name.lower()
                if any(token in lowered for token in ("tun", "tap", "wg", "vpn", "utun", "ppp")):
                    names.append(name)
        except OSError:
            pass
        return sorted(names)


monitor = NetworkMonitor()
