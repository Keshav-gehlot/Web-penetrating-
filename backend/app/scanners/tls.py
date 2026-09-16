import socket, ssl
from urllib.parse import urlparse

async def scan_tls(target: str) -> dict:
    parsed = urlparse(target)
    host = parsed.hostname
    if not host:
        raise ValueError("Invalid target")
    port = parsed.port or (443 if parsed.scheme == "https" else 443)
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=8) as raw:
            with context.wrap_socket(raw, server_hostname=host) as sock:
                cert = sock.getpeercert()
                cipher = sock.cipher()
                version = sock.version()
        return {
            "module": "tls",
            "host": host,
            "port": port,
            "protocol": version,
            "cipher": cipher[0] if cipher else None,
            "certificate": {
                "subject": cert.get("subject"),
                "issuer": cert.get("issuer"),
                "not_before": cert.get("notBefore"),
                "not_after": cert.get("notAfter"),
                "serial_number": cert.get("serialNumber"),
            },
            "findings": []
        }
    except (OSError, ssl.SSLError) as exc:
        return {"module": "tls", "host": host, "port": port, "error": str(exc), "findings": []}
