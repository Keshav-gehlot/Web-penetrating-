import socket
from urllib.parse import urlparse

async def scan_dns(target: str) -> dict:
    host = urlparse(target).hostname or target
    records = []
    try:
        infos = socket.getaddrinfo(host, None)
        addresses = sorted({item[4][0] for item in infos})
        records = [{"type": "A/AAAA", "value": ip} for ip in addresses]
    except socket.gaierror as exc:
        return {"module": "dns", "host": host, "records": [], "error": str(exc), "findings": []}
    return {"module": "dns", "host": host, "records": records, "findings": []}
