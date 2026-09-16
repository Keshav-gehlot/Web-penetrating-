import httpx
from urllib.parse import urlparse

SECURITY_HEADERS = {
    "strict-transport-security": ("High", "Enforce HTTPS with HSTS."),
    "content-security-policy": ("High", "Define a restrictive Content-Security-Policy."),
    "x-content-type-options": ("Medium", "Set X-Content-Type-Options: nosniff."),
    "x-frame-options": ("Medium", "Set X-Frame-Options or use CSP frame-ancestors."),
    "referrer-policy": ("Low", "Set an explicit Referrer-Policy."),
    "permissions-policy": ("Low", "Restrict unnecessary browser capabilities."),
}

async def scan_headers(target: str) -> dict:
    parsed = urlparse(target)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Invalid target")
    async with httpx.AsyncClient(follow_redirects=True, timeout=10.0) as client:
        response = await client.get(target, headers={"User-Agent": "PHANTOM/2.0 authorized-security-assessment"})
    headers = {k.lower(): v for k, v in response.headers.items()}
    findings = []
    for name, (severity, remediation) in SECURITY_HEADERS.items():
        if name not in headers:
            findings.append({"type": "missing-security-header", "header": name, "severity": severity, "remediation": remediation})
    return {
        "module": "http_headers",
        "status_code": response.status_code,
        "final_url": str(response.url),
        "server": headers.get("server"),
        "headers": dict(response.headers),
        "findings": findings,
    }
