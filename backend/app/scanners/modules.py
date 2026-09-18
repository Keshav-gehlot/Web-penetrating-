"""PHANTOM assessment modules.

All network modules are deliberately bounded and non-destructive. They are intended
for targets that the operator is authorized to assess. Active exploit verification
is not enabled by this baseline engine; candidate findings are reported with evidence
for a later, separately controlled verification workflow.
"""
from __future__ import annotations

import re
import socket
import ssl
from datetime import datetime, timezone
from html.parser import HTMLParser
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

import httpx

from .runtime import bounded_connect, bounded_get, bounded_resolve, bounded_snapshot, scoped_tcp_socket
from ..security_scope import scope_host_allowed
from ..intelligence.cve import enrich_cpe, fingerprint_from_header

UA = "PHANTOM/2.0 authorized-security-assessment"
TIMEOUT = httpx.Timeout(8.0, connect=5.0)
COMMON_PORTS = (21, 22, 25, 53, 80, 110, 143, 443, 445, 587, 993, 995, 3306, 5432, 6379, 8080, 8443)
COMMON_DIRS = ("robots.txt", "sitemap.xml", ".well-known/security.txt", "health", "status", "api", "login", "admin")
SQL_ERRORS = ("sql syntax", "mysql", "postgresql", "sqlite", "ora-", "odbc", "jdbc", "unclosed quotation")


def finding(module, title, severity="info", description="", remediation="", evidence=None, confidence=1.0):
    return {"module": module, "title": title, "severity": severity, "description": description,
            "remediation": remediation, "evidence": evidence or {}, "confidence": confidence}


def base(module, **extra):
    return {"module": module, "timestamp": datetime.now(timezone.utc).isoformat(), "findings": [], **extra}


async def get(target: str, path: str = ""):
    return await bounded_get(target, path)


async def http_snapshot(target: str):
    return await bounded_snapshot(target)


async def port_scanner(target):
    host = urlparse(target).hostname
    results = []
    if not host:
        return base("port_scanner", host=host, ports=[])
    for port in COMMON_PORTS:
        try:
            bounded_connect(host, port)
            services = {21: "ftp", 22: "ssh", 25: "smtp", 53: "dns", 80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "smb", 587: "smtp-submission", 993: "imaps", 995: "pop3s", 3306: "mysql", 5432: "postgresql", 6379: "redis", 8080: "http-alt", 8443: "https-alt"}
            results.append({"port": port, "protocol": "tcp", "service": services.get(port), "state": "open"})
        except OSError:
            pass
        except RuntimeError:
            continue
    return base("port_scanner", host=host, ports=results)


async def subdomain_enumeration(target):
    host = urlparse(target).hostname
    if not host or host.count(".") < 1:
        return base("subdomain_enumeration", host=host, subdomains=[])
    root = ".".join(host.split(".")[-2:])
    names = ("www", "api", "app", "dev", "staging", "test", "mail", "vpn", "cdn", "docs")
    found = []
    for name in names:
        fqdn = f"{name}.{root}"
        runtime_scope = __import__(".runtime", globals(), locals(), ["_CURRENT"], 1)._CURRENT.get()
        if runtime_scope is not None and runtime_scope.scope is not None and not scope_host_allowed(fqdn, runtime_scope.scope):
            continue
        try:
            addrs = bounded_resolve(fqdn)
            found.append({"host": fqdn, "addresses": addrs})
        except RuntimeError:
            continue
    return base("subdomain_enumeration", root=root, subdomains=found)


async def directory_enumeration(target):
    hits = []
    for path in COMMON_DIRS:
        try:
            r = await get(target, path)
            if r.status_code not in (404, 410):
                hits.append({"path": "/" + path, "status": r.status_code, "length": len(r.content)})
        except httpx.HTTPError:
            continue
    return base("directory_enumeration", paths=hits)


async def waf_detection(target):
    r = await http_snapshot(target)
    h = {k.lower(): v for k, v in r.headers.items()}
    signatures = {"cloudflare": ("server", "cloudflare"), "akamai": ("server", "akamai"),
                  "sucuri": ("server", "sucuri"), "aws-waf": ("x-amzn-waf", "")}
    detected = []
    for vendor, (key, value) in signatures.items():
        if key in h and (not value or value in h[key].lower()): detected.append(vendor)
    return base("waf_detection", detected=detected, evidence={"server": h.get("server"), "status": r.status_code})


async def whois_lookup(target):
    host = urlparse(target).hostname
    return base(
        "whois_lookup",
        host=host,
        source="disabled-external-rdap",
        data={"note": "External registry lookups are not performed by scanner modules; use an explicitly configured enrichment integration for registry data."},
    )


async def dns_recon(target):
    host = urlparse(target).hostname
    records = []
    try:
        for address in bounded_resolve(host):
            records.append({"type": "A/AAAA", "value": address})
    except RuntimeError as exc:
        return base("dns_recon", host=host, error=str(exc))
    return base("dns_recon", host=host, records=sorted({tuple(sorted(x.items())) for x in records}))


async def cve_lookup(target):
    r = await http_snapshot(target)
    fingerprints = []
    for header in ("server", "x-powered-by"):
        fp = fingerprint_from_header(header, r.headers.get(header, ""))
        if fp and fp not in fingerprints:
            fingerprints.append(fp)
    matches = []
    for fp in fingerprints:
        if fp.get("cpe") and fp.get("version"):
            for cve in await enrich_cpe(fp["cpe"], fp["version"]):
                cve["product"] = fp["product"]
                cve["version"] = fp["version"]
                cve["cpe"] = fp["cpe"]
                cve["fingerprint_confidence"] = fp["confidence"]
                matches.append(cve)
    findings = []
    for item in matches:
        v4 = item.get("cvss_v4") or {}
        v3 = item.get("cvss_v3") or {}
        findings.append(finding(
            "cve_lookup",
            f"{item['cve']} — {item['product']} {item['version']}",
            item.get("severity", "info").lower(),
            item.get("description", ""),
            item.get("remediation", ""),
            evidence={"source": "NVD", "product": item["product"], "version": item["version"], "cpe": item["cpe"],
                      "published": item.get("published"), "modified": item.get("modified"),
                      "cvss_v3": v3, "cvss_v4": v4, "affected_versions": item.get("affected_versions", []),
                      "references": item.get("references", [])},
            confidence=float(item.get("fingerprint_confidence", 0.9)),
        ) | {"cve": item["cve"], "cvss": item.get("cvss"), "cvss_v3_score": v3.get("score"),
           "cvss_v3_vector": v3.get("vector"), "cvss_v3_severity": v3.get("severity"),
           "cvss_v4_score": v4.get("score"), "cvss_v4_vector": v4.get("vector"),
           "cvss_v4_severity": v4.get("severity"), "published": item.get("published"),
           "modified": item.get("modified"), "affected_versions": item.get("affected_versions", []),
           "references": item.get("references", [])})
    return base("cve_lookup", detected_software=fingerprints, matches=matches, findings=findings, source="NVD")


class FormParser(HTMLParser):
    def __init__(self):
        super().__init__(); self.forms=[]; self.current=None
    def handle_starttag(self, tag, attrs):
        a=dict(attrs)
        if tag.lower()=="form":
            self.current={"action":a.get("action"),"method":a.get("method","get").lower(),"inputs":[]}; self.forms.append(self.current)
        elif tag.lower() in ("input","textarea","select") and self.current is not None:
            self.current["inputs"].append({"name":a.get("name"),"type":a.get("type","text")})
    def handle_endtag(self, tag):
        if tag.lower()=="form": self.current=None


async def html_parser(target):
    r=await http_snapshot(target); p=FormParser()
    try: p.feed(r.text)
    except Exception: pass
    return r,p


async def csrf_detector(target):
    r,p=await html_parser(target); findings=[]
    for form in p.forms:
        if form["method"]=="post" and not any((i.get("name") or "").lower() in ("csrf","csrf_token","xsrf","_token") for i in form["inputs"]):
            findings.append(finding("csrf_detector", "POST form has no apparent CSRF token", "medium",
                                    "The form contains a state-changing POST surface but no conventional CSRF token was detected.",
                                    "Use a server-validated CSRF token or an equivalent framework protection.", {"action":form["action"],"inputs":form["inputs"]}, 0.72))
    return base("csrf_detector", forms=p.forms, findings=findings)


async def xss_detector(target):
    r,p=await html_parser(target); qs=parse_qs(urlparse(target).query); findings=[]
    if qs:
        marker="PHANTOM_XSS_MARKER"
        u=urlparse(target); q={k:(marker if v else marker) for k,v in qs.items()}
        probe=urlunparse((u.scheme,u.netloc,u.path,u.params,urlencode(q),u.fragment))
        try:
            pr=await http_snapshot(probe)
            if marker in pr.text:
                findings.append(finding("xss_detector","Query parameter is reflected in response","medium",
                    "A harmless marker was reflected. This is a candidate reflection surface, not proof of executable XSS.",
                    "Context-encode untrusted output and apply an appropriate CSP.",{"url":probe,"marker":marker},0.8))
        except httpx.HTTPError: pass
    return base("xss_detector", query_parameters=list(qs), findings=findings)


async def sqli_detector(target):
    r=await http_snapshot(target); text=r.text.lower(); matches=[e for e in SQL_ERRORS if e in text]
    findings=[]
    if matches:
        findings.append(finding("sqli_detector","Database error signature exposed","medium",
            "The response contains database error terminology. This is a candidate injection/error-disclosure surface and is not proof of SQL injection.",
            "Return generic application errors and use parameterized queries.",{"signatures":matches},0.7))
    return base("sqli_detector", error_signatures=matches, findings=findings)


async def ssrf_detector(target):
    r,p=await html_parser(target); url_inputs=[i for f in p.forms for i in f["inputs"] if any(x in (i.get("name") or "").lower() for x in ("url","uri","link","callback","redirect","webhook"))]
    return base("ssrf_detector", candidate_url_inputs=url_inputs,
                findings=[finding("ssrf_detector","URL-like input surface detected","info","A URL-like input was found; server-side fetching could not be established without an intrusive verification request.","Allowlist destinations and block private/link-local address ranges for server-side fetchers.",{"inputs":url_inputs},0.55)] if url_inputs else [])


async def xxe_detector(target):
    r,p=await html_parser(target); xml=[i for f in p.forms for i in f["inputs"] if "xml" in (i.get("name") or "").lower()]
    return base("xxe_detector", candidate_xml_inputs=xml, findings=[finding("xxe_detector","Potential XML input surface detected","info","An XML-named input was found; no external-entity payload was sent.","Disable external entity resolution and DTD processing in XML parsers.",{"inputs":xml},0.5)] if xml else [])


async def auth_tester(target):
    r=await get(target,"login"); h={k.lower():v for k,v in r.headers.items()}; cookies=h.get("set-cookie","")
    findings=[]
    if cookies and "secure" not in cookies.lower() and urlparse(target).scheme=="https":
        findings.append(finding("authentication_tester","Session cookie lacks Secure attribute","medium","A cookie was set over HTTPS without an apparent Secure attribute.","Mark authentication cookies Secure; also use HttpOnly and an appropriate SameSite value.",{"set_cookie":cookies[:500]},0.9))
    return base("authentication_tester", login_status=r.status_code, headers={"www-authenticate":h.get("www-authenticate")}, findings=findings)


async def open_redirect_detector(target):
    u=urlparse(target); params=parse_qs(u.query); candidates=[k for k in params if k.lower() in ("next","url","redirect","return","returnurl","continue")]
    findings=[]
    if candidates:
        findings.append(finding("open_redirect_detector","Redirect-like parameter detected","info","A common redirect parameter is present. No external redirect was attempted.","Validate redirect destinations against an allowlist or use relative paths.",{"parameters":candidates},0.6))
    return base("open_redirect_detector", candidates=candidates, findings=findings)


async def security_txt(target):
    r=await get(target,".well-known/security.txt")
    return base("security_txt", status=r.status_code, present=r.status_code==200, content=r.text[:4096] if r.status_code==200 else None)


async def robots_sitemap(target):
    out={}
    for path in ("robots.txt","sitemap.xml"):
        try:
            r=await get(target,path); out[path]={"status":r.status_code,"length":len(r.content)}
        except httpx.HTTPError as exc: out[path]={"error":str(exc)}
    return base("robots_sitemap", resources=out)


async def cookie_audit(target):
    r=await http_snapshot(target); findings=[]
    for raw in r.headers.get_list("set-cookie"):
        low=raw.lower()
        if urlparse(target).scheme=="https" and "secure" not in low: findings.append(finding("cookie_audit","Cookie missing Secure attribute","medium","A cookie was set without Secure on an HTTPS response.","Set Secure on session and sensitive cookies.",{"cookie":raw.split(";",1)[0]},0.9))
        if "httponly" not in low: findings.append(finding("cookie_audit","Cookie missing HttpOnly attribute","low","A cookie lacks HttpOnly.","Use HttpOnly for cookies that do not need client-side JavaScript access.",{"cookie":raw.split(";",1)[0]},0.85))
        if "samesite" not in low: findings.append(finding("cookie_audit","Cookie has no explicit SameSite attribute","low","SameSite is not explicitly declared.","Choose an explicit SameSite policy appropriate to the application.",{"cookie":raw.split(";",1)[0]},0.8))
    return base("cookie_audit", cookies=len(r.headers.get_list("set-cookie")), findings=findings)


async def cors_audit(target):
    r=await http_snapshot(target); acao=r.headers.get("access-control-allow-origin"); acac=r.headers.get("access-control-allow-credentials"); findings=[]
    if acao=="*" and acac and acac.lower()=="true":
        findings.append(finding("cors_audit","Wildcard CORS with credentials","high","The response combines wildcard origin with credential permission.","Use an explicit trusted-origin allowlist and avoid wildcard credentialed CORS.",{"allow_origin":acao,"allow_credentials":acac},0.98))
    return base("cors_audit", allow_origin=acao, allow_credentials=acac, findings=findings)


async def tech_detection(target):
    r = await http_snapshot(target)
    h = {k.lower(): v for k, v in r.headers.items()}
    text = r.text[:200000]
    tech = []
    for header in ("server", "x-powered-by"):
        fp = fingerprint_from_header(header, h.get(header, ""))
        if fp:
            tech.append(fp)
        elif h.get(header):
            tech.append({"product": h[header].split("/", 1)[0].strip(), "version": None, "source": header, "cpe": None, "confidence": 0.4})
    for name, pat in (("WordPress", r"wp-content|wp-includes"), ("React", r"__react|reactroot"), ("Next.js", r"__next_f|_next/static"), ("Django", r"csrfmiddlewaretoken")):
        if re.search(pat, text, re.I):
            tech.append({"product": name, "version": None, "vendor": None, "cpe": None, "source": "html", "confidence": 0.7})
    return base("technology_detection", technologies=tech)


async def endpoint_inventory(target):
    response, parser = await html_parser(target)
    target_host = urlparse(target).hostname
    endpoints = []
    for match in re.finditer(r'href=["\']([^"\']+)', response.text, re.I):
        href = urljoin(str(response.url), match.group(1))
        if urlparse(href).hostname == target_host:
            endpoints.append(href)
    return base("endpoint_inventory", endpoints=sorted(set(endpoints))[:500], forms=parser.forms)


async def http_header_analyzer(target):
    response = await http_snapshot(target)
    headers = {key.lower(): value for key, value in response.headers.items()}
    required = {
        "strict-transport-security": ("high", "Enable HSTS on HTTPS deployments."),
        "content-security-policy": ("medium", "Define a restrictive CSP."),
        "x-content-type-options": ("medium", "Set X-Content-Type-Options: nosniff."),
        "referrer-policy": ("low", "Set an explicit Referrer-Policy."),
        "permissions-policy": ("low", "Restrict unnecessary browser capabilities."),
    }
    findings = [
        finding("http_header_analyzer", f"Missing {header}", severity,
                "The expected security response header was not present.", remediation,
                {"status": response.status_code}, 0.99)
        for header, (severity, remediation) in required.items()
        if header not in headers
    ]
    return base("http_header_analyzer", status=response.status_code,
                final_url=str(response.url), headers=dict(response.headers), findings=findings)


async def tls_analyzer(target):
    parsed = urlparse(target)
    host = parsed.hostname
    port = parsed.port or 443
    if parsed.scheme != "https":
        return base("tls_analyzer", enabled=False, note="Target is not HTTPS")
    try:
        with scoped_tcp_socket(host, port) as raw:
            context = ssl.create_default_context()
            with context.wrap_socket(raw, server_hostname=host) as sock:
                cert = sock.getpeercert()
                cipher = sock.cipher()
                return base(
                    "tls_analyzer",
                    enabled=True,
                    protocol=sock.version(),
                    cipher=cipher[0] if cipher else None,
                    certificate={
                        "subject": cert.get("subject"),
                        "issuer": cert.get("issuer"),
                        "not_after": cert.get("notAfter"),
                    },
                )
    except (OSError, ssl.SSLError, RuntimeError) as exc:
        return base("tls_analyzer", enabled=True, error=str(exc))


MODULES = {
    "port_scanner": port_scanner,
    "sql_injection": sqli_detector,
    "xss_detector": xss_detector,
    "subdomain_enumeration": subdomain_enumeration,
    "http_headers": http_header_analyzer,
    "ssl_tls": tls_analyzer,
    "directory_enumeration": directory_enumeration,
    "waf_detection": waf_detection,
    "whois_lookup": whois_lookup,
    "dns_recon": dns_recon,
    "cve_lookup": cve_lookup,
    "csrf_detector": csrf_detector,
    "ssrf_detector": ssrf_detector,
    "xxe_detector": xxe_detector,
    "authentication_tester": auth_tester,
    "open_redirect": open_redirect_detector,
    "security_txt": security_txt,
    "robots_sitemap": robots_sitemap,
    "cookie_audit": cookie_audit,
    "cors_audit": cors_audit,
    "technology_detection": tech_detection,
    "endpoint_inventory": endpoint_inventory,
    "net_watch": port_scanner,
}

PROFILES = {
    "quick": (
        "dns_recon",
        "http_headers",
        "ssl_tls",
        "security_txt",
        "robots_sitemap",
        "cookie_audit",
        "cors_audit",
        "technology_detection",
    ),
    "standard": tuple(MODULES.keys()),
    "deep": tuple(MODULES.keys()),
}
