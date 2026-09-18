"""Controlled CVE intelligence layer backed by the NVD 2.0 API.

This module only performs metadata enrichment: CPE/CVE correlation, version-range
matching, CVSS extraction, references and remediation guidance. It never sends
exploit payloads or performs vulnerability verification.
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Any

import httpx

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
UA = "PHANTOM/2.0 authorized-security-assessment"
MAX_RESULTS = 20

CPE_ALIASES = {
    "nginx": ("f5", "nginx"),
    "apache http server": ("apache", "http_server"),
    "apache httpd": ("apache", "http_server"),
    "iis": ("microsoft", "internet_information_services"),
    "microsoft iis": ("microsoft", "internet_information_services"),
    "php": ("php", "php"),
    "openresty": ("openresty", "openresty"),
    "caddy": ("caddyserver", "caddy"),
    "lighttpd": ("lighttpd", "lighttpd"),
    "tomcat": ("apache", "tomcat"),
    "jetty": ("eclipse", "jetty"),
    "postgresql": ("postgresql", "postgresql"),
    "mysql": ("oracle", "mysql"),
    "redis": ("redis", "redis"),
}

VERSION_RE = re.compile(r"(?<![0-9])(?:v)?([0-9]+(?:\.[0-9]+){1,3}(?:[-+._][0-9A-Za-z.-]+)?)", re.I)


def normalize_product(value: str) -> str:
    value = re.sub(r"\s+", " ", value.strip().lower())
    return value


def fingerprint_from_header(name: str, value: str) -> dict[str, Any] | None:
    """Turn an exposed product/version header into a conservative fingerprint."""
    if not value:
        return None
    raw = value.strip()
    lower = raw.lower()
    product_key = next((key for key in CPE_ALIASES if key in lower), None)
    if not product_key:
        return None
    match = VERSION_RE.search(raw)
    if not match:
        return {
            "product": product_key,
            "version": None,
            "vendor": CPE_ALIASES[product_key][0],
            "cpe": None,
            "source": name,
            "confidence": 0.55,
        }
    version = match.group(1)
    vendor, product = CPE_ALIASES[product_key]
    cpe = f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
    return {
        "product": product_key,
        "version": version,
        "vendor": vendor,
        "cpe": cpe,
        "source": name,
        "confidence": 0.9,
    }


def _version_key(value: str) -> tuple:
    parts = re.findall(r"\d+|[A-Za-z]+", value.lower())
    out = []
    for part in parts:
        if part.isdigit():
            out.append((0, int(part)))
        else:
            out.append((1, part))
    return tuple(out)


def version_in_range(
    version: str,
    start_including: str | None = None,
    start_excluding: str | None = None,
    end_including: str | None = None,
    end_excluding: str | None = None,
) -> bool:
    v = _version_key(version)
    if start_including and v < _version_key(start_including):
        return False
    if start_excluding and v <= _version_key(start_excluding):
        return False
    if end_including and v > _version_key(end_including):
        return False
    if end_excluding and v >= _version_key(end_excluding):
        return False
    return True


def _metric(metrics: dict[str, Any], key: str) -> dict[str, Any] | None:
    rows = metrics.get(key) or []
    if not rows:
        return None
    # Prefer NVD's own assessment when available.
    nvd = next((x for x in rows if x.get("source") == "nvd@nist.gov"), None)
    return (nvd or rows[0]).get("cvssData") or (nvd or rows[0]).get("cvssData")


def _severity(score: float | None) -> str:
    if score is None:
        return "info"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def _cpe_matches(node: dict[str, Any], observed_cpe: str, observed_version: str) -> list[dict[str, Any]]:
    matches = []
    for item in node.get("cpeMatch", []) or []:
        criteria = item.get("criteria") or item.get("matchCriteriaId")
        vulnerable = item.get("vulnerable", True)
        if not vulnerable:
            continue
        if criteria and criteria.split(":")[:5] == observed_cpe.split(":")[:5]:
            if version_in_range(
                observed_version,
                item.get("versionStartIncluding"),
                item.get("versionStartExcluding"),
                item.get("versionEndIncluding"),
                item.get("versionEndExcluding"),
            ):
                matches.append(item)
    return matches


def _affected_versions(configurations: list[dict[str, Any]], observed_cpe: str) -> list[dict[str, Any]]:
    ranges = []
    for node in configurations:
        for item in node.get("cpeMatch", []) or []:
            criteria = item.get("criteria")
            if not criteria or criteria.split(":")[:5] != observed_cpe.split(":")[:5]:
                continue
            ranges.append({
                "cpe": criteria,
                "version_start_including": item.get("versionStartIncluding"),
                "version_start_excluding": item.get("versionStartExcluding"),
                "version_end_including": item.get("versionEndIncluding"),
                "version_end_excluding": item.get("versionEndExcluding"),
                "vulnerable": bool(item.get("vulnerable", True)),
            })
        for child in node.get("children", []) or []:
            ranges.extend(_affected_versions([child], observed_cpe))
    return ranges


def _remediation(affected: list[dict[str, Any]], references: list[dict[str, Any]]) -> str:
    fixes = [r for r in references if any(t.lower() in {"patch", "vendor advisory", "mitigation"} for t in r.get("tags", []))]
    upper = [x.get("version_end_excluding") or x.get("version_end_including") for x in affected]
    upper = [x for x in upper if x]
    if upper:
        base = f"Upgrade {('to a release newer than ' + ', '.join(sorted(set(upper))))} or apply the vendor fix."
    else:
        base = "Upgrade to a vendor-supported fixed release and follow the vendor advisory."
    if fixes:
        return base + " Review the referenced vendor patch/advisory before deployment."
    return base


def parse_cve(cve: dict[str, Any], observed_cpe: str, observed_version: str) -> dict[str, Any] | None:
    configurations = cve.get("configurations") or []
    matched = []
    for node in configurations:
        matched.extend(_cpe_matches(node, observed_cpe, observed_version))
        for child in node.get("children", []) or []:
            matched.extend(_cpe_matches(child, observed_cpe, observed_version))
    if not matched:
        return None

    metrics = cve.get("metrics") or {}
    v4 = _metric(metrics, "cvssMetricV40")
    v31 = _metric(metrics, "cvssMetricV31")
    v30 = _metric(metrics, "cvssMetricV30")
    primary = v4 or v31 or v30
    score = primary.get("baseScore") if primary else None
    refs = [
        {"url": r.get("url"), "source": r.get("source"), "tags": r.get("tags", [])}
        for r in cve.get("references", [])
        if r.get("url")
    ]
    descriptions = cve.get("descriptions") or []
    description = next((d.get("value") for d in descriptions if d.get("lang") == "en"), "")
    affected = _affected_versions(configurations, observed_cpe)
    return {
        "cve": cve.get("id"),
        "description": description,
        "published": cve.get("published"),
        "modified": cve.get("lastModified"),
        "cvss": score,
        "severity": primary.get("baseSeverity") if primary and primary.get("baseSeverity") else _severity(score),
        "cvss_v4": {"score": v4.get("baseScore"), "vector": v4.get("vectorString"), "severity": v4.get("baseSeverity")} if v4 else None,
        "cvss_v3": {"score": v31.get("baseScore"), "vector": v31.get("vectorString"), "severity": v31.get("baseSeverity")} if v31 else ({"score": v30.get("baseScore"), "vector": v30.get("vectorString"), "severity": v30.get("baseSeverity")} if v30 else None),
        "affected_versions": affected,
        "references": refs,
        "remediation": _remediation(affected, refs),
        "source": "NVD",
    }


async def enrich_cpe(cpe: str, version: str, client: httpx.AsyncClient | None = None) -> list[dict[str, Any]]:
    if not cpe or not version:
        return []
    own = client is None
    if own:
        client = httpx.AsyncClient(timeout=8.0, headers={"User-Agent": UA})
    try:
        response = await client.get(NVD_URL, params={"cpeName": cpe, "resultsPerPage": MAX_RESULTS})
        response.raise_for_status()
        payload = response.json()
        results = []
        for item in payload.get("vulnerabilities", [])[:MAX_RESULTS]:
            parsed = parse_cve(item.get("cve", {}), cpe, version)
            if parsed:
                results.append(parsed)
        return results
    except (httpx.HTTPError, ValueError):
        return []
    finally:
        if own:
            await client.aclose()
