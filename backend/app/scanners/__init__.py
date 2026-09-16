from .headers import scan_headers
from .dns import scan_dns
from .tls import scan_tls
from .modules import MODULES, PROFILES
from .enrichment import cve_lookup as live_cve_lookup, whois_lookup as live_whois_lookup

# Replace the baseline metadata implementations with live registry-backed enrichment.
MODULES["cve_lookup"] = live_cve_lookup
MODULES["whois_lookup"] = live_whois_lookup

__all__ = ["scan_headers", "scan_dns", "scan_tls", "MODULES", "PROFILES"]
