"""PHANTOM web trust, accessibility and authenticity checks.

These checks are passive or use a single normal page fetch. They produce review
signals, not legal advice or proof of compliance. No intrusive payloads are sent.
"""
from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

import httpx

UA = "PHANTOM/2.0 authorized-security-assessment"
TIMEOUT = httpx.Timeout(8.0, connect=5.0)


def _finding(title, severity="low", description="", remediation="", evidence=None, confidence=0.8):
    return {
        "module": "web_trust_audit",
        "title": title,
        "severity": severity,
        "description": description,
        "remediation": remediation,
        "evidence": evidence or {},
        "confidence": confidence,
    }


class SiteParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.lang = None
        self.images = []
        self.inputs = []
        self.buttons = []
        self.links = []
        self.iframes = []
        self.scripts = []
        self.forms = []
        self.labels = []
        self._form = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        tag = tag.lower()
        if tag == "html": self.lang = a.get("lang")
        elif tag == "img": self.images.append({"alt": a.get("alt"), "src": a.get("src")})
        elif tag == "input": self.inputs.append({"id": a.get("id"), "name": a.get("name"), "type": a.get("type", "text"), "aria": a.get("aria-label")})
        elif tag == "button": self.buttons.append({"text": "", "aria": a.get("aria-label"), "title": a.get("title")})
        elif tag == "label": self.labels.append({"for": a.get("for")})
        elif tag == "a": self.links.append({"text": "", "href": a.get("href")})
        elif tag == "iframe": self.iframes.append(a.get("src"))
        elif tag == "script": self.scripts.append(a.get("src"))
        elif tag == "form":
            self._form = {"action": a.get("action"), "method": a.get("method", "get"), "controls": []}
            self.forms.append(self._form)
        elif tag in ("input", "textarea", "select") and self._form is not None:
            self._form["controls"].append(a.get("name"))

    def handle_data(self, data):
        text = " ".join(data.split())
        if not text: return
        if self.buttons: self.buttons[-1]["text"] += text[:120]
        if self.links: self.links[-1]["text"] += text[:120]

    def handle_endtag(self, tag):
        if tag.lower() == "form": self._form = None


def _has_link(parser: SiteParser, terms):
    return any(any(t in (f"{x['text']} {x['href']}").lower() for t in terms) for x in parser.links)


def _external(value, host):
    if not value: return False
    try: return bool(urlparse(urljoin(f"https://{host}", value)).hostname) and urlparse(urljoin(f"https://{host}", value)).hostname != host
    except Exception: return False


async def web_trust_audit(target: str):
    async with httpx.AsyncClient(follow_redirects=True, timeout=TIMEOUT, headers={"User-Agent": UA}) as client:
        response = await client.get(target)

    parser = SiteParser()
    try: parser.feed(response.text[:500_000])
    except Exception: pass

    host = urlparse(str(response.url)).hostname or urlparse(target).hostname
    findings = []
    checks = {}

    missing_alt = [i for i in parser.images if i.get("alt") is None]
    checks["alt_text"] = not missing_alt
    if missing_alt:
        findings.append(_finding("Images missing alt text", "low", "Some images have no alt attribute, which can reduce screen-reader accessibility.", "Provide meaningful alt text for informative images and empty alt text for decorative images.", {"count": len(missing_alt)}, 0.98))

    checks["document_language"] = bool(parser.lang)
    if not parser.lang:
        findings.append(_finding("Document language is not declared", "low", "The root HTML element has no lang attribute detected.", "Declare the primary document language on the html element.", confidence=0.95))

    label_ids = {x.get("for") for x in parser.labels if x.get("for")}
    unlabeled = [i for i in parser.inputs if i.get("type") not in ("hidden", "submit", "button") and not i.get("aria") and not (i.get("id") and i.get("id") in label_ids)]
    checks["form_labels"] = not unlabeled
    if unlabeled:
        findings.append(_finding("Form controls may lack accessible labels", "low", "Inputs without a matching label or aria-label were detected.", "Associate labels with controls and provide accessible names for custom controls.", {"count": len(unlabeled)}, 0.9))

    unlabeled_buttons = [b for b in parser.buttons if not (b["text"].strip() or b["aria"] or b["title"])]
    checks["button_names"] = not unlabeled_buttons
    if unlabeled_buttons:
        findings.append(_finding("Buttons without an accessible name", "low", "An empty button was detected.", "Give each interactive control a clear visible or accessible name.", {"count": len(unlabeled_buttons)}, 0.95))

    link_checks = {
        "privacy_policy": ("privacy",),
        "terms": ("terms", "conditions", "tos"),
        "refund_policy": ("refund", "return policy", "cancellation"),
        "cookie_policy": ("cookie",),
        "contact_or_business": ("contact", "about", "address"),
    }
    for key, terms in link_checks.items():
        checks[key] = _has_link(parser, terms)
        if not checks[key]:
            findings.append(_finding(f"{key.replace('_', ' ').title()} link not detected", "info", "No obvious public page or link matching this trust signal was found in the fetched HTML.", "Add an accurate, easy-to-find page when it applies to the service.", confidence=0.7))

    text = response.text.lower()
    checks["cookie_consent"] = bool(re.search(r"cookie.{0,80}(consent|preferences|accept|settings)", text, re.I))
    if not checks["cookie_consent"]:
        findings.append(_finding("Cookie consent signal not detected", "info", "No obvious cookie-consent wording was found. This does not determine legal compliance.", "Review applicable privacy/cookie requirements and provide appropriate controls where required.", confidence=0.65))

    tracking_terms = ("google-analytics", "googletagmanager", "gtag(", "facebook pixel", "hotjar", "segment")
    tracking = [s for s in parser.scripts if any(t in (s or "").lower() for t in tracking_terms)]
    checks["tracking_detected"] = not tracking
    if tracking:
        findings.append(_finding("Third-party tracking detected", "info", "Known analytics/tracking signatures were found in script URLs.", "Document tracking purposes and apply the consent/privacy controls required for your deployment.", {"scripts": tracking[:20]}, 0.9))

    external_embeds = [x for x in parser.iframes if _external(x, host)]
    checks["third_party_embeds"] = not external_embeds
    if external_embeds:
        findings.append(_finding("Third-party embeds detected", "info", "External iframe content was detected.", "Review each third-party embed for privacy, security, licensing and availability implications.", {"iframes": external_embeds[:20]}, 0.95))

    checks["copyright_notice"] = bool(re.search(r"©|copyright", text, re.I))
    if not checks["copyright_notice"]:
        findings.append(_finding("Copyright notice not detected", "info", "No obvious copyright notice was found in the fetched page text.", "Add accurate ownership/licensing information where appropriate.", confidence=0.7))

    checks["business_details"] = bool(re.search(r"(email|phone|address|registered office|company)", text, re.I))
    if not checks["business_details"]:
        findings.append(_finding("Business/contact details not detected", "info", "No obvious contact or business-detail signal was found.", "Publish truthful contact/business information appropriate to the service.", confidence=0.7))

    claim_terms = re.findall(r"\b(?:100%|guaranteed|guarantee|always|never|best|#1)\b", response.text, re.I)
    if claim_terms:
        findings.append(_finding("Marketing claims require human review", "info", "Absolute or comparative claim language was detected; PHANTOM does not verify whether claims are supported.", "Review claims for accuracy and retain evidence for material assertions.", {"claims": claim_terms[:20]}, 0.85))

    checks["https"] = urlparse(str(response.url)).scheme == "https"
    if not checks["https"]:
        findings.append(_finding("Site is not using HTTPS", "high", "The final fetched URL is HTTP.", "Serve the application over HTTPS and redirect HTTP to HTTPS where appropriate.", confidence=0.99))

    return {
        "module": "web_trust_audit",
        "status": "ok",
        "url": str(response.url),
        "status_code": response.status_code,
        "checks": checks,
        "summary": {"total_checks": len(checks), "passed": sum(bool(v) for v in checks.values()), "review": sum(not bool(v) for v in checks.values())},
        "findings": findings,
    }
