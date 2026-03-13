from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

import requests

from app.config import settings


_URL_PATTERN = re.compile(r"https?://[^\s\]\[\)\(\"'<>]+", re.IGNORECASE)


def extract_urls_from_text(text: str) -> list[str]:
    return _URL_PATTERN.findall(text or "")


def _domain_from_url(url: str) -> str:
    parsed = urlparse(url)
    return (parsed.netloc or "").lower().strip()


def _vt_domain_check(domain: str) -> dict[str, Any] | None:
    if not settings.VIRUSTOTAL_API_KEY:
        return None

    endpoint = f"https://www.virustotal.com/api/v3/domains/{domain}"
    try:
        response = requests.get(endpoint, headers={"x-apikey": settings.VIRUSTOTAL_API_KEY}, timeout=15)
        response.raise_for_status()
        payload = response.json()
    except requests.RequestException:
        return None

    stats = (((payload.get("data") or {}).get("attributes") or {}).get("last_analysis_stats") or {})
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))

    if malicious > 0:
        return {"domain_risk": "high", "reason": f"VirusTotal reported {malicious} malicious detections."}
    if suspicious > 0:
        return {"domain_risk": "medium", "reason": f"VirusTotal reported {suspicious} suspicious detections."}
    return {"domain_risk": "low", "reason": "VirusTotal did not report malicious activity for this domain."}


def _openphish_check(url: str) -> dict[str, Any] | None:
    if not settings.OPENPHISH_FEED_URL:
        return None

    try:
        response = requests.get(settings.OPENPHISH_FEED_URL, timeout=15)
        response.raise_for_status()
        lines = [line.strip() for line in response.text.splitlines() if line.strip()]
    except requests.RequestException:
        return None

    if url in lines:
        return {"domain_risk": "high", "reason": "URL appears in OpenPhish feed."}
    return None


def analyze_domain_risk(url: str) -> dict[str, Any]:
    domain = _domain_from_url(url)
    if not domain:
        return {"domain_risk": "unknown", "reason": "No valid domain found in URL.", "url": url}

    openphish_result = _openphish_check(url)
    if openphish_result:
        return {"url": url, "domain": domain, **openphish_result}

    vt_result = _vt_domain_check(domain)
    if vt_result:
        return {"url": url, "domain": domain, **vt_result}

    tld_parts = domain.split(".")
    if len(tld_parts) >= 3 and len(tld_parts[0]) > 16:
        return {
            "url": url,
            "domain": domain,
            "domain_risk": "medium",
            "reason": "Domain has a suspiciously long subdomain and lacks threat intelligence confirmation.",
        }

    return {
        "url": url,
        "domain": domain,
        "domain_risk": "unknown",
        "reason": "No external threat intelligence signals were available for this domain.",
    }


def analyze_claim_urls(claim_text: str) -> list[dict[str, Any]]:
    urls = extract_urls_from_text(claim_text)
    return [analyze_domain_risk(url) for url in urls]
