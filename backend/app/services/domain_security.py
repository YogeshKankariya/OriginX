from __future__ import annotations

import html
import re
import socket
import ssl
from typing import Any
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
from urllib.parse import urlparse

import requests

from app.config import settings


_URL_PATTERN = re.compile(r"https?://[^\s\]\[\)\(\"'<>]+", re.IGNORECASE)
_METADATA_PARALLEL_BUDGET_SECONDS = 8.5
_METADATA_MAX_WORKERS = 5


def extract_urls_from_text(text: str) -> list[str]:
    return _URL_PATTERN.findall(text or "")


def _domain_from_url(url: str) -> str:
    parsed = urlparse(url)
    return (parsed.hostname or "").lower().strip()


def _safe_get_json(url: str, *, params: dict[str, Any] | None = None, timeout: int = 10) -> dict[str, Any] | None:
    try:
        response = requests.get(url, params=params, timeout=timeout)
        response.raise_for_status()
        payload = response.json()
    except (requests.RequestException, ValueError):
        return None

    return payload if isinstance(payload, dict) else None


@lru_cache(maxsize=1)
def _get_rdap_bootstrap() -> list[tuple[list[str], list[str]]]:
    payload = _safe_get_json("https://data.iana.org/rdap/dns.json", timeout=15)
    if not payload:
        return []

    services = payload.get("services")
    if not isinstance(services, list):
        return []

    results: list[tuple[list[str], list[str]]] = []
    for service in services:
        if not isinstance(service, list) or len(service) < 2:
            continue

        suffixes, providers = service[0], service[1]
        if not isinstance(suffixes, list) or not isinstance(providers, list):
            continue

        normalized_suffixes = [str(suffix).lower().strip(".") for suffix in suffixes if isinstance(suffix, str) and suffix.strip()]
        normalized_providers = [str(provider).strip() for provider in providers if isinstance(provider, str) and provider.strip()]
        if normalized_suffixes and normalized_providers:
            results.append((normalized_suffixes, normalized_providers))

    return results


def _get_rdap_provider_urls(hostname: str) -> list[str]:
    labels = [part.lower() for part in hostname.split(".") if part]
    if not labels:
        return []

    candidates = [".".join(labels[index:]) for index in range(len(labels))]
    bootstrap = _get_rdap_bootstrap()

    for candidate in candidates:
        for suffixes, providers in bootstrap:
            if candidate in suffixes:
                return providers

    return []


def _fetch_rdap_payload(hostname: str) -> dict[str, Any] | None:
    provider_urls = _get_rdap_provider_urls(hostname)
    fallback_urls = [f"https://rdap.org/domain/{hostname}"]

    for provider in [*provider_urls, *fallback_urls]:
        base_url = provider.rstrip("/")
        endpoint = base_url if "/domain/" in base_url.lower() else f"{base_url}/domain/{hostname}"
        payload = _safe_get_json(endpoint, timeout=12)
        if payload:
            return payload

    return None


def _parse_rdap_date(value: str | None) -> datetime | None:
    if not value:
        return None

    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"

    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None

    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)

    return parsed


def _extract_rdap_event(events: list[dict[str, Any]], action: str) -> datetime | None:
    for event in events:
        if (event.get("eventAction") or "").lower() != action:
            continue
        parsed = _parse_rdap_date(event.get("eventDate"))
        if parsed:
            return parsed
    return None


def _extract_registrar(rdap_payload: dict[str, Any]) -> str | None:
    entities = rdap_payload.get("entities")
    if not isinstance(entities, list):
        return None

    for entity in entities:
        if not isinstance(entity, dict):
            continue
        roles = entity.get("roles")
        if not isinstance(roles, list) or "registrar" not in [str(role).lower() for role in roles]:
            continue

        vcard = entity.get("vcardArray")
        if not isinstance(vcard, list) or len(vcard) < 2 or not isinstance(vcard[1], list):
            continue

        for card in vcard[1]:
            if not isinstance(card, list) or len(card) < 4:
                continue
            label = str(card[0]).lower()
            if label not in {"fn", "org"}:
                continue
            value = card[3]
            if isinstance(value, str) and value.strip():
                return value.strip()

    return None


def _get_dns_a_records(hostname: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(hostname, None)
    except OSError:
        return []

    ips = {info[4][0] for info in infos if info and len(info) >= 5 and info[4]}
    return sorted(ip for ip in ips if isinstance(ip, str))


def _get_dns_mx_records(hostname: str) -> list[str]:
    payload = _safe_get_json(
        "https://dns.google/resolve",
        params={"name": hostname, "type": "MX"},
        timeout=8,
    )
    if not payload:
        return []

    answers = payload.get("Answer")
    if not isinstance(answers, list):
        return []

    results: list[str] = []
    for answer in answers:
        if not isinstance(answer, dict):
            continue
        raw_data = answer.get("data")
        if not isinstance(raw_data, str):
            continue
        results.append(raw_data.rstrip("."))

    return results


def _fetch_url_content_metadata(url: str) -> tuple[str | None, int]:
    try:
        response = requests.get(
            url,
            timeout=12,
            allow_redirects=True,
            headers={"User-Agent": "OriginX Scanner/1.0"},
        )
    except requests.RequestException:
        return None, 0

    text = getattr(response, "text", "")
    history = getattr(response, "history", [])
    redirect_hops = len(history) if isinstance(history, list) else 0

    title_match = re.search(r"<title[^>]*>(.*?)</title>", text or "", re.IGNORECASE | re.DOTALL)
    if not title_match:
        return None, redirect_hops

    title = html.unescape(title_match.group(1))
    normalized = " ".join(title.split()).strip()
    return (normalized or None), redirect_hops


def _get_ssl_expiry(hostname: str) -> str | None:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:
                cert = secure_sock.getpeercert()
    except OSError:
        return None
    except ssl.SSLError:
        return None

    not_after = cert.get("notAfter")
    if not isinstance(not_after, str):
        return None

    try:
        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
    except ValueError:
        return None

    return expiry.replace(tzinfo=timezone.utc).date().isoformat()


def _get_rdap_details(hostname: str) -> dict[str, Any]:
    payload = _fetch_rdap_payload(hostname)
    if not payload:
        return {}

    events = payload.get("events")
    if not isinstance(events, list):
        events = []

    created = _extract_rdap_event(events, "registration")
    expires = _extract_rdap_event(events, "expiration")

    age_days: int | None = None
    if created:
        age_days = max(0, (datetime.now(timezone.utc) - created).days)

    return {
        "registrar": _extract_registrar(payload),
        "domain_created_at": created.date().isoformat() if created else None,
        "domain_expires_at": expires.date().isoformat() if expires else None,
        "domain_age_days": age_days,
    }


def _get_ip_geolocation(ip_address: str) -> dict[str, Any]:
    payload = _safe_get_json(f"https://ipwho.is/{ip_address}", timeout=8)
    if not payload:
        return {}

    if payload.get("success") is False:
        return {}

    city = str(payload.get("city") or "").strip()
    region = str(payload.get("region") or "").strip()
    country = str(payload.get("country") or "").strip()
    location_parts = [part for part in [city, region, country] if part]

    connection = payload.get("connection")
    isp = ""
    if isinstance(connection, dict):
        isp = str(connection.get("isp") or "").strip()

    return {
        "location": ", ".join(location_parts) if location_parts else None,
        "country": country or None,
        "country_code": str(payload.get("country_code") or "").strip() or None,
        "isp": isp or None,
    }


def _collect_url_metadata(url: str, domain: str) -> dict[str, Any]:
    dns_a_records: list[str] = []
    dns_mx_records: list[str] = []
    page_title: str | None = None
    redirect_hops = 0
    rdap_details: dict[str, Any] = {}
    ssl_expiry: str | None = None

    with ThreadPoolExecutor(max_workers=_METADATA_MAX_WORKERS) as executor:
        future_map = {
            executor.submit(_get_dns_a_records, domain): "dns_a",
            executor.submit(_get_dns_mx_records, domain): "dns_mx",
            executor.submit(_fetch_url_content_metadata, url): "content",
            executor.submit(_get_rdap_details, domain): "rdap",
            executor.submit(_get_ssl_expiry, domain): "ssl",
        }

        try:
            for future in as_completed(future_map, timeout=_METADATA_PARALLEL_BUDGET_SECONDS):
                task_name = future_map[future]
                try:
                    result = future.result()
                except Exception:
                    continue

                if task_name == "dns_a" and isinstance(result, list):
                    dns_a_records = [ip for ip in result if isinstance(ip, str)]
                elif task_name == "dns_mx" and isinstance(result, list):
                    dns_mx_records = [mx for mx in result if isinstance(mx, str)]
                elif task_name == "content" and isinstance(result, tuple) and len(result) == 2:
                    page_title = result[0] if isinstance(result[0], str) or result[0] is None else None
                    redirect_hops = result[1] if isinstance(result[1], int) else 0
                elif task_name == "rdap" and isinstance(result, dict):
                    rdap_details = result
                elif task_name == "ssl" and (isinstance(result, str) or result is None):
                    ssl_expiry = result
        except TimeoutError:
            pass

    primary_ip = dns_a_records[0] if dns_a_records else None
    geo_details = _get_ip_geolocation(primary_ip) if primary_ip else {}

    return {
        "ip_address": primary_ip,
        "page_title": page_title,
        "redirect_hops": redirect_hops,
        "registrar": rdap_details.get("registrar"),
        "dns_a": dns_a_records,
        "dns_mx": dns_mx_records,
        "ssl_expiry": ssl_expiry,
        "ssl_valid": bool(ssl_expiry),
        "location": geo_details.get("location"),
        "country": geo_details.get("country"),
        "country_code": geo_details.get("country_code"),
        "isp": geo_details.get("isp"),
        "domain_created_at": rdap_details.get("domain_created_at"),
        "domain_expires_at": rdap_details.get("domain_expires_at"),
        "domain_age_days": rdap_details.get("domain_age_days"),
    }


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

    metadata = _collect_url_metadata(url, domain)

    openphish_result = _openphish_check(url)
    if openphish_result:
        return {"url": url, "domain": domain, "metadata": metadata, **openphish_result}

    vt_result = _vt_domain_check(domain)
    if vt_result:
        return {"url": url, "domain": domain, "metadata": metadata, **vt_result}

    tld_parts = domain.split(".")
    if len(tld_parts) >= 3 and len(tld_parts[0]) > 16:
        return {
            "url": url,
            "domain": domain,
            "metadata": metadata,
            "domain_risk": "medium",
            "reason": "Domain has a suspiciously long subdomain and lacks threat intelligence confirmation.",
        }

    return {
        "url": url,
        "domain": domain,
        "metadata": metadata,
        "domain_risk": "unknown",
        "reason": "No external threat intelligence signals were available for this domain.",
    }


def analyze_claim_urls(claim_text: str) -> list[dict[str, Any]]:
    urls = extract_urls_from_text(claim_text)
    return [analyze_domain_risk(url) for url in urls]
