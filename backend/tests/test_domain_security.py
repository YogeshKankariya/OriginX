from app.config import settings
from app.services.domain_security import analyze_claim_urls, analyze_domain_risk, extract_urls_from_text, _get_rdap_bootstrap


class _FakeResponse:
    def __init__(self, payload: dict, status_code: int = 200):
        self._payload = payload
        self.status_code = status_code

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError("HTTP error")

    def json(self) -> dict:
        return self._payload


class _FakeTextResponse:
    def __init__(self, text: str, status_code: int = 200):
        self.text = text
        self.status_code = status_code

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError("HTTP error")


def test_extract_urls_from_text() -> None:
    urls = extract_urls_from_text("See https://example.com and http://test.org/path")
    assert len(urls) == 2


def test_analyze_domain_risk_with_virustotal(monkeypatch) -> None:
    monkeypatch.setattr(settings, "VIRUSTOTAL_API_KEY", "demo-key")
    monkeypatch.setattr(settings, "OPENPHISH_FEED_URL", "")

    def _fake_get(*args, **kwargs):
        return _FakeResponse(
            {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 2,
                            "suspicious": 1,
                        }
                    }
                }
            }
        )

    monkeypatch.setattr("app.services.domain_security.requests.get", _fake_get)

    result = analyze_domain_risk("https://bad-domain.example/login")

    assert result["domain_risk"] == "high"
    assert "VirusTotal" in result["reason"]


def test_analyze_domain_risk_with_openphish(monkeypatch) -> None:
    monkeypatch.setattr(settings, "VIRUSTOTAL_API_KEY", "")
    monkeypatch.setattr(settings, "OPENPHISH_FEED_URL", "https://openphish.example/feed.txt")

    def _fake_get(url, timeout=15, **kwargs):
        if "openphish" in url:
            return _FakeTextResponse("https://phish.example/signin\n")
        return _FakeResponse({})

    monkeypatch.setattr("app.services.domain_security.requests.get", _fake_get)

    result = analyze_domain_risk("https://phish.example/signin")

    assert result["domain_risk"] == "high"
    assert "OpenPhish" in result["reason"]


def test_analyze_claim_urls_empty() -> None:
    assert analyze_claim_urls("no links here") == []


def test_analyze_domain_risk_resolves_rdap_provider(monkeypatch) -> None:
    monkeypatch.setattr(settings, "VIRUSTOTAL_API_KEY", "")
    monkeypatch.setattr(settings, "OPENPHISH_FEED_URL", "")
    _get_rdap_bootstrap.cache_clear()

    def _fake_get(url, params=None, timeout=10, **kwargs):
        if url == "https://data.iana.org/rdap/dns.json":
            return _FakeResponse({
                "services": [
                    [["com"], ["https://rdap.verisign.com/com/v1"]],
                ]
            })
        if url == "https://rdap.verisign.com/com/v1/domain/google.com":
            return _FakeResponse({
                "entities": [
                    {
                        "roles": ["registrar"],
                        "vcardArray": ["vcard", [["fn", {}, "text", "MarkMonitor Inc."]]],
                    }
                ],
                "events": [
                    {"eventAction": "registration", "eventDate": "1997-09-15T04:00:00Z"},
                    {"eventAction": "expiration", "eventDate": "2028-09-14T04:00:00Z"},
                ],
            })
        return _FakeResponse({})

    monkeypatch.setattr("app.services.domain_security.requests.get", _fake_get)
    monkeypatch.setattr("app.services.domain_security._get_dns_a_records", lambda _hostname: [])
    monkeypatch.setattr("app.services.domain_security._get_dns_mx_records", lambda _hostname: [])
    monkeypatch.setattr("app.services.domain_security._fetch_url_content_metadata", lambda _url: (None, 0))
    monkeypatch.setattr("app.services.domain_security._get_ssl_expiry", lambda _hostname: None)

    result = analyze_domain_risk("https://google.com")

    assert result["metadata"]["registrar"] == "MarkMonitor Inc."
    assert result["metadata"]["domain_created_at"] == "1997-09-15"
    assert result["metadata"]["domain_expires_at"] == "2028-09-14"
    assert isinstance(result["metadata"]["domain_age_days"], int)
    assert result["metadata"]["domain_age_days"] > 0
