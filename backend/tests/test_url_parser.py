"""Tests for the URL parser."""
from __future__ import annotations

from app.services.url_parser import parse_url, split_registered_domain, normalize_host_ascii


def test_parse_simple_url():
    p = parse_url("https://www.example.com/path?q=1#frag")
    assert p.scheme == "https"
    assert p.hostname == "www.example.com"
    assert p.registered_domain == "example.com"
    assert p.subdomain == "www"
    assert p.path == "/path"
    assert p.query == "q=1"
    assert p.fragment == "frag"


def test_parse_userinfo_deception():
    p = parse_url("https://trusted.com@malicious.com/steal")
    assert p.hostname == "malicious.com"
    assert p.username == "trusted.com"
    assert p.registered_domain == "malicious.com"
    assert p.warnings  # userinfo/credential warnings present


def test_parse_misleading_subdomain():
    p = parse_url("https://trusted.com.malicious.com/")
    assert p.registered_domain == "malicious.com"
    assert p.subdomain == "trusted.com"


def test_parse_redirect_query():
    p = parse_url("https://malicious.com/?redirect=https://trusted.com")
    assert p.registered_domain == "malicious.com"
    assert "redirect" in p.query


def test_split_registered_domain():
    assert split_registered_domain("example.com") == ("example.com", "")
    assert split_registered_domain("www.example.com") == ("example.com", "www")
    assert split_registered_domain("a.b.example.co.uk") == ("example.co.uk", "a.b")
    assert split_registered_domain("evil.app") == ("evil.app", "")
    assert split_registered_domain("weird.unknowntld") == ("weird.unknowntld", "")


def test_ipv4_host():
    p = parse_url("http://192.168.1.1/x")
    assert p.is_ip is True


def test_non_http_scheme():
    p = parse_url("ftp://example.org/file")
    assert p.scheme == "ftp"
    assert p.warnings  # non-http warning


def test_https_scheme_no_warning():
    p = parse_url("https://example.org/")
    assert "non-http" not in " ".join(p.warnings)


def test_idn_host():
    p = parse_url("https://еxample.com/")
    assert p.ascii_host.startswith("xn--")
    assert "punycode" in " ".join(p.warnings).lower() or "xn--" in p.ascii_host


def test_punycode_real():
    assert normalize_host_ascii("еxample.com") == "xn--xample-2of.com"