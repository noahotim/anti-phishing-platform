"""Low-level URL splitting and hostname analysis.

The product must never trust the human-readable prefix of a URL.  Every
suspicious URL shape (userinfo@host, dotted subdomains, punycode, fragment/query
redirection tricks) is decomposed here so detection logic and the SSRF guard
operate on the *authoritative* hostname only.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import unquote, urlsplit, urlunsplit

from .public_suffix import (
    INSTITUTIONAL_SECOND_LEVEL_LABELS,
    PUBLIC_SUFFIXES,
    STANDARD_SECOND_LEVEL_LABELS,
)

CPUBCLI_OPEN = "\u3002\uFF0E\uFF61"  # ideographic full stop / fullwidth full stop / halfwidth
_HTTP_SCHEME = re.compile(r"^(https?)\Z", re.IGNORECASE)


def _safe_unquote(value: str) -> str:
    """Decode percent escapes without raising on malformed sequences."""
    try:
        return unquote(value or "", encoding="utf-8", errors="replace")
    except Exception:
        return value or ""


def _to_unicode_host(ascii_host: str) -> str:
    try:
        import idna

        return idna.decode(ascii_host, uts46=True)
    except Exception:
        return ascii_host


def strip_userinfo(host: str) -> str:
    """Return host without any userinfo part (e.g. 'user:pass@host' -> 'host')."""
    if "@" in host:
        return host.rsplit("@", 1)[1]
    return host


def normalize_host(host: str) -> str:
    """Lowercase, strip userinfo and trailing dot, keep dots."""
    host = strip_userinfo(host).strip().lower()
    host = host.rstrip(".")
    return host


def normalize_host_ascii(host: str) -> str:
    """Best-effort IDNA → ASCII with the CPUBCLI characters turned into dots."""
    if not host:
        return ""
    for ch in CPUBCLI_OPEN:
        host = host.replace(ch, ".")
    host = normalize_host(host)
    try:
        import idna
        host = idna.encode(host, uts46=True).decode("ascii")
    except Exception:
        host = re.sub(r"[^a-z0-9.\-_]", "", host)
    return host.rstrip(".")


def split_registered_domain(host: str, public_suffixes: Optional[set[str]] = None) -> tuple[str, str]:
    """Return (registered_domain, subdomain).

    Uses an embedded suffix set, including two-label institutional and country
    suffixes, and recognizes common second-level country domains.  This is
    deliberately strict for a security tool: ownership checks operate on the
    registrable domain, never on a bare suffix match.
    """
    host = normalize_host_ascii(host)
    if not host:
        return "", ""
    if _is_ip_or_local(host):
        return host, ""
    labels = host.split(".")
    suffix_set = (public_suffixes if public_suffixes is not None else
                  PUBLIC_SUFFIXES)

    # Longest known public suffix at the end of the hostname.
    suffix_len = 0
    for length in range(min(4, len(labels)), 0, -1):
        candidate = ".".join(labels[-length:])
        if candidate in suffix_set:
            suffix_len = length
            break

    if suffix_len == 0 and len(labels) >= 3:
        second_level = labels[-2]
        top_level = labels[-1]
        if second_level in INSTITUTIONAL_SECOND_LEVEL_LABELS:
            # Generic academic/government/military namespace recognition.
            suffix_len = 2
        elif (len(top_level) == 2
              and second_level in STANDARD_SECOND_LEVEL_LABELS):
            # Generic country second-level domain recognition.
            suffix_len = 2

    if suffix_len == 0:
        if len(labels) >= 2:
            reg = ".".join(labels[-2:])
            sub = ".".join(labels[:-2])
        else:
            reg = host
            sub = ""
    else:
        if len(labels) > suffix_len:
            reg = ".".join(labels[-(suffix_len + 1):])
            sub = ".".join(labels[:-(suffix_len + 1)])
        else:
            # The whole hostname is itself a public suffix.
            reg = host
            sub = ""
    return reg.rstrip("."), sub


_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _is_ip_or_local(host: str) -> bool:
    if host == "localhost":
        return True
    if ":" in host:
        return True
    if _IP_RE.match(host):
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            pass
    return False


@dataclass
class ParsedURL:
    raw: str
    scheme: str = ""
    hostname: str = ""
    port: int | None = None
    path: str = ""
    query: str = ""
    fragment: str = ""
    username: str = ""
    password: str = ""
    registered_domain: str = ""
    subdomain: str = ""
    ascii_host: str = ""
    unicode_host: str = ""
    decoded_path: str = "/"
    decoded_query: str = ""
    is_ip: bool = False
    warnings: list[str] = field(default_factory=list)

    @property
    def tld(self) -> str:
        rd = self.registered_domain
        rd = rd.rstrip(".")
        if "." not in rd:
            return rd
        return rd.rsplit(".", 1)[1]

    def as_dict(self) -> dict:
        return {
            "raw": self.raw,
            "scheme": self.scheme,
            "hostname": self.hostname,
            "port": self.port,
            "path": self.path,
            "query": self.query,
            "fragment": self.fragment,
            "username": self.username,
            "registered_domain": self.registered_domain,
            "subdomain": self.subdomain,
            "ascii_host": self.ascii_host,
            "unicode_host": self.unicode_host,
            "tld": self.tld,
            "is_ip": self.is_ip,
            "decoded_path": self.decoded_path,
            "decoded_query": self.decoded_query,
            "warnings": self.warnings,
        }


def parse_url(url: str) -> ParsedURL:
    """Decompose a user-supplied URL.  Never fetches the network."""
    parts = urlsplit(url.strip())

    if parts.username is not None or parts.password is not None:
        # Rewrite so userinfo is decoded for the userview but the host is kept sane.
        pass

    raw = url.strip()
    scheme = parts.scheme.lower()
    host_raw = parts.hostname or parts.netloc or url.strip()

    parsed = ParsedURL(raw=raw, scheme=scheme)
    parsed.username = unquote(parts.username or "")
    parsed.password = unquote(parts.password or "")
    parsed.port = parts.port
    parsed.path = parts.path or "/"
    parsed.query = parts.query
    parsed.fragment = parts.fragment
    parsed.decoded_path = _safe_unquote(parsed.path)
    parsed.decoded_query = _safe_unquote(parsed.query)

    if raw.startswith("@") or parsed.username:
        parsed.warnings.append("URL contains userinfo authority before host")

    host = normalize_host(host_raw)
    if "@" in host:
        host = strip_userinfo(host)
        parsed.warnings.append("userinfo prefix stripped before analysis")
    parsed.hostname = host
    parsed.ascii_host = normalize_host_ascii(host)
    parsed.unicode_host = _to_unicode_host(parsed.ascii_host)

    if not parsed.ascii_host:
        parsed.warnings.append("unable to derive an ASCII hostname")

    if parsed.ascii_host.startswith("xn--"):
        parsed.warnings.append("host uses IDN/punycode")

    rd, sub = split_registered_domain(parsed.ascii_host)
    parsed.registered_domain = rd
    parsed.subdomain = sub

    # Best-effort IP detection on the ASCII host.
    if _is_ip_or_local(parsed.ascii_host):
        parsed.is_ip = True
        parsed.warnings.append("host is an IP address or local hostname")

    if not _HTTP_SCHEME.match(scheme) if scheme else False:
        parsed.warnings.append("non-http(s) scheme or missing scheme")

    # Common deceptive shapes.
    if re.search(r"(?i)(https?)?://[^/\s]+@[^/\s]+", raw):
        parsed.warnings.append("embedded credentials in URL authority")
    if re.search(r"\.(?:xml|so)$", parsed.registered_domain, re.IGNORECASE):
        parsed.warnings.append("potential XML/SOAP confusion suffix")

    return parsed


def sanitize_url_for_logging(url: str) -> str:
    """Return a log-safe URL with any authority credentials redacted."""
    raw = (url or "").strip()
    if "@" not in raw:
        return raw
    try:
        parts = urlsplit(raw)
        if parts.username is None and parts.password is None and "@" not in (parts.netloc or ""):
            return raw
        host = parts.hostname or ""
        netloc = host
        if parts.port:
            netloc = f"{netloc}:{parts.port}"
        return urlunsplit(
            (
                parts.scheme,
                f"redacted-userinfo@{netloc}" if host else "redacted-userinfo",
                parts.path,
                parts.query,
                parts.fragment,
            )
        )
    except ValueError:
        # Never return a possibly credential-bearing string when parsing fails.
        head, _, _ = raw.rpartition("@")
        return "redacted-userinfo" if head else "redacted-url"


def looks_like_url(text: str) -> bool:
    return bool(
        re.search(r"(?i)(https?://|ww{2}\.|xn--)", text)
        or re.search(r"[a-z0-9-]+(\.[a-z0-9-]+)+", text)
    )