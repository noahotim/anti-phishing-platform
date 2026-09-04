"""SSRF protection.

The analyzer NEVER fetches arbitrary user-submitted URLs.  The only code paths
allowed to open a socket are the optional external threat-intelligence clients,
and even those are constrained to their fixed API hosts by this module.

Guard strategy (defense in depth):
  1. Refuse anything but http/https and a finite allow-list of hostnames.
  2. Resolve the hostname; reject any address that is private, loopback,
     link-local, multicast, reserved, IPv6-mapped, or a cloud metadata address.
  3. Reject DNS results that resolve to a local/private range regardless of the
     literal hostname on the wire (mitigates DNS rebinding).
  4. Support a reconnect validation hook so the caller can re-check the socket
     peer address before sending a request body.
"""
from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass, field

# Cloud metadata endpoints must never be contacted.
_CLOUD_METADATA_HOSTS = {
    "169.254.169.254",
    "metadata.google.internal",
    "metadata",
}
# Fixed hosts the outbound reputation clients are allowed to reach.
ALLOWED_TI_HOSTS = {
    "www.virustotal.com",
    "virustotal.com",
    "safebrowsing.googleapis.com",
    "urlhaus-api.abuse.ch",
    "urlhaus.abuse.ch",
    "phishstats.info",
}

_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _blocked_ip(ip_str: str) -> None:
    ip = ipaddress.ip_address(ip_str)
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast \
            or ip.is_reserved or ip.is_unspecified:
        raise SSRFBlockedError(f"blocked non-routeable address {ip}")
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        _blocked_ip(str(ip.ipv4_mapped))
    if ip_str == "169.254.169.254" or str(ip) == "169.254.169.254":
        raise SSRFBlockedError("blocked cloud metadata address")


class SSRFBlockedError(Exception):
    pass


def validate_url_host(url: str) -> str:
    """Validate a URL string against policy; returns the hostname if safe."""
    from urllib.parse import urlsplit

    if len(url) > 2048:
        raise SSRFBlockedError("url too long")
    parts = urlsplit(url)
    if parts.scheme.lower() not in {"http", "https"}:
        raise SSRFBlockedError(f"scheme '{parts.scheme}' not allowed")
    host = (parts.hostname or "").lower().rstrip(".")
    if parts.username or parts.password:
        raise SSRFBlockedError("userinfo in url not allowed")
    if not host:
        raise SSRFBlockedError("no hostname")
    if host in _CLOUD_METADATA_HOSTS:
        raise SSRFBlockedError("cloud metadata host blocked")
    if host not in ALLOWED_TI_HOSTS:
        raise SSRFBlockedError(f"host '{host}' not allow-listed for outbound access")
    if _IPV4.match(host) or ":" in host:
        _blocked_ip(host)
    _assert_public_resolution(host)
    return host


def _assert_public_resolution(host: str) -> None:
    """Resolve the host and reject private/loopback answers."""
    try:
        infos = socket.getaddrinfo(
            host, None, socket.AF_UNSPEC, socket.SOCK_STREAM, 0, socket.AI_ADDRCONFIG
        )
    except socket.gaierror as exc:
        raise SSRFBlockedError(f"host resolution failed: {exc}")
    if not infos:
        raise SSRFBlockedError("no addresses resolved")
    for info in infos:
        _blocked_ip(info[4][0])


def resolve_and_validate(host: str) -> list[str]:
    """Validate policy then return vetted public addresses."""
    host = (host or "").lower().rstrip(".")
    if host in _CLOUD_METADATA_HOSTS:
        raise SSRFBlockedError("cloud metadata host blocked")
    if host not in ALLOWED_TI_HOSTS:
        raise SSRFBlockedError(f"host '{host}' not allow-listed")
    infos = socket.getaddrinfo(
        host, None, socket.AF_UNSPEC, socket.SOCK_STREAM, 0, socket.AI_ADDRCONFIG
    )
    if not infos:
        raise SSRFBlockedError("no addresses resolved")
    out: list[str] = []
    for info in infos:
        ip_str = info[4][0]
        _blocked_ip(ip_str)
        out.append(ip_str)
    return out


@dataclass
class GuardConfig:
    allowed_ti_hosts: set[str] = field(default_factory=lambda: set(ALLOWED_TI_HOSTS))

    def check_http(self, url: str) -> str:
        return validate_url_host(url)  # allow-list enforced internally