"""Domain normalization facade.

Everything the detection engine compares goes through this module so we never
compare a single raw string.  Comparison operates on normalized, IDNA-processed,
confusable-folded forms — DataFrame of the trusted domain list is normalized in
the same canonical space.
"""
from __future__ import annotations

import re
import urllib.parse

import idna

from . import homoglyph


def normalize_domain_identity(domain: str) -> str:
    """Canonical domain identity used for registering trusted domains.

    NFKC → lowercase → strip userinfo/trailing dot → IDNA ToASCII.
    """
    d = domain.strip()
    if "@" in d:
        d = d.rsplit("@", 1)[1]
    d = homoglyph.nfkc(d).strip().lower().rstrip(".")
    return d


def to_ascii(domain: str) -> str:
    """IDNA ToASCII (UTS-46 transitional) with graceful degradation."""
    for ch in "\u3002\uff0e\uff61":
        domain = domain.replace(ch, ".")
    d = domain.strip().lower().rstrip(".")
    if not d:
        return ""
    try:
        return idna.encode(d, uts46=True).decode("ascii").rstrip(".")
    except (idna.IDNAError, UnicodeError, IndexError):
        return re.sub(r"[^a-z0-9.\-_]", "", d).rstrip(".")


def domain_from_input(value: str) -> str:
    """Pull the bare hostname out of whatever a user pasted into a domain field.

    People paste full URLs ('https://example.com/path?q=1') into fields that
    expect 'example.com'.  Without this, to_ascii's fallback regex strips the
    ':' and '/' and registers a garbage host like 'httpsexample.com', so the
    whitelist entry never matches the real site.  Handles scheme, path, port
    and userinfo; leaves bare domains untouched.
    """
    d = (value or "").strip()
    if not d:
        return ""
    if "://" in d:
        try:
            parsed = urllib.parse.urlparse(d)
            if parsed.hostname:
                return parsed.hostname.lower().rstrip(".")
        except ValueError:
            pass
    # No scheme: strip path, credentials and port by hand.
    d = d.split("/", 1)[0]
    d = d.split("?", 1)[0].split("#", 1)[0]
    d = d.rsplit("@", 1)[-1]
    if d.startswith("["):
        d = d[1:].split("]", 1)[0]
    elif d.count(":") == 1:
        d = d.split(":", 1)[0]
    return d.strip().lower().rstrip(".")


def to_unicode(domain: str) -> str:
    """IDNA ToUnicode (UTS-46)."""
    try:
        return idna.decode(domain, uts46=True)
    except (idna.IDNAError, UnicodeError, ValueError):
        return domain


def fold_for_similarity(domain: str) -> str:
    """ASCII + confusable-folded form used for visual-similarity scoring."""
    ascii_d = to_ascii(domain)
    return homoglyph.fold_confusable(ascii_d).lower()


def fold_for_similarity_unicode(domain: str) -> str:
    """Confusable fold WITHOUT IDNA conversion, for unicode homoglyph checks.

    Example: trusted 'example.com' vs 'еxample.com' (Cyrillic е).  The fold
    produces 'example.com' in both cases, catching the homoglyph even without
    punycode.
    """
    return homoglyph.fold_confusable(homoglyph.nfkc(domain).casefold().lower())


def presentation_identity(domain: str) -> str:
    """A visually-rendered identity for humans to review."""
    return homoglyph.fold_confusable(domain)