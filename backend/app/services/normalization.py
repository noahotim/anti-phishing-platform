"""Domain normalization facade.

Everything the detection engine compares goes through this module so we never
compare a single raw string.  Comparison operates on normalized, IDNA-processed,
confusable-folded forms — DataFrame of the trusted domain list is normalized in
the same canonical space.
"""
from __future__ import annotations

import re

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