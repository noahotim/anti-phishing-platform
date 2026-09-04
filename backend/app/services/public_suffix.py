"""Embedded public-suffix list (reduced, security-focused).

Only a curated set of the most common commercial and country TLDs is embedded
so registered-domain extraction stays deterministic and offline.  Any match is
deliberately conservative: for a security product it is safer to treat an
unknown top-level name as part of the registrable domain than the reverse.
"""
PUBLIC_SUFFIXES: set[str] = {
    # Generic
    "com", "net", "org", "io", "co", "ai", "dev", "app", "info", "biz",
    "cloud", "online", "tech", "site", "store", "design", "xyz", "top",
    "club", "space", "website", "live", "life", "tech", "digital", "media",
    "news", "blog", "agency", "global", "group", "ltd", "limited", "llc",
    "works", "world", "systems", "solutions", "support", "services", "pro",
    # Rare/new / often-abused
    "icu", "link", "click", "country", "men", "work", "date", "faith",
    "science", "zip", "mov", "monster", "kim", "wtf", "xin", "loan",
    "racing", "review", "tk", "ml", "ga", "cf", "gq",
    # Country / geo
    "us", "uk", "ca", "de", "fr", "au", "jp", "in", "br", "cn", "ru",
    "mx", "za", "nl", "es", "it", "pl", "se", "no", "fi", "ch", "at",
    "be", "dk", "ie", "nz", "sg", "hk", "my", "eu", "asia", "ar", "cl",
    "co_uk", "com_au", "com_br", "com_mx", "com_tr", "com_my", "com_sg",
    "co_za", "com_sg", "net_au", "org_uk", "gov_uk", "ac_uk",
}


def is_public_suffix(label: str) -> bool:
    """True when a single dot-joined dot-joined label is a known public suffix."""
    return label in PUBLIC_SUFFIXES