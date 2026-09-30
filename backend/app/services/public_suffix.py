"""Embedded public-suffix list (reduced, security-focused).

Only a curated set of the most common commercial and country TLDs is embedded
so registered-domain extraction stays deterministic and offline.  Any match is
deliberately conservative: for a security product it is safer to treat an
unknown top-level name as part of the registrable domain than the reverse.
"""

_RAW_PUBLIC_SUFFIXES: set[str] = {
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
    "ug", "ke", "tz", "rw",
    "co_uk", "com_au", "com_br", "com_mx", "com_tr", "com_my", "com_sg",
    "co_za", "com_sg", "net_au", "org_uk", "gov_uk", "ac_uk",
    # Institutional second-level country domains.  These entries make
    # registrable-domain extraction correct for, for example, sun.ac.ug.
    "ac.ug", "co.ug", "go.ug", "ne.ug", "or.ug", "sc.ug",
    "ac.ke", "co.ke", "go.ke", "ne.ke", "or.ke", "sc.ke",
    "ac.tz", "co.tz", "go.tz", "ne.tz", "or.tz", "sc.tz",
    "ac.za", "co.za", "gov.za", "edu.za",
    "ac.in", "co.in", "gov.in", "edu.in",
    "ac.jp", "co.jp", "go.jp", "ne.jp", "or.jp",
    "ac.uk", "co.uk", "gov.uk", "org.uk", "sch.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
}


def _normalize_suffix(value: str) -> str:
    """Historical entries use underscores for dots; expose dotted suffixes."""
    return value.replace("_", ".").strip().lower().strip(".")


PUBLIC_SUFFIXES: set[str] = {_normalize_suffix(suffix) for suffix in _RAW_PUBLIC_SUFFIXES if suffix}


# Labels commonly used as second-level public-suffix components beneath a
# country-code TLD.  These are used when an explicit multi-label suffix is not
# in the curated set.
STANDARD_SECOND_LEVEL_LABELS: set[str] = {
    "ac", "co", "com", "edu", "gov", "gob", "go", "mobi", "mil", "net",
    "org", "ne", "nom", "or", "sch",
}


# Subset of second-level labels that provide institutional context rather than
# proof of legitimacy on their own.
INSTITUTIONAL_SECOND_LEVEL_LABELS: dict[str, str] = {
    "ac": "academic",
    "edu": "academic",
    "sch": "academic",
    "gov": "government",
    "gob": "government",
    "go": "government",
    "mil": "military",
}


def is_public_suffix(label: str) -> bool:
    """True when a dotted label is a known public suffix."""
    return _normalize_suffix(label) in PUBLIC_SUFFIXES
