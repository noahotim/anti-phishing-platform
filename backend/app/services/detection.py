"""Multi-layer evidence generation for URL analysis.

The layers are deliberately ordered:

1. URL normalization (handled by :mod:`url_parser`).
2. Registrable-domain extraction (handled by :mod:`url_parser`).
3. Reputation / threat-intelligence interpretation.
4. Domain intelligence: exact trust, institutional namespace, and neutral context.
5. Brand and impersonation analysis, restricted to plausible candidates.
6. URL-attack analysis: userinfo, IP hosts, credential paths, redirects, encoding.
7. Structured evidence output for correlation and scoring.

Unknown is deliberately represented as the absence of threat evidence.  In
particular, ``tld_changed`` is only meaningful when it accompanies an actual
impersonation candidate.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlsplit

from . import normalization
from .evidence import (
    CONTEXTUAL,
    MEDIUM,
    STRONG,
    WEAK,
    EvidenceItem,
)
from .homoglyph import mixed_script_warning
from .public_suffix import (
    INSTITUTIONAL_SECOND_LEVEL_LABELS,
    PUBLIC_SUFFIXES,
)
from .similarity import (
    SUSPICIOUS_TLDS,
    SimilarityEngine,
    damerau_levenshtein,
)
from .url_parser import ParsedURL, split_registered_domain

_CREDENTIAL_PATH_TOKENS = {
    "login",
    "log-in",
    "signin",
    "sign-in",
    "auth",
    "authenticate",
    "verify",
    "verification",
    "confirm",
    "confirmation",
    "validate",
    "validation",
    "secure",
    "security",
    "account",
    "accounts",
    "update",
    "recover",
    "recovery",
    "reset",
    "password",
    "passcode",
    "credential",
    "credentials",
    "2fa",
    "otp",
    "pin",
}

_REDIRECT_PARAMETERS = {
    "redirect",
    "redirect_url",
    "redirecturi",
    "url",
    "next",
    "return",
    "returnurl",
    "continue",
    "dest",
    "destination",
}

_TRUST_TERMS = {
    "university",
    "college",
    "school",
    "institute",
    "academy",
    "campus",
    "student",
    "faculty",
    "bank",
    "banking",
    "government",
    "ministry",
}

_GENERIC_HOST_TOKENS = {
    "www",
    "web",
    "mail",
    "email",
    "portal",
    "login",
    "secure",
    "account",
    "support",
    "help",
    "info",
    "admin",
    "app",
    "api",
    "dev",
    "test",
    "demo",
    "staging",
    "cdn",
    "static",
    "blog",
    "news",
}

_ENCODED_SEQUENCE = re.compile(r"%[0-9A-Fa-f]{2}")
_DANGEROUS_ENCODING = re.compile(r"%(?:2F|3A|40|5C|3F|23|26|3D)", re.IGNORECASE)


@dataclass
class TrustedBrand:
    domain: str
    registrable: str
    name: str
    suffix: str
    critical: bool


@dataclass
class DetectionOutput:
    items: list[EvidenceItem] = field(default_factory=list)
    matched_domain: str | None = None
    protected_identity: str | None = None
    legacy_signals: dict = field(default_factory=dict)


def _effective_suffix_length(registered: str) -> int:
    labels = registered.split(".") if registered else []
    for length in range(min(4, len(labels)), 0, -1):
        if ".".join(labels[-length:]) in PUBLIC_SUFFIXES:
            return length
    if len(labels) >= 3:
        second_level = labels[-2]
        top_level = labels[-1]
        if second_level in INSTITUTIONAL_SECOND_LEVEL_LABELS:
            return 2
        if len(top_level) == 2 and second_level in {
            "ac", "co", "com", "edu", "gov", "gob", "go", "mobi", "mil",
            "net", "org", "ne", "nom", "or", "sch",
        }:
            return 2
    return 1 if len(labels) >= 2 else 0


def _registrable_name_and_suffix(registered: str) -> tuple[str, str]:
    labels = registered.split(".") if registered else []
    suffix_len = _effective_suffix_length(registered)
    if not labels or suffix_len <= 0 or len(labels) <= suffix_len:
        return "", registered
    name = ".".join(labels[:-suffix_len])
    suffix = ".".join(labels[-suffix_len:])
    return name, suffix


def build_trusted_brands(rows: list[dict]) -> list[TrustedBrand]:
    brands: list[TrustedBrand] = []
    for row in rows or []:
        domain = normalization.to_ascii(row.get("normalized_domain") or "")
        if not domain or "." not in domain:
            continue
        registered, _ = split_registered_domain(domain)
        registered = registered or domain
        name, suffix = _registrable_name_and_suffix(registered)
        brands.append(
            TrustedBrand(
                domain=domain,
                registrable=registered,
                name=name,
                suffix=suffix,
                critical=bool(row.get("is_critical") or row.get("critical")),
            )
        )
    return brands


def _fold(value: str) -> str:
    return normalization.fold_for_similarity_unicode(value or "")


def _split_tokens(value: str) -> list[str]:
    return [token for token in re.split(r"[^a-z0-9]+", (value or "").lower()) if token]


def _shortlist_brands(
    candidate_host: str,
    candidate_registered: str,
    candidate_unicode: str,
    brands: list[TrustedBrand],
) -> list[TrustedBrand]:
    """Narrow trusted domains before any expensive comparison.

    The goal is to compare only plausible impersonation targets.  Generic,
    unrelated trusted domains are not returned merely because every unknown
    host must be checked against something.
    """
    if not candidate_registered:
        return []
    candidate_name, _ = _registrable_name_and_suffix(candidate_registered)
    candidate_first = candidate_registered.split(".")[0]
    candidate_fold = _fold(candidate_registered)
    unicode_registered = normalization.to_unicode(candidate_unicode or candidate_registered)
    candidate_unicode_fold = _fold(unicode_registered)
    candidate_name_fold = _fold(candidate_name)
    candidate_tokens = set(_split_tokens(candidate_registered.replace("-", " ")))

    shortlisted: list[TrustedBrand] = []
    for brand in brands:
        if candidate_registered == brand.registrable:
            # Exact registrable-domain equality is handled as trust/ownership,
            # not impersonation.
            continue
        brand_fold = _fold(brand.registrable)
        brand_name_fold = _fold(brand.name)
        if candidate_fold == brand_fold and candidate_fold:
            shortlisted.append(brand)
            continue
        if candidate_unicode_fold == brand_fold and candidate_unicode_fold:
            shortlisted.append(brand)
            continue
        if brand.registrable in candidate_host:
            index = candidate_host.find(brand.registrable)
            after = candidate_host[index + len(brand.registrable):]
            before = candidate_host[:index]
            if after.startswith(".") or (after == "" and before):
                shortlisted.append(brand)
                continue
        if brand.name and brand.name in candidate_name:
            index = candidate_name.find(brand.name)
            before = candidate_name[:index]
            after = candidate_name[index + len(brand.name):]
            # A shared substring is only meaningful at a token boundary.
            if before.endswith(("-", "_", ".")) or after.startswith(("-", "_", ".")) or after == "" or before == "":
                shortlisted.append(brand)
                continue
        if not brand.name or not candidate_name:
            continue
        # Changed-TLD comparison for the same registrable name.
        if candidate_name_fold == brand_name_fold and candidate_name_fold:
            shortlisted.append(brand)
            continue
        # Close lexical variants: same initial folded character, similar length,
        # and either a shared token or a small length difference.
        if (
            candidate_name_fold
            and brand_name_fold
            and (candidate_name_fold[0] == brand_name_fold[0] or candidate_unicode_fold[:1] == brand_name_fold[:1])
            and abs(len(candidate_name) - len(brand.name)) <= 2
            and (
                candidate_tokens & set(_split_tokens(brand.name))
                or len(candidate_name) >= 4
            )
        ):
            shortlisted.append(brand)
    return shortlisted


def _embedded_institutional_identity(labels: list[str]) -> tuple[str, str, str] | None:
    """Find a complete institutional identity embedded in hostname labels.

    For example, ``sun.ac.ug.attacker-example.com`` contains the identity
    ``sun.ac.ug`` even though another domain owns the URL.  This uses only the
    generic namespace shape; it does not contain a list of institutions.
    """
    for i in range(len(labels) - 2):
        core = labels[i].lower()
        second = labels[i + 1].lower()
        top = labels[i + 2].lower()
        namespace = INSTITUTIONAL_SECOND_LEVEL_LABELS.get(second)
        if not namespace:
            continue
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])?", core):
            continue
        if len(core) < 3 or core in _GENERIC_HOST_TOKENS or second in {core, top}:
            continue
        if not re.fullmatch(r"[a-z0-9-]{2,63}", top):
            continue
        return f"{core}.{second}.{top}", namespace, core
    return None


def _institutional_context(host: str, registered: str, items: list[EvidenceItem]) -> None:
    labels = host.split(".") if host else []
    if len(labels) >= 3:
        namespace = INSTITUTIONAL_SECOND_LEVEL_LABELS.get(labels[-2].lower())
        if namespace:
            items.append(
                EvidenceItem(
                    name=f"institutional_{namespace}_namespace",
                    category=CONTEXTUAL,
                    explanation=(
                        f"The domain uses an institutional {namespace} namespace. "
                        "That is context only; it does not prove the site is safe."
                    ),
                    details={"namespace": labels[-2].lower(), "type": namespace},
                )
            )


def _reputation_items(ti_summary: dict, items: list[EvidenceItem]) -> None:
    if ti_summary.get("malicious"):
        return
    if ti_summary.get("benign"):
        items.append(
            EvidenceItem(
                name="reputation_verified_benign",
                category=CONTEXTUAL,
                explanation="Threat intelligence reports no malicious verdict for this URL.",
            )
        )
    else:
        items.append(
            EvidenceItem(
                name="no_reputation_data",
                category=CONTEXTUAL,
                explanation="No reputation data was available; absence of reputation is not evidence of safety.",
            )
        )
    if ti_summary.get("errors"):
        items.append(
            EvidenceItem(
                name="threat_intel_error",
                category=CONTEXTUAL,
                explanation="A threat-intelligence provider was unavailable during this check.",
                details={"errors": list(ti_summary.get("errors") or [])[:3]},
            )
        )


def _host_context_items(parsed: ParsedURL, items: list[EvidenceItem]) -> None:
    if parsed.scheme == "https":
        items.append(
            EvidenceItem(
                name="secure_scheme",
                category=CONTEXTUAL,
                explanation="The URL uses HTTPS.",
            )
        )
    elif parsed.scheme == "http":
        items.append(
            EvidenceItem(
                name="unencrypted_scheme",
                category=CONTEXTUAL,
                explanation="The URL uses unencrypted HTTP.",
            )
        )
    elif parsed.scheme:
        items.append(
            EvidenceItem(
                name="non_http_scheme",
                category=WEAK,
                weight=3,
                explanation=f"The URL uses the unusual {parsed.scheme} scheme.",
            )
        )
    if parsed.registered_domain and not parsed.is_ip:
        items.append(
            EvidenceItem(
                name="valid_domain_structure",
                category=CONTEXTUAL,
                explanation="The hostname has a valid registrable-domain structure.",
            )
        )
    if parsed.is_ip:
        items.append(
            EvidenceItem(
                name="private_network_host" if _is_private_ip(parsed.ascii_host) else "ip_host",
                category=CONTEXTUAL,
                explanation="The host is an IP address rather than a registered domain name.",
            )
        )
    tld = (parsed.tld or "").lower()
    if tld and tld not in SUSPICIOUS_TLDS:
        items.append(
            EvidenceItem(
                name="normal_tld",
                category=CONTEXTUAL,
                explanation=f"The .{tld} namespace is not itself a high-abuse TLD.",
            )
        )


def _is_private_ip(host: str) -> bool:
    try:
        import ipaddress

        address = ipaddress.ip_address(host)
        return address.is_private or address.is_loopback or address.is_link_local
    except ValueError:
        return host.lower() == "localhost"


def _brand_items(
    parsed: ParsedURL,
    candidate_registered: str,
    candidate_name: str,
    candidate_suffix: str,
    brand: TrustedBrand,
    output: DetectionOutput,
) -> None:
    """Generate impersonation evidence for one plausible trusted target."""
    def remember(domain: str | None) -> None:
        if domain and output.matched_domain is None:
            output.matched_domain = domain

    engine = SimilarityEngine([brand.domain])
    finding = engine.best_finding(parsed.ascii_host or candidate_registered)
    if finding is None:
        return
    if finding.fold_match and candidate_registered != brand.registrable:
        output.items.append(
            EvidenceItem(
                name="confirmed_homograph",
                category=STRONG,
                weight=40 if candidate_registered.startswith("xn--") else 45,
                explanation=(
                    f"The domain visually impersonates {brand.domain} using confusable characters."
                ),
                matched_domain=brand.domain,
                details={"character_ops": finding.char_ops[:4]} if finding.char_ops else {},
            )
        )
        if candidate_registered.startswith("xn--"):
            output.items.append(
                EvidenceItem(
                    name="punycode_impersonation_marker",
                    category=CONTEXTUAL,
                    explanation="The impersonating hostname uses punycode encoding.",
                    matched_domain=brand.domain,
                )
            )
        remember(brand.domain)
        return
    brand_name, _ = _registrable_name_and_suffix(brand.registrable)
    candidate_name_fold = _fold(candidate_name)
    brand_name_fold = _fold(brand_name)
    host_norm = (parsed.ascii_host or "").lower()

    # Exact folded identity under a different registered domain is handled
    # above as a homograph; continue with structural impersonation checks.
    # Full-domain embedding under another registrable domain.
    if host_norm and brand.registrable in host_norm:
        index = host_norm.find(brand.registrable)
        after = host_norm[index + len(brand.registrable):]
        if after.startswith(".") or (after == "" and host_norm[:index]):
            output.items.append(
                EvidenceItem(
                    name="deceptive_subdomain",
                    category=STRONG,
                    weight=35,
                    explanation=(
                        f"The hostname embeds {brand.domain} as a subdomain, but the "
                        f"registrable domain is {candidate_registered}."
                    ),
                    matched_domain=brand.domain,
                )
            )
            remember(brand.domain)
            # A complete embedding already answers the ownership question.
            return

    # Exact registrable name with a changed suffix.  This only becomes
    # suspicious with an impersonation finding; a normal alternate TLD remains
    # contextual.
    if candidate_name_fold and candidate_name_fold == brand_name_fold:
        if candidate_suffix != brand.suffix:
            if candidate_suffix.lower() in SUSPICIOUS_TLDS:
                output.items.append(
                    EvidenceItem(
                        name="brand_similarity",
                        category=MEDIUM,
                        weight=25,
                        explanation=(
                            f"The registrable name exactly matches {brand.domain}, but uses "
                            f"the high-abuse .{candidate_suffix} namespace."
                        ),
                        matched_domain=brand.domain,
                    )
                )
                output.items.append(
                    EvidenceItem(
                        name="high_risk_namespace",
                        category=MEDIUM,
                        weight=15,
                        explanation=(
                            f"The .{candidate_suffix} namespace is frequently abused for phishing."
                        ),
                        matched_domain=brand.domain,
                    )
                )
            else:
                output.items.append(
                    EvidenceItem(
                        name="cross_tld_same_brand",
                        category=CONTEXTUAL,
                        explanation=(
                            f"The registrable name matches {brand.domain}, but it uses a "
                            f"different, normal TLD. A changed TLD alone is not deception."
                        ),
                        matched_domain=brand.domain,
                    )
                )
            remember(brand.domain)
        return

    # Punycode plus a close resemblance is impersonation rather than encoding.
    if candidate_registered.startswith("xn--") and brand_name:
        distance = damerau_levenshtein(candidate_name_fold, brand_name_fold)
        if distance <= 2 and max(len(candidate_name_fold), len(brand_name_fold)) >= 4:
            output.items.append(
                EvidenceItem(
                    name="punycode_impersonation",
                    category=STRONG,
                    weight=40,
                    explanation=(
                        f"The punycode hostname closely resembles {brand.domain}."
                    ),
                    matched_domain=brand.domain,
                )
            )
            remember(brand.domain)
            return

    # Close typo, including transposition, insertion, deletion, substitution.
    ascii_distance = damerau_levenshtein(candidate_name or "", brand_name or "")
    fold_distance = damerau_levenshtein(candidate_name_fold, brand_name_fold)
    distance = min(ascii_distance, fold_distance)
    longest = max(len(candidate_name_fold), len(brand_name_fold), 1)
    if distance <= 2 and longest >= 4:
        output.items.append(
            EvidenceItem(
                name="very_close_typosquat",
                category=STRONG,
                weight=40,
                explanation=(
                    f"The registrable name is within {distance} character change(s) of {brand.domain}."
                ),
                matched_domain=brand.domain,
                details={"edit_distance": distance},
            )
        )
        remember(brand.domain)
        return
    if 3 <= distance <= 4 and longest >= 6 and candidate_suffix == brand.suffix:
        output.items.append(
            EvidenceItem(
                name="brand_similarity",
                category=MEDIUM,
                weight=25,
                explanation=(
                    f"The registrable name is lexically similar to {brand.domain}."
                ),
                matched_domain=brand.domain,
                details={"edit_distance": distance},
            )
        )
        remember(brand.domain)

    # Hyphenated brand compounds, with and without a credential/trust modifier.
    brand_label = brand.registrable.split(".")[0]
    candidate_first = candidate_registered.split(".")[0]
    if brand_label and candidate_first.startswith(brand_label + "-"):
        remainder = candidate_first[len(brand_label) + 1:]
        modifier_tokens = set(_split_tokens(remainder))
        output.items.append(
            EvidenceItem(
                name="brand_prefix",
                category=MEDIUM,
                weight=20,
                explanation=(
                    f"The hostname prefixes the recognized name from {brand.domain} "
                    f"with {remainder}."
                ),
                matched_domain=brand.domain,
            )
        )
        if modifier_tokens & (_CREDENTIAL_PATH_TOKENS | _TRUST_TERMS):
            output.items.append(
                EvidenceItem(
                    name="brand_compound_modifier",
                    category=MEDIUM,
                    weight=20,
                    explanation=(
                        "The added hostname modifier uses a credential, security, or "
                        "institutional trust word."
                    ),
                    matched_domain=brand.domain,
                )
            )
        remember(brand.domain)

    # Brand embedded as the terminal run without a dot boundary.
    if (
        brand_name
        and candidate_name != brand_name
        and candidate_name.endswith(brand_name)
        and len(candidate_name) > len(brand_name)
        and longest >= 6
    ):
        output.items.append(
            EvidenceItem(
                name="brand_embedded",
                category=MEDIUM,
                weight=20,
                explanation=(
                    f"The hostname ends with the recognized name from {brand.domain} "
                    "without a domain boundary."
                ),
                matched_domain=brand.domain,
            )
        )
        if not any(item.category == MEDIUM and item.name == "brand_similarity" for item in output.items):
            output.items.append(
                EvidenceItem(
                    name="brand_similarity",
                    category=MEDIUM,
                    weight=25,
                    explanation=(
                        f"The complete hostname is lexically similar to {brand.domain}."
                    ),
                    matched_domain=brand.domain,
                )
            )
        remember(brand.domain)

    # A recognized brand token embedded in the candidate is supporting evidence.
    if (
        output.matched_domain is None
        and brand_name
        and len(brand_name) >= 4
        and brand_name not in _GENERIC_HOST_TOKENS
        and brand_name in _split_tokens(candidate_name)
        and candidate_name != brand_name
    ):
        output.items.append(
            EvidenceItem(
                name="brand_token_match",
                category=MEDIUM,
                weight=25,
                explanation=(
                    f"The hostname contains the recognized name from {brand.domain}."
                ),
                matched_domain=brand.domain,
            )
        )
        remember(brand.domain)

    # Keyword hits are only meaningful once a plausible brand has been found.
    if finding.keyword_hits:
        output.items.append(
            EvidenceItem(
                name="login_keyword",
                category=WEAK,
                weight=3,
                explanation=(
                    "The hostname contains a credential/security keyword alongside a "
                    "recognized brand candidate."
                ),
                matched_domain=brand.domain,
                details={"keywords": finding.keyword_hits},
            )
        )
    # A brand in the path is only meaningful once it is paired with the same
    # brand in the hostname.
    brand_base = brand.registrable.split(".")[0]
    if brand_base and len(brand_base) >= 4 and brand_base in {
        token for token in _split_tokens(parsed.decoded_path)
    }:
        output.items.append(
            EvidenceItem(
                name="brand_in_path",
                category=MEDIUM,
                weight=10,
                explanation=(
                    f"The URL path repeats the recognized name from {brand.domain}."
                ),
                matched_domain=brand.domain,
            )
        )
    # A critical brand raises confidence in an already-scored impersonation
    # finding, without letting the same typo count twice.
    if brand.critical and any(
        item.category in (STRONG, MEDIUM)
        and item.matched_domain == brand.domain
        and item.name
        in {
            "very_close_typosquat",
            "brand_similarity",
            "brand_prefix",
            "brand_embedded",
            "brand_token_match",
            "brand_compound_modifier",
            "deceptive_subdomain",
            "confirmed_homograph",
            "punycode_impersonation",
        }
        for item in output.items
    ):
        output.items.append(
            EvidenceItem(
                name="critical_brand_match",
                category=MEDIUM,
                weight=15,
                explanation=(
                    f"The impersonated {brand.domain} is marked as a critical brand."
                ),
                matched_domain=brand.domain,
            )
        )


def summarize_threat_intel(verdicts: list[dict]) -> dict:
    """Interpret provider verdicts as reputation evidence, not reputation absence."""
    malicious: list[dict] = []
    benign = False
    errors: list[str] = []
    for verdict in verdicts or []:
        name = str(verdict.get("verdict", "UNKNOWN")).upper()
        if name == "MALICIOUS":
            malicious.append(verdict)
        elif name == "BENIGN":
            benign = True
        if verdict.get("error"):
            errors.append(f"{verdict.get('provider', 'provider')}: {verdict.get('error')}")
    return {"malicious": malicious, "benign": benign and not malicious, "errors": errors}


def _credential_path_tokens(parsed: ParsedURL) -> set[str]:
    tokens: set[str] = set()
    for segment in (parsed.decoded_path or "").split("/"):
        tokens.update(_split_tokens(segment))
    return tokens


def _host_has_attack(items: list[EvidenceItem]) -> bool:
    return any(
        item.category in (STRONG, MEDIUM)
        and item.name
        not in {
            "brand_in_path",
            "external_redirect_target",
            "encoded_obfuscation",
            "tld_mismatch",
        }
        for item in items
    )


def _url_attack_items(parsed: ParsedURL, raw_url: str, output: DetectionOutput) -> None:
    path_tokens = _credential_path_tokens(parsed)
    credential_path = bool(path_tokens & _CREDENTIAL_PATH_TOKENS)

    if parsed.username:
        output.items.append(
            EvidenceItem(
                name="credential_userinfo",
                category=STRONG,
                weight=30,
                explanation=(
                    f"The URL places credentials before the host, but the authoritative "
                    f"host is {parsed.registered_domain or parsed.ascii_host}."
                ),
            )
        )
        userinfo_host = (parsed.username or "").lower().rstrip(".")
        if "." in userinfo_host:
            user_registered, _ = split_registered_domain(userinfo_host)
            if user_registered and user_registered != (parsed.registered_domain or ""):
                output.items.append(
                    EvidenceItem(
                        name="credential_brand_decoy",
                        category=MEDIUM,
                        weight=15,
                        explanation=(
                            "The credential prefix looks like a different domain from the "
                            "authoritative host."
                        ),
                    )
                )
        output.legacy_signals["userinfo_present"] = True
    else:
        output.legacy_signals["userinfo_present"] = False

    composite_host = _host_has_attack(output.items)
    suspicious_domain = composite_host or parsed.is_ip
    if credential_path:
        if parsed.is_ip:
            output.items.append(
                EvidenceItem(
                    name="ip_host_with_credential",
                    category=MEDIUM,
                    weight=20,
                    explanation=(
                        "An IP-address host is combined with a credential-related path."
                    ),
                )
            )
        elif suspicious_domain:
            output.items.append(
                EvidenceItem(
                    name="credential_path_with_suspicious_domain",
                    category=MEDIUM,
                    weight=15,
                    explanation=(
                        "A credential-related path is combined with a suspicious hostname."
                    ),
                )
            )
        else:
            output.items.append(
                EvidenceItem(
                    name="login_keyword",
                    category=WEAK,
                    weight=3,
                    explanation=(
                        "The URL path contains a credential-related word. Paths alone "
                        "do not establish phishing."
                    ),
                )
            )
        output.legacy_signals["credential_path"] = True
    else:
        output.legacy_signals["credential_path"] = bool(credential_path)

    try:
        query_pairs = parse_qsl(parsed.query or "", keep_blank_values=True)
    except ValueError:
        query_pairs = []
    redirect_seen = False
    external_redirect = False
    for key, value in query_pairs:
        if key.lower() not in _REDIRECT_PARAMETERS:
            continue
        redirect_seen = True
        nested_registered = ""
        nested = (value or "").strip()
        if nested.lower().startswith(("http://", "https://", "//")):
            try:
                nested_host = urlsplit(nested).hostname or ""
                nested_registered, _ = split_registered_domain(nested_host)
            except ValueError:
                nested_registered = ""
        if nested_registered and nested_registered != (parsed.registered_domain or ""):
            external_redirect = True
            output.items.append(
                EvidenceItem(
                    name="external_redirect_target",
                    category=MEDIUM,
                    weight=10,
                    explanation=(
                        f"The {key} parameter points to a different registrable domain, "
                        f"{nested_registered}."
                    ),
                    details={"parameter": key, "target": nested_registered},
                )
            )
    if redirect_seen and not external_redirect:
        output.items.append(
            EvidenceItem(
                name="redirect_parameter",
                category=WEAK,
                weight=3,
                explanation="The URL contains an internal redirect parameter.",
            )
        )
    output.legacy_signals["redirect_param"] = redirect_seen

    address = f"{parsed.path}?{parsed.query}" if parsed.query else parsed.path
    encoded = _ENCODED_SEQUENCE.findall(address or "")
    dangerous = _DANGEROUS_ENCODING.findall(address or "")
    ratio = (3 * len(encoded) / max(len(address or ""), 1)) if address else 0.0
    if len(encoded) >= 3 and (ratio > 0.12 or len(dangerous) >= 2):
        if _host_has_attack(output.items):
            output.items.append(
                EvidenceItem(
                    name="encoded_obfuscation",
                    category=MEDIUM,
                    weight=10,
                    explanation=(
                        "Excessive or dangerous URL encoding accompanies other attack evidence."
                    ),
                    details={"encoded_sequences": len(encoded)},
                )
            )
        else:
            output.items.append(
                EvidenceItem(
                    name="unusual_encoding",
                    category=WEAK,
                    weight=2,
                    explanation="The URL contains unusual percent encoding.",
                    details={"encoded_sequences": len(encoded)},
                )
            )

    if len(raw_url or "") >= 200:
        output.items.append(
            EvidenceItem(
                name="long_url",
                category=WEAK,
                weight=2,
                explanation="The URL is unusually long. Length alone is not phishing evidence.",
            )
        )

    output.legacy_signals["ip_host"] = bool(parsed.is_ip)


def _namespace_construction_items(parsed: ParsedURL, output: DetectionOutput) -> None:
    """Detect a compound deceptive namespace even without a known brand.

    This is structural, not a bare keyword rule: it needs an institutional or
    trust term, a credential/action term, a compound multi-token registrable
    name, and a high-abuse namespace.  One of those facts alone remains weak.
    """
    if any(item.name == "deceptive_subdomain" for item in output.items):
        return
    tokens = _split_tokens(parsed.registered_domain)
    if len(tokens) < 3:
        return
    token_set = set(tokens)
    if not (token_set & _TRUST_TERMS):
        return
    if not (token_set & _CREDENTIAL_PATH_TOKENS):
        return
    if (parsed.tld or "").lower() not in SUSPICIOUS_TLDS:
        return
    output.items.append(
        EvidenceItem(
            name="deceptive_domain_construction",
            category=MEDIUM,
            weight=25,
            explanation=(
                "The registrable domain compounds an institutional/trust word with a "
                "credential word in a frequently abused namespace."
            ),
            details={"tokens": tokens},
        )
    )


def _high_risk_namespace_item(parsed: ParsedURL, output: DetectionOutput) -> None:
    tld = (parsed.tld or "").lower()
    if tld not in SUSPICIOUS_TLDS:
        output.legacy_signals["suspicious_tld"] = None
        output.legacy_signals["high_risk_namespace"] = False
        return
    output.legacy_signals["suspicious_tld"] = tld
    if _host_has_attack(output.items) or any(
        item.name == "deceptive_domain_construction" for item in output.items
    ):
        output.items.append(
            EvidenceItem(
                name="high_risk_namespace",
                category=MEDIUM,
                weight=15,
                explanation=f"The .{tld} namespace is frequently abused for phishing.",
            )
        )
        output.legacy_signals["high_risk_namespace"] = True
    else:
        output.items.append(
            EvidenceItem(
                name="suspicious_tld",
                category=WEAK,
                weight=5,
                explanation=(
                    f"The .{tld} namespace is frequently abused, but a TLD alone does "
                    "not establish phishing."
                ),
            )
        )
        output.legacy_signals["high_risk_namespace"] = False


def build_detection_evidence(
    parsed: ParsedURL,
    raw_url: str,
    trusted_rows: list[dict],
    trusted_match: dict | None,
    ti_verdicts: list[dict],
) -> DetectionOutput:
    """Run reputation, intelligence, impersonation, and URL-attack layers."""
    output = DetectionOutput(
        legacy_signals={
            "hostname": parsed.ascii_host,
            "registered_domain": parsed.registered_domain,
            "tld_mismatch": False,
            "protected_identity": None,
        }
    )
    if not parsed.ascii_host:
        output.items.append(
            EvidenceItem(
                name="invalid_url",
                category=WEAK,
                weight=0,
                explanation="No valid hostname could be extracted from the URL.",
            )
        )
        return output

    ti_summary = summarize_threat_intel(ti_verdicts)
    for verdict in ti_summary["malicious"]:
        provider = str(verdict.get("provider", "threat-intelligence"))
        if provider == "local_database":
            output.items.append(
                EvidenceItem(
                    name="known_malicious",
                    category="critical",
                    weight=100,
                    explanation="Confirmed malicious threat intelligence: "
                    + (
                        verdict.get("detail")
                        or "the domain is on the administrator's confirmed malicious list."
                    ),
                )
            )
        else:
            output.items.append(
                EvidenceItem(
                    name="confirmed_threat_intelligence",
                    category="critical",
                    weight=100,
                    explanation="Confirmed malicious threat intelligence: "
                    + (
                        verdict.get("detail")
                        or f"{provider} confirms this URL is malicious."
                    ),
                )
            )
    output.legacy_signals["ti_malicious"] = bool(ti_summary["malicious"])
    output.legacy_signals["ti_benign"] = bool(ti_summary["benign"])
    if ti_summary["malicious"]:
        # Confirmed threat intelligence overrides both trust and context.
        return output

    if trusted_match:
        output.items.append(
            EvidenceItem(
                name="trusted_domain",
                category=CONTEXTUAL,
                explanation="The hostname exactly matches a verified trusted domain.",
                matched_domain=trusted_match.get("normalized_domain"),
            )
        )
        output.matched_domain = trusted_match.get("normalized_domain")
        output.legacy_signals.update(
            {
                "exact_match": True,
                "trusted_domain": True,
                "trusted_exact": True,
                "matched_domain": trusted_match.get("normalized_domain"),
            }
        )
        _reputation_items(ti_summary, output.items)
        _host_context_items(parsed, output.items)
        return output

    output.legacy_signals.update(
        {
            "exact_match": False,
            "trusted_domain": False,
            "trusted_exact": False,
            "matched_domain": None,
            "untrusted_destination": True,
        }
    )
    if not ti_summary["benign"]:
        output.items.append(
            EvidenceItem(
                name="not_in_trusted_database",
                category=WEAK,
                weight=5,
                explanation="The domain is not in the trusted database. Unknown is not suspicious.",
            )
        )
    _reputation_items(ti_summary, output.items)
    _host_context_items(parsed, output.items)
    _institutional_context(parsed.ascii_host, parsed.registered_domain, output.items)
    if parsed.ascii_host.startswith("xn--"):
        output.items.append(
            EvidenceItem(
                name="punycode_marker",
                category=CONTEXTUAL,
                explanation="The hostname uses punycode encoding. Encoding alone is not phishing.",
            )
        )
    unicode_form = parsed.unicode_host or ""
    if unicode_form and unicode_form != parsed.ascii_host:
        warning = mixed_script_warning(unicode_form)
        if warning:
            output.items.append(
                EvidenceItem(
                    name="mixed_script_marker",
                    category=CONTEXTUAL,
                    explanation=f"Unicode rendering note: {warning}.",
                )
            )

    candidate_registered = parsed.registered_domain or parsed.ascii_host
    host_labels = (parsed.ascii_host or "").split(".")
    embedded = _embedded_institutional_identity(host_labels)
    if embedded:
        identity, namespace, core = embedded
        output.protected_identity = identity
        output.legacy_signals["protected_identity"] = identity
        if parsed.registered_domain != identity:
            output.items.append(
                EvidenceItem(
                    name="deceptive_subdomain",
                    category=STRONG,
                    weight=35,
                    explanation=(
                        f"The hostname embeds the institutional identity {identity}, but the "
                        f"registrable domain is {parsed.registered_domain}."
                    ),
                    matched_domain=identity,
                )
            )
            if output.matched_domain is None:
                output.matched_domain = identity

    candidate_name, candidate_suffix = _registrable_name_and_suffix(candidate_registered)
    brands = build_trusted_brands(trusted_rows)
    for brand in _shortlist_brands(
        parsed.ascii_host, candidate_registered, parsed.unicode_host, brands
    ):
        _brand_items(parsed, candidate_registered, candidate_name, candidate_suffix, brand, output)
        if output.matched_domain is None and any(
            item.matched_domain == brand.domain for item in output.items
        ):
            output.matched_domain = brand.domain

    _url_attack_items(parsed, raw_url or "", output)
    _namespace_construction_items(parsed, output)
    _high_risk_namespace_item(parsed, output)

    # A changed TLD is context unless a plausible impersonation was generated.
    impersonated = any(
        item.category in (STRONG, MEDIUM)
        and item.name
        in {
            "brand_similarity",
            "very_close_typosquat",
            "brand_prefix",
            "brand_embedded",
            "brand_token_match",
            "confirmed_homograph",
            "punycode_impersonation",
        }
        for item in output.items
    )
    output.legacy_signals["tld_mismatch"] = bool(impersonated)
    if not impersonated:
        output.items.append(
            EvidenceItem(
                name="tld_context",
                category=CONTEXTUAL,
                explanation="Any TLD difference from another domain is normal on its own.",
            )
        )
    return output
