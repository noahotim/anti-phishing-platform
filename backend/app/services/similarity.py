"""Domain similarity engine.

Compares one domain against the trusted set using edit distance signals,
normalized/confusable forms and structural heuristics.  Returns structured
findings that the risk scorer converts into a 0–100 score.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from . import normalization


def levenshtein(a: str, b: str) -> int:
    """Classic Levenshtein (insert / delete / substitute) distance."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(
                min(
                    prev[j] + 1,          # deletion
                    cur[j - 1] + 1,       # insertion
                    prev[j - 1] + (ca != cb),  # substitution
                )
            )
        prev = cur
    return prev[-1]


def damerau_levenshtein(a: str, b: str) -> int:
    """Damerau–Levenshtein: adds transposition to the edit distance."""
    if a == b:
        return 0
    da: dict[str, int] = {}
    maxdist = len(a) + len(b) + 1
    d = [[0] * (len(b) + 2) for _ in range(len(a) + 2)]
    for i in range(len(a) + 1):
        d[i + 1][0] = maxdist
        d[i + 1][1] = i
    for j in range(len(b) + 1):
        d[0][j + 1] = maxdist
        d[1][j + 1] = j
    for i in range(1, len(a) + 1):
        db = 0
        for j in range(1, len(b) + 1):
            k = da.get(b[j - 1], 0)
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i + 1][j + 1] = min(
                d[i][j] + cost,           # substitution
                d[i + 1][j] + 1,          # insertion
                d[i][j + 1] + 1,          # deletion
                d[k][db] + (i - k - 1) + 1 + (j - db - 1),  # transposition
            )
            if cost == 0:
                db = j
        da[a[i - 1]] = i
    return d[len(a) + 1][len(b) + 1]


# Character pairs that are visually confusable with each other for
# substitution reporting (a real substitution of e→é under fold is identical,
# but plain ASCII substitutions like g→q are not trustable without the fold).
_CONFUSABLE_PAIRS: set[tuple[str, str]] = {
    ("o", "0"), ("0", "o"), ("l", "1"), ("1", "l"), ("i", "1"), ("1", "i"),
    ("l", "i"), ("i", "l"), ("o", "q"), ("q", "o"), ("m", "rn"), ("rn", "m"),
    ("rn", "nn"),
}


def _explain_character_ops(candidate: str, trusted: str) -> list[str]:
    """Report per-character differences as human-relevant insertions etc.

    Both strings expected already folded/lowercased.
    """
    if candidate == trusted:
        return []
    res: list[str] = []
    ca = list(candidate)
    cb = list(trusted)
    i = j = 0
    ops = 0
    prev_op = ""
    while i < len(ca) and j < len(cb):
        if ca[i] == cb[j]:
            i += 1
            j += 1
            continue
        if ops > 6:
            break
        # Transposition check
        if (
            i + 1 < len(ca)
            and j + 1 < len(cb)
            and ca[i] == cb[j + 1]
            and ca[i + 1] == cb[j]
        ):
            res.append("character transposition detected")
            ops += 1
            prev_op = "transposition"
            i += 2
            j += 2
            continue
        # Insertion: candidate has an extra char at this position
        if i + 1 < len(ca) and ca[i + 1] == cb[j]:
            res.append(f"character '{ca[i]}' inserted")
            ops += 1
            prev_op = "insertion"
            i += 1
            continue
        # Deletion: trusted has an extra char here
        if j + 1 < len(cb) and ca[i] == cb[j + 1]:
            res.append(f"character '{cb[j]}' deleted")
            ops += 1
            prev_op = "deletion"
            j += 1
            continue
        # Substitution
        res.append(f"character '{ca[i]}' substituted for '{cb[j]}'")
        ops += 1
        prev_op = "substitution"
        i += 1
        j += 1
    if i < len(ca) and prev_op != "insertion":
        res.append(f"extra character(s) inserted at end: {''.join(ca[i:])}")
    if j < len(cb) and prev_op != "deletion":
        res.append(f"character(s) removed at end: {''.join(cb[j:])}")
    return res


SUSPICIOUS_KEYWORDS = (
    "login", "log-in", "signin", "sign-in", "auth", "authenticate", "verify",
    "verification", "confirm", "validate", "secure", "security", "account",
    "accounts", "update", "recover", "reset", "password", "credential",
    "wallet", "banking", "webscr", "paypal", "ebayisapi", "idp", "sso",
    "mail", "webmail", "portal", "billing", "invoice", "payment", "office365",
    "outlook", "sharepoint",
)

SUSPICIOUS_TLDS = {
    "xyz", "top", "icu", "tk", "ml", "ga", "cf", "gq", "link", "click",
    "country", "men", "work", "date", "faith", "science", "zip", "mov",
    "monster", "kim", "wtf", "xin", "loan", "racing", "review", "racing",
}


@dataclass
class DomainFinding:
    trusted_domain: str
    candidate_domain: str
    edit_distance: int = -1
    char_ops: list[str] = field(default_factory=list)
    fold_match: bool = False
    ascii_fold_match: bool = False
    registered_confusable: bool = False
    same_tld: bool = False
    tld_confusion: str | None = None
    keyword_hits: list[str] = field(default_factory=list)
    suspicious_tld: str | None = None
    misleading_subdomain: bool = False
    brand_prefix: bool = False
    punycode: bool = False
    mixed_script: str | None = None
    suffix_embedded: bool = False
    description: str | None = None


class SimilarityEngine:
    def __init__(self, trusted_domains: list[str]) -> None:
        self.trusted = sorted(
            {normalization.to_ascii(d).rstrip(".") for d in trusted_domains if d}
        )
        self.folded = {
            t: normalization.fold_for_similarity_unicode(t) for t in self.trusted
        }

    def best_finding(self, candidate: str) -> Optional[DomainFinding]:
        """Balance of all signals.

        Returns the most *deception-relevant* finding rather than simply the
        nearest edit-distance match, so embedded-brand cases (e.g.
        "securityexample.com" vs "example.com") are attributed to the brand
        being impersonated.
        """
        findings = self._all_findings(candidate)
        if not findings:
            return None
        return max(
            findings,
            key=lambda f: (
                f.fold_match,
                f.misleading_subdomain,
                f.suffix_embedded,
                f.brand_prefix,
                -f.edit_distance if f.edit_distance >= 0 else 0,
                -len(f.keyword_hits),
            ),
        )

    def _all_findings(self, candidate: str) -> list[DomainFinding]:
        cand_ascii = normalization.to_ascii(candidate).rstrip(".")
        cand_unicode = normalization.to_unicode(cand_ascii)  # IDN ToUnicode
        cand_ascii_fold = normalization.fold_for_similarity(candidate)
        if not cand_ascii:
            return []

        out: list[DomainFinding] = []
        for trusted in self.trusted:
            a = cand_ascii
            b = trusted
            # Compare the IDN Unicode rendering first so punycode homoglyphs and
            # unicode look-alikes (Cyrillic/Greek/etc.) are seen as the strings
            # a human would read.
            unicode_form = cand_unicode if cand_unicode else cand_ascii
            trusted_folded = self.folded[trusted]
            unicode_fold = normalization.fold_for_similarity_unicode(unicode_form)
            full_dist = damerau_levenshtein(a, b)
            unicode_dist = damerau_levenshtein(
                unicode_fold.replace("xn--", ""), trusted_folded
            )
            combined = min(full_dist, unicode_dist)

            finding = DomainFinding(
                trusted_domain=trusted,
                candidate_domain=a,
                edit_distance=combined,
                fold_match=unicode_fold == trusted_folded,
                ascii_fold_match=cand_ascii_fold == trusted_folded.lower(),
            )

            # TLD comparison (registered domain level).
            at = a.rsplit(".", 1)[1] if "." in a else a
            bt = b.rsplit(".", 1)[1] if "." in b else b
            finding.same_tld = at == bt
            if not finding.same_tld and len(at) > 1 and len(bt) > 1:
                if levenshtein(at, bt) <= 1:
                    finding.tld_confusion = f"TLD '{at}' closely matches approved TLD '{bt}'"
            if at in SUSPICIOUS_TLDS:
                finding.suspicious_tld = at

            # Keyword presence inside the candidate's registrable host.
            kw_hits = [
                k for k in SUSPICIOUS_KEYWORDS if k in a.split(".")[0].lower()
            ]
            if kw_hits:
                finding.keyword_hits = kw_hits[:4]

            # Punycode / mixed-script.
            if a.startswith("xn--"):
                finding.punycode = True
            from . import homoglyph
            warning = homoglyph.mixed_script_warning(candidate)
            finding.mixed_script = warning or None

            # Misleading subdomain: a trusted brand is a label prefixed by other
            # labels ("trusted.com.malicious.com") — an attacker-controlled
            # domain that visually appears to be the brand.
            if b in a and a != b:
                idx = a.find(b)
                trailing = a[idx + len(b):]
                leading = a[:idx]
                if trailing.startswith("."):
                    finding.misleading_subdomain = True
                    finding.description = (
                        f"Candidate host '{a}' embeds approved brand '{b}' "
                        "as a subdomain/prefix"
                    )
                elif trailing == "" and leading:
                    # Brand is the terminal suffix without a dot break
                    # ("securityexample.com").
                    finding.suffix_embedded = True

            # Brand prefix ("example-secure.com" vs "example.com"):
            # candidate first label opens with the trusted brand label + "-".
            brand_label = b.split(".")[0]
            cand_label = a.split(".")[0]
            if cand_label.startswith(brand_label + "-") and cand_label != brand_label:
                finding.brand_prefix = True
                finding.description = (
                    f"Candidate host '{a}' prefixes approved brand "
                    f"'{brand_label}' with an extra label"
                )

            # Suffix embedded: candidate ends with trusted without a dot break.
            if a.endswith(b) and a != b and not finding.misleading_subdomain:
                finding.suffix_embedded = True

            # Character-level operations for tight distances.
            if combined <= 4:
                finding.char_ops = _explain_character_ops(
                    cand_ascii_fold,
                    self.folded[trusted].lower(),
                )

            out.append(finding)
        return out


def keyword_hits(domain: str) -> list[str]:
    label = domain.split(".")[0].lower()
    return [k for k in SUSPICIOUS_KEYWORDS if k in label]