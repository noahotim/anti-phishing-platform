"""Tests for the risk scoring and classification logic."""
from __future__ import annotations

from app.services.risk_scorer import (
    classify_raw,
    score_signals,
)

THRESHOLDS = {"low": 20, "moderate": 59, "high": 79}


def test_exact_trust_is_safe():
    r = score_signals({"trusted_exact": True, "matched_domain": "example.com"},
                      THRESHOLDS)
    assert r.classification == "SAFE"
    assert r.risk_level == "LOW"
    assert r.score == 0


def test_confusable_match_scores_high():
    r = score_signals({
        "trusted_exact": False,
        "confusable_exact_match": True,
        "matched_domain": "example.com",
    }, THRESHOLDS)
    assert r.score >= 40
    assert r.classification == "SUSPICIOUS"


def test_one_char_substitution():
    r = score_signals({
        "trusted_exact": False,
        "edit_distance": 1,
        "matched_domain": "example.com",
        "character_ops": ["character '1' substituted for 'e'"],
    }, THRESHOLDS)
    assert r.classification == "SUSPICIOUS"
    assert any("substitut" in reason for reason in r.reasons)


def test_neutral_untrusted_is_unknown():
    r = score_signals({"trusted_exact": False, "untrusted_destination": True},
                      THRESHOLDS)
    assert r.classification == "UNKNOWN"
    assert r.score <= 20


def test_keyword_alone_stays_unknown():
    r = score_signals({
        "trusted_exact": False,
        "untrusted_destination": True,
        "keyword": ["login"],
    }, THRESHOLDS)
    assert r.classification == "UNKNOWN"


def test_punycode_and_mixed_script_without_brand_stay_contextual():
    r = score_signals({
        "trusted_exact": False,
        "untrusted_destination": True,
        "punycode": True,
        "mixed_script": "CYRILLIC",
    }, THRESHOLDS)
    assert r.score <= 20
    assert r.classification == "UNKNOWN"
    assert "Punycode" in " ".join(r.reasons)


def test_ti_malicious_dominates():
    r = score_signals({
        "trusted_exact": False,
        "ti_malicious": True,
    }, THRESHOLDS)
    assert r.classification == "MALICIOUS"
    assert r.score >= 70


def test_classify_bands():
    assert classify_raw(5, THRESHOLDS, False, False) == ("UNKNOWN", "LOW")
    assert classify_raw(15, THRESHOLDS, True, False) == ("SAFE", "LOW")
    assert classify_raw(30, THRESHOLDS, False, False) == ("SUSPICIOUS", "MODERATE")
    assert classify_raw(60, THRESHOLDS, False, False) == ("HIGH_RISK", "HIGH")
    assert classify_raw(90, THRESHOLDS, False, False) == ("MALICIOUS", "CRITICAL")
    assert classify_raw(5, THRESHOLDS, False, False) == ("UNKNOWN", "LOW")
    assert classify_raw(5, THRESHOLDS, False, True, strong=True) == ("SUSPICIOUS", "MODERATE")
    assert classify_raw(5, THRESHOLDS, False, True, medium_count=2) == ("SUSPICIOUS", "MODERATE")
