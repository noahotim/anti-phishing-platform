"""Tests for the similarity engine: edit distances and finding generation."""
from __future__ import annotations

from app.services.similarity import (
    SimilarityEngine,
    damerau_levenshtein,
    levenshtein,
)

TRUSTED = ["example.com", "company.com", "citibank.com", "microsoft.com"]


def test_levenshtein():
    assert levenshtein("abc", "abc") == 0
    assert levenshtein("kitten", "sitting") == 3
    assert levenshtein("", "abc") == 3


def test_damerau_transposition():
    assert damerau_levenshtein("abcd", "abdc") == 1


def test_substitution():
    eng = SimilarityEngine(TRUSTED)
    f = eng.best_finding("examp1e.com")
    assert f is not None
    assert f.trusted_domain == "example.com"
    assert f.edit_distance <= 1


def test_insertion():
    eng = SimilarityEngine(TRUSTED)
    f = eng.best_finding("examplee.com")  # extra 'e'
    assert f is not None
    assert f.trusted_domain == "example.com"
    assert any("insert" in op for op in f.char_ops)


def test_deletion():
    eng = SimilarityEngine(TRUSTED)
    f = eng.best_finding("exampl.com")  # missing 'e'
    assert f is not None
    assert f.trusted_domain == "example.com"


def test_transposition():
    eng = SimilarityEngine(TRUSTED)
    f = eng.best_finding("exampel.com")  # swapped le -> el
    assert f is not None
    assert f.trusted_domain in TRUSTED
    assert any("transpos" in op for op in f.char_ops)


def test_unicode_homoglyph():
    eng = SimilarityEngine(TRUSTED)
    f = eng.best_finding("еxample.com")  # Cyrillic e
    assert f is not None
    assert f.fold_match is True
    assert f.trusted_domain == "example.com"


def test_punycode_homoglyph():
    eng = SimilarityEngine(TRUSTED)
    f = eng.best_finding("xn--xample-2of.com")  # punycode of еxample.com
    assert f is not None
    assert f.fold_match is True


def test_misleading_subdomain():
    eng = SimilarityEngine(TRUSTED)
    f = eng.best_finding("example.com.security-example.com")
    assert f is not None
    assert f.misleading_subdomain is True


def test_suffix_embedded():
    eng = SimilarityEngine(TRUSTED)
    f = eng.best_finding("securityexample.com")
    assert f is not None
    assert f.suffix_embedded is True


def test_brand_prefix():
    eng = SimilarityEngine(TRUSTED)
    f = eng.best_finding("example-secure.com")
    assert f is not None
    assert f.brand_prefix is True


def test_keyword_detection():
    eng = SimilarityEngine(TRUSTED)
    f = eng.best_finding("secure-login.example.net")
    assert f is not None
    assert any("login" in k or "secure" in k for k in f.keyword_hits)


def test_suspicious_tld():
    eng = SimilarityEngine(TRUSTED)
    f = eng.best_finding("citibank.xyz")
    assert f is not None
    assert f.suspicious_tld == "xyz"


def test_far_domain():
    eng = SimilarityEngine(TRUSTED)
    f = eng.best_finding("totallyunrelatedbrand.com")
    assert f is not None
    assert f.edit_distance > 4
    assert not f.fold_match