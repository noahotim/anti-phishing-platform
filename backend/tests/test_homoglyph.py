"""Tests for homoglyph folding and script detection."""
from __future__ import annotations

from app.services import normalization
from app.services.homoglyph import FOLD_MAP, fold_confusable, mixed_script_warning, nfkc


def test_fold_cyrillic_e():
    assert fold_confusable("\u0435") == "e"
    assert fold_confusable("еxample.com") == "example.com"


def test_fold_cyrillic_o():
    assert fold_confusable("\u043e") == "o"


def test_fold_greek_omicron():
    assert fold_confusable("\u03bf") == "o"


def test_fold_circled_letters():
    assert fold_confusable("\u24d0") == "a"
    # 0x24D4 is CIRCLED LATIN SMALL LETTER E
    assert fold_confusable("\u24d4xample.com") == "example.com"


def test_fold_leet():
    assert fold_confusable("examp1e.com") == "example.com"
    assert fold_confusable("c1tibank.com").startswith("cltibank")


def test_nfkc_normalization():
    # fullwidth letters normalize to ASCII
    assert nfkc("ｅｘａｍｐｌｅ") == "example"


def test_mixed_script_detection():
    assert mixed_script_warning("example.com") is None
    warn = mixed_script_warning("еxample.com")
    assert warn is not None
    assert "CYRILLIC" in warn


def test_confusable_similarity_forms():
    # Cyrillic homoglyph resolves to the trusted ascii form
    assert normalization.fold_for_similarity_unicode("еxample.com") == "example.com"
    # punycode resolves back to the unicode rendering, then folds
    unicode_form = normalization.to_unicode("xn--xample-2of.com")
    assert normalization.fold_for_similarity_unicode(unicode_form) == "example.com"


def test_fold_map_size_sane():
    assert len(FOLD_MAP) > 100