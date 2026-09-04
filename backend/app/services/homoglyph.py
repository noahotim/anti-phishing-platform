"""Unicode confusable / homoglyph analysis.

Provides Unicode Normalization Form KC normalization plus a curated map of
look-alike characters.  Symbols map to LATIN scenarios so that e.g. "0" vs "O",
"l" vs "1", and myriads of CIRCLED/LETTERLIKE codepoints collapse to the ASCII
forms they visually imitate.  This is the substrate the similarity engine uses
instead of raw string comparison.
"""
from __future__ import annotations

import unicodedata


def nfkc(text: str) -> str:
    """Unicode Normalization Form KC (compatibility composing)."""
    return unicodedata.normalize("NFKC", text)


def build_fold_map() -> dict[str, str]:
    """Canonical fold: confusable codepoint -> ASCII look-alike char(s)."""
    m: dict[str, str] = {}

    # Circled lowercase letters  ⓐ..ⓩ
    for i in range(26):
        m[chr(0x24D0 + i)] = chr(ord("a") + i)
    # Parenthesized lowercase letters
    for i in range(26):
        m[chr(0x249C + i)] = chr(ord("a") + i)
    # Fullwidth lowercase letters
    for i in range(26):
        m[chr(0xFF41 + i)] = chr(ord("a") + i)
    # Fullwidth digits
    for i in range(10):
        m[chr(0xFF10 + i)] = chr(ord("0") + i)
    # Superscript digits zero..seven
    for i in range(8):
        m[chr(0x2070 + (i + 1 if i else 0))] = chr(ord("0") + i)

    # --- Cyrillic implied Latin glyphs ------------------------------------
    cyrillic = {
        "\u0430": "a",   # А
        "\u0431": "6",
        "\u0432": "b",   # В
        "\u0433": "r",
        "\u0434": "g",
        "\u0435": "e",   # Е
        "\u0451": "e",   # Ё
        "\u0436": "x",
        "\u0437": "3",
        "\u0438": "u",
        "\u0439": "u",
        "\u043a": "k",   # К
        "\u043b": "n",
        "\u043c": "m",   # М
        "\u043d": "h",   # Н
        "\u043e": "o",
        "\u043f": "n",
        "\u0440": "p",
        "\u0441": "c",
        "\u0442": "t",
        "\u0443": "y",
        "\u0444": "4)",
        "\u0445": "x",
        "\u0446": "u",
        "\u0447": "4",
        "\u0448": "w",
        "\u0449": "w",
        "\u044a": "b",
        "\u044b": "bl",
        "\u044c": "b",
        "\u044d": "o",
        "\u044e": "10",
        "\u044f": "R",
        "\u0455": "s",
        "\u0456": "i",
        "\u0457": "i",
        "\u04af": "u",
        "\u0475": "u",
    }
    m.update(cyrillic)

    # --- Greek implied Latin glyphs ----------------------------------------
    greek = {
        "\u03b1": "a",   # α
        "\u03b2": "b",
        "\u03b3": "y",
        "\u03b4": "8",
        "\u03b5": "e",
        "\u03b6": "z",
        "\u03b7": "n",
        "\u03b8": "9",
        "\u03b9": "i",
        "\u03ba": "k",
        "\u03bb": "l",
        "\u03bc": "u",
        "\u03bd": "v",
        "\u03be": "e",
        "\u03bf": "o",
        "\u03c0": "n",
        "\u03c1": "p",
        "\u03c2": "c",
        "\u03c3": "c",
        "\u03c4": "t",
        "\u03c5": "u",
        "\u03c6": "p",
        "\u03c7": "x",
        "\u03c8": "y",
        "\u03c9": "w",
        "\u03ac": "a",
        "\u03ad": "e",
        "\u03af": "i",
        "\u03cc": "o",
        "\u03cd": "y",
    }
    m.update(greek)

    # --- Latin extended & miscellaneous look-alikes -------------------------
    latin = {
        "\u00fd": "y",         # ý
        "\u00ff": "y",         # ÿ
        "\u0131": "i",         # dotless i
        "\u0237": "j",         # dotless j
        "\u0259": "e",         # schwa
        "\u0261": "g",
        "\u0279": "r",
        "\u0299": "b",
        "\u0127": "h",
        "\u014b": "n",
        "\u0167": "t",
        "\u0142": "l",
        "\u0140": "l",
        "\u0138": "k",
        "\u0153": "oe",
        "\u00e0": "a", "\u00e1": "a", "\u00e2": "a", "\u00e3": "a",
        "\u00e4": "a", "\u00e5": "a", "\u0101": "a", "\u0103": "a",
        "\u00e8": "e", "\u00e9": "e", "\u00ea": "e", "\u00eb": "e",
        "\u0129": "i", "\u00ec": "i", "\u00ed": "i", "\u00ee": "i", "\u00ef": "i",
        "\u00f2": "o", "\u00f3": "o", "\u00f4": "o", "\u00f5": "o",
        "\u00f6": "o", "\u0151": "o", "\u00f9": "u", "\u00fa": "u",
        "\u00fb": "u", "\u00fc": "u", "\u00e7": "c", "\u00f1": "n",
    }
    m.update(latin)

    # --- ASCII visual confusables (leet / digit-for-letter substitutions) ---
    leet = {
        "O": "o", "0": "o", "1": "l", "I": "l", "|": "l",
        "\u00a6": "l", "\u2160": "l", "l": "l", "5": "s", "S": "s",
        "2": "z", "Z": "z", "7": "t", "T": "t", "8": "b", "B": "b",
        "6": "g", "G": "g", "9": "g", "3": "e", "4": "a", "A": "a", "E": "e",
    }
    m.update(leet)
    return m


FOLD_MAP = build_fold_map()


def fold_confusable(s: str) -> str:
    """Fold any char present in FOLD_MAP to its canonical look-alike."""
    return "".join(FOLD_MAP.get(ch, ch) for ch in s)


def contains_non_ascii(s: str) -> bool:
    return any(ord(c) > 127 for c in s)


def mixed_script_warning(s: str) -> str | None:
    """Return a warning string when a label mixes scripts, else None."""
    scripts: list[str] = []
    seen: set[str] = set()
    for ch in s:
        if ch in {".", "-"}:
            continue
        if ord(ch) > 127:
            try:
                block = unicodedata.name(ch).split()[0]
            except ValueError:
                block = "OTHER"
            if block not in seen:
                seen.add(block)
                scripts.append(block)
    if len(scripts) >= 1 and contains_non_ascii(s):
        return "Mixed Unicode script detected: " + ", ".join(scripts)
    return None