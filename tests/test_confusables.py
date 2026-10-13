from __future__ import annotations

import pytest

import glyphguard as gg
from glyphguard.confusables import (
    ALL_SCRIPTS,
    RestrictionLevel,
    ascii_lookalike,
    augmented_script_set,
    fold_in_context,
    is_mixed_script,
    lookalike_scripts,
    prototype,
    resolved_script_set,
    scripts_used,
    twin_in_script,
)

CYR_A = "\N{CYRILLIC SMALL LETTER A}"
CYR_O = "\N{CYRILLIC SMALL LETTER O}"
CYR_P = "\N{CYRILLIC SMALL LETTER ER}"
GREEK_OMICRON = "\N{GREEK SMALL LETTER OMICRON}"
RUSSIAN_PRIVET = (
    "\N{CYRILLIC CAPITAL LETTER PE}\N{CYRILLIC SMALL LETTER ER}\N{CYRILLIC SMALL LETTER I}"
    "\N{CYRILLIC SMALL LETTER VE}\N{CYRILLIC SMALL LETTER IE}\N{CYRILLIC SMALL LETTER TE}"
)


def test_prototype_and_skeleton() -> None:
    assert prototype(CYR_A) == "a"
    assert prototype("a") == "a"
    assert gg.skeleton(CYR_A + "dmin") == gg.skeleton("admin")
    assert gg.skeleton("ad\N{ZERO WIDTH SPACE}min") == gg.skeleton("admin")  # ignorables dropped
    assert gg.skeleton("rn") == gg.skeleton("m")


def test_is_confusable() -> None:
    assert gg.is_confusable(CYR_P + "ayp" + CYR_A + "l", "paypal")
    assert gg.is_confusable("g" + GREEK_OMICRON * 2 + "gle", "google")
    assert not gg.is_confusable("paypal", "paypa1x")
    assert not gg.is_confusable("Admin", "admin")  # skeletons keep case


def test_ascii_lookalike() -> None:
    assert ascii_lookalike(CYR_A) == "a"
    assert ascii_lookalike("\N{MATHEMATICAL BOLD SMALL A}") == "a"
    assert ascii_lookalike("\N{FULLWIDTH LATIN CAPITAL LETTER Q}") == "Q"
    assert ascii_lookalike("a") is None
    assert ascii_lookalike("\N{CJK UNIFIED IDEOGRAPH-6771}") is None


def test_script_sets() -> None:
    assert augmented_script_set(ord("1")) is ALL_SCRIPTS
    assert "Japanese" in augmented_script_set(ord("\N{CJK UNIFIED IDEOGRAPH-6771}"))
    assert "Japanese" in augmented_script_set(ord("\N{HIRAGANA LETTER DE}"))
    assert resolved_script_set("123 !") is ALL_SCRIPTS
    assert resolved_script_set("abc") == {"Latin"}
    japanese = "\N{CJK UNIFIED IDEOGRAPH-6771}\N{CJK UNIFIED IDEOGRAPH-4EAC}\N{HIRAGANA LETTER DE}"
    assert not is_mixed_script(japanese)
    assert is_mixed_script(CYR_A + "dmin")
    assert scripts_used(CYR_A + "dmin") == ["Latin", "Cyrillic"]


@pytest.mark.parametrize(
    ("text", "level"),
    [
        ("admin", RestrictionLevel.ASCII_ONLY),
        (RUSSIAN_PRIVET, RestrictionLevel.SINGLE_SCRIPT),
        ("caf\N{LATIN SMALL LETTER E WITH ACUTE}", RestrictionLevel.SINGLE_SCRIPT),
        (
            "Tokyo\N{CJK UNIFIED IDEOGRAPH-6771}\N{HIRAGANA LETTER DE}",
            RestrictionLevel.HIGHLY_RESTRICTIVE,
        ),
        ("abc\N{ARMENIAN SMALL LETTER AYB}", RestrictionLevel.MODERATELY_RESTRICTIVE),
        (CYR_A + "dmin", RestrictionLevel.MINIMALLY_RESTRICTIVE),
        ("ad\N{ZERO WIDTH SPACE}min", RestrictionLevel.UNRESTRICTED),
    ],
)
def test_restriction_level(text: str, level: RestrictionLevel) -> None:
    assert gg.restriction_level(text) == level


def test_restriction_level_str() -> None:
    assert str(RestrictionLevel.HIGHLY_RESTRICTIVE) == "highly-restrictive"


def test_twin_in_script() -> None:
    assert twin_in_script("e", "Cyrillic") == "\N{CYRILLIC SMALL LETTER IE}"
    assert twin_in_script(CYR_A, "Latin") == "a"
    assert twin_in_script("a", "Latin") is None  # already Latin
    assert twin_in_script("\N{CYRILLIC SMALL LETTER IE}", "Cyrillic") is None


def test_fold_in_context() -> None:
    word = RUSSIAN_PRIVET.replace("\N{CYRILLIC SMALL LETTER IE}", "e")
    assert fold_in_context(word, 4) == "\N{CYRILLIC SMALL LETTER IE}"  # Latin e in Cyrillic word
    text = CYR_A + "dmin"
    assert fold_in_context(text, 0) == "a"
    assert fold_in_context("1\N{ARABIC-INDIC DIGIT TWO}3", 1) == "2"


def test_lookalike_scripts() -> None:
    scripts = lookalike_scripts(gg.skeleton("o"))
    assert {"Latin", "Cyrillic", "Greek"} <= scripts
