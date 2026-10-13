from __future__ import annotations

import re
import unicodedata

import pytest

from glyphguard import catalog, ucd
from glyphguard.catalog import Severity


def test_catalog_ids_are_well_formed() -> None:
    entries = catalog.techniques()
    assert entries
    slugs = set()
    for tid, technique in entries.items():
        assert re.fullmatch(r"GG-[A-Z]+-\d{3}", tid)
        assert tid.split("-")[1] == technique.family
        assert re.fullmatch(r"[a-z0-9-]+", technique.slug)
        assert technique.slug not in slugs
        slugs.add(technique.slug)
        assert technique.summary


def test_lookup_by_id_slug_and_family() -> None:
    assert catalog.get("tag-smuggling").id == "GG-SMUG-001"
    assert catalog.get("gg-smug-001").slug == "tag-smuggling"
    assert catalog.resolve("BIDI") == {"GG-BIDI-001", "GG-BIDI-002", "GG-BIDI-003", "GG-BIDI-004"}


def test_severity_parse() -> None:
    assert Severity.parse("High") is Severity.HIGH
    assert Severity.CRITICAL > Severity.MEDIUM
    with pytest.raises(ValueError, match="unknown severity"):
        Severity.parse("severe")


def test_unicode_version() -> None:
    assert ucd.UNICODE_VERSION == "18.0.0"


@pytest.mark.parametrize(
    ("cp", "category", "script"),
    [
        (0x41, "Lu", "Latin"),
        (0x430, "Ll", "Cyrillic"),
        (0x200B, "Cf", "Common"),
        (0x0301, "Mn", "Inherited"),
        (0xE0041, "Cf", "Common"),
        (0xE000, "Co", "Unknown"),
        (0xD800, "Cs", "Unknown"),
        (0x0378, "Cn", "Unknown"),
        (0x10FFFF, "Cn", "Unknown"),
    ],
)
def test_properties(cp: int, category: str, script: str) -> None:
    assert ucd.general_category(cp) == category
    assert ucd.script(cp) == script


def test_tables_agree_with_stdlib_for_its_version() -> None:
    # Categories only change for code points newly assigned since the stdlib's version.
    mismatches = [
        cp
        for cp in range(0, 0x30000)
        if (std := unicodedata.category(chr(cp))) != "Cn" and ucd.general_category(cp) != std
    ]
    assert len(mismatches) < 50, [hex(cp) for cp in mismatches[:20]]


def test_binary_properties() -> None:
    assert ucd.is_default_ignorable(0x200B)
    assert not ucd.is_default_ignorable(0x41)
    assert ucd.is_bidi_control(0x202E)
    assert ucd.is_variation_selector(0xFE0F)
    assert ucd.is_variation_selector(0xE0100)
    assert ucd.is_extended_pictographic(0x1F600)
    assert ucd.is_overlay_mark(0x0335)
    assert ucd.is_valid_variation_sequence(0x2764, 0xFE0F)
    assert not ucd.is_valid_variation_sequence(0x41, 0xFE0F)
    assert ucd.script_extensions(0x0951) >= {"Devanagari"}


def test_names() -> None:
    assert ucd.name(0x200B) == "ZERO WIDTH SPACE"
    assert ucd.name(0x08) == "BACKSPACE"
    assert ucd.name(0xE0041).startswith("TAG")
    assert ucd.label(0x202E) == "U+202E RIGHT-TO-LEFT OVERRIDE"
