from __future__ import annotations

import pytest
from conftest import ATTACKS
from hypothesis import given
from hypothesis import strategies as st

import glyphguard as gg
from glyphguard.catalog import Severity, techniques
from glyphguard.sanitize import ACTIONS

PROFILES = sorted(gg.profiles())


def test_profiles_cover_known_actions() -> None:
    for profile in gg.profiles().values():
        for tid in techniques():
            assert profile.action_for(tid) in ACTIONS


def test_unknown_profile() -> None:
    with pytest.raises(ValueError, match="unknown profile"):
        gg.sanitize("x", "nope")


def test_result_records_changes() -> None:
    result = gg.sanitize("fun\u200bding", "llm-input")
    assert result.changed
    assert str(result) == "funding"
    (change,) = result.changes
    assert (change.technique_id, change.action, change.original, change.replacement) == (
        "GG-INV-001",
        "remove",
        "\u200b",
        "",
    )


def test_reveal_escapes_hidden_characters_only() -> None:
    assert gg.reveal("caf\u00e9 fun\u200bding") == "caf\u00e9 fun<U+200B>ding"
    assert gg.reveal("\x1b[2Kx") == "<U+001B>[2Kx"


def test_display_name_profile() -> None:
    assert gg.sanitize("\u202eadmin\u200f\u2800", "display-name").text == "admin"


def test_blank_text_is_not_wiped_by_whole_text_finding() -> None:
    # GG-INV-005 must not delete visible characters; only the invisible ones go.
    assert gg.sanitize("\u3000a", "strict").text == " a"


@pytest.mark.parametrize("vector", ATTACKS, ids=[v["name"] for v in ATTACKS])
def test_strict_neutralizes_every_attack(vector: dict[str, object]) -> None:
    cleaned = gg.sanitize(str(vector["text"]), "strict").text
    remaining = [f for f in gg.detect(cleaned) if f.severity >= Severity.LOW]
    assert remaining == [], [(f.technique_id, f.message) for f in remaining]


@pytest.mark.parametrize("vector", ATTACKS, ids=[v["name"] for v in ATTACKS])
def test_reveal_output_is_safe_to_print(vector: dict[str, object]) -> None:
    revealed = gg.reveal(str(vector["text"]))
    assert gg.detect(revealed, min_severity="low") == []


@pytest.mark.parametrize("profile", PROFILES)
@given(text=st.text())
def test_sanitize_is_idempotent(profile: str, text: str) -> None:
    once = gg.sanitize(text, profile).text
    assert gg.sanitize(once, profile).text == once
