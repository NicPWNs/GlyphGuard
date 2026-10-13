from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

import glyphguard as gg
from glyphguard import stego
from glyphguard.catalog import Severity
from glyphguard.detect import Options


def ids(text: str, **kwargs: object) -> list[str]:
    return [f.technique_id for f in gg.detect(text, **kwargs)]  # type: ignore[arg-type]


def test_clean_ascii_fast_path() -> None:
    assert gg.detect("plain text\twith tabs\r\nand newlines") == []


def test_spans_point_at_original_code_points() -> None:
    text = "ab\u200bcd\u202eef"
    findings = gg.detect(text)
    assert [(f.technique_id, text[f.start : f.end]) for f in findings] == [
        ("GG-INV-001", "\u200b"),
        ("GG-BIDI-001", "\u202e"),
        ("GG-BIDI-003", "\u202e"),
    ]


def test_runs_are_grouped() -> None:
    (finding,) = gg.detect("a\u200b\u200b\u200bb")
    assert finding.span == (1, 4)
    assert finding.codepoints == (0x200B, 0x200B, 0x200B)


def test_lone_surrogate() -> None:
    raw = b"abc\xff".decode("utf-8", errors="surrogateescape")
    (finding,) = gg.detect(raw)
    assert finding.technique_id == "GG-INV-010"
    assert finding.severity == Severity.HIGH
    assert gg.sanitize(raw).text == "abc\ufffd"


def test_leading_bom_is_info() -> None:
    (finding,) = gg.detect("\ufeffhello")
    assert finding.technique_id == "GG-INV-001"
    assert finding.severity == Severity.INFO


def test_filter_by_family_slug_and_severity() -> None:
    text = "a\u200bb" + stego.encode_tags("hi") + "\u202e"
    assert set(ids(text, techniques="SMUG")) == {"GG-SMUG-001"}
    assert ids(text, techniques=["zero-width"]) == ["GG-INV-001"]
    assert "GG-INV-001" not in ids(text, min_severity="high")


def test_unknown_technique_raises() -> None:
    with pytest.raises(KeyError):
        gg.detect("x\u200b", techniques="no-such-thing")


def test_short_invisible_run_is_not_binary() -> None:
    assert ids("a\u200b\u200c\u200bb") == ["GG-INV-001"]


def test_undecodable_binary_run_is_still_high() -> None:
    run = "\u200b\u200c" * 3 + "\u2060\u2061" * 3
    (finding,) = gg.detect("x" + run + "y")
    assert finding.technique_id == "GG-SMUG-003"
    assert finding.severity >= Severity.HIGH


def test_variation_selector_after_valid_base_still_decodes_payload() -> None:
    # U+2764 + VS16 is a valid sequence; the payload follows it.
    text = "\u2764" + "\ufe0f" + stego.encode_variation_selectors("payload", carrier="")
    payloads = gg.payloads(text)
    assert [p.text for p in payloads] == ["payload"]


def test_unterminated_isolate_reported_once_per_line() -> None:
    text = "a\u2066b\nc\u2066d\u2069"
    unbalanced = [f for f in gg.detect(text) if f.technique_id == "GG-BIDI-003"]
    assert [f.start for f in unbalanced] == [1]


def test_pdf_closes_override() -> None:
    assert "GG-BIDI-003" not in ids("a\u202eb\u202cc")


def test_rlm_in_rtl_text_is_info_only() -> None:
    assert gg.detect("\u05e9\u05dc\u05d5\u05dd\u200f", min_severity="low") == []


def test_joiner_between_scripts_is_flagged() -> None:
    # Arabic letter + ZWNJ + Latin letter: not a legitimate joining context.
    assert ids("\u0628\u200cabc") == ["GG-INV-001"]


def test_options_change_thresholds() -> None:
    text = "a\u0300\u0301\u0302"
    assert ids(text) == []
    assert ids(text, options=Options(max_marks=2)) == ["GG-MARK-001"]


def test_osc52_with_invalid_base64_keeps_raw_payload() -> None:
    (payload,) = gg.payloads("\x1b]52;c;not base64!\x07")
    assert payload.channel == "osc-52"
    assert payload.text == "not base64!"


def test_osc_command_is_escaped_in_message() -> None:
    # Found by the fuzzer: a C1 OSC introducer followed by a non-ASCII command byte.
    (finding,) = gg.detect("\x9d\x80", techniques="terminal-escape")
    assert finding.message.isascii()
    assert "'\\x80'" in finding.message


def test_messages_are_ascii() -> None:
    hostile = "\x1b[31m" + stego.encode_variation_selectors("\x1b]0;pwned\x07") + "\u202e\u0435"
    for finding in gg.detect(hostile):
        assert finding.message.isascii()


@given(st.text())
def test_detect_never_crashes_and_spans_are_valid(text: str) -> None:
    findings = gg.detect(text)
    for f in findings:
        assert 0 <= f.start < f.end <= len(text) or (f.start == f.end == 0 and not text)
        assert f.codepoints == tuple(ord(c) for c in text[f.start : f.end])
    assert findings == sorted(findings, key=lambda f: (f.start, f.end, f.technique_id))


@given(st.text(alphabet=st.characters(codec="utf-8")))
def test_detect_handles_arbitrary_code_points(text: str) -> None:
    gg.detect(text)
