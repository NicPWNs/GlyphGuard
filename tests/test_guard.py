from __future__ import annotations

import time

import pytest

import glyphguard as gg
from glyphguard.guard import fold

CYR_A = "\N{CYRILLIC SMALL LETTER A}"
CYR_O = "\N{CYRILLIC SMALL LETTER O}"
ZWSP = "\N{ZERO WIDTH SPACE}"


def styled(word: str, first: int) -> str:
    return "".join(chr(first + ord(c) - ord("a")) for c in word)


@pytest.fixture(scope="module")
def guard() -> gg.Guard:
    return gg.Guard(["admin", "support", "discord"], allow=["discordant"])


@pytest.mark.parametrize(
    ("text", "techniques"),
    [
        ("Contact the " + CYR_A + "dm1n team", ("leetspeak", "lookalike")),
        ("a.d.m.i.n", ("separator",)),
        ("a d m i n", ("separator",)),
        ("aaadmiin", ("repeated",)),
        ("4dm!n", ("leetspeak",)),
        ("ad" + ZWSP + "min", ("invisible",)),
        ("ad\N{COMBINING DOT ABOVE}min", ("invisible",)),
        (styled("admin", 0x1D41A), ("styled",)),  # mathematical bold
        (styled("admin", 0xFF41), ("styled",)),  # fullwidth
        (styled("admin", 0x1F170), ("styled",)),  # negative squared
        (
            "\N{LATIN LETTER SMALL CAPITAL A}\N{LATIN LETTER SMALL CAPITAL D}"
            "\N{LATIN LETTER SMALL CAPITAL M}\N{LATIN LETTER SMALL CAPITAL I}"
            "\N{LATIN LETTER SMALL CAPITAL N}",
            ("styled",),
        ),
        ("adrnin", ("lookalike",)),
        (
            "\N{LATIN SMALL LETTER A WITH GRAVE}dm\N{LATIN SMALL LETTER I WITH GRAVE}n",
            ("diacritic",),
        ),
        ("d i s c 0 r d", ("leetspeak", "separator")),
        ("supp0rt desk", ("leetspeak",)),
        ("disc" + CYR_O + "rd", ("lookalike",)),
    ],
)
def test_disguised_terms_are_caught(
    guard: gg.Guard, text: str, techniques: tuple[str, ...]
) -> None:
    result = guard.check(text)
    assert result.blocked
    assert result.verdict == "block"
    (match,) = result.matches
    assert match.disguised
    assert match.techniques == techniques


@pytest.mark.parametrize("text", ["admin", "ADMIN", "Ask an Admin.", "Discord"])
def test_plain_terms_match_but_are_not_disguised(guard: gg.Guard, text: str) -> None:
    (match,) = guard.check(text).matches
    assert not match.disguised
    assert match.evidence == ()


@pytest.mark.parametrize(
    "text", ["badminton club", "administrator", "the admins", "discordant views", "a dim inn", ""]
)
def test_clean_text_is_allowed(guard: gg.Guard, text: str) -> None:
    result = guard.check(text)
    assert not result.blocked
    assert result.verdict == "allow"


def test_spans_point_into_the_original_text(guard: gg.Guard) -> None:
    text = "hi " + ZWSP + "x " + CYR_A + "d" + ZWSP + "min!"
    (match,) = guard.check(text).matches
    assert text[match.start : match.end] == CYR_A + "d" + ZWSP + "min"
    assert match.span == (match.start, match.end)
    assert [e.index for e in match.evidence] == [match.start, match.start + 2]


def test_multiple_terms_sorted(guard: gg.Guard) -> None:
    result = guard.check("disc" + CYR_O + "rd Support and admin")
    assert [(m.term, m.disguised) for m in result.matches] == [
        ("discord", True),
        ("support", False),
        ("admin", False),
    ]


def test_modes() -> None:
    assert gg.Guard(["admin"], mode="contains").check("badminton").blocked
    assert not gg.Guard(["admin"]).check("badminton").blocked
    exact = gg.Guard(["admin"], mode="exact")
    assert exact.check("  " + CYR_A + "dmin!").blocked
    assert not exact.check("the admin").blocked
    mixed = gg.Guard(["admin", {"term": "mod", "mode": "contains"}])
    assert mixed.check("supermod").blocked
    assert mixed.terms == ["admin", "mod"]


def test_multi_word_terms() -> None:
    guard = gg.Guard(["paypal support"])
    assert guard.check("p" + CYR_A + "ypal   support").blocked
    assert guard.check("paypal-support").blocked
    assert not guard.check("paypalsupport").blocked


def test_invalid_terms() -> None:
    with pytest.raises(ValueError, match="empty"):
        gg.Guard([ZWSP])
    with pytest.raises(ValueError, match="unknown mode"):
        gg.Guard([{"term": "x", "mode": "fuzzy"}])


def test_to_dict(guard: gg.Guard) -> None:
    data = guard.check(CYR_A + "dmin").to_dict()
    assert data["verdict"] == "block"
    (match,) = data["matches"]
    assert match["techniques"] == ["lookalike"]
    assert match["evidence"] == [
        {"index": 0, "codepoint": "U+0430", "name": "CYRILLIC SMALL LETTER A", "kind": "lookalike"}
    ]


def test_canonicalize() -> None:
    key = gg.canonicalize("admin")
    assert gg.canonicalize("\N{CYRILLIC CAPITAL LETTER A}DMIN") == key
    assert gg.canonicalize(styled("admin", 0xFF41)) == key
    assert gg.canonicalize("ad" + ZWSP + "m\N{LATIN SMALL LETTER I WITH ACUTE}n") == key
    assert gg.canonicalize("adrnin") == key
    assert gg.canonicalize("admln") != key  # leetspeak is the Guard's job, not the key's


def test_fold() -> None:
    assert fold(ZWSP) == ""
    assert fold(" ") == " "
    assert fold("A") == "a"
    assert fold("\N{LATIN SMALL LETTER E WITH ACUTE}") == "e"


def test_adversarial_inputs_stay_linear() -> None:
    guards = [gg.Guard(["admin", "bill"], mode=m) for m in ("word", "contains", "exact")]
    texts = [
        "a" * 50_000,
        "4@" * 25_000,
        "a" + "d" * 50_000,
        "a...d...m...i" * 5_000,
        "b" + "1" * 50_000,
    ]
    start = time.perf_counter()
    for guard in guards:
        for text in texts:
            guard.check(text)
    assert time.perf_counter() - start < 5
