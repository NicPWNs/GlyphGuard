from __future__ import annotations

import json

import pytest

from glyphguard.cli import main
from glyphguard.confusables import RestrictionLevel
from glyphguard.net import check_hostname, check_label, check_url

CYR_A = "\N{CYRILLIC SMALL LETTER A}"
CYR_ER = "\N{CYRILLIC SMALL LETTER ER}"
CYR_IE = "\N{CYRILLIC SMALL LETTER IE}"
CYR_PALOCHKA = "\N{CYRILLIC SMALL LETTER PALOCHKA}"
APPLE_CYRILLIC = CYR_A + CYR_ER + CYR_ER + CYR_PALOCHKA + CYR_IE  # xn--80ak6aa92e
MUNCHEN = "m\N{LATIN SMALL LETTER U WITH DIAERESIS}nchen.de"
PROTECT = ["paypal.com", "apple.com", "google.com"]


def test_whole_script_punycode() -> None:
    result = check_hostname("xn--80ak6aa92e.com", protect=PROTECT)
    assert result.unicode == APPLE_CYRILLIC + ".com"
    assert result.ascii == "xn--80ak6aa92e.com"
    assert result.reads_as == "apple.com"
    assert result.deceptive
    assert result.lookalike_of == ("apple.com",)
    assert "every Cyrillic letter has an ASCII lookalike" in result.reasons[0]


@pytest.mark.parametrize(
    ("host", "reason", "lookalike_of"),
    [
        ("xn--pple-43d.com", "mixes Latin and Cyrillic letters", ("apple.com",)),
        ("p" + CYR_A + "ypal.com", "mixes Latin and Cyrillic letters", ("paypal.com",)),
        (
            "g\N{GREEK SMALL LETTER OMICRON}\N{GREEK SMALL LETTER OMICRON}gle.com",
            "mixes Latin and Greek letters",
            ("google.com",),
        ),
        (
            "\N{FULLWIDTH LATIN SMALL LETTER P}aypal.com",
            "styled or fullwidth letters",
            ("paypal.com",),
        ),
        ("ex\N{ZERO WIDTH SPACE}ample.com", "invisible characters", ()),
        ("xn--abc-.com", "punycode that decodes to plain ASCII", ()),
        ("xn--99999999999.com", "invalid punycode", ()),
        ("xn--a-9a.com", "does not allow in identifiers: U+0091", ()),
        ("login.p" + CYR_A + "ypal.com", "mixes Latin and Cyrillic letters", ("paypal.com",)),
    ],
)
def test_deceptive_hostnames(host: str, reason: str, lookalike_of: tuple[str, ...]) -> None:
    result = check_hostname(host, protect=PROTECT)
    assert result.deceptive
    assert any(reason in r for r in result.reasons), result.reasons
    assert result.lookalike_of == lookalike_of


@pytest.mark.parametrize(
    "host",
    [
        "www.paypal.com",
        "accounts.google.com",
        "PayPal.com.",
        MUNCHEN,
        "xn--mnchen-3ya.de",
        "\N{CJK UNIFIED IDEOGRAPH-4F8B}\N{HIRAGANA LETTER E}.jp",  # Japanese
        "\N{CYRILLIC SMALL LETTER PE}\N{CYRILLIC SMALL LETTER ER}\N{CYRILLIC SMALL LETTER I}"
        "\N{CYRILLIC SMALL LETTER EM}\N{CYRILLIC SMALL LETTER IE}\N{CYRILLIC SMALL LETTER ER}"
        ".\N{CYRILLIC SMALL LETTER ER}\N{CYRILLIC SMALL LETTER EF}",  # Russian, .rf
        "xn--example.com",  # decodes to Greek letters that don't read as ASCII
        "example\N{IDEOGRAPHIC FULL STOP}com",
    ],
)
def test_legitimate_hostnames(host: str) -> None:
    result = check_hostname(host, protect=PROTECT)
    assert not result.deceptive, (result.reasons, result.lookalike_of)


def test_wire_and_display_forms() -> None:
    result = check_hostname(MUNCHEN)
    assert result.ascii == "xn--mnchen-3ya.de"
    assert result.unicode == MUNCHEN
    assert check_hostname("example\N{IDEOGRAPHIC FULL STOP}com").unicode == "example.com"


def test_combosquatting_prefix() -> None:
    result = check_hostname("paypal.com.account-verify.example", protect=["paypal.com"])
    assert result.lookalike_of == ("paypal.com",)
    assert not result.reasons  # nothing wrong with the characters themselves


def test_label_levels() -> None:
    assert check_label("example").restriction_level == RestrictionLevel.ASCII_ONLY
    assert check_label("xn--80ak6aa92e").restriction_level == RestrictionLevel.SINGLE_SCRIPT


def test_check_url() -> None:
    trick = check_url("https://paypal.com@evil.example/login", protect=PROTECT)
    assert trick.deceptive
    assert trick.host is not None
    assert trick.host.unicode == "evil.example"
    assert "user name 'paypal.com' looks like a hostname" in trick.reasons[0]

    assert not check_url("https://user@example.com/").deceptive
    assert not check_url("mailto:someone@example.com").deceptive
    assert check_url("not a url").host is None
    punycode = check_url("https://xn--80ak6aa92e.com/signin")
    assert punycode.deceptive
    assert punycode.to_dict()["host"]["reads_as"] == "apple.com"


def test_to_dict_round_trips_through_json() -> None:
    data = check_hostname("xn--80ak6aa92e.com", protect=PROTECT).to_dict()
    assert json.loads(json.dumps(data)) == data
    assert data["labels"][0]["scripts"] == ["Cyrillic"]


def run(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, str]:
    code = main(["--color", "never", *argv])
    return code, capsys.readouterr().out


def test_cli_url(capsys: pytest.CaptureFixture[str]) -> None:
    code, out = run(capsys, "url", "-p", "apple.com", "xn--80ak6aa92e.com", "www.example.com")
    assert code == 1
    assert "deceptive  xn--80ak6aa92e.com" in out
    assert "reads as  apple.com" in out
    assert "<U+0430>" in out  # never prints the lookalike raw
    assert "imitates protected domain apple.com" in out
    assert "ok  www.example.com" in out

    code, out = run(capsys, "url", "https://example.com/")
    assert code == 0


def test_cli_url_json(capsys: pytest.CaptureFixture[str]) -> None:
    code, out = run(
        capsys, "url", "--format", "json", "-e", r"https://p\u0430ypal.com", "-p", "paypal.com"
    )
    (record,) = json.loads(out)
    assert code == 1
    assert record["deceptive"]
    assert record["host"]["ascii"] == "xn--pypal-4ve.com"
    assert "imitates protected domain paypal.com" in record["reasons"]


@pytest.mark.parametrize("url", ["https://[", "http://[::1", "https://[not-an-ip]/"])
def test_malformed_urls_are_reported_not_raised(url: str) -> None:
    result = check_url(url)
    assert result.deceptive
    assert result.host is None
    assert result.reasons[0].startswith("malformed URL")
