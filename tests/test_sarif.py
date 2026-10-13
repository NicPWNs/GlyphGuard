from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import glyphguard as gg
from glyphguard.cli import main
from glyphguard.sarif import to_sarif


def sarif_for(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, dict[str, Any]]:
    code = main(["detect", "--format", "sarif", *argv])
    return code, json.loads(capsys.readouterr().out)


def test_sarif_log_structure(
    capsys: pytest.CaptureFixture[str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "evil.py").write_bytes(
        b'ok = 1\nx = "user\xe2\x80\xae"\np = "Hi' + gg.stego.encode_tags("Ig").encode() + b'"\n'
    )
    code, log = sarif_for(capsys, str(Path("src") / "evil.py"))
    assert code == 1
    assert log["version"] == "2.1.0"
    run = log["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    assert [r["id"] for r in rules] == list(gg.techniques())
    assert run["columnKind"] == "unicodeCodePoints"

    by_rule = {r["ruleId"]: r for r in run["results"]}
    assert set(by_rule) == {"GG-BIDI-001", "GG-BIDI-003", "GG-SMUG-001"}
    for result in run["results"]:
        assert rules[result["ruleIndex"]]["id"] == result["ruleId"]

    bidi = by_rule["GG-BIDI-001"]
    assert bidi["level"] == "error"
    assert bidi["properties"]["security-severity"] == "8.0"
    location = bidi["locations"][0]["physicalLocation"]
    assert location["artifactLocation"] == {"uri": "src/evil.py", "uriBaseId": "%SRCROOT%"}
    assert location["region"] == {"startLine": 2, "startColumn": 10, "endLine": 2, "endColumn": 11}

    smuggled = by_rule["GG-SMUG-001"]
    assert smuggled["properties"]["security-severity"] == "9.5"
    assert smuggled["properties"]["payload"]["text"] == "Ig"


def test_rules_carry_cwe_tags_and_help() -> None:
    rules = to_sarif([], version="0")["runs"][0]["tool"]["driver"]["rules"]
    zero_width = next(r for r in rules if r["id"] == "GG-INV-001")
    assert "external/cwe/cwe-176" in zero_width["properties"]["tags"]
    assert zero_width["name"] == "ZeroWidth"
    assert zero_width["help"]["markdown"].startswith("**Zero-width character** (GG-INV-001)")


def test_text_input_has_no_location(capsys: pytest.CaptureFixture[str]) -> None:
    code, log = sarif_for(capsys, "-e", "-t", r"fun\u200Bding")
    (result,) = log["runs"][0]["results"]
    assert code == 1
    assert "locations" not in result


def test_clean_input_gives_empty_results(capsys: pytest.CaptureFixture[str]) -> None:
    code, log = sarif_for(capsys, "-t", "plain text")
    assert code == 0
    assert log["runs"][0]["results"] == []


def test_sarif_file_alongside_another_format(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    out = tmp_path / "glyphguard.sarif"
    code = main(["detect", "--format", "github", "--sarif", str(out), "-e", "-t", r"a\u202Eb"])
    assert code == 1
    assert capsys.readouterr().out.startswith("::error")
    assert len(json.loads(out.read_text(encoding="utf-8"))["runs"][0]["results"]) == 2
