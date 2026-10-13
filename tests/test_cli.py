from __future__ import annotations

import json
from pathlib import Path

import pytest

from glyphguard.cli import main, unescape


def run(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, str]:
    code = main(["--color", "never", *argv])
    return code, capsys.readouterr().out


def test_unescape() -> None:
    assert unescape(r"a\u200Bb\U000E0041\x1b\N{RIGHT-TO-LEFT OVERRIDE}\n\\") == (
        "a\u200bb\U000e0041\x1b\u202e\n\\"
    )


def test_inspect_text(capsys: pytest.CaptureFixture[str]) -> None:
    code, out = run(capsys, "inspect", "-e", r"Hi\U000E0068\U000E0069")
    assert code == 0
    assert "GG-SMUG-001" in out
    assert "tags: hi" in out
    assert "\U000e0068" not in out  # hidden characters are never echoed raw


def test_inspect_json(capsys: pytest.CaptureFixture[str]) -> None:
    code, out = run(capsys, "inspect", "--format", "json", "-e", r"a\u202Eb")
    report = json.loads(out)
    assert code == 0
    assert report["unicode_version"] == "18.0.0"
    assert {f["technique"] for f in report["findings"]} == {"GG-BIDI-001", "GG-BIDI-003"}


def test_detect_files_reports_line_and_column(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    source = tmp_path / "evil.py"
    source.write_text('ok = 1\nx = "user\u202e"\n', encoding="utf-8")
    clean = tmp_path / "clean.py"
    clean.write_text("print('hi')\n", encoding="utf-8")

    code, out = run(capsys, "detect", str(source), str(clean))
    assert code == 1
    assert f"{source}:2:10: high GG-BIDI-001" in out

    code, _ = run(capsys, "detect", str(clean))
    assert code == 0


def test_detect_fail_on_threshold(capsys: pytest.CaptureFixture[str]) -> None:
    assert run(capsys, "detect", "-e", "-t", r"x\u2003y")[0] == 0  # low < medium
    assert run(capsys, "detect", "--fail-on", "low", "-e", "-t", r"x\u2003y")[0] == 1


def test_detect_invalid_utf8_file(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    path = tmp_path / "bad.txt"
    path.write_bytes(b"abc\xff\n")
    code, out = run(capsys, "detect", "--format", "json", str(path))
    assert code == 1
    assert json.loads(out)[0]["technique"] == "GG-INV-010"


def test_sanitize(capsysbinary: pytest.CaptureFixture[bytes]) -> None:
    code = main(["sanitize", "-e", r"fun\u200Bding\U000E0041"])
    assert code == 0
    assert capsysbinary.readouterr().out == b"funding\n"


def test_catalog(capsys: pytest.CaptureFixture[str]) -> None:
    code, out = run(capsys, "catalog")
    assert code == 0
    assert "GG-SMUG-002" in out
    assert "llm-input" in out


def test_bad_severity_is_an_error(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["detect", "--fail-on", "severe", "-t", "x"]) == 2


def test_detect_skips_binary_files(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    path = tmp_path / "image.png"
    path.write_bytes(b"\x89PNG\x00\x00" + b"\xe2\x80\xae")  # NUL bytes, then an RLO
    assert run(capsys, "detect", str(path))[0] == 0
    assert run(capsys, "detect", "--binary", str(path))[0] == 1
