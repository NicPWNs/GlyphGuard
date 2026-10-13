from __future__ import annotations

import json
from pathlib import Path

import pytest

from glyphguard.cli import _gh_data, _gh_property, main, unescape


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


def test_detect_github_annotations(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    path = tmp_path / "evil.py"
    path.write_bytes(b'ok = 1\nx = "user\xe2\x80\xae"  # trailing\n\xe2\x80\x83\n')
    code, out = run(capsys, "detect", "--format", "github", "--min-severity", "low", str(path))
    lines = out.splitlines()
    assert code == 1
    assert lines[0] == (
        f"::error file={_gh_property(str(path))},line=2,col=10,"
        "title=GG-BIDI-001 Bidirectional override (high)::U+202E RIGHT-TO-LEFT OVERRIDE"
    )
    assert lines[-1].startswith(
        f"::warning file={_gh_property(str(path))},line=3,col=1,title=GG-INV-006"
    )


def test_github_escaping() -> None:
    assert _gh_data("50% done\r\nnext") == "50%25 done%0D%0Anext"
    assert _gh_property("a,b:c") == "a%2Cb%3Ac"


def test_detect_walks_directories(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    (tmp_path / "prompts" / "deep").mkdir(parents=True)
    (tmp_path / "prompts" / "deep" / "evil.txt").write_bytes(b"fun\xe2\x80\x8bding\n")
    (tmp_path / "prompts" / "clean.txt").write_text("fine\n", encoding="utf-8")
    (tmp_path / "prompts" / ".git").mkdir()
    (tmp_path / "prompts" / ".git" / "ignored").write_bytes(b"\xe2\x80\x8b")
    code, out = run(capsys, "detect", str(tmp_path / "prompts"))
    assert code == 1
    assert "evil.txt:1:4: medium GG-INV-001" in out
    assert "ignored" not in out


def test_detect_files0_from(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    clean, evil = tmp_path / "clean.txt", tmp_path / "evil.txt"
    clean.write_text("fine\n", encoding="utf-8")
    evil.write_bytes(b"fun\xe2\x80\x8bding\n")
    listing = tmp_path / "files.lst"
    listing.write_bytes(b"\0".join(str(p).encode() for p in (clean, evil)) + b"\0")
    code, out = run(capsys, "detect", "--files0-from", str(listing))
    assert code == 1
    assert f"{evil}:1:4: medium GG-INV-001" in out
    assert str(clean) not in out


def test_detect_exclude(
    capsys: pytest.CaptureFixture[str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for name in ("docs/notes.md", "docs/deep/more.md", "src/app.py", "src/vendor/lib.py"):
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_bytes(b"fun\xe2\x80\x8bding\n")
    monkeypatch.chdir(tmp_path)

    def scanned(*excludes: str) -> set[str]:
        argv = [arg for pattern in excludes for arg in ("--exclude", pattern)]
        _, out = run(capsys, "detect", *argv, ".")
        return {
            line.split(":")[0].replace("\\", "/").removeprefix("./") for line in out.splitlines()
        }

    everything = {"docs/notes.md", "docs/deep/more.md", "src/app.py", "src/vendor/lib.py"}
    assert scanned() == everything
    assert scanned("docs") == {"src/app.py", "src/vendor/lib.py"}
    assert scanned("docs/*.md") == {"src/app.py", "src/vendor/lib.py"}  # parent dir matches
    assert scanned("*.md", "vendor") == {"src/app.py"}
    assert scanned("./src/") == {"docs/notes.md", "docs/deep/more.md"}
    code, out = run(capsys, "detect", "--exclude", "*.py", "src/app.py")
    assert (code, out) == (0, "")


def test_check(capsys: pytest.CaptureFixture[str]) -> None:
    code, out = run(capsys, "check", "-p", "admin", "-p", "discord", "-e", r"ask the \u0430dm1n")
    assert code == 1
    assert "block  'admin' at [8:13] (leetspeak, lookalike)" in out
    assert "<U+0430>dm1n" in out  # the disguise is shown, never echoed raw
    assert "CYRILLIC SMALL LETTER A" in out

    code, out = run(capsys, "check", "-p", "admin", "badminton")
    assert (code, out.strip()) == (0, "allow  no protected terms found")
    assert run(capsys, "check", "-p", "admin", "--mode", "contains", "badminton")[0] == 1
    assert run(capsys, "check", "-p", "discord", "--allow", "discordant", "discordant")[0] == 0


def test_check_json_and_terms_file(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    terms = tmp_path / "terms.txt"
    terms.write_text("# staff\nadmin  # comment\n\nmoderator\n", encoding="utf-8")
    code, out = run(capsys, "check", "--protect-file", str(terms), "--format", "json", "m0derat0r")
    data = json.loads(out)
    assert code == 1
    assert data["verdict"] == "block"
    assert [m["term"] for m in data["matches"]] == ["moderator"]


def test_check_needs_terms(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["check", "admin"]) == 2
    assert "nothing to protect" in capsys.readouterr().err


def test_skeleton(capsys: pytest.CaptureFixture[str]) -> None:
    assert run(capsys, "skeleton", "-e", r"p\u0430yp\u0430l") == (0, "paypal\n")
    assert run(capsys, "skeleton", "--canonical", "-e", r"\uFF30\u0430y\u200bPal") == (
        0,
        "paypal\n",
    )


def test_confusable(capsys: pytest.CaptureFixture[str]) -> None:
    code, out = run(capsys, "confusable", "-e", "paypal", r"p\u0430yp\u0430l")
    assert code == 0
    assert "p<U+0430>yp<U+0430>l" in out
    assert "confusable (same UTS #39 skeleton)" in out
    assert run(capsys, "confusable", "Admin", "admin")[0] == 0
    code, out = run(capsys, "confusable", "apple", "orange")
    assert (code, out.splitlines()[-1]) == (1, "distinct")

    code, out = run(capsys, "confusable", "--format", "json", "-e", "paypal", r"p\u0430ypal")
    data = json.loads(out)
    assert data["confusable"]
    assert data["same_canonical"]
    assert data["b"]["restriction_level"] == "minimally-restrictive"
