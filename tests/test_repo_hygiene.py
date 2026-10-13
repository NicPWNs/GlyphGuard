"""Dogfooding: GlyphGuard's own sources must be free of what it detects.

Code and data files must be pure ASCII (non-ASCII test inputs are written as escapes), so
no hidden or lookalike character can slip into the tool that hunts for them.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import glyphguard as gg

ROOT = Path(__file__).resolve().parent.parent
ASCII_ONLY = sorted(
    p
    for pattern in (
        "src/**/*.py",
        "src/**/*.toml",
        "tests/**/*.py",
        "tests/**/*.toml",
        "scripts/*",
        ".clusterfuzzlite/*",
        ".github/**/*",
        ".pre-commit-hooks.yaml",
        "pyproject.toml",
        "README.md",
        "CONTRIBUTING.md",
        "SECURITY.md",
        "CHANGELOG.md",
    )
    for p in ROOT.glob(pattern)
    if "_data" not in p.parts and p.is_file()
)
PROSE = sorted(ROOT.glob("docs/*.md"))  # may show lookalike letters as examples, never hidden ones


@pytest.mark.parametrize("path", ASCII_ONLY, ids=lambda p: p.relative_to(ROOT).as_posix())
def test_source_is_ascii(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    bad = [
        (i, f"U+{ord(c):04X}")
        for i, c in enumerate(text)
        if ord(c) > 0x7E or (ord(c) < 0x20 and c not in "\t\n\r")
    ]
    assert not bad, f"non-ASCII or control characters (write them as escapes): {bad[:10]}"


@pytest.mark.parametrize(
    "path", [*ASCII_ONLY, *PROSE], ids=lambda p: p.relative_to(ROOT).as_posix()
)
def test_no_findings(path: Path) -> None:
    findings = gg.detect(path.read_text(encoding="utf-8"), min_severity="low")
    if path in PROSE:
        findings = [f for f in findings if f.technique.family != "CONF"]
    assert not findings, [(f.technique_id, f.start, f.message) for f in findings]
