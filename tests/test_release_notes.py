from __future__ import annotations

import importlib.util
import re
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parent.parent


def load(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


release_notes = load("release_notes")

CHANGELOG = """# Changelog

## [Unreleased]

### Added
- Something new.

## [0.2.0] - 2026-11-01

### Fixed
- A bug.

## [0.1.0] - 2026-10-14

### Added
- Everything.

## [0.0.9]
"""


def test_extracts_one_section() -> None:
    assert release_notes.section(CHANGELOG, "0.2.0") == "### Fixed\n- A bug."
    assert release_notes.section(CHANGELOG, "0.1.0") == "### Added\n- Everything."


def test_missing_or_empty_section_fails() -> None:
    with pytest.raises(LookupError, match=re.escape("no '## [0.3.0]' section")):
        release_notes.section(CHANGELOG, "0.3.0")
    with pytest.raises(LookupError, match="empty"):
        release_notes.section(CHANGELOG, "0.0.9")


@pytest.mark.parametrize("version", ["v0.1.0", "0.1", "latest", "0.1.0-beta"])
def test_rejects_malformed_versions(version: str) -> None:
    with pytest.raises(ValueError, match="not a release version"):
        release_notes.section(CHANGELOG, version)


def test_prerelease_versions_are_accepted() -> None:
    text = CHANGELOG.replace("## [0.2.0]", "## [0.2.0rc1]")
    assert release_notes.section(text, "0.2.0rc1") == "### Fixed\n- A bug."
