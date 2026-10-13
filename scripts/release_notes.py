"""Print the CHANGELOG.md section for a release, for the release workflow.

Usage: python scripts/release_notes.py 0.1.0 > notes.md

Exits 1 (with a message on stderr) if the version is malformed or CHANGELOG.md has no
non-empty ``## [<version>]`` section, so a release can't ship without notes.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

CHANGELOG = Path(__file__).resolve().parent.parent / "CHANGELOG.md"
VERSION = re.compile(r"\d+\.\d+\.\d+(?:(?:a|b|rc)\d+)?")


def section(changelog: str, version: str) -> str:
    """The body of the ``## [version]`` section, without its heading."""
    if not VERSION.fullmatch(version):
        raise ValueError(f"{version!r} is not a release version like 1.2.3 or 1.2.3rc1")
    heading = re.compile(rf"^## \[{re.escape(version)}\](?:\s|$)")
    lines = changelog.splitlines()
    for i, line in enumerate(lines):
        if heading.match(line):
            body = []
            for following in lines[i + 1 :]:
                if following.startswith("## "):
                    break
                body.append(following)
            text = "\n".join(body).strip()
            if text:
                return text
            raise LookupError(f"CHANGELOG.md section for {version} is empty")
    raise LookupError(f"CHANGELOG.md has no '## [{version}]' section; add one before releasing")


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    try:
        print(section(CHANGELOG.read_text(encoding="utf-8"), argv[1]))
    except (ValueError, LookupError) as exc:
        print(f"release_notes: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
