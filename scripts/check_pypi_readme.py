"""Fail if a built wheel's PyPI description has repository-relative images or links.

PyPI can't resolve paths like docs/assets/... the way GitHub does; the build rewrites them
(see tool.hatch.metadata.hooks.fancy-pypi-readme in pyproject.toml). This guards that.

Usage: python scripts/check_pypi_readme.py dist/glyphguard-*.whl
"""

from __future__ import annotations

import re
import sys
import zipfile
from email.parser import Parser

URL = re.compile(r'(?:src|srcset|href)="([^"]+)"|\]\(([^)]+)\)')


def relative_urls(wheel: str) -> list[str]:
    with zipfile.ZipFile(wheel) as archive:
        name = next(n for n in archive.namelist() if n.endswith(".dist-info/METADATA"))
        description = Parser().parsestr(archive.read(name).decode("utf-8")).get_payload()
    assert isinstance(description, str)
    urls = [a or b for a, b in URL.findall(description)]
    return [u for u in urls if not u.startswith(("https://", "http://", "#", "mailto:"))]


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    bad = relative_urls(argv[1])
    for url in bad:
        print(f"::error::relative URL in the PyPI description: {url}", file=sys.stderr)
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
