"""The Python examples in the README and the guide must run and their assertions must hold."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

import glyphguard as gg

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
DOCS = {README: 1, ROOT / "docs" / "guide.md": 6}  # document -> minimum number of examples
BLOCK = re.compile(r"```python\n(.*?)```", re.DOTALL)


def test_readme_technique_count_matches_catalog() -> None:
    claimed = re.search(r"^(\d+) techniques in", README.read_text(encoding="utf-8"), re.M)
    assert claimed is not None
    assert int(claimed.group(1)) == len(gg.techniques())


@pytest.mark.parametrize("path", DOCS, ids=lambda p: p.relative_to(ROOT).as_posix())
def test_examples_run(path: Path) -> None:
    blocks = BLOCK.findall(path.read_text(encoding="utf-8"))
    assert len(blocks) >= DOCS[path]
    for number, block in enumerate(blocks, 1):
        code = compile(block, f"{path.name} python block {number}", "exec")
        exec(code, {"__name__": "docs_example"})


def test_guide_contents_links_resolve() -> None:
    guide = (ROOT / "docs" / "guide.md").read_text(encoding="utf-8")
    anchors = {
        re.sub(r"[^a-z0-9 -]", "", heading.lower()).replace(" ", "-")
        for heading in re.findall(r"^#{2,3} (.+)$", guide, re.M)
    }
    for anchor in re.findall(r"\]\(#([a-z0-9-]+)\)", guide):
        assert anchor in anchors, anchor
