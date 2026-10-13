"""The README's Python examples must run and their assertions must hold."""

from __future__ import annotations

import re
from pathlib import Path

README = Path(__file__).resolve().parent.parent / "README.md"
BLOCK = re.compile(r"```python\n(.*?)```", re.DOTALL)


def test_readme_examples_run() -> None:
    blocks = BLOCK.findall(README.read_text(encoding="utf-8"))
    assert len(blocks) >= 4
    for number, block in enumerate(blocks, 1):
        code = compile(block, f"README.md python block {number}", "exec")
        exec(code, {"__name__": "readme"})
