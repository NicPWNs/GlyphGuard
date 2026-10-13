from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

VECTORS = Path(__file__).parent / "vectors"


def load_vectors(name: str, key: str) -> list[dict[str, Any]]:
    data = tomllib.loads((VECTORS / name).read_text(encoding="utf-8"))
    entries: list[dict[str, Any]] = data[key]
    return entries


ATTACKS = load_vectors("attacks.toml", "vector")
BENIGN = load_vectors("benign.toml", "sample")
