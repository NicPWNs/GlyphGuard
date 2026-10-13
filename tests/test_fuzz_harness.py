"""Keep the fuzz target honest: its invariants must hold on known inputs and random text."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from conftest import ATTACKS, BENIGN
from hypothesis import given
from hypothesis import strategies as st

ROOT = Path(__file__).resolve().parent.parent


def load_harness() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "fuzz_glyphguard", ROOT / "tests" / "fuzz" / "fuzz_glyphguard.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


harness = load_harness()


@pytest.mark.parametrize("vector", ATTACKS + BENIGN, ids=lambda v: v["name"])
def test_harness_invariants_hold_on_vectors(vector: dict[str, Any]) -> None:
    harness.check(vector["text"])


@given(st.text())
def test_harness_invariants_hold_on_random_text(text: str) -> None:
    harness.check(text)
