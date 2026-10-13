"""Conformance: the shared attack and benign corpora."""

from __future__ import annotations

from typing import Any

import pytest
from conftest import ATTACKS, BENIGN

import glyphguard as gg
from glyphguard.catalog import Severity, techniques


@pytest.mark.parametrize("vector", ATTACKS, ids=[v["name"] for v in ATTACKS])
def test_attack_detected(vector: dict[str, Any]) -> None:
    findings = gg.detect(vector["text"])
    found = {f.technique_id for f in findings}
    missing = set(vector["expect"]) - found
    assert not missing, f"missing {sorted(missing)}; got {sorted(found)}"

    if "severity" in vector:
        expected = [f for f in findings if f.technique_id in vector["expect"]]
        assert max(f.severity for f in expected) >= Severity.parse(vector["severity"])
    if "payload" in vector:
        texts = [p.text for p in gg.payloads(vector["text"])]
        assert vector["payload"] in texts
    if "sanitized" in vector:
        assert gg.sanitize(vector["text"], "llm-input").text == vector["sanitized"]


@pytest.mark.parametrize("sample", BENIGN, ids=[s["name"] for s in BENIGN])
def test_benign_is_clean(sample: dict[str, Any]) -> None:
    findings = gg.detect(sample["text"], min_severity="low")
    assert findings == [], [(f.technique_id, f.message) for f in findings]


@pytest.mark.parametrize("sample", BENIGN, ids=[s["name"] for s in BENIGN])
def test_benign_survives_llm_input(sample: dict[str, Any]) -> None:
    text = sample["text"]
    expected = text.replace("\u00a0", " ").replace("\u202f", " ")
    assert gg.sanitize(text, "llm-input").text == expected


def test_every_technique_has_a_vector() -> None:
    covered = {tid for v in ATTACKS for tid in v["expect"]}
    # Lone surrogates cannot be written in TOML; they are covered in test_detect.py.
    covered.add("GG-INV-010")
    assert set(techniques()) - covered == set()
