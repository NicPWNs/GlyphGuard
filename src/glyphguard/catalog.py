"""The technique catalog: stable IDs and metadata for everything GlyphGuard detects."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from enum import IntEnum
from functools import cache
from importlib.resources import files


class Severity(IntEnum):
    """How much a finding should worry you. Ordered, so severities compare naturally."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: Severity | str) -> Severity:
        if isinstance(value, Severity):
            return value
        try:
            return cls[value.strip().upper()]
        except KeyError:
            choices = ", ".join(s.name.lower() for s in cls)
            raise ValueError(f"unknown severity {value!r} (expected one of: {choices})") from None

    def __str__(self) -> str:
        return self.name.lower()


@dataclass(frozen=True, slots=True)
class Technique:
    id: str
    family: str
    slug: str
    title: str
    severity: Severity
    summary: str
    cwe: tuple[str, ...]
    atlas: tuple[str, ...]
    references: tuple[str, ...]


@cache
def techniques() -> dict[str, Technique]:
    """All techniques in the catalog, keyed by ID, in catalog order."""
    raw = tomllib.loads(files("glyphguard").joinpath("catalog.toml").read_text(encoding="utf-8"))
    loaded: dict[str, Technique] = {}
    for entry in raw["technique"]:
        technique = Technique(
            id=entry["id"],
            family=entry["family"],
            slug=entry["slug"],
            title=entry["title"],
            severity=Severity.parse(entry["severity"]),
            summary=" ".join(entry["summary"].split()),
            cwe=tuple(entry.get("cwe", ())),
            atlas=tuple(entry.get("atlas", ())),
            references=tuple(entry.get("references", ())),
        )
        if technique.id in loaded:
            raise ValueError(f"duplicate technique id {technique.id}")
        loaded[technique.id] = technique
    return loaded


@cache
def _slugs() -> dict[str, str]:
    return {t.slug: t.id for t in techniques().values()}


def get(key: str) -> Technique:
    """Look up a technique by ID (``GG-SMUG-001``) or slug (``tag-smuggling``)."""
    catalog = techniques()
    found = catalog.get(key.upper()) or catalog.get(_slugs().get(key.lower(), ""))
    if found is None:
        raise KeyError(f"unknown technique {key!r}")
    return found


def resolve(keys: str | list[str] | tuple[str, ...] | set[str] | frozenset[str]) -> frozenset[str]:
    """Expand IDs, slugs and family names (``SMUG``) into a set of technique IDs."""
    if isinstance(keys, str):
        keys = [keys]
    resolved: set[str] = set()
    for key in keys:
        family = [t.id for t in techniques().values() if t.family == key.upper()]
        resolved.update(family or [get(key).id])
    return frozenset(resolved)
