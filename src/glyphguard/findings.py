"""Result types shared by every GlyphGuard API."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from glyphguard import ucd
from glyphguard.catalog import Severity, Technique, get


@dataclass(frozen=True, slots=True)
class Payload:
    """Hidden content recovered from a smuggling channel."""

    channel: str
    """Encoding that carried it, e.g. ``"tags"``, ``"variation-selectors"``, ``"osc-8"``."""
    data: bytes
    """Raw recovered bytes."""

    @property
    def text(self) -> str:
        """The payload decoded as UTF-8, with undecodable bytes replaced."""
        return self.data.decode("utf-8", errors="replace")

    def to_dict(self) -> dict[str, Any]:
        return {"channel": self.channel, "text": self.text, "hex": self.data.hex()}


@dataclass(frozen=True, slots=True)
class Finding:
    """One occurrence of a technique, located by code point offsets into the input."""

    technique_id: str
    start: int
    """Index of the first code point (inclusive)."""
    end: int
    """Index after the last code point (exclusive)."""
    severity: Severity
    message: str
    codepoints: tuple[int, ...] = field(default=())
    payload: Payload | None = None

    @property
    def technique(self) -> Technique:
        return get(self.technique_id)

    @property
    def family(self) -> str:
        return self.technique.family

    @property
    def span(self) -> tuple[int, int]:
        return (self.start, self.end)

    def labels(self, limit: int = 8) -> list[str]:
        """``U+XXXX NAME`` labels for the distinct code points involved."""
        distinct = list(dict.fromkeys(self.codepoints))
        shown = [ucd.label(cp) for cp in distinct[:limit]]
        if len(distinct) > limit:
            shown.append(f"... {len(distinct) - limit} more")
        return shown

    def to_dict(self) -> dict[str, Any]:
        return {
            "technique": self.technique_id,
            "title": self.technique.title,
            "family": self.family,
            "severity": str(self.severity),
            "start": self.start,
            "end": self.end,
            "message": self.message,
            "codepoints": [f"U+{cp:04X}" for cp in self.codepoints],
            "payload": self.payload.to_dict() if self.payload else None,
        }
