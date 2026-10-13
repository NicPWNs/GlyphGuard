"""``inspect()``: a full, explainable account of what a string really contains."""

from __future__ import annotations

from dataclasses import dataclass
from functools import cached_property
from typing import Any

from glyphguard import ucd
from glyphguard.catalog import Severity
from glyphguard.detect import DEFAULT_OPTIONS, Options, detect
from glyphguard.findings import Finding, Payload
from glyphguard.sanitize import sanitize


@dataclass(frozen=True, slots=True)
class CharInfo:
    index: int
    codepoint: int
    name: str
    category: str
    script: str
    techniques: tuple[str, ...]

    @property
    def label(self) -> str:
        return f"U+{self.codepoint:04X}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "codepoint": self.label,
            "name": self.name,
            "category": self.category,
            "script": self.script,
            "techniques": list(self.techniques),
        }


@dataclass(frozen=True)
class Report:
    """Everything GlyphGuard knows about a string."""

    text: str
    findings: tuple[Finding, ...]
    options: Options = DEFAULT_OPTIONS

    @property
    def max_severity(self) -> Severity | None:
        return max((f.severity for f in self.findings), default=None)

    def is_clean(self, min_severity: Severity | str = Severity.LOW) -> bool:
        """True if no finding reaches ``min_severity``."""
        floor = Severity.parse(min_severity)
        return all(f.severity < floor for f in self.findings)

    @property
    def payloads(self) -> list[Payload]:
        """Hidden content decoded from smuggling channels."""
        return [f.payload for f in self.findings if f.payload is not None]

    @cached_property
    def cleaned(self) -> str:
        """The text with every flagged code point neutralized by the ``strict`` profile.

        This is not a rendering: bidirectional reordering is not applied, so text after
        an override still appears in logical order.
        """
        return sanitize(self.text, "strict", options=self.options).text

    @cached_property
    def revealed(self) -> str:
        """The text with every flagged code point shown as a ``<U+XXXX>`` marker."""
        return sanitize(self.text, "reveal", options=self.options).text

    def chars(self, *, flagged_only: bool = False) -> list[CharInfo]:
        """Per-code-point breakdown. By default lists every non-ASCII or flagged code point."""
        flags: dict[int, list[str]] = {}
        for f in self.findings:
            for i in range(f.start, f.end):
                flags.setdefault(i, []).append(f.technique_id)
        out: list[CharInfo] = []
        for i, c in enumerate(self.text):
            cp = ord(c)
            techniques = tuple(dict.fromkeys(flags.get(i, ())))
            if techniques or (not flagged_only and not 0x20 <= cp <= 0x7E):
                out.append(
                    CharInfo(
                        i, cp, ucd.name(cp), ucd.general_category(cp), ucd.script(cp), techniques
                    )
                )
        return out

    def to_dict(self) -> dict[str, Any]:
        severity = self.max_severity
        return {
            "unicode_version": ucd.UNICODE_VERSION,
            "length": len(self.text),
            "max_severity": str(severity) if severity is not None else None,
            "findings": [f.to_dict() for f in self.findings],
            "cleaned": self.cleaned,
            "revealed": self.revealed,
            "chars": [c.to_dict() for c in self.chars()],
        }


def inspect(text: str, *, options: Options = DEFAULT_OPTIONS) -> Report:
    """Analyze ``text`` and return a :class:`Report` with findings, payloads and views."""
    return Report(text, tuple(detect(text, options=options)), options)
