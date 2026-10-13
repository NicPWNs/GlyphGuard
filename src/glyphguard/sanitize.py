"""Profile-driven sanitization: neutralize what :func:`glyphguard.detect` finds."""

from __future__ import annotations

import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from functools import cache
from importlib.resources import files
from types import MappingProxyType

from glyphguard import ucd
from glyphguard.catalog import Severity, get
from glyphguard.confusables import fold_in_context
from glyphguard.detect import DEFAULT_OPTIONS, Options, detect
from glyphguard.findings import Finding

ACTIONS = frozenset({"keep", "remove", "replace", "space", "newline", "escape", "trim", "fold"})
# When findings overlap, the more destructive action wins.
_PRIORITY = {"keep": 0, "space": 1, "newline": 2, "fold": 3, "escape": 4, "replace": 5, "remove": 6}
_WHOLE_TEXT = frozenset({"GG-INV-005"})


@dataclass(frozen=True, slots=True)
class Profile:
    name: str
    description: str
    actions: Mapping[str, str]
    keep_marks: int = 2

    def action_for(self, technique_id: str) -> str:
        """Most specific action: technique ID, then family, then default."""
        if technique_id in self.actions:
            return self.actions[technique_id]
        family = get(technique_id).family
        return self.actions.get(family, self.actions.get("default", "keep"))


@cache
def profiles() -> dict[str, Profile]:
    """Built-in profiles keyed by name."""
    raw = tomllib.loads(files("glyphguard").joinpath("profiles.toml").read_text(encoding="utf-8"))
    loaded: dict[str, Profile] = {}
    for name, entry in raw["profile"].items():
        actions = dict(entry.get("actions", {}))
        for key, action in actions.items():
            if action not in ACTIONS:
                raise ValueError(f"profile {name}: unknown action {action!r} for {key}")
        loaded[name] = Profile(
            name=name,
            description=entry.get("description", ""),
            actions=MappingProxyType(actions),
            keep_marks=entry.get("keep_marks", 2),
        )
    return loaded


def get_profile(profile: str | Profile) -> Profile:
    if isinstance(profile, Profile):
        return profile
    try:
        return profiles()[profile]
    except KeyError:
        names = ", ".join(profiles())
        raise ValueError(f"unknown profile {profile!r} (expected one of: {names})") from None


@dataclass(frozen=True, slots=True)
class Change:
    """One finding that sanitization acted on."""

    technique_id: str
    start: int
    """Span in the text of the pass that made the change (pass 0 is the original input)."""
    end: int
    action: str
    original: str
    replacement: str
    pass_index: int = 0


@dataclass(frozen=True, slots=True)
class SanitizeResult:
    text: str
    original: str
    profile: str
    changes: tuple[Change, ...]

    @property
    def changed(self) -> bool:
        return self.text != self.original

    def __str__(self) -> str:
        return self.text


def _plan(text: str, finding: Finding, action: str, keep_marks: int) -> dict[int, str]:
    """Replacement for each code point of ``finding`` that ``action`` changes."""
    span = range(finding.start, finding.end)
    if action == "remove":
        return dict.fromkeys(span, "")
    if action in ("replace", "space", "newline"):
        filler = {"replace": "\ufffd", "space": " ", "newline": "\n"}[action]
        return {i: (filler if i == finding.start else "") for i in span}
    if action == "escape":
        # Printable ASCII stays readable (e.g. the "[2K" of an escape sequence), except in
        # lookalike findings, where the flagged letter itself is the disguise.
        everything = finding.technique_id.startswith("GG-CONF-")
        return {
            i: f"<U+{ord(text[i]):04X}>"
            for i in span
            if everything or not 0x20 <= ord(text[i]) <= 0x7E
        }
    if action == "fold":
        # Lookalikes become what they pass for. Info-level findings (IPA, math notation,
        # ligatures) are left alone: they are routine, not disguises.
        if finding.severity < Severity.LOW:
            return {}
        return {i: folded for i in span if (folded := fold_in_context(text, i)) != text[i]}
    if action == "trim":
        kept = 0
        plan: dict[int, str] = {}
        for i in span:
            if ucd.is_combining(ord(text[i])):
                kept += 1
                if kept > keep_marks:
                    plan[i] = ""
        return plan
    return {}


def sanitize(
    text: str,
    profile: str | Profile = "llm-input",
    *,
    options: Options = DEFAULT_OPTIONS,
    max_passes: int = 4,
) -> SanitizeResult:
    """Neutralize the techniques found in ``text`` according to ``profile``.

    Removing characters can create new adjacencies, so sanitization repeats until the
    text is stable (at most ``max_passes`` times). The result records every change.
    """
    chosen = get_profile(profile)
    current = text
    changes: list[Change] = []
    for pass_index in range(max_passes):
        ops: dict[int, tuple[int, str]] = {}
        for finding in detect(current, options=options):
            if finding.technique_id in _WHOLE_TEXT:
                continue
            action = chosen.action_for(finding.technique_id)
            if action == "trim" and finding.technique_id != "GG-MARK-001":
                action = "remove"
            if action == "keep":
                continue
            plan = _plan(current, finding, action, chosen.keep_marks)
            if not plan:
                continue
            priority = _PRIORITY["remove" if action == "trim" else action]
            for index, replacement in plan.items():
                if index not in ops or priority > ops[index][0]:
                    ops[index] = (priority, replacement)
            changes.append(
                Change(
                    technique_id=finding.technique_id,
                    start=finding.start,
                    end=finding.end,
                    action=action,
                    original=current[finding.start : finding.end],
                    replacement="".join(
                        plan.get(i, current[i]) for i in range(finding.start, finding.end)
                    ),
                    pass_index=pass_index,
                )
            )
        if not ops:
            break
        current = "".join(ops[i][1] if i in ops else c for i, c in enumerate(current))
    return SanitizeResult(current, text, chosen.name, tuple(changes))


def reveal(text: str, *, options: Options = DEFAULT_OPTIONS) -> str:
    """``text`` with every flagged code point shown as a visible ``<U+XXXX>`` marker."""
    return sanitize(text, "reveal", options=options).text
