"""Find hidden characters written as escape sequences.

In a JSON file an MCP tool description can carry tag smuggling as ``\\uDB40\\uDC41...``:
the file is plain ASCII, so a raw scan finds nothing, yet every program that loads it
gets invisible characters. ``decode`` turns the escapes back into characters while
remembering where each one came from, so findings point at the escape in the file.

Recognized: ``\\uXXXX`` (with UTF-16 surrogate pairs combined), ``\\UXXXXXXXX`` and
``\\u{X...}``. An escaped backslash (two backslashes) is never the start of an escape.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass, replace

from glyphguard.detect import detect
from glyphguard.findings import Finding

_BS = re.escape(chr(92))
_ESCAPE = re.compile(
    rf"{_BS}{_BS}"  # an escaped backslash: kept as is
    rf"|{_BS}u([0-9A-Fa-f]{{4}})"
    rf"|{_BS}U([0-9A-Fa-f]{{8}})"
    rf"|{_BS}u\{{([0-9A-Fa-f]{{1,6}})\}}"
)
JSON_SUFFIXES = (".json", ".jsonc", ".json5", ".jsonl", ".ipynb", ".code-workspace")


@dataclass(frozen=True, slots=True)
class Decoded:
    text: str
    """The text with escapes replaced by the characters they stand for."""
    starts: tuple[int, ...]
    """For each character of ``text``, where its source begins in the original."""
    ends: tuple[int, ...]
    """For each character of ``text``, where its source ends in the original."""
    escaped: tuple[bool, ...]
    """For each character of ``text``, whether it was written as an escape."""


def decode(source: str) -> Decoded | None:
    """``source`` with its Unicode escapes decoded, or None if it has none."""
    if chr(92) not in source:
        return None
    chars: list[str] = []
    starts: list[int] = []
    ends: list[int] = []
    escaped: list[bool] = []
    pos = 0
    found = False
    for match in _ESCAPE.finditer(source):
        for i in range(pos, match.start()):
            chars.append(source[i])
            starts.append(i)
            ends.append(i + 1)
            escaped.append(False)
        hex_digits = match.group(1) or match.group(2) or match.group(3)
        cp = int(hex_digits, 16) if hex_digits else -1
        if hex_digits is None or cp > 0x10FFFF:
            for i in range(match.start(), match.end()):  # not an escape we decode
                chars.append(source[i])
                starts.append(i)
                ends.append(i + 1)
                escaped.append(False)
        else:
            found = True
            low = 0xDC00 <= cp <= 0xDFFF
            if low and escaped and escaped[-1] and 0xD800 <= ord(chars[-1]) <= 0xDBFF:
                high = ord(chars[-1])  # combine a UTF-16 surrogate pair into one character
                chars[-1] = chr(0x10000 + ((high - 0xD800) << 10) + (cp - 0xDC00))
                ends[-1] = match.end()
            else:
                chars.append(chr(cp))
                starts.append(match.start())
                ends.append(match.end())
                escaped.append(True)
        pos = match.end()
    if not found:
        return None
    for i in range(pos, len(source)):
        chars.append(source[i])
        starts.append(i)
        ends.append(i + 1)
        escaped.append(False)
    return Decoded("".join(chars), tuple(starts), tuple(ends), tuple(escaped))


def detect_escaped(source: str, *, techniques: Sequence[str] | None = None) -> list[Finding]:
    """Findings that exist only once ``source``'s escapes are decoded.

    Spans point into ``source`` and cover the escape sequences; ``codepoints`` are the
    decoded characters. Findings a raw scan also makes are not repeated.
    """
    decoded = decode(source)
    if decoded is None:
        return []
    found = detect(decoded.text, techniques=list(techniques) if techniques else None)
    results = []
    for f in found:
        if not any(decoded.escaped[f.start : f.end]):
            continue
        start, end = decoded.starts[f.start], decoded.ends[f.end - 1]
        example = next(
            source[decoded.starts[i] : decoded.ends[i]]
            for i in range(f.start, f.end)
            if decoded.escaped[i]
        )
        note = f"written as escapes such as {example}, so it is hidden in the decoded value"
        results.append(replace(f, start=start, end=end, message=f"{f.message} ({note})"))
    return results
