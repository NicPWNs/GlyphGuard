"""Protected-term matching that survives lookalikes, styling, leetspeak, spacing and
invisible characters.

    >>> import glyphguard as gg
    >>> guard = gg.Guard(["admin"])
    >>> guard.check("Contact the \\N{CYRILLIC SMALL LETTER A}dm1n team").blocked
    True
    >>> guard.check("badminton club").blocked
    False
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, Literal

from glyphguard import ucd
from glyphguard.confusables import prototype

Mode = Literal["word", "contains", "exact"]
MODES: tuple[Mode, ...] = ("word", "contains", "exact")

# Leetspeak and symbol stand-ins for each letter, written as plain characters; they are
# folded like any input before use. "i" and "l" stand in for each other because capital I
# and lowercase l are identical in many fonts.
LEET = {
    "a": "4@",
    "b": "8",
    "e": "3",
    "g": "96",
    "i": "1!|l",
    "l": "1|i",
    "o": "0",
    "s": "5$",
    "t": "7+",
    "z": "2",
}

# Lookalikes that UTS #39 confusables.txt does not map to Latin letters.
_EXTRA = {
    **{0x1F170 + i: chr(0x61 + i) for i in range(26)},  # negative squared letters
    **{0x1F1E6 + i: chr(0x61 + i) for i in range(26)},  # regional indicator letters
    **dict(
        zip(
            # small capitals
            (
                0x1D00,
                0x0299,
                0x1D04,
                0x1D05,
                0x1D07,
                0xA730,
                0x0262,
                0x029C,
                0x026A,
                0x1D0A,
                0x1D0B,
                0x029F,
                0x1D0D,
                0x0274,
                0x1D0F,
                0x1D18,
                0x0280,
                0xA731,
                0x1D1B,
                0x1D1C,
                0x1D20,
                0x1D21,
                0x028F,
                0x1D22,
            ),
            "abcdefghijklmnoprstuvwyz",
            strict=True,
        )
    ),
}

LEET_CHARS = frozenset("".join(LEET.values()))

_SEPARATOR = r"[\W_]{0,3}?"


@lru_cache(maxsize=16384)
def fold(char: str) -> str:
    """The plain lowercase form ``char`` is matched as ("" for invisible characters)."""
    result = _fold_once(char)
    for _ in range(8):  # a prototype can fold further: small capital H -> h
        folded = "".join(_fold_once(c) for c in result)
        if folded == result:
            break
        result = folded
    return result


@lru_cache(maxsize=16384)
def _fold_once(char: str) -> str:
    cp = ord(char)
    if cp in _EXTRA:
        return _EXTRA[cp]
    category = ucd.general_category(cp)
    if (
        ucd.is_default_ignorable(cp)
        or ucd.is_variation_selector(cp)
        or ucd.is_tag(cp)
        or category in ("Cf", "Cc", "Mn", "Me", "Mc")
    ) and not char.isspace():
        return ""
    out = []
    for part in unicodedata.normalize("NFKD", char).casefold():
        if unicodedata.category(part)[0] == "M":
            continue
        for piece in unicodedata.normalize("NFKD", prototype(part)).casefold():
            if unicodedata.category(piece)[0] != "M":
                out.append(piece)
    return "".join(out)


def canonicalize(text: str) -> str:
    """A key for comparing names: equal keys mean the texts can pass for each other.

    Removes invisible characters and diacritics, undoes styling (fullwidth, mathematical,
    small capitals...), maps lookalikes to their prototypes and folds case, so
    ``canonicalize("\\N{CYRILLIC CAPITAL LETTER A}DMIN") == canonicalize("admin")``. Use
    it to find a new username that collides with an existing one. Like a skeleton, the
    result is for comparison only; never display it or store it in place of the text.
    """
    return _folded(text)[0]


def _folded(text: str) -> tuple[str, list[int]]:
    """``text`` folded, and for each folded character the index it came from."""
    chars: list[str] = []
    origin: list[int] = []
    for index, char in enumerate(text):
        for piece in fold(char):
            chars.append(piece)
            origin.append(index)
    return "".join(chars), origin


@dataclass(frozen=True, slots=True)
class Evidence:
    """One character in a match that was disguised, and how."""

    index: int
    codepoint: int
    kind: str
    """invisible, diacritic, lookalike, styled, leetspeak, separator or repeated."""

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "codepoint": f"U+{self.codepoint:04X}",
            "name": ucd.name(self.codepoint),
            "kind": self.kind,
        }


@dataclass(frozen=True, slots=True)
class GuardMatch:
    term: str
    start: int
    """Span of the match in the original text (code point offsets, end exclusive)."""
    end: int
    disguised: bool
    """True unless the text contains the term plainly (ignoring case)."""
    evidence: tuple[Evidence, ...] = ()

    @property
    def span(self) -> tuple[int, int]:
        return (self.start, self.end)

    @property
    def techniques(self) -> tuple[str, ...]:
        """The disguises used, e.g. ``("lookalike", "leetspeak")``."""
        return tuple(sorted({e.kind for e in self.evidence}))

    def to_dict(self) -> dict[str, Any]:
        return {
            "term": self.term,
            "start": self.start,
            "end": self.end,
            "disguised": self.disguised,
            "techniques": list(self.techniques),
            "evidence": [e.to_dict() for e in self.evidence],
        }


@dataclass(frozen=True, slots=True)
class GuardResult:
    text: str
    matches: tuple[GuardMatch, ...] = field(default=())

    @property
    def blocked(self) -> bool:
        return bool(self.matches)

    @property
    def verdict(self) -> str:
        return "block" if self.matches else "allow"

    def to_dict(self) -> dict[str, Any]:
        return {"verdict": self.verdict, "matches": [m.to_dict() for m in self.matches]}


@dataclass(frozen=True, slots=True)
class _Term:
    term: str
    mode: Mode
    pattern: re.Pattern[str]


def _compile(term: str, mode: Mode) -> re.Pattern[str]:
    folded_term, _ = _folded(term)
    if not folded_term.strip():
        raise ValueError(f"protected term {term!r} is empty after folding")
    parts = []
    first: set[str] = set()
    for char in term:
        piece = fold(char)
        if not piece:
            continue
        alternatives = {piece} | {fold(c) for c in LEET.get(piece, "")} - {""}
        options = "|".join(re.escape(a) for a in sorted(alternatives, key=len, reverse=True))
        parts.append(f"(?:{options})+" if not piece.isspace() else r"[\W_]+")
        first = first or alternatives
    # A match that starts inside a run of the first letter has an equivalent match at the
    # start of the run, which is found first. Refusing to start mid-run keeps long runs
    # ("aaaa...") linear instead of quadratic.
    not_mid_run = "".join(f"(?<!{re.escape(a)})" for a in sorted(first))
    body = f"(?P<term>{not_mid_run}{_SEPARATOR.join(parts)})"
    if mode == "word":
        body = rf"(?<![^\W_]){body}(?![^\W_])"
    elif mode == "exact":
        body = rf"^[\W_]*{body}[\W_]*$"
    return re.compile(body)


class Guard:
    """Checks text for disguised (or plain) uses of protected terms.

    Args:
        protected: Terms to protect. Each is a string, or a mapping with ``term`` and an
            optional per-term ``mode``.
        mode: ``"word"`` (default; the term must stand alone, so ``admin`` does not match
            ``badminton``), ``"contains"`` (anywhere) or ``"exact"`` (the whole text).
        allow: Words that may contain a protected term, for example ``"supportive"``
            when protecting ``"support"`` in ``contains`` mode.
    """

    def __init__(
        self,
        protected: Iterable[str | Mapping[str, str]],
        *,
        mode: Mode = "word",
        allow: Iterable[str] = (),
    ) -> None:
        self._terms: list[_Term] = []
        for item in protected:
            term = item if isinstance(item, str) else item["term"]
            term_mode = mode if isinstance(item, str) else item.get("mode", mode)
            if term_mode not in MODES:
                raise ValueError(
                    f"unknown mode {term_mode!r} (expected one of: {', '.join(MODES)})"
                )
            self._terms.append(_Term(term, term_mode, _compile(term, term_mode)))
        self._allow = {_folded(word)[0] for word in allow}

    @property
    def terms(self) -> list[str]:
        return [t.term for t in self._terms]

    def check(self, text: str) -> GuardResult:
        folded, origin = _folded(text)
        matches: list[GuardMatch] = []
        for term in self._terms:
            for match in term.pattern.finditer(folded):
                a, b = match.span("term")
                if self._allowed(folded, a, b):
                    continue
                start, end = origin[a], origin[b - 1] + 1
                matches.append(self._describe(term.term, text, start, end))
        matches.sort(key=lambda m: (m.start, m.end, m.term))
        return GuardResult(text, tuple(matches))

    def _allowed(self, folded: str, a: int, b: int) -> bool:
        if not self._allow:
            return False
        while a > 0 and (folded[a - 1].isalnum()):
            a -= 1
        while b < len(folded) and folded[b].isalnum():
            b += 1
        return folded[a:b] in self._allow

    @staticmethod
    def _describe(term: str, text: str, start: int, end: int) -> GuardMatch:
        evidence: list[Evidence] = []
        term_letters = set(term.casefold())
        term_folded = _folded(term)[0]
        for index in range(start, end):
            char = text[index]
            cp = ord(char)
            folded = fold(char)
            if not folded:
                evidence.append(Evidence(index, cp, "invisible"))
            elif not folded.isalnum():
                if char not in LEET_CHARS:
                    evidence.append(Evidence(index, cp, "separator"))
                else:
                    evidence.append(Evidence(index, cp, "leetspeak"))
            elif char.isascii():
                if char.isdigit():
                    evidence.append(Evidence(index, cp, "leetspeak"))
                elif char.casefold() not in term_letters:
                    evidence.append(Evidence(index, cp, "lookalike"))  # "rn" for "m", "l" for "i"
                elif (
                    index > start
                    and fold(text[index - 1]) == folded
                    and folded * 2 not in term_folded
                ):
                    evidence.append(Evidence(index, cp, "repeated"))
            elif (
                len(decomposed := unicodedata.normalize("NFD", char)) > 1
                and decomposed[0].isascii()
            ):
                evidence.append(Evidence(index, cp, "diacritic"))
            elif cp in _EXTRA or unicodedata.normalize("NFKC", char) != char:
                evidence.append(Evidence(index, cp, "styled"))
            else:
                evidence.append(Evidence(index, cp, "lookalike"))
        disguised = bool(evidence) or text[start:end].casefold() != term.casefold()
        return GuardMatch(term, start, end, disguised, tuple(evidence))
