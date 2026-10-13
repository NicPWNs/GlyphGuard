"""Lookalike characters: UTS #39 skeletons, mixed-script analysis and restriction levels.

Two strings are *confusable* when they have the same skeleton: the string you get by
mapping every character to the prototype it looks like (``confusables.txt``). Skeletons
are for comparison only; never display them or store them as a normalized form.
"""

from __future__ import annotations

import unicodedata
from enum import IntEnum
from functools import cache, lru_cache

from glyphguard import ucd
from glyphguard._data import ucd as _t

ALL_SCRIPTS = frozenset({"*"})
"""Marker for characters that are used with every script (Common, Inherited)."""

# Script sets that UTS #39 treats as a single writing system.
_JAPANESE, _KOREAN, _HAN_BOPOMOFO = "Japanese", "Korean", "Han_with_Bopomofo"


@cache
def _prototypes() -> dict[int, str]:
    return {
        cp: "".join(map(chr, target))
        for cp, target in zip(_t.CONFUSABLE_SOURCES, _t.CONFUSABLE_TARGETS, strict=True)
    }


def prototype(char: str) -> str:
    """The prototype ``char`` looks like, or ``char`` itself if it has none."""
    return _prototypes().get(ord(char), char)


def skeleton(text: str) -> str:
    """UTS #39 skeleton of left-to-right text.

    NFD, remove default-ignorable characters, map each character to its prototype, and
    NFD again. ``skeleton("\\N{CYRILLIC SMALL LETTER A}dmin") == skeleton("admin")``.
    """
    protos = _prototypes()
    mapped = "".join(
        protos.get(ord(c), c)
        for c in unicodedata.normalize("NFD", text)
        if not ucd.is_default_ignorable(ord(c))
    )
    return unicodedata.normalize("NFD", mapped)


def is_confusable(a: str, b: str) -> bool:
    """True if ``a`` and ``b`` can be mistaken for each other (same skeleton)."""
    return skeleton(a) == skeleton(b)


@lru_cache(maxsize=8192)
def augmented_script_set(cp: int) -> frozenset[str]:
    """UTS #39 augmented script set: Script_Extensions plus the CJK writing systems."""
    scripts = set(ucd.script_extensions(cp))
    if scripts & {"Common", "Inherited"}:
        return ALL_SCRIPTS
    if "Han" in scripts:
        scripts |= {_JAPANESE, _KOREAN, _HAN_BOPOMOFO}
    if scripts & {"Hiragana", "Katakana"}:
        scripts.add(_JAPANESE)
    if "Hangul" in scripts:
        scripts.add(_KOREAN)
    if "Bopomofo" in scripts:
        scripts.add(_HAN_BOPOMOFO)
    return frozenset(scripts)


def resolved_script_set(text: str) -> frozenset[str]:
    """Intersection of the augmented script sets of every character.

    Empty means the text mixes scripts; ``ALL_SCRIPTS`` means it uses only characters
    that belong to every script (digits, punctuation, combining marks...).
    """
    resolved: frozenset[str] = ALL_SCRIPTS
    for char in text:
        scripts = augmented_script_set(ord(char))
        if scripts is ALL_SCRIPTS:
            continue
        resolved = scripts if resolved is ALL_SCRIPTS else resolved & scripts
        if not resolved:
            break
    return resolved


def is_single_script(text: str) -> bool:
    return bool(resolved_script_set(text))


def is_mixed_script(text: str) -> bool:
    """True if no single script (or CJK writing system) covers all of ``text``."""
    return not resolved_script_set(text)


def scripts_used(text: str) -> list[str]:
    """Scripts of the characters in ``text``, most frequent first (Common/Inherited ignored)."""
    counts: dict[str, int] = {}
    for char in text:
        script = ucd.script(ord(char))
        if script not in ("Common", "Inherited", "Unknown"):
            counts[script] = counts.get(script, 0) + 1
    return sorted(counts, key=lambda s: (-counts[s], s))


class RestrictionLevel(IntEnum):
    """UTS #39 restriction levels, from most to least restrictive."""

    ASCII_ONLY = 1
    SINGLE_SCRIPT = 2
    HIGHLY_RESTRICTIVE = 3
    MODERATELY_RESTRICTIVE = 4
    MINIMALLY_RESTRICTIVE = 5
    UNRESTRICTED = 6

    def __str__(self) -> str:
        return self.name.lower().replace("_", "-")


_HIGHLY_RESTRICTIVE_SETS = (
    frozenset({"Latin", "Han", "Hiragana", "Katakana"}),
    frozenset({"Latin", "Han", "Bopomofo"}),
    frozenset({"Latin", "Han", "Hangul"}),
)


def restriction_level(text: str) -> RestrictionLevel:
    """The most restrictive UTS #39 level ``text`` satisfies (for identifiers and names)."""
    if text.isascii():
        return RestrictionLevel.ASCII_ONLY
    if not all(ucd.is_identifier_allowed(ord(c)) for c in text):
        return RestrictionLevel.UNRESTRICTED
    if is_single_script(text):
        return RestrictionLevel.SINGLE_SCRIPT
    used = set(scripts_used(text))
    if any(used <= allowed for allowed in _HIGHLY_RESTRICTIVE_SETS):
        return RestrictionLevel.HIGHLY_RESTRICTIVE
    others = used - {"Latin"}
    if "Latin" in used and len(others) == 1 and not others & {"Cyrillic", "Greek"}:
        return RestrictionLevel.MODERATELY_RESTRICTIVE
    return RestrictionLevel.MINIMALLY_RESTRICTIVE


@cache
def _twins() -> dict[tuple[str, str], str]:
    """(skeleton, script) -> a character of that script with that skeleton."""
    twins: dict[tuple[str, str], str] = {}
    candidates = [*_t.CONFUSABLE_SOURCES, *range(0x21, 0x7F)]
    for cp in candidates:
        char = chr(cp)
        for script in ucd.script_extensions(cp) - {"Common", "Inherited"}:
            twins.setdefault((skeleton(char), script), char)
    return twins


def twin_in_script(char: str, script: str) -> str | None:
    """A character of ``script`` that looks like ``char``, if there is one."""
    if script == "Latin":
        return ascii_lookalike(char)
    twin = _twins().get((skeleton(char), script))
    return twin if twin is not None and twin != char else None


def _is_word_char(char: str) -> bool:
    category = unicodedata.category(char)
    return category[0] in "LM" or category == "Nd"


def fold_in_context(text: str, index: int) -> str:
    """What ``text[index]`` passes for, judged by the main script of its word.

    A Cyrillic letter in a Latin word folds to ASCII; a Latin letter hiding in a Cyrillic
    word folds to its Cyrillic twin.
    """
    char = text[index]
    if unicodedata.category(char)[0] != "L":
        return fold_char(char)  # digits fold to their value, symbols to their lookalike
    start = index
    while start > 0 and _is_word_char(text[start - 1]):
        start -= 1
    end = index + 1
    while end < len(text) and _is_word_char(text[end]):
        end += 1
    counts: dict[str, int] = {}
    for i in range(start, end):
        if i == index or unicodedata.category(text[i])[0] != "L":
            continue  # only letters decide which script a word is written in
        script = ucd.script(ord(text[i]))
        if script not in ("Common", "Inherited", "Unknown"):
            counts[script] = counts.get(script, 0) + 1
    main = max(counts, key=lambda s: (counts[s], s == "Latin"), default="Latin")
    if main != "Latin" and ucd.script(ord(char)) != main:
        twin = twin_in_script(char, main)
        if twin is not None:
            return twin
    return fold_char(char)


def fold_char(char: str) -> str:
    """What ``char`` passes for in ASCII: its lookalike, or its decimal digit, or itself."""
    lookalike = ascii_lookalike(char)
    if lookalike is not None:
        return lookalike
    if not char.isascii() and unicodedata.category(char) == "Nd":
        return str(unicodedata.decimal(char))
    return char


@cache
def _scripts_by_skeleton() -> dict[str, frozenset[str]]:
    scripts: dict[str, set[str]] = {}
    for cp in _t.CONFUSABLE_SOURCES:
        char = chr(cp)
        for script in ucd.script_extensions(cp) - {"Common", "Inherited"}:
            scripts.setdefault(skeleton(char), set()).add(script)
    for cp in range(0x20, 0x7F):  # ASCII letters are their own prototypes
        scripts.setdefault(skeleton(chr(cp)), set()).update(ucd.script_extensions(cp))
    return {key: frozenset(value) for key, value in scripts.items()}


def lookalike_scripts(skeleton_text: str) -> frozenset[str]:
    """Scripts that have a character with this skeleton."""
    return _scripts_by_skeleton().get(skeleton_text, frozenset())


@lru_cache(maxsize=8192)
def ascii_lookalike(char: str) -> str | None:
    """The ASCII letters or digits ``char`` is meant to pass for, if any.

    Covers UTS #39 prototypes (Cyrillic ``\\N{CYRILLIC SMALL LETTER A}`` -> ``a``) and
    compatibility forms (``\\N{MATHEMATICAL BOLD SMALL A}`` or fullwidth letters -> ``a``).
    Returns None for ASCII characters and for characters with no ASCII lookalike.
    """
    if char.isascii():
        return None
    for candidate in (unicodedata.normalize("NFKC", char), prototype(char)):
        if candidate != char and candidate.isascii() and candidate.isalnum():
            return candidate
    return None
