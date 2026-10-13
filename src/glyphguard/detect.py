"""Detection engine: find catalog techniques in text, with spans, evidence and payloads.

Performance model: one compiled regular expression locates the maximal runs of
"interesting" code points (controls, format characters, marks, unassigned, private-use,
non-ASCII whitespace, default-ignorables, blank glyphs). Every technique in the catalog
involves at least one such code point, so detectors only visit those runs and ordinary
letters, digits and punctuation in any script cost almost nothing.
"""

from __future__ import annotations

import base64
import binascii
import re
import sys
from array import array
from collections.abc import Callable, Iterable, Iterator, Sequence
from dataclasses import dataclass
from functools import cache

from glyphguard import stego, ucd
from glyphguard.catalog import Severity, resolve
from glyphguard.findings import Finding, Payload

INFO, LOW, MEDIUM, HIGH, CRITICAL = (
    Severity.INFO,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
)


@dataclass(frozen=True, slots=True)
class Options:
    """Tunable detection thresholds."""

    max_marks: int = 4
    """Combining marks allowed on one base before it counts as Zalgo. Scripts that stack
    marks heavily (Tibetan, Hebrew with cantillation...) are allowed twice as many."""
    binary_run_min: int = 8
    """Shortest run of invisible characters treated as a binary-encoded payload."""
    private_use_run_min: int = 4
    """Shortest run of private-use characters treated as a hidden payload."""


DEFAULT_OPTIONS = Options()

ZERO_WIDTH = frozenset({0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x180E})
INVISIBLE_OPERATORS = frozenset(range(0x2061, 0x2065))
BLANK_GLYPHS = frozenset({0x115F, 0x1160, 0x3164, 0xFFA0, 0x2800})
BIDI_OVERRIDES = frozenset({0x202D, 0x202E})
BIDI_EMBEDDINGS = frozenset({0x202A, 0x202B, 0x202C, 0x2066, 0x2067, 0x2068, 0x2069})
BIDI_MARKS = frozenset({0x200E, 0x200F, 0x061C})
BIDI_ALL = BIDI_OVERRIDES | BIDI_EMBEDDINGS | BIDI_MARKS
LINE_SEPARATORS = frozenset({0x85, 0x2028, 0x2029})
TYPOGRAPHIC_SPACES = frozenset({0xA0, 0x2007, 0x202F})
ASCII_WHITESPACE = frozenset({0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20})
PARAGRAPH_SEPARATORS = frozenset({0x0A, 0x0D, 0x1C, 0x1D, 0x1E, 0x85, 0x2029})

# Scripts where ZWJ/ZWNJ legitimately control joining or conjunct formation.
JOINING_SCRIPTS = frozenset(
    """
    Arabic Syriac Mongolian Nko Mandaic Manichaean Psalter_Pahlavi Adlam Hanifi_Rohingya
    Sogdian Old_Uyghur Phags_Pa Devanagari Bengali Gurmukhi Gujarati Oriya Tamil Telugu
    Kannada Malayalam Sinhala Khmer Myanmar Tibetan Javanese Balinese Sundanese Tai_Tham
    Grantha Newa Sharada Tirhuta Takri Kaithi Syloti_Nagri Chakma Brahmi Limbu Meetei_Mayek
    Lepcha Saurashtra Batak Buginese Rejang Cham Tai_Viet Ahom Dogra Nandinagari Modi Khojki
    Khudawadi Mahajani Siddham Bhaiksuki Marchen Masaram_Gondi Gunjala_Gondi Kawi
    Tulu_Tigalari
    """.split()
)
RTL_SCRIPTS = frozenset(
    """
    Arabic Hebrew Syriac Thaana Nko Samaritan Mandaic Adlam Hanifi_Rohingya Yezidi Garay
    Mende_Kikakui Imperial_Aramaic Phoenician Avestan Old_South_Arabian Old_North_Arabian
    Nabataean Palmyrene Hatran Elymaic Sogdian Old_Sogdian Chorasmian Kharoshthi Lydian
    Old_Hungarian Old_Turkic Manichaean Psalter_Pahlavi Inscriptional_Pahlavi
    Inscriptional_Parthian Cypriot Meroitic_Cursive Meroitic_Hieroglyphs
    """.split()
)
# Scripts that routinely stack several marks on one base.
HEAVY_MARK_SCRIPTS = frozenset(
    """
    Tibetan Hebrew Arabic Syriac Devanagari Myanmar Khmer Balinese Javanese Tai_Tham Lao Thai
    Kannada Telugu Malayalam Inherited
    """.split()
)

# Combining marks are deliberately absent: they are common in many scripts and are
# located by the dedicated, linear-time patterns in _mark_patterns() instead.
_UTF32 = "utf-32-le" if sys.byteorder == "little" else "utf-32-be"
_U = chr(92) + "U"  # regex escape prefix for \\UXXXXXXXX
_TRIGGER_CATEGORIES = frozenset({"Cc", "Cf", "Cn", "Co", "Cs", "Zl", "Zp", "Zs"})
_ASCII_SUSPICIOUS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_ESCAPE_SEQUENCE = re.compile(
    r"""
      (?P<csi>(?:\x1b\[|\x9b)[\x30-\x3f]*[\x20-\x2f]*[\x40-\x7e]?)
    | (?P<osc>(?:\x1b\]|\x9d)[^\x07\x1b\x9c]*(?:\x07|\x1b\\|\x9c)?)
    | (?P<string>(?:\x1b[P_^X]|[\x90\x98\x9e\x9f])[^\x1b\x9c]*(?:\x1b\\|\x9c)?)
    | (?P<other>\x1b[\x20-\x2f]*[\x30-\x7e])
    """,
    re.VERBOSE,
)


@cache
def _trigger_pattern() -> re.Pattern[str]:
    """Regex matching maximal runs of code points that any detector may act on."""
    ranges = ucd.category_ranges(_TRIGGER_CATEGORIES)
    ranges += ucd.property_ranges("DEFAULT_IGNORABLE")
    ranges += ucd.property_ranges("WHITE_SPACE")
    ranges += [(cp, cp) for cp in BLANK_GLYPHS]
    excluded = (0x09, 0x0A, 0x0D, 0x20)  # tab, newlines and space never matter on their own
    pieces: list[tuple[int, int]] = []
    for low, end in sorted(ranges):
        start = low
        for cp in excluded:
            if start <= cp <= end:
                if start < cp:
                    pieces.append((start, cp - 1))
                start = cp + 1
        if start <= end:
            pieces.append((start, end))
    merged: list[tuple[int, int]] = []
    for start, end in sorted(pieces):
        if merged and start <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return re.compile(f"{_any_of(merged)}+")


def _char_class(ranges: list[tuple[int, int]]) -> str:
    """Body of a regex character class covering the inclusive ``ranges``."""
    return "".join(
        f"{_U}{start:08X}" if start == end else f"{_U}{start:08X}-{_U}{end:08X}"
        for start, end in ranges
    )


def _any_of(ranges: list[tuple[int, int]]) -> str:
    """A fast single-character matcher for ``ranges``.

    ``re`` compiles a BMP-only class to a bitmap, but a class with astral ranges to a
    linear list that every character must walk. Splitting the two and guarding the
    astral part keeps the common case (BMP text) at bitmap speed.
    """
    bmp = [(a, min(b, 0xFFFF)) for a, b in ranges if a <= 0xFFFF]
    astral = [(max(a, 0x10000), b) for a, b in ranges if b >= 0x10000]
    parts = []
    if bmp:
        parts.append(f"[{_char_class(bmp)}]")
    if astral:
        parts.append(f"(?=[{_U}00010000-{_U}0010FFFF])[{_char_class(astral)}]")
    return f"(?:{'|'.join(parts)})"


@cache
def _mark_patterns(max_marks: int) -> tuple[re.Pattern[str], ...]:
    """Linear-time patterns for the only mark situations that can be findings.

    Each match is a seed inside a cluster of marks: a stack longer than ``max_marks``
    (heavier limits are verified per script afterwards), an overlay mark, or a mark at
    the start of the text or after a control or separator.
    """
    marks = _any_of(ucd.category_ranges(frozenset({"Mn", "Me", "Mc"})))
    overlays = _any_of(ucd.property_ranges("OVERLAY_MARK"))
    controls = _char_class([*ucd.category_ranges(frozenset({"Cc"})), (0x2028, 0x2029)])
    return (
        re.compile(f"{marks}{{{max_marks + 1},}}+"),
        re.compile(overlays),
        re.compile(f"(?:^|(?<=[{controls}])){marks}"),
    )


def _codepoints(text: str) -> array[int]:
    """Code points of ``text`` (lone surrogates included) as a compact int array."""
    cps = array("I")
    cps.frombytes(text.encode(_UTF32, "surrogatepass"))
    return cps


class _Text:
    __slots__ = ("cps", "n", "runs", "text")

    def __init__(self, text: str, runs: list[tuple[int, int]]) -> None:
        self.text = text
        self.cps = _codepoints(text)
        self.n = len(self.cps)
        self.runs = runs
        """Maximal (start, end) spans of interesting code points."""

    def positions(self) -> Iterator[int]:
        for start, end in self.runs:
            yield from range(start, end)

    def finding(
        self,
        technique_id: str,
        start: int,
        end: int,
        severity: Severity,
        message: str,
        payload: Payload | None = None,
    ) -> Finding:
        return Finding(
            technique_id, start, end, severity, message, tuple(self.cps[start:end]), payload
        )

    def describe(self, start: int, end: int) -> str:
        distinct = list(dict.fromkeys(self.cps[start:end]))
        labels = ", ".join(ucd.label(cp) for cp in distinct[:3])
        if len(distinct) > 3:
            labels += ", ..."
        count = end - start
        return labels if count == 1 else f"{count} characters: {labels}"


Item = tuple[int, str, Severity]
"""(index, technique ID, severity) for one flagged code point, before grouping."""


def _group(t: _Text, items: Iterable[Item], context: str = "") -> Iterator[Finding]:
    """Merge consecutive flagged code points with the same technique and severity."""
    run: list[Item] = []

    def flush() -> Iterator[Finding]:
        if run:
            start, technique_id, severity = run[0]
            end = run[-1][0] + 1
            suffix = f" {context}" if context else ""
            yield t.finding(technique_id, start, end, severity, t.describe(start, end) + suffix)

    for item in items:
        if run and (item[0] != run[-1][0] + 1 or item[1:] != run[-1][1:]):
            yield from flush()
            run = []
        run.append(item)
    yield from flush()


def _prev_base(cps: Sequence[int], i: int) -> int | None:
    """Index of the nearest preceding character that is not a mark, selector or modifier."""
    j = i - 1
    while j >= 0 and (
        ucd.is_mark(cps[j]) or ucd.is_variation_selector(cps[j]) or ucd.is_emoji_modifier(cps[j])
    ):
        j -= 1
    return j if j >= 0 else None


def _benign_joiner(cps: Sequence[int], i: int) -> bool:
    """ZWJ inside an emoji ZWJ sequence, or ZWJ/ZWNJ after a letter of a joining script.

    In joining scripts the joiner may also end a word (e.g. Malayalam chillu forms), so it
    is accepted before the end of text or a non-letter, but not before a letter of a
    different script, which is how joiners are abused to split words.
    """
    if cps[i] not in (0x200C, 0x200D):
        return False
    prev = _prev_base(cps, i)
    if prev is None:
        return False
    a = cps[prev]
    b = cps[i + 1] if i + 1 < len(cps) else None
    if (
        cps[i] == 0x200D
        and b is not None
        and ucd.is_extended_pictographic(a)
        and (ucd.is_extended_pictographic(b) or (b > 0x7F and ucd.is_emoji_component(b)))
    ):
        return True
    if ucd.general_category(a)[0] != "L":
        return False
    joining = ucd.script_extensions(a) & JOINING_SCRIPTS
    if not joining:
        return False
    if b is None or ucd.general_category(b)[0] not in "LM":
        return True
    return bool(joining & ucd.script_extensions(b))


def _preview(data: bytes, limit: int = 60) -> str:
    text = data.decode("utf-8", errors="replace")
    shown = text if len(text) <= limit else text[:limit] + "..."
    return ascii(shown)


# --- INV + SMUG-003: invisible characters --------------------------------------------


def _invisible_kind(cps: Sequence[int], i: int) -> str | None:
    cp = cps[i]
    if cp in ZERO_WIDTH:
        return None if _benign_joiner(cps, i) else "GG-INV-001"
    if cp in INVISIBLE_OPERATORS:
        return "GG-INV-002"
    if (
        ucd.is_default_ignorable(cp)
        and cp not in BLANK_GLYPHS
        and not ucd.is_variation_selector(cp)
        and not ucd.is_tag(cp)
        and not ucd.is_bidi_control(cp)
    ):
        return "GG-INV-003"
    return None


def _detect_invisibles(t: _Text, opts: Options) -> Iterator[Finding]:
    cps = t.cps
    for run_start, run_end in t.runs:
        i = run_start
        while i < run_end:
            if i == 0 and cps[0] == 0xFEFF:
                yield t.finding("GG-INV-001", 0, 1, INFO, "Leading byte-order mark (U+FEFF)")
                i = 1
                continue
            if _invisible_kind(cps, i) is None:
                i += 1
                continue
            start = i
            kinds: list[str] = []
            while i < run_end and (k := _invisible_kind(cps, i)) is not None:
                kinds.append(k)
                i += 1
            yield from _invisible_run(t, start, i, kinds, opts)


def _invisible_run(
    t: _Text, start: int, end: int, kinds: list[str], opts: Options
) -> Iterator[Finding]:
    run = t.text[start:end]
    if len(run) >= opts.binary_run_min and len(set(run)) <= 4:
        data = stego.decode_binary(run)
        if data is not None:
            yield t.finding(
                "GG-SMUG-003",
                start,
                end,
                CRITICAL,
                f"{len(run)} invisible characters decode to hidden text {_preview(data)}",
                Payload("invisible-binary", data),
            )
        else:
            yield t.finding(
                "GG-SMUG-003",
                start,
                end,
                HIGH,
                f"Run of {len(run)} invisible characters from a {len(set(run))}-symbol "
                "alphabet, consistent with binary steganography",
            )
        return
    items: list[Item] = []
    for offset, kind in enumerate(kinds):
        cp = t.cps[start + offset]
        severity = MEDIUM if kind != "GG-INV-003" or ucd.general_category(cp) == "Cn" else LOW
        items.append((start + offset, kind, severity))
    yield from _group(t, items)


def _detect_blank(t: _Text, opts: Options) -> Iterator[Finding]:
    cps = t.cps
    items: list[Item] = []
    for i in t.positions():
        cp = cps[i]
        if cp not in BLANK_GLYPHS:
            continue
        # Hangul fillers are legitimate inside old-Hangul jamo sequences.
        if cp == 0x115F and i + 1 < t.n and 0x1160 <= cps[i + 1] <= 0x11A7:
            continue
        if cp == 0x1160 and i > 0 and 0x1100 <= cps[i - 1] <= 0x115F:
            continue
        items.append((i, "GG-INV-004", MEDIUM))
    yield from _group(t, items, "(renders as blank)")

    if (
        t.n
        and all(_renders_blank(cp) for cp in cps)
        and any(cp not in ASCII_WHITESPACE for cp in cps)
    ):
        yield t.finding(
            "GG-INV-005",
            0,
            t.n,
            MEDIUM,
            f"All {t.n} characters are invisible or blank; the text displays as nothing",
        )


def _renders_blank(cp: int) -> bool:
    return (
        ucd.is_white_space(cp)
        or ucd.is_default_ignorable(cp)
        or cp in BLANK_GLYPHS
        or ucd.is_tag(cp)
        or ucd.is_variation_selector(cp)
        or ucd.general_category(cp) in ("Cc", "Cf", "Zl", "Zp", "Zs")
    )


def _detect_codepoint_classes(t: _Text, opts: Options) -> Iterator[Finding]:
    """Whitespace, noncharacters, unassigned, private-use and surrogate code points."""
    cps = t.cps
    items: list[Item] = []
    for run_start, run_end in t.runs:
        i = run_start
        while i < run_end:
            cp = cps[i]
            category = ucd.general_category(cp)
            if category == "Co":
                start = i
                while i < run_end and ucd.general_category(cps[i]) == "Co":
                    i += 1
                if i - start >= opts.private_use_run_min:
                    yield t.finding(
                        "GG-SMUG-004",
                        start,
                        i,
                        HIGH,
                        f"Run of {i - start} private-use characters, which editors usually "
                        "show as blank; possible hidden payload",
                    )
                else:
                    items.extend((k, "GG-INV-009", LOW) for k in range(start, i))
                continue
            if category == "Cs":
                items.append((i, "GG-INV-010", HIGH))
            elif ucd.is_noncharacter(cp):
                items.append((i, "GG-INV-007", MEDIUM))
            elif category == "Cn" and not ucd.is_default_ignorable(cp) and not ucd.is_tag(cp):
                items.append((i, "GG-INV-008", LOW))
            elif (
                ucd.is_white_space(cp) and cp not in ASCII_WHITESPACE and cp not in LINE_SEPARATORS
            ):
                items.append((i, "GG-INV-006", INFO if cp in TYPOGRAPHIC_SPACES else LOW))
            i += 1
    yield from _group(t, items)


# --- SMUG: tags and variation selectors -----------------------------------------------


def _valid_emoji_tag_sequence(cps: Sequence[int], start: int, end: int) -> bool:
    """UTS #51 subdivision flag: U+1F3F4, 2-7 tag letters/digits, then CANCEL TAG."""
    body = cps[start : end - 1]
    return (
        start > 0
        and cps[start - 1] == 0x1F3F4
        and cps[end - 1] == stego.TAG_CANCEL
        and 2 <= len(body) <= 7
        and all(0xE0030 <= c <= 0xE0039 or 0xE0061 <= c <= 0xE007A for c in body)
    )


def _detect_tags(t: _Text, opts: Options) -> Iterator[Finding]:
    cps = t.cps
    for run_start, run_end in t.runs:
        i = run_start
        while i < run_end:
            if not ucd.is_tag(cps[i]):
                i += 1
                continue
            start = i
            while i < run_end and ucd.is_tag(cps[i]):
                i += 1
            if _valid_emoji_tag_sequence(cps, start, i):
                continue
            data = stego.decode_tags(t.text[start:i])
            letters = sum(1 for b in data if chr(b).isalnum())
            message = f"{i - start} invisible tag characters"
            message += f" carrying hidden text {_preview(data)}" if data else ""
            yield t.finding(
                "GG-SMUG-001",
                start,
                i,
                CRITICAL if letters >= 2 else HIGH,
                message,
                Payload("tags", data) if data else None,
            )


def _valid_selector(base: int | None, selector: int) -> bool:
    if base is None:
        return False
    if ucd.is_valid_variation_sequence(base, selector):
        return True
    if 0xE0100 <= selector <= 0xE01EF:
        return ucd.is_ideograph(base)
    if selector in (0xFE0E, 0xFE0F):
        return ucd.is_extended_pictographic(base)
    if 0x180B <= selector <= 0x180F:
        return ucd.script(base) == "Mongolian"
    return False


def _detect_variation_selectors(t: _Text, opts: Options) -> Iterator[Finding]:
    cps = t.cps
    for run_start, run_end in t.runs:
        i = run_start
        while i < run_end:
            if not ucd.is_variation_selector(cps[i]):
                i += 1
                continue
            start = i
            while i < run_end and ucd.is_variation_selector(cps[i]):
                i += 1
            yield from _selector_run(t, start, i)


def _selector_run(t: _Text, start: int, end: int) -> Iterator[Finding]:
    cps = t.cps
    base = cps[start - 1] if start > 0 else None
    count = end - start
    if count == 1:
        if not _valid_selector(base, cps[start]):
            yield t.finding(
                "GG-SMUG-002",
                start,
                end,
                LOW,
                f"{t.describe(start, end)} with no valid base character",
            )
        return
    run = t.text[start:end]
    candidates = [stego.decode_variation_selectors(run)]
    if _valid_selector(base, cps[start]):
        candidates.append(stego.decode_variation_selectors(run[1:]))
    data = max(candidates, key=stego.plausibility)
    payload = Payload("variation-selectors", data)
    if len(data) >= 2 and stego.printable_ratio(data) >= 0.9:
        yield t.finding(
            "GG-SMUG-002",
            start,
            end,
            CRITICAL,
            f"{count} variation selectors decode to hidden text {_preview(data)}",
            payload,
        )
    else:
        yield t.finding(
            "GG-SMUG-002",
            start,
            end,
            HIGH if count >= 3 else MEDIUM,
            f"{count} consecutive variation selectors ({len(data)} hidden bytes)",
            payload,
        )


# --- BIDI ---------------------------------------------------------------------------


def _paragraphs(cps: Sequence[int]) -> Iterator[tuple[int, int]]:
    start = 0
    for i, cp in enumerate(cps):
        if cp in PARAGRAPH_SEPARATORS:
            yield start, i
            start = i + 1
    yield start, len(cps)


def _has_rtl(cps: Sequence[int], start: int, end: int) -> bool:
    return any(
        ucd.general_category(cp)[0] == "L" and ucd.script(cp) in RTL_SCRIPTS
        for cp in cps[start:end]
    )


def _detect_bidi(t: _Text, opts: Options) -> Iterator[Finding]:
    cps = t.cps
    if not any(cps[i] in BIDI_ALL for i in t.positions()):
        return
    for start, end in _paragraphs(cps):
        items: list[Item] = []
        stack: list[tuple[int, str]] = []
        rtl: bool | None = None
        for i in range(start, end):
            cp = cps[i]
            if cp in BIDI_OVERRIDES:
                items.append((i, "GG-BIDI-001", HIGH))
                stack.append((i, "override"))
            elif cp in BIDI_EMBEDDINGS:
                items.append((i, "GG-BIDI-002", MEDIUM))
                if cp in (0x202A, 0x202B):
                    stack.append((i, "embedding"))
                elif cp in (0x2066, 0x2067, 0x2068):
                    stack.append((i, "isolate"))
                elif cp == 0x202C:
                    if stack and stack[-1][1] != "isolate":
                        stack.pop()
                elif any(kind == "isolate" for _, kind in stack):
                    while stack.pop()[1] != "isolate":
                        pass
            elif cp in BIDI_MARKS:
                if rtl is None:
                    rtl = _has_rtl(cps, start, end)
                items.append((i, "GG-BIDI-004", INFO if rtl else LOW))
        yield from _group(t, items)
        for index, kind in stack:
            yield t.finding(
                "GG-BIDI-003",
                index,
                index + 1,
                HIGH,
                f"{kind.capitalize()} U+{cps[index]:04X} is never closed; reordering leaks to "
                "the end of the line",
            )


# --- CTRL ---------------------------------------------------------------------------


def _classify_escape(match: re.Match[str]) -> tuple[Severity, str, Payload | None]:
    seq = match.group()
    if match.lastgroup == "osc":
        body = seq[2:] if seq.startswith("\x1b") else seq[1:]
        body = body.rstrip("\x07\x9c").removesuffix("\x1b\\")
        command, _, rest = body.partition(";")
        if command == "52":
            data = rest.partition(";")[2]
            try:
                decoded = base64.b64decode(data, validate=True)
            except (binascii.Error, ValueError):
                decoded = data.encode("utf-8", errors="replace")
            return CRITICAL, "OSC 52 sequence writes to the clipboard", Payload("osc-52", decoded)
        if command == "8":
            url = rest.partition(";")[2]
            if url:
                return (
                    HIGH,
                    f"OSC 8 hyperlink to {_preview(url.encode())} hidden behind display text",
                    Payload("osc-8", url.encode("utf-8", errors="replace")),
                )
            return MEDIUM, "OSC 8 hyperlink terminator", None
        # The command comes from untrusted input: never put it in a message unescaped.
        label = command if command.isascii() and command.isdigit() else ascii(command)
        return MEDIUM, f"OSC {label} sequence (e.g. sets the window title)", None
    if match.lastgroup == "csi":
        final = seq[-1]
        params = seq[2:-1] if seq.startswith("\x1b") else seq[1:-1]
        if final == "m":
            if "8" in params.split(";"):
                return HIGH, "SGR 8 sequence conceals the following text", None
            return MEDIUM, "SGR sequence changes text styling", None
        return HIGH, f"CSI sequence {seq!a} can move the cursor or erase text", None
    if match.lastgroup == "string":
        return HIGH, "Device control or application string sequence", None
    if seq == "\x1bc":
        return HIGH, "ESC c resets the terminal", None
    return MEDIUM, f"Escape sequence {seq!a}", None


def _detect_controls(t: _Text, opts: Options) -> Iterator[Finding]:
    cps = t.cps
    covered: set[int] = set()
    if "\x1b" in t.text or any(0x90 <= cps[i] <= 0x9F for i in t.positions()):
        for match in _ESCAPE_SEQUENCE.finditer(t.text):
            severity, message, payload = _classify_escape(match)
            covered.update(range(match.start(), match.end()))
            yield t.finding("GG-CTRL-003", match.start(), match.end(), severity, message, payload)

    items: list[Item] = []
    for i in t.positions():
        cp = cps[i]
        if i in covered:
            continue
        if cp < 0x20 or cp == 0x7F:
            if cp in (0x00, 0x08, 0x7F):
                severity = HIGH
            elif cp in (0x0B, 0x0C):
                severity = LOW
            else:
                severity = MEDIUM
            items.append((i, "GG-CTRL-001", severity))
        elif cp in LINE_SEPARATORS:
            items.append((i, "GG-CTRL-004", MEDIUM))
        elif 0x80 <= cp <= 0x9F:
            items.append((i, "GG-CTRL-002", HIGH))
    yield from _group(t, items)


# --- MARK ---------------------------------------------------------------------------


def _in_cluster(cp: int) -> bool:
    return ucd.is_mark(cp) or ucd.is_variation_selector(cp)


def _detect_marks(t: _Text, opts: Options) -> Iterator[Finding]:
    cps = t.cps
    seen: set[int] = set()
    for pattern in _mark_patterns(opts.max_marks):
        for match in pattern.finditer(t.text):
            # Expand the seed to its whole cluster; the character before it is the base.
            start, end = match.start(), match.end()
            while start > 0 and _in_cluster(cps[start - 1]):
                start -= 1
            if start in seen:
                continue
            seen.add(start)
            while end < t.n and _in_cluster(cps[end]):
                end += 1
            marks = [k for k in range(start, end) if ucd.is_combining(cps[k])]
            if marks:
                yield from _mark_findings(t, start - 1 if start > 0 else None, marks, opts)


def _mark_findings(
    t: _Text, base: int | None, marks: list[int], opts: Options
) -> Iterator[Finding]:
    cps = t.cps
    start, end = marks[0], marks[-1] + 1
    if base is None or ucd.general_category(cps[base]) in ("Cc", "Zl", "Zp"):
        yield t.finding(
            "GG-MARK-003",
            start,
            end,
            LOW,
            f"{t.describe(start, end)} with no base character",
        )

    overlays: list[Item] = [
        (k, "GG-MARK-002", MEDIUM)
        for k in marks
        if ucd.is_overlay_mark(cps[k]) and ucd.script_extensions(cps[k]) == {"Inherited"}
    ]
    yield from _group(t, overlays, "drawn through the preceding letter")

    limit = opts.max_marks
    if base is not None and ucd.script(cps[base]) in HEAVY_MARK_SCRIPTS:
        limit *= 2
    if len(marks) > limit:
        severity = HIGH if len(marks) > 3 * limit else MEDIUM
        where = ucd.label(cps[base]) if base is not None else "nothing"
        yield t.finding(
            "GG-MARK-001",
            start,
            end,
            severity,
            f"{len(marks)} combining marks stacked on {where} (limit {limit})",
        )


# --- Public API ---------------------------------------------------------------------

Detector = Callable[[_Text, Options], Iterable[Finding]]

DETECTORS: tuple[Detector, ...] = (
    _detect_invisibles,
    _detect_blank,
    _detect_codepoint_classes,
    _detect_tags,
    _detect_variation_selectors,
    _detect_bidi,
    _detect_controls,
    _detect_marks,
)


def detect(
    text: str,
    *,
    techniques: str | list[str] | tuple[str, ...] | set[str] | frozenset[str] | None = None,
    min_severity: Severity | str = Severity.INFO,
    options: Options = DEFAULT_OPTIONS,
) -> list[Finding]:
    """Find every catalog technique present in ``text``.

    Args:
        text: The string to analyze.
        techniques: Restrict results to these technique IDs, slugs or families
            (e.g. ``"SMUG"``, ``["GG-BIDI-001", "zero-width"]``).
        min_severity: Drop findings below this severity.
        options: Detection thresholds.

    Returns:
        Findings sorted by position. Spans are code point offsets into ``text``.
    """
    if text.isascii() and not _ASCII_SUSPICIOUS.search(text):
        return []
    floor = Severity.parse(min_severity)
    allowed = resolve(techniques) if techniques is not None else None
    runs = [m.span() for m in _trigger_pattern().finditer(text)]
    if not runs and not _may_have_mark_findings(text, options):
        return []
    t = _Text(text, runs)
    findings = [
        f
        for detector in DETECTORS
        for f in detector(t, options)
        if f.severity >= floor and (allowed is None or f.technique_id in allowed)
    ]
    findings.sort(key=lambda f: (f.start, f.end, f.technique_id))
    return findings


def _may_have_mark_findings(text: str, options: Options) -> bool:
    return any(p.search(text) for p in _mark_patterns(options.max_marks))


def payloads(text: str, *, options: Options = DEFAULT_OPTIONS) -> list[Payload]:
    """Hidden content recovered from every smuggling channel in ``text``."""
    return [f.payload for f in detect(text, options=options) if f.payload is not None]
