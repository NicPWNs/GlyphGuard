"""Generate GlyphGuard's vendored Unicode tables.

Downloads the pinned Unicode Character Database files into ``.cache/unicode/<version>/``
and writes ``src/glyphguard/_data/ucd.py``. The generated module is committed so the
library has no runtime dependency on the network or on the interpreter's own
``unicodedata`` version.

Usage::

    python scripts/gen_data.py                 # regenerate for the pinned version
    python scripts/gen_data.py --version 18.0.0
    python scripts/gen_data.py --check         # exit 1 if the committed tables are stale
"""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
import urllib.request
from collections.abc import Iterable, Iterator
from pathlib import Path

UNICODE_VERSION = "18.0.0"

ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "src" / "glyphguard" / "_data" / "ucd.py"

SOURCES = {
    "Scripts.txt": "ucd/Scripts.txt",
    "ScriptExtensions.txt": "ucd/ScriptExtensions.txt",
    "PropertyValueAliases.txt": "ucd/PropertyValueAliases.txt",
    "DerivedGeneralCategory.txt": "ucd/extracted/DerivedGeneralCategory.txt",
    "DerivedCombiningClass.txt": "ucd/extracted/DerivedCombiningClass.txt",
    "DerivedCoreProperties.txt": "ucd/DerivedCoreProperties.txt",
    "PropList.txt": "ucd/PropList.txt",
    "StandardizedVariants.txt": "ucd/StandardizedVariants.txt",
    "emoji-data.txt": "ucd/emoji/emoji-data.txt",
    "emoji-variation-sequences.txt": "ucd/emoji/emoji-variation-sequences.txt",
}

# Binary properties exported as range sets: (source file, property name, exported name).
BINARY_PROPERTIES = [
    ("DerivedCoreProperties.txt", "Default_Ignorable_Code_Point", "DEFAULT_IGNORABLE"),
    ("PropList.txt", "Bidi_Control", "BIDI_CONTROL"),
    ("PropList.txt", "White_Space", "WHITE_SPACE"),
    ("PropList.txt", "Noncharacter_Code_Point", "NONCHARACTER"),
    ("PropList.txt", "Variation_Selector", "VARIATION_SELECTOR"),
    ("PropList.txt", "Join_Control", "JOIN_CONTROL"),
    ("emoji-data.txt", "Extended_Pictographic", "EXTENDED_PICTOGRAPHIC"),
    ("emoji-data.txt", "Emoji_Modifier", "EMOJI_MODIFIER"),
    ("emoji-data.txt", "Emoji_Component", "EMOJI_COMPONENT"),
]

MAX_CODE_POINT = 0x10FFFF


def fetch(version: str, name: str) -> bytes:
    cache = ROOT / ".cache" / "unicode" / version
    path = cache / name
    if not path.exists():
        url = f"https://www.unicode.org/Public/{version}/{SOURCES[name]}"
        print(f"downloading {url}", file=sys.stderr)
        with urllib.request.urlopen(url, timeout=60) as response:
            data: bytes = response.read()
        cache.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return path.read_bytes()


def records(data: bytes) -> Iterator[list[str]]:
    """Yield the semicolon-separated fields of each non-comment line."""
    for raw in data.decode("utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            yield [field.strip() for field in line.split(";")]


def parse_range(field: str) -> tuple[int, int]:
    if ".." in field:
        start, end = field.split("..")
        return int(start, 16), int(end, 16)
    cp = int(field, 16)
    return cp, cp


def merge(ranges: Iterable[tuple[int, int]]) -> list[tuple[int, int]]:
    merged: list[tuple[int, int]] = []
    for start, end in sorted(ranges):
        if merged and start <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def boundaries(ranges: list[tuple[int, int]]) -> list[int]:
    """Flatten ranges to [start0, end0 + 1, start1, end1 + 1, ...] for bisect lookups."""
    flat: list[int] = []
    for start, end in ranges:
        flat += [start, end + 1]
    return flat


def dense(assignments: list[tuple[int, int, int]], default: int) -> tuple[list[int], list[int]]:
    """Turn sparse (start, end, value) ranges into segments covering the whole codespace."""
    starts: list[int] = []
    values: list[int] = []

    def push(start: int, value: int) -> None:
        if values and values[-1] == value:
            return
        starts.append(start)
        values.append(value)

    cursor = 0
    for start, end, value in sorted(assignments):
        if start > cursor:
            push(cursor, default)
        push(start, value)
        cursor = end + 1
    if cursor <= MAX_CODE_POINT:
        push(cursor, default)
    return starts, values


def script_aliases(data: bytes) -> dict[str, str]:
    """Map short script codes (e.g. ``Latn``) to long names (e.g. ``Latin``)."""
    aliases: dict[str, str] = {}
    for fields in records(data):
        if fields[0] == "sc":
            aliases[fields[1]] = fields[2]
    return aliases


def build(version: str) -> str:
    files = {name: fetch(version, name) for name in SOURCES}
    checksums = {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}

    # General_Category, dense over the codespace (unlisted code points are Cn).
    categories: list[str] = []
    gc_assign: list[tuple[int, int, int]] = []
    for fields in records(files["DerivedGeneralCategory.txt"]):
        start, end = parse_range(fields[0])
        if fields[1] not in categories:
            categories.append(fields[1])
        gc_assign.append((start, end, categories.index(fields[1])))
    if "Cn" not in categories:
        categories.append("Cn")
    gc_starts, gc_values = dense(gc_assign, categories.index("Cn"))

    # Script, dense over the codespace (unlisted code points are Unknown).
    aliases = script_aliases(files["PropertyValueAliases.txt"])
    scripts = ["Unknown"]
    sc_assign: list[tuple[int, int, int]] = []
    for fields in records(files["Scripts.txt"]):
        start, end = parse_range(fields[0])
        if fields[1] not in scripts:
            scripts.append(fields[1])
        sc_assign.append((start, end, scripts.index(fields[1])))
    sc_starts, sc_values = dense(sc_assign, 0)

    # Script_Extensions, sparse: code points not listed default to their Script value.
    scx_sets: list[tuple[int, ...]] = []
    scx_assign: list[tuple[int, int, int]] = []
    for fields in records(files["ScriptExtensions.txt"]):
        start, end = parse_range(fields[0])
        names = [aliases[code] for code in fields[1].split()]
        for name in names:
            if name not in scripts:
                scripts.append(name)
        ext = tuple(sorted(scripts.index(name) for name in names))
        if ext not in scx_sets:
            scx_sets.append(ext)
        scx_assign.append((start, end, scx_sets.index(ext) + 1))
    scx_starts, scx_values = dense(scx_assign, 0)

    # Canonical_Combining_Class = 1 (Overlay).
    overlay: list[tuple[int, int]] = []
    for fields in records(files["DerivedCombiningClass.txt"]):
        if fields[1] == "1":
            overlay.append(parse_range(fields[0]))

    binary: dict[str, list[tuple[int, int]]] = {}
    for source, prop, exported in BINARY_PROPERTIES:
        binary[exported] = merge(
            parse_range(fields[0]) for fields in records(files[source]) if fields[1] == prop
        )
    binary["OVERLAY_MARK"] = merge(overlay)

    # Valid (base, variation selector) pairs.
    sequences: set[tuple[int, int]] = set()
    for name in ("StandardizedVariants.txt", "emoji-variation-sequences.txt"):
        for fields in records(files[name]):
            points = [int(cp, 16) for cp in fields[0].split()]
            if len(points) == 2:
                sequences.add((points[0], points[1]))

    out: list[str] = [
        "# Generated by scripts/gen_data.py. Do not edit by hand.",
        f"# Source: Unicode Character Database, https://www.unicode.org/Public/{version}/",
        "# Unicode data is covered by the Unicode License v3 (see NOTICE).",
        "# fmt: off",
        "# ruff: noqa: E501",
        "",
        f'UNICODE_VERSION = "{version}"',
        "",
        "SOURCE_SHA256 = {",
        *(f'    "{name}": "{digest}",' for name, digest in sorted(checksums.items())),
        "}",
        "",
        f"GENERAL_CATEGORY_NAMES = {tuple(categories)!r}",
        f"GENERAL_CATEGORY_STARTS = {_ints(gc_starts)}",
        f"GENERAL_CATEGORY_VALUES = {_ints(gc_values)}",
        "",
        f"SCRIPT_NAMES = {tuple(scripts)!r}",
        f"SCRIPT_STARTS = {_ints(sc_starts)}",
        f"SCRIPT_VALUES = {_ints(sc_values)}",
        "",
        "# Index 0 means 'no explicit Script_Extensions';",
        "# index n refers to SCRIPT_EXTENSION_SETS[n - 1].",
        f"SCRIPT_EXTENSION_SETS = {tuple(scx_sets)!r}",
        f"SCRIPT_EXTENSION_STARTS = {_ints(scx_starts)}",
        f"SCRIPT_EXTENSION_VALUES = {_ints(scx_values)}",
        "",
        "# Binary properties as flattened half-open ranges: a code point is in the set",
        "# when bisect_right(boundaries, cp) is odd.",
    ]
    for exported in sorted(binary):
        out.append(f"{exported} = {_ints(boundaries(binary[exported]))}")
    out += [
        "",
        "# Valid variation sequences from StandardizedVariants.txt and",
        "# emoji-variation-sequences.txt, encoded as (base << 21) | selector.",
        f"VARIATION_SEQUENCES = frozenset({_ints(sorted((b << 21) | v for b, v in sequences))})",
        "",
    ]
    return "\n".join(out)


def _ints(values: list[int]) -> str:
    return "(" + ",".join(str(v) for v in values) + ("," if len(values) == 1 else "") + ")"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--version", default=UNICODE_VERSION)
    parser.add_argument("--check", action="store_true", help="fail if the output is out of date")
    args = parser.parse_args()

    if not re.fullmatch(r"\d+\.\d+\.\d+", args.version):
        parser.error("--version must look like 18.0.0")
    generated = build(args.version)
    if args.check:
        current = OUTPUT.read_text(encoding="utf-8") if OUTPUT.exists() else ""
        if current != generated:
            print(
                f"{OUTPUT.relative_to(ROOT)} is out of date; run scripts/gen_data.py",
                file=sys.stderr,
            )
            return 1
        return 0
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(generated, encoding="utf-8", newline="\n")
    print(f"wrote {OUTPUT.relative_to(ROOT)} (Unicode {args.version})", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
