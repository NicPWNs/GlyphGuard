"""Command-line interface: ``glyphguard inspect | detect | sanitize | catalog``."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import unicodedata
from collections.abc import Sequence
from pathlib import Path
from typing import Any, TextIO

import glyphguard
from glyphguard import ucd
from glyphguard.catalog import Severity, techniques
from glyphguard.detect import detect
from glyphguard.findings import Finding
from glyphguard.report import inspect
from glyphguard.sanitize import profiles, reveal, sanitize
from glyphguard.sarif import Located, to_sarif

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2

_COLORS = {
    Severity.INFO: "2",
    Severity.LOW: "36",
    Severity.MEDIUM: "33",
    Severity.HIGH: "31",
    Severity.CRITICAL: "1;37;41",
}
_UNESCAPE = re.compile(
    r"\\(?:u([0-9a-fA-F]{4})|U([0-9a-fA-F]{8})|x([0-9a-fA-F]{2})|N\{([^}]+)\}|(.))"
)
_SIMPLE_ESCAPES = {"n": "\n", "r": "\r", "t": "\t", "0": "\0", "e": "\x1b", "\\": "\\"}


def unescape(text: str) -> str:
    r"""Interpret ``\uXXXX``, ``\UXXXXXXXX``, ``\xXX``, ``\N{NAME}``, ``\n``, ``\t``, ``\e``..."""

    def replace(match: re.Match[str]) -> str:
        u4, u8, x2, named, simple = match.groups()
        if u4 or u8 or x2:
            return chr(int(u4 or u8 or x2, 16))
        if named:
            return unicodedata.lookup(named)
        return _SIMPLE_ESCAPES.get(simple, match.group())

    return _UNESCAPE.sub(replace, text)


class _Out:
    def __init__(self, stream: TextIO, color: bool) -> None:
        self.stream = stream
        self.color = color

    def __call__(self, line: str = "") -> None:
        print(line, file=self.stream)

    def style(self, text: str, code: str) -> str:
        return f"\x1b[{code}m{text}\x1b[0m" if self.color else text

    def severity(self, severity: Severity, width: int = 8) -> str:
        return self.style(f"{str(severity).upper():<{width}}", _COLORS[severity])


def _use_color(stream: TextIO, choice: str) -> bool:
    if choice != "auto":
        return choice == "always"
    if os.environ.get("NO_COLOR") or not stream.isatty():
        return False
    return os.name != "nt" or "WT_SESSION" in os.environ or "TERM" in os.environ


def _read_input(args: argparse.Namespace) -> str:
    if getattr(args, "file", None):
        return Path(args.file).read_bytes().decode("utf-8", errors="surrogateescape")
    if args.text is None or args.text == "-":
        data = sys.stdin.buffer.read()
        return data.decode("utf-8", errors="surrogateescape")
    return unescape(args.text) if args.unescape else str(args.text)


def _safe(text: str) -> str:
    """Render untrusted text for a terminal: flagged code points become <U+XXXX>."""
    return reveal(text)


# --- inspect ------------------------------------------------------------------------


def cmd_inspect(args: argparse.Namespace, out: _Out) -> int:
    text = _read_input(args)
    report = inspect(text)
    if args.format == "json":
        out(json.dumps(report.to_dict(), indent=2))
        return EXIT_OK

    worst = report.max_severity
    out(
        out.style(f"GlyphGuard {glyphguard.__version__}", "1")
        + f"  (Unicode {ucd.UNICODE_VERSION})"
    )
    summary = f"{len(text)} code points, {len(report.findings)} findings"
    if worst is not None:
        summary += f", max severity {out.severity(worst, 0)}"
    out(summary)

    if report.findings:
        out()
        out(out.style("Findings", "1"))
        for f in report.findings:
            title = f"{f.technique.title}  [{f.start}:{f.end}]"
            out(f"  {out.severity(f.severity)} {f.technique_id:<12} {title}")
            out(f"  {'':8} {'':12} {f.message}")
    if report.payloads:
        out()
        out(out.style("Hidden payloads", "1"))
        for p in report.payloads:
            out(f"  {p.channel}: {_safe(p.text)!s}")
    out()
    out(out.style("Revealed", "1"))
    out(f"  {report.revealed}")
    if report.findings:
        out(out.style("Cleaned (strict)", "1"))
        out(f"  {report.cleaned}")

    rows = report.chars(flagged_only=args.chars == "flagged")
    if args.chars != "none" and rows:
        out()
        out(out.style("Characters", "1"))
        out(f"  {'index':>5}  {'code':<8} {'cat':<3} {'script':<12} {'flags':<18} name")
        limit = args.max_chars
        for row in rows[:limit]:
            flags = ",".join(t.removeprefix("GG-") for t in row.techniques)
            cells = f"{row.label:<8} {row.category:<3} {row.script:<12} {flags:<18}"
            out(f"  {row.index:>5}  {cells} {row.name}")
        if len(rows) > limit:
            out(f"  ... {len(rows) - limit} more (use --max-chars)")
    return EXIT_OK


# --- detect -------------------------------------------------------------------------


def _line_col(text: str, offset: int) -> tuple[int, int]:
    line = text.count("\n", 0, offset) + 1
    col = offset - (text.rfind("\n", 0, offset) + 1) + 1
    return line, col


def _gh_data(value: str) -> str:
    """Escape a GitHub Actions workflow-command message."""
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _gh_property(value: str) -> str:
    """Escape a GitHub Actions workflow-command property value."""
    return _gh_data(value).replace(":", "%3A").replace(",", "%2C")


def _github_annotation(name: str, line: int, col: int, f: Finding, fail_on: Severity) -> str:
    level = "error" if f.severity >= fail_on else "warning"
    title = _gh_property(f"{f.technique_id} {f.technique.title} ({f.severity})")
    where = "" if name.startswith("<") else f"file={_gh_property(name)},line={line},col={col},"
    return f"::{level} {where}title={title}::{_gh_data(f.message)}"


def _paths_from(source: str) -> list[str]:
    """NUL-separated paths from a file or stdin, as produced by ``git ls-files -z``."""
    data = sys.stdin.buffer.read() if source == "-" else Path(source).read_bytes()
    return [os.fsdecode(p) for p in data.split(b"\0") if p]


def _expand_directories(paths: list[str]) -> list[str]:
    """Replace each directory with the files under it, skipping version-control folders."""
    expanded: list[str] = []
    for path in paths:
        if path == "-" or not os.path.isdir(path):
            expanded.append(path)
            continue
        for root, dirs, files in os.walk(path):
            dirs[:] = sorted(d for d in dirs if d not in (".git", ".hg", ".svn"))
            expanded.extend(os.path.join(root, name) for name in sorted(files))
    return expanded


def cmd_detect(args: argparse.Namespace, out: _Out) -> int:
    sources: list[tuple[str, str]] = []
    if args.text is not None:
        sources.append(("<text>", unescape(args.text) if args.unescape else args.text))
    paths = list(args.paths)
    if args.files0_from is not None:
        paths += _paths_from(args.files0_from)
    for path in _expand_directories(paths):
        if path == "-":
            sources.append(("<stdin>", sys.stdin.buffer.read().decode("utf-8", "surrogateescape")))
        else:
            data = Path(path).read_bytes()
            if not args.binary and b"\0" in data[:8192]:
                if path in args.paths:  # only mention files the user named explicitly
                    print(f"glyphguard: skipping binary file {path}", file=sys.stderr)
                continue
            sources.append((path, data.decode("utf-8", errors="surrogateescape")))
    if args.text is None and not args.paths and args.files0_from is None:
        sources.append(("<stdin>", sys.stdin.buffer.read().decode("utf-8", "surrogateescape")))

    fail_on = Severity.parse(args.fail_on)
    worst: Severity | None = None
    records: list[dict[str, Any]] = []
    located: list[Located] = []
    for name, text in sources:
        findings: list[Finding] = detect(
            text, techniques=args.technique or None, min_severity=args.min_severity
        )
        for f in findings:
            worst = f.severity if worst is None else max(worst, f.severity)
            line, col = _line_col(text, f.start)
            end_line, end_col = _line_col(text, f.end)
            location = None if name.startswith("<") else name
            located.append(Located(location, f, line, col, end_line, end_col))
            if args.format == "sarif":
                continue
            if args.format == "json":
                records.append({"source": name, "line": line, "column": col, **f.to_dict()})
            elif args.format == "github":
                out(_github_annotation(name, line, col, f, fail_on))
            else:
                level = out.style(str(f.severity), _COLORS[f.severity])
                out(
                    f"{name}:{line}:{col}: {level} {f.technique_id} "
                    f"{f.technique.title}: {f.message}"
                )
    if args.format == "json":
        out(json.dumps(records, indent=2))
    if args.format == "sarif" or args.sarif:
        log = json.dumps(to_sarif(located, version=glyphguard.__version__), indent=2)
        if args.format == "sarif":
            out(log)
        if args.sarif:
            Path(args.sarif).write_text(log + "\n", encoding="utf-8")
    return EXIT_FINDINGS if worst is not None and worst >= fail_on else EXIT_OK


# --- sanitize -----------------------------------------------------------------------


def cmd_sanitize(args: argparse.Namespace, out: _Out) -> int:
    text = _read_input(args)
    result = sanitize(text, args.profile)
    data = result.text.encode("utf-8", errors="surrogateescape")
    if args.text not in (None, "-") and not data.endswith(b"\n"):
        data += b"\n"
    sys.stdout.flush()
    sys.stdout.buffer.write(data)
    sys.stdout.flush()
    if args.report:
        err = _Out(sys.stderr, _use_color(sys.stderr, args.color))
        err(f"{len(result.changes)} changes ({result.profile})")
        for c in result.changes:
            err(f"  {c.technique_id:<12} {c.action:<8} [{c.start}:{c.end}] {_safe(c.original)}")
    return EXIT_OK


# --- catalog ------------------------------------------------------------------------


def cmd_catalog(args: argparse.Namespace, out: _Out) -> int:
    catalog = techniques()
    if args.format == "json":
        out(
            json.dumps(
                [
                    {
                        "id": t.id,
                        "family": t.family,
                        "slug": t.slug,
                        "title": t.title,
                        "severity": str(t.severity),
                        "summary": t.summary,
                        "cwe": list(t.cwe),
                        "atlas": list(t.atlas),
                        "references": list(t.references),
                    }
                    for t in catalog.values()
                ],
                indent=2,
            )
        )
        return EXIT_OK
    for t in catalog.values():
        out(f"{t.id:<12} {out.severity(t.severity)} {t.slug:<30} {t.title}")
    out()
    out("Profiles: " + ", ".join(profiles()))
    return EXIT_OK


# --- entry point --------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="glyphguard",
        description="See what the machine sees. Unicode security for humans, filters, and models.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"glyphguard {glyphguard.__version__} (Unicode {ucd.UNICODE_VERSION})",
    )
    parser.add_argument("--color", choices=("auto", "always", "never"), default="auto")
    sub = parser.add_subparsers(dest="command", required=True)

    def add_text_input(p: argparse.ArgumentParser) -> None:
        p.add_argument("text", nargs="?", help="text to analyze ('-' or omitted reads stdin)")
        p.add_argument("-f", "--file", help="read the text from a file")
        p.add_argument(
            "-e",
            "--unescape",
            action="store_true",
            help=r"interpret \uXXXX, \U0001XXXX, \xXX, \N{NAME}, \n, \e escapes in TEXT",
        )

    p = sub.add_parser("inspect", help="explain everything hidden in a string")
    add_text_input(p)
    p.add_argument("--format", choices=("text", "json"), default="text")
    p.add_argument(
        "--chars",
        choices=("all", "flagged", "none"),
        default="all",
        help="which code points to list (default: non-ASCII and flagged)",
    )
    p.add_argument("--max-chars", type=int, default=64)
    p.set_defaults(func=cmd_inspect)

    p = sub.add_parser("detect", help="report findings in text or files; exit 1 at --fail-on")
    p.add_argument("paths", nargs="*", help="files to scan ('-' reads stdin)")
    p.add_argument("-t", "--text", help="scan this text instead of files")
    p.add_argument("-e", "--unescape", action="store_true", help="interpret escapes in --text")
    p.add_argument("--min-severity", default="info", help="hide findings below this severity")
    p.add_argument("--fail-on", default="medium", help="exit 1 if a finding reaches this severity")
    p.add_argument(
        "--technique", action="append", help="only report these IDs, slugs or families (repeatable)"
    )
    p.add_argument(
        "--format",
        choices=("text", "json", "github", "sarif"),
        default="text",
        help="github: inline pull-request annotations; sarif: SARIF 2.1.0 for code scanning",
    )
    p.add_argument(
        "--sarif",
        metavar="FILE",
        help="also write a SARIF 2.1.0 log to FILE, whatever --format is",
    )
    p.add_argument(
        "--files0-from",
        metavar="FILE",
        help="also scan the NUL-separated paths in FILE ('-' for stdin), e.g. git ls-files -z",
    )
    p.add_argument(
        "--binary", action="store_true", help="also scan files that look binary (contain NUL)"
    )
    p.set_defaults(func=cmd_detect)

    p = sub.add_parser("sanitize", help="neutralize findings and print the cleaned text")
    add_text_input(p)
    p.add_argument("-p", "--profile", default="llm-input", choices=sorted(profiles()))
    p.add_argument("--report", action="store_true", help="list changes on stderr")
    p.set_defaults(func=cmd_sanitize)

    p = sub.add_parser("catalog", help="list techniques and profiles")
    p.add_argument("--format", choices=("text", "json"), default="text")
    p.set_defaults(func=cmd_catalog)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="backslashreplace")
    parser = build_parser()
    args = parser.parse_args(argv)
    out = _Out(sys.stdout, _use_color(sys.stdout, args.color))
    try:
        code: int = args.func(args, out)
    except (OSError, ValueError, KeyError) as exc:
        print(f"glyphguard: error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    return code


if __name__ == "__main__":
    raise SystemExit(main())
