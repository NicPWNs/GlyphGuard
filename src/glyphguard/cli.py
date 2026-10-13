"""Command-line interface: ``glyphguard inspect | detect | scan | sanitize | check | skeleton |
confusable | catalog``."""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import sys
import unicodedata
from collections.abc import Callable, Sequence
from pathlib import Path, PurePath
from typing import Any, TextIO

import glyphguard
from glyphguard import ucd
from glyphguard.catalog import Severity, techniques
from glyphguard.confusables import is_confusable, restriction_level, skeleton
from glyphguard.detect import detect
from glyphguard.findings import Finding
from glyphguard.guard import MODES, Guard, canonicalize
from glyphguard.report import inspect
from glyphguard.sanitize import profiles, reveal, sanitize
from glyphguard.sarif import Located, to_sarif
from glyphguard.scan import AGENT_CONFIG_FILES, agent_config_kind, repository_files, scan_text

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


def _excluded(path: str, patterns: Sequence[str]) -> bool:
    """True if ``path`` or one of its parent directories matches a glob in ``patterns``.

    As in .gitignore, a pattern without a slash matches a name at any depth.
    """
    if not patterns or path == "-":
        return False
    parts = [p for p in PurePath(path).as_posix().split("/") if p not in ("", ".")]
    prefixes = ["/".join(parts[:i]) for i in range(1, len(parts) + 1)]
    for pattern in patterns:
        glob = pattern.removeprefix("./").rstrip("/")
        candidates = prefixes if "/" in glob else parts
        if any(fnmatch.fnmatchcase(c, glob) for c in candidates):
            return True
    return False


def _expand_directories(paths: list[str], exclude: Sequence[str] = ()) -> list[str]:
    """Replace each directory with the files under it, skipping version-control folders
    and anything matching ``exclude``."""
    expanded: list[str] = []
    for path in paths:
        if _excluded(path, exclude):
            continue
        if path == "-" or not os.path.isdir(path):
            expanded.append(path)
            continue
        for root, dirs, files in os.walk(path):
            dirs[:] = sorted(
                d
                for d in dirs
                if d not in (".git", ".hg", ".svn")
                and not _excluded(os.path.join(root, d), exclude)
            )
            expanded.extend(
                p
                for p in (os.path.join(root, name) for name in sorted(files))
                if not _excluded(p, exclude)
            )
    return expanded


def _read_sources(args: argparse.Namespace, paths: list[str]) -> list[tuple[str, str]]:
    """(name, text) for each file in ``paths`` (directories expanded), skipping binaries."""
    sources: list[tuple[str, str]] = []
    for path in _expand_directories(paths, args.exclude or ()):
        if path == "-":
            sources.append(("<stdin>", sys.stdin.buffer.read().decode("utf-8", "surrogateescape")))
        else:
            data = Path(path).read_bytes()
            if not args.binary and b"\0" in data[:8192]:
                if path in args.paths:  # only mention files the user named explicitly
                    print(f"glyphguard: skipping binary file {path}", file=sys.stderr)
                continue
            sources.append((path, data.decode("utf-8", errors="surrogateescape")))
    return sources


def cmd_detect(args: argparse.Namespace, out: _Out) -> int:
    sources: list[tuple[str, str]] = []
    if args.text is not None:
        sources.append(("<text>", unescape(args.text) if args.unescape else args.text))
    paths = list(args.paths)
    if args.files0_from is not None:
        paths += _paths_from(args.files0_from)
    sources += _read_sources(args, paths)
    if args.text is None and not args.paths and args.files0_from is None:
        sources.append(("<stdin>", sys.stdin.buffer.read().decode("utf-8", "surrogateescape")))

    def analyze(name: str, text: str) -> list[Finding]:
        return detect(text, techniques=args.technique or None, min_severity=args.min_severity)

    return _report(args, out, sources, analyze)


def cmd_scan(args: argparse.Namespace, out: _Out) -> int:
    if args.list_agent_files:
        for pattern, kind in AGENT_CONFIG_FILES:
            out(f"{pattern:<34} {kind}")
        return EXIT_OK
    paths = list(args.paths)
    if args.files0_from is not None:
        paths += _paths_from(args.files0_from)
    if not paths:
        tracked = repository_files()
        paths = tracked if tracked is not None else ["."]
    sources = _read_sources(args, paths)
    agent_files = {name for name, _ in sources if agent_config_kind(name) is not None}
    if args.agents_only:
        sources = [(name, text) for name, text in sources if name in agent_files]

    def analyze(name: str, text: str) -> list[Finding]:
        return scan_text(
            text, name, techniques=args.technique or None, min_severity=args.min_severity
        )

    code = _report(args, out, sources, analyze)
    if args.format == "text":
        noun = "file" if len(sources) == 1 else "files"
        summary = f"Scanned {len(sources)} {noun}"
        if agent_files:
            summary += f", including {len(agent_files)} AI agent instruction files"
        out.stream.flush()
        print(summary + ".", file=sys.stderr)
    return code


def _report(
    args: argparse.Namespace,
    out: _Out,
    sources: list[tuple[str, str]],
    analyze: Callable[[str, str], list[Finding]],
) -> int:
    fail_on = Severity.parse(args.fail_on)
    worst: Severity | None = None
    records: list[dict[str, Any]] = []
    located: list[Located] = []
    for name, text in sources:
        findings = analyze(name, text)
        for f in findings:
            worst = f.severity if worst is None else max(worst, f.severity)
            line, col = _line_col(text, f.start)
            end_line, end_col = _line_col(text, f.end)
            location = None if name.startswith("<") else name
            located.append(Located(location, f, line, col, end_line, end_col))
            if args.format == "sarif":
                continue
            if args.format == "json":
                record = {"source": name, "line": line, "column": col, **f.to_dict()}
                if args.command == "scan":
                    record["agent_config"] = agent_config_kind(name)
                records.append(record)
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


# --- check, skeleton, confusable ----------------------------------------------------


def _terms_from(path: str) -> list[str]:
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    return [t for t in (line.split("#", 1)[0].strip() for line in lines) if t]


def cmd_check(args: argparse.Namespace, out: _Out) -> int:
    terms = list(args.protect)
    if args.protect_file:
        terms += _terms_from(args.protect_file)
    if not terms:
        raise ValueError("nothing to protect: pass --protect TERM or --protect-file FILE")
    text = _read_input(args)
    result = Guard(terms, mode=args.mode, allow=args.allow).check(text)
    if args.format == "json":
        out(json.dumps(result.to_dict(), indent=2))
    elif not result.matches:
        out(out.style("allow", "32") + "  no protected terms found")
    else:
        for m in result.matches:
            how = ", ".join(m.techniques) or ("plain" if not m.disguised else "case")
            out(f"{out.style('block', '31')}  {m.term!r} at [{m.start}:{m.end}] ({how})")
            out(f"       {_safe(text[m.start : m.end])}")
            for e in m.evidence:
                name = ucd.name(e.codepoint)
                out(f"       {e.index:>5}  U+{e.codepoint:04X}  {e.kind:<10} {name}")
    return EXIT_FINDINGS if result.blocked else EXIT_OK


def _escape_all(text: str) -> str:
    return "".join(c if 0x20 < ord(c) < 0x7F else f"<U+{ord(c):04X}>" for c in text)


def cmd_skeleton(args: argparse.Namespace, out: _Out) -> int:
    text = _read_input(args)
    out(_safe(canonicalize(text) if args.canonical else skeleton(text)))
    return EXIT_OK


def cmd_confusable(args: argparse.Namespace, out: _Out) -> int:
    a, b = (unescape(s) if args.unescape else s for s in (args.a, args.b))
    same_skeleton = is_confusable(a, b)
    same_key = canonicalize(a) == canonicalize(b)
    if args.format == "json":
        out(
            json.dumps(
                {
                    "confusable": same_skeleton,
                    "same_canonical": same_key,
                    "a": {"skeleton": skeleton(a), "restriction_level": str(restriction_level(a))},
                    "b": {"skeleton": skeleton(b), "restriction_level": str(restriction_level(b))},
                },
                indent=2,
            )
        )
    else:
        for label, value in (("a", a), ("b", b)):
            out(f"{label}  {_escape_all(value)}")
            out(f"   skeleton {_escape_all(skeleton(value))}  ({restriction_level(value)})")
        if same_skeleton:
            verdict = out.style("confusable", "31") + " (same UTS #39 skeleton)"
        elif same_key:
            verdict = (
                out.style("confusable", "33") + " (same once case, styling and accents are folded)"
            )
        else:
            verdict = out.style("distinct", "32")
        out(verdict)
    return EXIT_OK if same_skeleton or same_key else EXIT_FINDINGS


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

    def add_file_options(p: argparse.ArgumentParser, min_severity: str) -> None:
        p.add_argument(
            "--min-severity", default=min_severity, help="hide findings below this severity"
        )
        p.add_argument(
            "--fail-on", default="medium", help="exit 1 if a finding reaches this severity"
        )
        p.add_argument(
            "--technique",
            action="append",
            help="only report these IDs, slugs or families (repeatable)",
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
        p.add_argument(
            "--exclude",
            action="append",
            metavar="GLOB",
            help="skip files and directories matching GLOB, e.g. 'docs/*.md' (repeatable)",
        )

    p = sub.add_parser("detect", help="report findings in text or files; exit 1 at --fail-on")
    p.add_argument("paths", nargs="*", help="files to scan ('-' reads stdin)")
    p.add_argument("-t", "--text", help="scan this text instead of files")
    p.add_argument("-e", "--unescape", action="store_true", help="interpret escapes in --text")
    add_file_options(p, min_severity="info")
    p.set_defaults(func=cmd_detect)

    p = sub.add_parser(
        "scan",
        help="scan a repository; hidden text in AI agent instruction files counts as high",
        description=(
            "Scan files, directories or (by default) the current git repository. Files that "
            "AI coding agents read as instructions (AGENTS.md, CLAUDE.md, Cursor and Copilot "
            "rules, skills, MCP configs...) are judged more strictly: medium findings in them "
            "become high. See 'glyphguard scan --list-agent-files'."
        ),
    )
    p.add_argument(
        "paths", nargs="*", help="files or directories (default: the git repository, or '.')"
    )
    p.add_argument(
        "--agents-only", action="store_true", help="scan only AI agent instruction files"
    )
    p.add_argument(
        "--list-agent-files",
        action="store_true",
        help="print the file patterns treated as AI agent instructions and exit",
    )
    add_file_options(p, min_severity="low")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("sanitize", help="neutralize findings and print the cleaned text")
    add_text_input(p)
    p.add_argument("-p", "--profile", default="llm-input", choices=sorted(profiles()))
    p.add_argument("--report", action="store_true", help="list changes on stderr")
    p.set_defaults(func=cmd_sanitize)

    p = sub.add_parser(
        "check", help="check text for disguised protected terms; exit 1 if one is found"
    )
    add_text_input(p)
    p.add_argument(
        "-p",
        "--protect",
        action="append",
        default=[],
        metavar="TERM",
        help="term to protect (repeatable)",
    )
    p.add_argument(
        "--protect-file",
        metavar="FILE",
        help="file with one protected term per line ('#' comments)",
    )
    p.add_argument(
        "--mode", choices=MODES, default="word", help="how a term must appear (default: word)"
    )
    p.add_argument(
        "--allow",
        action="append",
        default=[],
        metavar="WORD",
        help="word that may contain a term (repeatable)",
    )
    p.add_argument("--format", choices=("text", "json"), default="text")
    p.set_defaults(func=cmd_check)

    p = sub.add_parser("skeleton", help="print the UTS #39 skeleton used to compare lookalikes")
    add_text_input(p)
    p.add_argument(
        "--canonical",
        action="store_true",
        help="print the canonical key instead: also folds case, styling, diacritics and invisibles",
    )
    p.set_defaults(func=cmd_skeleton)

    p = sub.add_parser(
        "confusable", help="tell whether two strings can pass for each other; exit 0 if they can"
    )
    p.add_argument("a")
    p.add_argument("b")
    p.add_argument("-e", "--unescape", action="store_true", help="interpret escapes in A and B")
    p.add_argument("--format", choices=("text", "json"), default="text")
    p.set_defaults(func=cmd_confusable)

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
