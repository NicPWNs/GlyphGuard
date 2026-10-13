"""Scan files and repositories, judging each file by what reads it.

Most files are read by people and compilers. Agent instruction files (``AGENTS.md``,
``CLAUDE.md``, Cursor and Copilot rules, skills, MCP configs...) are also read by AI coding
agents as instructions, which makes hidden text in them a direct prompt injection: the
Rules File Backdoor hid instructions in rules files with zero-width joiners, bidi
overrides and tag characters. In those files GlyphGuard raises medium findings to high.

    >>> from glyphguard.scan import agent_config_kind
    >>> agent_config_kind(".cursor/rules/style.mdc")
    'Cursor rules'
    >>> agent_config_kind("src/app.py") is None
    True
"""

from __future__ import annotations

import fnmatch
import os
import subprocess
from collections.abc import Iterable, Sequence
from dataclasses import replace
from pathlib import PurePath

from glyphguard.catalog import Severity
from glyphguard.detect import detect
from glyphguard.findings import Finding

# Files that AI coding agents read as instructions or configuration, as (glob, kind).
# A pattern without a slash matches a file name at any depth; one with a slash matches
# the end of a path, so ".cursor/rules/*" also covers packages/web/.cursor/rules/x.mdc.
AGENT_CONFIG_FILES: tuple[tuple[str, str], ...] = (
    ("AGENTS.md", "AGENTS.md agent instructions"),
    ("AGENT.md", "AGENTS.md agent instructions"),
    ("CLAUDE.md", "Claude Code memory"),
    ("CLAUDE.local.md", "Claude Code memory"),
    (".claude/*", "Claude Code configuration"),
    ("SKILL.md", "agent skill"),
    ("GEMINI.md", "Gemini CLI context"),
    (".gemini/*", "Gemini CLI configuration"),
    (".cursorrules", "Cursor rules"),
    (".cursor/rules/*", "Cursor rules"),
    (".cursor/mcp.json", "MCP server configuration"),
    (".windsurfrules", "Windsurf rules"),
    (".windsurf/rules/*", "Windsurf rules"),
    (".clinerules", "Cline rules"),
    (".clinerules/*", "Cline rules"),
    (".roorules", "Roo Code rules"),
    (".roo/*", "Roo Code rules"),
    (".github/copilot-instructions.md", "GitHub Copilot instructions"),
    ("*.instructions.md", "GitHub Copilot instructions"),
    ("*.prompt.md", "GitHub Copilot prompt"),
    ("*.chatmode.md", "GitHub Copilot chat mode"),
    (".github/instructions/*", "GitHub Copilot instructions"),
    (".github/prompts/*", "GitHub Copilot prompt"),
    (".github/chatmodes/*", "GitHub Copilot chat mode"),
    (".junie/*", "JetBrains Junie guidelines"),
    (".kiro/*", "Kiro steering"),
    (".augment/*", "Augment rules"),
    (".augment-guidelines", "Augment rules"),
    (".continue/*", "Continue configuration"),
    (".openhands/*", "OpenHands microagent"),
    (".aider.conf.yml", "Aider configuration"),
    ("CONVENTIONS.md", "Aider conventions"),
    (".mcp.json", "MCP server configuration"),
    ("mcp.json", "MCP server configuration"),
    ("claude_desktop_config.json", "MCP server configuration"),
    ("llms.txt", "llms.txt"),
    ("llms-full.txt", "llms.txt"),
)

AGENT_NOTE = "in a file AI agents read as instructions"
_BACKSLASH = chr(92)


def agent_config_kind(path: str) -> str | None:
    """What kind of agent instruction file ``path`` is, or None if it isn't one."""
    # Backslashes count as separators on every OS: Windows paths reach us in file lists.
    normalized = PurePath(path).as_posix().replace(_BACKSLASH, "/")
    parts = [p for p in normalized.split("/") if p not in ("", ".")]
    if not parts:
        return None
    suffixes = ["/".join(parts[i:]) for i in range(len(parts))]
    for pattern, kind in AGENT_CONFIG_FILES:
        if "/" in pattern:
            if any(fnmatch.fnmatchcase(s, pattern) for s in suffixes):
                return kind
        elif fnmatch.fnmatchcase(parts[-1], pattern):
            return kind
    return None


def escalate(findings: Iterable[Finding], kind: str | None) -> list[Finding]:
    """Raise medium findings to high in agent instruction files, noting why.

    Hidden or deceptive characters in a file an agent obeys are prompt injection, not
    noise. Low and info findings (an unusual space, IPA, math notation) are left as they
    are, so prose in those files stays usable.
    """
    if kind is None:
        return list(findings)
    return [
        replace(f, severity=Severity.HIGH, message=f"{f.message} ({AGENT_NOTE}: {kind})")
        if f.severity == Severity.MEDIUM
        else replace(f, message=f"{f.message} ({AGENT_NOTE}: {kind})")
        if f.severity >= Severity.HIGH
        else f
        for f in findings
    ]


def scan_text(
    text: str,
    path: str,
    *,
    techniques: Sequence[str] | None = None,
    min_severity: Severity | str = Severity.INFO,
) -> list[Finding]:
    """Findings in the contents of the file at ``path``, escalated by what the file is.

    ``min_severity`` applies after escalation, so a medium finding in an agent file
    survives ``min_severity="high"``.
    """
    floor = Severity.parse(min_severity)
    found = detect(text, techniques=list(techniques) if techniques else None)
    return [f for f in escalate(found, agent_config_kind(path)) if f.severity >= floor]


def repository_files(root: str = ".") -> list[str] | None:
    """Files git tracks under ``root``, plus untracked files it doesn't ignore.

    Returns None when ``root`` isn't inside a git work tree (or git isn't installed).
    """
    try:
        result = subprocess.run(
            ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
            cwd=root,
            capture_output=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    names = [os.fsdecode(p) for p in result.stdout.split(b"\0") if p]
    return [
        os.path.join(root, name) if root != "." else name
        for name in dict.fromkeys(names)
        if os.path.isfile(os.path.join(root, name))  # skip deleted files and submodules
    ]
