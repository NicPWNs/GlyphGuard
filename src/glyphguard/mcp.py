"""MCP tool descriptions: scan them for hidden text, and pin them to catch rug pulls.

An MCP server's tool descriptions and parameter descriptions go straight into the model's
context, so hidden text in them is prompt injection ("tool poisoning"). And because a
server can change its descriptions at any time, a tool that was reviewed and approved can
later turn malicious (a "rug pull"). Pinning records every tool definition in a lock file;
checking compares the server's current tools against it.

GlyphGuard never starts MCP servers. Give it each server's ``tools/list`` result as JSON,
for example from the MCP Inspector::

    npx @modelcontextprotocol/inspector --cli <server command> --method tools/list

    >>> from glyphguard.mcp import pin, compare
    >>> tools = [{"name": "add", "description": "Adds two numbers."}]
    >>> lock = pin({"calc": tools})
    >>> compare(lock, {"calc": tools})
    []
    >>> [c.kind for c in compare(lock, {"calc": [{"name": "add", "description": "Adds."}]})]
    ['changed']
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from glyphguard.catalog import Severity
from glyphguard.detect import detect
from glyphguard.findings import Finding
from glyphguard.scan import escalate

LOCK_VERSION = 1
DEFAULT_LOCK = "glyphguard-mcp.lock"
_KIND = "MCP tool definition"
_NOTE = "read by AI agents as instructions"

Tool = dict[str, Any]


def load_tools(data: Any) -> list[Tool]:
    """The tools in a ``tools/list`` result, its JSON-RPC response, or a bare list."""
    if isinstance(data, Mapping) and "result" in data:
        data = data["result"]
    if isinstance(data, Mapping) and "tools" in data:
        data = data["tools"]
    if not isinstance(data, list) or not all(
        isinstance(t, Mapping) and isinstance(t.get("name"), str) for t in data
    ):
        raise ValueError("expected a tools/list result: a list of tools that each have a name")
    names = [t["name"] for t in data]
    duplicates = sorted({n for n in names if names.count(n) > 1})
    if duplicates:
        raise ValueError(f"duplicate tool names: {', '.join(duplicates)}")
    return [dict(t) for t in data]


def digest(tool: Mapping[str, Any]) -> str:
    """SHA-256 of the tool's canonical JSON: any change to any field changes it."""
    canonical = json.dumps(tool, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8", "surrogatepass")).hexdigest()


def strings(value: Any, path: str = "") -> Iterator[tuple[str, str]]:
    """Every string in a JSON value (keys included), with a readable path to it."""
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, Mapping):
        for key, item in value.items():
            child = f"{path}.{key}" if path else str(key)
            yield f"{child} (key)", str(key)
            yield from strings(item, child)
    elif isinstance(value, list):
        for i, item in enumerate(value):
            yield from strings(item, f"{path}[{i}]")


@dataclass(frozen=True, slots=True)
class ToolFinding:
    server: str
    tool: str
    path: str
    """Where in the tool definition, e.g. ``inputSchema.properties.path.description``."""
    finding: Finding

    def to_dict(self) -> dict[str, Any]:
        return {
            "server": self.server,
            "tool": self.tool,
            "path": self.path,
            **self.finding.to_dict(),
        }


def scan_tools(server: str, tools: Sequence[Tool]) -> list[ToolFinding]:
    """Hidden or deceptive text anywhere in the tool definitions.

    Tool definitions are instructions to the model, so findings are escalated the same
    way as in agent instruction files: medium becomes high.
    """
    results = []
    for tool in tools:
        for path, text in strings(tool):
            for f in escalate(detect(text), _KIND, note=_NOTE):
                results.append(ToolFinding(server, str(tool["name"]), path, f))
    return results


def pin(
    servers: Mapping[str, Sequence[Tool]], lock: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    """A lock recording every tool of every server (other servers in ``lock`` are kept)."""
    pinned: dict[str, Any] = dict(lock["servers"]) if lock else {}
    for server, tools in servers.items():
        pinned[server] = {
            str(t["name"]): {"sha256": digest(t), "tool": t}
            for t in sorted(tools, key=lambda t: str(t["name"]))
        }
    return {"version": LOCK_VERSION, "servers": dict(sorted(pinned.items()))}


@dataclass(frozen=True, slots=True)
class Change:
    server: str
    tool: str
    kind: str
    """added, removed, changed, or unpinned (a server the lock doesn't know)."""
    fields: tuple[str, ...] = ()
    """For changed tools: the top-level fields that differ, e.g. ``description``."""
    before: Mapping[str, Any] | None = None
    """For changed tools: the pinned values of ``fields`` (missing fields are absent)."""
    after: Mapping[str, Any] | None = None
    """For changed tools: the current values of ``fields``."""

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "server": self.server,
            "tool": self.tool,
            "kind": self.kind,
            "fields": list(self.fields),
        }
        if self.before is not None:
            data["before"], data["after"] = dict(self.before), dict(self.after or {})
        return data


def compare(lock: Mapping[str, Any], servers: Mapping[str, Sequence[Tool]]) -> list[Change]:
    """How the current tools differ from the pinned ones."""
    if lock.get("version") != LOCK_VERSION:
        raise ValueError(f"unsupported lock version {lock.get('version')!r}")
    changes: list[Change] = []
    for server, tools in servers.items():
        if server not in lock["servers"]:
            changes.append(Change(server, "*", "unpinned"))
            continue
        pinned: Mapping[str, Any] = lock["servers"][server]
        current = {str(t["name"]): t for t in tools}
        for name in sorted(current.keys() - pinned.keys()):
            changes.append(Change(server, name, "added"))
        for name in sorted(pinned.keys() - current.keys()):
            changes.append(Change(server, name, "removed"))
        for name in sorted(current.keys() & pinned.keys()):
            if digest(current[name]) != pinned[name]["sha256"]:
                old: Mapping[str, Any] = pinned[name].get("tool", {})
                new = current[name]
                fields = tuple(
                    sorted(k for k in old.keys() | new.keys() if old.get(k) != new.get(k))
                )
                before = {k: old[k] for k in fields if k in old}
                after = {k: new[k] for k in fields if k in new}
                changes.append(Change(server, name, "changed", fields, before, after))
    return changes


def worst(findings: Sequence[ToolFinding]) -> Severity | None:
    return max((f.finding.severity for f in findings), default=None)
