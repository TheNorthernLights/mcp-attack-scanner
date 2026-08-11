"""Indirect prompt injection carried in tool output.

An MCP server's read-style tools return whatever content lives in the data
source behind them — files, database rows, fetched web pages. If an attacker
can get text into that source (plant a document on a share, edit a record,
control a page the server fetches), the content the tool returns can carry
*instructions* aimed at whatever AI agent consumes the output. A susceptible
agent may then follow those instructions and misuse the server's *other* tools
— e.g. read a secret with one tool and push it out through a `send_notification`
tool the injected text names by hand. The server is the delivery channel; the
payload rides in on ordinary tool output.

This module does not *execute* any instruction it finds — doing so would be
falling for the injection. It only reads content back through the target's own
read tools and inspects it for a planted payload. A finding requires the
returned content to BOTH:

  * reference at least one *other* tool on the same server by its exact name
    (the tell that the payload was written for this specific server), AND
  * carry imperative/directive language aimed at an agent ("you must",
    "before proceeding", "call <tool>", "ignore previous instructions", a
    "SYSTEM UPDATE:"-style framing, ...).

Both are required on purpose. A tool name alone proves nothing — normal
documentation mentions tools descriptively ("run `list_files` to see the
share"). Directive language alone proves nothing — a to-do note can say "you
must finish this". It is the combination, tool-name reference *plus* an
instruction to act, that distinguishes a real injection payload from prose that
merely resembles one.
"""

from __future__ import annotations

import json
import re
from typing import Any

from ..client import MCPClient, TargetConfig
from ..reporting import Finding, Outcome, Severity

ATTACK_ID = "prompt_injection_tool_output"
CATEGORY = "prompt-injection-tool-output"

# Tools whose output is worth inspecting: those that return content from a data
# source. The tool-chaining module keys off the same words but as loose
# substrings; here they are matched at a word boundary so a sender like
# `send_notification` is not misread as a `cat`-style read tool.
_READ_HINTS = ("read", "get", "list", "file", "fetch", "load", "cat", "show",
               "view", "download", "dump", "open")
_READ_HINT_RE = re.compile(r"\b(?:" + "|".join(_READ_HINTS) + r")",
                           re.IGNORECASE)

# Which input parameter of a read tool names the thing to read.
_TARGET_PARAM_HINTS = ("path", "file", "filename", "name", "key", "id",
                       "directory", "dir", "resource")

# Documents worth trying even if a list tool discovers nothing — the kind of
# place a planted payload tends to live.
_FALLBACK_FILENAMES = ("meeting-notes.md", "notes.md", "README.md", "README.txt",
                       "notes.txt", "onboarding.md", "instructions.md",
                       "ticket.txt", "message.txt")

# Directive verbs that turn a tool-name mention into a command. Detected only
# when they immediately precede a referenced tool name ("call send_notification"),
# which is what makes "call X" an instruction rather than a description.
_DIRECTIVE_VERBS = ("call", "invoke", "execute", "run", "use", "trigger",
                    "send", "issue", "perform")

# Imperative / injection-framing language aimed at an agent. Any match counts as
# directive language; each pattern is kept human-readable so evidence can name
# exactly what fired.
_IMPERATIVE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("you must", re.compile(r"(?i)\byou\s+must\b")),
    ("you should", re.compile(r"(?i)\byou\s+should\b")),
    ("you are required to", re.compile(r"(?i)\byou\s+are\s+required\b")),
    ("before proceeding", re.compile(r"(?i)\bbefore\s+proceeding\b")),
    ("before you continue", re.compile(
        r"(?i)\bbefore\s+(?:you\s+)?(?:continue|proceeding|responding|"
        r"answering|any\s+other)\b")),
    ("ignore previous instructions", re.compile(
        r"(?i)\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:the\s+)?"
        r"(?:previous|prior|earlier|above)\b")),
    ("system update", re.compile(r"(?i)\bsystem\s+update\b")),
    ("security audit step", re.compile(r"(?i)\bsecurity\s+audit\b")),
    ("required step", re.compile(
        r"(?i)\brequired\s+(?:security\s+)?(?:step|update|action|task)\b")),
    ("new instructions", re.compile(r"(?i)\bnew\s+instructions?\b")),
    ("do not tell/mention the user", re.compile(
        r"(?i)\bdo\s+not\s+(?:tell|mention|inform|reveal|disclose|notify)\b")),
    ("SYSTEM/ADMIN/OVERRIDE framing", re.compile(
        r"(?im)^\s*(?:important\s+)?(?:system|admin|administrator|override|"
        r"security|urgent|notice|attention)\b[^\n]{0,40}?:")),
)

_SAMPLE_LEN = 300
_SNIPPET_LEN = 400


def _text(*parts: str | None) -> str:
    return " ".join(p for p in parts if p).lower()


def _is_read_tool(tool: Any) -> bool:
    return _READ_HINT_RE.search(_text(tool.name, tool.description)) is not None


def _properties(tool: Any) -> dict[str, Any]:
    return (tool.inputSchema or {}).get("properties") or {}


def _required(tool: Any) -> list[str]:
    return list((tool.inputSchema or {}).get("required") or [])


def _pick_param(tool: Any, hints: tuple[str, ...]) -> str | None:
    for name in _properties(tool):
        if any(h in name.lower() for h in hints):
            return name
    return None


def _first_string_param(tool: Any) -> str | None:
    for name, spec in _properties(tool).items():
        if (spec or {}).get("type", "string") == "string":
            return name
    return None


def _placeholder_for(spec: dict[str, Any]) -> Any:
    kind = (spec or {}).get("type", "string")
    return {"integer": 0, "number": 0, "boolean": False,
            "array": [], "object": {}}.get(kind, "scanner-test")


def _extract_text(result: Any) -> str:
    """Flatten a CallToolResult's content blocks into a single string."""
    parts: list[str] = []
    for block in getattr(result, "content", None) or []:
        text = getattr(block, "text", None)
        if text:
            parts.append(text)
    if parts:
        return "\n".join(parts)
    structured = getattr(result, "structuredContent", None)
    if structured is not None:
        return json.dumps(structured)
    return ""


def _extract_names(result: Any) -> list[str]:
    """Pull a list of entry names out of a list-tool result."""
    structured = getattr(result, "structuredContent", None)
    if isinstance(structured, dict):
        value = structured.get("result", structured)
        if isinstance(value, list):
            return [str(v) for v in value]
    names: list[str] = []
    for block in getattr(result, "content", None) or []:
        text = getattr(block, "text", None)
        if text:
            names.extend(line.strip() for line in text.splitlines() if line.strip())
    return names


async def _discover_filenames(client: MCPClient, tools: list[Any]) -> list[str]:
    """Ask any list-type tool for filenames, then add document fallbacks."""
    discovered: list[str] = []
    for tool in tools:
        if "list" not in _text(tool.name, tool.description):
            continue
        args = {name: _placeholder_for(_properties(tool)[name])
                for name in _required(tool)}
        try:
            result = await client.call_tool(tool.name, args)
        except Exception:
            continue
        if not getattr(result, "isError", False):
            discovered.extend(_extract_names(result))

    candidates: list[str] = []
    for name in [*discovered, *_FALLBACK_FILENAMES]:
        if name not in candidates:
            candidates.append(name)
    return candidates


def _read_args(read_tool: Any, target_param: str, filename: str) -> dict[str, Any]:
    args: dict[str, Any] = {target_param: filename}
    for name in _required(read_tool):
        if name != target_param and name not in args:
            args[name] = _placeholder_for(_properties(read_tool)[name])
    return args


def _tool_reference(content: str, name: str) -> bool:
    """True if `content` names the tool `name` at a word boundary."""
    return re.search(r"\b" + re.escape(name) + r"\b", content,
                     flags=re.IGNORECASE) is not None


def _referenced_tools(content: str, other_names: list[str]) -> list[str]:
    return [name for name in other_names if _tool_reference(content, name)]


def _imperative_markers(content: str) -> list[str]:
    """Labels of every imperative / injection-framing pattern present."""
    return [label for label, pattern in _IMPERATIVE_PATTERNS
            if pattern.search(content)]


def _directive_tool_refs(content: str, referenced: list[str]) -> list[str]:
    """Referenced tools that appear directly after a directive verb.

    Catches the "call <tool>" / "you must use <tool>" shape, where the tool name
    is the object of a command rather than a descriptive mention.
    """
    verbs = "|".join(_DIRECTIVE_VERBS)
    hits: list[str] = []
    for name in referenced:
        pattern = re.compile(
            r"(?i)\b(?:" + verbs + r")\s+(?:the\s+|a\s+|to\s+)?"
            + re.escape(name) + r"\b")
        if pattern.search(content):
            hits.append(name)
    return hits


def _injection_snippet(content: str, referenced: list[str]) -> str:
    """The lines of `content` that carry the payload, for evidence.

    Keeps lines that either match an imperative pattern or name a referenced
    tool, so the reader sees the planted instruction rather than the whole file.
    """
    kept: list[str] = []
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if any(p.search(line) for _, p in _IMPERATIVE_PATTERNS) or \
                any(_tool_reference(line, name) for name in referenced):
            kept.append(stripped)
    snippet = " ".join(kept) if kept else content.strip()
    return snippet[:_SNIPPET_LEN] + ("…" if len(snippet) > _SNIPPET_LEN else "")


async def _run_connected(client: MCPClient) -> list[Finding]:
    tools = await client.list_tools()
    read_tools = [t for t in tools if _is_read_tool(t)]
    if not read_tools:
        return []
    all_tool_names = [t.name for t in tools]

    candidates = await _discover_filenames(client, tools)
    findings: list[Finding] = []
    # One finding per (read tool, resource) that returns a payload, so a file
    # is not double-reported just because two read tools can both reach it.
    seen: set[tuple[str, str]] = set()

    for read_tool in read_tools:
        target_param = (_pick_param(read_tool, _TARGET_PARAM_HINTS)
                        or _first_string_param(read_tool))
        if not target_param:
            continue
        # Every tool on the server except the one whose output we're reading.
        other_names = [n for n in all_tool_names if n != read_tool.name]

        for filename in candidates:
            try:
                result = await client.call_tool(
                    read_tool.name, _read_args(read_tool, target_param, filename))
            except Exception:
                continue
            if getattr(result, "isError", False):
                continue
            content = _extract_text(result)
            if not content.strip():
                continue

            referenced = _referenced_tools(content, other_names)
            if not referenced:
                continue
            markers = _imperative_markers(content)
            directive_refs = _directive_tool_refs(content, referenced)
            # Gate: an OTHER tool is named AND the content is directive — either
            # via a general imperative marker or a "verb <tool>" command.
            if not markers and not directive_refs:
                continue

            key = (read_tool.name, filename)
            if key in seen:
                continue
            seen.add(key)
            findings.append(_make_finding(
                read_tool, target_param, filename, content, referenced,
                markers, directive_refs))
    return findings


def _make_finding(read_tool: Any, target_param: str, filename: str,
                  content: str, referenced: list[str], markers: list[str],
                  directive_refs: list[str]) -> Finding:
    snippet = _injection_snippet(content, referenced)
    # Surface the "verb <tool>" commands as markers too, so evidence names them.
    marker_list = list(markers)
    for name in directive_refs:
        marker_list.append(f"directive verb → {name}")
    return Finding(
        attack_id=ATTACK_ID,
        category=CATEGORY,
        title=f"Prompt injection in {read_tool.name} output ({filename})",
        outcome=Outcome.VULNERABLE,
        severity=Severity.HIGH,
        description=(
            f"Content returned by {read_tool.name!r} from {filename!r} contains "
            f"embedded instructions aimed at an AI agent. The injected text "
            f"names other tool(s) on this server ({', '.join(referenced)}) and "
            f"uses directive language, so an agent consuming this output could "
            f"be steered into misusing those tools. The scanner detected the "
            f"payload by inspection only and did not act on it."),
        evidence={
            "read_tool": read_tool.name,
            "read_call": f"{read_tool.name}({target_param}={filename!r})",
            "resource": filename,
            "referenced_tools": referenced,
            "detected_markers": marker_list,
            "injection_text": snippet,
            "content_sample": content[:_SAMPLE_LEN]
            + ("…" if len(content) > _SAMPLE_LEN else ""),
            "why_confirmed": (
                "returned content references at least one other tool on this "
                "server by its exact name AND carries imperative/directive "
                "language — the combination that marks a planted injection, not "
                "a descriptive mention"),
        },
    )


async def run(config: TargetConfig) -> list[Finding]:
    """Connect to the target and inspect read-tool output for planted prompt
    injection.

    Returns a list of `Finding`s (one per resource whose returned content
    carries a tool-referencing injection payload); an empty list means no
    inspected output contained one.
    """
    client = MCPClient(config)
    async with client.connect():
        return await _run_connected(client)
