"""Permission escalation via broken authorization on identity-scoped tools.

The MCP analogue of an IDOR. A tool advertised as self-scoped — "get *your*
account record", "list *your* orders" — takes the identity it operates on as an
ordinary input parameter (`user_id`, `account_id`, ...). If the server trusts
that parameter instead of checking it against the caller's own identity, any
client can read any identity's data just by changing the argument.

Like the other modules this is *dynamic*: the verdict comes from calling the
tool twice with two different identifiers on a live target and comparing what
comes back. A description that merely says "your own record" proves nothing
either way.

Conservatism is the point here — "the second call didn't error" is far too weak
a signal, because a tool can succeed while returning nothing, an error string,
or a bare echo of the id it was handed. A finding requires all of:

  * the baseline call succeeded and returned substantive data;
  * the probe call (a *different* identifier) succeeded and returned
    substantive data;
  * the probe response is not error/refusal-shaped;
  * the two responses still differ after the identifiers themselves are
    stripped out — i.e. genuinely different *records* came back, not the same
    template with a different id echoed into it.

Only read-shaped tools are probed. A parameter named `user_id` on a
`delete_account` tool is just as likely to be vulnerable, but confirming it
would mean destroying someone's data on the target; that trade is not worth
making, so mutating tools are skipped.
"""

from __future__ import annotations

import json
import re
from typing import Any

from ..client import MCPClient, TargetConfig
from ..reporting import Finding, Outcome, Severity

ATTACK_ID = "permission_escalation"
CATEGORY = "permission-escalation"

# Parameter names that suggest the tool is scoped to an identity the caller is
# supposed to own. Matched as substrings against lowercased parameter names.
_IDENTITY_PARAM_HINTS = (
    "user_id", "userid", "user", "account_id", "accountid", "account",
    "owner_id", "ownerid", "owner", "customer_id", "customerid",
    "member_id", "memberid", "profile_id", "profileid",
    "subject_id", "principal_id", "tenant_id", "org_id", "organization_id",
    "self", "uid", "caller", "actor",
)

# Tools whose name/description suggest they change state. Never probed: the
# attack works by calling the same tool twice with different identities, which
# against a mutating tool means damaging data that isn't ours.
_MUTATION_HINTS = (
    "create", "update", "delete", "remove", "write", "set", "put", "patch",
    "insert", "add", "edit", "modify", "rename", "move", "copy", "upload",
    "send", "post", "publish", "transfer", "pay", "charge", "revoke", "grant",
    "reset", "rotate", "disable", "enable", "invite", "cancel", "close",
    "approve", "execute", "run", "exec",
)

# Identifiers tried, in order, to establish a baseline "our own" identity.
_BASELINE_IDS = ("u1", "1", "user1", "user-1", "user_1", "u001", "100", "1001",
                 "0", "a1", "id1")

# Tried after the baseline-derived neighbours are exhausted.
_GENERIC_PROBE_IDS = ("u2", "u3", "2", "3", "user2", "admin", "root")

# A probe response containing one of these is treated as a refusal, not data,
# even when the server reported the call as successful (isError=False).
_REFUSAL_MARKERS = (
    "unauthorized", "not authorized", "authorization", "forbidden", "denied",
    "permission", "access is restricted", "not allowed", "must be",
    "not found", "no such", "does not exist", "doesn't exist", "unknown user",
    "error", "invalid", "failed", "exception", "traceback",
)

# Below this length a response carries too little to call it "a record".
_MIN_SUBSTANTIVE_LEN = 20
_SAMPLE_LEN = 300

_TRAILING_NUMBER = re.compile(r"^(.*?)(\d+)(\D*)$")


def _text(*parts: str | None) -> str:
    return " ".join(p for p in parts if p).lower()


def _properties(tool: Any) -> dict[str, Any]:
    return (tool.inputSchema or {}).get("properties") or {}


def _required(tool: Any) -> list[str]:
    return list((tool.inputSchema or {}).get("required") or [])


def _placeholder_for(spec: dict[str, Any]) -> Any:
    kind = (spec or {}).get("type", "string")
    return {"integer": 0, "number": 0, "boolean": False,
            "array": [], "object": {}}.get(kind, "scanner-test")


def _identity_param(tool: Any) -> str | None:
    """The tool's identity-scoping parameter, if it has one.

    Prefers the most specific match (`user_id` over a bare `user`), and only
    considers string/integer-typed parameters — an identity does not arrive as
    an array or an object.
    """
    best: tuple[int, str] | None = None
    for name, spec in _properties(tool).items():
        kind = (spec or {}).get("type", "string")
        if kind not in ("string", "integer", "number"):
            continue
        low = name.lower()
        matches = [h for h in _IDENTITY_PARAM_HINTS if h in low]
        if not matches:
            continue
        score = max(len(h) for h in matches)
        if best is None or score > best[0]:
            best = (score, name)
    return best[1] if best else None


def _is_mutating(tool: Any) -> bool:
    """True if the tool looks like it changes state (so we leave it alone)."""
    name_words = re.split(r"[^a-z0-9]+", tool.name.lower())
    if any(word in _MUTATION_HINTS for word in name_words):
        return True
    description = (tool.description or "").lower()
    return any(f" {hint} " in f" {description} " for hint in _MUTATION_HINTS)


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
        return json.dumps(structured, sort_keys=True, default=str)
    return ""


def _adjacent_ids(baseline: str) -> list[str]:
    """Plausible *other* identifiers, given the one that worked.

    Neighbours derived from the baseline come first (`u1` → `u2`, `u3`,
    preserving any prefix and zero-padding), then a fixed generic set.
    """
    probes: list[str] = []
    match = _TRAILING_NUMBER.match(baseline)
    if match:
        prefix, digits, suffix = match.groups()
        for delta in (1, 2):
            nxt = str(int(digits) + delta)
            probes.append(f"{prefix}{nxt.zfill(len(digits))}{suffix}")
    probes.extend(_GENERIC_PROBE_IDS)

    ordered: list[str] = []
    for probe in probes:
        if probe != baseline and probe not in ordered:
            ordered.append(probe)
    return ordered


def _args_for(tool: Any, identity_param: str, identity: str) -> dict[str, Any]:
    """Call arguments: the identity under test, plus placeholders for whatever
    else the tool requires."""
    args: dict[str, Any] = {identity_param: identity}
    for name in _required(tool):
        if name not in args:
            args[name] = _placeholder_for(_properties(tool)[name])
    return args


def _looks_like_refusal(payload: str) -> bool:
    low = payload.lower()
    return any(marker in low for marker in _REFUSAL_MARKERS)


def _is_substantive(payload: str) -> bool:
    return len(payload.strip()) >= _MIN_SUBSTANTIVE_LEN


def _strip_ids(payload: str, *identities: str) -> str:
    """Remove the identifiers themselves and all whitespace from a response.

    Used to answer "is this actually different data?" — a tool that just echoes
    its argument back inside a fixed template collapses to the same string for
    both calls, and is therefore not reported.
    """
    stripped = payload
    for identity in identities:
        if identity:
            stripped = re.sub(re.escape(identity), "", stripped,
                              flags=re.IGNORECASE)
    return re.sub(r"\s+", "", stripped)


def _is_distinct_data(baseline: str, probe: str, baseline_id: str,
                      probe_id: str) -> bool:
    """True only if the two responses represent genuinely different records."""
    if baseline.strip() == probe.strip():
        return False
    core_baseline = _strip_ids(baseline, baseline_id, probe_id)
    core_probe = _strip_ids(probe, baseline_id, probe_id)
    if core_baseline == core_probe:
        return False
    # Both must still hold real content once the identifiers are removed.
    return (len(core_baseline) >= _MIN_SUBSTANTIVE_LEN
            and len(core_probe) >= _MIN_SUBSTANTIVE_LEN)


async def _call(client: MCPClient, tool: Any, identity_param: str,
                identity: str) -> str | None:
    """Call `tool` for `identity`; return its payload, or None if the call
    errored, was refused, or came back too thin to mean anything."""
    try:
        result = await client.call_tool(
            tool.name, _args_for(tool, identity_param, identity))
    except Exception:
        return None
    if getattr(result, "isError", False):
        return None
    payload = _extract_text(result)
    if not _is_substantive(payload) or _looks_like_refusal(payload):
        return None
    return payload


async def _probe_tool(client: MCPClient, tool: Any,
                      identity_param: str) -> Finding | None:
    """Establish a baseline identity on `tool`, then try to read another one."""
    baseline_id = baseline = None
    for candidate in _BASELINE_IDS:
        payload = await _call(client, tool, identity_param, candidate)
        if payload is not None:
            baseline_id, baseline = candidate, payload
            break
    if baseline is None or baseline_id is None:
        return None

    for probe_id in _adjacent_ids(baseline_id):
        probe = await _call(client, tool, identity_param, probe_id)
        if probe is None:
            continue
        if not _is_distinct_data(baseline, probe, baseline_id, probe_id):
            continue
        return _make_finding(tool, identity_param, baseline_id, baseline,
                             probe_id, probe)
    return None


async def _run_connected(client: MCPClient) -> list[Finding]:
    findings: list[Finding] = []
    for tool in await client.list_tools():
        identity_param = _identity_param(tool)
        if not identity_param or _is_mutating(tool):
            continue
        finding = await _probe_tool(client, tool, identity_param)
        if finding is not None:
            findings.append(finding)
    return findings


def _sample(payload: str) -> str:
    return payload[:_SAMPLE_LEN] + ("…" if len(payload) > _SAMPLE_LEN else "")


def _make_finding(tool: Any, identity_param: str, baseline_id: str,
                  baseline: str, probe_id: str, probe: str) -> Finding:
    return Finding(
        attack_id=ATTACK_ID,
        category=CATEGORY,
        title=f"Cross-identity data access via {tool.name}",
        outcome=Outcome.VULNERABLE,
        severity=Severity.HIGH,
        description=(
            f"{tool.name!r} takes the identity it operates on as the "
            f"{identity_param!r} parameter and does not check it against the "
            f"caller's own identity. Calling it with {baseline_id!r} and then "
            f"with {probe_id!r} returned two different records, so any client "
            f"can read data belonging to identities it does not own."),
        evidence={
            "tool": tool.name,
            "tool_description": (tool.description or "").strip(),
            "identity_param": identity_param,
            "baseline_call": f"{tool.name}({identity_param}={baseline_id!r})",
            "baseline_result": _sample(baseline),
            "probe_call": f"{tool.name}({identity_param}={probe_id!r})",
            "probe_result": _sample(probe),
            "why_confirmed": (
                "both calls succeeded (isError=False), neither response was "
                "refusal-shaped, and the two responses still differ after the "
                "identifiers themselves are removed — different records, not "
                "the same template echoing the argument back"),
        },
    )


async def run(config: TargetConfig) -> list[Finding]:
    """Connect to the target and attempt cross-identity access on its
    identity-scoped tools.

    Returns a list of `Finding`s (one per tool with a confirmed authorization
    boundary violation); an empty list means every identity-scoped tool held
    its boundary.
    """
    client = MCPClient(config)
    async with client.connect():
        return await _run_connected(client)
