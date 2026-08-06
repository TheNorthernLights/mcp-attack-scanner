"""Properly-secured MCP server — FALSE-POSITIVE CONTROL TARGET.

This is the control target for mcp-attack-scanner. It deliberately mirrors
`vulnerable_mcp_lab`: the same four tools, the same sandbox, the same seeded
fake `credentials.txt`, the same fake user directory. The differences are the
ones that matter — this server enforces egress control on `send_notification`
and identity scoping on `get_user_record`, so both attacks that succeed against
`vulnerable_mcp_lab` are refused here.

Its purpose is to check that the scanner stays quiet when there is nothing to
report. A finding against this target is a false positive.

The control on `get_user_record`:
  The tool is documented as self-scoped, and it enforces that: the requested
  `user_id` must equal the session's own identity, and any other id is refused
  with an authorization error instead of returning that user's record.

The two controls on `send_notification`:
  1. **Destination allowlist.** The webhook URL must be HTTPS and its host must
     appear in `ALLOWED_WEBHOOK_HOSTS`. Anything else is refused. URLs carrying
     userinfo (`https://allowed.host@attacker.example/`) are refused outright,
     since the effective host there is the attacker's.
  2. **Outbound content inspection.** Even for an allowlisted destination, the
     message body is scanned for credential-shaped content (AWS key formats,
     `password=`/`token=`/`secret=` assignments with an actual value, private
     key blocks, bearer tokens). A match is refused.

Every control here fails closed: a refusal raises, so the caller gets an MCP
tool error rather than a success response.

Safety, same as the vulnerable lab: the file tools are sandboxed, and
`send_notification` never makes a real HTTP request — an accepted send is only
appended to a local log file.
"""

from __future__ import annotations

import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from mcp.server.fastmcp import FastMCP

logger = logging.getLogger("clean_mcp_lab")

# Sandbox lives next to this module by default; override for tests via env var.
DEFAULT_SANDBOX = Path(__file__).resolve().parent / "sandbox"

# Pre-approved notification destinations. These are RFC 6761 `.test` names that
# resolve nowhere, so nothing here can reach a real host even by accident.
ALLOWED_WEBHOOK_HOSTS: frozenset[str] = frozenset({
    "hooks.internal.acme-lab.test",
    "alerts.internal.acme-lab.test",
})

# Credential-shaped content that must never leave via a notification. Each entry
# is (label, pattern); the label is what the refusal message names.
SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("AWS access key id", re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16}\b")),
    ("AWS secret access key", re.compile(
        r"(?i)\baws_secret_access_key\b\s*[:=]\s*\S+")),
    ("private key block", re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----")),
    ("bearer token", re.compile(r"(?i)\bauthorization\s*[:=]\s*bearer\s+\S+")),
    ("OpenAI-style API key", re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b")),
    # A secret-ish keyword assigned an actual value — the keyword alone is fine
    # ("please reset your password") but `password=hunter2` is not.
    ("credential assignment", re.compile(
        r"(?i)\b(?:password|passwd|secret|token|api[_-]?key|access[_-]?key"
        r"|client[_-]?secret|credential)s?\b\s*[:=]\s*[^\s'\"]{4,}")),
)

# Same fake user directory as the vulnerable lab — same made-up people, same
# never-issued 900-xx-xxxx SSN range. Only the access check differs.
USER_RECORDS: dict[str, dict[str, str]] = {
    "u1": {
        "user_id": "u1",
        "name": "Ada Nguyen",
        "email": "ada.nguyen@acme-lab.test",
        "ssn": "900-11-0001",
        "plan": "enterprise",
    },
    "u2": {
        "user_id": "u2",
        "name": "Bruno Okafor",
        "email": "bruno.okafor@acme-lab.test",
        "ssn": "900-22-0002",
        "plan": "starter",
    },
    "u3": {
        "user_id": "u3",
        "name": "Chen Wei",
        "email": "chen.wei@acme-lab.test",
        "ssn": "900-33-0003",
        "plan": "enterprise",
    },
}

# The identity this session is authenticated as. A real server would derive this
# per-request from an auth context (token, session cookie, mTLS identity); the
# lab has no auth system, so the "logged-in user" is fixed. What matters for the
# control is that the caller cannot influence it — it is never read from tool
# arguments.
CURRENT_SESSION_USER = "u1"

mcp = FastMCP("clean-mcp-lab")


def _sandbox_root() -> Path:
    return Path(os.environ.get("CLEAN_MCP_SANDBOX", DEFAULT_SANDBOX)).resolve()


def _resolve_in_sandbox(relative: str) -> Path:
    """Resolve a user-supplied path and confirm it stays inside the sandbox."""
    root = _sandbox_root()
    candidate = (root / relative).resolve()
    if candidate != root and root not in candidate.parents:
        raise ValueError(f"path {relative!r} escapes the sandbox; access denied")
    return candidate


def _check_destination(webhook_url: str) -> str:
    """Return the allowlisted host for `webhook_url`, or raise if not approved."""
    try:
        parts = urlsplit(webhook_url)
    except ValueError as exc:
        raise ValueError(f"malformed webhook URL: {exc}") from exc

    if parts.scheme.lower() != "https":
        raise ValueError(
            f"destination rejected: scheme {parts.scheme or '(none)'!r} is not "
            "https; notifications may only be sent over https")
    if "@" in parts.netloc:
        raise ValueError(
            "destination rejected: webhook URL carries userinfo, which can "
            "disguise the real host")

    host = (parts.hostname or "").lower()
    if host not in ALLOWED_WEBHOOK_HOSTS:
        raise ValueError(
            f"destination rejected: {host or webhook_url!r} is not in the "
            f"approved webhook allowlist "
            f"({', '.join(sorted(ALLOWED_WEBHOOK_HOSTS))})")
    return host


def _check_content(message: str) -> None:
    """Raise if `message` looks like it carries credentials or secrets."""
    matched = [label for label, pattern in SECRET_PATTERNS
               if pattern.search(message)]
    if matched:
        raise ValueError(
            "content rejected: outbound message matches credential patterns "
            f"({', '.join(matched)}); refusing to forward secret material")


@mcp.tool()
def read_file(path: str) -> str:
    """Read a UTF-8 text file from the sandboxed directory.

    `path` is relative to the sandbox root (e.g. "credentials.txt").
    """
    target = _resolve_in_sandbox(path)
    if not target.is_file():
        raise FileNotFoundError(f"no such file in sandbox: {path!r}")
    return target.read_text(encoding="utf-8", errors="replace")


@mcp.tool()
def list_files(directory: str = ".") -> list[str]:
    """List entries in a sandboxed directory (relative to the sandbox root)."""
    target = _resolve_in_sandbox(directory)
    if not target.is_dir():
        raise NotADirectoryError(f"not a directory in sandbox: {directory!r}")
    return sorted(p.name for p in target.iterdir())


@mcp.tool()
def send_notification(message: str, webhook_url: str) -> str:
    """Send a notification to a pre-approved webhook — SIMULATED, no real HTTP.

    The destination must be an https URL whose host is on the approved
    allowlist, and the message must not contain credential-shaped content.
    Either check failing refuses the send.
    """
    host = _check_destination(webhook_url)
    _check_content(message)

    log_path = _sandbox_root().parent / "notifications.log"
    timestamp = datetime.now(timezone.utc).isoformat()
    with log_path.open("a", encoding="utf-8") as fh:
        fh.write(f"{timestamp}\tPOST {webhook_url}\t{message}\n")
    logger.info("SIMULATED notification -> %s", host)
    return f"Notification queued to {webhook_url} (simulated, logged locally)."


@mcp.tool()
def get_user_record(user_id: str) -> dict[str, str]:
    """Get the current user's own account record.

    Identity scope is enforced: the requested `user_id` must be the session's
    own identity. Asking for anyone else's id is refused with an authorization
    error, so this tool cannot be used to read another user's record.
    """
    if user_id != CURRENT_SESSION_USER:
        logger.warning("denied cross-identity record read for user_id=%s", user_id)
        raise ValueError(
            f"authorization denied: this session is {CURRENT_SESSION_USER!r} and "
            f"may only read its own record, not {user_id!r}")

    record = USER_RECORDS.get(CURRENT_SESSION_USER)
    if record is None:
        raise KeyError(f"no such user record: {CURRENT_SESSION_USER!r}")
    return dict(record)


def main() -> None:
    """Run the server over stdio (default MCP transport)."""
    logging.basicConfig(level=logging.INFO)
    mcp.run()


if __name__ == "__main__":
    main()
