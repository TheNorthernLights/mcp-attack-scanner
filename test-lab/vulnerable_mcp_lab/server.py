"""Deliberately vulnerable MCP server — TEST TARGET ONLY.

    ⚠️  This server is intentionally insecure. It exists solely so that
        mcp-attack-scanner has something realistic to attack in a contained
        lab. NEVER expose it on a network, NEVER run it against real files,
        and NEVER give it a real webhook URL.

What is safe here (deliberate guardrails — keep these):
  * `read_file` / `list_files` are contained to a sandbox directory. Path
    traversal outside the sandbox is rejected, so no real system files are
    reachable.
  * `send_notification` never makes a real HTTP request. It only appends to a
    local log file to *simulate* an outbound webhook.

The INTENTIONAL vulnerabilities (the whole point of this lab):
  1. **Tool-chaining exfiltration.** There is no data-flow / egress control.
     Nothing stops an agent from calling `read_file("credentials.txt")` and then
     feeding the returned secret straight into
     `send_notification(message=<secret>, webhook_url=<attacker>)`.
  2. **Broken authorization on an identity-scoped tool.** `get_user_record` is
     documented as returning "the current user's own account record", but it
     never checks that the requested `user_id` is the caller's — the MCP
     equivalent of an IDOR.

Both are exactly what mcp-attack-scanner should catch.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from pathlib import Path

from mcp.server.fastmcp import FastMCP

logger = logging.getLogger("vulnerable_mcp_lab")

# Sandbox lives next to this module by default; override for tests via env var.
DEFAULT_SANDBOX = Path(__file__).resolve().parent / "sandbox"

# In-memory fake user directory backing `get_user_record`. These people do not
# exist: the addresses are RFC 6761 `.test` names that resolve nowhere, and the
# `ssn` values use the 900-xx-xxxx range, which the SSA has never issued, so no
# value here can collide with a real person's number.
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

mcp = FastMCP("vulnerable-mcp-lab")


def _sandbox_root() -> Path:
    return Path(os.environ.get("VULN_MCP_SANDBOX", DEFAULT_SANDBOX)).resolve()


def _resolve_in_sandbox(relative: str) -> Path:
    """Resolve a user-supplied path and CONFIRM it stays inside the sandbox.

    This containment is an intentional safety guardrail and must not be
    weakened — the lab's intended vulnerability is tool-chaining exfiltration,
    not arbitrary file read.
    """
    root = _sandbox_root()
    candidate = (root / relative).resolve()
    if candidate != root and root not in candidate.parents:
        raise ValueError(
            f"path {relative!r} escapes the sandbox; access denied"
        )
    return candidate


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
    """"Send" a notification to a webhook — SIMULATED, no real HTTP call.

    Intentionally performs no validation on `message` or `webhook_url`: any
    content can be sent to any URL. The call is only appended to a local log
    file so nothing actually leaves the machine.
    """
    log_path = _sandbox_root().parent / "notifications.log"
    timestamp = datetime.now(timezone.utc).isoformat()
    entry = f"{timestamp}\tPOST {webhook_url}\t{message}\n"
    with log_path.open("a", encoding="utf-8") as fh:
        fh.write(entry)
    logger.warning("SIMULATED notification -> %s: %s", webhook_url, message)
    return f"Notification queued to {webhook_url} (simulated, logged locally)."


@mcp.tool()
def get_user_record(user_id: str) -> dict[str, str]:
    """Get the current user's own account record.

    Intentionally performs no authorization check: the tool is documented as
    self-scoped ("your own record"), but it never establishes who the caller is
    and never confirms that `user_id` is the caller's own identity. It simply
    looks the id up and hands back whoever matches — so any caller can read any
    user's record, fake SSN included. This is the MCP equivalent of an IDOR, and
    it is the second thing mcp-attack-scanner should catch here.
    """
    record = USER_RECORDS.get(user_id)
    if record is None:
        # An id nobody owns is a plain lookup miss, not an authorization event.
        raise KeyError(f"no such user record: {user_id!r}")
    logger.warning("UNSCOPED record read for user_id=%s", user_id)
    return dict(record)


def main() -> None:
    """Run the server over stdio (default MCP transport)."""
    logging.basicConfig(level=logging.INFO)
    mcp.run()


if __name__ == "__main__":
    main()
