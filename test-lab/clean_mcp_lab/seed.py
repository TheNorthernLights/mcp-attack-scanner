"""Populate the sandbox directory with fake files for the clean lab.

Run this once before starting the server:

    python -m clean_mcp_lab.seed

The seeded files mirror the vulnerable lab's — same fake AWS keys, same dummy
passwords — so the read tools have the same realistic content to return. Two
deliberate differences make this the false-positive control:

  * The tool-chaining / permission-escalation controls live in the *server*,
    not the data: the clean server's `send_notification` refuses to forward
    credential-shaped content and only sends to allowlisted destinations, and
    `get_user_record` enforces identity scope.
  * `meeting-notes.md` here is the SAME document as the vulnerable lab's but
    with the planted prompt-injection block removed — ordinary meeting notes
    that mention no tool by name and give the agent no instructions. The
    prompt-injection module must stay silent on it.
"""

from __future__ import annotations

import os
from pathlib import Path

DEFAULT_SANDBOX = Path(__file__).resolve().parent / "sandbox"

SEED_FILES: dict[str, str] = {
    "credentials.txt": (
        "# ACME Corp service credentials\n"
        "# !!! FAKE TEST DATA — NOT REAL, DO NOT USE !!!\n"
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        "DB_PASSWORD=hunter2-do-not-use\n"
        "API_TOKEN=sk-test-000000000000000000000000\n"
    ),
    "README.txt": (
        "Internal file share (lab fixture).\n"
        "Contains routine project notes plus a credentials file that should\n"
        "never leave this directory.\n"
    ),
    # Same document as the vulnerable lab's meeting-notes.md, minus the planted
    # injection block. Ordinary notes: no tool is named, no instruction is aimed
    # at an agent. This is the control the prompt-injection module must not flag.
    "meeting-notes.md": (
        "# Q3 Planning — Weekly Sync\n\n"
        "Attendees: Ada, Bruno, Chen\n\n"
        "## Agenda\n"
        "- Ship the new analytics dashboard by end of sprint\n"
        "- Rotate the shared service account (tracked in credentials.txt)\n"
        "- Follow up with the vendor about the SSO rollout\n\n"
        "## Discussion\n"
        "Bruno walked through the dashboard mockups. We agreed to cut the\n"
        "export-to-PDF feature from this release and revisit it in Q4. Chen\n"
        "raised that the staging environment needs more memory before launch.\n\n"
        "## Action items\n"
        "- Ada: finalize the dashboard spec by Thursday\n"
        "- Chen: schedule the vendor SSO call\n"
        "- Bruno: open the ticket to rotate the service account\n"
    ),
}


def seed(sandbox: Path | None = None) -> Path:
    root = sandbox or Path(os.environ.get("CLEAN_MCP_SANDBOX", DEFAULT_SANDBOX))
    root = root.resolve()
    root.mkdir(parents=True, exist_ok=True)
    for name, contents in SEED_FILES.items():
        (root / name).write_text(contents, encoding="utf-8")
    return root


def main() -> None:
    root = seed()
    print(f"Seeded sandbox at: {root}")
    for name in sorted(SEED_FILES):
        print(f"  - {name}")


if __name__ == "__main__":
    main()
