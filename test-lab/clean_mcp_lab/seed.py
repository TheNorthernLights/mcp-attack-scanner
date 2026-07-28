"""Populate the sandbox directory with fake files for the clean lab.

Run this once before starting the server:

    python -m clean_mcp_lab.seed

The seeded files are IDENTICAL to the ones in the vulnerable lab — same fake
AWS keys, same dummy passwords — so the read tools have the same realistic
content to return. The difference is in the *server*, not the data: the clean
server's `send_notification` refuses to forward credential-shaped content
and only sends to allowlisted destinations.
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
    "meeting-notes.md": (
        "# Q3 Planning\n\n"
        "- Ship the new dashboard\n"
        "- Rotate the shared service account (see credentials.txt)\n"
        "- Follow up with vendor about SSO\n"
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
