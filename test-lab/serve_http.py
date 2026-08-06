"""Serve one of the test labs over streamable HTTP — TEST HELPER ONLY.

The lab servers (`vulnerable_mcp_lab.server`, `clean_mcp_lab.server`) default to
stdio when run directly. This wrapper reuses the exact same `FastMCP` instance
and its exact same tools, but runs it over streamable HTTP so the scanner can be
exercised end-to-end against a remote-style endpoint. Nothing about the tools or
their (deliberately in/secure) behaviour changes — only the transport.

Usage:
    python test-lab/serve_http.py                 # vulnerable lab, :8081/mcp
    python test-lab/serve_http.py --lab clean     # clean lab
    python test-lab/serve_http.py --port 9000     # custom port

The endpoint the scanner should target is  http://<host>:<port>/mcp .

Safety: same guardrails as the stdio labs — file tools are sandboxed and
`send_notification` never makes a real HTTP request. Bind to localhost only;
never expose these deliberately-vulnerable servers on a network.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Allow running as a plain script (`python test-lab/serve_http.py`) by putting
# the test-lab directory on the path so `vulnerable_mcp_lab` / `clean_mcp_lab`
# import the same way they do under stdio.
sys.path.insert(0, str(Path(__file__).resolve().parent))

LABS = {
    "vulnerable": "vulnerable_mcp_lab.server",
    "clean": "clean_mcp_lab.server",
}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--lab",
        choices=sorted(LABS),
        default="vulnerable",
        help="Which lab server to serve (default: vulnerable).",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host to bind (default: 127.0.0.1 — keep it localhost).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8081,
        help="Port to listen on (default: 8081).",
    )
    args = parser.parse_args()

    import importlib

    module = importlib.import_module(LABS[args.lab])
    server = module.mcp  # the shared FastMCP instance, tools already registered

    server.settings.host = args.host
    server.settings.port = args.port

    endpoint = f"http://{args.host}:{args.port}{server.settings.streamable_http_path}"
    print(f"serving {args.lab} lab over streamable HTTP at {endpoint}",
          file=sys.stderr, flush=True)

    server.run(transport="streamable-http")


if __name__ == "__main__":
    main()
