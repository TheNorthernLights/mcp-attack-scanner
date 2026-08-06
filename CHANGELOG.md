# Changelog

All notable changes to `mcp-attack-scanner` are recorded here. This project is
early-stage — versioning follows [Semantic Versioning](https://semver.org),
and pre-1.0 releases may make breaking changes to the CLI or JSON schema
between minor versions.

## [0.1.0] — 2026-08-06

Initial public release. A working proof-of-concept, not a stable production
tool.

### Added
- `MCPClient`: a thin async wrapper over the official `mcp` SDK that connects
  to a target MCP server over **stdio** (spawn a subprocess) or **streamable
  HTTP** (connect to a remote endpoint) and performs the `initialize`
  handshake. Transport choice is confined to `connect()`, so everything above
  it is transport-agnostic.
- Attack module **`tool_chain_exfil`**: dynamically discovers read-shaped and
  send-shaped tools on the target, drives a `read → send` chain, and reports a
  finding only when the send call succeeded and carried the exact bytes the
  read call returned.
- Attack module **`permission_escalation`**: probes identity-scoped read tools
  (`get_user_record(user_id=…)` and similar) with two different identifiers
  and reports a finding only when both calls succeed with substantive,
  refusal-free responses that still differ once the identifiers themselves are
  stripped.
- CLI (`mcp-attack-scanner`) with three subcommands:
  - `list-tools` — enumerate the target's tools.
  - `call-tool` — invoke a single tool (debug helper).
  - `scan` — run every implemented attack module and render a combined report.
- Human (via `rich`) and machine-readable JSON output for every command.
- `--verbose` flag to surface the target subprocess's own stderr (off by
  default so a chatty server does not obscure findings).
- `--connect-timeout` flag (default 30s) bounding the initialize handshake.
- Preflight connection check in `scan`, so an unreachable target produces one
  clean error instead of one "module raised" entry per attack module.
- Friendly, non-traceback error messages for the common failure modes
  (missing `--command`/`--url`, unknown executable, connection refused,
  handshake timeout, unknown tool name, malformed `--arg`).
- Test lab: **`vulnerable_mcp_lab`** — a deliberately-vulnerable FastMCP
  server with two intentional flaws (one per attack category), fully
  sandboxed (path-traversal-safe file tools, simulated-only "send" tool,
  invented users with never-issued SSN-shaped values).
- Test lab: **`clean_mcp_lab`** — a defended counterpart with egress control
  on the send path and enforced identity scoping; the scanner reports 0
  findings against it (false-positive check).
- `serve_http.py` helper that runs either lab over streamable HTTP for
  transport-parity testing.
- Test suite: 52 tests covering the CLI, both attack modules' selection /
  confirmation heuristics, and end-to-end runs against both labs.

[0.1.0]: https://github.com/TheNorthernLights/mcp-attack-scanner/releases/tag/v0.1.0
