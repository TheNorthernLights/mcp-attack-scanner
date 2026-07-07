# MCP Attack Scanner

**Dynamic** security testing for [MCP (Model Context Protocol)](https://modelcontextprotocol.io) servers.

`mcp-attack-scanner` connects to a **live** target MCP server and executes
attacks end-to-end to see what actually succeeds, rather than statically
pattern-matching on tool descriptions. Existing tools such as
[`mcp-scan`](https://github.com/invariantlabs-ai/mcp-scan) inspect tool
metadata; this project drives the server and observes real behavior.

## Attack categories (planned)

- **Tool-chaining abuse** — chaining otherwise-benign tools into a harmful
  end-to-end effect.
- **Permission escalation** — using tool access to reach state or actions
  beyond the intended authorization boundary.
- **Prompt-injection-via-tool-output** — malicious content returned by one tool
  steering a downstream model/agent into unintended tool calls.

## Status

**Scaffold only.** This is the initial project skeleton. No attack logic is
implemented yet — attack categories are added one at a time in subsequent work.

What exists today:

| Component | State |
| --- | --- |
| Package layout, CLI, config plumbing | ✅ scaffolded |
| MCP client (stdio + HTTP) | 🚧 stubbed (`NotImplementedError`) |
| Attack modules | ⬜ none yet (`attacks/` is empty) |
| Reporting (JSON + human-readable) | ✅ data model + renderers |
| Tests | ✅ scaffold smoke tests |

Running `scan` or `list-tools` today raises a clear "not implemented" message.

## Layout

```
mcp_attack_scanner/
  cli.py         # CLI entrypoint (click)
  client.py      # MCP client connection logic (stdio / HTTP, official mcp SDK)
  reporting.py   # structured output: JSON + human-readable (rich)
  attacks/       # one module per attack category (empty for now)
tests/           # pytest smoke tests
```

## Requirements

Python **3.10+** (required by the `mcp` SDK).

## Install

```bash
python -m venv venv && source venv/bin/activate
pip install -e ".[dev]"
```

## Usage

```bash
# Show help
mcp-attack-scanner --help

# Target a stdio server (spawns a subprocess)
mcp-attack-scanner scan --transport stdio --command python --arg -m --arg my_server

# Target an HTTP server
mcp-attack-scanner scan --transport http --url https://example.com/mcp
```

## ⚠️ Authorized use only

This is an offensive security testing tool. Only run it against MCP servers you
own or are explicitly authorized to test.

## License

MIT
