"""Attack modules.

Each attack category lives in its own module here and exposes the same surface
so the CLI can run them uniformly:

    ATTACK_ID: str                      # stable slug, e.g. "permission_escalation"
    CATEGORY: str                       # vulnerability class, e.g. "permission-escalation"
    async def run(config) -> list[Finding]

`run` owns its own connection to the target, so modules are independent of each
other. `cli.ATTACK_MODULES` is the list `scan` walks.

Implemented so far:
  * `tool_chain_exfil` — read-tool output pushed out through a send tool.
  * `permission_escalation` — broken authorization on identity-scoped tools.
  * `prompt_injection_tool_output` — read-tool output carrying instructions that
    reference other tools on the same server.
"""
