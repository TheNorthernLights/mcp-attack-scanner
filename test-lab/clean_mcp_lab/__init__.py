"""clean_mcp_lab: a properly-secured MCP server used as a false-positive control.

This is the counterpart to `vulnerable_mcp_lab`. It exposes the same three tools
but enforces egress control on the send path, so mcp-attack-scanner should find
nothing here. See the README in the `test-lab/` directory.
"""

__version__ = "0.0.1"
