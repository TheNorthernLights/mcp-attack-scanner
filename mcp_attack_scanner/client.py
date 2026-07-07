"""MCP client connection logic.

Wraps the official `mcp` Python SDK to connect to a target MCP server over
either stdio (spawn a subprocess) or streamable HTTP. Attack modules use this
client to enumerate and invoke tools on the target.

NOTE (scaffold only): the connection methods are stubs. The `mcp` SDK is
imported lazily inside methods so the CLI and its `--help` load even when the
SDK (which requires Python 3.10+) is not installed.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, AsyncIterator


class Transport(str, Enum):
    """Transport used to reach the target MCP server."""

    STDIO = "stdio"
    HTTP = "http"


@dataclass
class TargetConfig:
    """How to reach the MCP server under test.

    For STDIO: `command` and `args` describe the subprocess to spawn.
    For HTTP: `url` is the streamable-HTTP endpoint of the server.
    """

    transport: Transport

    # stdio
    command: str | None = None
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)

    # http
    url: str | None = None
    headers: dict[str, str] = field(default_factory=dict)

    def validate(self) -> None:
        if self.transport is Transport.STDIO and not self.command:
            raise ValueError("stdio transport requires a --command to spawn")
        if self.transport is Transport.HTTP and not self.url:
            raise ValueError("http transport requires a --url")


class MCPClient:
    """Thin async wrapper around an MCP SDK client session.

    Scaffold only — the actual session wiring lands in a later session.
    """

    def __init__(self, config: TargetConfig) -> None:
        config.validate()
        self.config = config
        self._session: Any | None = None

    @asynccontextmanager
    async def connect(self) -> AsyncIterator["MCPClient"]:
        """Open a session to the target and yield a connected client.

        Not yet implemented. Will use `mcp.client.stdio.stdio_client` or
        `mcp.client.streamable_http.streamablehttp_client` depending on the
        configured transport, then initialize an `mcp.ClientSession`.
        """
        raise NotImplementedError(
            "MCP connection is not implemented yet (scaffold only)."
        )
        # The following makes this a valid async generator for type-checkers.
        yield self  # pragma: no cover

    async def list_tools(self) -> list[Any]:
        """Enumerate tools exposed by the target. Not yet implemented."""
        raise NotImplementedError("list_tools is not implemented yet (scaffold only).")

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        """Invoke a tool on the target. Not yet implemented."""
        raise NotImplementedError("call_tool is not implemented yet (scaffold only).")
