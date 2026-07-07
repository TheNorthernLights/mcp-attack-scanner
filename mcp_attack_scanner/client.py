"""MCP client connection logic.

Wraps the official `mcp` Python SDK to connect to a target MCP server over
either stdio (spawn a subprocess) or streamable HTTP. Attack modules use this
client to enumerate and invoke tools on the target.

The `mcp` SDK is imported lazily inside methods so the CLI and its `--help`
load even when the SDK (which requires Python 3.10+) is not installed. Only
stdio transport is wired up so far; HTTP support arrives in a later session.
"""

from __future__ import annotations

from contextlib import AsyncExitStack, asynccontextmanager
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
    """Thin async wrapper around an MCP SDK client session."""

    def __init__(self, config: TargetConfig) -> None:
        config.validate()
        self.config = config
        self._session: Any | None = None

    @asynccontextmanager
    async def connect(self) -> AsyncIterator["MCPClient"]:
        """Open a session to the target and yield a connected client.

        Spawns the target (stdio transport), performs the MCP `initialize`
        handshake, and keeps the session open for the duration of the `async
        with` block. On exit the session and the transport are torn down and
        the subprocess is reaped.
        """
        if self.config.transport is not Transport.STDIO:
            raise NotImplementedError(
                f"{self.config.transport.value!r} transport is not implemented "
                "yet; only stdio is supported."
            )

        from mcp import ClientSession
        from mcp.client.stdio import StdioServerParameters, stdio_client

        server_params = StdioServerParameters(
            command=self.config.command,  # validated non-None for stdio
            args=self.config.args,
            env=self.config.env or None,
        )

        async with AsyncExitStack() as stack:
            read, write = await stack.enter_async_context(
                stdio_client(server_params)
            )
            session = await stack.enter_async_context(ClientSession(read, write))
            await session.initialize()
            self._session = session
            try:
                yield self
            finally:
                self._session = None

    def _require_session(self) -> Any:
        if self._session is None:
            raise RuntimeError(
                "not connected; use `async with client.connect():` first"
            )
        return self._session

    async def list_tools(self) -> list[Any]:
        """Enumerate tools exposed by the target.

        Returns the SDK `Tool` objects (each carries `name`, `description`,
        and `inputSchema`).
        """
        session = self._require_session()
        result = await session.list_tools()
        return list(result.tools)

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        """Invoke a tool on the target. Not yet implemented."""
        raise NotImplementedError("call_tool is not implemented yet (scaffold only).")
