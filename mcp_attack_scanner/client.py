"""MCP client connection logic.

Wraps the official `mcp` Python SDK to connect to a target MCP server over
either stdio (spawn a subprocess) or streamable HTTP. Attack modules use this
client to enumerate and invoke tools on the target.

The `mcp` SDK is imported lazily inside methods so the CLI and its `--help`
load even when the SDK (which requires Python 3.10+) is not installed. Both
stdio (spawn a subprocess) and streamable HTTP (connect to a remote endpoint)
transports are supported; the choice is confined to `connect()` so everything
above it — attack modules, reporting, CLI — is transport-agnostic.
"""

from __future__ import annotations

import os
import sys
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, AsyncIterator

# Default budget for connecting to the target and completing its MCP
# `initialize` handshake. Individual tool calls are not clamped by this — a
# tool that legitimately takes a while is not the connection's fault.
DEFAULT_CONNECT_TIMEOUT = 30.0


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

    # Show the target subprocess's stderr (stdio only). Off by default so a
    # chatty server does not drown out the scanner's own output.
    verbose: bool = False

    # Seconds to wait for the initial `connect + initialize` handshake.
    connect_timeout: float = DEFAULT_CONNECT_TIMEOUT

    def validate(self) -> None:
        if self.transport is Transport.STDIO and not self.command:
            raise ValueError(
                "stdio transport requires --command (the executable to spawn)"
            )
        if self.transport is Transport.HTTP and not self.url:
            raise ValueError(
                "http transport requires --url (the streamable-HTTP endpoint)"
            )
        if self.transport is Transport.STDIO and self.url:
            raise ValueError(
                "stdio transport ignores --url; drop it or use --transport http"
            )
        if self.transport is Transport.HTTP and (self.command or self.args):
            raise ValueError(
                "http transport ignores --command/--arg; drop them or use "
                "--transport stdio"
            )


class MCPClient:
    """Thin async wrapper around an MCP SDK client session."""

    def __init__(self, config: TargetConfig) -> None:
        config.validate()
        self.config = config
        self._session: Any | None = None

    @asynccontextmanager
    async def connect(self) -> AsyncIterator["MCPClient"]:
        """Open a session to the target and yield a connected client.

        Opens the configured transport (spawn a subprocess for stdio, or a
        streamable-HTTP connection for http), performs the MCP `initialize`
        handshake, and keeps the session open for the duration of the `async
        with` block. On exit the session and the transport are torn down (and
        for stdio the subprocess is reaped).

        The connect+initialize step is bounded by `config.connect_timeout`.
        Once inside the `async with`, per-call operations are not timed here —
        a legitimately slow tool is not the connection's fault.
        """
        import asyncio

        from mcp import ClientSession

        async with AsyncExitStack() as stack:
            try:
                read, write = await asyncio.wait_for(
                    self._open_transport(stack),
                    timeout=self.config.connect_timeout,
                )
                session = await stack.enter_async_context(
                    ClientSession(read, write))
                await asyncio.wait_for(
                    session.initialize(),
                    timeout=self.config.connect_timeout,
                )
            except asyncio.TimeoutError as exc:
                raise TimeoutError(
                    f"target did not complete the MCP initialize handshake "
                    f"within {self.config.connect_timeout:.0f}s"
                ) from exc
            self._session = session
            try:
                yield self
            finally:
                self._session = None

    async def _open_transport(self, stack: AsyncExitStack) -> tuple[Any, Any]:
        """Enter the configured transport and return its (read, write) streams.

        This is the only place transport differs — the session handshake and
        every call above it are identical regardless of how the streams were
        obtained.
        """
        if self.config.transport is Transport.STDIO:
            from mcp.client.stdio import StdioServerParameters, stdio_client

            server_params = StdioServerParameters(
                command=self.config.command,  # validated non-None for stdio
                args=self.config.args,
                env=self.config.env or None,
            )
            # Suppress the target subprocess's stderr unless the user asked
            # for --verbose. A chatty server otherwise obscures the scanner's
            # own output. `errlog` expects a text-mode file object.
            if self.config.verbose:
                errlog = sys.stderr
            else:
                errlog = stack.enter_context(
                    open(os.devnull, "w", encoding="utf-8"))
            read, write = await stack.enter_async_context(
                stdio_client(server_params, errlog=errlog)
            )
            return read, write

        if self.config.transport is Transport.HTTP:
            from mcp.client.streamable_http import streamablehttp_client

            # streamablehttp_client yields a third value (a callback returning
            # the negotiated session id) that stdio does not; we only need the
            # read/write streams to drive a ClientSession.
            read, write, _get_session_id = await stack.enter_async_context(
                streamablehttp_client(
                    url=self.config.url,  # validated non-None for http
                    headers=self.config.headers or None,
                )
            )
            return read, write

        raise NotImplementedError(
            f"{self.config.transport.value!r} transport is not implemented"
        )

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
        """Invoke a tool on the target and return the SDK `CallToolResult`.

        The returned object carries `isError` (whether the server reported the
        call as failed), `content` (the content blocks the tool returned, e.g.
        `TextContent`), and `structuredContent`. A tool that raises server-side
        comes back with `isError=True` rather than raising here; transport-level
        failures still propagate as exceptions.
        """
        session = self._require_session()
        return await session.call_tool(name, arguments)
