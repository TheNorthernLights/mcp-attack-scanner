"""Command-line entrypoint for mcp-attack-scanner.

Scaffold only: the commands parse arguments, build a target configuration, and
wire up reporting, but no attacks are implemented yet. Running an attack raises
a clear "not implemented" message.
"""

from __future__ import annotations

import asyncio

import click

from . import __version__
from .client import MCPClient, TargetConfig, Transport
from .reporting import ToolInfo, render_tools_human, render_tools_json


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="mcp-attack-scanner")
def main() -> None:
    """Dynamic security testing for MCP (Model Context Protocol) servers.

    Executes attacks end-to-end against a live MCP server (tool-chaining abuse,
    permission escalation, prompt-injection-via-tool-output) rather than
    statically scanning tool descriptions.
    """


def _target_options(f):
    """Shared options describing how to reach the target MCP server."""
    f = click.option(
        "--transport",
        type=click.Choice([t.value for t in Transport]),
        default=Transport.STDIO.value,
        show_default=True,
        help="Transport used to reach the target server.",
    )(f)
    f = click.option(
        "--command",
        default=None,
        help="[stdio] Executable to spawn for the target MCP server.",
    )(f)
    f = click.option(
        "--arg",
        "args",
        multiple=True,
        help="[stdio] Argument passed to --command (repeatable).",
    )(f)
    f = click.option(
        "--url",
        default=None,
        help="[http] Streamable-HTTP endpoint of the target server.",
    )(f)
    return f


def _build_config(transport: str, command: str | None, args: tuple[str, ...],
                  url: str | None) -> TargetConfig:
    cfg = TargetConfig(
        transport=Transport(transport),
        command=command,
        args=list(args),
        url=url,
    )
    cfg.validate()
    return cfg


def _target_label(cfg: TargetConfig) -> str:
    """A short human label identifying the target, for report headers."""
    if cfg.transport is Transport.STDIO:
        return " ".join([cfg.command or "", *cfg.args]).strip()
    return cfg.url or ""


async def _discover_tools(cfg: TargetConfig) -> list[ToolInfo]:
    client = MCPClient(cfg)
    async with client.connect():
        tools = await client.list_tools()
    return [ToolInfo.from_sdk(t) for t in tools]


@main.command()
@_target_options
@click.option(
    "--output",
    type=click.Choice(["human", "json"]),
    default="human",
    show_default=True,
    help="Report format.",
)
def list_tools(transport: str, command: str | None, args: tuple[str, ...],
               url: str | None, output: str) -> None:
    """Connect to the target and enumerate its tools."""
    cfg = _build_config(transport, command, args, url)
    try:
        tools = asyncio.run(_discover_tools(cfg))
    except Exception as exc:  # surface a clean CLI error, not a traceback
        raise click.ClickException(f"failed to enumerate tools: {exc}")

    label = _target_label(cfg)
    if output == "json":
        click.echo(render_tools_json(label, tools))
    else:
        click.echo(render_tools_human(label, tools))


@main.command()
@_target_options
@click.option(
    "--output",
    type=click.Choice(["human", "json"]),
    default="human",
    show_default=True,
    help="Report format.",
)
def scan(transport: str, command: str | None, args: tuple[str, ...],
         url: str | None, output: str) -> None:
    """Run all attack modules against the target (not implemented yet)."""
    _build_config(transport, command, args, url)
    raise click.ClickException(
        "scan is not implemented yet — attacks arrive in later sessions "
        "(scaffold only)."
    )


if __name__ == "__main__":
    main()
