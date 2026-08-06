"""Command-line entrypoint for mcp-attack-scanner.

`list-tools` and `call-tool` are discovery/debug helpers; `scan` runs every
implemented attack module against the target and renders one combined report.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any

import click

from . import __version__
from .attacks import permission_escalation, tool_chain_exfil
from .client import MCPClient, TargetConfig, Transport
from .reporting import (
    Finding,
    Outcome,
    ScanReport,
    ToolInfo,
    render_human,
    render_json,
    render_tools_human,
    render_tools_json,
)


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="mcp-attack-scanner")
def main() -> None:
    """Dynamic security testing for MCP (Model Context Protocol) servers.

    Executes attacks end-to-end against a live MCP server (tool-chaining abuse,
    permission escalation, prompt-injection-via-tool-output) rather than
    statically scanning tool descriptions.
    """


def _target_options(f, *, arg_flag: str = "--arg"):
    """Shared options describing how to reach the target MCP server.

    `arg_flag` names the repeatable option carrying the stdio subprocess
    arguments; it defaults to ``--arg`` but is overridable so a command that
    needs ``--arg`` for its own purpose (e.g. ``call-tool``) can move the
    subprocess args onto ``--server-arg``.
    """
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
        arg_flag,
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


def _target_options_server_arg(f):
    """Target options with the subprocess args on ``--server-arg``."""
    return _target_options(f, arg_flag="--server-arg")


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


# Attack modules run by `scan`, in order. Each exposes
# `run(TargetConfig) -> list[Finding]` and opens its own connection to the
# target, so a module that fails to connect does not take the others down.
ATTACK_MODULES = (tool_chain_exfil, permission_escalation)


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


def _parse_tool_args(pairs: tuple[str, ...]) -> dict[str, str]:
    """Parse repeated ``key=value`` strings into an arguments dict.

    Values are kept as strings; JSON typing of arguments is out of scope for
    this debug command.
    """
    arguments: dict[str, str] = {}
    for pair in pairs:
        key, sep, value = pair.partition("=")
        if not sep or not key:
            raise click.BadParameter(
                f"expected key=value, got {pair!r}", param_hint="--arg"
            )
        arguments[key] = value
    return arguments


async def _call_tool(cfg: TargetConfig, tool_name: str,
                     arguments: dict[str, Any]) -> Any:
    client = MCPClient(cfg)
    async with client.connect():
        return await client.call_tool(tool_name, arguments)


@main.command(name="call-tool")
@_target_options_server_arg
@click.option("--tool-name", required=True, help="Name of the tool to invoke.")
@click.option(
    "--arg",
    "tool_args",
    multiple=True,
    metavar="KEY=VALUE",
    help="Argument passed to the tool as key=value (repeatable).",
)
def call_tool(transport: str, command: str | None, args: tuple[str, ...],
              url: str | None, tool_name: str, tool_args: tuple[str, ...]) -> None:
    """Invoke a single tool on the target and print the raw result.

    Debug/verification helper — not part of `scan`. Use --server-arg for the
    stdio subprocess arguments and --arg key=value for the tool's arguments.
    """
    cfg = _build_config(transport, command, args, url)
    arguments = _parse_tool_args(tool_args)
    try:
        result = asyncio.run(_call_tool(cfg, tool_name, arguments))
    except Exception as exc:  # surface a clean CLI error, not a traceback
        raise click.ClickException(f"failed to call tool {tool_name!r}: {exc}")

    is_error = getattr(result, "isError", None)
    click.echo(f"tool:     {tool_name}")
    click.echo(f"arguments: {arguments}")
    click.echo(f"isError:  {is_error}")
    click.echo("result:")
    # `result` is a pydantic CallToolResult; dump it verbatim as JSON.
    if hasattr(result, "model_dump_json"):
        click.echo(result.model_dump_json(indent=2))
    else:
        click.echo(repr(result))


async def _run_attacks(cfg: TargetConfig) -> list[Finding]:
    """Run every attack module in turn and collect their findings.

    Modules run sequentially — each spawns its own copy of a stdio target, and
    running them concurrently would mean several live subprocesses racing on the
    same target state. A module that blows up is recorded as an ERROR finding
    rather than discarding what the other modules already confirmed.
    """
    findings: list[Finding] = []
    for module in ATTACK_MODULES:
        try:
            findings.extend(await module.run(cfg))
        except Exception as exc:
            findings.append(Finding(
                attack_id=module.ATTACK_ID,
                category=module.CATEGORY,
                title=f"{module.ATTACK_ID} could not be completed",
                outcome=Outcome.ERROR,
                description=f"The module raised before reaching a verdict: {exc}",
                evidence={"error": f"{type(exc).__name__}: {exc}"},
            ))
    return findings


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
    """Run every implemented attack module against the target.

    Runs tool-chaining exfiltration and permission escalation, and reports the
    findings from both. More attack categories are added in later sessions.
    """
    cfg = _build_config(transport, command, args, url)
    report = ScanReport(target=_target_label(cfg))
    try:
        findings = asyncio.run(_run_attacks(cfg))
    except Exception as exc:  # surface a clean CLI error, not a traceback
        raise click.ClickException(f"scan failed: {exc}")

    for finding in findings:
        report.add(finding)
    report.finished_at = datetime.now(timezone.utc).isoformat()

    if output == "json":
        click.echo(render_json(report))
    else:
        click.echo(render_human(report))


if __name__ == "__main__":
    main()
