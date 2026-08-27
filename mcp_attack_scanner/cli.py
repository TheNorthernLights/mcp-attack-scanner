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
from .attacks import (
    permission_escalation,
    prompt_injection_tool_output,
    tool_chain_exfil,
)
from .client import DEFAULT_CONNECT_TIMEOUT, MCPClient, TargetConfig, Transport
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
@click.option(
    "-v", "--verbose",
    is_flag=True,
    default=False,
    help="Show the target server's own stderr output. Off by default so a "
         "chatty server does not obscure the scanner's findings.",
)
@click.pass_context
def main(ctx: click.Context, verbose: bool) -> None:
    """Dynamic security testing for MCP (Model Context Protocol) servers.

    Executes attacks end-to-end against a live MCP server (tool-chaining
    exfiltration, permission escalation, prompt injection via tool output)
    rather than statically scanning tool descriptions. Findings are reported
    only when the attack actually succeeded against the running target.
    """
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose


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
        help="Transport used to reach the target MCP server.",
    )(f)
    f = click.option(
        "--command",
        default=None,
        metavar="EXECUTABLE",
        help="[stdio] Executable to spawn as the target MCP server.",
    )(f)
    f = click.option(
        arg_flag,
        "args",
        multiple=True,
        metavar="ARG",
        help=f"[stdio] Argument to pass to --command "
             f"(repeat {arg_flag} once per argument).",
    )(f)
    f = click.option(
        "--url",
        default=None,
        metavar="URL",
        help="[http] Streamable-HTTP endpoint of the target server "
             "(e.g. http://localhost:8081/mcp).",
    )(f)
    f = click.option(
        "--header",
        "headers",
        multiple=True,
        metavar="'NAME: VALUE'",
        help="[http] Custom HTTP header to send with every request, e.g. "
             "--header 'Authorization: Bearer <token>' (repeat once per "
             "header). Only valid with --transport http.",
    )(f)
    f = click.option(
        "--connect-timeout",
        type=click.FloatRange(min=0.1),
        default=DEFAULT_CONNECT_TIMEOUT,
        show_default=True,
        metavar="SECONDS",
        help="How long to wait for the target's MCP initialize handshake.",
    )(f)
    return f


def _target_options_server_arg(f):
    """Target options with the subprocess args on ``--server-arg``."""
    return _target_options(f, arg_flag="--server-arg")


def _parse_headers(raw: tuple[str, ...]) -> dict[str, str]:
    """Parse repeated ``Name: Value`` strings into an HTTP headers dict.

    Splits on the first colon so header values may themselves contain colons
    (Bearer tokens, URLs). Both the name and value are stripped of surrounding
    whitespace, matching how ``Name: Value`` is written on the wire.
    """
    headers: dict[str, str] = {}
    for item in raw:
        name, sep, value = item.partition(":")
        if not sep or not name.strip():
            raise click.ClickException(
                f"invalid header format {item!r}, expected 'Name: Value'."
            )
        headers[name.strip()] = value.strip()
    return headers


def _build_config(ctx: click.Context, transport: str, command: str | None,
                  args: tuple[str, ...], url: str | None,
                  connect_timeout: float,
                  headers: tuple[str, ...] = ()) -> TargetConfig:
    """Assemble a validated TargetConfig, converting validation failures into
    clean ClickExceptions so the user sees a readable message, not a
    traceback."""
    cfg = TargetConfig(
        transport=Transport(transport),
        command=command,
        args=list(args),
        url=url,
        headers=_parse_headers(headers),
        verbose=bool(ctx.obj.get("verbose") if ctx.obj else False),
        connect_timeout=connect_timeout,
    )
    try:
        cfg.validate()
    except ValueError as exc:
        raise click.ClickException(str(exc)) from None
    return cfg


# Python 3.11 added BaseExceptionGroup as a builtin; on 3.10 we fall back to
# an empty tuple so the isinstance() check simply never matches.
try:
    _EXC_GROUP: tuple[type[BaseException], ...] = (BaseExceptionGroup,)
except NameError:  # pragma: no cover — 3.10 fallback
    _EXC_GROUP = ()


def _unwrap(exc: BaseException) -> BaseException:
    """Peel single-element ExceptionGroups off an error.

    Anyio (used by the MCP SDK's transports) wraps errors in TaskGroups, so a
    plain "connection refused" comes back as "unhandled errors in a TaskGroup
    (1 sub-exception)". Unwrapping surfaces the underlying cause.
    """
    while _EXC_GROUP and isinstance(exc, _EXC_GROUP) and len(exc.exceptions) == 1:
        exc = exc.exceptions[0]
    return exc


def _friendly_connect_error(exc: BaseException, cfg: TargetConfig) -> str:
    """Turn a low-level connect/handshake failure into a one-line message
    that names the likely cause instead of the raw exception type."""
    exc = _unwrap(exc)
    if isinstance(exc, click.ClickException):
        return exc.format_message()
    if isinstance(exc, TimeoutError):
        return str(exc)
    if isinstance(exc, FileNotFoundError) and cfg.transport is Transport.STDIO:
        return (f"could not spawn --command {cfg.command!r}: executable not "
                f"found on PATH")
    if isinstance(exc, PermissionError) and cfg.transport is Transport.STDIO:
        return (f"could not spawn --command {cfg.command!r}: permission "
                f"denied")
    if isinstance(exc, ConnectionError) and cfg.transport is Transport.HTTP:
        return f"could not connect to --url {cfg.url!r}: {exc}"
    return f"{type(exc).__name__}: {exc}"


async def _preflight(cfg: TargetConfig) -> None:
    """Open and immediately close a connection to the target.

    Used before running the full scan so that a totally unreachable target
    produces one clean error message, not one 'attack module raised' entry per
    module.
    """
    client = MCPClient(cfg)
    async with client.connect():
        pass


# Attack modules run by `scan`, in order. Each exposes
# `run(TargetConfig) -> list[Finding]` and opens its own connection to the
# target, so a module that fails to connect does not take the others down.
ATTACK_MODULES = (tool_chain_exfil, permission_escalation,
                  prompt_injection_tool_output)


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


@main.command(name="list-tools")
@_target_options
@click.option(
    "--output",
    type=click.Choice(["human", "json"]),
    default="human",
    show_default=True,
    help="Report format: human table or full JSON schemas.",
)
@click.pass_context
def list_tools(ctx: click.Context, transport: str, command: str | None,
               args: tuple[str, ...], url: str | None,
               connect_timeout: float, headers: tuple[str, ...],
               output: str) -> None:
    """Connect to the target and enumerate the tools it exposes."""
    cfg = _build_config(ctx, transport, command, args, url, connect_timeout,
                        headers)
    try:
        tools = asyncio.run(_discover_tools(cfg))
    except Exception as exc:  # surface a clean CLI error, not a traceback
        raise click.ClickException(
            f"could not enumerate tools: {_friendly_connect_error(exc, cfg)}"
        ) from None

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
        available = {t.name for t in await client.list_tools()}
        if tool_name not in available:
            raise click.ClickException(
                f"target does not expose a tool named {tool_name!r}. "
                f"Available: {', '.join(sorted(available)) or '(none)'}"
            )
        return await client.call_tool(tool_name, arguments)


@main.command(name="call-tool")
@_target_options_server_arg
@click.option("--tool-name", required=True, metavar="NAME",
              help="Name of the tool to invoke on the target.")
@click.option(
    "--arg",
    "tool_args",
    multiple=True,
    metavar="KEY=VALUE",
    help="Argument to pass to the tool (repeat --arg once per argument).",
)
@click.pass_context
def call_tool(ctx: click.Context, transport: str, command: str | None,
              args: tuple[str, ...], url: str | None,
              connect_timeout: float, headers: tuple[str, ...],
              tool_name: str, tool_args: tuple[str, ...]) -> None:
    """Invoke a single tool on the target and print the raw result.

    Debug/verification helper — not part of `scan`. Because --arg carries the
    tool's own key=value arguments here, the stdio subprocess arguments move
    to --server-arg.
    """
    cfg = _build_config(ctx, transport, command, args, url, connect_timeout,
                        headers)
    arguments = _parse_tool_args(tool_args)
    try:
        result = asyncio.run(_call_tool(cfg, tool_name, arguments))
    except Exception as exc:  # surface a clean CLI error, not a traceback
        unwrapped = _unwrap(exc)
        if isinstance(unwrapped, click.ClickException):
            raise unwrapped from None
        raise click.ClickException(
            f"could not call tool {tool_name!r}: "
            f"{_friendly_connect_error(exc, cfg)}"
        ) from None

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
    help="Report format: human table or machine-readable JSON.",
)
@click.pass_context
def scan(ctx: click.Context, transport: str, command: str | None,
         args: tuple[str, ...], url: str | None, connect_timeout: float,
         headers: tuple[str, ...], output: str) -> None:
    """Run every implemented attack module against the target.

    Runs tool-chaining exfiltration, permission escalation, and prompt injection
    via tool output, and reports the findings from all three in one combined
    report.
    """
    cfg = _build_config(ctx, transport, command, args, url, connect_timeout,
                        headers)
    report = ScanReport(target=_target_label(cfg))
    try:
        asyncio.run(_preflight(cfg))
    except Exception as exc:  # target unreachable — one clean error, not N
        raise click.ClickException(
            f"could not connect to target: "
            f"{_friendly_connect_error(exc, cfg)}"
        ) from None
    try:
        findings = asyncio.run(_run_attacks(cfg))
    except Exception as exc:  # surface a clean CLI error, not a traceback
        raise click.ClickException(
            f"scan failed: {_friendly_connect_error(exc, cfg)}"
        ) from None

    for finding in findings:
        report.add(finding)
    report.finished_at = datetime.now(timezone.utc).isoformat()

    if output == "json":
        click.echo(render_json(report))
    else:
        click.echo(render_human(report))


if __name__ == "__main__":
    main()
