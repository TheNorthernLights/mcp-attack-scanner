"""Structured reporting of attack results.

Produces both machine-readable JSON and a human-readable table (via `rich`).
The data model here is the contract attack modules report against.

NOTE (scaffold only): the data model and renderers are in place; attack modules
that populate them arrive in later sessions. `rich` is imported lazily so the
CLI loads even if it is not installed.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Outcome(str, Enum):
    """Result of running a single attack against the target."""

    VULNERABLE = "vulnerable"
    NOT_VULNERABLE = "not_vulnerable"
    INCONCLUSIVE = "inconclusive"
    ERROR = "error"


@dataclass
class Finding:
    """One result from running one attack."""

    attack_id: str
    title: str
    outcome: Outcome
    severity: Severity = Severity.INFO
    description: str = ""
    # Free-form supporting data: the tool calls made, responses observed, etc.
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanReport:
    """The full result of a scan run against one target."""

    target: str
    findings: list[Finding] = field(default_factory=list)
    started_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    finished_at: str | None = None

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)


@dataclass
class ToolInfo:
    """A tool discovered on the target during enumeration."""

    name: str
    description: str = ""
    input_schema: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_sdk(cls, tool: Any) -> "ToolInfo":
        """Build from an `mcp.types.Tool` returned by the SDK."""
        return cls(
            name=tool.name,
            description=(tool.description or "").strip(),
            input_schema=tool.inputSchema or {},
        )


def render_json(report: ScanReport) -> str:
    """Machine-readable JSON output."""
    return report.to_json()


def render_tools_json(target: str, tools: list[ToolInfo]) -> str:
    """Machine-readable JSON listing of discovered tools."""
    payload = {
        "target": target,
        "tool_count": len(tools),
        "tools": [asdict(t) for t in tools],
    }
    return json.dumps(payload, indent=2, default=str)


def render_tools_human(target: str, tools: list[ToolInfo]) -> str:
    """Human-readable table of discovered tools rendered with `rich`."""
    import io

    from rich.console import Console
    from rich.table import Table

    # Render into a buffer (not real stdout) so the caller owns the output.
    console = Console(record=True, file=io.StringIO())

    if not tools:
        console.print(f"[bold]Target:[/bold] {target}")
        console.print("[dim]No tools exposed by the target.[/dim]")
        return console.export_text()

    table = Table(title=f"MCP Tools — {target}")
    table.add_column("Tool", style="cyan", no_wrap=True)
    table.add_column("Description")
    table.add_column("Parameters")

    for t in tools:
        params = sorted((t.input_schema.get("properties") or {}).keys())
        table.add_row(t.name, t.description or "[dim](none)[/dim]",
                      ", ".join(params) or "[dim](none)[/dim]")

    console.print(table)
    console.print(f"[dim]{len(tools)} tool(s) discovered.[/dim]")
    return console.export_text()


def render_human(report: ScanReport) -> str:
    """Human-readable summary rendered with `rich`.

    Returns the rendered string so the caller controls where it is written.
    """
    from rich.console import Console
    from rich.table import Table

    console = Console(record=True)

    if not report.findings:
        console.print(f"[bold]Target:[/bold] {report.target}")
        console.print("[dim]No findings (scaffold — no attacks implemented yet).[/dim]")
        return console.export_text()

    table = Table(title=f"MCP Attack Scan — {report.target}")
    table.add_column("Attack", style="cyan", no_wrap=True)
    table.add_column("Outcome")
    table.add_column("Severity")
    table.add_column("Title")

    for f in report.findings:
        table.add_row(f.attack_id, f.outcome.value, f.severity.value, f.title)

    console.print(table)
    return console.export_text()
