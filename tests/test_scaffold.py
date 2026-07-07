"""Smoke tests for the scaffold.

These verify the package imports and the CLI loads. Attack-specific tests are
added with each attack module.
"""

from click.testing import CliRunner

from mcp_attack_scanner import __version__
from mcp_attack_scanner.cli import main
from mcp_attack_scanner.client import TargetConfig, Transport
from mcp_attack_scanner.reporting import Outcome, ScanReport, Severity, render_json


def test_version_is_set():
    assert __version__


def test_cli_help_loads():
    result = CliRunner().invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "MCP" in result.output


def test_stdio_config_requires_command():
    cfg = TargetConfig(transport=Transport.STDIO)
    try:
        cfg.validate()
    except ValueError:
        return
    raise AssertionError("expected ValueError for stdio without command")


def test_http_config_requires_url():
    cfg = TargetConfig(transport=Transport.HTTP)
    try:
        cfg.validate()
    except ValueError:
        return
    raise AssertionError("expected ValueError for http without url")


def test_empty_report_serializes_to_json():
    report = ScanReport(target="stdio:example-server")
    payload = render_json(report)
    assert "example-server" in payload
    assert report.findings == []


def test_severity_and_outcome_enums_have_expected_members():
    assert Severity.CRITICAL.value == "critical"
    assert Outcome.VULNERABLE.value == "vulnerable"
