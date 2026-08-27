"""Smoke tests for the package scaffold and CLI wiring."""

import pytest
from click.testing import CliRunner

from mcp_attack_scanner import __version__
from mcp_attack_scanner.cli import _parse_headers, main
from mcp_attack_scanner.client import TargetConfig, Transport
from mcp_attack_scanner.reporting import Outcome, ScanReport, Severity, render_json


def test_package_exposes_a_version():
    assert __version__


def test_cli_help_loads():
    result = CliRunner().invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "MCP" in result.output


def test_cli_version_flag_prints_the_package_version():
    result = CliRunner().invoke(main, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_stdio_config_rejects_missing_command():
    with pytest.raises(ValueError, match="stdio transport requires --command"):
        TargetConfig(transport=Transport.STDIO).validate()


def test_http_config_rejects_missing_url():
    with pytest.raises(ValueError, match="http transport requires --url"):
        TargetConfig(transport=Transport.HTTP).validate()


def test_stdio_config_rejects_stray_url():
    with pytest.raises(ValueError, match="stdio transport ignores --url"):
        TargetConfig(
            transport=Transport.STDIO, command="x", url="http://x").validate()


def test_http_config_rejects_stray_command():
    with pytest.raises(ValueError, match="http transport ignores --command"):
        TargetConfig(
            transport=Transport.HTTP, url="http://x", command="foo").validate()


def test_stdio_config_rejects_custom_headers():
    with pytest.raises(
        ValueError, match="custom headers are only supported with HTTP"
    ):
        TargetConfig(
            transport=Transport.STDIO, command="x",
            headers={"Authorization": "Bearer t"}).validate()


def test_http_config_accepts_custom_headers():
    # A well-formed header on HTTP must not trip validation.
    TargetConfig(
        transport=Transport.HTTP, url="http://x",
        headers={"Authorization": "Bearer t"}).validate()


def test_parse_headers_splits_on_first_colon():
    # Values may themselves contain colons (Bearer tokens, URLs); only the
    # first colon separates the name from the value.
    parsed = _parse_headers((
        "Authorization: Bearer eyJhbG:cd.ef",
        "X-API-Key:abc123",
    ))
    assert parsed == {
        "Authorization": "Bearer eyJhbG:cd.ef",
        "X-API-Key": "abc123",
    }


def test_cli_rejects_header_with_stdio_transport():
    result = CliRunner().invoke(main, [
        "list-tools", "--transport", "stdio", "--command", "true",
        "--header", "Authorization: Bearer t",
    ])
    assert result.exit_code != 0
    assert "custom headers are only supported with HTTP transport." \
        in result.output


def test_cli_rejects_malformed_header():
    result = CliRunner().invoke(main, [
        "scan", "--transport", "http", "--url", "http://localhost:8081/mcp",
        "--header", "no-colon-here",
    ])
    assert result.exit_code != 0
    assert "invalid header format 'no-colon-here', expected 'Name: Value'." \
        in result.output


def test_empty_report_serializes_to_json():
    report = ScanReport(target="stdio:example-server")
    payload = render_json(report)
    assert "example-server" in payload
    assert report.findings == []


def test_severity_and_outcome_enums_have_expected_members():
    assert Severity.CRITICAL.value == "critical"
    assert Outcome.VULNERABLE.value == "vulnerable"
