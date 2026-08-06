"""Tests for the `scan` command wiring.

`scan` must run *every* attack module and merge their findings into one report,
so a target with two different flaws comes back with two findings.
"""

from __future__ import annotations

import json

from click.testing import CliRunner

from mcp_attack_scanner.cli import ATTACK_MODULES, main

from .conftest import lab_config


def _scan(package: str) -> dict:
    cfg = lab_config(package)
    result = CliRunner().invoke(main, [
        "scan", "--transport", "stdio", "--command", cfg.command,
        *sum((["--arg", a] for a in cfg.args), []),
        "--output", "json",
    ])
    assert result.exit_code == 0, result.output
    return json.loads(result.output)


def test_every_module_exposes_the_shared_surface():
    for module in ATTACK_MODULES:
        assert module.ATTACK_ID
        assert module.CATEGORY
        assert callable(module.run)


def test_both_attack_modules_are_wired_in():
    assert {m.ATTACK_ID for m in ATTACK_MODULES} == {
        "tool_chain_exfil", "permission_escalation"}


def test_scan_reports_both_findings_for_the_vulnerable_lab():
    report = _scan("vulnerable_mcp_lab")

    by_attack = {f["attack_id"]: f for f in report["findings"]}
    assert set(by_attack) == {"tool_chain_exfil", "permission_escalation"}
    assert [f["outcome"] for f in report["findings"]] == ["vulnerable"] * 2
    assert [f["severity"] for f in report["findings"]] == ["high"] * 2
    assert by_attack["tool_chain_exfil"]["category"] == "tool-chaining-exfiltration"
    assert by_attack["permission_escalation"]["category"] == "permission-escalation"


def test_scan_reports_nothing_for_the_clean_lab():
    assert _scan("clean_mcp_lab")["findings"] == []
