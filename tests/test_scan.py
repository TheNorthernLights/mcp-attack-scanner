"""Tests for the `scan` command wiring.

`scan` must run *every* attack module and merge their findings into one report,
so a target with three different flaws comes back with three findings.
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


def test_all_attack_modules_are_wired_in():
    assert {m.ATTACK_ID for m in ATTACK_MODULES} == {
        "tool_chain_exfil", "permission_escalation",
        "prompt_injection_tool_output"}


def test_scan_reports_all_findings_for_the_vulnerable_lab():
    report = _scan("vulnerable_mcp_lab")

    by_attack = {f["attack_id"]: f for f in report["findings"]}
    assert set(by_attack) == {"tool_chain_exfil", "permission_escalation",
                              "prompt_injection_tool_output"}
    assert [f["outcome"] for f in report["findings"]] == ["vulnerable"] * 3
    assert [f["severity"] for f in report["findings"]] == ["high"] * 3
    assert by_attack["tool_chain_exfil"]["category"] == "tool-chaining-exfiltration"
    assert by_attack["permission_escalation"]["category"] == "permission-escalation"
    assert (by_attack["prompt_injection_tool_output"]["category"]
            == "prompt-injection-tool-output")


def test_scan_reports_nothing_for_the_clean_lab():
    assert _scan("clean_mcp_lab")["findings"] == []
