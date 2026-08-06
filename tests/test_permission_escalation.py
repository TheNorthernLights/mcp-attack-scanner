"""Tests for the permission-escalation attack module.

Two layers: unit tests for the candidate-selection and confirmation heuristics
(no server involved), and end-to-end tests that run the module against both lab
targets — it must fire on the vulnerable one and stay silent on the clean one.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest

from mcp_attack_scanner.attacks import permission_escalation as pe
from mcp_attack_scanner.reporting import Outcome, Severity


@dataclass
class FakeTool:
    """Stands in for an `mcp.types.Tool` in the unit tests."""

    name: str
    description: str = ""
    inputSchema: dict[str, Any] = field(default_factory=dict)  # noqa: N815


def tool(name: str, params: dict[str, str], description: str = "") -> FakeTool:
    return FakeTool(
        name=name,
        description=description,
        inputSchema={"properties": {p: {"type": t} for p, t in params.items()}},
    )


# --- candidate selection ---------------------------------------------------

@pytest.mark.parametrize("param", ["user_id", "userId", "account_id",
                                   "owner_id", "customerId", "tenant_id",
                                   "self_id", "uid"])
def test_identity_params_are_recognised(param):
    assert pe._identity_param(tool("get_record", {param: "string"})) == param


@pytest.mark.parametrize("param", ["path", "directory", "query", "message",
                                   "webhook_url", "limit"])
def test_non_identity_params_are_ignored(param):
    assert pe._identity_param(tool("read_file", {param: "string"})) is None


def test_most_specific_identity_param_wins():
    candidate = tool("get_record", {"user": "string", "account_id": "string"})
    assert pe._identity_param(candidate) == "account_id"


def test_non_scalar_identity_params_are_ignored():
    assert pe._identity_param(tool("bulk", {"user_id": "array"})) is None


@pytest.mark.parametrize("name", ["delete_user", "update_account",
                                  "reset_password", "transfer_funds",
                                  "send_invite"])
def test_mutating_tools_are_skipped(name):
    assert pe._is_mutating(tool(name, {"user_id": "string"}))


@pytest.mark.parametrize("name", ["get_user_record", "read_profile",
                                  "fetch_account", "show_orders"])
def test_read_shaped_tools_are_probed(name):
    assert not pe._is_mutating(tool(name, {"user_id": "string"}))


# --- probe generation ------------------------------------------------------

def test_adjacent_ids_increment_the_baseline():
    probes = pe._adjacent_ids("u1")
    assert probes[:2] == ["u2", "u3"]
    assert "u1" not in probes


def test_adjacent_ids_preserve_zero_padding():
    assert pe._adjacent_ids("user_007")[:2] == ["user_008", "user_009"]


def test_adjacent_ids_fall_back_to_generics_without_digits():
    assert pe._adjacent_ids("alice") == list(pe._GENERIC_PROBE_IDS)


# --- confirmation: only real boundary violations count ---------------------

RECORD_U1 = '{"user_id": "u1", "name": "Ada Nguyen", "plan": "enterprise"}'
RECORD_U2 = '{"user_id": "u2", "name": "Bruno Okafor", "plan": "starter"}'


def test_distinct_records_are_confirmed():
    assert pe._is_distinct_data(RECORD_U1, RECORD_U2, "u1", "u2")


def test_echoed_argument_is_not_confirmed():
    """A tool that just reflects the id back is not an authorization flaw."""
    assert not pe._is_distinct_data(
        "No record is currently associated with account u1.",
        "No record is currently associated with account u2.",
        "u1", "u2")


def test_identical_responses_are_not_confirmed():
    assert not pe._is_distinct_data(RECORD_U1, RECORD_U1, "u1", "u2")


def test_thin_responses_are_not_confirmed():
    assert not pe._is_distinct_data("u1", "u2", "u1", "u2")


@pytest.mark.parametrize("payload", [
    "Error executing tool: authorization denied for user 'u2'",
    "403 Forbidden: you do not have permission to view this record",
    "No such user record: 'u2'",
])
def test_refusals_are_recognised_even_without_iserror(payload):
    assert pe._looks_like_refusal(payload)


def test_a_real_record_is_not_mistaken_for_a_refusal():
    assert not pe._looks_like_refusal(RECORD_U2)


# --- end-to-end against the labs -------------------------------------------

async def test_vulnerable_lab_yields_one_confirmed_finding(vulnerable_target):
    findings = await pe.run(vulnerable_target)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.attack_id == "permission_escalation"
    assert finding.category == "permission-escalation"
    assert finding.outcome is Outcome.VULNERABLE
    assert finding.severity is Severity.HIGH
    assert finding.evidence["tool"] == "get_user_record"
    assert finding.evidence["identity_param"] == "user_id"
    # The evidence must show two different identities' data, not one call twice.
    assert "Ada Nguyen" in finding.evidence["baseline_result"]
    assert "Bruno Okafor" in finding.evidence["probe_result"]


async def test_clean_lab_yields_no_findings(clean_target):
    assert await pe.run(clean_target) == []


async def test_clean_lab_still_answers_for_its_own_identity(clean_target):
    """Guards against a vacuous pass: the clean lab must report 0 findings
    because it *refused* the cross-identity read, not because its baseline call
    failed and the module never got as far as probing."""
    from mcp_attack_scanner.client import MCPClient

    client = MCPClient(clean_target)
    async with client.connect():
        tools = {t.name: t for t in await client.list_tools()}
        own = await pe._call(client, tools["get_user_record"], "user_id", "u1")
        other = await pe._call(client, tools["get_user_record"], "user_id", "u2")

    assert own is not None and "Ada Nguyen" in own
    assert other is None
