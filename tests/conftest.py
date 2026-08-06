"""Shared pytest fixtures.

Chiefly: how to reach the two `test-lab` servers, so attack modules can be
tested end-to-end against a real target instead of a mock. The labs live
outside the installed package, so they are launched by putting `test-lab/` on
the child interpreter's import path rather than by importing them here.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from mcp_attack_scanner.client import TargetConfig, Transport

TEST_LAB = Path(__file__).resolve().parent.parent / "test-lab"


def lab_config(package: str) -> TargetConfig:
    """A stdio target config that runs one of the lab servers."""
    bootstrap = (
        f"import sys; sys.path.insert(0, {str(TEST_LAB)!r}); "
        f"from {package}.server import main; main()"
    )
    return TargetConfig(
        transport=Transport.STDIO,
        command=sys.executable,
        args=["-c", bootstrap],
    )


@pytest.fixture(scope="session", autouse=True)
def _seeded_labs():
    """Populate both sandboxes once, so the read tools have files to return."""
    if not TEST_LAB.is_dir():
        return
    sys.path.insert(0, str(TEST_LAB))
    for package in ("vulnerable_mcp_lab", "clean_mcp_lab"):
        try:
            __import__(f"{package}.seed").seed.seed()
        except ImportError:
            pass


@pytest.fixture
def vulnerable_target() -> TargetConfig:
    return lab_config("vulnerable_mcp_lab")


@pytest.fixture
def clean_target() -> TargetConfig:
    return lab_config("clean_mcp_lab")
