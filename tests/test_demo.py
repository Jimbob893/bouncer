"""The demo is a deliverable, so it is tested like one.

A demo that silently stops demonstrating anything is worse than no demo: the
scenarios are the README's evidence. These tests assert that each of the six
attempts still produces the outcome it claims to.
"""

from __future__ import annotations

import runpy
import sys
from pathlib import Path

import pytest

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


@pytest.fixture()
def demo_output(capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.syspath_prepend(str(EXAMPLES.parent))
    with pytest.raises(SystemExit) as exit_info:
        runpy.run_path(str(EXAMPLES / "demo.py"), run_name="__main__")
    assert exit_info.value.code == 0, "demo exited non-zero"
    return capsys.readouterr().out


def test_demo_runs_clean(demo_output: str) -> None:
    assert "BUG" not in demo_output


def test_demo_shows_an_allowed_purchase(demo_output: str) -> None:
    assert "ALLOW  WITHIN_POLICY" in demo_output


def test_demo_shows_the_per_transaction_cap(demo_output: str) -> None:
    assert "DENY  OVER_PER_TXN_CAP" in demo_output


def test_demo_shows_a_denylisted_merchant(demo_output: str) -> None:
    assert "DENY  MERCHANT_DENIED" in demo_output


def test_demo_shows_the_rolling_window(demo_output: str) -> None:
    assert "DENY  OVER_ROLLING_WINDOW" in demo_output


def test_demo_shows_role_based_approval(demo_output: str) -> None:
    assert "APPROVAL  APPROVAL_REQUIRED" in demo_output
    assert "requires role 'finance', but you asserted 'engineering'" in demo_output
    assert "approved" in demo_output


def test_demo_shows_a_replayed_mandate(demo_output: str) -> None:
    assert "REJECTED  MandateReplayed" in demo_output


def test_demo_shows_the_chain_verifying_then_breaking(demo_output: str) -> None:
    assert "chain intact: 9 entries verified" in demo_output
    assert "CHAIN BROKEN at entry seq=" in demo_output


def test_demo_leaves_no_state_behind(demo_output: str) -> None:
    """It must run from a clean checkout without touching ~/.bouncer."""
    assert not (Path.home() / ".bouncer").exists()


def test_sample_policy_is_valid() -> None:
    from bouncer.policy import Policy

    policy = Policy.from_yaml((EXAMPLES / "policy.yaml").read_text())
    assert set(policy.agents) == {"research-bot", "procurement-bot"}
    assert policy.agents["research-bot"].approval_required_above is not None
