"""The examples are the README's evidence, so they are tested like it.

An example that silently stops demonstrating its claim is worse than none: the
README quotes their output as proof of what the software does.
"""

from __future__ import annotations

import runpy
import sys
from pathlib import Path

import pytest

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def run_example(name: str, capsys: pytest.CaptureFixture[str]) -> str:
    sys.path.insert(0, str(EXAMPLES.parent))
    try:
        with pytest.raises(SystemExit) as exit_info:
            runpy.run_path(str(EXAMPLES / name), run_name="__main__")
        assert exit_info.value.code == 0, f"{name} exited non-zero"
    finally:
        sys.path.remove(str(EXAMPLES.parent))
    return capsys.readouterr().out


# --- with_and_without.py: the README's headline claim ----------------------


def test_the_unguarded_run_really_is_unguarded(capsys: pytest.CaptureFixture[str]) -> None:
    out = run_example("with_and_without.py", capsys)
    assert "spent $320.00 in a single loop" in out


def test_the_guarded_run_is_stopped_by_the_budget(capsys: pytest.CaptureFixture[str]) -> None:
    out = run_example("with_and_without.py", capsys)
    assert "REFUSED" in out
    assert "spent $80.00, then stopped" in out


def test_the_headline_difference_is_what_the_readme_quotes(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The README states $240. If the numbers drift, the README becomes a lie."""
    out = run_example("with_and_without.py", capsys)
    assert "difference:      $240.00" in out


def test_the_guarded_run_leaves_a_verifiable_chain(
    capsys: pytest.CaptureFixture[str],
) -> None:
    out = run_example("with_and_without.py", capsys)
    assert "chain intact: 3 entries verified" in out


# --- stripe_agent.py: the reference integration ----------------------------


def test_stripe_example_parses_the_real_wire_format(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The adapter must read amounts out of Stripe's own form encoding."""
    monkeypatch.delenv("STRIPE_API_KEY", raising=False)
    out = run_example("stripe_agent.py", capsys)
    assert "read the Stripe body: 20 USD" in out
    assert "read the Stripe body: 800 USD" in out


def test_stripe_example_blocks_the_oversized_payment_before_the_network(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("STRIPE_API_KEY", raising=False)
    out = run_example("stripe_agent.py", capsys)
    assert "exceeds the per-transaction cap" in out
    assert "never called. the request did not leave this machine." in out


def test_stripe_example_refuses_a_live_key(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("STRIPE_API_KEY", raising=False)
    out = run_example("stripe_agent.py", capsys)
    assert "REFUSED before any policy check" in out
    assert "supports test mode only" in out


def test_stripe_example_never_calls_out_without_a_key(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """CI has no Stripe account; the example must not attempt a network call."""
    monkeypatch.delenv("STRIPE_API_KEY", raising=False)

    def forbidden(*args: object, **kwargs: object) -> object:
        raise AssertionError("the example must not reach the network without a key")

    monkeypatch.setattr("urllib.request.urlopen", forbidden)
    out = run_example("stripe_agent.py", capsys)
    assert "set STRIPE_API_KEY" in out


def test_stripe_example_refuses_to_run_against_a_live_key(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("STRIPE_API_KEY", "sk_live_definitely_real")
    sys.path.insert(0, str(EXAMPLES.parent))
    try:
        with pytest.raises(SystemExit) as exit_info:
            runpy.run_path(str(EXAMPLES / "stripe_agent.py"), run_name="__main__")
    finally:
        sys.path.remove(str(EXAMPLES.parent))
    assert exit_info.value.code == 1
    assert "must not sit in front of real money" in capsys.readouterr().out
