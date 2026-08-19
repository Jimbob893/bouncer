"""Regression tests for the enforcement core.

Every test here corresponds to a bug that existed and was fixed. They are the
fail-open cases — the ones where bouncer would have let spending through — so
they matter more than the happy paths.
"""

from __future__ import annotations

import threading
from datetime import datetime, timedelta
from decimal import Decimal
from pathlib import Path

import pytest

from bouncer.approvals import ApprovalQueue
from bouncer.audit import AuditLog
from bouncer.enforcement import Enforcer
from bouncer.keys import OperatorKey
from bouncer.mandate import NonceStore
from bouncer.models import Outcome, PaymentIntent
from bouncer.policy import Policy
from bouncer.sources import StaticSource

from .conftest import NOW, intent


class MovableClock:
    def __init__(self, now: datetime) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now


def build(tmp_path: Path, key: OperatorKey, policy: str) -> tuple[Enforcer, MovableClock]:
    clock = MovableClock(NOW)
    audit = AuditLog(tmp_path / "e.db", key)
    enforcer = Enforcer(
        source=StaticSource(Policy.from_yaml(policy)),
        audit=audit,
        key=key,
        nonces=NonceStore(tmp_path / "e.db", engine=audit.engine),
        approvals=ApprovalQueue(tmp_path / "e.db", engine=audit.engine),
        clock=clock,
    )
    return enforcer, clock


# ---------------------------------------------------------------------------
# a dry run must not hand out spending authority
# ---------------------------------------------------------------------------

SIMPLE = """
version: 1
currency: USD
agents:
  research-bot:
    per_transaction_cap: 100.00
"""


def test_dry_run_mints_no_mandate(tmp_path: Path, operator_key: OperatorKey) -> None:
    """A mandate that is never logged is unaccountable spending authority."""
    enforcer, _ = build(tmp_path, operator_key, SIMPLE)
    result = enforcer.authorize(intent(amount=Decimal("10.00")), record=False)

    assert result.decision.outcome is Outcome.ALLOW
    assert result.mandate is None, "dry run must not issue a usable mandate"
    assert result.audit_seq is None
    assert enforcer.audit.count() == 0


def test_dry_run_does_not_queue_an_approval(
    tmp_path: Path, operator_key: OperatorKey
) -> None:
    enforcer, _ = build(
        tmp_path,
        operator_key,
        """
        version: 1
        agents:
          research-bot:
            per_transaction_cap: 100.00
            approval_required_above:
              amount: 5.00
              approver_role: finance
        """,
    )
    result = enforcer.authorize(intent(amount=Decimal("50.00")), record=False)

    assert result.decision.outcome is Outcome.REQUIRE_APPROVAL
    assert result.pending_id is None
    assert enforcer.approvals.list() == []


def test_a_real_run_still_mints_a_mandate(
    tmp_path: Path, operator_key: OperatorKey
) -> None:
    enforcer, _ = build(tmp_path, operator_key, SIMPLE)
    result = enforcer.authorize(intent(amount=Decimal("10.00")))
    assert result.mandate is not None
    assert result.audit_seq == 1


# ---------------------------------------------------------------------------
# spend history must reach as far back as the policy's longest window
# ---------------------------------------------------------------------------

LONG_WINDOW = """
version: 1
currency: USD
agents:
  research-bot:
    per_transaction_cap: 5000.00
    rolling_windows:
      - amount: 10000.00
        window: 104w
"""


def test_spend_older_than_a_year_still_counts_against_a_two_year_window(
    tmp_path: Path, operator_key: OperatorKey
) -> None:
    """A fixed lookback horizon shorter than the window would fail open."""
    enforcer, clock = build(tmp_path, operator_key, LONG_WINDOW)

    # Spend 500 days ago — beyond any fixed 400-day horizon.
    clock.now = NOW - timedelta(days=500)
    seeded = enforcer.authorize(intent(intent_id="old", amount=Decimal("4500.00")))
    assert seeded.decision.outcome is Outcome.ALLOW

    clock.now = NOW - timedelta(days=400)
    second = enforcer.authorize(intent(intent_id="mid", amount=Decimal("4500.00")))
    assert second.decision.outcome is Outcome.ALLOW

    # Total is now 9000 inside a 104-week window; 2000 more must be refused.
    clock.now = NOW
    result = enforcer.authorize(intent(intent_id="new", amount=Decimal("2000.00")))

    assert result.decision.outcome is Outcome.DENY
    assert result.decision.reason_code.value == "OVER_ROLLING_WINDOW"


def test_spend_beyond_the_window_still_ages_out(
    tmp_path: Path, operator_key: OperatorKey
) -> None:
    """The fix must not make windows infinite in the other direction."""
    enforcer, clock = build(
        tmp_path,
        operator_key,
        """
        version: 1
        agents:
          research-bot:
            per_transaction_cap: 100.00
            rolling_windows:
              - amount: 100.00
                window: 7d
        """,
    )
    clock.now = NOW - timedelta(days=30)
    enforcer.authorize(intent(intent_id="ancient", amount=Decimal("100.00")))

    clock.now = NOW
    result = enforcer.authorize(intent(intent_id="fresh", amount=Decimal("100.00")))
    assert result.decision.outcome is Outcome.ALLOW


def test_policy_without_windows_needs_no_history(
    tmp_path: Path, operator_key: OperatorKey
) -> None:
    enforcer, _ = build(tmp_path, operator_key, SIMPLE)
    for index in range(3):
        result = enforcer.authorize(
            intent(intent_id=f"i{index}", amount=Decimal("100.00"))
        )
        assert result.decision.outcome is Outcome.ALLOW


# ---------------------------------------------------------------------------
# concurrent requests must not both consume the same budget
# ---------------------------------------------------------------------------

RACE_POLICY = """
version: 1
currency: USD
agents:
  research-bot:
    per_transaction_cap: 60.00
    rolling_windows:
      - amount: 100.00
        window: 30d
"""


def test_concurrent_requests_cannot_both_exceed_the_window(
    tmp_path: Path, operator_key: OperatorKey
) -> None:
    """Two $60 charges must not both pass a $100 ceiling.

    Without a lock around read-history/decide/record, both requests read
    "spent: 0" and both are allowed, overspending by 20%.
    """
    enforcer, _ = build(tmp_path, operator_key, RACE_POLICY)

    outcomes: list[Outcome] = []
    lock = threading.Lock()
    barrier = threading.Barrier(2)

    def attempt(index: int) -> None:
        barrier.wait()
        result = enforcer.authorize(
            intent(intent_id=f"race-{index}", amount=Decimal("60.00"))
        )
        with lock:
            outcomes.append(result.decision.outcome)

    threads = [threading.Thread(target=attempt, args=(i,)) for i in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert not any(thread.is_alive() for thread in threads)

    assert outcomes.count(Outcome.ALLOW) == 1
    assert outcomes.count(Outcome.DENY) == 1


def test_many_concurrent_requests_respect_the_ceiling(
    tmp_path: Path, operator_key: OperatorKey
) -> None:
    """Ten $20 requests against a $100 ceiling: exactly five may pass."""
    enforcer, _ = build(
        tmp_path,
        operator_key,
        """
        version: 1
        currency: USD
        agents:
          research-bot:
            per_transaction_cap: 20.00
            rolling_windows:
              - amount: 100.00
                window: 30d
        """,
    )

    outcomes: list[Outcome] = []
    lock = threading.Lock()
    barrier = threading.Barrier(10)

    def attempt(index: int) -> None:
        barrier.wait()
        result = enforcer.authorize(
            intent(intent_id=f"c-{index}", amount=Decimal("20.00"))
        )
        with lock:
            outcomes.append(result.decision.outcome)

    threads = [threading.Thread(target=attempt, args=(i,)) for i in range(10)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)

    assert outcomes.count(Outcome.ALLOW) == 5
    assert outcomes.count(Outcome.DENY) == 5
    assert enforcer.audit.verify().ok


def test_the_audit_chain_survives_concurrent_writers(
    tmp_path: Path, operator_key: OperatorKey
) -> None:
    """Parallel appends must not fork the hash chain."""
    enforcer, _ = build(tmp_path, operator_key, SIMPLE)

    barrier = threading.Barrier(8)

    def attempt(index: int) -> None:
        barrier.wait()
        enforcer.authorize(intent(intent_id=f"p-{index}", amount=Decimal("1.00")))

    threads = [threading.Thread(target=attempt, args=(i,)) for i in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)

    result = enforcer.audit.verify()
    assert result.ok, result.problem
    assert result.entries_checked == 8


def test_approval_is_serialized_against_evaluation(
    tmp_path: Path, operator_key: OperatorKey
) -> None:
    """Granting an approval commits spend, so it takes the same lock."""
    enforcer, _ = build(
        tmp_path,
        operator_key,
        """
        version: 1
        currency: USD
        agents:
          research-bot:
            per_transaction_cap: 80.00
            rolling_windows:
              - amount: 100.00
                window: 30d
            approval_required_above:
              amount: 50.00
              approver_role: finance
        """,
    )
    queued = enforcer.authorize(intent(intent_id="big", amount=Decimal("80.00")))
    assert queued.pending_id is not None

    approved = enforcer.resolve(queued.pending_id, role="finance", approve=True)
    assert approved.decision.outcome is Outcome.ALLOW

    # 80 committed; a further 30 would breach the 100 ceiling.
    after = enforcer.authorize(intent(intent_id="after", amount=Decimal("30.00")))
    assert after.decision.outcome is Outcome.DENY
    assert after.decision.reason_code.value == "OVER_ROLLING_WINDOW"


def test_timed_out_approvals_do_not_consume_budget(
    tmp_path: Path, operator_key: OperatorKey
) -> None:
    enforcer, _ = build(
        tmp_path,
        operator_key,
        """
        version: 1
        currency: USD
        agents:
          research-bot:
            per_transaction_cap: 80.00
            rolling_windows:
              - amount: 100.00
                window: 30d
            approval_required_above:
              amount: 50.00
              approver_role: finance
        """,
    )
    queued = enforcer.authorize(intent(intent_id="big", amount=Decimal("80.00")))
    assert queued.pending_id is not None
    enforcer.resolve(queued.pending_id, role="finance", approve=False)

    # The refused 80 must not have eaten the budget.
    result = enforcer.authorize(intent(intent_id="next", amount=Decimal("80.00")))
    assert result.decision.outcome is Outcome.REQUIRE_APPROVAL


def test_unparseable_and_tunnel_denials_never_count_as_spend(
    tmp_path: Path, operator_key: OperatorKey
) -> None:
    from bouncer.errors import UnparseableIntent

    enforcer, _ = build(tmp_path, operator_key, RACE_POLICY)
    placeholder = PaymentIntent(
        agent_id="research-bot", merchant="unknown", amount=Decimal(0), currency="XXX"
    )
    enforcer.deny_unparseable(UnparseableIntent("nope"), placeholder)
    enforcer.authorize_tunnel("api.example.com", "research-bot")

    history = enforcer.audit.spend_history(
        "research-bot", since=NOW - timedelta(days=30)
    )
    assert history == []


# ---------------------------------------------------------------------------
# a token-denominated policy must mint, not crash
# ---------------------------------------------------------------------------

TOKEN_POLICY = """
version: 1
currency: USDC
agents:
  research-bot:
    per_transaction_cap: 100.00
"""


def test_token_currency_mints_a_usable_mandate(
    tmp_path: Path, operator_key: OperatorKey
) -> None:
    """MandateClaims.currency was capped at 3 characters.

    PaymentIntent and Policy both accept token symbols up to 12, so a USDC
    policy evaluated to ALLOW and then raised an uncaught ValidationError out
    of issue_mandate -- a traceback from the CLI and a 500 from the API.
    """
    from bouncer.mandate import verify_mandate

    enforcer, clock = build(tmp_path, operator_key, TOKEN_POLICY)
    result = enforcer.authorize(
        PaymentIntent(
            agent_id="research-bot",
            merchant="api.example.com",
            amount=Decimal("5.00"),
            currency="USDC",
        )
    )

    assert result.decision.outcome is Outcome.ALLOW
    assert result.mandate is not None

    claims = verify_mandate(
        result.mandate,
        operator_key,
        now=clock.now,
        expected_merchant="api.example.com",
        amount=Decimal("5.00"),
    )
    assert claims.currency == "USDC"


# ---------------------------------------------------------------------------
# every decision reaches the audit log, including the failing branches
# ---------------------------------------------------------------------------


def test_a_decision_is_logged_even_when_minting_fails(
    tmp_path: Path, operator_key: OperatorKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Minting used to run before the audit append.

    Anything that raised between deciding and recording produced spending
    authority -- or a refusal -- that left no trace at all, which is the one
    outcome the enforcement core promises cannot happen.
    """
    enforcer, _ = build(tmp_path, operator_key, SIMPLE)
    before = enforcer.audit.count()

    def explode(*args: object, **kwargs: object) -> tuple[str, object]:
        raise RuntimeError("mint failed")

    monkeypatch.setattr("bouncer.enforcement.issue_mandate", explode)

    with pytest.raises(RuntimeError):
        enforcer.authorize(intent(amount=Decimal("10.00")))

    assert enforcer.audit.count() == before + 1, "the decision must still be logged"
    assert enforcer.audit.verify().ok, "the chain must stay intact"
