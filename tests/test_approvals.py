"""M5 — human-in-the-loop approvals and RBAC-tagged queueing."""

from __future__ import annotations

import asyncio
import threading
from datetime import timedelta
from decimal import Decimal
from pathlib import Path

import pytest

from bouncer.approvals import ApprovalQueue, ApprovalStatus
from bouncer.audit import AuditLog
from bouncer.enforcement import Enforcer
from bouncer.errors import RoleMismatch, UnknownApproval
from bouncer.keys import OperatorKey
from bouncer.mandate import NonceStore, verify_mandate
from bouncer.models import Outcome, ReasonCode
from bouncer.policy import Policy
from bouncer.sources import StaticSource

from .conftest import NOW, intent

APPROVAL_POLICY = """
version: 1
currency: USD
agents:
  research-bot:
    per_transaction_cap: 500.00
    approval_required_above:
      amount: 50.00
      approver_role: finance
  procurement-bot:
    per_transaction_cap: 20000.00
    approval_required_above:
      amount: 1000.00
      approver_role: cfo
"""


@pytest.fixture()
def enforcer(tmp_path: Path, operator_key: OperatorKey) -> Enforcer:
    audit = AuditLog(tmp_path / "b.db", operator_key)
    return Enforcer(
        source=StaticSource(Policy.from_yaml(APPROVAL_POLICY)),
        audit=audit,
        key=operator_key,
        nonces=NonceStore(tmp_path / "b.db", engine=audit.engine),
        approvals=ApprovalQueue(tmp_path / "b.db", engine=audit.engine),
        approval_timeout=1.0,
        clock=lambda: NOW,
    )


# ---------------------------------------------------------------------------
# queueing
# ---------------------------------------------------------------------------


def test_over_threshold_lands_in_the_queue_tagged_with_the_role(
    enforcer: Enforcer,
) -> None:
    result = enforcer.authorize(intent(amount=Decimal("100.00")))
    assert result.decision.outcome is Outcome.REQUIRE_APPROVAL
    assert result.pending_id is not None
    assert result.mandate is None

    item = enforcer.approvals.get(result.pending_id)
    assert item.required_role == "finance"
    assert item.status is ApprovalStatus.PENDING


def test_pending_list_filters_by_role(enforcer: Enforcer) -> None:
    enforcer.authorize(intent(amount=Decimal("100.00")))
    enforcer.authorize(
        intent(agent_id="procurement-bot", amount=Decimal("5000.00"), intent_id="i2")
    )

    finance = enforcer.approvals.list(role="finance")
    cfo = enforcer.approvals.list(role="cfo")
    everything = enforcer.approvals.list()

    assert len(finance) == 1 and finance[0].agent_id == "research-bot"
    assert len(cfo) == 1 and cfo[0].agent_id == "procurement-bot"
    assert len(everything) == 2


def test_allowed_transactions_never_reach_the_queue(enforcer: Enforcer) -> None:
    result = enforcer.authorize(intent(amount=Decimal("10.00")))
    assert result.decision.outcome is Outcome.ALLOW
    assert enforcer.approvals.list() == []


def test_denied_transactions_never_reach_the_queue(enforcer: Enforcer) -> None:
    result = enforcer.authorize(intent(amount=Decimal("5000.00")))
    assert result.decision.outcome is Outcome.DENY
    assert enforcer.approvals.list() == []


# ---------------------------------------------------------------------------
# role checks
# ---------------------------------------------------------------------------


def test_correct_role_can_approve(enforcer: Enforcer) -> None:
    pending = enforcer.authorize(intent(amount=Decimal("100.00")))
    assert pending.pending_id is not None
    result = enforcer.resolve(pending.pending_id, role="finance", approve=True)

    assert result.decision.outcome is Outcome.ALLOW
    assert result.decision.reason_code is ReasonCode.APPROVAL_GRANTED
    assert result.mandate is not None


def test_wrong_role_cannot_approve(enforcer: Enforcer) -> None:
    pending = enforcer.authorize(intent(amount=Decimal("100.00")))
    assert pending.pending_id is not None
    with pytest.raises(RoleMismatch, match="requires role 'finance'"):
        enforcer.resolve(pending.pending_id, role="engineering", approve=True)


def test_wrong_role_cannot_deny_either(enforcer: Enforcer) -> None:
    """Approve and deny are symmetric: no asymmetric authority."""
    pending = enforcer.authorize(intent(amount=Decimal("100.00")))
    assert pending.pending_id is not None
    with pytest.raises(RoleMismatch):
        enforcer.resolve(pending.pending_id, role="engineering", approve=False)
    assert enforcer.approvals.get(pending.pending_id).status is ApprovalStatus.PENDING


def test_role_check_is_case_insensitive(enforcer: Enforcer) -> None:
    pending = enforcer.authorize(intent(amount=Decimal("100.00")))
    assert pending.pending_id is not None
    result = enforcer.resolve(pending.pending_id, role="FINANCE", approve=True)
    assert result.decision.outcome is Outcome.ALLOW


def test_cfo_cannot_resolve_a_finance_item(enforcer: Enforcer) -> None:
    pending = enforcer.authorize(intent(amount=Decimal("100.00")))
    assert pending.pending_id is not None
    with pytest.raises(RoleMismatch):
        enforcer.resolve(pending.pending_id, role="cfo", approve=True)


def test_unknown_id_is_reported(enforcer: Enforcer) -> None:
    with pytest.raises(UnknownApproval):
        enforcer.resolve("nosuchid", role="finance", approve=True)


# ---------------------------------------------------------------------------
# resolution
# ---------------------------------------------------------------------------


def test_denial_produces_no_mandate(enforcer: Enforcer) -> None:
    pending = enforcer.authorize(intent(amount=Decimal("100.00")))
    assert pending.pending_id is not None
    result = enforcer.resolve(pending.pending_id, role="finance", approve=False)

    assert result.decision.outcome is Outcome.DENY
    assert result.decision.reason_code is ReasonCode.APPROVAL_DENIED
    assert result.mandate is None


def test_an_item_cannot_be_resolved_twice(enforcer: Enforcer) -> None:
    pending = enforcer.authorize(intent(amount=Decimal("100.00")))
    assert pending.pending_id is not None
    enforcer.resolve(pending.pending_id, role="finance", approve=True)
    with pytest.raises(RoleMismatch, match="already"):
        enforcer.resolve(pending.pending_id, role="finance", approve=True)


def test_approval_mandate_is_scoped_to_the_original_intent(
    enforcer: Enforcer, operator_key: OperatorKey
) -> None:
    request = intent(amount=Decimal("100.00"), merchant="vendor.example.com")
    pending = enforcer.authorize(request)
    assert pending.pending_id is not None
    result = enforcer.resolve(pending.pending_id, role="finance", approve=True)

    assert result.mandate is not None
    claims = verify_mandate(
        result.mandate,
        operator_key,
        now=NOW,
        expected_merchant="vendor.example.com",
        amount=Decimal("100.00"),
    )
    assert claims.max_amount == Decimal("100.00")


def test_resolution_is_recorded_in_the_audit_log(enforcer: Enforcer) -> None:
    pending = enforcer.authorize(intent(amount=Decimal("100.00")))
    assert pending.pending_id is not None
    enforcer.resolve(pending.pending_id, role="finance", approve=True, note="ok by me")

    entries = enforcer.audit.entries()
    assert [entry.outcome for entry in entries] == ["REQUIRE_APPROVAL", "ALLOW"]
    assert entries[1].kind == "approval"
    assert "ok by me" in entries[1].payload
    assert enforcer.audit.verify().ok


def test_note_is_retained(enforcer: Enforcer) -> None:
    pending = enforcer.authorize(intent(amount=Decimal("100.00")))
    assert pending.pending_id is not None
    enforcer.resolve(pending.pending_id, role="finance", approve=False, note="too much")
    assert enforcer.approvals.get(pending.pending_id).note == "too much"


# ---------------------------------------------------------------------------
# blocking mode
# ---------------------------------------------------------------------------


def test_blocking_mode_times_out_into_a_deny(enforcer: Enforcer) -> None:
    """The headline property: a timeout must never become an allow."""

    async def scenario() -> None:
        result = await enforcer.authorize_blocking(
            intent(amount=Decimal("100.00")), timeout=0.5
        )
        assert result.decision.outcome is Outcome.DENY
        assert result.decision.reason_code is ReasonCode.APPROVAL_TIMEOUT
        assert result.mandate is None

    asyncio.run(scenario())


def test_timed_out_item_is_marked_and_cannot_be_approved_later(
    enforcer: Enforcer,
) -> None:
    async def scenario() -> str:
        result = await enforcer.authorize_blocking(
            intent(amount=Decimal("100.00")), timeout=0.5
        )
        assert result.pending_id is not None
        return result.pending_id

    item_id = asyncio.run(scenario())
    assert enforcer.approvals.get(item_id).status is ApprovalStatus.TIMED_OUT
    with pytest.raises(RoleMismatch, match="already"):
        enforcer.resolve(item_id, role="finance", approve=True)


def test_blocking_mode_returns_when_a_human_approves(enforcer: Enforcer) -> None:
    async def scenario() -> None:
        task = asyncio.create_task(
            enforcer.authorize_blocking(intent(amount=Decimal("100.00")), timeout=10)
        )
        # Let the request register before resolving it.
        await asyncio.sleep(0.1)
        items = enforcer.approvals.list(role="finance")
        assert len(items) == 1
        enforcer.resolve(items[0].id, role="finance", approve=True)

        result = await task
        assert result.decision.outcome is Outcome.ALLOW
        assert result.decision.reason_code is ReasonCode.APPROVAL_GRANTED
        assert result.mandate is not None

    asyncio.run(scenario())


def test_blocking_mode_returns_when_a_human_denies(enforcer: Enforcer) -> None:
    async def scenario() -> None:
        task = asyncio.create_task(
            enforcer.authorize_blocking(intent(amount=Decimal("100.00")), timeout=10)
        )
        await asyncio.sleep(0.1)
        items = enforcer.approvals.list(role="finance")
        enforcer.resolve(items[0].id, role="finance", approve=False)

        result = await task
        assert result.decision.outcome is Outcome.DENY
        assert result.decision.reason_code is ReasonCode.APPROVAL_DENIED

    asyncio.run(scenario())


def test_blocking_mode_returns_immediately_for_allowed_requests(
    enforcer: Enforcer,
) -> None:
    async def scenario() -> None:
        result = await enforcer.authorize_blocking(
            intent(amount=Decimal("10.00")), timeout=10
        )
        assert result.decision.outcome is Outcome.ALLOW

    asyncio.run(scenario())


# ---------------------------------------------------------------------------
# concurrency
# ---------------------------------------------------------------------------


def test_concurrent_resolution_produces_exactly_one_winner(
    enforcer: Enforcer,
) -> None:
    """Two operators racing to resolve the same item: one wins, one is refused."""
    pending = enforcer.authorize(intent(amount=Decimal("100.00")))
    assert pending.pending_id is not None

    outcomes: list[str] = []
    lock = threading.Lock()
    # Only the worker threads wait on the barrier; it trips when all four are
    # lined up, so they contend for the same item as simultaneously as possible.
    barrier = threading.Barrier(4)

    def attempt() -> None:
        barrier.wait()
        try:
            enforcer.resolve(pending.pending_id, role="finance", approve=True)  # type: ignore[arg-type]
            result = "won"
        except RoleMismatch:
            result = "refused"
        with lock:
            outcomes.append(result)

    threads = [threading.Thread(target=attempt) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert not any(thread.is_alive() for thread in threads)

    assert outcomes.count("won") == 1
    assert outcomes.count("refused") == 3


def test_enqueue_requires_a_role(enforcer: Enforcer) -> None:
    from bouncer.engine import evaluate

    policy = Policy.from_yaml(APPROVAL_POLICY)
    request = intent(amount=Decimal("10.00"))
    allowed = evaluate(request, policy, now=NOW)
    with pytest.raises(ValueError, match="approver_role"):
        enforcer.approvals.enqueue(request, allowed)
