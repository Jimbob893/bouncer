"""The client library.

The property under test throughout is that a denial cannot be ignored: the
guarded block must not run unless bouncer allowed the payment *and* minted a
mandate to prove it.
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from decimal import Decimal
from pathlib import Path

import pytest

from bouncer.approvals import ApprovalQueue
from bouncer.audit import AuditLog
from bouncer.client import (
    ApprovalRequired,
    Authorized,
    Client,
    InvalidSpend,
    SpendDenied,
    SpendRefused,
)
from bouncer.enforcement import Enforcer
from bouncer.keys import OperatorKey
from bouncer.mandate import NonceStore
from bouncer.models import Outcome
from bouncer.policy import Policy
from bouncer.sources import StaticSource

from .conftest import NOW

POLICY = """
version: 1
currency: USD
agents:
  research-bot:
    per_transaction_cap: 50.00
    merchants:
      deny: ["*.casino.example"]
    approval_required_above:
      amount: 20.00
      approver_role: finance
"""


class MovableClock:
    def __init__(self, now: datetime) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now


def build(tmp_path: Path, key: OperatorKey, policy: str = POLICY) -> Enforcer:
    audit = AuditLog(tmp_path / "c.db", key)
    return Enforcer(
        source=StaticSource(Policy.from_yaml(policy)),
        audit=audit,
        key=key,
        nonces=NonceStore(tmp_path / "c.db", engine=audit.engine),
        approvals=ApprovalQueue(tmp_path / "c.db", engine=audit.engine),
        clock=MovableClock(NOW),
        approval_timeout=0.5,
    )


@pytest.fixture()
def client(tmp_path: Path, operator_key: OperatorKey) -> Client:
    return Client(build(tmp_path, operator_key), agent_id="research-bot")


# ---------------------------------------------------------------------------
# the allow path
# ---------------------------------------------------------------------------


def test_allowed_spend_runs_the_block_and_yields_a_mandate(client: Client) -> None:
    ran = False
    with client.spend(merchant="api.example.com", amount="12.00") as ok:
        ran = True
        assert isinstance(ok, Authorized)
        assert ok.mandate
        assert ok.decision.outcome is Outcome.ALLOW
        assert ok.amount == Decimal("12.00")
        assert ok.merchant == "api.example.com"
    assert ran, "an allowed spend must run the guarded block"


def test_allowed_spend_is_recorded_in_the_audit_log(client: Client) -> None:
    before = client.enforcer.audit.count()
    with client.spend(merchant="api.example.com", amount="5.00"):
        pass
    assert client.enforcer.audit.count() == before + 1


def test_amount_accepts_decimal_int_and_str_identically(client: Client) -> None:
    seen = []
    for amount in (Decimal("7"), 7, "7"):
        with client.spend(merchant="api.example.com", amount=amount) as ok:
            seen.append(ok.amount)
    assert seen == [Decimal(7), Decimal(7), Decimal(7)]


# ---------------------------------------------------------------------------
# the deny path — the block must never run
# ---------------------------------------------------------------------------


def test_denied_spend_raises_and_never_runs_the_block(client: Client) -> None:
    ran = False
    with pytest.raises(SpendDenied) as caught:
        with client.spend(merchant="api.example.com", amount="75.00"):
            ran = True  # pragma: no cover - the point is that this cannot run
    assert not ran, "a denied spend must not run the guarded block"
    assert caught.value.decision.outcome is Outcome.DENY
    assert "exceeds the per-transaction cap" in str(caught.value)


def test_denied_merchant_raises(client: Client) -> None:
    with pytest.raises(SpendDenied) as caught:
        with client.spend(merchant="lucky.casino.example", amount="1.00"):
            pass  # pragma: no cover
    assert caught.value.decision.rule is not None
    assert "denylist" in str(caught.value)


def test_unknown_agent_is_denied(tmp_path: Path, operator_key: OperatorKey) -> None:
    stranger = Client(build(tmp_path, operator_key), agent_id="not-in-policy")
    with pytest.raises(SpendDenied):
        with stranger.spend(merchant="api.example.com", amount="1.00"):
            pass  # pragma: no cover


def test_every_refusal_is_catchable_as_one_type(client: Client) -> None:
    """An embedder should be able to catch a single exception and fail closed."""
    with pytest.raises(SpendRefused):
        with client.spend(merchant="api.example.com", amount="75.00"):
            pass  # pragma: no cover


# ---------------------------------------------------------------------------
# approval
# ---------------------------------------------------------------------------


def test_approval_required_raises_when_not_waiting(client: Client) -> None:
    with pytest.raises(ApprovalRequired) as caught:
        with client.spend(merchant="api.example.com", amount="35.00"):
            pass  # pragma: no cover
    assert caught.value.pending_id
    assert caught.value.decision.approver_role == "finance"


def test_approval_required_still_queues_the_item(client: Client) -> None:
    try:
        with client.spend(merchant="api.example.com", amount="35.00"):
            pass  # pragma: no cover
    except ApprovalRequired as exc:
        pending_id = exc.pending_id
    assert pending_id is not None
    item = client.enforcer.approvals.get(pending_id)
    assert item.required_role == "finance"


def test_waiting_for_an_approval_that_never_comes_denies(client: Client) -> None:
    """The wait times out into a deny, never into an allow."""
    with pytest.raises(SpendDenied) as caught:
        with client.spend(merchant="api.example.com", amount="35.00", wait=True, timeout=0.5):
            pass  # pragma: no cover
    assert caught.value.decision.outcome is Outcome.DENY
    assert "timeout" in str(caught.value).lower()


# ---------------------------------------------------------------------------
# malformed requests are refused, not evaluated
# ---------------------------------------------------------------------------


def test_malformed_request_raises_invalid_spend(client: Client) -> None:
    with pytest.raises(InvalidSpend):
        with client.spend(merchant="", amount="1.00"):
            pass  # pragma: no cover


def test_negative_amount_is_refused(client: Client) -> None:
    with pytest.raises(SpendRefused):
        with client.spend(merchant="api.example.com", amount="-5.00"):
            pass  # pragma: no cover


def test_unparseable_amount_is_refused(client: Client) -> None:
    with pytest.raises(InvalidSpend, match="not a valid decimal"):
        with client.spend(merchant="api.example.com", amount="1.2.3"):
            pass  # pragma: no cover


# ---------------------------------------------------------------------------
# the block's own exceptions are never swallowed
# ---------------------------------------------------------------------------


def test_an_exception_inside_the_block_propagates(client: Client) -> None:
    class PaymentRailDown(RuntimeError):
        pass

    with pytest.raises(PaymentRailDown):
        with client.spend(merchant="api.example.com", amount="5.00"):
            raise PaymentRailDown("upstream refused")


def test_authorized_spend_counts_even_if_the_payment_fails(client: Client) -> None:
    """Spend is committed at authorization, not at settlement.

    Deliberately conservative: under-counting would let a retry loop outspend
    its ceiling.
    """
    before = client.enforcer.audit.count()
    with pytest.raises(RuntimeError):
        with client.spend(merchant="api.example.com", amount="5.00"):
            raise RuntimeError("payment never went through")
    assert client.enforcer.audit.count() == before + 1


# ---------------------------------------------------------------------------
# async form
# ---------------------------------------------------------------------------


def test_aspend_allows_and_yields_a_mandate(client: Client) -> None:
    async def go() -> str:
        async with client.aspend(merchant="api.example.com", amount="9.00") as ok:
            return ok.mandate

    assert asyncio.run(go())


def test_aspend_denies_without_running_the_block(client: Client) -> None:
    ran = False

    async def go() -> None:
        nonlocal ran
        async with client.aspend(merchant="api.example.com", amount="75.00"):
            ran = True  # pragma: no cover

    with pytest.raises(SpendDenied):
        asyncio.run(go())
    assert not ran


def test_sync_wait_inside_a_running_loop_is_refused(client: Client) -> None:
    """Blocking the caller's event loop would be worse than refusing."""

    async def go() -> None:
        with client.spend(merchant="api.example.com", amount="35.00", wait=True):
            pass  # pragma: no cover

    with pytest.raises(InvalidSpend, match="event loop"):
        asyncio.run(go())


# ---------------------------------------------------------------------------
# Client.from_policy -- the one-call entry point for embedders
# ---------------------------------------------------------------------------


def test_from_policy_yaml_string_builds_a_working_client(tmp_path: Path) -> None:
    client = Client.from_policy(POLICY, agent_id="research-bot", state_dir=tmp_path)
    with client.spend(merchant="api.example.com", amount="12.00") as ok:
        assert ok.mandate
    assert client.enforcer.audit.count() == 1


def test_from_policy_creates_its_state_on_first_use(tmp_path: Path) -> None:
    target = tmp_path / "nested" / "state"
    client = Client.from_policy(POLICY, agent_id="research-bot", state_dir=target)
    with client.spend(merchant="api.example.com", amount="1.00"):
        pass
    assert (target / "operator.pem").exists()
    assert (target / "bouncer.db").exists()


def test_from_policy_reuses_an_existing_key(tmp_path: Path) -> None:
    """A second client must not re-key and orphan the existing audit chain."""
    first = Client.from_policy(POLICY, agent_id="research-bot", state_dir=tmp_path)
    second = Client.from_policy(POLICY, agent_id="research-bot", state_dir=tmp_path)
    assert first.enforcer.key.key_id == second.enforcer.key.key_id


def test_from_policy_accepts_a_path_and_picks_up_edits(tmp_path: Path) -> None:
    """A Path is watched, so an operator can tighten policy without a restart."""
    # No approval rule here: the point under test is the cap changing, and a
    # threshold above the cap is itself a policy validation error.
    loose = "version: 1\ncurrency: USD\nagents:\n  research-bot:\n    per_transaction_cap: 50.00\n"
    tight = loose.replace("50.00", "5.00")

    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(loose, encoding="utf-8")
    client = Client.from_policy(
        policy_file, agent_id="research-bot", state_dir=tmp_path / "state"
    )
    with client.spend(merchant="api.example.com", amount="30.00") as ok:
        assert ok.decision.outcome is Outcome.ALLOW

    policy_file.write_text(tight, encoding="utf-8")
    with pytest.raises(SpendDenied) as caught:
        with client.spend(merchant="api.example.com", amount="30.00"):
            pass  # pragma: no cover
    assert "per-transaction cap" in str(caught.value)


def test_from_policy_rejects_a_filename_passed_as_a_string(tmp_path: Path) -> None:
    """The likely mistake gets a useful message, not a YAML parse error."""
    with pytest.raises(InvalidSpend, match="looks like a filename"):
        Client.from_policy("policy.yaml", agent_id="research-bot", state_dir=tmp_path)


def test_from_policy_rejects_malformed_yaml(tmp_path: Path) -> None:
    with pytest.raises(InvalidSpend, match="not valid"):
        Client.from_policy(
            "version: 1\nagents: {}\n", agent_id="research-bot", state_dir=tmp_path
        )
