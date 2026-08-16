"""M2 — the tamper-evident audit log."""

from __future__ import annotations

import io
import json
from datetime import timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import text

from bouncer.audit import GENESIS_HASH, AuditLog, export_jsonl, verify_exported
from bouncer.engine import evaluate
from bouncer.keys import OperatorKey
from bouncer.models import Outcome
from bouncer.policy import Policy

from .conftest import NOW, SIMPLE_POLICY, intent


@pytest.fixture()
def log(tmp_path: Path, operator_key: OperatorKey) -> AuditLog:
    return AuditLog(tmp_path / "audit.db", operator_key)


def fill(log: AuditLog, count: int, policy: Policy | None = None) -> None:
    """Write ``count`` real decisions into the log."""
    resolved = policy if policy is not None else Policy.from_yaml(SIMPLE_POLICY)
    for index in range(count):
        request = intent(
            intent_id=f"intent-{index}",
            amount=Decimal("10.00") + index,
            merchant=f"m{index % 7}.example.com",
        )
        decision = evaluate(request, resolved, now=NOW + timedelta(seconds=index))
        log.append(request, decision)


# ---------------------------------------------------------------------------
# chaining
# ---------------------------------------------------------------------------


def test_empty_log_verifies_with_genesis_head(log: AuditLog) -> None:
    result = log.verify()
    assert result.ok
    assert result.entries_checked == 0
    assert result.head_hash == GENESIS_HASH


def test_first_entry_chains_to_genesis(log: AuditLog) -> None:
    fill(log, 1)
    entry = log.entries()[0]
    assert entry.seq == 1
    assert entry.prev_hash == GENESIS_HASH


def test_each_entry_chains_to_its_predecessor(log: AuditLog) -> None:
    fill(log, 5)
    entries = log.entries()
    for previous, current in zip(entries, entries[1:]):
        assert current.prev_hash == previous.entry_hash
        assert current.seq == previous.seq + 1


def test_hundred_entries_verify_clean(log: AuditLog) -> None:
    fill(log, 100)
    result = log.verify()
    assert result.ok
    assert result.entries_checked == 100
    assert log.head() == result.head_hash


def test_entry_records_the_request_decision_and_policy_hash(log: AuditLog) -> None:
    policy = Policy.from_yaml(SIMPLE_POLICY)
    request = intent(amount=Decimal("42.50"))
    decision = evaluate(request, policy, now=NOW)
    entry = log.append(request, decision)

    payload = json.loads(entry.payload)
    assert payload["intent"]["amount"] == "42.5"
    assert payload["decision"]["outcome"] == "ALLOW"
    assert entry.policy_hash == policy.policy_hash
    assert entry.amount == "42.50"


# ---------------------------------------------------------------------------
# tamper detection — the headline requirement
# ---------------------------------------------------------------------------


def test_mutating_a_row_is_caught_and_the_row_is_named(log: AuditLog) -> None:
    """Write 100 entries, mutate one directly in SQLite, prove verify catches it."""
    fill(log, 100)
    assert log.verify().ok

    with log.engine.begin() as connection:
        connection.execute(
            text("UPDATE audit_entries SET payload = :payload WHERE seq = 42"),
            {"payload": '{"kind":"decision","tampered":true}'},
        )

    result = log.verify()
    assert not result.ok
    assert result.broken_seq == 42
    assert "altered" in (result.problem or "")
    assert result.entries_checked == 41
    assert "seq=42" in result.describe()


def test_changing_a_recorded_amount_is_caught(log: AuditLog) -> None:
    """The realistic attack: quietly restate what was authorized."""
    fill(log, 10)
    with log.engine.begin() as connection:
        connection.execute(
            text("UPDATE audit_entries SET amount = '999999.00' WHERE seq = 3")
        )
    result = log.verify()
    assert not result.ok
    assert result.broken_seq == 3


def test_flipping_a_deny_to_an_allow_is_caught(log: AuditLog) -> None:
    """Make a blocked payment look authorized after the fact."""
    policy = Policy.from_yaml(SIMPLE_POLICY)
    blocked = intent(intent_id="blocked", amount=Decimal("5000.00"))
    decision = evaluate(blocked, policy, now=NOW)
    assert decision.outcome is Outcome.DENY
    log.append(blocked, decision)
    fill(log, 3)

    with log.engine.begin() as connection:
        connection.execute(
            text("UPDATE audit_entries SET outcome = 'ALLOW' WHERE seq = 1")
        )

    result = log.verify()
    assert not result.ok
    assert result.broken_seq == 1
    assert "altered" in (result.problem or "")


def test_deleting_a_row_from_the_middle_is_caught(log: AuditLog) -> None:
    fill(log, 20)
    with log.engine.begin() as connection:
        connection.execute(text("DELETE FROM audit_entries WHERE seq = 11"))
    result = log.verify()
    assert not result.ok
    assert result.broken_seq == 12
    assert "removed" in (result.problem or "")


def test_forging_a_row_without_the_key_is_caught(log: AuditLog) -> None:
    """Recompute the hash correctly but sign with the wrong key."""
    fill(log, 5)
    entries = log.entries()
    victim = entries[2]
    attacker = OperatorKey.generate()
    import base64

    forged = base64.b64encode(attacker.sign(victim.entry_hash.encode())).decode()
    with log.engine.begin() as connection:
        connection.execute(
            text("UPDATE audit_entries SET signature = :sig WHERE seq = 3"),
            {"sig": forged},
        )
    result = log.verify()
    assert not result.ok
    assert result.broken_seq == 3
    assert "signature" in (result.problem or "")


def test_tail_truncation_needs_an_external_head_to_detect(log: AuditLog) -> None:
    """An honest limitation: a truncated chain is internally consistent."""
    fill(log, 50)
    recorded_head = log.head()

    with log.engine.begin() as connection:
        connection.execute(text("DELETE FROM audit_entries WHERE seq > 40"))

    # Nothing in the log itself reveals the loss...
    assert log.verify().ok
    # ...but a previously recorded head hash does.
    result = log.verify(expect_head=recorded_head)
    assert not result.ok
    assert "removed from the end" in (result.problem or "")


def test_verify_against_the_wrong_public_key_fails(log: AuditLog, tmp_path: Path) -> None:
    fill(log, 3)
    stranger = OperatorKey.generate(tmp_path / "other.pem")
    result = log.verify(verify_key=stranger.verify_key)
    assert not result.ok
    assert result.broken_seq == 1


# ---------------------------------------------------------------------------
# export
# ---------------------------------------------------------------------------


def test_export_writes_one_json_object_per_line(log: AuditLog) -> None:
    fill(log, 10)
    buffer = io.StringIO()
    written = export_jsonl(log, buffer)

    lines = buffer.getvalue().strip().split("\n")
    assert written == 10
    assert len(lines) == 10
    first: dict[str, Any] = json.loads(lines[0])
    assert first["seq"] == 1
    assert first["prev_hash"] == GENESIS_HASH
    assert set(first) >= {"seq", "ts", "outcome", "payload", "entry_hash", "signature"}


def test_export_to_a_path(log: AuditLog, tmp_path: Path) -> None:
    fill(log, 5)
    target = tmp_path / "out" / "audit.jsonl"
    assert export_jsonl(log, target) == 5
    assert len(target.read_text().strip().split("\n")) == 5


def test_exported_log_reverifies_from_the_file_alone(
    log: AuditLog, operator_key: OperatorKey
) -> None:
    """An auditor with the export and the public key can check it independently."""
    fill(log, 25)
    buffer = io.StringIO()
    export_jsonl(log, buffer)

    result = verify_exported(buffer.getvalue().splitlines(), operator_key.verify_key)
    assert result.ok
    assert result.entries_checked == 25
    assert result.head_hash == log.head()


def test_tampering_with_the_export_is_caught(
    log: AuditLog, operator_key: OperatorKey
) -> None:
    fill(log, 10)
    buffer = io.StringIO()
    export_jsonl(log, buffer)
    lines = buffer.getvalue().splitlines()

    row = json.loads(lines[4])
    row["payload"]["intent"]["amount"] = "999999.00"
    lines[4] = json.dumps(row, sort_keys=True)

    result = verify_exported(lines, operator_key.verify_key)
    assert not result.ok
    assert result.broken_seq == 5


# ---------------------------------------------------------------------------
# spend history
# ---------------------------------------------------------------------------


def test_spend_history_returns_only_allowed_spend(
    log: AuditLog, tmp_path: Path
) -> None:
    policy = Policy.from_yaml(SIMPLE_POLICY)
    allowed = intent(amount=Decimal("30.00"))
    denied = intent(intent_id="i2", amount=Decimal("5000.00"))

    log.append(allowed, evaluate(allowed, policy, now=NOW))
    log.append(denied, evaluate(denied, policy, now=NOW))

    history = log.spend_history("research-bot", since=NOW - timedelta(days=30))
    assert [record.amount for record in history] == [Decimal("30.00")]


def test_spend_history_is_scoped_to_one_agent(log: AuditLog) -> None:
    policy = Policy.from_yaml(
        "version: 1\nagents:\n  research-bot:\n    per_transaction_cap: 100\n"
        "  other-bot:\n    per_transaction_cap: 100\n"
    )
    for agent in ("research-bot", "other-bot"):
        request = intent(agent_id=agent, amount=Decimal("20.00"), intent_id=f"i-{agent}")
        log.append(request, evaluate(request, policy, now=NOW))

    history = log.spend_history("research-bot", since=NOW - timedelta(days=30))
    assert len(history) == 1
    assert history[0].agent_id == "research-bot"


def test_spend_history_respects_the_since_bound(log: AuditLog) -> None:
    policy = Policy.from_yaml(SIMPLE_POLICY)
    old = intent(intent_id="old", amount=Decimal("50.00"))
    log.append(old, evaluate(old, policy, now=NOW - timedelta(days=40)))
    recent = intent(intent_id="new", amount=Decimal("25.00"))
    log.append(recent, evaluate(recent, policy, now=NOW))

    history = log.spend_history("research-bot", since=NOW - timedelta(days=30))
    assert [record.amount for record in history] == [Decimal("25.00")]


def test_spend_history_round_trips_timestamps_exactly(log: AuditLog) -> None:
    policy = Policy.from_yaml(SIMPLE_POLICY)
    request = intent(amount=Decimal("10.00"))
    log.append(request, evaluate(request, policy, now=NOW))
    history = log.spend_history("research-bot", since=NOW - timedelta(days=1))
    assert history[0].timestamp == NOW


def test_history_feeds_back_into_the_engine(log: AuditLog) -> None:
    """End to end: logged spend actually closes a rolling window."""
    policy = Policy.from_yaml(
        """
        version: 1
        agents:
          research-bot:
            per_transaction_cap: 100.00
            rolling_windows:
              - amount: 150.00
                window: 30d
        """
    )
    for index in range(2):
        request = intent(intent_id=f"i{index}", amount=Decimal("75.00"))
        decision = evaluate(
            request,
            policy,
            log.spend_history("research-bot", since=NOW - timedelta(days=30)),
            now=NOW,
        )
        assert decision.outcome is Outcome.ALLOW
        log.append(request, decision)

    third = intent(intent_id="i2", amount=Decimal("1.00"))
    decision = evaluate(
        third,
        policy,
        log.spend_history("research-bot", since=NOW - timedelta(days=30)),
        now=NOW,
    )
    assert decision.outcome is Outcome.DENY
    assert decision.reason_code.value == "OVER_ROLLING_WINDOW"
