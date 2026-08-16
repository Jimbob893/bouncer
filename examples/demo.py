"""A scripted agent tries six purchases against the sample policy.

Run it:

    python examples/demo.py

Everything happens in a throwaway directory, so the demo never touches your
real bouncer state. Six attempts, six different outcomes:

    1. within policy                 -> ALLOW, mandate issued and redeemed
    2. over the per-transaction cap  -> DENY
    3. merchant on the denylist      -> DENY
    4. above the approval threshold  -> REQUIRE_APPROVAL, then a human approves
    5. trips the rolling window      -> DENY
    6. a mandate replayed            -> REJECTED

It closes by verifying the audit chain, then tampering with one row to show
the tamper evidence actually fires.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import text  # noqa: E402

from bouncer.approvals import ApprovalQueue  # noqa: E402
from bouncer.audit import AuditLog  # noqa: E402
from bouncer.enforcement import AuthorizationResult, Enforcer  # noqa: E402
from bouncer.errors import MandateError  # noqa: E402
from bouncer.keys import OperatorKey  # noqa: E402
from bouncer.mandate import NonceStore, verify_mandate  # noqa: E402
from bouncer.models import Outcome, PaymentIntent  # noqa: E402
from bouncer.sources import LocalFileSource  # noqa: E402

POLICY_PATH = Path(__file__).parent / "policy.yaml"

_USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def _c(code: str, text_value: str) -> str:
    return f"\033[{code}m{text_value}\033[0m" if _USE_COLOR else text_value


def BOLD(s: str) -> str:
    return _c("1", s)


def DIM(s: str) -> str:
    return _c("2", s)


def GREEN(s: str) -> str:
    return _c("32", s)


def RED(s: str) -> str:
    return _c("31", s)


def YELLOW(s: str) -> str:
    return _c("33", s)


def CYAN(s: str) -> str:
    return _c("36", s)

WIDTH = 68


class Clock:
    """A movable clock, so the demo can have a believable spending history."""

    def __init__(self, now: datetime) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now


def rule(char: str = "─") -> None:
    print(DIM(char * WIDTH))


def banner() -> None:
    print()
    rule("═")
    print(BOLD("  bouncer") + DIM("  ·  policy enforcement for agent spending"))
    rule("═")


def show_outcome(result: AuthorizationResult) -> None:
    decision = result.decision
    if decision.outcome is Outcome.ALLOW:
        badge = GREEN("✔ ALLOW")
    elif decision.outcome is Outcome.DENY:
        badge = RED("✘ DENY")
    else:
        badge = YELLOW("⏸ APPROVAL")
    print(f"    {badge}  {DIM(decision.reason_code.value)}")
    print(f"    {DIM('└')} {decision.reason}")
    if decision.rule:
        print(f"      {DIM('rule: ' + decision.rule)}")


def attempt(
    number: int,
    title: str,
    enforcer: Enforcer,
    intent: PaymentIntent,
) -> AuthorizationResult:
    print()
    print(
        BOLD(f" {number}. {title}")
    )
    print(
        f"    {CYAN(f'${intent.amount}')} to {intent.merchant}"
        + (f"  {DIM('(' + intent.category + ')')}" if intent.category else "")
    )
    result = enforcer.authorize(intent)
    show_outcome(result)
    return result


def main() -> int:
    home = Path(tempfile.mkdtemp(prefix="bouncer-demo-"))
    try:
        return run(home)
    finally:
        shutil.rmtree(home, ignore_errors=True)


def run(home: Path) -> int:
    clock = Clock(datetime(2026, 3, 11, 14, 30, tzinfo=timezone.utc))
    key = OperatorKey.generate(home / "operator.pem")
    audit = AuditLog(home / "bouncer.db", key)
    source = LocalFileSource(POLICY_PATH)
    nonces = NonceStore(home / "bouncer.db", engine=audit.engine)
    enforcer = Enforcer(
        source=source,
        audit=audit,
        key=key,
        nonces=nonces,
        approvals=ApprovalQueue(home / "bouncer.db", engine=audit.engine),
        clock=clock,
    )

    loaded = source.load()
    assert loaded.policy is not None, loaded.error
    rules = loaded.policy.agents["research-bot"]

    banner()
    print(f"  {DIM('policy')}      {POLICY_PATH.name}")
    print(f"  {DIM('policy hash')} {loaded.policy_hash[:32]}…")
    print(f"  {DIM('agent')}       research-bot")
    print(
        f"  {DIM('limits')}      ${rules.per_transaction_cap} per transaction  ·  "
        f"${rules.rolling_windows[0].amount} per {rules.rolling_windows[0].window}"
    )
    assert rules.approval_required_above is not None
    print(
        f"  {DIM('approval')}    above ${rules.approval_required_above.amount} "
        f"→ role {rules.approval_required_above.approver_role!r}"
    )

    # Give the agent a believable spending history. Each seeded purchase stays
    # under the approval threshold so it commits straight away — an amount that
    # needed a human would sit in the queue instead of counting as spend.
    seeded = Decimal(0)
    for days_ago in (20, 15, 10):
        clock.now -= timedelta(days=days_ago)
        seed = enforcer.authorize(
            PaymentIntent(
                agent_id="research-bot",
                merchant="api.data-vendor.example",
                amount=Decimal("16.00"),
                currency="USD",
                category="data",
                description="Earlier this month",
            )
        )
        assert seed.decision.outcome is Outcome.ALLOW, seed.decision.reason
        seeded += Decimal("16.00")
        clock.now += timedelta(days=days_ago)
    print(f"  {DIM('already spent')} ${seeded} in the last 30 days")
    rule()

    # -- 1. within policy -------------------------------------------------
    allowed = attempt(
        1,
        "A small, in-policy purchase",
        enforcer,
        PaymentIntent(
            agent_id="research-bot",
            merchant="api.weather.example",
            amount=Decimal("12.00"),
            currency="USD",
            category="data",
            description="Forecast API credits",
        ),
    )
    assert allowed.mandate is not None
    print(f"      {DIM('mandate:')} {allowed.mandate[:44]}…")
    claims = verify_mandate(
        allowed.mandate, key, now=clock.now, nonce_store=nonces
    )
    print(
        f"      {GREEN('redeemed once')} "
        + DIM(f"(scoped to {claims.merchant}, ≤ ${claims.max_amount}, expires "
              f"{claims.expires_at.strftime('%H:%M:%S')}Z)")
    )

    # -- 2. over the per-transaction cap ----------------------------------
    attempt(
        2,
        "Over the per-transaction cap",
        enforcer,
        PaymentIntent(
            agent_id="research-bot",
            merchant="api.data-vendor.example",
            amount=Decimal("75.00"),
            currency="USD",
            description="Bulk dataset",
        ),
    )

    # -- 3. denylisted merchant -------------------------------------------
    attempt(
        3,
        "A merchant on the denylist",
        enforcer,
        PaymentIntent(
            agent_id="research-bot",
            merchant="lucky.casino.example",
            amount=Decimal("5.00"),
            currency="USD",
            description="Definitely research",
        ),
    )

    # -- 4. needs a human -------------------------------------------------
    pending = attempt(
        4,
        "Above the approval threshold",
        enforcer,
        PaymentIntent(
            agent_id="research-bot",
            merchant="api.data-vendor.example",
            amount=Decimal("35.00"),
            currency="USD",
            description="Quarterly dataset",
        ),
    )
    assert pending.pending_id is not None
    print()
    print(f"      {DIM('queued for a human:')} {pending.pending_id}")
    print(f"      {DIM('$ bouncer pending --role finance')}")

    wrong = None
    try:
        enforcer.resolve(pending.pending_id, role="engineering", approve=True)
    except Exception as exc:  # RoleMismatch
        wrong = exc
    print(f"      {DIM('$ bouncer approve ' + pending.pending_id + ' --role engineering')}")
    print(f"      {RED('✘ refused')}  {DIM(str(wrong))}")

    print(f"      {DIM('$ bouncer approve ' + pending.pending_id + ' --role finance')}")
    approved = enforcer.resolve(
        pending.pending_id, role="finance", approve=True, note="ok for Q1 research"
    )
    print(f"      {GREEN('✔ approved')}  {DIM(approved.decision.reason)}")

    # -- 5. trips the rolling window --------------------------------------
    attempt(
        5,
        "Trips the 30-day rolling ceiling",
        enforcer,
        PaymentIntent(
            agent_id="research-bot",
            merchant="api.weather.example",
            amount=Decimal("10.00"),
            currency="USD",
            description="One more forecast",
        ),
    )

    # -- 6. replayed mandate ----------------------------------------------
    print()
    print(BOLD(" 6. Replaying the mandate from step 1"))
    print(f"    {CYAN('$12.00')} to api.weather.example  {DIM('(same mandate, second use)')}")
    try:
        verify_mandate(allowed.mandate, key, now=clock.now, nonce_store=nonces)
        print(f"    {RED('✘ BUG: replay succeeded')}")
        return 1
    except MandateError as exc:
        print(f"    {RED('✘ REJECTED')}  {DIM(type(exc).__name__)}")
        print(f"    {DIM('└')} {exc}")

    # -- the audit log ----------------------------------------------------
    print()
    rule("═")
    print(BOLD("  The audit log"))
    rule("═")
    print()
    print(f"  {DIM('seq  outcome           reason                  amount')}")
    for entry in audit.entries():
        colour = GREEN if entry.outcome == "ALLOW" else (
            YELLOW if entry.outcome == "REQUIRE_APPROVAL" else RED
        )
        # Pad before colourizing: ANSI escapes count toward field width and
        # would knock every column out of alignment.
        print(
            f"  {entry.seq:<4} {colour(f'{entry.outcome:<16}')} "
            f"{DIM(f'{entry.reason_code:<23}')} ${entry.amount}"
        )

    result = audit.verify()
    print()
    print(f"  {DIM('$ bouncer verify')}")
    print(f"  {GREEN('✔ ' + result.describe())}")

    # Now break it, to show the evidence is real. Pick a row that really was a
    # denial, so flipping it to ALLOW is a genuine change rather than a no-op.
    victim = next(entry.seq for entry in audit.entries() if entry.outcome == "DENY")
    print()
    print(
        f"  {DIM(f'An attacker edits row {victim} directly in SQLite, flipping a blocked')}"
    )
    print(f"  {DIM('payment to an authorized one…')}")
    with audit.engine.begin() as connection:
        connection.execute(
            text("UPDATE audit_entries SET outcome='ALLOW' WHERE seq=:seq"),
            {"seq": victim},
        )
    broken = audit.verify()
    print(f"  {DIM('$ bouncer verify')}")
    print(f"  {RED('✘ ' + broken.describe())}")
    if broken.ok:
        print(f"  {RED('BUG: tampering went undetected')}")
        return 1

    print()
    rule("═")
    print(
        DIM("  bouncer is the policy decision point. Pair it with egress control\n"
            "  at the network layer — it is not a sandbox on its own.")
    )
    rule("═")
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
