"""The enforcement core: load policy, decide, log, mint.

Both entry points — the REST API and the forward proxy — go through this class,
so there is exactly one path from "a payment was attempted" to "a decision was
recorded". A second path would be a second place for the rules to be wrong.

Threat model: every branch here ends in an audit entry, including the failure
branches. Traffic that cannot be parsed, policy that cannot be loaded, and
approvals that time out are all *logged denials*, never silent pass-throughs.
"""

from __future__ import annotations

import asyncio
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any

from .approvals import ApprovalQueue, ApprovalStatus, PendingView, to_webhook_payload
from .audit import AuditLog
from .engine import evaluate, evaluate_tunnel
from .errors import UnparseableIntent
from .keys import OperatorKey
from .mandate import DEFAULT_TTL, NonceStore, issue_mandate
from .models import Decision, Outcome, PaymentIntent, ReasonCode
from .sources import PolicySource

__all__ = ["AuthorizationResult", "Enforcer"]

#: How far back to pull spend history. Must exceed the longest rolling window a
#: policy can express; over-fetching is harmless because the engine filters.
_HISTORY_LOOKBACK = timedelta(days=400)

#: Poll interval while a request waits on a human.
_APPROVAL_POLL_SECONDS = 0.25


@dataclass(frozen=True)
class AuthorizationResult:
    """The outcome of an authorization attempt."""

    decision: Decision
    intent: PaymentIntent
    mandate: str | None = None
    pending_id: str | None = None
    audit_seq: int | None = None

    @property
    def allowed(self) -> bool:
        return self.decision.outcome is Outcome.ALLOW

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.model_dump(mode="json"),
            "intent": self.intent.model_dump(mode="json"),
            "mandate": self.mandate,
            "pending_id": self.pending_id,
            "audit_seq": self.audit_seq,
        }


class Enforcer:
    """Ties policy, audit, mandates and approvals into one decision path."""

    def __init__(
        self,
        *,
        source: PolicySource,
        audit: AuditLog,
        key: OperatorKey,
        nonces: NonceStore,
        approvals: ApprovalQueue,
        mandate_ttl: timedelta = DEFAULT_TTL,
        approval_timeout: float = 300.0,
        webhook_url: str | None = None,
        clock: Any = None,
    ) -> None:
        self.source = source
        self.audit = audit
        self.key = key
        self.nonces = nonces
        self.approvals = approvals
        self.mandate_ttl = mandate_ttl
        self.approval_timeout = approval_timeout
        self.webhook_url = webhook_url
        self._clock = clock if clock is not None else (lambda: datetime.now(timezone.utc))

    def now(self) -> datetime:
        moment: datetime = self._clock()
        if moment.tzinfo is None:
            raise ValueError("clock must return timezone-aware datetimes")
        return moment

    # -- the main path ----------------------------------------------------

    def authorize(
        self, intent: PaymentIntent, *, record: bool = True
    ) -> AuthorizationResult:
        """Evaluate one intent, log the decision, and mint a mandate if allowed.

        Approval-requiring decisions are parked in the queue and returned
        immediately; use :meth:`authorize_blocking` to wait for a human.
        """
        moment = self.now()
        loaded = self.source.load()

        history = self.audit.spend_history(
            intent.agent_id, since=moment - _HISTORY_LOOKBACK
        )
        decision = evaluate(intent, loaded, history, now=moment)

        mandate: str | None = None
        pending_id: str | None = None

        if decision.outcome is Outcome.ALLOW:
            mandate, _ = issue_mandate(
                intent,
                self.key,
                policy_hash=decision.policy_hash,
                now=moment,
                ttl=self.mandate_ttl,
            )
        elif decision.outcome is Outcome.REQUIRE_APPROVAL:
            item = self.approvals.enqueue(intent, decision)
            pending_id = item.id
            self._fire_webhook(item)

        seq = None
        if record:
            seq = self.audit.append(intent, decision).seq

        return AuthorizationResult(
            decision=decision,
            intent=intent,
            mandate=mandate,
            pending_id=pending_id,
            audit_seq=seq,
        )

    def deny_unparseable(
        self, error: UnparseableIntent, intent: PaymentIntent
    ) -> AuthorizationResult:
        """Record a deny for traffic no adapter could read.

        Threat model: an intent bouncer cannot parse is never forwarded. It is
        denied, logged with the parse failure, and surfaced to the operator.
        """
        moment = self.now()
        loaded = self.source.load()
        decision = Decision(
            outcome=Outcome.DENY,
            reason_code=ReasonCode.UNPARSEABLE_INTENT,
            reason=str(error),
            rule="adapters",
            policy_hash=loaded.policy_hash,
            evaluated_at=moment,
        )
        seq = self.audit.append(intent, decision, kind="unparseable").seq
        return AuthorizationResult(decision=decision, intent=intent, audit_seq=seq)

    def authorize_tunnel(self, host: str, agent_id: str) -> AuthorizationResult:
        """Decide on an opaque CONNECT tunnel. See :func:`evaluate_tunnel`."""
        moment = self.now()
        loaded = self.source.load()
        decision = evaluate_tunnel(host, loaded, agent_id=agent_id, now=moment)
        # A tunnel has no amount; record it as zero so the row is well-formed
        # without implying a spend. Tunnels never count toward rolling windows.
        placeholder = PaymentIntent(
            agent_id=agent_id,
            merchant=host,
            amount=Decimal(0),
            currency="XXX",
            rail="connect",
            description=f"CONNECT {host}",
        )
        seq = self.audit.append(placeholder, decision, kind="tunnel").seq
        return AuthorizationResult(decision=decision, intent=placeholder, audit_seq=seq)

    # -- human in the loop ------------------------------------------------

    def resolve(
        self, item_id: str, *, role: str, approve: bool, note: str | None = None
    ) -> AuthorizationResult:
        """Resolve a queued approval and record the final decision.

        The queued item's original decision is superseded by a new one recorded
        here, so the audit log shows both the request for approval and its
        answer. Only an approval mints a mandate.
        """
        moment = self.now()
        item = self.approvals.resolve(
            item_id, role=role, approve=approve, note=note, now=moment
        )
        return self._finalize(item, approve=approve, moment=moment, note=note)

    def _finalize(
        self,
        item: PendingView,
        *,
        approve: bool,
        moment: datetime,
        note: str | None,
        timed_out: bool = False,
    ) -> AuthorizationResult:
        if timed_out:
            reason_code = ReasonCode.APPROVAL_TIMEOUT
            reason = (
                f"no {item.required_role!r} approval arrived before the timeout; "
                "bouncer denies on timeout"
            )
        elif approve:
            reason_code = ReasonCode.APPROVAL_GRANTED
            reason = f"approved by role {item.resolved_by_role!r}"
        else:
            reason_code = ReasonCode.APPROVAL_DENIED
            reason = f"denied by role {item.resolved_by_role!r}"
        if note:
            reason = f"{reason}: {note}"

        decision = Decision(
            outcome=Outcome.ALLOW if approve else Outcome.DENY,
            reason_code=reason_code,
            reason=reason,
            rule=item.decision.rule,
            approver_role=item.required_role,
            policy_hash=item.decision.policy_hash,
            evaluated_at=moment,
        )

        mandate: str | None = None
        if approve:
            mandate, _ = issue_mandate(
                item.intent,
                self.key,
                policy_hash=decision.policy_hash,
                now=moment,
                ttl=self.mandate_ttl,
            )

        seq = self.audit.append(
            item.intent, decision, kind="approval", note=f"approval:{item.id}"
        ).seq
        return AuthorizationResult(
            decision=decision,
            intent=item.intent,
            mandate=mandate,
            pending_id=item.id,
            audit_seq=seq,
        )

    async def authorize_blocking(
        self, intent: PaymentIntent, *, timeout: float | None = None
    ) -> AuthorizationResult:
        """Authorize, waiting for a human if the policy requires one.

        Threat model: the wait **times out into a deny**. A request that nobody
        answered is not an approved request, and an operator who is asleep must
        not become an implicit rubber stamp.
        """
        result = self.authorize(intent)
        if result.decision.outcome is not Outcome.REQUIRE_APPROVAL:
            return result

        assert result.pending_id is not None
        limit = timeout if timeout is not None else self.approval_timeout
        deadline = asyncio.get_running_loop().time() + limit

        while asyncio.get_running_loop().time() < deadline:
            await asyncio.sleep(_APPROVAL_POLL_SECONDS)
            item = self.approvals.get(result.pending_id)
            if item.status is ApprovalStatus.APPROVED:
                return self._finalize(item, approve=True, moment=self.now(), note=item.note)
            if item.status in (ApprovalStatus.DENIED, ApprovalStatus.TIMED_OUT):
                return self._finalize(item, approve=False, moment=self.now(), note=item.note)

        expired = self.approvals.expire(result.pending_id, now=self.now())
        if expired is None:
            # Resolved in the gap between the last poll and the timeout.
            item = self.approvals.get(result.pending_id)
            approved = item.status is ApprovalStatus.APPROVED
            return self._finalize(item, approve=approved, moment=self.now(), note=item.note)

        return self._finalize(
            expired, approve=False, moment=self.now(), note=None, timed_out=True
        )

    # -- notifications ----------------------------------------------------

    def _fire_webhook(self, item: PendingView) -> None:
        """POST a notification about a new pending item, best-effort.

        Runs on a daemon thread and swallows every error: a Slack outage must
        not change an authorization outcome, and must never block the decision
        path. The queue is the source of truth; the webhook is a convenience.
        """
        if not self.webhook_url:
            return

        url = self.webhook_url
        body = to_webhook_payload(item).encode("utf-8")

        def send() -> None:
            request = urllib.request.Request(
                url,
                data=body,
                headers={"Content-Type": "application/json", "User-Agent": "bouncer"},
                method="POST",
            )
            try:
                with urllib.request.urlopen(request, timeout=5):
                    pass
            except (urllib.error.URLError, OSError, ValueError):
                pass

        threading.Thread(target=send, daemon=True, name="bouncer-webhook").start()
