"""The human-in-the-loop approval queue.

Threat model: the ``--role`` flag is a **workflow guardrail, not a security
control**. It is an assertion by whoever holds shell access, not an
authenticated identity. It exists to stop the wrong person approving something
by mistake, not to stop someone determined to approve it anyway. v1 assumes a
single trusted operator on a trusted machine; anyone who can run the CLI can
approve anything. Do not build authentication on top of this without revisiting
the whole model.

Two properties do matter and are enforced here:

- **Approve and deny are symmetric.** Both require the same role check. There is
  no asymmetric authority where denying is easier than approving — that would
  let anyone veto spending, which is its own denial-of-service.
- **Resolution is once-only.** Resolving takes the row under a write lock and
  refuses if it is no longer pending, so an item cannot be approved twice or
  approved after it has timed out.
"""

from __future__ import annotations

import json
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from sqlalchemy import Engine, Index, String, Text, select
from sqlalchemy.orm import Mapped, mapped_column

from .canonical import utc_iso
from .db import Base, SessionFactory, create_session_factory, make_engine
from .errors import RoleMismatch, UnknownApproval
from .models import Decision, PaymentIntent

__all__ = ["ApprovalQueue", "ApprovalStatus", "PendingApproval", "PendingView"]


class ApprovalStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    DENIED = "DENIED"
    #: The requester's long poll elapsed. Timeouts resolve to denied, never
    #: to allowed.
    TIMED_OUT = "TIMED_OUT"


class PendingApproval(Base):
    """One decision waiting on a human."""

    __tablename__ = "pending_approvals"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    created_at: Mapped[str] = mapped_column(String(32), index=True)
    agent_id: Mapped[str] = mapped_column(String(128), index=True)
    merchant: Mapped[str] = mapped_column(String(253))
    amount: Mapped[str] = mapped_column(String(32))
    currency: Mapped[str] = mapped_column(String(12))
    required_role: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(String(16), index=True)
    intent_json: Mapped[str] = mapped_column(Text)
    decision_json: Mapped[str] = mapped_column(Text)
    resolved_at: Mapped[str | None] = mapped_column(String(32), nullable=True)
    resolved_by_role: Mapped[str | None] = mapped_column(String(64), nullable=True)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (Index("ix_pending_role_status", "required_role", "status"),)


@dataclass(frozen=True)
class PendingView:
    """A detached, read-only snapshot of a queue item."""

    id: str
    created_at: str
    agent_id: str
    merchant: str
    amount: str
    currency: str
    required_role: str
    status: ApprovalStatus
    intent: PaymentIntent
    decision: Decision
    resolved_at: str | None = None
    resolved_by_role: str | None = None
    note: str | None = None

    @classmethod
    def of(cls, row: PendingApproval) -> PendingView:
        return cls(
            id=row.id,
            created_at=row.created_at,
            agent_id=row.agent_id,
            merchant=row.merchant,
            amount=row.amount,
            currency=row.currency,
            required_role=row.required_role,
            status=ApprovalStatus(row.status),
            intent=PaymentIntent.model_validate_json(row.intent_json),
            decision=Decision.model_validate_json(row.decision_json),
            resolved_at=row.resolved_at,
            resolved_by_role=row.resolved_by_role,
            note=row.note,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "created_at": self.created_at,
            "agent_id": self.agent_id,
            "merchant": self.merchant,
            "amount": self.amount,
            "currency": self.currency,
            "required_role": self.required_role,
            "status": self.status.value,
            "intent": self.intent.model_dump(mode="json"),
            "decision": self.decision.model_dump(mode="json"),
            "resolved_at": self.resolved_at,
            "resolved_by_role": self.resolved_by_role,
            "note": self.note,
        }


class ApprovalQueue:
    """Stores decisions awaiting a human, tagged with the role that may act."""

    def __init__(self, db_path: str | Path, *, engine: Engine | None = None) -> None:
        self._engine = engine if engine is not None else make_engine(db_path)
        self._sessions: SessionFactory = create_session_factory(self._engine)
        self._lock = threading.Lock()

    @property
    def engine(self) -> Engine:
        return self._engine

    def enqueue(self, intent: PaymentIntent, decision: Decision) -> PendingView:
        """Park a REQUIRE_APPROVAL decision, tagged with its required role."""
        if not decision.approver_role:
            raise ValueError(
                "cannot enqueue a decision with no approver_role; the policy "
                "engine must name the role that may resolve it"
            )
        item_id = uuid.uuid4().hex[:12]
        with self._lock, self._sessions.begin() as session:
            row = PendingApproval(
                id=item_id,
                created_at=utc_iso(decision.evaluated_at),
                agent_id=intent.agent_id,
                merchant=intent.merchant,
                amount=str(intent.amount),
                currency=intent.currency,
                required_role=decision.approver_role,
                status=ApprovalStatus.PENDING.value,
                intent_json=intent.model_dump_json(),
                decision_json=decision.model_dump_json(),
            )
            session.add(row)
        return self.get(item_id)

    def get(self, item_id: str) -> PendingView:
        with self._sessions() as session:
            row = session.get(PendingApproval, item_id)
            if row is None:
                raise UnknownApproval(f"no pending approval with id {item_id!r}")
            return PendingView.of(row)

    def list(
        self,
        *,
        role: str | None = None,
        status: ApprovalStatus | None = ApprovalStatus.PENDING,
        limit: int = 200,
    ) -> list[PendingView]:
        with self._sessions() as session:
            statement = select(PendingApproval).order_by(PendingApproval.created_at)
            if role is not None:
                statement = statement.where(
                    PendingApproval.required_role == role.strip().lower()
                )
            if status is not None:
                statement = statement.where(PendingApproval.status == status.value)
            rows = session.execute(statement.limit(limit)).scalars().all()
            return [PendingView.of(row) for row in rows]

    def resolve(
        self,
        item_id: str,
        *,
        role: str,
        approve: bool,
        note: str | None = None,
        now: datetime | None = None,
    ) -> PendingView:
        """Approve or deny a pending item.

        Both paths run the identical role check — see this module's threat
        model on symmetry.

        Raises:
            UnknownApproval: no such item.
            RoleMismatch: the asserted role is not the required role, or the
                item is no longer pending.
        """
        asserted = role.strip().lower()
        moment = now if now is not None else datetime.now(timezone.utc)

        with self._lock, self._sessions.begin() as session:
            row = session.get(PendingApproval, item_id)
            if row is None:
                raise UnknownApproval(f"no pending approval with id {item_id!r}")

            if row.status != ApprovalStatus.PENDING.value:
                raise RoleMismatch(
                    f"approval {item_id!r} is already {row.status}; it cannot be "
                    "resolved again"
                )

            if asserted != row.required_role:
                raise RoleMismatch(
                    f"approval {item_id!r} requires role "
                    f"{row.required_role!r}, but you asserted {asserted!r}"
                )

            row.status = (
                ApprovalStatus.APPROVED.value if approve else ApprovalStatus.DENIED.value
            )
            row.resolved_at = utc_iso(moment)
            row.resolved_by_role = asserted
            row.note = note

        return self.get(item_id)

    def expire(self, item_id: str, *, now: datetime | None = None) -> PendingView | None:
        """Mark a still-pending item as timed out. Returns None if it was resolved.

        Threat model: a timeout is a denial. If a human never answered, the
        answer is no.
        """
        moment = now if now is not None else datetime.now(timezone.utc)
        with self._lock, self._sessions.begin() as session:
            row = session.get(PendingApproval, item_id)
            if row is None:
                raise UnknownApproval(f"no pending approval with id {item_id!r}")
            if row.status != ApprovalStatus.PENDING.value:
                return None
            row.status = ApprovalStatus.TIMED_OUT.value
            row.resolved_at = utc_iso(moment)
        return self.get(item_id)

    def status_of(self, item_id: str) -> ApprovalStatus:
        return self.get(item_id).status


def to_webhook_payload(item: PendingView) -> str:
    """Serialize a queue item for an outbound webhook."""
    return json.dumps(
        {
            "event": "approval.pending",
            "id": item.id,
            "agent_id": item.agent_id,
            "merchant": item.merchant,
            "amount": item.amount,
            "currency": item.currency,
            "required_role": item.required_role,
            "created_at": item.created_at,
            "reason": item.decision.reason,
        }
    )
