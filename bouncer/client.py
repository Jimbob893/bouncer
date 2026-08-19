"""The client library: how an agent asks before it spends.

Everything else in bouncer is machinery. This is the seam an application
developer actually touches, so it has exactly one job — make the safe thing
the easy thing:

    with client.spend(merchant="api.weather.example", amount="12.00") as ok:
        charge_the_card(mandate=ok.mandate)

Threat model: **a denial raises, and the guarded block never runs.** This is
the whole reason the API is a context manager rather than a function returning
a verdict. A returned decision can be ignored by forgetting to check it, and an
ignored denial is an unenforced policy — the failure would be silent, and it
would look exactly like success. Raising makes that mistake impossible to write.

Two further properties follow from the same reasoning:

- **An allow with no mandate is treated as a denial.** A mandate is the proof
  bouncer authorized this payment; if one was not minted, there is nothing to
  present downstream, so proceeding would be spending on an unproven verdict.
- **Nothing is caught around the guarded block.** An exception raised by your
  payment call propagates untouched. This module never converts a failed
  payment into a successful-looking one.

What this does NOT do:

- It does not settle anything. bouncer authorizes; your code still calls the
  payment rail. The mandate is what you hand to it.
- It does not reconcile. Spend counts against rolling windows at *authorization*
  time, not at settlement, so a payment you authorize and then abandon still
  consumes budget. That is deliberate: the conservative direction is to
  over-count, because under-counting would let a retry loop outspend its
  ceiling.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation

from pydantic import ValidationError

from .config import BouncerConfig
from .enforcement import AuthorizationResult, Enforcer
from .errors import BouncerError
from .models import Decision, Outcome, PaymentIntent

__all__ = [
    "ApprovalRequired",
    "Authorized",
    "Client",
    "InvalidSpend",
    "SpendDenied",
    "SpendRefused",
]

#: Amounts are accepted as Decimal, int, or str — never float. A float cannot
#: represent most monetary values exactly, and the number that gets authorized
#: must be the number that was written. See bouncer.canonical.
Amount = Decimal | int | str


class SpendRefused(BouncerError):
    """Base class for a spend this client would not let proceed."""


class InvalidSpend(SpendRefused):
    """The spend request itself was malformed, so it was never evaluated.

    Threat model: this is a refusal, not a pass-through. A request bouncer
    cannot construct an intent from is a request it cannot judge.
    """


class SpendDenied(SpendRefused):
    """Policy denied this payment. The guarded block did not run."""

    def __init__(self, message: str, *, decision: Decision, intent: PaymentIntent) -> None:
        super().__init__(message)
        self.decision = decision
        self.intent = intent


class ApprovalRequired(SpendRefused):
    """A human must sign off, and the caller asked not to wait.

    The request is already parked in the approval queue under
    :attr:`pending_id`; resolving it is a separate act by an approver.
    """

    def __init__(
        self,
        message: str,
        *,
        decision: Decision,
        intent: PaymentIntent,
        pending_id: str | None,
    ) -> None:
        super().__init__(message)
        self.decision = decision
        self.intent = intent
        self.pending_id = pending_id


@dataclass(frozen=True)
class Authorized:
    """Proof that bouncer authorized one specific payment.

    Yielded into the guarded block. ``mandate`` is the artifact to hand to the
    payment rail — it is scoped to this merchant and ceiling, expires, and can
    be redeemed exactly once.
    """

    mandate: str
    decision: Decision
    intent: PaymentIntent
    audit_seq: int | None = None

    @property
    def amount(self) -> Decimal:
        return self.intent.amount

    @property
    def merchant(self) -> str:
        return self.intent.merchant


class Client:
    """The in-process client. Wraps an :class:`~bouncer.enforcement.Enforcer`.

    One client is bound to one ``agent_id``, because an agent's identity is the
    thing policy is written against. Sharing a client between agents would let
    one agent spend under another's rules.
    """

    def __init__(
        self,
        enforcer: Enforcer,
        *,
        agent_id: str,
        currency: str = "USD",
    ) -> None:
        self._enforcer = enforcer
        self._agent_id = agent_id
        self._currency = currency

    @classmethod
    def open(
        cls,
        *,
        agent_id: str,
        config: BouncerConfig | None = None,
        currency: str = "USD",
    ) -> Client:
        """Build a client from on-disk state (``~/.bouncer`` by default)."""
        # Imported here rather than at module scope: the wiring helper lives in
        # the HTTP layer, and a library caller should not pay FastAPI's import
        # cost merely to use the in-process client.
        from .api import build_enforcer

        resolved = config if config is not None else BouncerConfig.from_env()
        return cls(build_enforcer(resolved), agent_id=agent_id, currency=currency)

    @property
    def agent_id(self) -> str:
        return self._agent_id

    @property
    def enforcer(self) -> Enforcer:
        return self._enforcer

    # -- the guarded spend -------------------------------------------------

    @contextmanager
    def spend(
        self,
        *,
        merchant: str,
        amount: Amount,
        currency: str | None = None,
        category: str | None = None,
        description: str | None = None,
        wait: bool = False,
        timeout: float | None = None,
    ) -> Iterator[Authorized]:
        """Authorize one payment, then run the guarded block if it was allowed.

        Args:
            wait: When True and the policy requires a human, block until an
                approver answers or the timeout elapses. **The wait times out
                into a deny**, never into an allow.

        Yields:
            :class:`Authorized`, carrying the mandate to present downstream.

        Raises:
            SpendDenied: policy said no. The block does not run.
            ApprovalRequired: a human is needed and ``wait`` was False.
            InvalidSpend: the request could not be turned into an intent.
        """
        intent = self._intent(
            merchant=merchant,
            amount=amount,
            currency=currency,
            category=category,
            description=description,
        )
        result = self._authorize(intent, wait=wait, timeout=timeout)
        # Deliberately outside any try/except: an exception from the caller's
        # block is theirs and must propagate untouched.
        yield _require_allowed(result)

    @asynccontextmanager
    async def aspend(
        self,
        *,
        merchant: str,
        amount: Amount,
        currency: str | None = None,
        category: str | None = None,
        description: str | None = None,
        wait: bool = False,
        timeout: float | None = None,
    ) -> AsyncIterator[Authorized]:
        """Async form of :meth:`spend`, for agents running on an event loop.

        The synchronous authorization work is pushed to a worker thread so a
        spend cannot stall the caller's event loop.
        """
        intent = self._intent(
            merchant=merchant,
            amount=amount,
            currency=currency,
            category=category,
            description=description,
        )
        if wait:
            result = await self._enforcer.authorize_blocking(intent, timeout=timeout)
        else:
            result = await asyncio.to_thread(self._enforcer.authorize, intent)
        yield _require_allowed(result)

    # -- internals ---------------------------------------------------------

    def _intent(
        self,
        *,
        merchant: str,
        amount: Amount,
        currency: str | None,
        category: str | None,
        description: str | None,
    ) -> PaymentIntent:
        try:
            return PaymentIntent(
                agent_id=self._agent_id,
                merchant=merchant,
                amount=_coerce_amount(amount),
                currency=currency if currency is not None else self._currency,
                category=category,
                description=description,
                rail="client",
            )
        except ValidationError as exc:
            raise InvalidSpend(f"cannot build a payment intent: {exc}") from exc

    def _authorize(
        self, intent: PaymentIntent, *, wait: bool, timeout: float | None
    ) -> AuthorizationResult:
        if not wait:
            return self._enforcer.authorize(intent)

        try:
            asyncio.get_running_loop()
        except RuntimeError:
            # No loop running, so we own one for the duration of the wait.
            return asyncio.run(
                self._enforcer.authorize_blocking(intent, timeout=timeout)
            )
        raise InvalidSpend(
            "spend(wait=True) would block the running event loop; "
            "use `async with client.aspend(..., wait=True)` instead"
        )


def _coerce_amount(value: Amount) -> Decimal:
    """Convert an accepted amount type to an exact ``Decimal``.

    ``int`` and ``str`` both convert exactly. ``float`` is deliberately absent
    from :data:`Amount`: it cannot represent most monetary values, so the number
    authorized would not be the number written.
    """
    if isinstance(value, Decimal):
        return value
    try:
        return Decimal(value)
    except (InvalidOperation, ValueError) as exc:
        raise InvalidSpend(f"amount {value!r} is not a valid decimal amount") from exc


def _require_allowed(result: AuthorizationResult) -> Authorized:
    """Turn a result into an :class:`Authorized`, or raise.

    Threat model: this is the single gate every spend passes through. Every
    outcome other than ALLOW-with-a-mandate raises, so there is no path that
    yields a falsy or empty authorization into a caller's block.
    """
    decision = result.decision
    outcome = decision.outcome

    if outcome is Outcome.REQUIRE_APPROVAL:
        raise ApprovalRequired(
            decision.reason,
            decision=decision,
            intent=result.intent,
            pending_id=result.pending_id,
        )

    if outcome is not Outcome.ALLOW:
        raise SpendDenied(decision.reason, decision=decision, intent=result.intent)

    if not result.mandate:
        # An allow carrying no mandate cannot be proven downstream. Refusing is
        # the fail-closed reading; yielding an empty mandate would let a caller
        # spend on an unproven verdict.
        raise SpendDenied(
            "bouncer allowed this payment but issued no mandate, so there is "
            "nothing to present to the payment rail; refusing to proceed",
            decision=decision,
            intent=result.intent,
        )

    return Authorized(
        mandate=result.mandate,
        decision=decision,
        intent=result.intent,
        audit_seq=result.audit_seq,
    )
