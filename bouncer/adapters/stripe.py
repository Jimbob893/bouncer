"""Stripe adapter: parse a PaymentIntent create call. Test mode only.

Threat model: this adapter deliberately refuses to parse a request carrying a
*live* Stripe key. bouncer has not been security audited, and a v1 policy layer
should not be the thing standing between an agent and real money. A live-key
request raises, which the enforcement path turns into a logged deny — so the
refusal is visible rather than silent.

Stripe amounts arrive as integer minor units (``2000`` means $20.00), so the
adapter must know the currency's exponent. Zero-decimal currencies are listed
explicitly; anything unrecognized is treated as two-decimal, which matches ISO
4217 for every currency Stripe supports outside that list.
"""

from __future__ import annotations

from decimal import Decimal
from urllib.parse import parse_qs

from pydantic import ValidationError

from ..errors import UnparseableIntent
from ..models import PaymentIntent
from .base import RequestContext

__all__ = ["StripeAdapter"]

_STRIPE_HOSTS = {"api.stripe.com"}
_PAYMENT_INTENT_PATHS = ("/v1/payment_intents", "/v1/charges")

#: Currencies Stripe quotes without minor units: 2000 JPY is ¥2000, not ¥20.
_ZERO_DECIMAL = {
    "BIF", "CLP", "DJF", "GNF", "JPY", "KMF", "KRW", "MGA", "PYG",
    "RWF", "UGX", "VND", "VUV", "XAF", "XOF", "XPF",
}
#: Currencies Stripe quotes in thousandths.
_THREE_DECIMAL = {"BHD", "JOD", "KWD", "OMR", "TND"}

_TEST_KEY_PREFIXES = ("sk_test_", "rk_test_", "pk_test_")


def _exponent(currency: str) -> int:
    if currency in _ZERO_DECIMAL:
        return 0
    if currency in _THREE_DECIMAL:
        return 3
    return 2


class StripeAdapter:
    """Turns a Stripe PaymentIntent create call into a normalized intent."""

    name = "stripe"

    def matches(self, ctx: RequestContext) -> bool:
        if ctx.host not in _STRIPE_HOSTS:
            return False
        return any(ctx.path.startswith(prefix) for prefix in _PAYMENT_INTENT_PATHS)

    def parse(self, ctx: RequestContext) -> PaymentIntent:
        self._require_test_mode(ctx)

        form = parse_qs(ctx.text(), keep_blank_values=True)

        def first(key: str) -> str | None:
            values = form.get(key)
            return values[0] if values else None

        raw_amount = first("amount")
        if raw_amount is None:
            raise UnparseableIntent("Stripe request has no 'amount' field")
        try:
            minor_units = int(raw_amount)
        except ValueError as exc:
            raise UnparseableIntent(
                f"Stripe amount {raw_amount!r} is not an integer number of minor units"
            ) from exc

        currency = (first("currency") or "usd").strip().upper()
        amount = Decimal(minor_units) / (Decimal(10) ** _exponent(currency))

        # A direct charge names no payee, so the merchant is Stripe itself.
        # Connect charges name a destination, which is the useful thing to put
        # on an allowlist.
        merchant = (
            first("transfer_data[destination]")
            or first("on_behalf_of")
            or ctx.host
            or "api.stripe.com"
        )

        description = first("description") or first("statement_descriptor")
        metadata = {
            key[len("metadata[") : -1]: values[0]
            for key, values in form.items()
            if key.startswith("metadata[") and key.endswith("]") and values
        }
        metadata["stripe_amount_minor"] = str(minor_units)
        metadata["stripe_path"] = ctx.path

        try:
            return PaymentIntent(
                agent_id=ctx.agent_id,
                merchant=merchant,
                amount=amount,
                currency=currency,
                category=metadata.get("category"),
                description=description,
                rail=self.name,
                metadata=metadata,
            )
        except ValidationError as exc:
            raise UnparseableIntent(
                f"Stripe request did not yield a valid intent: {exc}"
            ) from exc

    @staticmethod
    def _require_test_mode(ctx: RequestContext) -> None:
        """Refuse live keys. See this module's threat model."""
        authorization = ctx.header("authorization")
        token = ""
        if authorization.lower().startswith("bearer "):
            token = authorization[7:].strip()
        elif authorization.lower().startswith("basic "):
            import base64
            import binascii

            try:
                decoded = base64.b64decode(authorization[6:].strip()).decode(
                    "utf-8", errors="replace"
                )
            except (ValueError, binascii.Error):
                decoded = ""
            token = decoded.split(":", 1)[0]

        if not token:
            raise UnparseableIntent(
                "Stripe request carries no API key, so bouncer cannot confirm it "
                "is a test-mode call"
            )
        if not token.startswith(_TEST_KEY_PREFIXES):
            raise UnparseableIntent(
                "refusing to authorize a live-mode Stripe call: bouncer v1 has "
                "not been security audited and supports test mode only"
            )
