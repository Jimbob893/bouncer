"""x402 adapter: parse an HTTP 402 challenge into a normalized intent.

An x402 server answers a request with ``402 Payment Required`` and a body
describing what it will accept. That challenge is the payment intent: it names
the price, the asset, and who is being paid.

Threat model: the challenge is written by the *server*, not the agent, but
bouncer trusts neither. The amount is read from ``maxAmountRequired`` — the
ceiling the agent would be authorizing, which is the number policy must be
applied to. If the asset's decimal precision is not stated, the challenge is
refused rather than guessed: reading an amount at the wrong scale would be off
by a factor of a million.
"""

from __future__ import annotations

import json
from decimal import Decimal, InvalidOperation
from typing import Any
from urllib.parse import urlsplit

from pydantic import ValidationError

from ..errors import UnparseableIntent
from ..models import PaymentIntent
from .base import RequestContext

__all__ = ["X402Adapter"]

#: Decimals for assets x402 commonly quotes. Anything else must state
#: `extra.decimals` in the challenge.
_KNOWN_DECIMALS: dict[str, int] = {"USDC": 6, "USDT": 6, "DAI": 18, "PYUSD": 6}


class X402Adapter:
    """Turns an HTTP 402 challenge into a :class:`PaymentIntent`."""

    name = "x402"

    def matches(self, ctx: RequestContext) -> bool:
        if ctx.status_code == 402:
            return True
        if not ctx.body:
            return False
        try:
            payload = json.loads(ctx.text())
        except ValueError:
            return False
        return isinstance(payload, dict) and "x402Version" in payload

    def parse(self, ctx: RequestContext) -> PaymentIntent:
        try:
            payload: Any = json.loads(ctx.text())
        except ValueError as exc:
            raise UnparseableIntent(f"402 challenge is not valid JSON: {exc}") from exc
        if not isinstance(payload, dict):
            raise UnparseableIntent("402 challenge must be a JSON object")

        offers = payload.get("accepts")
        if not isinstance(offers, list) or not offers:
            raise UnparseableIntent("402 challenge has no 'accepts' entries")
        offer = offers[0]
        if not isinstance(offer, dict):
            raise UnparseableIntent("'accepts' entry must be an object")

        extra = offer.get("extra") if isinstance(offer.get("extra"), dict) else {}
        symbol = str(extra.get("name") or offer.get("asset") or "").strip().upper()
        if not symbol:
            raise UnparseableIntent("402 challenge does not name the asset")

        decimals = extra.get("decimals", _KNOWN_DECIMALS.get(symbol))
        if decimals is None:
            raise UnparseableIntent(
                f"402 challenge does not state decimals for asset {symbol!r}; "
                "refusing to guess the scale of the amount"
            )
        try:
            scale = int(decimals)
        except (TypeError, ValueError) as exc:
            raise UnparseableIntent(f"invalid decimals {decimals!r}") from exc
        if not 0 <= scale <= 36:
            raise UnparseableIntent(f"implausible decimals: {scale}")

        raw_amount = offer.get("maxAmountRequired")
        if raw_amount is None:
            raise UnparseableIntent("402 offer is missing 'maxAmountRequired'")
        try:
            atomic = Decimal(str(raw_amount))
        except InvalidOperation as exc:
            raise UnparseableIntent(
                f"maxAmountRequired {raw_amount!r} is not a number"
            ) from exc
        amount = atomic / (Decimal(10) ** scale)

        resource = str(offer.get("resource") or "")
        merchant = urlsplit(resource).hostname or ctx.host
        if not merchant:
            raise UnparseableIntent(
                "cannot determine the merchant: the 402 offer names no resource "
                "host and the request URL has none"
            )

        metadata = {
            "x402_version": str(payload.get("x402Version", "")),
            "scheme": str(offer.get("scheme", "")),
            "network": str(offer.get("network", "")),
            "pay_to": str(offer.get("payTo", "")),
            "asset": str(offer.get("asset", "")),
            "resource": resource,
            "atomic_amount": str(atomic),
            "decimals": str(scale),
        }

        try:
            return PaymentIntent(
                agent_id=ctx.agent_id,
                merchant=merchant,
                amount=amount,
                currency=symbol,
                category=str(offer.get("category")) if offer.get("category") else None,
                description=str(offer.get("description") or "")[:512] or None,
                rail=self.name,
                metadata={k: v for k, v in metadata.items() if v},
            )
        except ValidationError as exc:
            raise UnparseableIntent(
                f"402 challenge did not yield a valid intent: {exc}"
            ) from exc
