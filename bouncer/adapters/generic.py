"""Generic adapter: an explicit JSON payment intent.

The rail for agents that ask bouncer directly rather than being proxied. The
body is simply the intent, so there is nothing to infer.
"""

from __future__ import annotations

import json
from decimal import Decimal, InvalidOperation
from typing import Any

from pydantic import ValidationError

from ..errors import UnparseableIntent
from ..models import PaymentIntent
from .base import RequestContext

__all__ = ["GenericAdapter"]


class GenericAdapter:
    """Parses ``{"merchant": ..., "amount": ..., "currency": ...}``."""

    name = "generic"

    def matches(self, ctx: RequestContext) -> bool:
        if not ctx.body:
            return False
        try:
            payload = json.loads(ctx.text())
        except ValueError:
            return False
        return isinstance(payload, dict) and "amount" in payload and "merchant" in payload

    def parse(self, ctx: RequestContext) -> PaymentIntent:
        try:
            payload: Any = json.loads(ctx.text())
        except ValueError as exc:
            raise UnparseableIntent(f"body is not valid JSON: {exc}") from exc
        if not isinstance(payload, dict):
            raise UnparseableIntent("intent body must be a JSON object")

        raw_amount = payload.get("amount")
        if raw_amount is None:
            raise UnparseableIntent("intent is missing 'amount'")
        try:
            # str() first: a JSON float like 10.10 is not exactly 10.10, and the
            # amount that gets authorized must be the amount that was written.
            amount = Decimal(str(raw_amount))
        except InvalidOperation as exc:
            raise UnparseableIntent(f"amount {raw_amount!r} is not a number") from exc

        fields: dict[str, Any] = {
            "agent_id": str(payload.get("agent_id") or ctx.agent_id),
            "merchant": str(payload.get("merchant", "")),
            "amount": amount,
            "currency": str(payload.get("currency", "USD")),
            "category": payload.get("category"),
            "description": payload.get("description"),
            "rail": self.name,
            "metadata": {
                str(k): str(v) for k, v in (payload.get("metadata") or {}).items()
            },
        }
        if payload.get("intent_id"):
            fields["intent_id"] = str(payload["intent_id"])

        try:
            return PaymentIntent(**fields)
        except ValidationError as exc:
            raise UnparseableIntent(f"intent failed validation: {exc}") from exc
