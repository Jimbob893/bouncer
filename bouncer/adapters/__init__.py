"""Payment-rail adapters and the registry that dispatches to them.

Adding a rail means adding one file here and one entry to :data:`DEFAULT_ADAPTERS`.
Nothing else in bouncer changes.
"""

from __future__ import annotations

from collections.abc import Sequence

from ..errors import UnparseableIntent
from ..models import PaymentIntent
from .base import Adapter, RequestContext
from .generic import GenericAdapter
from .stripe import StripeAdapter
from .x402 import X402Adapter

__all__ = [
    "Adapter",
    "DEFAULT_ADAPTERS",
    "GenericAdapter",
    "RequestContext",
    "StripeAdapter",
    "X402Adapter",
    "parse_intent",
]

#: Ordered most-specific first. Generic is last because it matches any JSON body
#: carrying an amount and a merchant, which a rail-specific body might also do.
DEFAULT_ADAPTERS: tuple[Adapter, ...] = (
    StripeAdapter(),
    X402Adapter(),
    GenericAdapter(),
)


def parse_intent(
    ctx: RequestContext, adapters: Sequence[Adapter] | None = None
) -> PaymentIntent:
    """Normalize a request into a :class:`PaymentIntent`.

    Threat model: this function raises rather than returning ``None`` so that
    unparseable traffic cannot be mistaken for benign traffic by a caller that
    forgot to check. Every call site turns the exception into a logged deny —
    bouncer never forwards a request it could not read.

    Raises:
        UnparseableIntent: no adapter recognized the request, or the adapter
            that did recognize it could not extract a coherent intent.
    """
    candidates = adapters if adapters is not None else DEFAULT_ADAPTERS
    attempted: list[str] = []

    for adapter in candidates:
        if not adapter.matches(ctx):
            continue
        attempted.append(adapter.name)
        return adapter.parse(ctx)

    raise UnparseableIntent(
        f"no adapter recognized {ctx.method} {ctx.url or '(no url)'} "
        f"(content-type {ctx.content_type or 'unset'}); "
        f"tried {', '.join(a.name for a in candidates)}"
    )
