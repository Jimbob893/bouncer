"""The adapter seam.

An adapter's entire job is to turn one payment rail's wire format into a
:class:`~bouncer.models.PaymentIntent`. Nothing downstream of an adapter knows
which rail a request came from, so adding a rail means writing one file here and
changing nothing else.

Threat model: an adapter is parsing hostile input — the agent controls the
request body. Adapters therefore never *decide* anything; they extract fields
and hand them to the engine. An adapter that cannot confidently parse a request
must raise, because :func:`~bouncer.adapters.parse_intent` turns that into a
deny. Guessing at an ambiguous amount would be worse than refusing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable
from urllib.parse import urlsplit

from ..models import PaymentIntent

__all__ = ["Adapter", "RequestContext"]


@dataclass(frozen=True)
class RequestContext:
    """One piece of agent traffic, as seen by the proxy or the API."""

    method: str = "POST"
    url: str = ""
    body: bytes = b""
    agent_id: str = "unknown"
    status_code: int | None = None
    headers: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Header names are case-insensitive on the wire; fold once here so no
        # adapter can be bypassed by a differently-cased header.
        object.__setattr__(
            self, "headers", {k.lower(): v for k, v in self.headers.items()}
        )

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)

    @property
    def host(self) -> str:
        return urlsplit(self.url).hostname or ""

    @property
    def path(self) -> str:
        return urlsplit(self.url).path or "/"

    @property
    def content_type(self) -> str:
        return self.header("content-type").split(";")[0].strip().lower()

    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


@runtime_checkable
class Adapter(Protocol):
    """Maps one payment rail's traffic into the normalized intent."""

    name: str

    def matches(self, ctx: RequestContext) -> bool:
        """Cheap check: is this request plausibly for this rail?"""
        ...

    def parse(self, ctx: RequestContext) -> PaymentIntent:
        """Extract a normalized intent, or raise ``UnparseableIntent``."""
        ...
