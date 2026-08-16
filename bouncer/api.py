"""The authorization API.

``POST /authorize`` takes a payment intent and returns a decision plus, when
allowed, a signed mandate.

Threat model: this service authenticates nobody. It is meant to listen on
loopback for a single operator's agents. The ``agent_id`` in a request is an
assertion by the caller, not a verified identity — an agent that can reach this
endpoint can claim to be any agent in the policy. Binding it to a public
interface would let anyone on the network do the same. See README.md.
"""

from __future__ import annotations

from decimal import Decimal, InvalidOperation
from typing import Any

from fastapi import FastAPI, Query, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from .adapters import RequestContext, parse_intent
from .approvals import ApprovalQueue
from .audit import AuditLog
from .config import BouncerConfig
from .enforcement import AuthorizationResult, Enforcer
from .errors import MandateError, UnparseableIntent
from .keys import OperatorKey
from .mandate import NonceStore, verify_mandate
from .models import Outcome, PaymentIntent
from .sources import LocalFileSource

__all__ = ["build_enforcer", "create_app"]

#: HTTP status per outcome. A denial is a 403 so an agent's HTTP client raises
#: on it by default rather than treating a block as success.
_STATUS = {
    Outcome.ALLOW: 200,
    Outcome.DENY: 403,
    Outcome.REQUIRE_APPROVAL: 202,
}

#: Cap on a single request body. An agent should not be able to exhaust memory
#: by posting an enormous "intent".
MAX_BODY_BYTES = 256 * 1024


class RawTraffic(BaseModel):
    """A description of intercepted traffic, for adapter-based parsing."""

    model_config = ConfigDict(extra="forbid")

    agent_id: str = Field(min_length=1, max_length=128)
    method: str = "POST"
    url: str = ""
    headers: dict[str, str] = Field(default_factory=dict)
    body: str = ""
    status_code: int | None = None


class VerifyMandateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mandate: str
    merchant: str | None = None
    amount: str | None = None
    agent_id: str | None = None
    consume: bool = True


def build_enforcer(config: BouncerConfig) -> Enforcer:
    """Wire up an enforcer from on-disk state."""
    config.ensure_home()
    assert config.key_path is not None and config.db_path is not None
    assert config.policy_path is not None
    key = OperatorKey.load_or_generate(config.key_path)
    audit = AuditLog(config.db_path, key)
    # All three share one engine, so they share one SQLite file and one write
    # lock — the CLI and the server stay consistent with each other.
    return Enforcer(
        source=LocalFileSource(config.policy_path),
        audit=audit,
        key=key,
        nonces=NonceStore(config.db_path, engine=audit.engine),
        approvals=ApprovalQueue(config.db_path, engine=audit.engine),
        approval_timeout=config.approval_timeout,
        webhook_url=config.webhook_url,
    )


def _respond(result: AuthorizationResult) -> JSONResponse:
    return JSONResponse(
        status_code=_STATUS[result.decision.outcome], content=result.to_dict()
    )


def create_app(config: BouncerConfig | None = None, *, enforcer: Enforcer | None = None) -> FastAPI:
    """Build the FastAPI application."""
    resolved = config if config is not None else BouncerConfig.from_env()
    engine = enforcer if enforcer is not None else build_enforcer(resolved)

    app = FastAPI(
        title="bouncer",
        version="0.1.0",
        description=(
            "A policy enforcement point for agent spending. Authorizes payment "
            "intents against a declarative policy and returns signed mandates. "
            "Never custodies funds. Authenticates nobody — bind to loopback."
        ),
    )
    app.state.enforcer = engine
    app.state.config = resolved

    @app.get("/healthz")
    def healthz() -> dict[str, Any]:
        loaded = engine.source.load()
        return {
            "status": "ok",
            "policy_ok": loaded.ok,
            "policy_origin": loaded.origin,
            "policy_hash": loaded.policy_hash,
            "policy_error": loaded.error,
            "key_id": engine.key.key_id,
        }

    @app.get("/policy")
    def current_policy() -> JSONResponse:
        loaded = engine.source.load()
        if loaded.policy is None:
            return JSONResponse(
                status_code=503,
                content={"ok": False, "error": loaded.error, "origin": loaded.origin},
            )
        return JSONResponse(
            content={
                "ok": True,
                "origin": loaded.origin,
                "policy_hash": loaded.policy_hash,
                "policy": loaded.policy.model_dump(mode="json"),
            }
        )

    @app.post("/authorize")
    async def authorize(
        request: Request,
        wait: bool = Query(False, description="block until a human resolves it"),
        timeout: float | None = Query(None, gt=0, le=3600),
    ) -> Response:
        """Authorize a payment intent supplied as a JSON body."""
        body = await request.body()
        if len(body) > MAX_BODY_BYTES:
            return JSONResponse(
                status_code=413,
                content={"error": f"body exceeds {MAX_BODY_BYTES} bytes"},
            )

        ctx = RequestContext(
            method="POST",
            url=request.headers.get("x-bouncer-target-url", ""),
            body=body,
            agent_id=request.headers.get("x-bouncer-agent", "unknown"),
            headers=dict(request.headers),
        )
        return await _authorize_ctx(ctx, wait=wait, timeout=timeout)

    @app.post("/authorize/raw")
    async def authorize_raw(
        traffic: RawTraffic,
        wait: bool = Query(False),
        timeout: float | None = Query(None, gt=0, le=3600),
    ) -> Response:
        """Authorize traffic described explicitly, for rails like Stripe."""
        ctx = RequestContext(
            method=traffic.method,
            url=traffic.url,
            body=traffic.body.encode("utf-8"),
            agent_id=traffic.agent_id,
            status_code=traffic.status_code,
            headers=traffic.headers,
        )
        return await _authorize_ctx(ctx, wait=wait, timeout=timeout)

    async def _authorize_ctx(
        ctx: RequestContext, *, wait: bool, timeout: float | None
    ) -> Response:
        try:
            intent = parse_intent(ctx)
        except UnparseableIntent as exc:
            # Denied and logged — never passed through unexamined.
            placeholder = PaymentIntent(
                agent_id=ctx.agent_id or "unknown",
                merchant=ctx.host or "unknown",
                amount=Decimal(0),
                currency="XXX",
                rail="unparsed",
                description=f"{ctx.method} {ctx.url}"[:512] or None,
            )
            return _respond(engine.deny_unparseable(exc, placeholder))

        if wait:
            return _respond(await engine.authorize_blocking(intent, timeout=timeout))
        return _respond(engine.authorize(intent))

    @app.post("/mandates/verify")
    def verify(request: VerifyMandateRequest) -> JSONResponse:
        """Verify a mandate. Any downstream service can call this."""
        amount: Decimal | None = None
        if request.amount is not None:
            try:
                amount = Decimal(request.amount)
            except InvalidOperation:
                return JSONResponse(
                    status_code=400, content={"valid": False, "error": "invalid amount"}
                )
        try:
            claims = verify_mandate(
                request.mandate,
                engine.key.verify_key,
                # The enforcer's clock, not the wall clock: the service must
                # have exactly one notion of "now", or a mandate can be minted
                # and judged against two different times.
                now=engine.now(),
                nonce_store=engine.nonces,
                expected_merchant=request.merchant,
                expected_agent_id=request.agent_id,
                amount=amount,
                consume=request.consume,
            )
        except MandateError as exc:
            return JSONResponse(
                status_code=403,
                content={
                    "valid": False,
                    "error": str(exc),
                    "error_type": type(exc).__name__,
                },
            )
        return JSONResponse(
            content={"valid": True, "claims": claims.model_dump(mode="json")}
        )

    @app.get("/pending")
    def pending(role: str | None = None) -> dict[str, Any]:
        """List approvals awaiting a human. Resolution happens via the CLI."""
        items = engine.approvals.list(role=role)
        return {"count": len(items), "items": [item.to_dict() for item in items]}

    @app.get("/audit/verify")
    def audit_verify(expect_head: str | None = None) -> JSONResponse:
        result = engine.audit.verify(expect_head=expect_head)
        return JSONResponse(
            status_code=200 if result.ok else 409,
            content={
                "ok": result.ok,
                "entries_checked": result.entries_checked,
                "head_hash": result.head_hash,
                "broken_seq": result.broken_seq,
                "problem": result.problem,
            },
        )

    return app
