"""An agent paying through Stripe, with bouncer in front of it.

Run it:

    python examples/stripe_agent.py

    # to actually reach Stripe's test API, first:
    #   PowerShell:  $env:STRIPE_API_KEY = "sk_test_..."
    #   bash:        export STRIPE_API_KEY=sk_test_...

Without a key it still runs every decision for real and simply skips the
outbound HTTP call, saying so. With one, an allowed payment is genuinely
created in your Stripe *test* account and a blocked one never leaves the
machine.

What this demonstrates that the other examples do not: bouncer reading a real
payment rail's own wire format. The agent builds the exact form body the Stripe
SDK sends, and the `stripe` adapter pulls the amount, currency and destination
out of it. Nothing here teaches bouncer about dollars twice -- the adapter is
the only thing that knows Stripe quotes amounts in minor units.

**Test mode only.** The adapter refuses live keys by design; the last scenario
below shows that happening. bouncer has not been security audited and should not
stand between an agent and real money.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from bouncer.adapters import RequestContext, parse_intent  # noqa: E402
from bouncer.approvals import ApprovalQueue  # noqa: E402
from bouncer.audit import AuditLog  # noqa: E402
from bouncer.enforcement import Enforcer  # noqa: E402
from bouncer.errors import UnparseableIntent  # noqa: E402
from bouncer.keys import OperatorKey  # noqa: E402
from bouncer.mandate import NonceStore  # noqa: E402
from bouncer.models import Outcome, PaymentIntent  # noqa: E402
from bouncer.policy import Policy  # noqa: E402
from bouncer.sources import StaticSource  # noqa: E402

STRIPE_URL = "https://api.stripe.com/v1/payment_intents"

POLICY = """
version: 1
currency: USD
agents:
  checkout-agent:
    per_transaction_cap: 100.00
    rolling_windows:
      - amount: 250.00
        window: 30d
"""


def build_enforcer(home: Path) -> Enforcer:
    key = OperatorKey.generate(home / "operator.pem")
    audit = AuditLog(home / "stripe.db", key)
    return Enforcer(
        source=StaticSource(Policy.from_yaml(POLICY)),
        audit=audit,
        key=key,
        nonces=NonceStore(home / "stripe.db", engine=audit.engine),
        approvals=ApprovalQueue(home / "stripe.db", engine=audit.engine),
    )


def stripe_request_body(minor_units: int, description: str) -> str:
    """Exactly what the Stripe SDK puts on the wire for a PaymentIntent."""
    return urllib.parse.urlencode(
        {
            "amount": minor_units,
            "currency": "usd",
            "description": description,
            "payment_method_types[]": "card",
        }
    )


def call_stripe(body: str, api_key: str) -> str:
    """Actually create the PaymentIntent. Only reached when bouncer allowed it."""
    request = urllib.request.Request(
        STRIPE_URL,
        data=body.encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            created = json.loads(response.read().decode("utf-8"))
        return f"created {created['id']} ({created['status']})"
    except urllib.error.HTTPError as exc:
        detail = json.loads(exc.read().decode("utf-8")).get("error", {})
        return f"Stripe rejected it: {detail.get('message', exc.reason)}"
    except urllib.error.URLError as exc:
        return f"could not reach Stripe: {exc.reason}"


def attempt(
    enforcer: Enforcer,
    api_key: str | None,
    *,
    label: str,
    minor_units: int,
    key_for_request: str,
) -> None:
    """One agent payment attempt, judged before it is allowed to leave."""
    print(f"\n{label}")
    body = stripe_request_body(minor_units, "agent purchase")

    # The agent's outbound Stripe call, exactly as it would go over the wire.
    context = RequestContext(
        method="POST",
        url=STRIPE_URL,
        body=body.encode("utf-8"),
        agent_id="checkout-agent",
        headers={
            "authorization": f"Bearer {key_for_request}",
            "content-type": "application/x-www-form-urlencoded",
        },
    )

    try:
        intent = parse_intent(context)
    except UnparseableIntent as exc:
        # A refusal to parse is a logged deny, never a pass-through.
        result = enforcer.deny_unparseable(exc, _placeholder(context.agent_id))
        print(f"   bouncer  REFUSED before any policy check")
        print(f"            {exc}")
        print(f"            audit row {result.audit_seq} written")
        return

    print(f"   adapter  read the Stripe body: {intent.amount} {intent.currency}")
    result = enforcer.authorize(intent)

    if result.decision.outcome is not Outcome.ALLOW:
        print(f"   bouncer  {result.decision.outcome.value} -- {result.decision.reason}")
        print("   stripe   never called. the request did not leave this machine.")
        return

    print(f"   bouncer  ALLOW -- mandate {result.mandate[:24] if result.mandate else ''}...")
    if api_key is None:
        print("   stripe   skipped: set STRIPE_API_KEY=sk_test_... to send it for real")
    else:
        print(f"   stripe   {call_stripe(body, api_key)}")


def _placeholder(agent_id: str) -> PaymentIntent:
    """A well-formed stand-in so an unreadable request still gets a logged row."""
    return PaymentIntent(
        agent_id=agent_id,
        merchant="api.stripe.com",
        amount=Decimal(0),
        currency="XXX",
        rail="unparsed",
    )


def main() -> int:
    api_key = os.environ.get("STRIPE_API_KEY")
    if api_key is not None and not api_key.startswith(("sk_test_", "rk_test_")):
        print("STRIPE_API_KEY is not a test-mode key. Refusing to run.")
        print("bouncer is unaudited and must not sit in front of real money.")
        return 1

    print("bouncer in front of Stripe (test mode)")
    print("  policy: at most $100 per payment, $250 per 30 days")
    print(f"  stripe: {'live calls enabled' if api_key else 'no STRIPE_API_KEY set - decisions only'}")

    home = Path(tempfile.mkdtemp())
    try:
        enforcer = build_enforcer(home)
        test_key = api_key or "sk_test_placeholder"

        attempt(enforcer, api_key, label="1. agent buys $20.00 of credits",
                minor_units=2000, key_for_request=test_key)
        attempt(enforcer, api_key, label="2. agent buys $800.00 -- over the cap",
                minor_units=80000, key_for_request=test_key)
        attempt(enforcer, api_key, label="3. agent retries $20.00 with a LIVE key",
                minor_units=2000, key_for_request="sk_live_realmoney")

        print(f"\n{enforcer.audit.verify().describe()}")
    finally:
        shutil.rmtree(home, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
