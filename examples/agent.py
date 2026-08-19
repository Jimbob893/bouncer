"""A toy agent with a $50 budget that keeps spending until bouncer stops it.

Run it:

    python examples/agent.py

This is the client library rather than the CLI. The point it demonstrates is
the shape of the API: a denial *raises*, so the body of the ``with`` block
never runs. There is no return value to forget to check, which means there is
no way to accidentally spend through a refusal.

Everything happens in a throwaway directory, so your real ~/.bouncer is never
touched.
"""

from __future__ import annotations

import shutil
import sys
import tempfile
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from bouncer import ApprovalRequired, Client, SpendDenied  # noqa: E402

# A genuine budget: 50.00 total across a rolling 30-day window, not a
# per-transaction cap. The agent below will walk straight into it.
POLICY = """
version: 1
currency: USD
agents:
  research-bot:
    per_transaction_cap: 20.00
    rolling_windows:
      - amount: 50.00
        window: 30d
    merchants:
      allow: ["api.weather.example", "api.data-vendor.example"]
    approval_required_above:
      amount: 15.00
      approver_role: finance
"""

#: What the agent tries to buy, in order.
#:
#: One purchase is above the approval threshold and gets held for a human --
#: note that it does *not* count against the budget, because nothing was
#: committed. The rest commit, and the fifth one crosses the 50.00 ceiling.
SHOPPING_LIST = [
    ("api.weather.example", "14.00", "forecast data"),
    ("api.data-vendor.example", "18.00", "market snapshot"),
    ("api.weather.example", "15.00", "historical series"),
    ("api.data-vendor.example", "12.00", "sentiment feed"),
    ("api.weather.example", "13.00", "radar tiles"),
]


def build_client(home: Path) -> Client:
    """One call: key, audit log, nonce store and approval queue, all wired.

    ``state_dir`` is a throwaway directory here so the example leaves nothing
    behind. A real deployment points it at somewhere persistent -- the audit
    log is where rolling-window ceilings are computed from, so discarding it
    resets an agent's spent-to-date.
    """
    return Client.from_policy(POLICY, agent_id="research-bot", state_dir=home)


def call_the_payment_rail(mandate: str) -> None:
    """Stand-in for whatever actually moves the money.

    bouncer never does this part. It hands you a signed mandate; settling the
    payment is your code's job, and the mandate is what proves the payment was
    authorized.
    """
    print("       paid. mandate {}...".format(mandate[:32]))


def main() -> int:
    home = Path(tempfile.mkdtemp())
    try:
        client = build_client(home)

        print("agent 'research-bot' has a 50.00 budget over 30 days")
        print("  per transaction:   20.00 cap")
        print("  needs a human:     above 15.00")
        print()

        spent = Decimal(0)
        blocked_at: str | None = None

        for merchant, amount, what in SHOPPING_LIST:
            print("-> buying {} from {} for ${}".format(what, merchant, amount))
            try:
                with client.spend(merchant=merchant, amount=amount) as ok:
                    # Only reachable when bouncer allowed the payment.
                    call_the_payment_rail(ok.mandate)
                    spent += ok.amount
                    print("       running total: ${}".format(spent))

            except ApprovalRequired as pending:
                print("       HELD for a human: {}".format(pending.decision.reason))
                print("       queued as {}".format(pending.pending_id))

            except SpendDenied as refused:
                print("       BLOCKED: {}".format(refused.decision.reason))
                print("       rule: {}".format(refused.decision.rule))
                blocked_at = amount
                break

            print()

        print()
        if blocked_at is not None:
            print("The agent tried to spend ${} and was stopped.".format(blocked_at))
            print("It spent ${} in total, against a 50.00 ceiling.".format(spent))
        else:
            print("The agent finished its list having spent ${}.".format(spent))

        print()
        print("Nothing above trusted the agent to behave. Every attempt, allowed")
        print("or refused, is now a signed row in the audit log:")
        verification = client.enforcer.audit.verify()
        print("  {}".format(verification.describe()))
        return 0
    finally:
        shutil.rmtree(home, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
