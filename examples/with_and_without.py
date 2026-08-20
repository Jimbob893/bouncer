"""The same buggy agent, run twice: once without bouncer, once with it.

Run it:

    python examples/with_and_without.py

There is no policy engine in the first run and nothing else differs, so the
$240 gap between them is the entire product. Everything happens against a
throwaway directory and a pretend card; no real money is involved anywhere.
"""

from __future__ import annotations

import shutil
import sys
import tempfile
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from bouncer import Client, SpendDenied  # noqa: E402

#: Two rules, in the language an operator actually writes.
POLICY = """
version: 1
currency: USD
agents:
  shopping-agent:
    per_transaction_cap: 50.00
    rolling_windows:
      - amount: 100.00
        window: 30d
"""

#: A stuck agent. It has decided it needs more data and will not stop asking.
PURCHASES = [("web scraping credits", "40.00")] * 8

RULE = "=" * 64


class Card:
    """Stands in for whatever actually holds the money."""

    def __init__(self, balance: str) -> None:
        self.start = Decimal(balance)
        self.balance = Decimal(balance)

    def charge(self, amount: str, what: str) -> None:
        self.balance -= Decimal(amount)
        print(f"      CHARGED ${amount} for {what}. balance now ${self.balance}")

    @property
    def spent(self) -> Decimal:
        return self.start - self.balance


def without_bouncer() -> Decimal:
    print(RULE)
    print("RUN 1  -  the agent holds the card. no policy layer.")
    print(RULE)
    card = Card("1000.00")
    for what, amount in PURCHASES:
        print(f"  agent: I need {what}, buying ${amount}")
        card.charge(amount, what)  # nothing stands between the agent and the card
    print(f"\n  RESULT: spent ${card.spent} in a single loop, unopposed.")
    print("  Nothing refused it. You find out when the statement arrives.\n")
    return card.spent


def with_bouncer(home: Path) -> Decimal:
    print(RULE)
    print("RUN 2  -  same agent, same bug. bouncer checks each payment.")
    print(RULE)
    print("  the rules:  at most $50 per purchase, at most $100 per 30 days\n")

    client = Client.from_policy(POLICY, agent_id="shopping-agent", state_dir=home)
    card = Card("1000.00")

    for what, amount in PURCHASES:
        print(f"  agent: I need {what}, buying ${amount}")
        try:
            with client.spend(merchant="api.scraper.example", amount=amount):
                # Reached only when bouncer allowed the payment. A refusal
                # raises, so this line cannot run by accident.
                card.charge(amount, what)
        except SpendDenied as refused:
            print(f"      REFUSED. {refused.decision.reason}")
            print(f"      the charge never happened. balance still ${card.balance}")
            break

    print(f"\n  RESULT: spent ${card.spent}, then stopped.")
    print("  Every attempt above -- allowed and refused -- is a signed row:")
    print(f"  {client.enforcer.audit.verify().describe()}\n")
    return card.spent


def main() -> int:
    home = Path(tempfile.mkdtemp())
    try:
        loose = without_bouncer()
        guarded = with_bouncer(home)
    finally:
        shutil.rmtree(home, ignore_errors=True)

    print(RULE)
    print(f"  without bouncer: ${loose}")
    print(f"  with bouncer:    ${guarded}")
    print(f"  difference:      ${loose - guarded} that the agent could not spend")
    print(RULE)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
