"""M4 — payment-rail adapters."""

from __future__ import annotations

import json
from decimal import Decimal

import pytest

from bouncer.adapters import DEFAULT_ADAPTERS, RequestContext, parse_intent
from bouncer.adapters.stripe import StripeAdapter
from bouncer.adapters.x402 import X402Adapter
from bouncer.errors import UnparseableIntent

# ---------------------------------------------------------------------------
# generic
# ---------------------------------------------------------------------------


def test_generic_intent_round_trips() -> None:
    ctx = RequestContext(
        body=json.dumps(
            {
                "agent_id": "research-bot",
                "merchant": "api.example.com",
                "amount": "12.50",
                "currency": "usd",
                "category": "API_CREDITS",
            }
        ).encode(),
        agent_id="header-agent",
    )
    intent = parse_intent(ctx)
    assert intent.rail == "generic"
    assert intent.agent_id == "research-bot"
    assert intent.amount == Decimal("12.50")
    assert intent.currency == "USD"
    assert intent.category == "api_credits"


def test_generic_falls_back_to_the_context_agent() -> None:
    ctx = RequestContext(
        body=json.dumps({"merchant": "api.example.com", "amount": "1.00"}).encode(),
        agent_id="from-header",
    )
    assert parse_intent(ctx).agent_id == "from-header"


def test_generic_json_float_amount_is_exact() -> None:
    """10.10 as a JSON number must not authorize 10.099999999999999."""
    ctx = RequestContext(
        body=b'{"merchant": "api.example.com", "amount": 10.10}', agent_id="bot"
    )
    assert parse_intent(ctx).amount == Decimal("10.10")


def test_generic_rejects_a_non_numeric_amount() -> None:
    ctx = RequestContext(
        body=b'{"merchant": "api.example.com", "amount": "lots"}', agent_id="bot"
    )
    with pytest.raises(UnparseableIntent, match="not a number"):
        parse_intent(ctx)


# ---------------------------------------------------------------------------
# x402
# ---------------------------------------------------------------------------


def x402_body(**overrides: object) -> bytes:
    offer = {
        "scheme": "exact",
        "network": "base-sepolia",
        "maxAmountRequired": "10000",
        "resource": "https://api.weather.example/forecast",
        "description": "One forecast call",
        "payTo": "0xabc",
        "asset": "0xdef",
        "extra": {"name": "USDC", "decimals": 6},
    }
    offer.update(overrides)
    return json.dumps({"x402Version": 1, "accepts": [offer]}).encode()


def test_x402_challenge_becomes_an_intent() -> None:
    ctx = RequestContext(status_code=402, body=x402_body(), agent_id="research-bot")
    intent = parse_intent(ctx)
    assert intent.rail == "x402"
    assert intent.merchant == "api.weather.example"
    assert intent.amount == Decimal("0.01")  # 10000 atomic units at 6 decimals
    assert intent.currency == "USDC"
    assert intent.metadata["network"] == "base-sepolia"


def test_x402_scales_by_the_declared_decimals() -> None:
    ctx = RequestContext(
        status_code=402,
        body=x402_body(maxAmountRequired="5000000000000000000",
                       extra={"name": "DAI", "decimals": 18}),
        agent_id="bot",
    )
    assert parse_intent(ctx).amount == Decimal("5")


def test_x402_uses_known_decimals_when_extra_omits_them() -> None:
    ctx = RequestContext(
        status_code=402,
        body=x402_body(maxAmountRequired="2500000", extra={"name": "USDC"}),
        agent_id="bot",
    )
    assert parse_intent(ctx).amount == Decimal("2.5")


def test_x402_refuses_to_guess_an_unknown_assets_scale() -> None:
    """Guessing wrong here is a factor-of-a-million error."""
    ctx = RequestContext(
        status_code=402,
        body=x402_body(extra={"name": "WEIRDCOIN"}),
        agent_id="bot",
    )
    with pytest.raises(UnparseableIntent, match="decimals"):
        parse_intent(ctx)


def test_x402_without_accepts_is_refused() -> None:
    ctx = RequestContext(
        status_code=402, body=b'{"x402Version": 1, "accepts": []}', agent_id="bot"
    )
    with pytest.raises(UnparseableIntent, match="accepts"):
        parse_intent(ctx)


def test_x402_currency_is_not_silently_mapped_to_usd() -> None:
    """USDC is not USD. Treating them as equal needs a rate we refuse to fetch."""
    ctx = RequestContext(status_code=402, body=x402_body(), agent_id="bot")
    assert parse_intent(ctx).currency == "USDC"


# ---------------------------------------------------------------------------
# stripe
# ---------------------------------------------------------------------------

TEST_AUTH = {"authorization": "Bearer sk_test_abc123"}
STRIPE_URL = "https://api.stripe.com/v1/payment_intents"


def test_stripe_payment_intent_is_parsed() -> None:
    ctx = RequestContext(
        method="POST",
        url=STRIPE_URL,
        body=b"amount=2000&currency=usd&description=Widgets",
        headers=TEST_AUTH,
        agent_id="research-bot",
    )
    intent = parse_intent(ctx)
    assert intent.rail == "stripe"
    assert intent.amount == Decimal("20.00")
    assert intent.currency == "USD"
    assert intent.description == "Widgets"
    assert intent.metadata["stripe_amount_minor"] == "2000"


def test_stripe_zero_decimal_currency_is_not_divided() -> None:
    """2000 JPY is ¥2000, not ¥20."""
    ctx = RequestContext(
        url=STRIPE_URL, body=b"amount=2000&currency=jpy", headers=TEST_AUTH, agent_id="bot"
    )
    assert parse_intent(ctx).amount == Decimal("2000")


def test_stripe_three_decimal_currency() -> None:
    ctx = RequestContext(
        url=STRIPE_URL, body=b"amount=2000&currency=kwd", headers=TEST_AUTH, agent_id="bot"
    )
    assert parse_intent(ctx).amount == Decimal("2")


def test_stripe_connect_destination_becomes_the_merchant() -> None:
    ctx = RequestContext(
        url=STRIPE_URL,
        body=b"amount=500&currency=usd&transfer_data%5Bdestination%5D=acct_123",
        headers=TEST_AUTH,
        agent_id="bot",
    )
    assert parse_intent(ctx).merchant == "acct_123"


def test_stripe_live_key_is_refused() -> None:
    """bouncer v1 has not been audited; it does not stand between an agent
    and real money."""
    ctx = RequestContext(
        url=STRIPE_URL,
        body=b"amount=2000&currency=usd",
        headers={"authorization": "Bearer sk_live_realmoney"},
        agent_id="bot",
    )
    with pytest.raises(UnparseableIntent, match="live-mode"):
        parse_intent(ctx)


def test_stripe_missing_key_is_refused() -> None:
    ctx = RequestContext(
        url=STRIPE_URL, body=b"amount=2000&currency=usd", agent_id="bot"
    )
    with pytest.raises(UnparseableIntent, match="no API key"):
        parse_intent(ctx)


def test_stripe_basic_auth_test_key_is_accepted() -> None:
    import base64

    encoded = base64.b64encode(b"sk_test_abc:").decode()
    ctx = RequestContext(
        url=STRIPE_URL,
        body=b"amount=1000&currency=usd",
        headers={"authorization": f"Basic {encoded}"},
        agent_id="bot",
    )
    assert parse_intent(ctx).amount == Decimal("10.00")


def test_stripe_metadata_is_carried_through() -> None:
    ctx = RequestContext(
        url=STRIPE_URL,
        body=b"amount=1000&currency=usd&metadata%5Bcategory%5D=software",
        headers=TEST_AUTH,
        agent_id="bot",
    )
    intent = parse_intent(ctx)
    assert intent.category == "software"


def test_stripe_adapter_ignores_non_stripe_hosts() -> None:
    ctx = RequestContext(url="https://example.com/v1/payment_intents", agent_id="bot")
    assert not StripeAdapter().matches(ctx)


# ---------------------------------------------------------------------------
# dispatch
# ---------------------------------------------------------------------------


def test_unrecognized_traffic_raises_rather_than_passing_through() -> None:
    ctx = RequestContext(
        method="GET", url="https://example.com/hello", body=b"", agent_id="bot"
    )
    with pytest.raises(UnparseableIntent, match="no adapter recognized"):
        parse_intent(ctx)


def test_stripe_wins_over_generic_for_stripe_traffic() -> None:
    """Ordering matters: a Stripe form body must not fall through to generic."""
    ctx = RequestContext(
        url=STRIPE_URL,
        body=b"amount=2000&currency=usd",
        headers=TEST_AUTH,
        agent_id="bot",
    )
    assert parse_intent(ctx).rail == "stripe"


def test_x402_wins_over_generic_for_402_bodies() -> None:
    ctx = RequestContext(status_code=402, body=x402_body(), agent_id="bot")
    assert parse_intent(ctx).rail == "x402"


def test_every_default_adapter_declares_a_name() -> None:
    names = [adapter.name for adapter in DEFAULT_ADAPTERS]
    assert names == ["stripe", "x402", "generic"]
    assert len(set(names)) == len(names)


def test_header_lookup_is_case_insensitive() -> None:
    """A differently-cased header must not bypass the live-key check."""
    ctx = RequestContext(
        url=STRIPE_URL,
        body=b"amount=2000&currency=usd",
        headers={"AuThOrIzAtIoN": "Bearer sk_live_x"},
        agent_id="bot",
    )
    with pytest.raises(UnparseableIntent, match="live-mode"):
        parse_intent(ctx)
