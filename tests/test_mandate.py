"""M3 — signed mandates."""

from __future__ import annotations

import base64
import json
from datetime import timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from bouncer.errors import (
    MandateExpired,
    MandateMalformed,
    MandateReplayed,
    MandateScopeViolation,
    MandateSignatureInvalid,
)
from bouncer.keys import OperatorKey
from bouncer.mandate import (
    MandateClaims,
    DEFAULT_TTL,
    NonceStore,
    decode_unverified,
    issue_mandate,
    verify_mandate,
)

from .conftest import NOW, intent

POLICY_HASH = "a" * 64


@pytest.fixture()
def nonces(tmp_path: Path) -> NonceStore:
    return NonceStore(tmp_path / "nonces.db")


def mint(key: OperatorKey, **overrides: Any) -> tuple[str, MandateClaims]:
    return issue_mandate(intent(**overrides), key, policy_hash=POLICY_HASH, now=NOW)


# ---------------------------------------------------------------------------
# happy path
# ---------------------------------------------------------------------------


def test_issued_mandate_verifies(operator_key: OperatorKey) -> None:
    token, claims = mint(operator_key)
    verified = verify_mandate(token, operator_key, now=NOW)
    assert verified.nonce == claims.nonce
    assert verified.merchant == "api.example.com"
    assert verified.max_amount == Decimal("10.00")


def test_mandate_is_two_base64url_segments(operator_key: OperatorKey) -> None:
    token, _ = mint(operator_key)
    assert token.count(".") == 1
    assert "=" not in token
    assert "+" not in token and "/" not in token


def test_mandate_is_scoped_to_the_intents_merchant_and_amount(
    operator_key: OperatorKey,
) -> None:
    token, _ = mint(operator_key, merchant="shop.example.com", amount=Decimal("25.00"))
    claims = verify_mandate(
        token,
        operator_key,
        now=NOW,
        expected_merchant="shop.example.com",
        amount=Decimal("25.00"),
    )
    assert claims.covers(merchant="shop.example.com", amount=Decimal("25.00"))
    assert not claims.covers(merchant="shop.example.com", amount=Decimal("25.01"))


def test_verification_works_with_only_the_public_key(operator_key: OperatorKey) -> None:
    """A downstream service should never need the signing key."""
    token, _ = mint(operator_key)
    assert verify_mandate(token, operator_key.verify_key, now=NOW) is not None


def test_a_lower_amount_than_the_ceiling_is_covered(operator_key: OperatorKey) -> None:
    token, _ = mint(operator_key, amount=Decimal("100.00"))
    claims = verify_mandate(token, operator_key, now=NOW, amount=Decimal("40.00"))
    assert claims.max_amount == Decimal("100.00")


# ---------------------------------------------------------------------------
# expiry
# ---------------------------------------------------------------------------


def test_expired_mandate_is_rejected(operator_key: OperatorKey) -> None:
    token, _ = mint(operator_key)
    with pytest.raises(MandateExpired):
        verify_mandate(token, operator_key, now=NOW + DEFAULT_TTL + timedelta(seconds=1))


def test_mandate_valid_just_before_expiry(operator_key: OperatorKey) -> None:
    token, _ = mint(operator_key)
    assert verify_mandate(
        token, operator_key, now=NOW + DEFAULT_TTL - timedelta(seconds=1)
    )


def test_expiry_boundary_is_exclusive(operator_key: OperatorKey) -> None:
    """At exactly expires_at the mandate is dead."""
    token, _ = mint(operator_key)
    with pytest.raises(MandateExpired):
        verify_mandate(token, operator_key, now=NOW + DEFAULT_TTL)


def test_custom_ttl_is_honored(operator_key: OperatorKey) -> None:
    token, claims = issue_mandate(
        intent(), operator_key, policy_hash=POLICY_HASH, now=NOW, ttl=timedelta(seconds=30)
    )
    assert claims.expires_at == NOW + timedelta(seconds=30)
    with pytest.raises(MandateExpired):
        verify_mandate(token, operator_key, now=NOW + timedelta(seconds=31))


# ---------------------------------------------------------------------------
# tampering
# ---------------------------------------------------------------------------


def tamper(token: str, **changes: object) -> str:
    """Rewrite claims and re-encode, leaving the original signature in place."""
    payload_b64, signature_b64 = token.split(".")
    padding = "=" * (-len(payload_b64) % 4)
    claims = json.loads(base64.urlsafe_b64decode(payload_b64 + padding))
    claims.update(changes)
    forged = base64.urlsafe_b64encode(
        json.dumps(claims, sort_keys=True, separators=(",", ":")).encode()
    ).rstrip(b"=").decode()
    return f"{forged}.{signature_b64}"


def test_altered_amount_is_rejected(operator_key: OperatorKey) -> None:
    """The headline attack: raise your own spending ceiling."""
    token, _ = mint(operator_key, amount=Decimal("10.00"))
    forged = tamper(token, max_amount="999999.00")
    with pytest.raises(MandateSignatureInvalid):
        verify_mandate(forged, operator_key, now=NOW)


def test_altered_merchant_is_rejected(operator_key: OperatorKey) -> None:
    token, _ = mint(operator_key)
    forged = tamper(token, merchant="attacker.example.com")
    with pytest.raises(MandateSignatureInvalid):
        verify_mandate(forged, operator_key, now=NOW)


def test_extended_expiry_is_rejected(operator_key: OperatorKey) -> None:
    token, _ = mint(operator_key)
    forged = tamper(token, expires_at="2099-01-01T00:00:00.000000Z")
    with pytest.raises(MandateSignatureInvalid):
        verify_mandate(forged, operator_key, now=NOW)


def test_mandate_from_another_key_is_rejected(operator_key: OperatorKey) -> None:
    attacker = OperatorKey.generate()
    token, _ = mint(attacker)
    with pytest.raises(MandateSignatureInvalid):
        verify_mandate(token, operator_key, now=NOW)


@pytest.mark.parametrize(
    "bad_token",
    ["", "notatoken", "only.two.parts.here", "!!!.???", "a.b"],
)
def test_malformed_tokens_are_rejected(operator_key: OperatorKey, bad_token: str) -> None:
    with pytest.raises((MandateMalformed, MandateSignatureInvalid)):
        verify_mandate(bad_token, operator_key, now=NOW)


# ---------------------------------------------------------------------------
# scope
# ---------------------------------------------------------------------------


def test_wrong_merchant_is_a_scope_violation(operator_key: OperatorKey) -> None:
    token, _ = mint(operator_key, merchant="shop.example.com")
    with pytest.raises(MandateScopeViolation, match="scoped to merchant"):
        verify_mandate(
            token, operator_key, now=NOW, expected_merchant="attacker.example.com"
        )


def test_amount_above_the_ceiling_is_a_scope_violation(operator_key: OperatorKey) -> None:
    token, _ = mint(operator_key, amount=Decimal("10.00"))
    with pytest.raises(MandateScopeViolation, match="exceeds the mandate ceiling"):
        verify_mandate(token, operator_key, now=NOW, amount=Decimal("10.01"))


def test_wrong_agent_is_a_scope_violation(operator_key: OperatorKey) -> None:
    token, _ = mint(operator_key, agent_id="research-bot")
    with pytest.raises(MandateScopeViolation, match="issued to agent"):
        verify_mandate(token, operator_key, now=NOW, expected_agent_id="other-bot")


def test_merchant_scope_check_is_case_insensitive(operator_key: OperatorKey) -> None:
    token, _ = mint(operator_key, merchant="shop.example.com")
    assert verify_mandate(
        token, operator_key, now=NOW, expected_merchant="SHOP.Example.com"
    )


# ---------------------------------------------------------------------------
# replay
# ---------------------------------------------------------------------------


def test_replayed_nonce_is_rejected(operator_key: OperatorKey, nonces: NonceStore) -> None:
    token, _ = mint(operator_key)
    assert verify_mandate(token, operator_key, now=NOW, nonce_store=nonces)
    with pytest.raises(MandateReplayed):
        verify_mandate(token, operator_key, now=NOW, nonce_store=nonces)


def test_each_mandate_gets_a_distinct_nonce(operator_key: OperatorKey) -> None:
    nonce_values = {mint(operator_key)[1].nonce for _ in range(50)}
    assert len(nonce_values) == 50


def test_two_mandates_can_both_be_redeemed(
    operator_key: OperatorKey, nonces: NonceStore
) -> None:
    first, _ = mint(operator_key, intent_id="a")
    second, _ = mint(operator_key, intent_id="b")
    assert verify_mandate(first, operator_key, now=NOW, nonce_store=nonces)
    assert verify_mandate(second, operator_key, now=NOW, nonce_store=nonces)
    assert nonces.count() == 2


def test_inspection_without_consuming_leaves_the_nonce_unspent(
    operator_key: OperatorKey, nonces: NonceStore
) -> None:
    token, claims = mint(operator_key)
    verify_mandate(token, operator_key, now=NOW, nonce_store=nonces, consume=False)
    assert not nonces.seen(claims.nonce)
    assert verify_mandate(token, operator_key, now=NOW, nonce_store=nonces)


def test_a_failed_check_does_not_burn_the_nonce(
    operator_key: OperatorKey, nonces: NonceStore
) -> None:
    """A scope violation must not lock out the legitimate redemption."""
    token, _ = mint(operator_key, amount=Decimal("10.00"))
    with pytest.raises(MandateScopeViolation):
        verify_mandate(
            token, operator_key, now=NOW, nonce_store=nonces, amount=Decimal("500.00")
        )
    assert nonces.count() == 0
    assert verify_mandate(token, operator_key, now=NOW, nonce_store=nonces)


def test_expired_mandate_does_not_burn_a_nonce(
    operator_key: OperatorKey, nonces: NonceStore
) -> None:
    token, _ = mint(operator_key)
    with pytest.raises(MandateExpired):
        verify_mandate(
            token, operator_key, now=NOW + timedelta(hours=1), nonce_store=nonces
        )
    assert nonces.count() == 0


def test_purge_removes_only_expired_nonces(
    operator_key: OperatorKey, nonces: NonceStore
) -> None:
    live, _ = issue_mandate(
        intent(intent_id="live"), operator_key, policy_hash=POLICY_HASH,
        now=NOW, ttl=timedelta(hours=2),
    )
    stale, _ = issue_mandate(
        intent(intent_id="stale"), operator_key, policy_hash=POLICY_HASH,
        now=NOW, ttl=timedelta(minutes=1),
    )
    verify_mandate(live, operator_key, now=NOW, nonce_store=nonces)
    verify_mandate(stale, operator_key, now=NOW, nonce_store=nonces)
    assert nonces.count() == 2

    removed = nonces.purge_expired(now=NOW + timedelta(minutes=30))
    assert removed == 1
    assert nonces.count() == 1


# ---------------------------------------------------------------------------
# misc
# ---------------------------------------------------------------------------


def test_decode_unverified_does_not_validate(operator_key: OperatorKey) -> None:
    token, _ = mint(operator_key)
    forged = tamper(token, max_amount="999999.00")
    peeked = decode_unverified(forged)
    assert peeked["max_amount"] == "999999.00"
    with pytest.raises(MandateSignatureInvalid):
        verify_mandate(forged, operator_key, now=NOW)


def test_naive_now_is_rejected(operator_key: OperatorKey) -> None:
    token, _ = mint(operator_key)
    with pytest.raises(ValueError, match="timezone-aware"):
        verify_mandate(token, operator_key, now=NOW.replace(tzinfo=None))
