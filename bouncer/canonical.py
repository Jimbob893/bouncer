"""Canonical serialization.

Threat model: every hash and every signature in bouncer is taken over the bytes
produced by this module. If two structurally-identical records can serialize to
different bytes, the audit chain produces false tamper alarms; if two
*different* records can serialize to the same bytes, tampering becomes
invisible. Both are security failures, so the rules here are deliberately rigid
rather than permissive:

- Object keys are sorted; only ``str`` keys are accepted.
- Separators are fixed and whitespace-free, so formatting cannot vary.
- ``Decimal`` is emitted as a normalized string, never as a JSON number.
- ``float`` is rejected outright. Binary floating point cannot represent most
  monetary values exactly, so a float in a signed record means the number that
  was signed is not the number that was intended. Amounts reach this module as
  ``Decimal`` or they do not reach it at all.
- ``datetime`` must be timezone-aware and is emitted as UTC with fixed-width
  microseconds, so the same instant always yields the same string.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from datetime import date, datetime, time, timezone
from decimal import Decimal
from enum import Enum
from typing import Any

__all__ = [
    "CanonicalizationError",
    "canonical_bytes",
    "canonical_json",
    "money_str",
    "normalize",
    "sha256_hex",
    "utc_iso",
]

#: Serialization settings. Changing any of these invalidates every existing
#: audit chain, so treat them as a wire format, not a style choice.
_JSON_KWARGS: dict[str, Any] = {
    "sort_keys": True,
    "separators": (",", ":"),
    "ensure_ascii": False,
    "allow_nan": False,
}


class CanonicalizationError(TypeError):
    """A value cannot be canonically serialized, so it must not be signed."""


def money_str(value: Decimal) -> str:
    """Render a monetary ``Decimal`` as a stable, exponent-free string.

    ``Decimal("10.50")`` and ``Decimal("10.5")`` are the same amount of money
    and must hash identically, so trailing zeros are stripped. Exponent notation
    (``1E+3``) is expanded, and negative zero is folded to ``"0"``.
    """
    if not value.is_finite():
        raise CanonicalizationError(f"non-finite monetary value: {value!r}")
    normalized = value.normalize()
    if normalized == 0:
        # Decimal("-0.00").normalize() is Decimal("-0"); collapse the sign.
        return "0"
    return format(normalized, "f")


def utc_iso(value: datetime) -> str:
    """Render a timezone-aware datetime as fixed-width UTC ISO-8601."""
    if value.tzinfo is None:
        raise CanonicalizationError(
            "naive datetime cannot be canonicalized; attach a timezone"
        )
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def normalize(value: object) -> Any:
    """Recursively convert ``value`` into JSON-serializable primitives.

    Accepts pydantic models via their ``model_dump`` method without importing
    pydantic, which keeps this module free of dependencies.
    """
    # Enum is checked first: IntEnum and StrEnum are also int/str subclasses,
    # and their declared value is what belongs in the record.
    if isinstance(value, Enum):
        return normalize(value.value)
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        raise CanonicalizationError(
            "float is not canonically serializable; use Decimal for amounts"
        )
    if isinstance(value, Decimal):
        return money_str(value)
    # datetime is a subclass of date, so it must be tested first.
    if isinstance(value, datetime):
        return utc_iso(value)
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, time):
        if value.tzinfo is not None:
            raise CanonicalizationError(
                "time-of-day with an offset is ambiguous; use a named timezone"
            )
        # Fixed width, so 09:00 and 09:00:00 cannot hash differently.
        return value.strftime("%H:%M:%S.%f")
    if isinstance(value, bytes):
        raise CanonicalizationError("bytes must be encoded before serialization")
    dump = getattr(value, "model_dump", None)
    if callable(dump):
        return normalize(dump())
    if isinstance(value, Mapping):
        out: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError(f"non-string object key: {key!r}")
            out[key] = normalize(item)
        return dict(sorted(out.items()))
    if isinstance(value, Sequence):
        return [normalize(item) for item in value]
    if isinstance(value, (set, frozenset)):
        raise CanonicalizationError("sets have no stable order; use a sorted list")
    raise CanonicalizationError(f"unserializable type: {type(value).__name__}")


def canonical_json(value: object) -> str:
    """Serialize ``value`` to its single canonical JSON representation."""
    return json.dumps(normalize(value), **_JSON_KWARGS)


def canonical_bytes(value: object) -> bytes:
    """Canonical JSON as UTF-8 bytes. This is what gets hashed and signed."""
    return canonical_json(value).encode("utf-8")


def sha256_hex(value: object) -> str:
    """SHA-256 of the canonical serialization of ``value``, as lowercase hex."""
    return hashlib.sha256(canonical_bytes(value)).hexdigest()
