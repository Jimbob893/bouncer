"""Exception hierarchy.

Every error that can reach a caller descends from :class:`BouncerError`, so an
embedding application can catch one type and fail closed.
"""

from __future__ import annotations

__all__ = [
    "AdapterError",
    "ApprovalError",
    "AuditError",
    "BouncerError",
    "MandateError",
    "MandateExpired",
    "MandateMalformed",
    "MandateReplayed",
    "MandateScopeViolation",
    "MandateSignatureInvalid",
    "PolicyError",
    "RoleMismatch",
    "UnknownApproval",
    "UnparseableIntent",
]


class BouncerError(Exception):
    """Base class for every error bouncer raises."""


class PolicyError(BouncerError):
    """A policy file is missing, unreadable, or does not satisfy the schema."""


class AuditError(BouncerError):
    """The audit log could not be written or read consistently."""


class AdapterError(BouncerError):
    """Base class for payment-rail adapter failures."""


class UnparseableIntent(AdapterError):
    """No adapter could turn this traffic into a :class:`PaymentIntent`.

    Threat model: this is a *deny* condition, never a pass-through. Traffic
    bouncer cannot read is traffic bouncer cannot authorize.
    """


class MandateError(BouncerError):
    """Base class for mandate verification failures."""


class MandateMalformed(MandateError):
    """The token is not a well-formed mandate."""


class MandateSignatureInvalid(MandateError):
    """The signature does not match the payload under the operator key."""


class MandateExpired(MandateError):
    """The mandate's time-to-live has elapsed."""


class MandateReplayed(MandateError):
    """This mandate's nonce has already been consumed."""


class MandateScopeViolation(MandateError):
    """The mandate is valid but does not cover the transaction presented."""


class ApprovalError(BouncerError):
    """Base class for approval-queue failures."""


class UnknownApproval(ApprovalError):
    """No pending approval with the given id."""


class RoleMismatch(ApprovalError):
    """The asserted role does not match the role the policy requires.

    Threat model: this is a workflow guardrail, not a security control. The role
    is an assertion by whoever holds shell access, not an authenticated
    identity. See the Threat Model section of the README.
    """
