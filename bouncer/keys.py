"""Operator key management (Ed25519).

Threat model: the operator key signs audit entries and mandates. What a valid
signature proves is narrow and worth stating precisely:

- It proves a record was produced by a holder of this key and has not been
  altered *since it was written*.
- It proves nothing about whether the decision was correct, and nothing about
  an operator who was already compromised at the moment of writing. An attacker
  who holds the key can write a consistent, correctly-signed history.

The private key is written with mode 0600 and never leaves this process.
"""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .errors import BouncerError

__all__ = ["KeyError_", "OperatorKey", "VerifyKey", "key_id_for"]


class KeyError_(BouncerError):
    """The operator key is missing, malformed, or unreadable."""


def key_id_for(public_key: Ed25519PublicKey) -> str:
    """A short, stable fingerprint of a public key.

    Recorded on every audit row so a log signed under a rotated key can still
    be attributed to the key that signed it.
    """
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(raw).hexdigest()[:16]


class VerifyKey:
    """The public half. Enough to verify, never enough to sign."""

    def __init__(self, public_key: Ed25519PublicKey) -> None:
        self._public = public_key

    @classmethod
    def from_pem(cls, pem: bytes) -> VerifyKey:
        try:
            loaded = serialization.load_pem_public_key(pem)
        except (ValueError, TypeError) as exc:
            raise KeyError_(f"not a valid PEM public key: {exc}") from exc
        if not isinstance(loaded, Ed25519PublicKey):
            raise KeyError_("public key is not Ed25519")
        return cls(loaded)

    @classmethod
    def from_file(cls, path: str | Path) -> VerifyKey:
        try:
            return cls.from_pem(Path(path).read_bytes())
        except OSError as exc:
            raise KeyError_(f"cannot read public key at {path}: {exc}") from exc

    @property
    def key_id(self) -> str:
        return key_id_for(self._public)

    def to_pem(self) -> bytes:
        return self._public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def verify(self, signature: bytes, message: bytes) -> bool:
        """Constant-time signature check. Returns False rather than raising."""
        try:
            self._public.verify(signature, message)
        except InvalidSignature:
            return False
        return True


class OperatorKey:
    """The signing key held by the single trusted operator."""

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._private = private_key

    # -- lifecycle --------------------------------------------------------

    @classmethod
    def generate(cls, path: str | Path | None = None) -> OperatorKey:
        """Create a new key, writing it to ``path`` with mode 0600 if given."""
        key = cls(Ed25519PrivateKey.generate())
        if path is not None:
            key.save(path)
        return key

    @classmethod
    def load(cls, path: str | Path) -> OperatorKey:
        file_path = Path(path).expanduser()
        try:
            pem = file_path.read_bytes()
        except OSError as exc:
            raise KeyError_(
                f"cannot read operator key at {file_path}: {exc}; "
                "run `bouncer keygen` to create one"
            ) from exc
        cls._warn_if_world_readable(file_path)
        try:
            loaded = serialization.load_pem_private_key(pem, password=None)
        except (ValueError, TypeError) as exc:
            raise KeyError_(f"not a valid PEM private key: {exc}") from exc
        if not isinstance(loaded, Ed25519PrivateKey):
            raise KeyError_("operator key is not Ed25519")
        return cls(loaded)

    @classmethod
    def load_or_generate(cls, path: str | Path) -> OperatorKey:
        file_path = Path(path).expanduser()
        if file_path.exists():
            return cls.load(file_path)
        return cls.generate(file_path)

    def save(self, path: str | Path) -> Path:
        """Write the private key as PEM with restrictive permissions."""
        file_path = Path(path).expanduser()
        file_path.parent.mkdir(parents=True, exist_ok=True)
        pem = self._private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        # Create with 0600 from the outset rather than chmod-ing afterwards,
        # which would leave a window where the key is world-readable.
        descriptor = os.open(
            file_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR
        )
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(pem)
        return file_path

    @staticmethod
    def _warn_if_world_readable(path: Path) -> None:
        try:
            mode = path.stat().st_mode
        except OSError:  # pragma: no cover - stat succeeded moments earlier
            return
        if mode & (stat.S_IRGRP | stat.S_IROTH):
            import warnings

            warnings.warn(
                f"operator key {path} is readable by other users (mode "
                f"{stat.filemode(mode)}); anyone who can read it can forge "
                "audit entries and mandates",
                stacklevel=3,
            )

    # -- use --------------------------------------------------------------

    @property
    def key_id(self) -> str:
        return key_id_for(self._private.public_key())

    @property
    def verify_key(self) -> VerifyKey:
        return VerifyKey(self._private.public_key())

    def public_pem(self) -> bytes:
        return self.verify_key.to_pem()

    def sign(self, message: bytes) -> bytes:
        return self._private.sign(message)

    def verify(self, signature: bytes, message: bytes) -> bool:
        return self.verify_key.verify(signature, message)
