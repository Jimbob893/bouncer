"""Where policy comes from.

The engine never reads a file. It consumes a :class:`LoadedPolicy` handed to it
by a :class:`PolicySource`, so a future source (a signed bundle, a control
plane, a git ref) can be dropped in without the engine changing.

Threat model: a source never raises. A source that cannot produce a valid policy
returns one carrying an error, and the engine turns that into a deny. Failing to
load policy must never be indistinguishable from loading a permissive one.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

from .errors import PolicyError
from .policy import Policy

__all__ = ["LoadedPolicy", "LocalFileSource", "PolicySource", "StaticSource"]

#: Hash reported when no policy could be loaded. Distinct from any real hash and
#: recorded in the audit log so "we denied because policy was missing" is
#: provable after the fact.
NO_POLICY_HASH = "0" * 64


@dataclass(frozen=True)
class LoadedPolicy:
    """A policy, or an explanation of why there isn't one."""

    policy: Policy | None
    error: str | None = None
    origin: str = "unknown"

    @property
    def ok(self) -> bool:
        return self.policy is not None

    @property
    def policy_hash(self) -> str:
        return self.policy.policy_hash if self.policy is not None else NO_POLICY_HASH

    @classmethod
    def failed(cls, error: str, origin: str) -> LoadedPolicy:
        return cls(policy=None, error=error, origin=origin)


@runtime_checkable
class PolicySource(Protocol):
    """A place policy can be loaded from."""

    def load(self) -> LoadedPolicy:
        """Return the current policy. Must not raise."""
        ...

    @property
    def origin(self) -> str:
        """Human-readable description of where policy comes from."""
        ...


class LocalFileSource:
    """Loads policy from a YAML file on the local filesystem.

    The only source shipped in v1. Results are cached on a hash of the file's
    contents, so the proxy can reload per request without re-parsing on every
    call while still picking up any edit without a restart.
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path).expanduser()
        self._lock = threading.Lock()
        self._digest: str | None = None
        self._cached: LoadedPolicy | None = None

    @property
    def origin(self) -> str:
        return f"file:{self._path}"

    @property
    def path(self) -> Path:
        return self._path

    def load(self) -> LoadedPolicy:
        """Read and parse the policy, reusing the last parse when unchanged.

        Threat model: the cache is keyed on a hash of the file's *contents*, not
        on ``(mtime, size)``. An edit that preserves both — a same-length change
        such as a cap going from ``90.00`` to ``10.00``, or any restore that
        keeps timestamps, as ``rsync --times``, backup restores and
        configuration management all do — would otherwise leave the engine
        enforcing the previous policy indefinitely. Since the stale copy is
        typically the *looser* one, that fails open.

        Reading the file every time is cheap; parsing and validating the YAML is
        the expensive part, and that is what the cache still skips.
        """
        try:
            raw = self._path.read_bytes()
        except OSError as exc:
            return LoadedPolicy.failed(
                f"policy file unavailable at {self._path}: {exc}", self.origin
            )
        digest = hashlib.sha256(raw).hexdigest()
        with self._lock:
            if self._cached is not None and self._digest == digest:
                return self._cached
            try:
                loaded = LoadedPolicy(
                    policy=Policy.from_yaml(raw.decode("utf-8")), origin=self.origin
                )
            except UnicodeDecodeError as exc:
                loaded = LoadedPolicy.failed(
                    f"policy at {self._path} is not valid UTF-8: {exc}", self.origin
                )
            except PolicyError as exc:
                loaded = LoadedPolicy.failed(str(exc), self.origin)
            self._digest = digest
            self._cached = loaded
            return loaded

    def invalidate(self) -> None:
        """Drop the cache, forcing a re-parse on the next load."""
        with self._lock:
            self._digest = None
            self._cached = None


class StaticSource:
    """Wraps an already-constructed policy. Used by tests and embedders."""

    def __init__(self, policy: Policy | None, error: str | None = None) -> None:
        self._loaded = LoadedPolicy(policy=policy, error=error, origin="static")

    @property
    def origin(self) -> str:
        return "static"

    def load(self) -> LoadedPolicy:
        return self._loaded
