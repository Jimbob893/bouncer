"""Where policy comes from.

The engine never reads a file. It consumes a :class:`LoadedPolicy` handed to it
by a :class:`PolicySource`, so a future source (a signed bundle, a control
plane, a git ref) can be dropped in without the engine changing.

Threat model: a source never raises. A source that cannot produce a valid policy
returns one carrying an error, and the engine turns that into a deny. Failing to
load policy must never be indistinguishable from loading a permissive one.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

from .errors import PolicyError
from .policy import Policy, load_policy_file

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

    The only source shipped in v1. Results are cached on the file's
    (mtime, size) so the proxy can reload per request without re-parsing on
    every call, while still picking up edits without a restart.
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path).expanduser()
        self._lock = threading.Lock()
        self._stamp: tuple[float, int] | None = None
        self._cached: LoadedPolicy | None = None

    @property
    def origin(self) -> str:
        return f"file:{self._path}"

    @property
    def path(self) -> Path:
        return self._path

    def load(self) -> LoadedPolicy:
        try:
            stat = self._path.stat()
        except OSError as exc:
            return LoadedPolicy.failed(
                f"policy file unavailable at {self._path}: {exc}", self.origin
            )
        stamp = (stat.st_mtime, stat.st_size)
        with self._lock:
            if self._cached is not None and self._stamp == stamp:
                return self._cached
            try:
                loaded = LoadedPolicy(
                    policy=load_policy_file(self._path), origin=self.origin
                )
            except PolicyError as exc:
                loaded = LoadedPolicy.failed(str(exc), self.origin)
            self._stamp = stamp
            self._cached = loaded
            return loaded

    def invalidate(self) -> None:
        """Drop the cache, forcing a re-read on the next load."""
        with self._lock:
            self._stamp = None
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
