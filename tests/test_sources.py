"""Where policy comes from.

Threat model: a source that misses an edit keeps the *previous* policy in
force, and the previous policy is usually the looser one. Every test here is
about that failure direction.
"""

from __future__ import annotations

import os
from pathlib import Path

from bouncer.sources import LocalFileSource, StaticSource

LOOSE = "version: 1\ncurrency: USD\nagents:\n  bot:\n    per_transaction_cap: 90.00\n"
TIGHT = "version: 1\ncurrency: USD\nagents:\n  bot:\n    per_transaction_cap: 10.00\n"


def cap(source: LocalFileSource) -> str:
    loaded = source.load()
    assert loaded.policy is not None
    return str(loaded.policy.agents["bot"].per_transaction_cap)


def test_an_edit_that_preserves_size_and_mtime_is_still_seen(tmp_path: Path) -> None:
    """The cache used to key on (mtime, size).

    A same-length edit whose timestamp is preserved -- by a coarse filesystem,
    an rsync --times, a backup restore or a config-management tool -- left the
    engine enforcing the old, looser policy indefinitely.
    """
    policy = tmp_path / "policy.yaml"
    policy.write_text(LOOSE, encoding="utf-8")
    stat = policy.stat()
    source = LocalFileSource(policy)
    assert cap(source) == "90.00"

    assert len(LOOSE) == len(TIGHT), "the point of the test is an identical size"
    policy.write_text(TIGHT, encoding="utf-8")
    os.utime(policy, ns=(stat.st_atime_ns, stat.st_mtime_ns))

    assert cap(source) == "10.00", "a tightened policy must take effect"


def test_an_ordinary_edit_is_seen(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text(LOOSE, encoding="utf-8")
    source = LocalFileSource(policy)
    assert cap(source) == "90.00"
    policy.write_text(TIGHT, encoding="utf-8")
    assert cap(source) == "10.00"


def test_an_unchanged_file_reuses_the_parse(tmp_path: Path) -> None:
    """The cache still exists; identical content must not be re-parsed."""
    policy = tmp_path / "policy.yaml"
    policy.write_text(LOOSE, encoding="utf-8")
    source = LocalFileSource(policy)
    assert source.load() is source.load()


def test_a_missing_file_denies_rather_than_raising(tmp_path: Path) -> None:
    loaded = LocalFileSource(tmp_path / "absent.yaml").load()
    assert not loaded.ok
    assert loaded.error is not None
    assert loaded.policy_hash == "0" * 64


def test_malformed_yaml_denies_rather_than_raising(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text("this is not: [valid yaml\n", encoding="utf-8")
    loaded = LocalFileSource(policy).load()
    assert not loaded.ok
    assert loaded.error is not None


def test_non_utf8_denies_rather_than_raising(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_bytes(b"\xff\xfe version: 1\n")
    loaded = LocalFileSource(policy).load()
    assert not loaded.ok
    assert loaded.error is not None


def test_invalidate_forces_a_reparse(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text(LOOSE, encoding="utf-8")
    source = LocalFileSource(policy)
    first = source.load()
    source.invalidate()
    assert source.load() is not first


def test_static_source_never_raises() -> None:
    loaded = StaticSource(None, error="deliberately broken").load()
    assert not loaded.ok
    assert loaded.error == "deliberately broken"
