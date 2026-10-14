"""Deterministic check-then-use race injection for the descriptor-chain file readers.

`PathSwapper` wraps every path-taking call a reader could make and, right after the k-th call that names
the guarded file or its directory, performs the attacker's swap. A dry run (no swap) enumerates how many
such calls there are; a test then runs the reader once per k. No timing is involved, so the proof cannot
flake: a reader that checks by path and opens by path reads the attacker's file at some k, a reader that
opens relative to the directory descriptor it checked never does.
"""

import builtins
import io
import os
from collections.abc import Callable
from pathlib import Path

import pytest


class PathSwapper:
    def __init__(self, path: Path, swap: Callable[[], None], swap_at: int | None) -> None:
        self.path = path
        self.swap = swap
        self.swap_at = swap_at
        self.naming_calls = 0

    def _names_target(self, args: tuple[object, ...], kwargs: dict[str, object]) -> bool:
        first = args[0] if args else kwargs.get("path", kwargs.get("file"))
        if isinstance(first, int):
            return False
        text = os.fsdecode(first) if isinstance(first, str | bytes | os.PathLike) else ""
        return text in {str(self.path), str(self.path.parent)} or (text == self.path.name and "dir_fd" in kwargs)

    def wrap(self, original: Callable[..., object]) -> Callable[..., object]:
        def wrapped(*args: object, **kwargs: object) -> object:
            result = original(*args, **kwargs)
            if self._names_target(args, kwargs):
                self.naming_calls += 1
                if self.swap_at is not None and self.naming_calls == self.swap_at:
                    self.swap()
            return result

        return wrapped

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # `Path.open`/`read_bytes` go through `io.open`; the rest are the primitives a reader could use.
        for module, name in [(os, "open"), (os, "stat"), (os, "lstat"), (builtins, "open"), (io, "open")]:
            monkeypatch.setattr(module, name, self.wrap(getattr(module, name)))
        monkeypatch.setattr(Path, "stat", self.wrap(Path.stat))


def swap_outcomes(
    monkeypatch: pytest.MonkeyPatch,
    fresh: Callable[[], tuple[Path, Callable[[], None]]],
    read: Callable[[Path], object],
    untouched: object,
) -> list[object]:
    """One outcome per swap point k: `read`'s return value, or `f"refused: {exc}"` for a `ConfigError`.
    The dry run must return `untouched`, otherwise the wrapped reader is not reading what the test assumes."""
    from unifiwifioptimizer.domain.errors import ConfigError

    path, _ = fresh()
    dry_run = PathSwapper(path, lambda: None, None)
    with monkeypatch.context() as patched:
        dry_run.install(patched)
        assert read(path) == untouched
    assert dry_run.naming_calls >= 2, "the reader names the file and its directory at least once each"
    outcomes: list[object] = []
    for k in range(1, dry_run.naming_calls + 1):
        path, swap = fresh()
        swapper = PathSwapper(path, swap, k)
        with monkeypatch.context() as patched:
            swapper.install(patched)
            try:
                outcomes.append(read(path))
            except ConfigError as exc:
                outcomes.append(f"refused: {exc}")
    return outcomes
