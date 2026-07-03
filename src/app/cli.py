from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import tyro

from .types import CodexAuth, OpenCodeAuth, PiAuth, UniversalAuth


class AuthKind(StrEnum):
    """Auth format kind: codex, pi, or opencode."""

    codex = "codex"
    pi = "pi"
    opencode = "opencode"


_READERS: dict[AuthKind, Callable[[Path | None], UniversalAuth]] = {
    AuthKind.codex: lambda p: CodexAuth.read(p).to_universal(),
    AuthKind.pi: lambda p: PiAuth.read(p).to_universal(),
    AuthKind.opencode: lambda p: OpenCodeAuth.read(p).to_universal(),
}


_WRITERS: dict[AuthKind, Callable[[UniversalAuth, Path | None], Path]] = {
    AuthKind.codex: lambda u, p: CodexAuth.from_universal(u).write(p),
    AuthKind.pi: lambda u, p: PiAuth.from_universal(u).write(p),
    AuthKind.opencode: lambda u, p: OpenCodeAuth.from_universal(u).write(p),
}


@dataclass
class Cli:
    """Sync Codex auth token across coding agents."""

    source: AuthKind
    """Auth kind to read from."""
    source_path: Path | None = None
    """Optional path to read from. Defaults to the kind's standard location."""
    targets: tuple[AuthKind, ...] = ()
    """Auth kinds to write to (at least one)."""
    target_paths: tuple[Path, ...] = ()
    """Optional output paths aligned positionally with --targets. Empty = defaults."""


def _resolve_paths(supplied: tuple[Path, ...], n: int) -> tuple[Path | None, ...]:
    """Pad/truncate a path tuple to exactly n entries; missing entries become None."""
    padded: list[Path | None] = list(supplied) + [None] * (n - len(supplied))
    return tuple(padded[:n])


def run(cli: Annotated[Cli, tyro.conf.OmitArgPrefixes]) -> list[Path]:
    """Execute CLI logic. Returns paths written."""
    if not cli.targets:
        raise SystemExit("error: at least one --targets value required")
    universal = _READERS[cli.source](cli.source_path)
    paths = _resolve_paths(cli.target_paths, len(cli.targets))
    written: list[Path] = []
    for kind, path in zip(cli.targets, paths, strict=True):
        written.append(_WRITERS[kind](universal, path))
    return written


def main(argv: list[str] | None = None) -> None:
    """Entry point. Parses argv via tyro, runs, prints written paths."""
    written = tyro.cli(run, args=argv)
    for path in written:
        print(path)


if __name__ == "__main__":
    main()
