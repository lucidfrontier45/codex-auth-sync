from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import tyro

from .types import (
    CodexAuth,
    ExpiryResolutionError,
    OpenCodeAuth,
    PiAuth,
    UniversalAuth,
)


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


def _target_path(supplied: Path | None, default: Path) -> Path:
    return supplied if supplied is not None else default


def _write_codex(universal: UniversalAuth, path: Path | None) -> Path:
    target = _target_path(path, CodexAuth.DEFAULT_PATH)
    auth = (
        CodexAuth.read(target).merge_from_universal(universal)
        if target.exists()
        else CodexAuth.from_universal(universal)
    )
    return auth.write(target)


def _write_opencode(universal: UniversalAuth, path: Path | None) -> Path:
    target = _target_path(path, OpenCodeAuth.DEFAULT_PATH)
    try:
        auth = (
            OpenCodeAuth.read(target).merge_from_universal(universal)
            if target.exists()
            else OpenCodeAuth.from_universal(universal)
        )
    except ExpiryResolutionError as exc:
        raise ExpiryResolutionError(
            f"opencode target requires a usable OAuth expiry: {exc}"
        ) from exc
    return auth.write(target)


def _write_pi(universal: UniversalAuth, path: Path | None) -> Path:
    target = _target_path(path, PiAuth.DEFAULT_PATH)
    try:
        auth = (
            PiAuth.read(target).merge_from_universal(universal)
            if target.exists()
            else PiAuth.from_universal(universal)
        )
    except ExpiryResolutionError as exc:
        raise ExpiryResolutionError(
            f"pi target requires a usable OAuth expiry: {exc}"
        ) from exc
    return auth.write(target)


_WRITERS: dict[AuthKind, Callable[[UniversalAuth, Path | None], Path]] = {
    AuthKind.codex: _write_codex,
    AuthKind.pi: _write_pi,
    AuthKind.opencode: _write_opencode,
}


@dataclass
class Cli:
    """Sync Codex auth token across coding agents."""

    source: AuthKind
    """Auth kind to read from."""
    targets: tuple[AuthKind, ...]
    """Auth kinds to write to (at least one)."""
    source_path: Path | None = None
    """Optional path to read from. Defaults to the kind's standard location."""
    target_paths: tuple[Path, ...] = ()
    """Optional output paths aligned positionally with --targets. Empty = defaults."""


def _resolve_paths(supplied: tuple[Path, ...], n: int) -> tuple[Path | None, ...]:
    """Pad/truncate a path tuple to exactly n entries; missing entries become None."""
    padded: list[Path | None] = list(supplied) + [None] * (n - len(supplied))
    return tuple(padded[:n])


def run(cli: Annotated[Cli, tyro.conf.OmitArgPrefixes]) -> list[Path]:
    """Execute CLI logic. Returns paths written."""
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
