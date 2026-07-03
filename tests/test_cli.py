"""Tests for CLI orchestration: read universal, write to each target."""

from __future__ import annotations

import io
import json
from contextlib import redirect_stdout
from pathlib import Path

import pytest

from src.app.cli import AuthKind, Cli, main, run
from src.app.types import (
    CodexAuth,
    CodexTokens,
    OAuthAccount,
    OpenCodeAuth,
    PiAuth,
    UniversalAuth,
)


# ── fixture helpers ──


def _codex_payload() -> dict:
    return {
        "auth_mode": "chatgpt",
        "OPENAI_API_KEY": None,
        "tokens": {
            "id_token": "id-abc",
            "access_token": "acc-def",
            "refresh_token": "ref-ghi",
            "account_id": "acct-123",
        },
        "last_refresh": "2026-07-03T12:00:00Z",
    }


def _opencode_payload() -> dict:
    return {
        "openai": {
            "type": "oauth",
            "access": "acc-def",
            "refresh": "ref-ghi",
            "expires": 1_800_000_000,
            "accountId": "acct-123",
        },
    }


def _pi_payload() -> dict:
    return {
        "openai-codex": {
            "type": "oauth",
            "access": "acc-def",
            "refresh": "ref-ghi",
            "expires": 1_800_000_000,
            "accountId": "acct-123",
        },
    }


def _write(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


# ── run() core logic ──


class TestRun:
    def test_codex_to_pi_and_opencode(self, tmp_path: Path) -> None:
        src = tmp_path / "src.json"
        out_pi = tmp_path / "out_pi.json"
        out_oc = tmp_path / "out_oc.json"
        _write(src, _codex_payload())
        written = run(
            Cli(
                source=AuthKind.codex,
                source_path=src,
                targets=(AuthKind.pi, AuthKind.opencode),
                target_paths=(out_pi, out_oc),
            )
        )
        assert written == [out_pi, out_oc]
        assert out_pi.exists() and out_oc.exists()
        # opencode-format written under pi target; codex has no expires
        # field, so the universal form carries None → PiAuth defaults to 0
        pi_raw = json.loads(out_pi.read_text())
        assert pi_raw == {
            "openai-codex": {
                "type": "oauth",
                "access": "acc-def",
                "refresh": "ref-ghi",
                "expires": 0,
                "accountId": "acct-123",
            }
        }

    def test_opencode_to_pi(self, tmp_path: Path) -> None:
        src = tmp_path / "src.json"
        out_pi = tmp_path / "out_pi.json"
        _write(src, _opencode_payload())
        written = run(
            Cli(
                source=AuthKind.opencode,
                source_path=src,
                targets=(AuthKind.pi,),
                target_paths=(out_pi,),
            )
        )
        assert written == [out_pi]
        loaded = PiAuth.read(out_pi)
        assert loaded.openai_codex.access == "acc-def"

    def test_pi_to_codex(self, tmp_path: Path) -> None:
        src = tmp_path / "src.json"
        out_codex = tmp_path / "out_codex.json"
        _write(src, _pi_payload())
        run(
            Cli(
                source=AuthKind.pi,
                source_path=src,
                targets=(AuthKind.codex,),
                target_paths=(out_codex,),
            )
        )
        loaded = CodexAuth.read(out_codex)
        assert loaded.auth_mode == "chatgpt"
        assert loaded.tokens.access_token == "acc-def"
        assert loaded.tokens.refresh_token == "ref-ghi"
        # opencode-shaped → codex: id_token/last_refresh absent → empty
        assert loaded.tokens.id_token == ""
        assert loaded.last_refresh == ""

    def test_codex_to_codex_round_trip(self, tmp_path: Path) -> None:
        src = tmp_path / "src.json"
        out_codex = tmp_path / "out.json"
        _write(src, _codex_payload())
        run(
            Cli(
                source=AuthKind.codex,
                source_path=src,
                targets=(AuthKind.codex,),
                target_paths=(out_codex,),
            )
        )
        assert json.loads(out_codex.read_text()) == _codex_payload()

    def test_missing_target_paths_uses_none(self, tmp_path: Path) -> None:
        # Supply paths for both targets to avoid touching real home dirs;
        # verify positional alignment via tuple index slicing behavior.
        from src.app.cli import _resolve_paths

        resolved = _resolve_paths((tmp_path / "only.json",), 2)
        assert resolved == (tmp_path / "only.json", None)
        assert resolved[1] is None

    def test_extra_target_paths_truncated(self, tmp_path: Path) -> None:
        src = tmp_path / "src.json"
        out_a = tmp_path / "a.json"
        out_b = tmp_path / "b.json"
        out_c = tmp_path / "c.json"
        _write(src, _codex_payload())
        run(
            Cli(
                source=AuthKind.codex,
                source_path=src,
                targets=(AuthKind.codex,),
                target_paths=(out_a, out_b, out_c),
            )
        )
        # only first target-path used; extras ignored
        assert out_a.exists()
        assert not out_b.exists()
        assert not out_c.exists()


class TestMain:
    def test_main_writes_and_prints(self, tmp_path: Path) -> None:
        src = tmp_path / "src.json"
        out = tmp_path / "out.json"
        _write(src, _pi_payload())
        buf = io.StringIO()
        with redirect_stdout(buf):
            main(
                [
                    "--source",
                    "pi",
                    "--source-path",
                    str(src),
                    "--targets",
                    "codex",
                    "--target-paths",
                    str(out),
                ]
            )
        output = buf.getvalue().strip()
        assert str(out) in output
        assert out.exists()
        loaded = CodexAuth.read(out)
        assert loaded.tokens.access_token == "acc-def"

    def test_main_empty_targets_exits(self, tmp_path: Path) -> None:
        src = tmp_path / "src.json"
        _write(src, _codex_payload())
        with pytest.raises(SystemExit):
            main(["--source", "codex", "--source-path", str(src)])

    def test_main_invalid_source_exits(self) -> None:
        with pytest.raises(SystemExit):
            main(["--source", "bogus", "--targets", "pi"])

    def test_main_space_separated_targets(self, tmp_path: Path) -> None:
        src = tmp_path / "src.json"
        out_a = tmp_path / "a.json"
        out_b = tmp_path / "b.json"
        _write(src, _codex_payload())
        main(
            [
                "--source",
                "codex",
                "--source-path",
                str(src),
                "--targets",
                "pi",
                "opencode",
                "--target-paths",
                str(out_a),
                str(out_b),
            ]
        )
        assert out_a.exists()
        assert out_b.exists()
