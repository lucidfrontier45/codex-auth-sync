"""Tests for CLI orchestration: read universal, write to each target."""

from __future__ import annotations

import base64
import io
import json
from contextlib import redirect_stdout
from pathlib import Path

import pytest

from src.app.cli import AuthKind, Cli, main, run
from src.app.types import (
    CodexAuth,
    ExpiryResolutionError,
    OAuthAccount,
    OAuthAccountMissingError,
    PiAuth,
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


def _jwt_access_token(exp: int = 1_800_000_000) -> str:
    header = (
        base64.urlsafe_b64encode(
            json.dumps({"alg": "none", "typ": "JWT"}).encode("utf-8")
        )
        .decode("ascii")
        .rstrip("=")
    )
    payload = (
        base64.urlsafe_b64encode(
            json.dumps({"exp": exp, "scope": "read"}).encode("utf-8")
        )
        .decode("ascii")
        .rstrip("=")
    )
    return f"{header}.{payload}.sig"


def _codex_payload_with_jwt() -> dict:
    payload = _codex_payload()
    payload["tokens"]["access_token"] = _jwt_access_token()
    return payload


def _write(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def _require_openai_codex(auth: PiAuth) -> OAuthAccount:
    assert auth.openai_codex is not None
    return auth.openai_codex


# ── run() core logic ──


class TestRun:
    def test_codex_to_pi_and_opencode(self, tmp_path: Path) -> None:
        src = tmp_path / "src.json"
        out_pi = tmp_path / "out_pi.json"
        out_oc = tmp_path / "out_oc.json"
        _write(src, _codex_payload_with_jwt())
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
        pi_raw = json.loads(out_pi.read_text())
        assert pi_raw == {
            "openai-codex": {
                "type": "oauth",
                "access": _jwt_access_token(),
                "refresh": "ref-ghi",
                "expires": 1_800_000_000,
                "accountId": "acct-123",
            }
        }
        opencode_raw = json.loads(out_oc.read_text())
        assert opencode_raw["openai"]["expires"] == 1_800_000_000

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
        assert _require_openai_codex(loaded).access == "acc-def"

    def test_codex_to_opencode_preserves_existing_extras(self, tmp_path: Path) -> None:
        src = tmp_path / "src.json"
        out_oc = tmp_path / "out_oc.json"
        _write(src, _codex_payload_with_jwt())
        _write(
            out_oc,
            {
                "openai": {
                    "type": "oauth",
                    "access": "old-access",
                    "refresh": "old-refresh",
                    "expires": 7,
                    "accountId": "old-account",
                    "scope": "read-write",
                },
                "anthropic": {"key": "sk-ant"},
            },
        )
        run(
            Cli(
                source=AuthKind.codex,
                source_path=src,
                targets=(AuthKind.opencode,),
                target_paths=(out_oc,),
            )
        )
        raw = json.loads(out_oc.read_text())
        assert raw["anthropic"] == {"key": "sk-ant"}
        assert raw["openai"]["scope"] == "read-write"
        assert raw["openai"]["expires"] == 1_800_000_000

    def test_codex_to_pi_preserves_existing_extras(self, tmp_path: Path) -> None:
        src = tmp_path / "src.json"
        out_pi = tmp_path / "out_pi.json"
        _write(src, _codex_payload_with_jwt())
        _write(
            out_pi,
            {
                "openai-codex": {
                    "type": "oauth",
                    "access": "old-access",
                    "refresh": "old-refresh",
                    "expires": 7,
                    "accountId": "old-account",
                    "scope": "all",
                },
                "version": 3,
            },
        )
        run(
            Cli(
                source=AuthKind.codex,
                source_path=src,
                targets=(AuthKind.pi,),
                target_paths=(out_pi,),
            )
        )
        raw = json.loads(out_pi.read_text())
        assert raw["version"] == 3
        assert raw["openai-codex"]["scope"] == "all"
        assert raw["openai-codex"]["expires"] == 1_800_000_000

    def test_codex_to_existing_opencode_with_null_source_slot(
        self, tmp_path: Path
    ) -> None:
        src = tmp_path / "src.json"
        out_oc = tmp_path / "out_oc.json"
        _write(src, _codex_payload_with_jwt())
        _write(out_oc, {"openai": None, "anthropic": {"key": "sk-ant"}})
        run(
            Cli(
                source=AuthKind.codex,
                source_path=src,
                targets=(AuthKind.opencode,),
                target_paths=(out_oc,),
            )
        )
        raw = json.loads(out_oc.read_text())
        assert raw["anthropic"] == {"key": "sk-ant"}
        assert raw["openai"]["access"] == _jwt_access_token()
        assert raw["openai"]["expires"] == 1_800_000_000

    def test_codex_to_existing_pi_with_empty_source_slot(self, tmp_path: Path) -> None:
        src = tmp_path / "src.json"
        out_pi = tmp_path / "out_pi.json"
        _write(src, _codex_payload_with_jwt())
        _write(out_pi, {"openai-codex": {}, "version": 3})
        run(
            Cli(
                source=AuthKind.codex,
                source_path=src,
                targets=(AuthKind.pi,),
                target_paths=(out_pi,),
            )
        )
        raw = json.loads(out_pi.read_text())
        assert raw["version"] == 3
        assert raw["openai-codex"]["access"] == _jwt_access_token()
        assert raw["openai-codex"]["expires"] == 1_800_000_000

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
        # opencode-shaped → codex: preserve missing codex-only metadata on fresh create
        assert loaded.tokens.id_token == ""
        assert loaded.last_refresh == ""

    def test_pi_to_existing_codex_preserves_codex_only_metadata(
        self, tmp_path: Path
    ) -> None:
        src = tmp_path / "src.json"
        out_codex = tmp_path / "out_codex.json"
        _write(src, _pi_payload())
        _write(
            out_codex,
            {
                "auth_mode": "chatgpt",
                "OPENAI_API_KEY": "sk-existing",
                "tokens": {
                    "id_token": "id-existing",
                    "access_token": "old-access",
                    "refresh_token": "old-refresh",
                    "account_id": "old-account",
                    "scope": "offline",
                },
                "last_refresh": "2026-07-01T00:00:00Z",
                "future_field": {"nested": True},
            },
        )
        run(
            Cli(
                source=AuthKind.pi,
                source_path=src,
                targets=(AuthKind.codex,),
                target_paths=(out_codex,),
            )
        )
        raw = json.loads(out_codex.read_text())
        assert raw["OPENAI_API_KEY"] == "sk-existing"
        assert raw["tokens"]["id_token"] == "id-existing"
        assert raw["tokens"]["scope"] == "offline"
        assert raw["last_refresh"] == "2026-07-01T00:00:00Z"
        assert raw["future_field"] == {"nested": True}

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

    def test_codex_to_existing_codex_preserves_forward_compatible_extras(
        self, tmp_path: Path
    ) -> None:
        src = tmp_path / "src.json"
        out_codex = tmp_path / "out.json"
        _write(src, _codex_payload())
        _write(
            out_codex,
            {
                "auth_mode": "chatgpt",
                "OPENAI_API_KEY": None,
                "tokens": {
                    "id_token": "old-id",
                    "access_token": "old-access",
                    "refresh_token": "old-refresh",
                    "account_id": "old-account",
                    "new_token_meta": "v2",
                },
                "last_refresh": "2026-07-01T00:00:00Z",
                "future_field": {"nested": True, "count": 7},
            },
        )
        run(
            Cli(
                source=AuthKind.codex,
                source_path=src,
                targets=(AuthKind.codex,),
                target_paths=(out_codex,),
            )
        )
        raw = json.loads(out_codex.read_text())
        assert raw["future_field"] == {"nested": True, "count": 7}
        assert raw["tokens"]["new_token_meta"] == "v2"

    def test_codex_to_oauth_target_fails_when_expiry_cannot_be_derived(
        self, tmp_path: Path
    ) -> None:
        src = tmp_path / "src.json"
        out_pi = tmp_path / "out_pi.json"
        bad_payload = _codex_payload()
        bad_payload["tokens"]["access_token"] = "not-a-jwt"
        _write(src, bad_payload)
        with pytest.raises(ExpiryResolutionError, match="pi target"):
            run(
                Cli(
                    source=AuthKind.codex,
                    source_path=src,
                    targets=(AuthKind.pi,),
                    target_paths=(out_pi,),
                )
            )

    def test_opencode_source_with_empty_account_fails(self, tmp_path: Path) -> None:
        src = tmp_path / "src.json"
        out_pi = tmp_path / "out_pi.json"
        _write(src, {"openai": {}})
        with pytest.raises(OAuthAccountMissingError, match="OpenCodeAuth\\.openai"):
            run(
                Cli(
                    source=AuthKind.opencode,
                    source_path=src,
                    targets=(AuthKind.pi,),
                    target_paths=(out_pi,),
                )
            )

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
        _write(src, _codex_payload_with_jwt())
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
