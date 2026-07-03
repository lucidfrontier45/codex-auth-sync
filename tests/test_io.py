"""Tests for read/write round-trip on CodexAuth, OpenCodeAuth, PiAuth, including extra fields."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.app.types import (
    DEFAULT_CODEX_PATH,
    DEFAULT_OPENCODE_PATH,
    DEFAULT_PI_PATH,
    CodexAuth,
    CodexTokens,
    OAuthAccount,
    OpenCodeAuth,
    PiAuth,
)


# ── fixture helpers ──


def _codex_auth() -> CodexAuth:
    return CodexAuth(
        auth_mode="chatgpt",
        OPENAI_API_KEY=None,
        tokens=CodexTokens(
            id_token="id-abc",
            access_token="acc-def",
            refresh_token="ref-ghi",
            account_id="acct-123",
        ),
        last_refresh="2026-07-03T12:00:00Z",
    )


def _opencode_auth() -> OpenCodeAuth:
    return OpenCodeAuth(
        openai=OAuthAccount(
            type="oauth",
            access="acc-def",
            refresh="ref-ghi",
            expires=1_800_000_000,
            accountId="acct-123",
        ),
    )


def _pi_auth() -> PiAuth:
    return PiAuth(
        **{
            "openai-codex": OAuthAccount(
                type="oauth",
                access="acc-def",
                refresh="ref-ghi",
                expires=1_800_000_000,
                accountId="acct-123",
            ),
        }
    )


# ── default paths ──


class TestDefaultPaths:
    def test_codex_default_path(self) -> None:
        assert CodexAuth.DEFAULT_PATH == Path.home() / ".codex" / "auth.json"
        assert DEFAULT_CODEX_PATH == CodexAuth.DEFAULT_PATH

    def test_opencode_default_path(self) -> None:
        assert (
            OpenCodeAuth.DEFAULT_PATH
            == Path.home() / ".local" / "share" / "opencode" / "auth.json"
        )
        assert DEFAULT_OPENCODE_PATH == OpenCodeAuth.DEFAULT_PATH

    def test_pi_default_path(self) -> None:
        assert PiAuth.DEFAULT_PATH == Path.home() / ".pi" / "agent" / "auth.json"
        assert DEFAULT_PI_PATH == PiAuth.DEFAULT_PATH


# ── write → read round-trip ──


class TestWriteReadRoundTrip:
    def test_codex_round_trip(self, tmp_path: Path) -> None:
        target = tmp_path / "codex" / "auth.json"
        auth = _codex_auth()
        written = auth.write(target)
        assert written == target
        assert target.exists()
        loaded = CodexAuth.read(target)
        assert loaded.model_dump() == auth.model_dump()

    def test_opencode_round_trip(self, tmp_path: Path) -> None:
        target = tmp_path / "opencode" / "auth.json"
        auth = _opencode_auth()
        written = auth.write(target)
        assert written == target
        loaded = OpenCodeAuth.read(target)
        assert loaded.model_dump() == auth.model_dump()

    def test_pi_round_trip(self, tmp_path: Path) -> None:
        target = tmp_path / "pi" / "auth.json"
        auth = _pi_auth()
        written = auth.write(target)
        assert written == target
        loaded = PiAuth.read(target)
        assert loaded.model_dump() == auth.model_dump()

    def test_write_creates_parent_dirs(self, tmp_path: Path) -> None:
        target = tmp_path / "deep" / "nested" / "dir" / "auth.json"
        assert not target.parent.exists()
        _codex_auth().write(target)
        assert target.exists()

    def test_string_path_accepted(self, tmp_path: Path) -> None:
        target = tmp_path / "auth.json"
        auth = _opencode_auth()
        auth.write(str(target))
        assert target.exists()


# ── alias on-disk format ──


class TestOnDiskFormat:
    def test_opencode_uses_accountId_alias(self, tmp_path: Path) -> None:
        target = tmp_path / "auth.json"
        _opencode_auth().write(target)
        raw = json.loads(target.read_text())
        assert "accountId" in raw["openai"]
        assert "account_id" not in raw["openai"]

    def test_pi_uses_hyphenated_alias(self, tmp_path: Path) -> None:
        target = tmp_path / "auth.json"
        _pi_auth().write(target)
        raw = json.loads(target.read_text())
        assert "openai-codex" in raw
        assert "openai_codex" not in raw

    def test_codex_round_trip_preserves_key_case(self, tmp_path: Path) -> None:
        target = tmp_path / "auth.json"
        _codex_auth().write(target)
        raw = json.loads(target.read_text())
        assert "OPENAI_API_KEY" in raw
        assert "openai_api_key" not in raw


# ── extra fields ──


class TestExtraFields:
    def test_codex_holds_top_level_extra(self) -> None:
        auth = CodexAuth.model_validate(
            {
                "auth_mode": "chatgpt",
                "OPENAI_API_KEY": None,
                "tokens": {
                    "id_token": "x",
                    "access_token": "a",
                    "refresh_token": "r",
                    "account_id": "ac",
                },
                "last_refresh": "now",
                "extra_top": "top-value",
            }
        )
        assert auth.model_extra == {"extra_top": "top-value"}

    def test_codex_holds_nested_extra(self) -> None:
        auth = CodexAuth.model_validate(
            {
                "auth_mode": "chatgpt",
                "OPENAI_API_KEY": None,
                "tokens": {
                    "id_token": "x",
                    "access_token": "a",
                    "refresh_token": "r",
                    "account_id": "ac",
                    "extra_nested": 42,
                },
                "last_refresh": "now",
            }
        )
        assert auth.tokens.model_extra == {"extra_nested": 42}

    def test_codex_round_trip_with_extras(self, tmp_path: Path) -> None:
        target = tmp_path / "auth.json"
        auth = CodexAuth.model_validate(
            {
                "auth_mode": "chatgpt",
                "OPENAI_API_KEY": None,
                "tokens": {
                    "id_token": "id-abc",
                    "access_token": "acc-def",
                    "refresh_token": "ref-ghi",
                    "account_id": "acct-123",
                    "new_token_meta": "v2",
                },
                "last_refresh": "2026-07-03T12:00:00Z",
                "future_field": {"nested": True, "count": 7},
            }
        )
        auth.write(target)
        loaded = CodexAuth.read(target)
        assert loaded.model_extra == {"future_field": {"nested": True, "count": 7}}
        assert loaded.tokens.model_extra == {"new_token_meta": "v2"}

    def test_opencode_round_trip_with_extras(self, tmp_path: Path) -> None:
        target = tmp_path / "auth.json"
        auth = OpenCodeAuth.model_validate(
            {
                "openai": {
                    "type": "oauth",
                    "access": "acc-def",
                    "refresh": "ref-ghi",
                    "expires": 1_800_000_000,
                    "accountId": "acct-123",
                    "scope": "read-write",
                },
                "anthropic": {"key": "sk-ant"},
            }
        )
        auth.write(target)
        loaded = OpenCodeAuth.read(target)
        assert loaded.model_extra == {"anthropic": {"key": "sk-ant"}}
        assert loaded.openai.model_extra == {"scope": "read-write"}

    def test_pi_round_trip_with_extras(self, tmp_path: Path) -> None:
        target = tmp_path / "auth.json"
        auth = PiAuth.model_validate(
            {
                "openai-codex": {
                    "type": "oauth",
                    "access": "acc-def",
                    "refresh": "ref-ghi",
                    "expires": 1_800_000_000,
                    "accountId": "acct-123",
                    "scope": "all",
                },
                "version": 3,
            }
        )
        auth.write(target)
        loaded = PiAuth.read(target)
        assert loaded.model_extra == {"version": 3}
        assert loaded.openai_codex.model_extra == {"scope": "all"}


# ── failure modes ──


class TestErrors:
    def test_read_missing_file_raises(self, tmp_path: Path) -> None:
        target = tmp_path / "does-not-exist.json"
        with pytest.raises(FileNotFoundError):
            CodexAuth.read(target)

    def test_read_invalid_json_raises(self, tmp_path: Path) -> None:
        target = tmp_path / "bad.json"
        target.write_text("{not json")
        with pytest.raises(Exception):  # noqa: BLE001 — pydantic ValidationError
            CodexAuth.read(target)
