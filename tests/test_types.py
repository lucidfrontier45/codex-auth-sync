"""Tests for to_universal / from_universal on CodexAuth, OpenCodeAuth, PiAuth."""

from __future__ import annotations

import base64
import json

import pytest

from src.app.types import (
    CodexAuth,
    CodexTokens,
    ExpiryResolutionError,
    OAuthAccount,
    OAuthAccountMissingError,
    OpenCodeAuth,
    PiAuth,
    UniversalAuth,
    resolve_oauth_expires,
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
            expires=1_800_000_000_000,  # ty: ignore
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
                expires=1_800_000_000_000,  # ty: ignore
                accountId="acct-123",
            ),
        }
    )


def _require_openai(auth: OpenCodeAuth) -> OAuthAccount:
    assert auth.openai is not None
    return auth.openai


def _require_openai_codex(auth: PiAuth) -> OAuthAccount:
    assert auth.openai_codex is not None
    return auth.openai_codex


def _expected_codex_dict() -> dict:
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


def _expected_opencode_dict() -> dict:
    return {
        "openai": {
            "type": "oauth",
            "access": "acc-def",
            "refresh": "ref-ghi",
            "expires": 1_800_000_000_000,
            "account_id": "acct-123",
        },
    }


def _expected_pi_dict() -> dict:
    return {
        "openai-codex": {
            "type": "oauth",
            "access": "acc-def",
            "refresh": "ref-ghi",
            "expires": 1_800_000_000_000,
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


# ── to_universal tests ──


class TestToUniversal:
    def test_codex_to_universal(self) -> None:
        u = _codex_auth().to_universal()
        assert u.access_token == "acc-def"
        assert u.refresh_token == "ref-ghi"
        assert u.account_id == "acct-123"
        assert u.id_token == "id-abc"
        assert u.last_refresh == "2026-07-03T12:00:00Z"
        assert u.openai_api_key is None
        assert u.auth_mode == "chatgpt"
        assert u.expires is None

    def test_opencode_to_universal(self) -> None:
        u = _opencode_auth().to_universal()
        assert u.access_token == "acc-def"
        assert u.refresh_token == "ref-ghi"
        assert u.account_id == "acct-123"
        assert u.expires is not None
        assert u.expires.value == 1_800_000_000_000
        assert u.id_token is None
        assert u.last_refresh is None
        assert u.openai_api_key is None
        assert u.auth_mode is None

    def test_pi_to_universal(self) -> None:
        u = _pi_auth().to_universal()
        assert u.access_token == "acc-def"
        assert u.refresh_token == "ref-ghi"
        assert u.account_id == "acct-123"
        assert u.expires is not None
        assert u.expires.value == 1_800_000_000_000
        assert u.id_token is None

    def test_opencode_to_universal_rejects_missing_source_account(self) -> None:
        auth = OpenCodeAuth(openai=None)
        with pytest.raises(
            OAuthAccountMissingError,
            match="OpenCodeAuth\\.openai source requires a non-empty oauth account",
        ):
            auth.to_universal()

    def test_pi_to_universal_rejects_missing_source_account(self) -> None:
        auth = PiAuth.model_validate({"openai-codex": {}})
        with pytest.raises(
            OAuthAccountMissingError,
            match="PiAuth\\.openai_codex source requires a non-empty oauth account",
        ):
            auth.to_universal()


class TestFromUniversal:
    def test_codex_from_universal(self) -> None:
        u = _codex_auth().to_universal()
        out = CodexAuth.from_universal(u)
        assert out.model_dump() == _expected_codex_dict()
        assert out.auth_mode == "chatgpt"
        assert out.tokens.id_token == "id-abc"

    def test_opencode_from_universal(self) -> None:
        u = _opencode_auth().to_universal()
        out = OpenCodeAuth.from_universal(u)
        assert out.model_dump() == _expected_opencode_dict()

    def test_pi_from_universal(self) -> None:
        u = _pi_auth().to_universal()
        out = PiAuth.from_universal(u)
        assert out.model_dump(by_alias=True) == _expected_pi_dict()

    def test_opencode_from_universal_derives_expiry_from_jwt(self) -> None:
        u = UniversalAuth(
            access_token=_jwt_access_token(),
            refresh_token="ref-ghi",
            account_id="acct-123",
            expires=None,
        )
        out = OpenCodeAuth.from_universal(u)
        assert _require_openai(out).expires.value == 1_800_000_000_000

    def test_pi_from_universal_derives_expiry_from_zero_value(self) -> None:
        u = UniversalAuth(
            access_token=_jwt_access_token(),
            refresh_token="ref-ghi",
            account_id="acct-123",
            expires=None,
        )
        out = PiAuth.from_universal(u)
        assert _require_openai_codex(out).expires.value == 1_800_000_000_000

    @pytest.mark.parametrize(
        ("access_token", "message"),
        [
            ("not-a-jwt", "three segments"),
            ("a.b.c", "valid base64url"),
            (
                "a."
                + base64.urlsafe_b64encode(b"[]").decode("ascii").rstrip("=")
                + ".c",
                "JSON object",
            ),
            (
                "a."
                + base64.urlsafe_b64encode(json.dumps({}).encode("utf-8"))
                .decode("ascii")
                .rstrip("=")
                + ".c",
                "exp claim",
            ),
        ],
    )
    def test_oauth_from_universal_requires_resolvable_expiry(
        self, access_token: str, message: str
    ) -> None:
        u = UniversalAuth(
            access_token=access_token,
            refresh_token="ref-ghi",
            account_id="acct-123",
        )
        with pytest.raises(ExpiryResolutionError, match=message):
            OpenCodeAuth.from_universal(u)


class TestRoundTrip:
    """Strict round-trips: source → universal → source."""

    def test_codex_round_trip(self) -> None:
        orig = _codex_auth()
        u = orig.to_universal()
        back = CodexAuth.from_universal(u)
        assert back.model_dump() == orig.model_dump()

    def test_opencode_round_trip(self) -> None:
        orig = _opencode_auth()
        u = orig.to_universal()
        back = OpenCodeAuth.from_universal(u)
        assert back.model_dump() == orig.model_dump()

    def test_pi_round_trip(self) -> None:
        orig = _pi_auth()
        u = orig.to_universal()
        back = PiAuth.from_universal(u)
        assert back.model_dump(by_alias=True) == orig.model_dump(by_alias=True)


class TestCrossConvert:
    """Build universal from one source type, materialise as another."""

    def test_codex_as_opencode(self) -> None:
        codex = CodexAuth(
            auth_mode="chatgpt",
            OPENAI_API_KEY=None,
            tokens=CodexTokens(
                id_token="id-abc",
                access_token=_jwt_access_token(),
                refresh_token="ref-ghi",
                account_id="acct-123",
            ),
            last_refresh="2026-07-03T12:00:00Z",
        )
        u = codex.to_universal()
        out = OpenCodeAuth.from_universal(u)
        openai = _require_openai(out)
        assert openai.access == _jwt_access_token()
        assert openai.refresh == "ref-ghi"
        assert openai.account_id == "acct-123"
        assert openai.expires.value == 1_800_000_000_000

    def test_opencode_as_codex(self) -> None:
        u = _opencode_auth().to_universal()
        out = CodexAuth.from_universal(u)
        assert out.auth_mode == "chatgpt"
        assert out.OPENAI_API_KEY is None
        assert out.tokens.access_token == "acc-def"
        assert out.tokens.refresh_token == "ref-ghi"
        assert out.tokens.account_id == "acct-123"
        # id_token not available from OpenCodeAuth → converted as empty
        assert out.tokens.id_token == ""
        assert out.last_refresh == ""

    def test_pi_as_opencode(self) -> None:
        u = _pi_auth().to_universal()
        out = OpenCodeAuth.from_universal(u)
        openai = _require_openai(out)
        assert openai.access == "acc-def"
        assert openai.refresh == "ref-ghi"

    def test_opencode_as_pi(self) -> None:
        u = _opencode_auth().to_universal()
        out = PiAuth.from_universal(u)
        openai_codex = _require_openai_codex(out)
        assert openai_codex.access == "acc-def"
        assert openai_codex.refresh == "ref-ghi"


class TestEdgeCases:
    def test_api_key_carries_through(self) -> None:
        codex = CodexAuth(
            auth_mode="chatgpt",
            OPENAI_API_KEY="sk-xxx",
            tokens=CodexTokens(
                id_token="t1",
                access_token="a1",
                refresh_token="r1",
                account_id="ac1",
            ),
            last_refresh="now",
        )
        u = codex.to_universal()
        assert u.openai_api_key == "sk-xxx"
        out = CodexAuth.from_universal(u)
        assert out.OPENAI_API_KEY == "sk-xxx"

    def test_universal_direct_construction(self) -> None:
        u = UniversalAuth(access_token="a", refresh_token="b", account_id="c")
        assert u.access_token == "a"
        assert u.refresh_token == "b"
        assert u.account_id == "c"

    def test_pi_alias_round_trip(self) -> None:
        """PiAuth can be constructed by alias and read back via Python field name."""
        p = PiAuth(
            **{
                "openai-codex": OAuthAccount(
                    type="oauth",
                    access="tok-a",
                    refresh="tok-r",
                    expires=1_800_000_000_000,  # ty: ignore
                    accountId="acct-x",
                ),
            }
        )
        openai_codex = _require_openai_codex(p)
        assert openai_codex.access == "tok-a"
        assert openai_codex.refresh == "tok-r"
        assert openai_codex.account_id == "acct-x"
        assert openai_codex.expires.value == 1_800_000_000_000
        assert p.model_dump(by_alias=True)["openai-codex"]["access"] == "tok-a"

    def test_resolve_oauth_expires_prefers_existing_expiry(self) -> None:
        u = UniversalAuth(
            access_token="not-needed",
            refresh_token="ref",
            account_id="acct",
            expires=1_800_000_000_000,  # ty: ignore
        )
        assert resolve_oauth_expires(u).value == 1_800_000_000_000


class TestMergeFromUniversal:
    def test_codex_merge_preserves_extras_and_missing_codex_fields(self) -> None:
        auth = CodexAuth.model_validate(
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
            }
        )
        merged = auth.merge_from_universal(
            UniversalAuth(
                access_token="new-access",
                refresh_token="new-refresh",
                account_id="new-account",
            )
        )
        assert merged.tokens.access_token == "new-access"
        assert merged.tokens.refresh_token == "new-refresh"
        assert merged.tokens.account_id == "new-account"
        assert merged.tokens.id_token == "id-existing"
        assert merged.last_refresh == "2026-07-01T00:00:00Z"
        assert merged.OPENAI_API_KEY == "sk-existing"
        assert merged.model_extra == {"future_field": {"nested": True}}
        assert merged.tokens.model_extra == {"scope": "offline"}

    def test_opencode_merge_preserves_top_level_and_nested_extras(self) -> None:
        auth = OpenCodeAuth.model_validate(
            {
                "openai": {
                    "type": "oauth",
                    "access": "old-access",
                    "refresh": "old-refresh",
                    "expires": 2_000_000_000_000,
                    "accountId": "old-account",
                    "scope": "read-write",
                },
                "anthropic": {"key": "sk-ant"},
            }
        )
        merged = auth.merge_from_universal(
            UniversalAuth(
                access_token=_jwt_access_token(),
                refresh_token="new-refresh",
                account_id="new-account",
            )
        )
        openai = _require_openai(merged)
        assert openai.access != "old-access"
        assert openai.refresh == "new-refresh"
        assert openai.account_id == "new-account"
        assert openai.expires.value == 1_800_000_000_000
        assert merged.model_extra == {"anthropic": {"key": "sk-ant"}}
        assert openai.model_extra == {"scope": "read-write"}

    def test_pi_merge_preserves_top_level_and_nested_extras(self) -> None:
        auth = PiAuth.model_validate(
            {
                "openai-codex": {
                    "type": "oauth",
                    "access": "old-access",
                    "refresh": "old-refresh",
                    "expires": 2_000_000_000_000,
                    "accountId": "old-account",
                    "scope": "all",
                },
                "version": 3,
            }
        )
        merged = auth.merge_from_universal(
            UniversalAuth(
                access_token=_jwt_access_token(),
                refresh_token="new-refresh",
                account_id="new-account",
            )
        )
        openai_codex = _require_openai_codex(merged)
        assert openai_codex.account_id == "new-account"
        assert openai_codex.expires.value == 1_800_000_000_000
        assert merged.model_extra == {"version": 3}
        assert openai_codex.model_extra == {"scope": "all"}
