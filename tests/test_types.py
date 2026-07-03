"""Tests for to_universal / from_universal on CodexAuth, OpenCodeAuth, PiAuth."""

from __future__ import annotations

from src.app.types import (
    CodexAuth,
    CodexTokens,
    OAuthAccount,
    OpenCodeAuth,
    PiAuth,
    UniversalAuth,
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
            expires=1800000000,
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
                expires=1800000000,
                accountId="acct-123",
            ),
        }
    )


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
            "expires": 1800000000,
            "account_id": "acct-123",
        },
    }


def _expected_pi_dict() -> dict:
    return {
        "openai-codex": {
            "type": "oauth",
            "access": "acc-def",
            "refresh": "ref-ghi",
            "expires": 1800000000,
            "accountId": "acct-123",
        },
    }


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
        assert u.expires == 1800000000
        assert u.id_token is None
        assert u.last_refresh is None
        assert u.openai_api_key is None
        assert u.auth_mode is None

    def test_pi_to_universal(self) -> None:
        u = _pi_auth().to_universal()
        assert u.access_token == "acc-def"
        assert u.refresh_token == "ref-ghi"
        assert u.account_id == "acct-123"
        assert u.expires == 1800000000
        assert u.id_token is None


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
        u = _codex_auth().to_universal()
        out = OpenCodeAuth.from_universal(u)
        assert out.openai.access == "acc-def"
        assert out.openai.refresh == "ref-ghi"
        assert out.openai.account_id == "acct-123"

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
        assert out.openai.access == "acc-def"
        assert out.openai.refresh == "ref-ghi"

    def test_opencode_as_pi(self) -> None:
        u = _opencode_auth().to_universal()
        out = PiAuth.from_universal(u)
        assert out.openai_codex.access == "acc-def"
        assert out.openai_codex.refresh == "ref-ghi"


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
                    expires=999,
                    accountId="acct-x",
                ),
            }
        )
        assert p.openai_codex.access == "tok-a"
        assert p.openai_codex.refresh == "tok-r"
        assert p.openai_codex.account_id == "acct-x"
        assert p.openai_codex.expires == 999
        assert p.model_dump(by_alias=True)["openai-codex"]["access"] == "tok-a"
