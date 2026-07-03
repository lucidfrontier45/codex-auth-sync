from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class CodexTokens(BaseModel):
    id_token: str
    access_token: str
    refresh_token: str
    account_id: str


class CodexAuth(BaseModel):
    auth_mode: Literal["chatgpt"]
    OPENAI_API_KEY: str | None
    tokens: CodexTokens
    last_refresh: str

    def to_universal(self) -> UniversalAuth:
        return UniversalAuth(
            access_token=self.tokens.access_token,
            refresh_token=self.tokens.refresh_token,
            account_id=self.tokens.account_id,
            id_token=self.tokens.id_token,
            last_refresh=self.last_refresh,
            openai_api_key=self.OPENAI_API_KEY,
            auth_mode=self.auth_mode,
        )

    @classmethod
    def from_universal(cls, u: UniversalAuth) -> CodexAuth:
        return cls(
            auth_mode="chatgpt",
            OPENAI_API_KEY=u.openai_api_key,
            tokens=CodexTokens(
                id_token=u.id_token or "",
                access_token=u.access_token,
                refresh_token=u.refresh_token,
                account_id=u.account_id,
            ),
            last_refresh=u.last_refresh or "",
        )


class OAuthAccount(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    type: Literal["oauth"]
    access: str
    refresh: str
    expires: int
    account_id: str = Field(alias="accountId")


class OpenCodeAuth(BaseModel):
    openai: OAuthAccount

    def to_universal(self) -> UniversalAuth:
        return UniversalAuth(
            access_token=self.openai.access,
            refresh_token=self.openai.refresh,
            account_id=self.openai.account_id,
            expires=self.openai.expires,
        )

    @classmethod
    def from_universal(cls, u: UniversalAuth) -> OpenCodeAuth:
        return cls(
            openai=OAuthAccount(
                type="oauth",
                access=u.access_token,
                refresh=u.refresh_token,
                accountId=u.account_id,
                expires=u.expires or 0,
            ),
        )


class PiAuth(BaseModel):
    """PiAuth uses a hyphenated key that maps to a Python-safe field name via alias."""

    model_config = ConfigDict(populate_by_name=True)

    openai_codex: OAuthAccount = Field(alias="openai-codex")

    def to_universal(self) -> UniversalAuth:
        return UniversalAuth(
            access_token=self.openai_codex.access,
            refresh_token=self.openai_codex.refresh,
            account_id=self.openai_codex.account_id,
            expires=self.openai_codex.expires,
        )

    @classmethod
    def from_universal(cls, u: UniversalAuth) -> PiAuth:
        return cls(
            **{
                "openai-codex": OAuthAccount(
                    type="oauth",
                    access=u.access_token,
                    refresh=u.refresh_token,
                    accountId=u.account_id,
                    expires=u.expires or 0,
                )
            }
        )


class UniversalAuth(BaseModel):
    """Unified auth representation convertible from/to CodexAuth, OpenCodeAuth, PiAuth."""

    access_token: str
    refresh_token: str
    account_id: str
    expires: int | None = None
    id_token: str | None = None
    last_refresh: str | None = None
    openai_api_key: str | None = None
    auth_mode: Literal["chatgpt"] | None = None
