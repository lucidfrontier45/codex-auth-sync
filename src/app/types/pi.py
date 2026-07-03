from __future__ import annotations

from pathlib import Path
from typing import ClassVar

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .common import (
    OAuthAccount,
    OAuthAccountMissingError,
    UniversalAuth,
    _empty_oauth_account_to_none,
    resolve_oauth_expires,
)

__all__ = ["DEFAULT_PI_PATH", "PiAuth"]


DEFAULT_PI_PATH: Path = Path.home() / ".pi" / "agent" / "auth.json"


class PiAuth(BaseModel):
    """PiAuth uses a hyphenated key that maps to a Python-safe field name via alias."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    DEFAULT_PATH: ClassVar[Path] = DEFAULT_PI_PATH

    openai_codex: OAuthAccount | None = Field(default=None, alias="openai-codex")

    @field_validator("openai_codex", mode="before")
    @classmethod
    def _validate_openai_codex(cls, value: object) -> object:
        return _empty_oauth_account_to_none(value)

    @classmethod
    def read(cls, path: Path | str | None = None) -> PiAuth:
        """Load auth from JSON file. Defaults to ~/.pi/agent/auth.json."""
        target = Path(path) if path is not None else cls.DEFAULT_PATH
        return cls.model_validate_json(target.read_text(encoding="utf-8"))

    def write(self, path: Path | str | None = None) -> Path:
        """Persist auth to JSON file. Returns path. Hyphenated alias used on disk."""
        target = Path(path) if path is not None else self.DEFAULT_PATH
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            self.model_dump_json(by_alias=True, indent=2), encoding="utf-8"
        )
        return target

    def to_universal(self) -> UniversalAuth:
        if self.openai_codex is None:
            raise OAuthAccountMissingError(
                "PiAuth.openai_codex source requires a non-empty oauth account"
            )
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
                    expires=resolve_oauth_expires(u),
                )
            }
        )

    def merge_from_universal(self, u: UniversalAuth) -> PiAuth:
        account = (
            self.openai_codex.model_copy(
                update={
                    "type": "oauth",
                    "access": u.access_token,
                    "refresh": u.refresh_token,
                    "expires": resolve_oauth_expires(u),
                    "account_id": u.account_id,
                }
            )
            if self.openai_codex is not None
            else OAuthAccount(
                type="oauth",
                access=u.access_token,
                refresh=u.refresh_token,
                accountId=u.account_id,
                expires=resolve_oauth_expires(u),
            )
        )
        return self.model_copy(update={"openai_codex": account})
