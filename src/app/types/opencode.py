from __future__ import annotations

from pathlib import Path
from typing import ClassVar

from pydantic import BaseModel, ConfigDict, field_validator

from .common import (
    OAuthAccount,
    OAuthAccountMissingError,
    UniversalAuth,
    _empty_oauth_account_to_none,
    resolve_oauth_expires,
)

__all__ = ["DEFAULT_OPENCODE_PATH", "OpenCodeAuth"]


DEFAULT_OPENCODE_PATH: Path = (
    Path.home() / ".local" / "share" / "opencode" / "auth.json"
)


class OpenCodeAuth(BaseModel):
    model_config = ConfigDict(extra="allow")

    DEFAULT_PATH: ClassVar[Path] = DEFAULT_OPENCODE_PATH

    openai: OAuthAccount | None = None

    @field_validator("openai", mode="before")
    @classmethod
    def _validate_openai(cls, value: object) -> object:
        return _empty_oauth_account_to_none(value)

    @classmethod
    def read(cls, path: Path | str | None = None) -> OpenCodeAuth:
        """Load auth from JSON file. Defaults to ~/.local/share/opencode/auth.json."""
        target = Path(path) if path is not None else cls.DEFAULT_PATH
        return cls.model_validate_json(target.read_text(encoding="utf-8"))

    def write(self, path: Path | str | None = None) -> Path:
        """Persist auth to JSON file. Returns path. Aliases used on disk."""
        target = Path(path) if path is not None else self.DEFAULT_PATH
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            self.model_dump_json(by_alias=True, indent=2), encoding="utf-8"
        )
        return target

    def to_universal(self) -> UniversalAuth:
        if self.openai is None:
            raise OAuthAccountMissingError(
                "OpenCodeAuth.openai source requires a non-empty oauth account"
            )
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
                expires=resolve_oauth_expires(u),
            ),
        )

    def merge_from_universal(self, u: UniversalAuth) -> OpenCodeAuth:
        account = (
            self.openai.model_copy(
                update={
                    "type": "oauth",
                    "access": u.access_token,
                    "refresh": u.refresh_token,
                    "expires": resolve_oauth_expires(u),
                    "account_id": u.account_id,
                }
            )
            if self.openai is not None
            else OAuthAccount(
                type="oauth",
                access=u.access_token,
                refresh=u.refresh_token,
                accountId=u.account_id,
                expires=resolve_oauth_expires(u),
            )
        )
        return self.model_copy(update={"openai": account})
