from __future__ import annotations

from pathlib import Path
from typing import ClassVar, Literal

from pydantic import BaseModel, ConfigDict, Field

DEFAULT_CODEX_PATH: Path = Path.home() / ".codex" / "auth.json"
DEFAULT_OPENCODE_PATH: Path = (
    Path.home() / ".local" / "share" / "opencode" / "auth.json"
)
DEFAULT_PI_PATH: Path = Path.home() / ".pi" / "agent" / "auth.json"


class CodexTokens(BaseModel):
    model_config = ConfigDict(extra="allow")

    id_token: str
    access_token: str
    refresh_token: str
    account_id: str


class CodexAuth(BaseModel):
    model_config = ConfigDict(extra="allow")

    DEFAULT_PATH: ClassVar[Path] = DEFAULT_CODEX_PATH

    auth_mode: Literal["chatgpt"]
    OPENAI_API_KEY: str | None
    tokens: CodexTokens
    last_refresh: str

    @classmethod
    def read(cls, path: Path | str | None = None) -> CodexAuth:
        """Load auth from JSON file. Defaults to ~/.codex/auth.json."""
        target = Path(path) if path is not None else cls.DEFAULT_PATH
        return cls.model_validate_json(target.read_text(encoding="utf-8"))

    def write(self, path: Path | str | None = None) -> Path:
        """Persist auth to JSON file. Defaults to ~/.codex/auth.json. Returns path."""
        target = Path(path) if path is not None else self.DEFAULT_PATH
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            self.model_dump_json(by_alias=True, indent=2), encoding="utf-8"
        )
        return target

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
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    type: Literal["oauth"]
    access: str
    refresh: str
    expires: int
    account_id: str = Field(alias="accountId")


class OpenCodeAuth(BaseModel):
    model_config = ConfigDict(extra="allow")

    DEFAULT_PATH: ClassVar[Path] = DEFAULT_OPENCODE_PATH

    openai: OAuthAccount

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

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    DEFAULT_PATH: ClassVar[Path] = DEFAULT_PI_PATH

    openai_codex: OAuthAccount = Field(alias="openai-codex")

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
