from __future__ import annotations

from pathlib import Path
from typing import ClassVar, Literal

from pydantic import BaseModel, ConfigDict

from .common import UniversalAuth

__all__ = ["DEFAULT_CODEX_PATH", "CodexAuth", "CodexTokens"]


DEFAULT_CODEX_PATH: Path = Path.home() / ".codex" / "auth.json"


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
            auth_mode=u.auth_mode or "chatgpt",
            OPENAI_API_KEY=u.openai_api_key,
            tokens=CodexTokens(
                id_token=u.id_token or "",
                access_token=u.access_token,
                refresh_token=u.refresh_token,
                account_id=u.account_id,
            ),
            last_refresh=u.last_refresh or "",
        )

    def merge_from_universal(self, u: UniversalAuth) -> CodexAuth:
        return self.model_copy(
            update={
                "auth_mode": u.auth_mode or self.auth_mode,
                "OPENAI_API_KEY": (
                    u.openai_api_key
                    if u.openai_api_key is not None
                    else self.OPENAI_API_KEY
                ),
                "tokens": self.tokens.model_copy(
                    update={
                        "id_token": u.id_token or self.tokens.id_token,
                        "access_token": u.access_token,
                        "refresh_token": u.refresh_token,
                        "account_id": u.account_id,
                    }
                ),
                "last_refresh": u.last_refresh or self.last_refresh,
            }
        )
