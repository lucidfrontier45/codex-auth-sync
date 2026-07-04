"""Auth type definitions, grouped by provider.

Public surface (re-exported from submodules for backward compatibility
with `from app.types import ...`):

- common: ``UniversalAuth``, ``OAuthAccount``, ``ExpiryResolutionError``,
  ``OAuthAccountMissingError``, ``resolve_oauth_expires``
- codex: ``CodexAuth``, ``CodexTokens``, ``DEFAULT_CODEX_PATH``
- opencode: ``OpenCodeAuth``, ``DEFAULT_OPENCODE_PATH``
- pi: ``PiAuth``, ``DEFAULT_PI_PATH``
"""

from __future__ import annotations

from .codex import DEFAULT_CODEX_PATH, CodexAuth, CodexTokens
from .common import (
    ExpiryResolutionError,
    OAuthAccount,
    OAuthAccountMissingError,
    Timestamp,
    UniversalAuth,
    resolve_oauth_expires,
)
from .opencode import DEFAULT_OPENCODE_PATH, OpenCodeAuth
from .pi import DEFAULT_PI_PATH, PiAuth

__all__ = [
    "DEFAULT_CODEX_PATH",
    "DEFAULT_OPENCODE_PATH",
    "DEFAULT_PI_PATH",
    "CodexAuth",
    "CodexTokens",
    "ExpiryResolutionError",
    "OAuthAccount",
    "OAuthAccountMissingError",
    "OpenCodeAuth",
    "PiAuth",
    "Timestamp",
    "UniversalAuth",
    "resolve_oauth_expires",
]
