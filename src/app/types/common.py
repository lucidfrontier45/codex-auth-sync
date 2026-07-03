from __future__ import annotations

import base64
import json
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "ExpiryResolutionError",
    "OAuthAccount",
    "OAuthAccountMissingError",
    "UniversalAuth",
    "resolve_oauth_expires",
]


class ExpiryResolutionError(ValueError):
    """Raised when an OAuth expiry cannot be resolved from universal auth."""


class OAuthAccountMissingError(ValueError):
    """Raised when a source auth file lacks a usable OAuth account."""


def _empty_oauth_account_to_none(value: object) -> object:
    if value is None:
        return None
    if isinstance(value, dict) and not value:
        return None
    return value


def _decode_jwt_payload(access_token: str) -> dict[str, object]:
    parts = access_token.split(".")
    if len(parts) != 3:
        raise ExpiryResolutionError("access token is not a JWT with three segments")

    payload = parts[1]
    padded = payload + "=" * (-len(payload) % 4)
    try:
        decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise ExpiryResolutionError(
            "access token payload is not valid base64url"
        ) from exc

    try:
        parsed = json.loads(decoded)
    except json.JSONDecodeError as exc:
        raise ExpiryResolutionError("access token payload is not valid JSON") from exc

    if not isinstance(parsed, dict):
        raise ExpiryResolutionError("access token payload is not a JSON object")
    return parsed


def resolve_oauth_expires(u: UniversalAuth) -> int:
    if u.expires is not None and u.expires > 0:
        return u.expires

    payload = _decode_jwt_payload(u.access_token)
    exp = payload.get("exp")
    if not isinstance(exp, int) or isinstance(exp, bool) or exp <= 0:
        raise ExpiryResolutionError(
            "access token payload is missing a positive integer exp claim"
        )
    return exp


class OAuthAccount(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    type: Literal["oauth"]
    access: str
    refresh: str
    expires: int
    account_id: str = Field(alias="accountId")


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
