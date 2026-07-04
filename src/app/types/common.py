from __future__ import annotations

import base64
import json
from typing import Annotated, Literal

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, model_serializer

__all__ = [
    "ExpiryResolutionError",
    "OAuthAccount",
    "OAuthAccountMissingError",
    "Timestamp",
    "UniversalAuth",
    "resolve_oauth_expires",
]


_EPOCH_2026_MS: int = 1_767_254_400_000
_EPOCH_9999_MS: int = 253_402_300_799_000


def _normalize_timestamp(v: int) -> int:
    ms = v if v >= _EPOCH_2026_MS else v * 1000
    if not _EPOCH_2026_MS <= ms <= _EPOCH_9999_MS:
        raise ValueError(f"Timestamp out of range [2026, 9999]: {ms}ms")
    return ms


class Timestamp(BaseModel):
    model_config = ConfigDict(frozen=True)

    value: Annotated[int, BeforeValidator(_normalize_timestamp)]

    @model_serializer(mode="wrap")
    def _serialize(self, handler):
        return handler(self)["value"]

    @classmethod
    def __get_pydantic_core_schema__(cls, source, handler):
        from pydantic_core import core_schema

        model_schema = handler(source)

        def preprocess(v: object) -> object:
            if isinstance(v, Timestamp):
                return v
            if isinstance(v, int) and not isinstance(v, bool):
                return {"value": v}
            return v

        return core_schema.no_info_before_validator_function(
            preprocess,
            model_schema,
            serialization=core_schema.plain_serializer_function_ser_schema(
                lambda ts: ts.value,
                return_schema=core_schema.int_schema(),
                when_used="always",
            ),
        )


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


def resolve_oauth_expires(u: UniversalAuth) -> Timestamp:
    if u.expires is not None and u.expires.value > 0:
        return u.expires

    payload = _decode_jwt_payload(u.access_token)
    exp = payload.get("exp")
    if not isinstance(exp, int) or isinstance(exp, bool) or exp <= 0:
        raise ExpiryResolutionError(
            "access token payload is missing a positive integer exp claim"
        )
    return Timestamp(value=exp)


class OAuthAccount(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    type: Literal["oauth"]
    access: str
    refresh: str
    expires: Timestamp
    account_id: str = Field(alias="accountId")


class UniversalAuth(BaseModel):
    """Unified auth representation convertible from/to CodexAuth, OpenCodeAuth, PiAuth."""

    access_token: str
    refresh_token: str
    account_id: str
    expires: Timestamp | None = None
    id_token: str | None = None
    last_refresh: str | None = None
    openai_api_key: str | None = None
    auth_mode: Literal["chatgpt"] | None = None
