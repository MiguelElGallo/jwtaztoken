"""JWT decoding and metadata extraction.

Handles decoding Azure OAuth JWTs (both with and without signature
verification), extracting header information, computing token
lifetime and validity windows, and enriching claims with descriptions.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt


@dataclass(frozen=True)
class TokenHeader:
    """Decoded JOSE header of the JWT."""

    algorithm: str
    key_id: str | None
    token_type: str | None
    x5t: str | None  # X.509 cert thumbprint
    nonce: str | None
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class TokenLifetime:
    """Computed lifetime / validity information."""

    issued_at: datetime | None
    not_before: datetime | None
    expires_at: datetime | None
    lifetime: timedelta | None
    is_expired: bool
    time_remaining: timedelta | None
    time_since_expiry: timedelta | None


@dataclass(frozen=True)
class DecodedToken:
    """Full decoded representation of a JWT."""

    raw: str
    header: TokenHeader
    claims: dict[str, Any]
    lifetime: TokenLifetime
    token_version: str | None
    issuer: str | None
    audience: str | list[str] | None
    tenant_id: str | None
    subject: str | None
    scopes: list[str]
    roles: list[str]
    app_id: str | None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _safe_ts(value: int | float | str | None) -> datetime | None:
    """Convert a Unix timestamp (int/float) to a UTC datetime, or None."""
    if value is None:
        return None
    try:
        return datetime.fromtimestamp(float(value), tz=UTC)
    except (TypeError, ValueError, OSError):
        return None


_HEADER_KNOWN_KEYS = frozenset({"alg", "kid", "typ", "x5t", "nonce"})


def _extract_header(raw_header: dict[str, Any]) -> TokenHeader:
    """Parse the JOSE header into a structured `TokenHeader`."""
    extra = {k: v for k, v in raw_header.items() if k not in _HEADER_KNOWN_KEYS}
    return TokenHeader(
        algorithm=raw_header.get("alg", "unknown"),
        key_id=raw_header.get("kid"),
        token_type=raw_header.get("typ"),
        x5t=raw_header.get("x5t"),
        nonce=raw_header.get("nonce"),
        extra=extra,
    )


def _compute_lifetime(claims: dict[str, Any]) -> TokenLifetime:
    """Derive token validity window and expiry status from timestamp claims."""
    now = datetime.now(tz=UTC)
    issued_at = _safe_ts(claims.get("iat"))
    not_before = _safe_ts(claims.get("nbf"))
    expires_at = _safe_ts(claims.get("exp"))

    lifetime: timedelta | None = None
    if issued_at and expires_at:
        lifetime = expires_at - issued_at

    is_expired = expires_at < now if expires_at else False
    time_remaining: timedelta | None = None
    time_since_expiry: timedelta | None = None
    if expires_at:
        if is_expired:
            time_since_expiry = now - expires_at
        else:
            time_remaining = expires_at - now

    return TokenLifetime(
        issued_at=issued_at,
        not_before=not_before,
        expires_at=expires_at,
        lifetime=lifetime,
        is_expired=is_expired,
        time_remaining=time_remaining,
        time_since_expiry=time_since_expiry,
    )


def _parse_scopes(claims: dict[str, Any]) -> list[str]:
    scp = claims.get("scp", "")
    if isinstance(scp, str) and scp:
        return scp.split()
    if isinstance(scp, list):
        return [str(s) for s in scp]
    return []


def _parse_roles(claims: dict[str, Any]) -> list[str]:
    roles = claims.get("roles", [])
    if isinstance(roles, list):
        return [str(r) for r in roles]
    return []


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def decode_token(raw_token: str) -> DecodedToken:
    """Decode an Azure OAuth JWT **without** signature verification.

    We deliberately skip verification so the CLI can inspect any token
    regardless of whether we have the signing keys.
    """
    raw_token = raw_token.strip()

    # Decode header
    raw_header: dict[str, Any] = jwt.get_unverified_header(raw_token)
    header = _extract_header(raw_header)

    # Decode payload (no verification)
    # Use the algorithm from the header so we accept any token regardless of alg
    alg = raw_header.get("alg", "RS256")
    claims: dict[str, Any] = jwt.decode(
        raw_token,
        algorithms=[alg],
        options={"verify_signature": False, "verify_aud": False, "verify_exp": False},
    )

    lifetime = _compute_lifetime(claims)

    return DecodedToken(
        raw=raw_token,
        header=header,
        claims=claims,
        lifetime=lifetime,
        token_version=claims.get("ver"),
        issuer=claims.get("iss"),
        audience=claims.get("aud"),
        tenant_id=claims.get("tid"),
        subject=claims.get("sub"),
        scopes=_parse_scopes(claims),
        roles=_parse_roles(claims),
        app_id=claims.get("appid") or claims.get("azp"),
    )


def claims_to_json(claims: dict[str, Any]) -> str:
    """Serialize claims to pretty-printed JSON."""
    return json.dumps(claims, indent=2, default=str)
