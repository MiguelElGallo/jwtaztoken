"""Fetch Azure OAuth tokens using the Azure CLI (`az`).

Shells out to `az account get-access-token` so that the user does not
need to manage credentials manually — they just need to be logged in
via `az login`.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass

import httpx


@dataclass(frozen=True)
class AzTokenResult:
    """Result of calling `az account get-access-token`."""

    access_token: str
    expires_on: str
    subscription: str
    tenant: str
    token_type: str


class AzCliError(Exception):
    """Raised when the Azure CLI command fails."""


# ---------------------------------------------------------------------------
# Token acquisition
# ---------------------------------------------------------------------------

_DEFAULT_RESOURCE = "https://management.azure.com/"


def fetch_token(
    resource: str = _DEFAULT_RESOURCE,
    scopes: list[str] | None = None,
    tenant: str | None = None,
) -> AzTokenResult:
    """Acquire an access token from the Azure CLI.

    Parameters
    ----------
    resource:
        The resource / audience URI to request a token for.
    scopes:
        Optional scopes (used with `--scope` flag). If provided, they
        override *resource*.
    tenant:
        Optional tenant ID to target a specific directory.

    Returns
    -------
    AzTokenResult with the raw access token and metadata.
    """
    cmd: list[str] = ["az", "account", "get-access-token", "--output", "json"]

    if scopes:
        for scope in scopes:
            cmd.extend(["--scope", scope])
    else:
        cmd.extend(["--resource", resource])

    if tenant:
        cmd.extend(["--tenant", tenant])

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
    except FileNotFoundError:
        raise AzCliError(
            "Azure CLI (`az`) not found. "
            "Install it from https://aka.ms/installazurecli"
        ) from None
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.strip() if exc.stderr else "unknown error"
        raise AzCliError(f"az CLI failed: {stderr}") from exc
    except subprocess.TimeoutExpired:
        raise AzCliError("az CLI timed out after 30 seconds") from None

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise AzCliError(f"Failed to parse az CLI output: {exc}") from exc

    return AzTokenResult(
        access_token=data["accessToken"],
        expires_on=data.get("expiresOn", ""),
        subscription=data.get("subscription", ""),
        tenant=data.get("tenant", ""),
        token_type=data.get("tokenType", "Bearer"),
    )


# ---------------------------------------------------------------------------
# OIDC metadata discovery
# ---------------------------------------------------------------------------


def fetch_openid_config(tenant_id: str) -> dict[str, object]:
    """Fetch the OpenID Connect discovery document for a given tenant.

    This is useful for showing the JWKS URI, authorization endpoint, and
    other metadata related to the token issuer.
    """
    url = (
        f"https://login.microsoftonline.com/{tenant_id}"
        "/v2.0/.well-known/openid-configuration"
    )
    try:
        resp = httpx.get(url, timeout=10, follow_redirects=True)
        resp.raise_for_status()
        result: dict[str, object] = resp.json()
        return result
    except httpx.HTTPError:
        # Non-fatal: we still show the token even if metadata is unreachable
        from rich.console import Console as _Console

        _Console(stderr=True).print(
            f"[yellow]Warning: could not fetch OIDC metadata from {url}[/yellow]"
        )
        return {}
