"""Typer CLI application for jwtaztoken.

This module wires together the decoder, fetcher, and display modules
into a cohesive command-line interface with two primary commands:

- ``decode``  — decode a token passed as an argument or via stdin
- ``fetch``   — acquire a token from the Azure CLI and decode it
"""

from __future__ import annotations

import sys
from typing import Annotated

import jwt as pyjwt
import typer
from rich.console import Console

from jwtaztoken.decoder import DecodedToken, decode_token
from jwtaztoken.display import render_token
from jwtaztoken.fetcher import AzCliError, fetch_openid_config, fetch_token

app = typer.Typer(
    name="jwtaztoken",
    help="Inspect Azure OAuth / JWT tokens from the command line.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)

console = Console(stderr=True)


def _render(
    token: DecodedToken,
    *,
    show_raw: bool,
    json_output: bool,
    show_oidc: bool,
) -> None:
    """Shared rendering logic used by both commands."""
    oidc_meta: dict[str, object] | None = None
    if show_oidc and token.tenant_id:
        console.print("[dim]Fetching OIDC discovery metadata…[/dim]")
        oidc_meta = fetch_openid_config(token.tenant_id)

    out = Console()  # stdout
    render_token(
        token,
        console=out,
        show_raw=show_raw,
        json_output=json_output,
        oidc_metadata=oidc_meta,
    )


# ---------------------------------------------------------------------------
# decode command
# ---------------------------------------------------------------------------


@app.command()
def decode(
    token: Annotated[
        str | None,
        typer.Argument(
            help="The raw JWT string. If omitted, reads from stdin.",
        ),
    ] = None,
    *,
    raw: Annotated[
        bool,
        typer.Option("--raw", "-r", help="Also print the raw token string."),
    ] = False,
    json_output: Annotated[
        bool,
        typer.Option("--json", "-j", help="Output claims as JSON."),
    ] = False,
    oidc: Annotated[
        bool,
        typer.Option("--oidc", help="Fetch and display OIDC discovery metadata."),
    ] = False,
) -> None:
    """Decode and display an Azure OAuth JWT.

    Pass the token as a positional argument, or pipe it via stdin:

        az account get-access-token --query accessToken -o tsv | jwtaztoken decode
    """
    if token is None:
        if sys.stdin.isatty():
            console.print(
                "[red]Error:[/red] No token provided. "
                "Pass it as an argument or pipe via stdin."
            )
            raise typer.Exit(code=1)
        token = sys.stdin.readline().strip()

    if not token:
        console.print("[red]Error:[/red] Empty token.")
        raise typer.Exit(code=1)

    try:
        decoded = decode_token(token)
    except pyjwt.exceptions.PyJWTError as exc:
        console.print(f"[red]Error decoding token:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    _render(decoded, show_raw=raw, json_output=json_output, show_oidc=oidc)


# ---------------------------------------------------------------------------
# fetch command
# ---------------------------------------------------------------------------


@app.command()
def fetch(
    *,
    resource: Annotated[
        str,
        typer.Option(
            "--resource",
            "-R",
            help="Resource URI to request the token for.",
        ),
    ] = "https://management.azure.com/",
    scope: Annotated[
        list[str] | None,
        typer.Option(
            "--scope",
            "-s",
            help="Scope(s) to request. Overrides --resource if given.",
        ),
    ] = None,
    tenant: Annotated[
        str | None,
        typer.Option(
            "--tenant",
            "-t",
            help="Tenant ID to target a specific directory.",
        ),
    ] = None,
    raw: Annotated[
        bool,
        typer.Option("--raw", "-r", help="Also print the raw token string."),
    ] = False,
    json_output: Annotated[
        bool,
        typer.Option("--json", "-j", help="Output claims as JSON."),
    ] = False,
    oidc: Annotated[
        bool,
        typer.Option("--oidc", help="Fetch and display OIDC discovery metadata."),
    ] = False,
) -> None:
    """Fetch an access token from the Azure CLI and decode it.

    Requires that you are logged in via `az login`.
    """
    try:
        result = fetch_token(
            resource=resource,
            scopes=scope,
            tenant=tenant,
        )
    except AzCliError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    try:
        decoded = decode_token(result.access_token)
    except pyjwt.exceptions.PyJWTError as exc:
        console.print(f"[red]Error decoding token:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    _render(decoded, show_raw=raw, json_output=json_output, show_oidc=oidc)
