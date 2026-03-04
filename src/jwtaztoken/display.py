"""Rich-based pretty-printing for decoded Azure OAuth tokens.

Separates all display / formatting concerns from the decoding logic
so that the CLI layer stays thin and the output can be evolved
independently.
"""

from __future__ import annotations

import json
from datetime import timedelta
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from jwtaztoken.claims import describe_claim
from jwtaztoken.decoder import DecodedToken, claims_to_json


def _fmt_timedelta(td: timedelta | None) -> str:
    if td is None:
        return "—"
    total_seconds = int(td.total_seconds())
    if total_seconds < 0:
        return f"-{_fmt_timedelta(-td)}"
    hours, remainder = divmod(total_seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    parts: list[str] = []
    if hours:
        parts.append(f"{hours}h")
    if minutes:
        parts.append(f"{minutes}m")
    parts.append(f"{seconds}s")
    return " ".join(parts)


def _fmt_value(value: Any) -> str:  # noqa: ANN401
    """Format a claim value for display."""
    if isinstance(value, dict):
        return json.dumps(value, indent=2, default=str)
    if isinstance(value, list):
        return ", ".join(str(v) for v in value)
    return str(value)


def render_token(
    token: DecodedToken,
    *,
    console: Console | None = None,
    show_raw: bool = False,
    json_output: bool = False,
    oidc_metadata: dict[str, object] | None = None,
) -> None:
    """Render a fully decoded token to the console using Rich."""
    con = console or Console()

    # -- JSON mode (machine-readable) ---------------------------------------
    if json_output:
        con.print(claims_to_json(token.claims))
        return

    # -- Header panel -------------------------------------------------------
    header_table = Table(show_header=False, box=None, padding=(0, 2))
    header_table.add_column("Key", style="bold cyan", min_width=14)
    header_table.add_column("Value")
    header_table.add_row("Algorithm", token.header.algorithm)
    header_table.add_row("Key ID (kid)", token.header.key_id or "—")
    header_table.add_row("Type", token.header.token_type or "—")
    if token.header.x5t:
        header_table.add_row("X.509 Thumbprint", token.header.x5t)
    if token.header.nonce:
        header_table.add_row("Nonce", token.header.nonce)
    for k, v in token.header.extra.items():
        header_table.add_row(k, _fmt_value(v))
    con.print(Panel(header_table, title="[bold]JOSE Header[/bold]", border_style="blue"))

    # -- Identity summary ---------------------------------------------------
    id_table = Table(show_header=False, box=None, padding=(0, 2))
    id_table.add_column("Key", style="bold green", min_width=18)
    id_table.add_column("Value")
    id_table.add_row("Token version", token.token_version or "—")
    id_table.add_row("Issuer", token.issuer or "—")
    id_table.add_row("Audience", _fmt_value(token.audience) if token.audience else "—")
    id_table.add_row("Tenant ID", token.tenant_id or "—")
    id_table.add_row("Subject", token.subject or "—")
    id_table.add_row("App / Client ID", token.app_id or "—")
    if token.scopes:
        id_table.add_row("Scopes", " ".join(token.scopes))
    if token.roles:
        id_table.add_row("Roles", ", ".join(token.roles))
    con.print(Panel(id_table, title="[bold]Identity Summary[/bold]", border_style="green"))

    # -- Lifetime -----------------------------------------------------------
    lt = token.lifetime
    lt_table = Table(show_header=False, box=None, padding=(0, 2))
    lt_table.add_column("Key", style="bold yellow", min_width=18)
    lt_table.add_column("Value")
    lt_table.add_row("Issued at", str(lt.issued_at) if lt.issued_at else "—")
    lt_table.add_row("Not before", str(lt.not_before) if lt.not_before else "—")
    lt_table.add_row("Expires at", str(lt.expires_at) if lt.expires_at else "—")
    lt_table.add_row("Lifetime", _fmt_timedelta(lt.lifetime))

    if lt.is_expired:
        status = Text("EXPIRED", style="bold red")
        lt_table.add_row("Status", status)
        lt_table.add_row("Expired ago", _fmt_timedelta(lt.time_since_expiry))
    else:
        status = Text("VALID", style="bold green")
        lt_table.add_row("Status", status)
        lt_table.add_row("Time remaining", _fmt_timedelta(lt.time_remaining))

    con.print(Panel(lt_table, title="[bold]Token Lifetime[/bold]", border_style="yellow"))

    # -- All claims with descriptions ---------------------------------------
    claims_table = Table(
        title="All Claims",
        show_lines=True,
        title_style="bold magenta",
    )
    claims_table.add_column("Claim", style="cyan", min_width=12)
    claims_table.add_column("Value", overflow="fold")
    claims_table.add_column("Description", style="dim", max_width=50)

    for claim_name, claim_value in sorted(token.claims.items()):
        desc = describe_claim(claim_name)
        claims_table.add_row(claim_name, _fmt_value(claim_value), desc)

    con.print(claims_table)

    # -- OIDC metadata (if available) ---------------------------------------
    if oidc_metadata:
        tree = Tree("[bold]OpenID Connect Configuration[/bold]")
        for key, value in sorted(oidc_metadata.items()):
            if isinstance(value, list):
                branch = tree.add(f"[cyan]{key}[/cyan]")
                for item in value:
                    branch.add(str(item))
            else:
                tree.add(f"[cyan]{key}[/cyan]: {value}")
        con.print(Panel(tree, border_style="magenta"))

    # -- Raw token ----------------------------------------------------------
    if show_raw:
        con.print(
            Panel(
                token.raw,
                title="[bold]Raw Token[/bold]",
                border_style="dim",
            )
        )
