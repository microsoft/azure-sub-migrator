"""CLI interface for tenova.

Built with *Click* for a clean, extensible command structure.
Each major capability (scan, plan, export, transfer, …) is a sub-command
under the top-level ``tenova`` group.
"""

from __future__ import annotations

import sys
from pathlib import Path

import click
from rich.console import Console

from tenova import __version__
from tenova.auth import AuthMethod, get_credential
from tenova.config import MigrationConfig
from tenova.logger import setup_logging

console = Console()

# ──────────────────────────────────────────────────────────────────────
# CLI root group
# ──────────────────────────────────────────────────────────────────────

@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(version=__version__, prog_name="tenova")
@click.option(
    "-v", "--verbose",
    count=True,
    help="Increase verbosity (-v for INFO, -vv for DEBUG).",
)
@click.option(
    "--log-file",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Write logs to a file in addition to stderr.",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Path to a YAML configuration file.",
)
@click.option(
    "--auth-method",
    type=click.Choice([m.value for m in AuthMethod], case_sensitive=False),
    default=AuthMethod.CLI.value,
    show_default=True,
    help="Azure authentication method.",
)
@click.option("--tenant-id", default=None, help="Azure AD tenant ID (source).")
@click.option("--client-id", default=None, help="Service-principal client ID.")
@click.option("--client-secret", default=None, help="Service-principal client secret.")
@click.option(
    "--output-dir",
    type=click.Path(path_type=Path),
    default=None,
    help="Directory for migration output artifacts.",
)
@click.pass_context
def cli(
    ctx: click.Context,
    verbose: int,
    log_file: Path | None,
    config_path: Path | None,
    auth_method: str,
    tenant_id: str | None,
    client_id: str | None,
    client_secret: str | None,
    output_dir: Path | None,
) -> None:
    """Tenova – Azure Tenant-to-Tenant Migration Tool.

    Migrate Azure subscriptions and resources from one Microsoft Entra
    (Azure AD) tenant to another.
    """
    setup_logging(verbosity=verbose, log_file=log_file)

    # Build configuration (YAML → env → CLI flags, with CLI taking precedence)
    if config_path:
        cfg = MigrationConfig.from_yaml(config_path)
    else:
        cfg = MigrationConfig.from_env()

    # Override with explicit CLI flags
    cfg.auth_method = auth_method
    if tenant_id:
        cfg.source_tenant_id = tenant_id
    if client_id:
        cfg.client_id = client_id
    if client_secret:
        cfg.client_secret = client_secret
    if output_dir:
        cfg.output_dir = str(output_dir)

    ctx.ensure_object(dict)
    ctx.obj["config"] = cfg


# ──────────────────────────────────────────────────────────────────────
# Sub-commands
# ──────────────────────────────────────────────────────────────────────

@cli.command()
@click.pass_context
def login(ctx: click.Context) -> None:
    """Authenticate to Azure and verify credentials."""
    cfg: MigrationConfig = ctx.obj["config"]
    console.print("[bold cyan]Authenticating to Azure…[/]")
    try:
        credential = get_credential(
            method=cfg.auth_method,
            tenant_id=cfg.source_tenant_id or None,
            client_id=cfg.client_id or None,
            client_secret=cfg.client_secret or None,
        )
        console.print("[bold green]✔ Authentication successful.[/]")
        ctx.obj["credential"] = credential
    except Exception as exc:
        console.print(f"[bold red]✘ Authentication failed:[/] {exc}")
        sys.exit(1)


@cli.command("list-subs")
@click.pass_context
def list_subscriptions(ctx: click.Context) -> None:
    """List Azure subscriptions accessible with current credentials."""
    cfg: MigrationConfig = ctx.obj["config"]
    try:
        credential = get_credential(
            method=cfg.auth_method,
            tenant_id=cfg.source_tenant_id or None,
            client_id=cfg.client_id or None,
            client_secret=cfg.client_secret or None,
        )
    except Exception as exc:
        console.print(f"[bold red]✘ Authentication failed:[/] {exc}")
        sys.exit(1)

    from tenova.scanner import list_subscriptions as _list_subs

    console.print("[bold cyan]Fetching subscriptions…[/]")
    subs = _list_subs(credential)
    if not subs:
        console.print("[yellow]No subscriptions found.[/]")
        return

    from rich.table import Table

    table = Table(title="Azure Subscriptions")
    table.add_column("#", style="dim", width=4)
    table.add_column("Subscription ID", style="cyan")
    table.add_column("Display Name")
    table.add_column("State")
    for idx, sub in enumerate(subs, 1):
        table.add_row(
            str(idx),
            sub["subscription_id"],
            sub["display_name"],
            sub["state"],
        )
    console.print(table)


@cli.command()
@click.option("--subscription-id", "-s", required=True, help="Subscription ID to scan.")
@click.pass_context
def scan(ctx: click.Context, subscription_id: str) -> None:
    """Scan a subscription and classify resources for cross-tenant transfer."""
    cfg: MigrationConfig = ctx.obj["config"]
    cfg.subscription_id = subscription_id

    try:
        credential = get_credential(
            method=cfg.auth_method,
            tenant_id=cfg.source_tenant_id or None,
            client_id=cfg.client_id or None,
            client_secret=cfg.client_secret or None,
        )
    except Exception as exc:
        console.print(f"[bold red]✘ Authentication failed:[/] {exc}")
        sys.exit(1)

    from tenova.scanner import scan_subscription

    console.print(f"[bold cyan]Scanning subscription {subscription_id}…[/]")
    report = scan_subscription(credential, subscription_id)

    from rich.table import Table

    # Transfer-safe
    table_safe = Table(title="Transfer-Safe Resources (no action needed)")
    table_safe.add_column("Type", style="green")
    table_safe.add_column("Name")
    table_safe.add_column("Resource Group")
    for r in report["transfer_safe"]:
        table_safe.add_row(r["type"], r["name"], r["resource_group"])

    # Requires action
    table_action = Table(title="Requires-Action Resources (tenant-bound dependencies)")
    table_action.add_column("Type", style="red")
    table_action.add_column("Name")
    table_action.add_column("Resource Group")
    table_action.add_column("Timing", style="cyan")
    table_action.add_column("Required Action", style="yellow")
    table_action.add_column("MS Learn", style="blue")
    for r in report["requires_action"]:
        timing = r.get("timing", "post").upper()
        pre = r.get("pre_action", "")
        post = r.get("post_action", "")
        parts = []
        if pre:
            parts.append(f"[PRE] {pre}")
        if post:
            parts.append(f"[POST] {post}")
        doc_url = r.get("doc_url", "")
        doc_link = f"[link={doc_url}]Docs ↗[/link]" if doc_url else "—"
        table_action.add_row(r["type"], r["name"], r["resource_group"], timing, "\n".join(parts) or "—", doc_link)

    console.print(table_safe)
    console.print(table_action)

    # Transfer notes — tenant-level warnings
    if report.get("transfer_notes"):
        from rich.panel import Panel

        notes_lines = []
        for key, note in report["transfer_notes"].items():
            notes_lines.append(f"[bold yellow]⚠ {key}:[/] {note}")
        console.print(Panel(
            "\n\n".join(notes_lines),
            title="[bold]Tenant-Level Impacts[/]",
            subtitle="These apply to EVERY cross-tenant transfer",
            border_style="yellow",
        ))

    console.print(
        f"\n[bold]Summary:[/] {len(report['transfer_safe'])} transfer-safe, "
        f"{len(report['requires_action'])} requires-action resources."
    )


@cli.command()
@click.option("--subscription-id", "-s", required=True, help="Subscription ID.")
@click.option("--target-tenant-id", "-t", required=True, help="Target tenant ID.")
@click.pass_context
def plan(ctx: click.Context, subscription_id: str, target_tenant_id: str) -> None:
    """Scan a subscription and generate a migration plan report."""
    cfg: MigrationConfig = ctx.obj["config"]
    cfg.subscription_id = subscription_id
    cfg.target_tenant_id = target_tenant_id

    try:
        credential = get_credential(
            method=cfg.auth_method,
            tenant_id=cfg.source_tenant_id or None,
            client_id=cfg.client_id or None,
            client_secret=cfg.client_secret or None,
        )
    except Exception as exc:
        console.print(f"[bold red]✘ Authentication failed:[/] {exc}")
        sys.exit(1)

    from tenova.migration_plan import generate_migration_plan

    console.print("[bold cyan]Generating migration plan…[/]")
    output_path = generate_migration_plan(
        credential=credential,
        config=cfg,
    )
    console.print(f"[bold green]✔ Migration plan saved to:[/] {output_path}")


@cli.command()
@click.option("--subscription-id", "-s", required=True, help="Subscription ID to transfer.")
@click.option("--target-tenant-id", "-t", required=True, help="Target tenant ID.")
@click.option("--dry-run", is_flag=True, default=False, help="Preview without executing.")
@click.pass_context
def transfer(ctx: click.Context, subscription_id: str, target_tenant_id: str, dry_run: bool) -> None:
    """Initiate the subscription transfer to the target tenant."""
    cfg: MigrationConfig = ctx.obj["config"]
    cfg.subscription_id = subscription_id
    cfg.target_tenant_id = target_tenant_id
    cfg.dry_run = dry_run

    try:
        credential = get_credential(
            method=cfg.auth_method,
            tenant_id=cfg.source_tenant_id or None,
            client_id=cfg.client_id or None,
            client_secret=cfg.client_secret or None,
        )
    except Exception as exc:
        console.print(f"[bold red]✘ Authentication failed:[/] {exc}")
        sys.exit(1)

    from tenova.transfer import initiate_transfer

    if dry_run:
        console.print("[yellow]Dry-run mode — no changes will be made.[/]")

    console.print(f"[bold cyan]Transferring subscription {subscription_id} → tenant {target_tenant_id}…[/]")
    initiate_transfer(credential=credential, config=cfg)
    console.print("[bold green]✔ Transfer initiated.[/]")


@cli.command("export-rbac")
@click.option("--subscription-id", "-s", required=True, help="Subscription ID.")
@click.option(
    "--output-dir", "-o",
    type=click.Path(path_type=Path),
    default="migration_output",
    show_default=True,
    help="Directory to save the RBAC export file.",
)
@click.pass_context
def export_rbac_cmd(ctx: click.Context, subscription_id: str, output_dir: Path) -> None:
    """Export role assignments, custom roles, and managed identities to JSON.

    Run this BEFORE the subscription transfer — role assignments and custom
    roles are permanently deleted during transfer.
    """
    cfg: MigrationConfig = ctx.obj["config"]
    try:
        credential = get_credential(
            method=cfg.auth_method,
            tenant_id=cfg.source_tenant_id or None,
            client_id=cfg.client_id or None,
            client_secret=cfg.client_secret or None,
        )
    except Exception as exc:
        console.print(f"[bold red]✘ Authentication failed:[/] {exc}")
        sys.exit(1)

    from tenova.rbac import export_rbac

    console.print(f"[bold cyan]Exporting RBAC for subscription {subscription_id}…[/]")
    filepath = export_rbac(credential, subscription_id, output_dir)
    console.print(f"[bold green]✔ RBAC exported to:[/] {filepath}")

    # Show summary
    import json

    data = json.loads(filepath.read_text(encoding="utf-8"))
    summary = data.get("summary", {})

    from rich.table import Table

    table = Table(title="RBAC Export Summary")
    table.add_column("Category", style="cyan")
    table.add_column("Count", justify="right", style="bold")
    table.add_row("Role Assignments", str(summary.get("role_assignment_count", 0)))
    table.add_row("Custom Roles", str(summary.get("custom_role_count", 0)))
    table.add_row("Managed Identities", str(summary.get("managed_identity_count", 0)))
    console.print(table)
    console.print("\n[yellow]⚠ Keep this file safe — you will need it to restore RBAC after transfer.[/]")


@cli.command("import-rbac")
@click.option("--subscription-id", "-s", required=True, help="Target subscription ID.")
@click.option(
    "--export-file", "-f",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
    help="Path to the RBAC export JSON file.",
)
@click.option(
    "--mapping-file", "-m",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Optional JSON file mapping old principal IDs → new principal IDs.",
)
@click.pass_context
def import_rbac_cmd(
    ctx: click.Context,
    subscription_id: str,
    export_file: Path,
    mapping_file: Path | None,
) -> None:
    """Import RBAC from a previously exported JSON file.

    Run this AFTER the subscription transfer to recreate role assignments
    and custom roles in the target tenant.
    """
    cfg: MigrationConfig = ctx.obj["config"]
    try:
        credential = get_credential(
            method=cfg.auth_method,
            tenant_id=cfg.source_tenant_id or None,
            client_id=cfg.client_id or None,
            client_secret=cfg.client_secret or None,
        )
    except Exception as exc:
        console.print(f"[bold red]✘ Authentication failed:[/] {exc}")
        sys.exit(1)

    import json

    from tenova.rbac import import_rbac

    mapping: dict[str, str] | None = None
    if mapping_file:
        mapping = json.loads(mapping_file.read_text(encoding="utf-8"))
        console.print(f"[dim]Using principal mapping from {mapping_file} ({len(mapping)} entries)[/]")

    console.print(f"[bold cyan]Importing RBAC into subscription {subscription_id}…[/]")
    results = import_rbac(credential, subscription_id, export_file, mapping)

    from rich.table import Table

    table = Table(title="RBAC Import Results")
    table.add_column("Metric", style="cyan")
    table.add_column("Count", justify="right", style="bold")
    table.add_row("[green]Assignments Created[/]", str(results["role_assignments_created"]))
    table.add_row("[yellow]Assignments Skipped[/]", str(results["role_assignments_skipped"]))
    table.add_row("[red]Assignments Failed[/]", str(results["role_assignments_failed"]))
    table.add_row("[green]Custom Roles Created[/]", str(results["custom_roles_created"]))
    table.add_row("[red]Custom Roles Failed[/]", str(results["custom_roles_failed"]))
    console.print(table)

    if results["errors"]:
        console.print(f"\n[red]Errors ({len(results['errors'])}):[/]")
        for err in results["errors"]:
            console.print(f"  • {err}")


@cli.command("readiness-check")
@click.option("--subscription-id", "-s", required=True, help="Subscription ID to check.")
@click.pass_context
def readiness_check_cmd(ctx: click.Context, subscription_id: str) -> None:
    """Run a pre-transfer readiness check for blockers and warnings.

    Validates whether the subscription is safe to transfer by checking
    for known blockers (⛔) and warnings (⚠️).
    """
    cfg: MigrationConfig = ctx.obj["config"]
    try:
        credential = get_credential(
            method=cfg.auth_method,
            tenant_id=cfg.source_tenant_id or None,
            client_id=cfg.client_id or None,
            client_secret=cfg.client_secret or None,
        )
    except Exception as exc:
        console.print(f"[bold red]✘ Authentication failed:[/] {exc}")
        sys.exit(1)

    from tenova.readiness import check_readiness

    console.print(f"[bold cyan]Running readiness check for subscription {subscription_id}…[/]")
    result = check_readiness(credential, subscription_id)

    from rich.table import Table
    from rich.panel import Panel

    # Overall verdict
    if result["ready"]:
        console.print(Panel(
            "[bold green]✔ READY TO TRANSFER[/]\n\n"
            "No blockers found. Complete the warnings below before proceeding.",
            title="Readiness Verdict",
            border_style="green",
        ))
    else:
        console.print(Panel(
            "[bold red]✘ NOT READY — BLOCKERS FOUND[/]\n\n"
            "You MUST resolve ALL blockers before transferring the subscription.\n"
            "Attempting to transfer now may result in data loss or transfer failure.",
            title="Readiness Verdict",
            border_style="red",
        ))

    # Blockers
    if result["blockers"]:
        table_b = Table(title=f"⛔ Blockers ({len(result['blockers'])})", show_lines=True)
        table_b.add_column("Resource", style="red")
        table_b.add_column("Type", style="dim")
        table_b.add_column("Issue", style="yellow")
        table_b.add_column("Action Required")
        for b in result["blockers"]:
            table_b.add_row(b["name"], b["type"], b["issue"], b["action"])
        console.print(table_b)

    # Warnings
    if result["warnings"]:
        table_w = Table(title=f"⚠️  Warnings ({len(result['warnings'])})", show_lines=True)
        table_w.add_column("Resource", style="yellow")
        table_w.add_column("Type", style="dim")
        table_w.add_column("Issue")
        table_w.add_column("Action Required")
        for w in result["warnings"]:
            table_w.add_row(w["name"], w["type"], w["issue"], w["action"])
        console.print(table_w)

    # Info items
    if result["info"]:
        table_i = Table(title=f"ℹ️  Information ({len(result['info'])})")
        table_i.add_column("Category", style="cyan")
        table_i.add_column("Details")
        for i in result["info"]:
            table_i.add_row(i["category"], i["detail"])
        console.print(table_i)

    # Summary line
    console.print(
        f"\n[bold]Summary:[/] {len(result['blockers'])} blocker(s), "
        f"{len(result['warnings'])} warning(s), {len(result['info'])} info item(s)."
    )


# ──────────────────────────────────────────────────────────────────────
# Entry-point
# ──────────────────────────────────────────────────────────────────────

def main() -> None:
    """Package entry-point wrapper."""
    cli(obj={})


if __name__ == "__main__":
    main()
