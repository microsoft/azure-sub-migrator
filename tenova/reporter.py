"""Migration-plan reporter — writes human-readable Markdown reports.

Report sections reflect cross-tenant subscription transfer semantics:
all resources move with the subscription, but some require pre-transfer
preparation and/or post-transfer reconfiguration due to tenant-bound
dependencies.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tenova.logger import get_logger

logger = get_logger("reporter")


def write_plan_report(plan: dict[str, Any], output_path: Path) -> Path:
    """Write a Markdown migration-plan report to *output_path*.

    Parameters
    ----------
    plan:
        The migration-plan dict produced by ``generate_migration_plan``.
    output_path:
        Destination ``.md`` file.

    Returns
    -------
    Path to the written file.
    """
    lines: list[str] = []
    _h = lines.append  # shorthand

    _h("# Tenova Migration Plan\n")
    _h(f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
    _h(f"**Subscription:** `{plan.get('subscription_id', 'N/A')}`  ")
    _h(f"**Source Tenant:** `{plan.get('source_tenant_id', 'N/A')}`  ")
    _h(f"**Target Tenant:** `{plan.get('target_tenant_id', 'N/A')}`\n")

    # Summary
    transfer_safe = plan.get("transfer_safe_resources", [])
    requires_action = plan.get("requires_action_resources", [])
    _h("## Summary\n")
    _h("| Category | Count |")
    _h("|----------|------:|")
    _h(f"| Transfer-safe resources | {len(transfer_safe)} |")
    _h(f"| Requires-action resources | {len(requires_action)} |")
    _h(f"| **Total** | **{len(transfer_safe) + len(requires_action)}** |\n")

    _h("> **Note:** All resources physically move with the subscription.")
    _h("> Resources in the *Requires Action* category have tenant-bound")
    _h("> dependencies. Some require action BEFORE the transfer (or the")
    _h("> transfer will fail / cause data loss), and some require action AFTER.\n")

    # Transfer-safe
    _h("## Transfer-Safe Resources\n")
    _h("These resources have no tenant-bound dependencies and will continue ")
    _h("working after the subscription is transferred to the target tenant.\n")
    if transfer_safe:
        _h("| Type | Name | Resource Group | Location |")
        _h("|------|------|----------------|----------|")
        for r in transfer_safe:
            _h(f"| {r['type']} | {r['name']} | {r.get('resource_group', '')} | {r.get('location', '')} |")
    else:
        _h("_No transfer-safe resources found._\n")

    # Requires action
    _h("\n## Requires-Action Resources\n")
    _h("These resources have tenant-bound dependencies (managed identities, ")
    _h("AAD auth, Key Vault policies, etc.) that require preparation before ")
    _h("and/or reconfiguration after the cross-tenant transfer.\n")
    if requires_action:
        _h("| Type | Name | Timing | Pre-Transfer Action | Post-Transfer Action | Docs |")
        _h("|------|------|--------|--------------------|--------------------|------|")
        for r in requires_action:
            timing = r.get('timing', 'post').upper()
            pre = r.get('pre_action', '') or '—'
            post = r.get('post_action', '') or '—'
            doc_url = r.get('doc_url', '')
            doc_link = f'[Learn ↗]({doc_url})' if doc_url else '—'
            _h(
                f"| {r['type']} | {r['name']} | **{timing}** "
                f"| {pre} | {post} | {doc_link} |"
            )
    else:
        _h("_No resources requiring action found._\n")

    # IaC artifacts
    iac = plan.get("iac_artifacts", {})
    if iac:
        _h("\n## Generated IaC Templates\n")
        for fmt, paths in iac.items():
            _h(f"### {fmt.upper()}\n")
            for p in paths:
                _h(f"- `{p}`")
            _h("")

    # Next steps
    _h("\n## Next Steps\n")
    _h("1. Review the transfer-safe vs. requires-action classification above.")
    _h("2. Complete ALL **Pre-Transfer Actions** listed above (⛔/⚠️ items are critical).")
    _h("3. Export RBAC role assignments and custom roles (they are permanently deleted).")
    _h("4. Back up Key Vault secrets, certificates, and keys.")
    _h("5. Disable Entra auth on SQL/MySQL/PostgreSQL if applicable.")
    _h("6. Export Azure Policy definitions and assignments.")
    _h("7. Initiate the subscription transfer via Azure Portal or `tenova transfer`.")
    _h("8. Complete ALL **Post-Transfer Actions** listed above.")
    _h("9. Recreate role assignments and managed identities in the target tenant.")
    _h("10. Validate all services in the target tenant.")
    _h("\n> **Reference:** [Transfer an Azure subscription to a different Microsoft Entra directory]"
        "(https://learn.microsoft.com/en-us/azure/role-based-access-control/transfer-subscription)\n")

    # Write
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines), encoding="utf-8")
    logger.info("Migration plan report written to %s", output_path)
    return output_path
