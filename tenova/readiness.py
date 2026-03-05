"""Pre-transfer readiness check.

Validates whether a subscription is safe to transfer by scanning for
known blockers (⛔ — transfer will fail or cause data loss) and warnings
(⚠️ — transfer will succeed but services will break until fixed).

Usage
-----
    result = check_readiness(credential, subscription_id)
    if not result["ready"]:
        print("Blockers found — do NOT transfer yet!")
"""

from __future__ import annotations

from typing import Any

from azure.core.credentials import TokenCredential

from tenova.constants import REQUIRED_ACTIONS
from tenova.scanner import scan_subscription
from tenova.rbac import (
    list_role_assignments,
    list_custom_roles,
    list_managed_identities,
)
from tenova.logger import get_logger

logger = get_logger("readiness")

# Resource types that are hard blockers — transfer fails or data is lost
_BLOCKER_TYPES: set[str] = {
    "Microsoft.ContainerService/managedClusters",
    "Microsoft.AAD/domainServices",
    "Microsoft.Databricks/workspaces",
    "Microsoft.DevCenter/devcenters",
    "Microsoft.DevCenter/projects",
    "Microsoft.ServiceFabric/clusters",
    "Microsoft.ServiceFabric/managedClusters",
}

# Resource types that block transfer when Entra auth is enabled
_ENTRA_AUTH_BLOCKERS: set[str] = {
    "Microsoft.Sql/servers",
    "Microsoft.Sql/managedInstances",
    "Microsoft.DBforMySQL/flexibleServers",
    "Microsoft.DBforMySQL/servers",
    "Microsoft.DBforPostgreSQL/flexibleServers",
    "Microsoft.DBforPostgreSQL/servers",
}

# Resource types with critical CMK/encryption dependencies
_CMK_WARNING_TYPES: set[str] = {
    "Microsoft.KeyVault/vaults",
    "Microsoft.KeyVault/managedHSMs",
    "Microsoft.Compute/diskEncryptionSets",
}


def check_readiness(
    credential: TokenCredential,
    subscription_id: str,
) -> dict[str, Any]:
    """Run a comprehensive pre-transfer readiness check.

    Returns a dict with:
    - ``ready``: bool — True if no blockers found
    - ``blockers``: list of hard-blocker dicts (must fix before transfer)
    - ``warnings``: list of warning dicts (should fix, risk if ignored)
    - ``info``: list of informational items
    """
    logger.info("Running readiness check for subscription %s …", subscription_id)

    blockers: list[dict[str, str]] = []
    warnings: list[dict[str, str]] = []
    info: list[dict[str, str]] = []

    # ── 1. Scan resources ──────────────────────────────────────────
    scan_result = scan_subscription(credential, subscription_id)
    requires_action = scan_result.get("requires_action", [])

    for resource in requires_action:
        rtype = resource.get("type", "")
        rname = resource.get("name", "")
        timing = resource.get("timing", "post")
        pre_action = resource.get("pre_action", "")

        # Hard blockers: resources that CANNOT be transferred
        if rtype in _BLOCKER_TYPES:
            blockers.append({
                "name": rname,
                "type": rtype,
                "issue": "Cannot be transferred to a different tenant",
                "action": pre_action or "Must be deleted and recreated in the target tenant.",
            })

        # Entra auth blockers: transfer fails if Entra auth is enabled
        elif rtype in _ENTRA_AUTH_BLOCKERS:
            blockers.append({
                "name": rname,
                "type": rtype,
                "issue": "Cannot transfer with Entra authentication enabled",
                "action": pre_action or "Disable Entra authentication before transfer.",
            })

        # CMK/encryption warnings
        elif rtype in _CMK_WARNING_TYPES:
            warnings.append({
                "name": rname,
                "type": rtype,
                "issue": "Encryption/Key Vault dependency — risk of unrecoverable data loss",
                "action": pre_action or "Disable CMK and export access policies before transfer.",
            })

        # Policy deletions
        elif rtype.startswith("Microsoft.Authorization/policy"):
            warnings.append({
                "name": rname,
                "type": rtype,
                "issue": "Permanently deleted during transfer",
                "action": pre_action or "Export before transfer.",
            })

        # Everything else with PRE timing is a warning
        elif timing in ("pre", "both") and pre_action:
            warnings.append({
                "name": rname,
                "type": rtype,
                "issue": "Requires pre-transfer action",
                "action": pre_action,
            })

    # ── 2. Check RBAC ──────────────────────────────────────────────
    try:
        assignments = list_role_assignments(credential, subscription_id)
        if assignments:
            info.append({
                "category": "RBAC Role Assignments",
                "detail": (
                    f"{len(assignments)} role assignment(s) will be PERMANENTLY DELETED. "
                    f"Run 'tenova export-rbac' to save them before transfer."
                ),
            })
    except Exception as exc:
        warnings.append({
            "name": "RBAC",
            "type": "Role Assignments",
            "issue": f"Could not read role assignments: {exc}",
            "action": "Ensure you have Reader access to list role assignments.",
        })

    # ── 3. Check custom roles ──────────────────────────────────────
    try:
        custom_roles = list_custom_roles(credential, subscription_id)
        if custom_roles:
            info.append({
                "category": "Custom Roles",
                "detail": (
                    f"{len(custom_roles)} custom role(s) will be PERMANENTLY DELETED. "
                    f"Run 'tenova export-rbac' to save them before transfer."
                ),
            })
    except Exception:
        pass  # Non-critical — already warned about RBAC access

    # ── 4. Check managed identities ────────────────────────────────
    try:
        identities = list_managed_identities(credential, subscription_id)
        if identities:
            info.append({
                "category": "User-Assigned Managed Identities",
                "detail": (
                    f"{len(identities)} identity(ies) found. These must be deleted and "
                    f"recreated in the target tenant after transfer."
                ),
            })
    except Exception:
        pass  # Non-critical

    # ── 5. Summary info ────────────────────────────────────────────
    total_resources = (
        len(scan_result.get("transfer_safe", []))
        + len(requires_action)
    )
    info.append({
        "category": "Total Resources",
        "detail": (
            f"{total_resources} resource(s) scanned: "
            f"{len(scan_result.get('transfer_safe', []))} transfer-safe, "
            f"{len(requires_action)} require action."
        ),
    })

    ready = len(blockers) == 0

    logger.info(
        "Readiness check complete: %s (%d blockers, %d warnings, %d info)",
        "READY" if ready else "NOT READY",
        len(blockers),
        len(warnings),
        len(info),
    )

    return {
        "ready": ready,
        "blockers": blockers,
        "warnings": warnings,
        "info": info,
    }
