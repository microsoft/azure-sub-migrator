"""Pre-transfer automation engine.

Automates every pre-transfer export that the checklist currently tells
users to do manually with copy-paste CLI commands.  Each export function
calls Azure SDKs to collect data and returns a JSON-serialisable dict
that can be included in a migration bundle.

Orchestrator: :func:`run_pre_transfer` runs all exports and returns a
combined artifacts dict ready for :func:`tenova.bundle.create_bundle`.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from azure.core.credentials import TokenCredential

from tenova.logger import get_logger
from tenova.retry import azure_retry

logger = get_logger("pre_transfer")


# ──────────────────────────────────────────────────────────────────────
# Top-level orchestrator
# ──────────────────────────────────────────────────────────────────────

def run_pre_transfer(
    credential: TokenCredential,
    subscription_id: str,
    scan_data: dict[str, Any],
    on_progress: Callable[[str, int, int], None] | None = None,
) -> dict[str, Any]:
    """Run all pre-transfer exports and return the combined artifacts.

    Parameters
    ----------
    credential:
        TokenCredential authenticated in the **source** tenant.
    subscription_id:
        The subscription being migrated.
    scan_data:
        The scan result dict (transfer_safe, requires_action).
    on_progress:
        Optional callback ``(step_name, step_number, total_steps)``
        invoked after each export step completes.

    Returns
    -------
    Dict with per-step results and an ``artifacts`` dict containing
    all exported data keyed by artifact name.
    """
    total_steps = 7
    step_num = 0

    def _report(name: str) -> None:
        nonlocal step_num
        step_num += 1
        if on_progress:
            on_progress(name, step_num, total_steps)
    results: dict[str, Any] = {
        "steps": [],
        "artifacts": {},
        "summary": {"total": 0, "succeeded": 0, "failed": 0},
    }

    # Include scan results as the baseline artifact
    results["artifacts"]["scan_results"] = scan_data

    # 1) RBAC export (assignments + custom roles)
    _run_step(
        results, "Export RBAC Assignments",
        lambda: _export_rbac_assignments(credential, subscription_id),
        artifact_key="rbac_assignments",
    )
    _report("Export RBAC Assignments")

    # 2) Custom roles
    _run_step(
        results, "Export Custom Roles",
        lambda: _export_custom_roles(credential, subscription_id),
        artifact_key="rbac_custom_roles",
    )
    _report("Export Custom Roles")

    # 3) Managed identities
    _run_step(
        results, "Export Managed Identities",
        lambda: _export_managed_identities(credential, subscription_id),
        artifact_key="managed_identities",
    )
    _report("Export Managed Identities")

    # 4) Policy assignments
    _run_step(
        results, "Export Policy Assignments",
        lambda: _export_policy_assignments(credential, subscription_id),
        artifact_key="policy_assignments",
    )
    _report("Export Policy Assignments")

    # 5) Custom policy definitions
    _run_step(
        results, "Export Custom Policy Definitions",
        lambda: _export_policy_definitions(credential, subscription_id),
        artifact_key="policy_definitions",
    )
    _report("Export Custom Policy Definitions")

    # 6) Resource locks
    _run_step(
        results, "Export Resource Locks",
        lambda: _export_resource_locks(credential, subscription_id),
        artifact_key="resource_locks",
    )
    _report("Export Resource Locks")

    # 7) Key Vault access policies
    requires_action = scan_data.get("requires_action", [])
    _run_step(
        results, "Export Key Vault Access Policies",
        lambda: _export_keyvault_policies(credential, subscription_id, requires_action),
        artifact_key="keyvault_policies",
    )
    _report("Export Key Vault Access Policies")

    # Overall status
    overall = "succeeded" if results["summary"]["failed"] == 0 else "partial"
    if results["summary"]["succeeded"] == 0 and results["summary"]["total"] > 0:
        overall = "failed"
    results["overall_status"] = overall

    logger.info(
        "Pre-transfer complete: %d total, %d succeeded, %d failed",
        results["summary"]["total"],
        results["summary"]["succeeded"],
        results["summary"]["failed"],
    )
    return results


# ──────────────────────────────────────────────────────────────────────
# Step runner helper
# ──────────────────────────────────────────────────────────────────────

def _run_step(
    results: dict[str, Any],
    name: str,
    func: Any,
    *,
    artifact_key: str,
) -> None:
    """Execute a single export step, catch errors, and record results."""
    results["summary"]["total"] += 1
    step: dict[str, Any] = {"name": name, "artifact_key": artifact_key}
    try:
        data = func()
        results["artifacts"][artifact_key] = data
        step["status"] = "succeeded"
        step["count"] = len(data) if isinstance(data, list) else (
            len(data.get("items", data.get("vaults", []))) if isinstance(data, dict) else 0
        )
        results["summary"]["succeeded"] += 1
        logger.info("Step '%s' succeeded (%s items)", name, step.get("count", "?"))
    except Exception as exc:
        step["status"] = "failed"
        step["error"] = str(exc)[:200]
        results["summary"]["failed"] += 1
        logger.exception("Step '%s' failed", name)

    results["steps"].append(step)


# ──────────────────────────────────────────────────────────────────────
# 1. RBAC Assignments
# ──────────────────────────────────────────────────────────────────────

def _export_rbac_assignments(
    credential: TokenCredential,
    subscription_id: str,
) -> list[dict[str, Any]]:
    """Export all role assignments in the subscription."""
    from tenova.rbac import list_role_assignments
    return list_role_assignments(credential, subscription_id)


# ──────────────────────────────────────────────────────────────────────
# 2. Custom Roles
# ──────────────────────────────────────────────────────────────────────

def _export_custom_roles(
    credential: TokenCredential,
    subscription_id: str,
) -> list[dict[str, Any]]:
    """Export all custom role definitions in the subscription."""
    from tenova.rbac import list_custom_roles
    return list_custom_roles(credential, subscription_id)


# ──────────────────────────────────────────────────────────────────────
# 3. Managed Identities
# ──────────────────────────────────────────────────────────────────────

def _export_managed_identities(
    credential: TokenCredential,
    subscription_id: str,
) -> list[dict[str, Any]]:
    """Export user-assigned managed identity inventory."""
    from tenova.rbac import list_managed_identities
    return list_managed_identities(credential, subscription_id)


# ──────────────────────────────────────────────────────────────────────
# 4. Policy Assignments
# ──────────────────────────────────────────────────────────────────────

@azure_retry
def _export_policy_assignments(
    credential: TokenCredential,
    subscription_id: str,
) -> list[dict[str, Any]]:
    """Export all policy assignments in the subscription."""
    from azure.mgmt.resource.policy import PolicyClient

    client = PolicyClient(credential, subscription_id)
    assignments: list[dict[str, Any]] = []

    for pa in client.policy_assignments.list():
        assignments.append({
            "id": pa.id,
            "name": pa.name,
            "display_name": pa.display_name or "",
            "description": pa.description or "",
            "policy_definition_id": pa.policy_definition_id or "",
            "scope": pa.scope or "",
            "not_scopes": list(pa.not_scopes or []),
            "parameters": dict(pa.parameters or {}),
            "enforcement_mode": str(pa.enforcement_mode) if pa.enforcement_mode else "Default",
            "metadata": pa.metadata if isinstance(pa.metadata, dict) else {},
        })

    logger.info("Exported %d policy assignment(s)", len(assignments))
    return assignments


# ──────────────────────────────────────────────────────────────────────
# 5. Custom Policy Definitions
# ──────────────────────────────────────────────────────────────────────

@azure_retry
def _export_policy_definitions(
    credential: TokenCredential,
    subscription_id: str,
) -> list[dict[str, Any]]:
    """Export custom policy definitions (not built-ins)."""
    from azure.mgmt.resource.policy import PolicyClient

    client = PolicyClient(credential, subscription_id)
    definitions: list[dict[str, Any]] = []

    for pd in client.policy_definitions.list():
        # Only export custom policies, not built-ins
        if pd.policy_type and str(pd.policy_type).lower() == "custom":
            definitions.append({
                "id": pd.id,
                "name": pd.name,
                "display_name": pd.display_name or "",
                "description": pd.description or "",
                "policy_type": str(pd.policy_type) if pd.policy_type else "",
                "mode": pd.mode or "",
                "policy_rule": pd.policy_rule if isinstance(pd.policy_rule, dict) else {},
                "parameters": pd.parameters if isinstance(pd.parameters, dict) else {},
                "metadata": pd.metadata if isinstance(pd.metadata, dict) else {},
            })

    logger.info("Exported %d custom policy definition(s)", len(definitions))
    return definitions


# ──────────────────────────────────────────────────────────────────────
# 6. Resource Locks
# ──────────────────────────────────────────────────────────────────────

@azure_retry
def _export_resource_locks(
    credential: TokenCredential,
    subscription_id: str,
) -> list[dict[str, Any]]:
    """Export all management locks in the subscription."""
    from azure.mgmt.resource.locks import ManagementLockClient

    client = ManagementLockClient(credential, subscription_id)
    locks: list[dict[str, Any]] = []

    for lock in client.management_locks.list_at_subscription_level():
        locks.append({
            "id": lock.id,
            "name": lock.name,
            "level": str(lock.level) if lock.level else "",
            "notes": lock.notes or "",
            "owners": [str(o.application_id) for o in (lock.owners or [])],
        })

    # Also list locks at resource group level for better fidelity
    from azure.mgmt.resource import ResourceManagementClient
    rm_client = ResourceManagementClient(credential, subscription_id)
    for rg in rm_client.resource_groups.list():
        try:
            for lock in client.management_locks.list_at_resource_group_level(rg.name):
                lock_entry = {
                    "id": lock.id,
                    "name": lock.name,
                    "level": str(lock.level) if lock.level else "",
                    "notes": lock.notes or "",
                    "owners": [str(o.application_id) for o in (lock.owners or [])],
                    "resource_group": rg.name,
                }
                # Avoid duplicates (sub-level locks also appear at RG level)
                if not any(existing["id"] == lock_entry["id"] for existing in locks):
                    locks.append(lock_entry)
        except Exception:
            logger.debug("Could not list locks for RG %s", rg.name)

    logger.info("Exported %d resource lock(s)", len(locks))
    return locks


# ──────────────────────────────────────────────────────────────────────
# 7. Key Vault Access Policies
# ──────────────────────────────────────────────────────────────────────

@azure_retry
def _export_keyvault_policies(
    credential: TokenCredential,
    subscription_id: str,
    requires_action: list[dict[str, Any]],
) -> dict[str, Any]:
    """Export access policies for each Key Vault found in the scan."""
    from azure.mgmt.keyvault import KeyVaultManagementClient

    client = KeyVaultManagementClient(credential, subscription_id)
    export: dict[str, Any] = {"vaults": []}

    # Find KV resources from scan results
    kv_resources = _filter_by_type(requires_action, "Microsoft.KeyVault/vaults")

    # Also discover KVs directly if scan didn't catch them all
    try:
        for vault in client.vaults.list_by_subscription():
            rg = _extract_rg(vault.id)
            if not any(v.get("name") == vault.name for v in kv_resources):
                kv_resources.append({
                    "name": vault.name,
                    "resource_group": rg,
                    "type": "Microsoft.KeyVault/vaults",
                })
    except Exception:
        logger.debug("Could not list KVs via subscription-wide API")

    for kv in kv_resources:
        rg = kv.get("resource_group", "")
        name = kv.get("name", "")
        try:
            vault = client.vaults.get(rg, name)
            policies = []
            for ap in (vault.properties.access_policies or []):
                policies.append({
                    "tenant_id": str(ap.tenant_id) if ap.tenant_id else "",
                    "object_id": ap.object_id or "",
                    "permissions": {
                        "keys": [str(p) for p in (ap.permissions.keys or [])],
                        "secrets": [str(p) for p in (ap.permissions.secrets or [])],
                        "certificates": [str(p) for p in (ap.permissions.certificates or [])],
                        "storage": [str(p) for p in (ap.permissions.storage or [])],
                    },
                })

            export["vaults"].append({
                "name": name,
                "resource_group": rg,
                "location": vault.location,
                "sku": str(vault.properties.sku.name) if vault.properties.sku else "",
                "tenant_id": str(vault.properties.tenant_id) if vault.properties.tenant_id else "",
                "access_policies": policies,
            })
            logger.info("Exported %d access policies for Key Vault '%s'", len(policies), name)
        except Exception as exc:
            logger.warning("Could not export Key Vault '%s': %s", name, exc)

    return export


# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────

def _filter_by_type(
    resources: list[dict[str, Any]],
    resource_type: str,
) -> list[dict[str, Any]]:
    """Filter resources (and their children) by type, case-insensitive."""
    result: list[dict[str, Any]] = []
    rt_lower = resource_type.lower()
    for r in resources:
        if (r.get("type", "")).lower() == rt_lower:
            result.append(r)
        for child in r.get("children", []):
            if (child.get("type", "")).lower() == rt_lower:
                result.append(child)
    return result


def _extract_rg(resource_id: str | None) -> str:
    """Extract resource group name from an ARM resource ID."""
    if not resource_id:
        return ""
    parts = resource_id.split("/")
    try:
        idx = [p.lower() for p in parts].index("resourcegroups")
        return parts[idx + 1]
    except (ValueError, IndexError):
        return ""
