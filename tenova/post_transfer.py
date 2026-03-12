"""Post-transfer reconfiguration engine.

After the subscription has landed in the target tenant, this module
executes the reconfiguration operations using the target-tenant
credential:

  1. **RBAC** — recreate role assignments using the principal mapping.
  2. **Key Vault** — update access policies with new-tenant principals.
  3. **SQL Server** — update the AD admin.
  4. **App Service** — update Entra auth configuration.
  5. **Managed Identities** — document new principal IDs.

Each operation is idempotent (safe to re-run) and produces a structured
result dict so the UI can show progress and final status.
"""

from __future__ import annotations

import uuid
from typing import Any

from azure.core.credentials import TokenCredential

from tenova.logger import get_logger

logger = get_logger("post_transfer")


# ──────────────────────────────────────────────────────────────────────
# Top-level orchestrator
# ──────────────────────────────────────────────────────────────────────

def run_post_transfer(
    credential: TokenCredential,
    subscription_id: str,
    scan_data: dict[str, Any],
    rbac_export: dict[str, Any] | None,
    principal_mapping: dict[str, str],
) -> dict[str, Any]:
    """Run all post-transfer operations and return a summary.

    Parameters
    ----------
    credential:
        TokenCredential authenticated in the **target** tenant.
    scan_data:
        The original scan result dict (transfer_safe, requires_action).
    rbac_export:
        The RBAC export JSON (role_assignments, custom_roles, etc.).
        If None, RBAC restoration is skipped.
    principal_mapping:
        ``{old_principal_id: new_principal_id}`` mapping.

    Returns
    -------
    Dict with per-operation results and an overall status.
    """
    results: dict[str, Any] = {
        "operations": [],
        "summary": {"total": 0, "succeeded": 0, "failed": 0, "skipped": 0},
    }

    requires_action = scan_data.get("requires_action", [])

    # 1) RBAC restoration
    if rbac_export:
        rbac_result = _restore_rbac(
            credential, subscription_id, rbac_export, principal_mapping,
        )
        results["operations"].append(rbac_result)

    # 2) Key Vault access policies
    kv_resources = _filter_by_type(requires_action, "Microsoft.KeyVault/vaults")
    for kv in kv_resources:
        kv_result = _update_keyvault(
            credential, subscription_id, kv, principal_mapping,
        )
        results["operations"].append(kv_result)

    # 3) SQL Server AD admin
    sql_resources = _filter_by_type(requires_action, "Microsoft.Sql/servers")
    for sql in sql_resources:
        sql_result = _update_sql_admin(
            credential, subscription_id, sql, principal_mapping,
        )
        results["operations"].append(sql_result)

    # 4) App Service auth
    app_resources = _filter_by_type(requires_action, "Microsoft.Web/sites")
    for app in app_resources:
        app_result = _update_app_service_auth(
            credential, subscription_id, app,
        )
        results["operations"].append(app_result)

    # 5) Managed Identity documentation
    mi_resources = _filter_by_type(
        requires_action, "Microsoft.ManagedIdentity/userAssignedIdentities",
    )
    for mi in mi_resources:
        mi_result = _document_managed_identity(
            credential, subscription_id, mi,
        )
        results["operations"].append(mi_result)

    # Tally summary
    for op in results["operations"]:
        results["summary"]["total"] += 1
        status = op.get("status", "failed")
        if status == "succeeded":
            results["summary"]["succeeded"] += 1
        elif status == "skipped":
            results["summary"]["skipped"] += 1
        else:
            results["summary"]["failed"] += 1

    overall = "succeeded" if results["summary"]["failed"] == 0 else "partial"
    if results["summary"]["succeeded"] == 0 and results["summary"]["total"] > 0:
        overall = "failed"
    results["overall_status"] = overall

    logger.info(
        "Post-transfer complete: %d total, %d succeeded, %d failed, %d skipped",
        results["summary"]["total"],
        results["summary"]["succeeded"],
        results["summary"]["failed"],
        results["summary"]["skipped"],
    )
    return results


# ──────────────────────────────────────────────────────────────────────
# 1. RBAC restoration
# ──────────────────────────────────────────────────────────────────────

def _restore_rbac(
    credential: TokenCredential,
    subscription_id: str,
    rbac_export: dict[str, Any],
    principal_mapping: dict[str, str],
) -> dict[str, Any]:
    """Recreate role assignments and custom roles from the RBAC export."""
    op: dict[str, Any] = {
        "operation": "RBAC Restoration",
        "resource_type": "Microsoft.Authorization/roleAssignments",
        "details": [],
    }

    try:
        from azure.mgmt.authorization import AuthorizationManagementClient
        client = AuthorizationManagementClient(credential, subscription_id)

        # Custom roles first (assignments may reference them)
        custom_created = 0
        for role in rbac_export.get("custom_roles", []):
            try:
                role_id = str(uuid.uuid4())
                client.role_definitions.create_or_update(
                    scope=f"/subscriptions/{subscription_id}",
                    role_definition_id=role_id,
                    role_definition={
                        "properties": {
                            "role_name": role["name"],
                            "description": role.get("description", ""),
                            "permissions": role.get("permissions", []),
                            "assignable_scopes": [f"/subscriptions/{subscription_id}"],
                        }
                    },
                )
                custom_created += 1
            except Exception as exc:
                op["details"].append({
                    "action": f"Create custom role '{role['name']}'",
                    "status": "failed",
                    "error": str(exc)[:200],
                })

        # Role assignments
        created = 0
        skipped = 0
        failed = 0
        for ra in rbac_export.get("role_assignments", []):
            old_pid = ra.get("principal_id", "")
            new_pid = principal_mapping.get(old_pid)
            if not new_pid:
                skipped += 1
                continue

            try:
                client.role_assignments.create(
                    scope=ra.get("scope", f"/subscriptions/{subscription_id}"),
                    role_assignment_name=str(uuid.uuid4()),
                    parameters={
                        "properties": {
                            "role_definition_id": ra["role_definition_id"],
                            "principal_id": new_pid,
                        }
                    },
                )
                created += 1
            except Exception as exc:
                err = str(exc)
                if "RoleAssignmentExists" in err:
                    skipped += 1  # idempotent
                else:
                    failed += 1
                    op["details"].append({
                        "action": f"Create assignment for {new_pid}",
                        "status": "failed",
                        "error": err[:200],
                    })

        op["details"].insert(0, {
            "action": "Summary",
            "custom_roles_created": custom_created,
            "assignments_created": created,
            "assignments_skipped": skipped,
            "assignments_failed": failed,
        })
        op["status"] = "succeeded" if failed == 0 else "partial"
        logger.info(
            "RBAC restoration: %d custom roles, %d assignments created, "
            "%d skipped, %d failed",
            custom_created, created, skipped, failed,
        )

    except Exception as exc:
        op["status"] = "failed"
        op["error"] = str(exc)[:200]
        logger.exception("RBAC restoration failed")

    return op


# ──────────────────────────────────────────────────────────────────────
# 2. Key Vault access policies
# ──────────────────────────────────────────────────────────────────────

def _update_keyvault(
    credential: TokenCredential,
    subscription_id: str,
    resource: dict[str, Any],
    principal_mapping: dict[str, str],
) -> dict[str, Any]:
    """Update Key Vault tenant ID and access policies."""
    rg = resource.get("resource_group", "")
    name = resource.get("name", "")
    op: dict[str, Any] = {
        "operation": f"Key Vault: {name}",
        "resource_type": "Microsoft.KeyVault/vaults",
        "resource_name": name,
        "details": [],
    }

    try:
        from azure.mgmt.keyvault import KeyVaultManagementClient

        client = KeyVaultManagementClient(credential, subscription_id)
        vault = client.vaults.get(rg, name)

        # The tenant ID is automatically updated during transfer,
        # but access policies reference old-tenant principal IDs.
        new_policies = []
        for policy in (vault.properties.access_policies or []):
            old_oid = policy.object_id
            new_oid = principal_mapping.get(old_oid, old_oid)
            new_policies.append({
                "tenantId": str(vault.properties.tenant_id),
                "objectId": new_oid,
                "permissions": {
                    "keys": [str(p) for p in (policy.permissions.keys or [])],
                    "secrets": [str(p) for p in (policy.permissions.secrets or [])],
                    "certificates": [str(p) for p in (policy.permissions.certificates or [])],
                    "storage": [str(p) for p in (policy.permissions.storage or [])],
                },
            })
            op["details"].append({
                "action": f"Map policy {old_oid} → {new_oid}",
                "status": "mapped" if new_oid != old_oid else "kept",
            })

        # Update the vault with new access policies
        client.vaults.create_or_update(
            resource_group_name=rg,
            vault_name=name,
            parameters={
                "location": vault.location,
                "properties": {
                    "tenantId": str(vault.properties.tenant_id),
                    "sku": {
                        "family": "A",
                        "name": str(vault.properties.sku.name),
                    },
                    "accessPolicies": new_policies,
                },
            },
        )
        op["status"] = "succeeded"
        logger.info("Key Vault '%s' access policies updated (%d policies)", name, len(new_policies))

    except Exception as exc:
        op["status"] = "failed"
        op["error"] = str(exc)[:200]
        logger.exception("Key Vault '%s' update failed", name)

    return op


# ──────────────────────────────────────────────────────────────────────
# 3. SQL Server AD admin
# ──────────────────────────────────────────────────────────────────────

def _update_sql_admin(
    credential: TokenCredential,
    subscription_id: str,
    resource: dict[str, Any],
    principal_mapping: dict[str, str],
) -> dict[str, Any]:
    """Update or document the SQL Server AD admin."""
    rg = resource.get("resource_group", "")
    name = resource.get("name", "")
    op: dict[str, Any] = {
        "operation": f"SQL Server AD Admin: {name}",
        "resource_type": "Microsoft.Sql/servers",
        "resource_name": name,
        "details": [],
    }

    try:
        from azure.mgmt.sql import SqlManagementClient

        client = SqlManagementClient(credential, subscription_id)

        # List current AD admins
        admins = list(client.server_azure_ad_administrators.list_by_server(rg, name))

        if not admins:
            op["status"] = "skipped"
            op["details"].append({"action": "No AD admin configured", "status": "skipped"})
            return op

        for admin in admins:
            old_sid = admin.sid
            new_sid = principal_mapping.get(old_sid, "")
            if new_sid:
                # Update the AD admin with the new principal
                client.server_azure_ad_administrators.begin_create_or_update(
                    rg, name, "ActiveDirectory",
                    parameters={
                        "administratorType": "ActiveDirectory",
                        "login": admin.login,
                        "sid": new_sid,
                        "tenantId": admin.tenant_id,
                    },
                ).result()
                op["details"].append({
                    "action": f"Updated AD admin {admin.login}: {old_sid} → {new_sid}",
                    "status": "succeeded",
                })
            else:
                op["details"].append({
                    "action": f"AD admin {admin.login} ({old_sid}): no mapping — manual update needed",
                    "status": "manual",
                })

        op["status"] = "succeeded" if any(
            d["status"] == "succeeded" for d in op["details"]
        ) else "manual"

    except Exception as exc:
        op["status"] = "failed"
        op["error"] = str(exc)[:200]
        logger.exception("SQL Server '%s' AD admin update failed", name)

    return op


# ──────────────────────────────────────────────────────────────────────
# 4. App Service auth
# ──────────────────────────────────────────────────────────────────────

def _update_app_service_auth(
    credential: TokenCredential,
    subscription_id: str,
    resource: dict[str, Any],
) -> dict[str, Any]:
    """Document App Service authentication configuration.

    App Service auth settings reference Entra app registrations that
    live in the old tenant.  These registrations must be manually
    recreated in the new tenant — we can't automate that.
    Instead we capture the current config so the user knows what to recreate.
    """
    rg = resource.get("resource_group", "")
    name = resource.get("name", "")
    op: dict[str, Any] = {
        "operation": f"App Service Auth: {name}",
        "resource_type": "Microsoft.Web/sites",
        "resource_name": name,
        "details": [],
    }

    try:
        from azure.mgmt.web import WebSiteManagementClient

        client = WebSiteManagementClient(credential, subscription_id)
        auth = client.web_apps.get_auth_settings_v2(rg, name)

        if auth and auth.identity_providers:
            idp = auth.identity_providers
            if idp.azure_active_directory and idp.azure_active_directory.registration:
                reg = idp.azure_active_directory.registration
                op["details"].append({
                    "action": "Entra auth detected",
                    "old_client_id": reg.client_id or "",
                    "old_issuer": reg.open_id_issuer or "",
                    "status": "manual",
                    "note": (
                        "Create a new app registration in the target tenant, "
                        "then update the App Service auth settings with the new client ID."
                    ),
                })
            else:
                op["details"].append({
                    "action": "No Entra auth configured",
                    "status": "skipped",
                })
        else:
            op["details"].append({
                "action": "No auth settings found",
                "status": "skipped",
            })

        op["status"] = "manual" if any(
            d.get("status") == "manual" for d in op["details"]
        ) else "skipped"

    except Exception as exc:
        op["status"] = "failed"
        op["error"] = str(exc)[:200]
        logger.exception("App Service '%s' auth check failed", name)

    return op


# ──────────────────────────────────────────────────────────────────────
# 5. Managed Identity documentation
# ──────────────────────────────────────────────────────────────────────

def _document_managed_identity(
    credential: TokenCredential,
    subscription_id: str,
    resource: dict[str, Any],
) -> dict[str, Any]:
    """Document a managed identity's new principal ID.

    After transfer, user-assigned managed identities get new principal
    IDs.  Any resource that referenced the old principal ID (e.g., AKS
    pod identity, ADF linked services) needs to be updated.
    """
    rg = resource.get("resource_group", "")
    name = resource.get("name", "")
    op: dict[str, Any] = {
        "operation": f"Managed Identity: {name}",
        "resource_type": "Microsoft.ManagedIdentity/userAssignedIdentities",
        "resource_name": name,
        "details": [],
    }

    try:
        from azure.mgmt.msi import ManagedServiceIdentityClient

        client = ManagedServiceIdentityClient(credential, subscription_id)
        mi = client.user_assigned_identities.get(rg, name)

        op["details"].append({
            "action": "Document new identity",
            "new_principal_id": mi.principal_id,
            "new_client_id": mi.client_id,
            "note": (
                "Update any resources that reference this managed identity's "
                "principal ID (RBAC, pod identity, linked services, etc.)."
            ),
            "status": "documented",
        })
        op["status"] = "succeeded"
        logger.info(
            "Managed identity '%s': new principal_id=%s, client_id=%s",
            name, mi.principal_id, mi.client_id,
        )

    except Exception as exc:
        op["status"] = "failed"
        op["error"] = str(exc)[:200]
        logger.exception("Managed identity '%s' documentation failed", name)

    return op


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
        # Also check children
        for child in r.get("children", []):
            if (child.get("type", "")).lower() == rt_lower:
                result.append(child)
    return result
