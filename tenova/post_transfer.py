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
    *,
    dry_run: bool = False,
    **kwargs: Any,
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
    dry_run:
        If True, simulate all operations without calling Azure APIs.
        Each operation will report what *would* happen with status
        ``"dry_run"`` instead of actually executing.

    Returns
    -------
    Dict with per-operation results and an overall status.
    """
    if dry_run:
        logger.info("DRY RUN mode — no Azure APIs will be called")

    results: dict[str, Any] = {
        "operations": [],
        "summary": {"total": 0, "succeeded": 0, "failed": 0, "skipped": 0},
        "dry_run": dry_run,
    }

    requires_action = scan_data.get("requires_action", [])

    # 1) RBAC restoration
    if rbac_export:
        rbac_result = _restore_rbac(
            credential, subscription_id, rbac_export, principal_mapping,
            dry_run=dry_run,
        )
        results["operations"].append(rbac_result)

    # 2) Key Vault access policies
    kv_resources = _filter_by_type(requires_action, "Microsoft.KeyVault/vaults")
    for kv in kv_resources:
        kv_result = _update_keyvault(
            credential, subscription_id, kv, principal_mapping,
            dry_run=dry_run,
        )
        results["operations"].append(kv_result)

    # 3) SQL Server AD admin
    sql_resources = _filter_by_type(requires_action, "Microsoft.Sql/servers")
    for sql in sql_resources:
        sql_result = _update_sql_admin(
            credential, subscription_id, sql, principal_mapping,
            dry_run=dry_run,
        )
        results["operations"].append(sql_result)

    # 4) App Service auth
    app_resources = _filter_by_type(requires_action, "Microsoft.Web/sites")
    for app in app_resources:
        app_result = _update_app_service_auth(
            credential, subscription_id, app,
            dry_run=dry_run,
        )
        results["operations"].append(app_result)

    # 5) Managed Identity documentation
    mi_resources = _filter_by_type(
        requires_action, "Microsoft.ManagedIdentity/userAssignedIdentities",
    )
    for mi in mi_resources:
        mi_result = _document_managed_identity(
            credential, subscription_id, mi,
            dry_run=dry_run,
        )
        results["operations"].append(mi_result)

    # ── Bundle-driven restoration steps ──────────────────────────────
    # These run only when a pre-transfer bundle is provided.
    bundle_artifacts = kwargs.get("bundle_artifacts", {})

    # 6) Policy assignment restoration
    policy_data = bundle_artifacts.get("policy_assignments", [])
    if policy_data:
        policy_result = _restore_policy_assignments(
            credential, subscription_id, policy_data,
            dry_run=dry_run,
        )
        results["operations"].append(policy_result)

    # 7) Custom policy definition restoration
    policy_def_data = bundle_artifacts.get("policy_definitions", [])
    if policy_def_data:
        policy_def_result = _restore_policy_definitions(
            credential, subscription_id, policy_def_data,
            dry_run=dry_run,
        )
        results["operations"].append(policy_def_result)

    # 8) Resource lock restoration
    lock_data = bundle_artifacts.get("resource_locks", [])
    if lock_data:
        lock_result = _restore_resource_locks(
            credential, subscription_id, lock_data,
            dry_run=dry_run,
        )
        results["operations"].append(lock_result)

    # 9) Key Vault access policy restoration (from bundle)
    kv_policy_data = bundle_artifacts.get("keyvault_policies", {})
    if kv_policy_data and kv_policy_data.get("vaults"):
        for vault_snapshot in kv_policy_data["vaults"]:
            kv_result = _restore_keyvault_from_snapshot(
                credential, subscription_id, vault_snapshot, principal_mapping,
                dry_run=dry_run,
            )
            results["operations"].append(kv_result)

    # 10) Toggle system-assigned managed identities
    sami_resources = _find_sami_resources(requires_action)
    if sami_resources:
        sami_result = _toggle_managed_identities(
            credential, subscription_id, sami_resources,
            dry_run=dry_run,
        )
        results["operations"].append(sami_result)

    # 11) Rotate storage account keys
    storage_resources = _filter_by_type(
        requires_action, "Microsoft.Storage/storageAccounts",
    )
    if storage_resources:
        storage_result = _rotate_storage_keys(
            credential, subscription_id, storage_resources,
            dry_run=dry_run,
        )
        results["operations"].append(storage_result)

    # Tally summary
    for op in results["operations"]:
        results["summary"]["total"] += 1
        status = op.get("status", "failed")
        if status in ("succeeded", "dry_run"):
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
    *,
    dry_run: bool = False,
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
                if not dry_run:
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
        unmapped = 0
        failed = 0
        for ra in rbac_export.get("role_assignments", []):
            old_pid = ra.get("principal_id", "")
            new_pid = principal_mapping.get(old_pid)
            if not new_pid:
                unmapped += 1
                skipped += 1
                continue

            try:
                if not dry_run:
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

        summary: dict[str, Any] = {
            "action": "Summary",
            "custom_roles_created": custom_created,
            "assignments_created": created,
            "assignments_skipped": skipped,
            "assignments_unmapped": unmapped,
            "assignments_failed": failed,
        }
        if dry_run:
            summary["note"] = "Dry run \u2014 no changes made"
        op["details"].insert(0, summary)
        op["status"] = "dry_run" if dry_run else ("succeeded" if failed == 0 else "partial")
        logger.info(
            "RBAC restoration%s: %d custom roles, %d assignments created, "
            "%d skipped, %d failed",
            " (dry run)" if dry_run else "",
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
    *,
    dry_run: bool = False,
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
            # Use .as_dict() to avoid name collision between the
            # Permissions.keys attribute and the Model.keys() method
            # that the SDK base class exposes for dict-like access.
            perms = (
                policy.permissions.as_dict()
                if hasattr(policy.permissions, "as_dict")
                else {}
            )
            new_policies.append({
                "tenantId": str(vault.properties.tenant_id),
                "objectId": new_oid,
                "permissions": {
                    "keys": [str(p) for p in (perms.get("keys") or [])],
                    "secrets": [str(p) for p in (perms.get("secrets") or [])],
                    "certificates": [str(p) for p in (perms.get("certificates") or [])],
                    "storage": [str(p) for p in (perms.get("storage") or [])],
                },
            })
            op["details"].append({
                "action": f"Map policy {old_oid} → {new_oid}",
                "status": "mapped" if new_oid != old_oid else "kept",
            })

        # Update the vault with new access policies
        # v13+ uses begin_create_or_update (LRO) instead of create_or_update
        if not dry_run:
            poller = client.vaults.begin_create_or_update(
                resource_group_name=rg,
                vault_name=name,
                parameters={
                    "location": vault.location,
                    "properties": {
                        "tenantId": str(vault.properties.tenant_id),
                        "sku": {
                            "family": "A",
                            "name": vault.properties.sku.name.value,
                        },
                        "accessPolicies": new_policies,
                    },
                },
            )
            poller.result()
        op["details"].insert(0, {
            "action": "Summary",
            "policies_updated": len(new_policies),
            "note": "Dry run \u2014 no changes made" if dry_run else None,
        })
        op["status"] = "dry_run" if dry_run else "succeeded"
        action = "simulated" if dry_run else "updated"
        logger.info("Key Vault '%s' access policies %s (%d policies)", name, action, len(new_policies))

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
    *,
    dry_run: bool = False,
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
                if not dry_run:
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
                    "action": f"Updated AD admin {admin.login}: {old_sid} \u2192 {new_sid}",
                    "status": "dry_run" if dry_run else "succeeded",
                })
            else:
                op["details"].append({
                    "action": f"AD admin {admin.login} ({old_sid}): no mapping \u2014 manual update needed",
                    "status": "manual",
                })

        if dry_run:
            op["details"].append({"action": "Summary", "note": "Dry run \u2014 no changes made"})
            op["status"] = "dry_run"
        else:
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
    *,
    dry_run: bool = False,
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

        if dry_run:
            op["details"].append({"action": "Summary", "note": "Dry run \u2014 no changes made"})
            op["status"] = "dry_run"
        else:
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
    *,
    dry_run: bool = False,
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
        if dry_run:
            op["details"].append({"action": "Summary", "note": "Dry run \u2014 no changes made"})
            op["status"] = "dry_run"
        else:
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
# 6. Policy Assignment Restoration
# ──────────────────────────────────────────────────────────────────────

def _restore_policy_assignments(
    credential: TokenCredential,
    subscription_id: str,
    policy_data: list[dict[str, Any]],
    *,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Recreate policy assignments from pre-transfer export."""
    op: dict[str, Any] = {
        "operation": "Restore Policy Assignments",
        "resource_type": "Microsoft.Authorization/policyAssignments",
        "details": [],
    }
    created = 0
    failed = 0

    try:
        from azure.mgmt.resource.policy import PolicyClient
        client = PolicyClient(credential, subscription_id)

        for pa in policy_data:
            try:
                # Re-scope to current subscription if needed
                scope = pa.get("scope", f"/subscriptions/{subscription_id}")
                if not scope.startswith(f"/subscriptions/{subscription_id}"):
                    scope = f"/subscriptions/{subscription_id}"

                params = {
                    "policy_definition_id": pa["policy_definition_id"],
                    "display_name": pa.get("display_name", ""),
                    "description": pa.get("description", ""),
                }
                if pa.get("not_scopes"):
                    params["not_scopes"] = pa["not_scopes"]
                if pa.get("parameters"):
                    params["parameters"] = pa["parameters"]
                enforcement = pa.get("enforcement_mode", "Default")
                if enforcement:
                    params["enforcement_mode"] = enforcement

                if not dry_run:
                    client.policy_assignments.create(
                        scope=scope,
                        policy_assignment_name=pa["name"],
                        parameters=params,
                    )
                created += 1
            except Exception as exc:
                err = str(exc)
                if "PolicyAssignmentAlreadyExists" in err or "already exists" in err.lower():
                    created += 1  # idempotent
                else:
                    failed += 1
                    op["details"].append({
                        "action": f"Create assignment '{pa.get('display_name', pa['name'])}'",
                        "status": "failed",
                        "error": err[:200],
                    })

        summary_pa: dict[str, Any] = {
            "action": "Summary",
            "assignments_created": created,
            "assignments_failed": failed,
        }
        if dry_run:
            summary_pa["note"] = "Dry run \u2014 no changes made"
        op["details"].insert(0, summary_pa)
        op["status"] = "dry_run" if dry_run else ("succeeded" if failed == 0 else "partial")
        logger.info("Policy assignments%s: %d created, %d failed", " (dry run)" if dry_run else "", created, failed)

    except Exception as exc:
        op["status"] = "failed"
        op["error"] = str(exc)[:200]
        logger.exception("Policy assignment restoration failed")

    return op


# ──────────────────────────────────────────────────────────────────────
# 7. Custom Policy Definition Restoration
# ──────────────────────────────────────────────────────────────────────

def _restore_policy_definitions(
    credential: TokenCredential,
    subscription_id: str,
    definitions: list[dict[str, Any]],
    *,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Recreate custom policy definitions from pre-transfer export."""
    op: dict[str, Any] = {
        "operation": "Restore Custom Policy Definitions",
        "resource_type": "Microsoft.Authorization/policyDefinitions",
        "details": [],
    }
    created = 0
    failed = 0

    try:
        from azure.mgmt.resource.policy import PolicyClient
        client = PolicyClient(credential, subscription_id)

        for pd_item in definitions:
            try:
                if not dry_run:
                    client.policy_definitions.create_or_update(
                        policy_definition_name=pd_item["name"],
                        parameters={
                            "policy_type": "Custom",
                            "mode": pd_item.get("mode", "All"),
                            "display_name": pd_item.get("display_name", ""),
                            "description": pd_item.get("description", ""),
                            "policy_rule": pd_item.get("policy_rule", {}),
                            "parameters": pd_item.get("parameters", {}),
                            "metadata": pd_item.get("metadata", {}),
                        },
                    )
                created += 1
            except Exception as exc:
                failed += 1
                op["details"].append({
                    "action": f"Create definition '{pd_item.get('display_name', pd_item['name'])}'",
                    "status": "failed",
                    "error": str(exc)[:200],
                })

        summary_pd: dict[str, Any] = {
            "action": "Summary",
            "definitions_created": created,
            "definitions_failed": failed,
        }
        if dry_run:
            summary_pd["note"] = "Dry run \u2014 no changes made"
        op["details"].insert(0, summary_pd)
        op["status"] = "dry_run" if dry_run else ("succeeded" if failed == 0 else "partial")
        logger.info("Policy definitions%s: %d created, %d failed", " (dry run)" if dry_run else "", created, failed)

    except Exception as exc:
        op["status"] = "failed"
        op["error"] = str(exc)[:200]
        logger.exception("Policy definition restoration failed")

    return op


# ──────────────────────────────────────────────────────────────────────
# 8. Resource Lock Restoration
# ──────────────────────────────────────────────────────────────────────

def _restore_resource_locks(
    credential: TokenCredential,
    subscription_id: str,
    lock_data: list[dict[str, Any]],
    *,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Recreate resource locks from pre-transfer export."""
    op: dict[str, Any] = {
        "operation": "Restore Resource Locks",
        "resource_type": "Microsoft.Authorization/locks",
        "details": [],
    }
    created = 0
    failed = 0

    try:
        from azure.mgmt.resource.locks import ManagementLockClient
        client = ManagementLockClient(credential, subscription_id)

        for lock in lock_data:
            try:
                params: dict[str, Any] = {
                    "level": lock["level"],
                }
                if lock.get("notes"):
                    params["notes"] = lock["notes"]

                rg = lock.get("resource_group", "")
                if not dry_run:
                    if rg:
                        client.management_locks.create_or_update_at_resource_group_level(
                            resource_group_name=rg,
                            lock_name=lock["name"],
                            parameters=params,
                        )
                    else:
                        client.management_locks.create_or_update_at_subscription_level(
                            lock_name=lock["name"],
                            parameters=params,
                        )
                created += 1
            except Exception as exc:
                failed += 1
                op["details"].append({
                    "action": f"Create lock '{lock['name']}'",
                    "status": "failed",
                    "error": str(exc)[:200],
                })

        summary_lk: dict[str, Any] = {
            "action": "Summary",
            "locks_created": created,
            "locks_failed": failed,
        }
        if dry_run:
            summary_lk["note"] = "Dry run \u2014 no changes made"
        op["details"].insert(0, summary_lk)
        op["status"] = "dry_run" if dry_run else ("succeeded" if failed == 0 else "partial")
        logger.info("Resource locks%s: %d created, %d failed", " (dry run)" if dry_run else "", created, failed)

    except Exception as exc:
        op["status"] = "failed"
        op["error"] = str(exc)[:200]
        logger.exception("Resource lock restoration failed")

    return op


# ──────────────────────────────────────────────────────────────────────
# 9. Key Vault restoration from bundle snapshot
# ──────────────────────────────────────────────────────────────────────

def _restore_keyvault_from_snapshot(
    credential: TokenCredential,
    subscription_id: str,
    vault_snapshot: dict[str, Any],
    principal_mapping: dict[str, str],
    *,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Restore Key Vault access policies using the pre-transfer snapshot."""
    name = vault_snapshot.get("name", "")
    rg = vault_snapshot.get("resource_group", "")
    op: dict[str, Any] = {
        "operation": f"Key Vault (bundle): {name}",
        "resource_type": "Microsoft.KeyVault/vaults",
        "resource_name": name,
        "details": [],
    }

    try:
        from azure.mgmt.keyvault import KeyVaultManagementClient
        client = KeyVaultManagementClient(credential, subscription_id)

        # Get the current vault to read its tenant_id post-transfer
        current_vault = client.vaults.get(rg, name)
        new_tenant_id = str(current_vault.properties.tenant_id)

        new_policies = []
        for ap in vault_snapshot.get("access_policies", []):
            old_oid = ap.get("object_id", "")
            new_oid = principal_mapping.get(old_oid, old_oid)
            new_policies.append({
                "tenantId": new_tenant_id,
                "objectId": new_oid,
                "permissions": ap.get("permissions", {}),
            })
            op["details"].append({
                "action": f"Map policy {old_oid} → {new_oid}",
                "status": "mapped" if new_oid != old_oid else "kept",
            })

        # v13+ uses begin_create_or_update (LRO) instead of create_or_update
        if not dry_run:
            poller = client.vaults.begin_create_or_update(
                resource_group_name=rg,
                vault_name=name,
                parameters={
                    "location": vault_snapshot.get("location", current_vault.location),
                    "properties": {
                        "tenantId": new_tenant_id,
                        "sku": {
                            "family": "A",
                            "name": vault_snapshot.get("sku", current_vault.properties.sku.name.value),
                        },
                        "accessPolicies": new_policies,
                    },
                },
            )
            poller.result()
        op["details"].insert(0, {
            "action": "Summary",
            "policies_restored": len(new_policies),
            "note": "Dry run \u2014 no changes made" if dry_run else None,
        })
        op["status"] = "dry_run" if dry_run else "succeeded"
        action = "simulated" if dry_run else "restored"
        logger.info("Key Vault '%s' %s from bundle (%d policies)", name, action, len(new_policies))

    except Exception as exc:
        op["status"] = "failed"
        op["error"] = str(exc)[:200]
        logger.exception("Key Vault '%s' bundle restoration failed", name)

    return op


# ──────────────────────────────────────────────────────────────────────
# 10. Toggle system-assigned managed identities
# ──────────────────────────────────────────────────────────────────────

def _toggle_managed_identities(
    credential: TokenCredential,
    subscription_id: str,
    resources: list[dict[str, Any]],
    *,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Disable and re-enable system-assigned managed identities.

    After a tenant transfer, system-assigned identities get new
    principal IDs.  Toggling them off/on forces the identity to be
    re-provisioned in the new tenant.
    """
    op: dict[str, Any] = {
        "operation": "Toggle System-Assigned Managed Identities",
        "resource_type": "identity",
        "details": [],
    }
    toggled = 0
    failed = 0

    try:
        from azure.mgmt.resource import ResourceManagementClient
        client = ResourceManagementClient(credential, subscription_id)

        for r in resources:
            resource_id = r.get("id", "")
            name = r.get("name", "")
            try:
                if not dry_run:
                    # Use generic ARM PATCH to toggle identity
                    # Step 1: Disable
                    client.resources.begin_update_by_id(
                        resource_id=resource_id,
                        api_version=_get_api_version(r.get("type", "")),
                        parameters={"identity": {"type": "None"}},
                    ).result()

                    # Step 2: Re-enable
                    client.resources.begin_update_by_id(
                        resource_id=resource_id,
                        api_version=_get_api_version(r.get("type", "")),
                        parameters={"identity": {"type": "SystemAssigned"}},
                    ).result()

                toggled += 1
                op["details"].append({
                    "action": f"Toggled identity on '{name}'",
                    "status": "dry_run" if dry_run else "succeeded",
                })
            except Exception as exc:
                failed += 1
                op["details"].append({
                    "action": f"Toggle identity on '{name}'",
                    "status": "failed",
                    "error": str(exc)[:200],
                })

        summary_mi: dict[str, Any] = {
            "action": "Summary",
            "identities_toggled": toggled,
            "identities_failed": failed,
        }
        if dry_run:
            summary_mi["note"] = "Dry run \u2014 no changes made"
        op["details"].insert(0, summary_mi)
        op["status"] = "dry_run" if dry_run else ("succeeded" if failed == 0 else "partial")
        suffix = " (dry run)" if dry_run else ""
        logger.info("Managed identities toggled%s: %d succeeded, %d failed", suffix, toggled, failed)

    except Exception as exc:
        op["status"] = "failed"
        op["error"] = str(exc)[:200]
        logger.exception("Managed identity toggle failed")

    return op


# ──────────────────────────────────────────────────────────────────────
# 11. Rotate storage account keys
# ──────────────────────────────────────────────────────────────────────

def _rotate_storage_keys(
    credential: TokenCredential,
    subscription_id: str,
    storage_resources: list[dict[str, Any]],
    *,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Rotate access keys on storage accounts to revoke source-tenant access."""
    op: dict[str, Any] = {
        "operation": "Rotate Storage Account Keys",
        "resource_type": "Microsoft.Storage/storageAccounts",
        "details": [],
    }
    rotated = 0
    failed = 0

    try:
        from azure.mgmt.storage import StorageManagementClient
        client = StorageManagementClient(credential, subscription_id)

        for r in storage_resources:
            rg = r.get("resource_group", "")
            name = r.get("name", "")
            try:
                if not dry_run:
                    client.storage_accounts.regenerate_key(
                        resource_group_name=rg,
                        account_name=name,
                        regenerate_key={"key_name": "key1"},
                    )
                    client.storage_accounts.regenerate_key(
                        resource_group_name=rg,
                        account_name=name,
                        regenerate_key={"key_name": "key2"},
                    )
                rotated += 1
                op["details"].append({
                    "action": f"Rotated keys for '{name}'",
                    "status": "dry_run" if dry_run else "succeeded",
                })
            except Exception as exc:
                failed += 1
                op["details"].append({
                    "action": f"Rotate keys for '{name}'",
                    "status": "failed",
                    "error": str(exc)[:200],
                })

        summary_sk: dict[str, Any] = {
            "action": "Summary",
            "accounts_rotated": rotated,
            "accounts_failed": failed,
        }
        if dry_run:
            summary_sk["note"] = "Dry run \u2014 no changes made"
        op["details"].insert(0, summary_sk)
        op["status"] = "dry_run" if dry_run else ("succeeded" if failed == 0 else "partial")
        logger.info("Storage keys rotated%s: %d succeeded, %d failed", " (dry run)" if dry_run else "", rotated, failed)

    except Exception as exc:
        op["status"] = "failed"
        op["error"] = str(exc)[:200]
        logger.exception("Storage key rotation failed")

    return op


# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────

def _find_sami_resources(
    resources: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Find resources with system-assigned managed identities."""
    result: list[dict[str, Any]] = []
    for r in resources:
        identity = r.get("identity", {})
        if isinstance(identity, dict) and identity.get("type", "").lower() in (
            "systemassigned", "systemassigned,userassigned",
        ):
            result.append(r)
        # Also check children
        for child in r.get("children", []):
            child_id = child.get("identity", {})
            if isinstance(child_id, dict) and child_id.get("type", "").lower() in (
                "systemassigned", "systemassigned,userassigned",
            ):
                result.append(child)
    return result


# Common API versions for the generic ARM PATCH approach
_API_VERSIONS: dict[str, str] = {
    "microsoft.compute/virtualmachines": "2024-03-01",
    "microsoft.web/sites": "2023-12-01",
    "microsoft.containerservice/managedclusters": "2024-01-01",
    "microsoft.logic/workflows": "2019-05-01",
    "microsoft.datafactory/factories": "2018-06-01",
    "microsoft.sql/servers": "2023-05-01-preview",
    "microsoft.keyvault/vaults": "2023-07-01",
    "microsoft.automation/automationaccounts": "2023-11-01",
}


def _get_api_version(resource_type: str) -> str:
    """Return a suitable API version for the ARM PATCH call."""
    return _API_VERSIONS.get(resource_type.lower(), "2023-07-01")


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
