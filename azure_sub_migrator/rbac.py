# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""RBAC and managed-identity operations for cross-tenant transfer.

Role assignments and custom role definitions are **permanently deleted**
during a cross-tenant subscription transfer.  This module provides:

* **Export** — snapshot role assignments, custom roles, and managed
  identities to a JSON file *before* the transfer.
* **Import** — recreate them in the target tenant *after* the transfer
  using the exported JSON and a principal-mapping file.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from azure.core.credentials import TokenCredential
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.msi import ManagedServiceIdentityClient

from azure_sub_migrator.exceptions import RBACError
from azure_sub_migrator.logger import get_logger

logger = get_logger("rbac")


# ──────────────────────────────────────────────────────────────────────
# Role Assignments
# ──────────────────────────────────────────────────────────────────────

def list_role_assignments(
    credential: TokenCredential,
    subscription_id: str,
) -> list[dict[str, Any]]:
    """List all role assignments in *subscription_id*."""
    try:
        client = AuthorizationManagementClient(credential, subscription_id)
        assignments: list[dict[str, Any]] = []
        for ra in client.role_assignments.list_for_subscription():
            assignments.append(
                {
                    "id": ra.id,
                    "name": ra.name,
                    "principal_id": ra.principal_id,
                    "principal_type": str(ra.principal_type) if ra.principal_type else "",
                    "role_definition_id": ra.role_definition_id,
                    "scope": ra.scope,
                }
            )
        logger.info("Found %d role assignment(s)", len(assignments))
        return assignments
    except Exception as exc:
        raise RBACError(f"Failed to list role assignments: {exc}") from exc


def list_custom_roles(
    credential: TokenCredential,
    subscription_id: str,
) -> list[dict[str, Any]]:
    """List all custom role definitions in *subscription_id*."""
    try:
        client = AuthorizationManagementClient(credential, subscription_id)
        custom_roles: list[dict[str, Any]] = []
        for rd in client.role_definitions.list(
            scope=f"/subscriptions/{subscription_id}",
            filter="type eq 'CustomRole'",
        ):
            custom_roles.append(
                {
                    "id": rd.id,
                    "name": rd.role_name,
                    "description": rd.description or "",
                    "role_type": str(rd.role_type) if rd.role_type else "",
                    "permissions": [
                        {
                            "actions": list(p.actions or []),
                            "not_actions": list(p.not_actions or []),
                            "data_actions": list(p.data_actions or []),
                            "not_data_actions": list(p.not_data_actions or []),
                        }
                        for p in (rd.permissions or [])
                    ],
                    "assignable_scopes": list(rd.assignable_scopes or []),
                }
            )
        logger.info("Found %d custom role(s)", len(custom_roles))
        return custom_roles
    except Exception as exc:
        raise RBACError(f"Failed to list custom roles: {exc}") from exc


def recreate_role_assignments(
    credential: TokenCredential,
    subscription_id: str,
    assignments: list[dict[str, Any]],
    principal_mapping: dict[str, str],
) -> list[dict[str, Any]]:
    """Recreate role assignments in the target subscription.

    Parameters
    ----------
    principal_mapping:
        Maps old principal IDs → new principal IDs in the target tenant.

    Returns
    -------
    list of created assignment dicts.
    """
    client = AuthorizationManagementClient(credential, subscription_id)
    created: list[dict[str, Any]] = []

    for ra in assignments:
        old_principal = ra["principal_id"]
        new_principal = principal_mapping.get(old_principal)
        if not new_principal:
            logger.warning(
                "No mapping for principal %s — skipping assignment %s",
                old_principal,
                ra["id"],
            )
            continue

        new_name = str(uuid.uuid4())
        try:
            result = client.role_assignments.create(
                scope=ra["scope"],
                role_assignment_name=new_name,
                parameters={
                    "properties": {
                        "role_definition_id": ra["role_definition_id"],
                        "principal_id": new_principal,
                    }
                },
            )
            created.append({"name": result.name, "principal_id": new_principal})
            logger.info("Created role assignment %s for principal %s", result.name, new_principal)
        except Exception as exc:
            logger.error("Failed to create assignment for principal %s: %s", new_principal, exc)

    return created


# ──────────────────────────────────────────────────────────────────────
# Managed Identities
# ──────────────────────────────────────────────────────────────────────

def list_managed_identities(
    credential: TokenCredential,
    subscription_id: str,
) -> list[dict[str, Any]]:
    """List user-assigned managed identities in *subscription_id*."""
    try:
        client = ManagedServiceIdentityClient(credential, subscription_id)
        identities: list[dict[str, Any]] = []
        for mi in client.user_assigned_identities.list_by_subscription():
            identities.append(
                {
                    "id": mi.id,
                    "name": mi.name,
                    "location": mi.location,
                    "resource_group": _extract_rg(mi.id),
                    "client_id": mi.client_id,
                    "principal_id": mi.principal_id,
                }
            )
        logger.info("Found %d managed identity(ies)", len(identities))
        return identities
    except Exception as exc:
        raise RBACError(f"Failed to list managed identities: {exc}") from exc


# ──────────────────────────────────────────────────────────────────────
# Export / Import
# ──────────────────────────────────────────────────────────────────────

def export_rbac(
    credential: TokenCredential,
    subscription_id: str,
    output_dir: Path | str = "migration_output",
) -> Path:
    """Export role assignments, custom roles, and managed identities to JSON.

    Creates a timestamped JSON file containing everything needed to
    recreate RBAC in the target tenant after the subscription transfer.

    Returns the path to the exported JSON file.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    logger.info("Exporting RBAC for subscription %s …", subscription_id)

    assignments = list_role_assignments(credential, subscription_id)
    custom = list_custom_roles(credential, subscription_id)
    identities = list_managed_identities(credential, subscription_id)

    export_data = {
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "subscription_id": subscription_id,
        "role_assignments": assignments,
        "custom_roles": custom,
        "managed_identities": identities,
        "summary": {
            "role_assignment_count": len(assignments),
            "custom_role_count": len(custom),
            "managed_identity_count": len(identities),
        },
    }

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"rbac_export_{subscription_id[:8]}_{timestamp}.json"
    filepath = output_dir / filename
    filepath.write_text(json.dumps(export_data, indent=2), encoding="utf-8")

    logger.info(
        "RBAC export complete → %s  (%d assignments, %d custom roles, %d identities)",
        filepath,
        len(assignments),
        len(custom),
        len(identities),
    )
    return filepath


def import_rbac(
    credential: TokenCredential,
    subscription_id: str,
    export_path: Path | str,
    principal_mapping: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Import RBAC from a previously exported JSON file.

    Parameters
    ----------
    export_path:
        Path to the JSON file created by ``export_rbac``.
    principal_mapping:
        Optional dict mapping old principal IDs → new principal IDs.
        If not provided, assignments are created with the original
        principal IDs (useful when principals exist in both tenants).

    Returns
    -------
    Summary dict with counts of created/skipped/failed items.
    """
    export_path = Path(export_path)
    data = json.loads(export_path.read_text(encoding="utf-8"))

    mapping = principal_mapping or {}
    results: dict[str, Any] = {
        "role_assignments_created": 0,
        "role_assignments_skipped": 0,
        "role_assignments_failed": 0,
        "custom_roles_created": 0,
        "custom_roles_failed": 0,
        "errors": [],
    }

    # 1) Recreate custom roles first (assignments may reference them)
    client = AuthorizationManagementClient(credential, subscription_id)
    for role in data.get("custom_roles", []):
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
            results["custom_roles_created"] += 1
            logger.info("Created custom role: %s", role["name"])
        except Exception as exc:
            results["custom_roles_failed"] += 1
            results["errors"].append(f"Custom role '{role['name']}': {exc}")
            logger.error("Failed to create custom role '%s': %s", role["name"], exc)

    # 2) Recreate role assignments
    for ra in data.get("role_assignments", []):
        old_principal = ra["principal_id"]
        new_principal = mapping.get(old_principal, old_principal)

        new_name = str(uuid.uuid4())
        try:
            client.role_assignments.create(
                scope=ra["scope"],
                role_assignment_name=new_name,
                parameters={
                    "properties": {
                        "role_definition_id": ra["role_definition_id"],
                        "principal_id": new_principal,
                    }
                },
            )
            results["role_assignments_created"] += 1
        except Exception as exc:
            err_str = str(exc)
            if "PrincipalNotFound" in err_str or "does not exist" in err_str:
                results["role_assignments_skipped"] += 1
                logger.warning("Skipped — principal %s not found in target tenant", new_principal)
            else:
                results["role_assignments_failed"] += 1
                results["errors"].append(f"Assignment for {new_principal}: {exc}")
                logger.error("Failed to create assignment for %s: %s", new_principal, exc)

    logger.info(
        "RBAC import complete: %d created, %d skipped, %d failed",
        results["role_assignments_created"],
        results["role_assignments_skipped"],
        results["role_assignments_failed"],
    )
    return results


def _extract_rg(resource_id: str | None) -> str:
    if not resource_id:
        return ""
    parts = resource_id.split("/")
    try:
        idx = [p.lower() for p in parts].index("resourcegroups")
        return parts[idx + 1]
    except (ValueError, IndexError):
        return ""
