# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""Resource scanner — lists subscriptions and classifies resources.

Queries the Azure Resource Manager to enumerate every resource in a
subscription, then classifies each as *transfer-safe* (will keep working
after a cross-tenant subscription transfer) or *requires-action* (has
tenant-bound dependencies that will break and need reconfiguration).

Detection uses a two-layer approach:
  1. **Runtime** — Azure Resource Graph query from Microsoft's official
     sample queries that checks for known impacted types (Key Vault, AKS,
     SQL, Data Lake, User-Assigned Managed Identities), resources with
     SystemAssigned identity, and ADLS Gen2 storage accounts.
  2. **Static fallback** — a curated list of known-impacted resource types
     for cases where Resource Graph access is unavailable.

References:
https://learn.microsoft.com/en-us/azure/governance/resource-graph/samples/samples-by-category#list-impacted-resources-when-transferring-an-azure-subscription
https://learn.microsoft.com/en-us/azure/role-based-access-control/transfer-subscription
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from azure.core.credentials import TokenCredential
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.resource.locks import ManagementLockClient
from azure.mgmt.resource.policy import PolicyClient
from azure.mgmt.subscription import SubscriptionClient

from azure_sub_migrator.constants import IMPACTED_RESOURCE_TYPES, REQUIRED_ACTIONS, TRANSFER_NOTES
from azure_sub_migrator.exceptions import ResourceScanError
from azure_sub_migrator.logger import get_logger

logger = get_logger("scanner")


# ──────────────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────────────

def list_subscriptions(credential: TokenCredential) -> list[dict[str, str]]:
    """Return a list of subscriptions accessible with *credential*.

    Each item has keys: ``subscription_id``, ``display_name``, ``state``.
    """
    try:
        client = SubscriptionClient(credential)
        subs: list[dict[str, str]] = []
        for sub in client.subscriptions.list():
            subs.append(
                {
                    "subscription_id": sub.subscription_id,
                    "display_name": sub.display_name or "",
                    "state": str(sub.state) if sub.state else "Unknown",
                }
            )
        logger.info("Found %d subscription(s)", len(subs))
        return subs
    except Exception as exc:
        raise ResourceScanError(f"Failed to list subscriptions: {exc}") from exc


def scan_subscription(
    credential: TokenCredential,
    subscription_id: str,
    *,
    on_progress: Callable[[str, int, int], None] | None = None,
) -> dict[str, list[dict[str, Any]]]:
    """Scan all resources in *subscription_id* and classify them.

    All resources physically transfer with the subscription.  The
    classification identifies which ones will need post-transfer action.

    Detection strategy:
      1. Try Azure Resource Graph to find resources with tenant-bound
         properties (identity, tenantId, encryption).
      2. Merge with the static known-impacted type list so nothing is missed.

    Returns
    -------
    dict with two keys:
        - ``transfer_safe``    – resources with no tenant-bound dependencies.
        - ``requires_action``  – resources that will break or need
          reconfiguration after the cross-tenant transfer.
    """
    logger.info("Scanning subscription %s", subscription_id)
    _progress = on_progress or (lambda *_: None)
    try:
        client = ResourceManagementClient(credential, subscription_id)

        # ── Step 1: Query Resource Graph for runtime-detected impacted IDs ──
        _progress("Querying Resource Graph", 1, 6)
        graph_impacted_ids = _query_resource_graph(credential, subscription_id)

        # ── Step 2: Enumerate all resources and classify ──
        _progress("Enumerating resources", 2, 6)
        transfer_safe: list[dict[str, Any]] = []
        requires_action: list[dict[str, Any]] = []

        for resource in client.resources.list():
            resource_type = resource.type or ""
            resource_id = resource.id or ""

            # For child resources (e.g. VM extensions), build a display
            # name from the resource ID so "ArcBox-Win2K22/AzureMonitorWindowsAgent"
            # is shown instead of just "AzureMonitorWindowsAgent".
            display_name = _extract_display_name(resource_id, resource.name)

            entry: dict[str, Any] = {
                "id": resource_id,
                "name": display_name,
                "type": resource_type,
                "location": resource.location,
                "resource_group": _extract_resource_group(resource_id),
            }

            # A resource is impacted if EITHER detection layer flags it
            in_graph = resource_id.lower() in graph_impacted_ids
            in_static = _is_impacted(resource_type)

            if in_graph or in_static:
                # Determine reason for flagging
                reasons: list[str] = []
                if in_graph:
                    reasons.append("runtime (Resource Graph: identity/tenantId/encryption)")
                if in_static:
                    reasons.append("known impacted type")
                entry["detection"] = " + ".join(reasons)

                action_info = REQUIRED_ACTIONS.get(resource_type, {})
                entry["timing"] = action_info.get("timing", "post")
                entry["pre_action"] = action_info.get("pre", "")
                entry["post_action"] = action_info.get("post", "")
                entry["doc_url"] = action_info.get(
                    "doc_url",
                    "https://learn.microsoft.com/en-us/azure/role-based-access-control/transfer-subscription",
                )
                if not action_info:
                    entry["post_action"] = (
                        "Disable and re-enable the system-assigned managed identity. "
                        "Recreate any RBAC role assignments for target-tenant principals."
                    )
                requires_action.append(entry)
            else:
                transfer_safe.append(entry)

        logger.info(
            "Scan complete: %d transfer-safe, %d requires-action "
            "(Resource Graph found %d impacted)",
            len(transfer_safe),
            len(requires_action),
            len(graph_impacted_ids),
        )

        # ── Step 3: Discover policy objects (separate API namespace) ──
        _progress("Discovering policies", 3, 6)
        # Policy assignments/definitions are NOT returned by resources.list()
        # but are permanently deleted during cross-tenant transfer.
        policy_items = _collect_policy_items(credential, subscription_id)
        requires_action.extend(policy_items)
        if policy_items:
            logger.info("Added %d policy item(s) to requires-action", len(policy_items))

        # ── Step 4: Discover RBAC items (separate API namespace) ──
        _progress("Discovering RBAC assignments", 4, 6)
        # Role assignments and custom roles are permanently deleted.
        rbac_items = _collect_rbac_items(credential, subscription_id)
        requires_action.extend(rbac_items)
        if rbac_items:
            logger.info("Added %d RBAC item(s) to requires-action", len(rbac_items))

        # ── Step 5: Discover resource locks ──
        _progress("Discovering resource locks", 5, 6)
        # Locks should be exported before transfer and recreated after.
        lock_items = _collect_lock_items(credential, subscription_id)
        requires_action.extend(lock_items)
        if lock_items:
            logger.info("Added %d lock item(s) to requires-action", len(lock_items))

        # ── Step 6: Build hierarchical parent-child view ──
        _progress("Building hierarchy", 6, 6)
        # If a child resource (e.g. VM extension) requires action but its
        # parent (e.g. VM) was classified as transfer-safe, promote the
        # parent into requires_action and nest children underneath it.
        transfer_safe, requires_action = _build_hierarchy(
            transfer_safe, requires_action,
        )

        return {
            "transfer_safe": transfer_safe,
            "requires_action": requires_action,
            "transfer_notes": TRANSFER_NOTES,
        }

    except Exception as exc:
        raise ResourceScanError(f"Failed to scan subscription {subscription_id}: {exc}") from exc


# ──────────────────────────────────────────────────────────────────────
# Resource Graph — runtime detection
# ──────────────────────────────────────────────────────────────────────

# KQL query from the official Microsoft Resource Graph samples:
# https://learn.microsoft.com/en-us/azure/governance/resource-graph/samples/samples-by-category#list-impacted-resources-when-transferring-an-azure-subscription
#
# Adapted to project individual resource IDs instead of summarize count()
# so we can flag each resource individually in our scan results.
_RESOURCE_GRAPH_QUERY = """\
Resources
| where type in (
    'microsoft.managedidentity/userassignedidentities',
    'microsoft.keyvault/vaults',
    'microsoft.sql/servers/databases',
    'microsoft.datalakestore/accounts',
    'microsoft.containerservice/managedclusters')
    or identity has 'SystemAssigned'
    or (type =~ 'microsoft.storage/storageaccounts' and properties['isHnsEnabled'] == true)
| project id, name, type
"""


def _query_resource_graph(
    credential: TokenCredential,
    subscription_id: str,
) -> set[str]:
    """Query Azure Resource Graph for resources with tenant-bound dependencies.

    Returns a set of **lower-cased** resource IDs that are impacted.
    Falls back to an empty set if Resource Graph is unavailable.
    """
    try:
        from azure.mgmt.resourcegraph import ResourceGraphClient
        from azure.mgmt.resourcegraph.models import (
            QueryRequest,
            QueryRequestOptions,
            ResultFormat,
        )
    except ImportError:
        logger.warning(
            "azure-mgmt-resourcegraph is not installed — "
            "falling back to static type list only.  "
            "Install it for runtime detection: pip install azure-mgmt-resourcegraph"
        )
        return set()

    try:
        rg_client = ResourceGraphClient(credential)
        request = QueryRequest(
            subscriptions=[subscription_id],
            query=_RESOURCE_GRAPH_QUERY,
            options=QueryRequestOptions(result_format=ResultFormat.OBJECT_ARRAY),
        )
        response = rg_client.resources(request)
        impacted_ids: set[str] = set()
        for row in response.data or []:
            rid = row.get("id", "") if isinstance(row, dict) else ""
            if rid:
                impacted_ids.add(rid.lower())

        logger.info(
            "Resource Graph returned %d impacted resources for subscription %s",
            len(impacted_ids),
            subscription_id,
        )
        return impacted_ids

    except Exception as exc:
        logger.warning(
            "Resource Graph query failed (will use static list only): %s", exc
        )
        return set()


# ──────────────────────────────────────────────────────────────────────
# Policy discovery — lightweight count-only scan
# ──────────────────────────────────────────────────────────────────────

def _collect_policy_items(
    credential: TokenCredential,
    subscription_id: str,
) -> list[dict[str, Any]]:
    """Discover policy assignments and custom definitions via the Policy API.

    These objects live in a separate ARM namespace and are NOT returned by
    ``resources.list()``.  They are **permanently deleted** during a
    cross-tenant subscription transfer and must be recreated afterward.

    Returns lightweight summary entries (one per category) to be merged
    into the ``requires_action`` list.
    """
    items: list[dict[str, Any]] = []
    try:
        client = PolicyClient(credential, subscription_id)

        # ── Policy Assignments ─────────────────────────────────────
        assignment_count = 0
        assignment_names: list[str] = []
        for pa in client.policy_assignments.list():
            assignment_count += 1
            name = pa.display_name or pa.name or ""
            if len(assignment_names) < 5:  # keep first 5 for display
                assignment_names.append(name)

        if assignment_count > 0:
            action_info = REQUIRED_ACTIONS.get(
                "Microsoft.Authorization/policyAssignments", {}
            )
            sample_text = ", ".join(assignment_names)
            if assignment_count > 5:
                sample_text += f", … (+{assignment_count - 5} more)"
            items.append({
                "id": f"/subscriptions/{subscription_id}/providers/Microsoft.Authorization/policyAssignments",
                "name": f"{assignment_count} policy assignment(s): {sample_text}",
                "type": "Microsoft.Authorization/policyAssignments",
                "location": "subscription-wide",
                "resource_group": "—",
                "detection": "policy API",
                "timing": action_info.get("timing", "pre"),
                "pre_action": action_info.get("pre", ""),
                "post_action": action_info.get("post", ""),
                "doc_url": action_info.get("doc_url", ""),
            })
            logger.info("Found %d policy assignment(s)", assignment_count)

        # ── Custom Policy Definitions ──────────────────────────────
        custom_def_count = 0
        custom_def_names: list[str] = []
        for pd in client.policy_definitions.list(
            filter="policyType eq 'Custom'",
        ):
            custom_def_count += 1
            name = pd.display_name or pd.name or ""
            if len(custom_def_names) < 5:
                custom_def_names.append(name)

        if custom_def_count > 0:
            action_info = REQUIRED_ACTIONS.get(
                "Microsoft.Authorization/policyDefinitions", {}
            )
            sample_text = ", ".join(custom_def_names)
            if custom_def_count > 5:
                sample_text += f", … (+{custom_def_count - 5} more)"
            items.append({
                "id": f"/subscriptions/{subscription_id}/providers/Microsoft.Authorization/policyDefinitions",
                "name": f"{custom_def_count} custom policy definition(s): {sample_text}",
                "type": "Microsoft.Authorization/policyDefinitions",
                "location": "subscription-wide",
                "resource_group": "—",
                "detection": "policy API",
                "timing": action_info.get("timing", "pre"),
                "pre_action": action_info.get("pre", ""),
                "post_action": action_info.get("post", ""),
                "doc_url": action_info.get("doc_url", ""),
            })
            logger.info("Found %d custom policy definition(s)", custom_def_count)

    except Exception as exc:
        # Policy API failure should NOT block the entire scan
        logger.warning("Policy discovery failed (non-fatal): %s", exc)

    return items


# ──────────────────────────────────────────────────────────────────────
# RBAC discovery — role assignments & custom roles
# ──────────────────────────────────────────────────────────────────────

def _collect_rbac_items(
    credential: TokenCredential,
    subscription_id: str,
) -> list[dict[str, Any]]:
    """Discover RBAC role assignments and custom role definitions.

    Role assignments and custom roles live under ``Microsoft.Authorization``
    and are NOT returned by ``resources.list()``.  Both are **permanently
    deleted** during a cross-tenant subscription transfer.

    Returns lightweight summary entries to merge into ``requires_action``.
    """
    items: list[dict[str, Any]] = []
    try:
        client = AuthorizationManagementClient(credential, subscription_id)

        # ── Role Assignments ───────────────────────────────────
        assignment_count = sum(1 for _ in client.role_assignments.list_for_subscription())

        if assignment_count > 0:
            action_info = REQUIRED_ACTIONS.get(
                "Microsoft.Authorization/roleAssignments", {}
            )
            items.append({
                "id": f"/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleAssignments",
                "name": f"{assignment_count} role assignment(s) (all permanently deleted during transfer)",
                "type": "Microsoft.Authorization/roleAssignments",
                "location": "subscription-wide",
                "resource_group": "—",
                "detection": "authorization API",
                "timing": action_info.get("timing", "pre"),
                "pre_action": action_info.get("pre", ""),
                "post_action": action_info.get("post", ""),
                "doc_url": action_info.get("doc_url", ""),
            })
            logger.info("Found %d role assignment(s)", assignment_count)

        # ── Custom Role Definitions ─────────────────────────────
        scope = f"/subscriptions/{subscription_id}"
        custom_role_count = 0
        custom_role_names: list[str] = []
        for rd in client.role_definitions.list(scope, filter="type eq 'CustomRole'"):
            custom_role_count += 1
            name = rd.role_name or rd.name or ""
            if len(custom_role_names) < 5:
                custom_role_names.append(name)

        if custom_role_count > 0:
            action_info = REQUIRED_ACTIONS.get(
                "Microsoft.Authorization/roleDefinitions", {}
            )
            sample_text = ", ".join(custom_role_names)
            if custom_role_count > 5:
                sample_text += f", … (+{custom_role_count - 5} more)"
            items.append({
                "id": f"/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleDefinitions",
                "name": f"{custom_role_count} custom role(s): {sample_text}",
                "type": "Microsoft.Authorization/roleDefinitions",
                "location": "subscription-wide",
                "resource_group": "—",
                "detection": "authorization API",
                "timing": action_info.get("timing", "pre"),
                "pre_action": action_info.get("pre", ""),
                "post_action": action_info.get("post", ""),
                "doc_url": action_info.get("doc_url", ""),
            })
            logger.info("Found %d custom role definition(s)", custom_role_count)

    except Exception as exc:
        # RBAC API failure should NOT block the entire scan
        logger.warning("RBAC discovery failed (non-fatal): %s", exc)

    return items


# ──────────────────────────────────────────────────────────────────────
# Resource lock discovery
# ──────────────────────────────────────────────────────────────────────

def _collect_lock_items(
    credential: TokenCredential,
    subscription_id: str,
) -> list[dict[str, Any]]:
    """Discover resource locks in the subscription.

    Resource locks live under ``Microsoft.Authorization/locks`` and are NOT
    returned by ``resources.list()``.  They should be exported before
    transfer and recreated afterward.

    Returns a lightweight summary entry to merge into ``requires_action``.
    """
    items: list[dict[str, Any]] = []
    try:
        client = ManagementLockClient(credential, subscription_id)

        lock_count = 0
        lock_names: list[str] = []
        for lock in client.management_locks.list_at_subscription_level():
            lock_count += 1
            name = lock.name or ""
            level = str(lock.level) if lock.level else ""
            display = f"{name} ({level})" if level else name
            if len(lock_names) < 5:
                lock_names.append(display)

        if lock_count > 0:
            action_info = REQUIRED_ACTIONS.get(
                "Microsoft.Authorization/locks", {}
            )
            sample_text = ", ".join(lock_names)
            if lock_count > 5:
                sample_text += f", … (+{lock_count - 5} more)"
            items.append({
                "id": f"/subscriptions/{subscription_id}/providers/Microsoft.Authorization/locks",
                "name": f"{lock_count} resource lock(s): {sample_text}",
                "type": "Microsoft.Authorization/locks",
                "location": "subscription-wide",
                "resource_group": "—",
                "detection": "locks API",
                "timing": action_info.get("timing", "pre"),
                "pre_action": action_info.get("pre", ""),
                "post_action": action_info.get("post", ""),
                "doc_url": action_info.get("doc_url", ""),
            })
            logger.info("Found %d resource lock(s)", lock_count)

    except Exception as exc:
        # Lock API failure should NOT block the entire scan
        logger.warning("Resource lock discovery failed (non-fatal): %s", exc)

    return items


# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────

def _is_impacted(resource_type: str) -> bool:
    """Check whether *resource_type* is in the known-impacted static list."""
    return resource_type.lower() in {rt.lower() for rt in IMPACTED_RESOURCE_TYPES}


def _find_parent_id(resource_id: str) -> str | None:
    """Return the ARM resource ID of the parent resource, or None for top-level.

    Azure child resources have IDs like::

        .../Microsoft.Compute/virtualMachines/vm1/extensions/ext1

    The parent ID is everything up to (but not including) the last
    ``/childType/childName`` segment::

        .../Microsoft.Compute/virtualMachines/vm1

    Subscription-wide items (policies, RBAC, locks) have no "providers"
    segment in the format we need, so return None for those.
    """
    if not resource_id:
        return None
    parts = resource_id.split("/")
    try:
        idx = [p.lower() for p in parts].index("providers")
    except ValueError:
        return None
    # After "providers": provider/type/name[/childType/childName/...]
    after = parts[idx + 1:]  # e.g. [Provider, Type, Name, ChildType, ChildName]
    # A top-level resource has exactly 3 segments: provider, type, name
    # A child resource has 5+: provider, type, name, childType, childName, ...
    if len(after) <= 3:
        return None  # top-level → no parent
    # Parent ID = everything up to (but not including) last 2 segments
    parent_parts = parts[: -2]
    return "/".join(parent_parts)


def _build_hierarchy(
    transfer_safe: list[dict[str, Any]],
    requires_action: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Nest child resources under their parents and promote parents.

    Rules:
    1. If a child resource is in *requires_action* and its parent is in
       *transfer_safe*, the parent is **promoted** to *requires_action*
       (tagged as promoted, with its own timing set to ``"post"`` and a
       note that it was promoted due to its children).
    2. Child resources are nested inside their parent's ``children`` list
       and removed from the top-level *requires_action*.
    3. If a child's parent is already in *requires_action* the children
       are simply nested — no promotion needed.
    4. Resources without a discoverable parent (subscription-wide policy,
       RBAC, locks) remain as flat top-level entries.
    """
    # Index all resources by lower-cased ID for fast lookup
    safe_by_id: dict[str, dict[str, Any]] = {}
    for r in transfer_safe:
        rid = (r.get("id") or "").lower()
        if rid:
            safe_by_id[rid] = r

    action_by_id: dict[str, dict[str, Any]] = {}
    for r in requires_action:
        rid = (r.get("id") or "").lower()
        if rid:
            action_by_id[rid] = r

    # Track which requires_action entries become children (to remove later)
    nested_ids: set[str] = set()
    # Track which transfer_safe entries get promoted (to remove later)
    promoted_ids: set[str] = set()

    # Pass 1 — find children in requires_action whose parent exists
    for r in list(requires_action):
        rid = (r.get("id") or "").lower()
        parent_id = _find_parent_id(rid)
        if not parent_id:
            continue
        parent_id_lower = parent_id.lower()

        # Parent already in requires_action — just nest
        if parent_id_lower in action_by_id:
            parent = action_by_id[parent_id_lower]
            parent.setdefault("children", []).append(r)
            nested_ids.add(rid)
            continue

        # Parent in transfer_safe — promote it
        if parent_id_lower in safe_by_id:
            parent = safe_by_id[parent_id_lower]
            parent.setdefault("children", []).append(r)
            if parent_id_lower not in promoted_ids:
                # Mark as promoted (not inherently impacted itself)
                parent["promoted"] = True
                parent["timing"] = "post"
                parent["pre_action"] = ""
                parent["post_action"] = (
                    "This resource has child resources that require action. "
                    "See children below."
                )
                parent["detection"] = "child resource requires action"
                parent["doc_url"] = (
                    "https://learn.microsoft.com/en-us/azure/role-based-access-control/"
                    "transfer-subscription"
                )
                # Move to action_by_id so subsequent children find it
                action_by_id[parent_id_lower] = parent
                promoted_ids.add(parent_id_lower)
            nested_ids.add(rid)

    # Build new flat lists excluding nested/promoted items
    new_safe = [
        r for r in transfer_safe
        if (r.get("id") or "").lower() not in promoted_ids
    ]
    new_action = [
        r for r in requires_action
        if (r.get("id") or "").lower() not in nested_ids
    ]
    # Add promoted parents (they're not in the original requires_action list)
    for pid in promoted_ids:
        parent = action_by_id[pid]
        new_action.append(parent)

    logger.info(
        "Hierarchy: promoted %d parent(s), nested %d child(ren)",
        len(promoted_ids),
        len(nested_ids),
    )
    return new_safe, new_action


def _extract_resource_group(resource_id: str | None) -> str:
    """Extract the resource-group name from a full ARM resource ID."""
    if not resource_id:
        return ""
    parts = resource_id.split("/")
    try:
        idx = [p.lower() for p in parts].index("resourcegroups")
        return parts[idx + 1]
    except (ValueError, IndexError):
        return ""


def _extract_display_name(resource_id: str | None, fallback_name: str | None) -> str:
    """Build a display name for a resource from its ARM ID.

    For top-level resources the SDK ``name`` is fine, but for child
    resources (e.g. VM extensions) the SDK returns only the leaf name
    (``AzureMonitorWindowsAgent``).  This helper extracts the full
    name path from the resource ID so the user sees
    ``ArcBox-Win2K22/AzureMonitorWindowsAgent`` instead.
    """
    name = fallback_name or ""
    if not resource_id:
        return name
    # Find the provider segment and take everything after the resource type
    parts = resource_id.split("/")
    try:
        idx = [p.lower() for p in parts].index("providers")
        # After providers: provider/type/name[/childType/childName/...]
        after_provider = parts[idx + 1 :]  # e.g. [Provider, Type, Name, ChildType, ChildName]
        # Names sit at odd positions (0-indexed from after_provider):
        # idx 0 = provider, 1 = type, 2 = name, 3 = childType, 4 = childName, …
        name_parts = [after_provider[i] for i in range(2, len(after_provider), 2)]
        if name_parts:
            return "/".join(name_parts)
    except (ValueError, IndexError):
        pass
    return name
