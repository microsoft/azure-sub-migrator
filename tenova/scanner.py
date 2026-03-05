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

from typing import Any

from azure.core.credentials import TokenCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.subscription import SubscriptionClient

from tenova.constants import IMPACTED_RESOURCE_TYPES, REQUIRED_ACTIONS
from tenova.exceptions import ResourceScanError
from tenova.logger import get_logger

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
    try:
        client = ResourceManagementClient(credential, subscription_id)

        # ── Step 1: Query Resource Graph for runtime-detected impacted IDs ──
        graph_impacted_ids = _query_resource_graph(credential, subscription_id)

        # ── Step 2: Enumerate all resources and classify ──
        transfer_safe: list[dict[str, Any]] = []
        requires_action: list[dict[str, Any]] = []

        for resource in client.resources.list():
            resource_type = resource.type or ""
            resource_id = resource.id or ""
            entry: dict[str, Any] = {
                "id": resource_id,
                "name": resource.name,
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
        return {"transfer_safe": transfer_safe, "requires_action": requires_action}

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
# Helpers
# ──────────────────────────────────────────────────────────────────────

def _is_impacted(resource_type: str) -> bool:
    """Check whether *resource_type* is in the known-impacted static list."""
    return resource_type.lower() in {rt.lower() for rt in IMPACTED_RESOURCE_TYPES}


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
