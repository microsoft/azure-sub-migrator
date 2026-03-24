"""Cross-subscription dependency analysis.

Scans multiple Azure subscriptions in parallel and identifies
dependencies between them — VNet peering, Private Endpoints,
Private DNS Zone links, diagnostic settings forwarding, and
generic cross-subscription resource references embedded in
resource properties.

The result is a lightweight dependency graph that helps operators
plan the transfer order and understand what will break if a single
subscription is transferred in isolation.
"""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from azure.core.credentials import TokenCredential

from tenova.logger import get_logger
from tenova.scanner import scan_subscription

logger = get_logger("cross_sub")

# Regex that extracts subscription IDs from ARM resource ID strings.
_SUB_ID_RE = re.compile(
    r"/subscriptions/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
    re.IGNORECASE,
)


# ──────────────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────────────

def analyze_cross_sub_dependencies(
    credential: TokenCredential,
    subscription_ids: list[str],
) -> dict[str, Any]:
    """Scan multiple subscriptions and detect cross-sub dependencies.

    Parameters
    ----------
    credential : TokenCredential
        Azure credential with Reader access to all subscriptions.
    subscription_ids : list[str]
        Two or more subscription IDs to analyze.

    Returns
    -------
    dict with keys:
        - ``subscriptions`` – per-sub scan summaries (id, name, counts).
        - ``dependencies`` – list of edge dicts describing each dependency.
        - ``matrix`` – adjacency dict  ``{source_sub: {target_sub: count}}``.
        - ``suggested_order`` – topological sort hint (least-depended first).
    """
    if len(subscription_ids) < 2:
        return {
            "subscriptions": [],
            "dependencies": [],
            "matrix": {},
            "suggested_order": subscription_ids[:],
            "error": "At least two subscriptions are required for cross-sub analysis.",
        }

    sub_set = {s.lower() for s in subscription_ids}

    # ── Step 1: Scan each subscription (parallel) ──
    scan_results: dict[str, dict[str, Any]] = {}
    with ThreadPoolExecutor(max_workers=min(len(subscription_ids), 4)) as pool:
        futures = {
            pool.submit(scan_subscription, credential, sid): sid
            for sid in subscription_ids
        }
        for future in as_completed(futures):
            sid = futures[future]
            try:
                scan_results[sid] = future.result()
            except Exception as exc:
                logger.warning("Scan failed for %s: %s", sid, exc)
                scan_results[sid] = {"transfer_safe": [], "requires_action": [], "error": str(exc)}

    # ── Step 2: Detect cross-sub references via targeted SDK calls ──
    dependencies: list[dict[str, Any]] = []

    for sid in subscription_ids:
        try:
            deps = _detect_vnet_peering(credential, sid, sub_set)
            dependencies.extend(deps)
        except Exception as exc:
            logger.warning("VNet peering detection failed for %s: %s", sid, exc)

        try:
            deps = _detect_private_endpoints(credential, sid, sub_set)
            dependencies.extend(deps)
        except Exception as exc:
            logger.warning("Private endpoint detection failed for %s: %s", sid, exc)

        try:
            deps = _detect_private_dns_links(credential, sid, sub_set)
            dependencies.extend(deps)
        except Exception as exc:
            logger.warning("Private DNS link detection failed for %s: %s", sid, exc)

        try:
            deps = _detect_diagnostic_settings(credential, sid, sub_set)
            dependencies.extend(deps)
        except Exception as exc:
            logger.warning("Diagnostic settings detection failed for %s: %s", sid, exc)

    # ── Step 3: Generic cross-sub reference scan via resource IDs ──
    for sid in subscription_ids:
        scan = scan_results.get(sid, {})
        all_resources = scan.get("transfer_safe", []) + scan.get("requires_action", [])
        for resource in all_resources:
            refs = _find_cross_sub_references(resource, sid, sub_set)
            dependencies.extend(refs)

    # ── Step 4: Deduplicate ──
    dependencies = _deduplicate(dependencies)

    # ── Step 5: Build summary structures ──
    matrix = _build_matrix(dependencies, subscription_ids)
    subscriptions = _build_sub_summaries(subscription_ids, scan_results, matrix)
    suggested_order = _suggest_order(subscription_ids, matrix)

    logger.info(
        "Cross-sub analysis complete: %d subs, %d dependencies",
        len(subscription_ids),
        len(dependencies),
    )

    return {
        "subscriptions": subscriptions,
        "dependencies": dependencies,
        "matrix": matrix,
        "suggested_order": suggested_order,
    }


# ──────────────────────────────────────────────────────────────────────
# Targeted dependency detectors
# ──────────────────────────────────────────────────────────────────────

def _detect_vnet_peering(
    credential: TokenCredential,
    subscription_id: str,
    sub_set: set[str],
) -> list[dict[str, Any]]:
    """Detect VNet peerings that reference VNets in other subscriptions."""
    deps: list[dict[str, Any]] = []
    try:
        from azure.mgmt.network import NetworkManagementClient
        client = NetworkManagementClient(credential, subscription_id)

        for vnet in client.virtual_networks.list_all():
            if not vnet.virtual_network_peerings:
                continue
            for peering in vnet.virtual_network_peerings:
                remote_id = peering.remote_virtual_network.id if peering.remote_virtual_network else ""
                if not remote_id:
                    continue
                match = _SUB_ID_RE.search(remote_id)
                if match and match.group(1).lower() in sub_set and match.group(1).lower() != subscription_id.lower():
                    deps.append({
                        "source_sub": subscription_id,
                        "target_sub": match.group(1),
                        "type": "VNet Peering",
                        "source_resource": vnet.id,
                        "target_resource": remote_id,
                        "detail": f"VNet '{vnet.name}' is peered with '{peering.remote_virtual_network.id}'",
                        "impact": "Peering will break if subscriptions are in different tenants",
                    })
    except ImportError:
        logger.warning("azure-mgmt-network not installed — skipping VNet peering detection")
    return deps


def _detect_private_endpoints(
    credential: TokenCredential,
    subscription_id: str,
    sub_set: set[str],
) -> list[dict[str, Any]]:
    """Detect Private Endpoints connected to resources in other subscriptions."""
    deps: list[dict[str, Any]] = []
    try:
        from azure.mgmt.network import NetworkManagementClient
        client = NetworkManagementClient(credential, subscription_id)

        for pe in client.private_endpoints.list_by_subscription():
            for conn in (pe.private_link_service_connections or []):
                target_id = conn.private_link_service_id or ""
                match = _SUB_ID_RE.search(target_id)
                if match and match.group(1).lower() in sub_set and match.group(1).lower() != subscription_id.lower():
                    deps.append({
                        "source_sub": subscription_id,
                        "target_sub": match.group(1),
                        "type": "Private Endpoint",
                        "source_resource": pe.id,
                        "target_resource": target_id,
                        "detail": f"Private endpoint '{pe.name}' connects to resource in another subscription",
                        "impact": "Private link connection may break after transfer",
                    })
            for conn in (pe.manual_private_link_service_connections or []):
                target_id = conn.private_link_service_id or ""
                match = _SUB_ID_RE.search(target_id)
                if match and match.group(1).lower() in sub_set and match.group(1).lower() != subscription_id.lower():
                    deps.append({
                        "source_sub": subscription_id,
                        "target_sub": match.group(1),
                        "type": "Private Endpoint (Manual)",
                        "source_resource": pe.id,
                        "target_resource": target_id,
                        "detail": f"Private endpoint '{pe.name}' (manual) connects to resource in another subscription",
                        "impact": "Private link connection may break after transfer",
                    })
    except ImportError:
        logger.warning("azure-mgmt-network not installed — skipping Private Endpoint detection")
    return deps


def _detect_private_dns_links(
    credential: TokenCredential,
    subscription_id: str,
    sub_set: set[str],
) -> list[dict[str, Any]]:
    """Detect Private DNS Zone virtual-network links referencing other subs."""
    deps: list[dict[str, Any]] = []
    try:
        from azure.mgmt.privatedns import PrivateDnsManagementClient
        client = PrivateDnsManagementClient(credential, subscription_id)

        for zone in client.private_zones.list():
            zone_name = zone.name or ""
            # Extract resource group from the zone ID
            rg_match = re.search(r"/resourceGroups/([^/]+)/", zone.id or "")
            if not rg_match:
                continue
            rg = rg_match.group(1)

            for link in client.virtual_network_links.list(rg, zone_name):
                vnet_id = link.virtual_network.id if link.virtual_network else ""
                match = _SUB_ID_RE.search(vnet_id)
                if match and match.group(1).lower() in sub_set and match.group(1).lower() != subscription_id.lower():
                    deps.append({
                        "source_sub": subscription_id,
                        "target_sub": match.group(1),
                        "type": "Private DNS Link",
                        "source_resource": zone.id,
                        "target_resource": vnet_id,
                        "detail": f"DNS zone '{zone_name}' linked to VNet in another subscription",
                        "impact": "DNS resolution for private endpoints may break",
                    })
    except ImportError:
        logger.warning("azure-mgmt-privatedns not installed — skipping Private DNS link detection")
    return deps


def _detect_diagnostic_settings(
    credential: TokenCredential,
    subscription_id: str,
    sub_set: set[str],
) -> list[dict[str, Any]]:
    """Detect diagnostic settings forwarding to workspaces in other subs."""
    deps: list[dict[str, Any]] = []
    try:
        from azure.mgmt.monitor import MonitorManagementClient
        from azure.mgmt.resource import ResourceManagementClient

        monitor = MonitorManagementClient(credential, subscription_id)
        rm = ResourceManagementClient(credential, subscription_id)

        # Check diagnostic settings on each resource (sample top-level only)
        for resource in rm.resources.list():
            resource_id = resource.id or ""
            if not resource_id:
                continue
            try:
                for ds in monitor.diagnostic_settings.list(resource_id).value or []:
                    targets = [
                        ("Log Analytics", ds.workspace_id),
                        ("Storage Account", ds.storage_account_id),
                        ("Event Hub", ds.event_hub_authorization_rule_id),
                    ]
                    for target_type, target_id in targets:
                        if not target_id:
                            continue
                        match = _SUB_ID_RE.search(target_id)
                        if match and match.group(1).lower() in sub_set and match.group(1).lower() != subscription_id.lower():
                            deps.append({
                                "source_sub": subscription_id,
                                "target_sub": match.group(1),
                                "type": f"Diagnostic Settings ({target_type})",
                                "source_resource": resource_id,
                                "target_resource": target_id,
                                "detail": f"'{resource.name}' sends diagnostics to {target_type} in another subscription",
                                "impact": "Diagnostic data forwarding will break after transfer",
                            })
            except Exception:
                # Some resource types don't support diagnostic settings
                continue
    except ImportError:
        logger.warning("azure-mgmt-monitor not installed — skipping diagnostic settings detection")
    return deps


# ──────────────────────────────────────────────────────────────────────
# Generic cross-reference scanner
# ──────────────────────────────────────────────────────────────────────

def _find_cross_sub_references(
    resource: dict[str, Any],
    source_sub: str,
    sub_set: set[str],
) -> list[dict[str, Any]]:
    """Scan a resource dict for ARM resource IDs referencing other subs.

    This is a catch-all that finds references the targeted detectors
    might miss (e.g. Key Vault references in app settings).
    """
    deps: list[dict[str, Any]] = []
    resource_id = resource.get("id", "")
    resource_str = str(resource)

    for match in _SUB_ID_RE.finditer(resource_str):
        found_sub = match.group(1).lower()
        if found_sub in sub_set and found_sub != source_sub.lower():
            deps.append({
                "source_sub": source_sub,
                "target_sub": match.group(1),
                "type": "Resource Reference",
                "source_resource": resource_id,
                "target_resource": "(embedded in resource properties)",
                "detail": f"Resource '{resource.get('name', '')}' references subscription {match.group(1)}",
                "impact": "Resource may have cross-subscription dependency",
            })
    return deps


# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────

def _deduplicate(deps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Remove duplicate dependency entries (same source+target+type+resources)."""
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for d in deps:
        key = f"{d['source_sub'].lower()}|{d['target_sub'].lower()}|{d['type']}|{d.get('source_resource', '').lower()}|{d.get('target_resource', '').lower()}"
        if key not in seen:
            seen.add(key)
            unique.append(d)
    return unique


def _build_matrix(
    deps: list[dict[str, Any]],
    subscription_ids: list[str],
) -> dict[str, dict[str, int]]:
    """Build an adjacency matrix counting dependencies between subs."""
    matrix: dict[str, dict[str, int]] = {sid: {} for sid in subscription_ids}
    for d in deps:
        src = d["source_sub"]
        tgt = d["target_sub"]
        if src not in matrix:
            matrix[src] = {}
        matrix[src][tgt] = matrix[src].get(tgt, 0) + 1
    return matrix


def _build_sub_summaries(
    subscription_ids: list[str],
    scan_results: dict[str, dict[str, Any]],
    matrix: dict[str, dict[str, int]],
) -> list[dict[str, Any]]:
    """Build per-subscription summary entries."""
    summaries: list[dict[str, Any]] = []
    for sid in subscription_ids:
        scan = scan_results.get(sid, {})
        outgoing = sum(matrix.get(sid, {}).values())
        incoming = sum(
            counts.get(sid, 0)
            for other_sid, counts in matrix.items()
            if other_sid != sid
        )
        summaries.append({
            "subscription_id": sid,
            "transfer_safe_count": len(scan.get("transfer_safe", [])),
            "requires_action_count": len(scan.get("requires_action", [])),
            "outgoing_dependencies": outgoing,
            "incoming_dependencies": incoming,
            "total_dependencies": outgoing + incoming,
            "error": scan.get("error"),
        })
    return summaries


def _suggest_order(
    subscription_ids: list[str],
    matrix: dict[str, dict[str, int]],
) -> list[str]:
    """Suggest a transfer order based on dependency direction.

    Subscriptions that are **depended upon** by others should transfer
    first (or at minimum be flagged as coordinated).  Uses a simple
    heuristic: sort by (incoming_count DESC) so the most-depended-on
    sub is transferred first.

    A proper topological sort could be used if we modelled directed
    edges, but for v1 a weighted sort is sufficient and handles cycles
    gracefully (no crash).
    """
    incoming_counts: dict[str, int] = {sid: 0 for sid in subscription_ids}
    for src, targets in matrix.items():
        for tgt, count in targets.items():
            if tgt in incoming_counts:
                incoming_counts[tgt] += count

    # Most depended-on first
    return sorted(subscription_ids, key=lambda s: incoming_counts.get(s, 0), reverse=True)
