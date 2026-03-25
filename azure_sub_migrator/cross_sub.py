# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""Cross-subscription dependency analysis.

Scans multiple Azure subscriptions in parallel and identifies
dependencies between them — VNet peering, Private Endpoints,
Private DNS Zone links, Route Tables / UDRs, diagnostic settings
forwarding, and generic cross-subscription resource references
embedded in resource properties.

The result is a lightweight dependency graph that helps operators
plan the transfer order and understand what will break if a single
subscription is transferred in isolation.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from azure.core.credentials import TokenCredential

from azure_sub_migrator.logger import get_logger
from azure_sub_migrator.scanner import scan_subscription

logger = get_logger("cross_sub")

# Regex that extracts subscription IDs from ARM resource ID strings.
_SUB_ID_RE = re.compile(
    r"/subscriptions/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
    re.IGNORECASE,
)

# Resource types worth checking for diagnostic settings (keeps API calls
# bounded instead of iterating *every* resource in the subscription).
_DIAG_RESOURCE_TYPES: set[str] = {
    "microsoft.keyvault/vaults",
    "microsoft.network/networksecuritygroups",
    "microsoft.network/virtualnetworks",
    "microsoft.network/applicationgateways",
    "microsoft.network/azurefirewalls",
    "microsoft.network/loadbalancers",
    "microsoft.sql/servers",
    "microsoft.storage/storageaccounts",
    "microsoft.containerservice/managedclusters",
    "microsoft.web/sites",
    "microsoft.compute/virtualmachines",
}


def _check_and_append(
    deps: list[dict[str, Any]],
    subscription_id: str,
    sub_set: set[str],
    target_id: str,
    dep_type: str,
    source_resource: str,
    detail: str,
    impact: str,
) -> None:
    """Append a dependency if *target_id* references another sub in *sub_set*."""
    if not target_id:
        return
    match = _SUB_ID_RE.search(target_id)
    if not match:
        return
    found = match.group(1).lower()
    if found in sub_set and found != subscription_id.lower():
        deps.append({
            "source_sub": subscription_id,
            "target_sub": match.group(1),
            "type": dep_type,
            "source_resource": source_resource,
            "target_resource": target_id,
            "detail": detail,
            "impact": impact,
        })


# ──────────────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────────────

def analyze_cross_sub_dependencies(
    credential: TokenCredential,
    subscription_ids: list[str],
    *,
    on_progress: Callable[[str, int, int], None] | None = None,
) -> dict[str, Any]:
    """Scan multiple subscriptions and detect cross-sub dependencies.

    Parameters
    ----------
    credential : TokenCredential
        Azure credential with Reader access to all subscriptions.
    subscription_ids : list[str]
        Two or more subscription IDs to analyze.
    on_progress : callable, optional
        Callback ``(step_name, step_number, total_steps)``.

    Returns
    -------
    dict with keys:
        - ``subscriptions`` – per-sub scan summaries (id, name, counts).
        - ``dependencies`` – list of edge dicts describing each dependency.
        - ``matrix`` – adjacency dict  ``{source_sub: {target_sub: count}}``.
        - ``suggested_order`` – topological sort hint (least-depended first).
    """
    _progress = on_progress or (lambda *_: None)

    if len(subscription_ids) < 2:
        return {
            "subscriptions": [],
            "dependencies": [],
            "matrix": {},
            "suggested_order": subscription_ids[:],
            "error": "At least two subscriptions are required for cross-sub analysis.",
        }

    sub_set = {s.lower() for s in subscription_ids}
    n_subs = len(subscription_ids)
    # Steps: scan each sub (n_subs) + detect deps per sub (n_subs) + generic scan + build summary
    total = n_subs + n_subs + 2

    # ── Step 1: Scan each subscription (parallel) ──
    _progress("Scanning subscriptions", 0, total)
    scan_results: dict[str, dict[str, Any]] = {}
    completed_scans = 0
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
            completed_scans += 1
            _progress(f"Scanned {completed_scans}/{n_subs} subscriptions", completed_scans, total)

    # ── Step 2: Detect cross-sub references via targeted SDK calls ──
    dependencies: list[dict[str, Any]] = []

    for sub_idx, sid in enumerate(subscription_ids):
        step = n_subs + sub_idx + 1
        _progress(f"Detecting dependencies ({sub_idx + 1}/{n_subs})", step, total)
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
            deps = _detect_nsg_references(credential, sid, sub_set)
            dependencies.extend(deps)
        except Exception as exc:
            logger.warning("NSG detection failed for %s: %s", sid, exc)

        try:
            deps = _detect_load_balancer_refs(credential, sid, sub_set)
            dependencies.extend(deps)
        except Exception as exc:
            logger.warning("Load balancer detection failed for %s: %s", sid, exc)

        try:
            deps = _detect_diagnostic_settings(credential, sid, sub_set)
            dependencies.extend(deps)
        except Exception as exc:
            logger.warning("Diagnostic settings detection failed for %s: %s", sid, exc)

        try:
            deps = _detect_route_table_refs(credential, sid, sub_set)
            dependencies.extend(deps)
        except Exception as exc:
            logger.warning("Route table detection failed for %s: %s", sid, exc)

    # ── Step 3: Generic cross-sub reference scan via resource IDs ──
    _progress("Scanning resource properties", n_subs * 2 + 1, total)
    for sid in subscription_ids:
        scan = scan_results.get(sid, {})
        all_resources = scan.get("transfer_safe", []) + scan.get("requires_action", [])
        for resource in all_resources:
            refs = _find_cross_sub_references(resource, sid, sub_set)
            dependencies.extend(refs)

    # ── Step 4: Deduplicate ──
    dependencies = _deduplicate(dependencies)

    _progress("Building summary", total, total)
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
            # list_all() does NOT populate virtual_network_peerings —
            # we must call the peerings API explicitly per VNet.
            vnet_id = vnet.id or ""
            rg_match = re.search(
                r"/resourceGroups/([^/]+)/", vnet_id,
            )
            if not rg_match or not vnet.name:
                continue
            rg = rg_match.group(1)
            try:
                peerings = client.virtual_network_peerings.list(
                    rg, vnet.name,
                )
            except Exception:
                continue
            for peering in peerings:
                rv = peering.remote_virtual_network
                remote_id = rv.id if rv else ""
                if not remote_id:
                    continue
                match = _SUB_ID_RE.search(remote_id)
                if not match:
                    continue
                found = match.group(1).lower()
                if found in sub_set and found != subscription_id.lower():
                    deps.append({
                        "source_sub": subscription_id,
                        "target_sub": match.group(1),
                        "type": "VNet Peering",
                        "source_resource": vnet_id,
                        "target_resource": remote_id,
                        "detail": (
                            f"VNet '{vnet.name}' is peered with"
                            f" '{remote_id}'"
                        ),
                        "impact": (
                            "Peering will break if subscriptions"
                            " are in different tenants"
                        ),
                    })
    except ImportError:
        logger.warning("azure-mgmt-network not installed — skipping VNet peering detection")
    return deps


def _detect_private_endpoints(
    credential: TokenCredential,
    subscription_id: str,
    sub_set: set[str],
) -> list[dict[str, Any]]:
    """Detect Private Endpoints connected to resources in other subs.

    Checks both the private-link target resource and the subnet/VNet
    the PE is deployed into, since either can be cross-subscription.
    """
    deps: list[dict[str, Any]] = []
    try:
        from azure.mgmt.network import NetworkManagementClient
        client = NetworkManagementClient(credential, subscription_id)

        for pe in client.private_endpoints.list_by_subscription():
            pe_id = pe.id or ""

            # Check private link service connections (auto-approved)
            for conn in (pe.private_link_service_connections or []):
                target_id = conn.private_link_service_id or ""
                _check_and_append(
                    deps, subscription_id, sub_set, target_id,
                    "Private Endpoint", pe_id,
                    f"PE '{pe.name}' connects to resource "
                    f"in another subscription",
                    "Private link connection may break after "
                    "transfer",
                )

            # Check manual private link connections
            for conn in (
                pe.manual_private_link_service_connections or []
            ):
                target_id = conn.private_link_service_id or ""
                _check_and_append(
                    deps, subscription_id, sub_set, target_id,
                    "Private Endpoint (Manual)", pe_id,
                    f"PE '{pe.name}' (manual) connects to "
                    f"resource in another subscription",
                    "Private link connection may break after "
                    "transfer",
                )

            # Check if the PE's subnet is in another subscription
            subnet_id = pe.subnet.id if pe.subnet else ""
            _check_and_append(
                deps, subscription_id, sub_set, subnet_id,
                "Private Endpoint (Subnet)", pe_id,
                f"PE '{pe.name}' is deployed into a subnet "
                f"in another subscription",
                "PE will lose connectivity if the VNet sub "
                "is transferred separately",
            )
    except ImportError:
        logger.warning(
            "azure-mgmt-network not installed — "
            "skipping Private Endpoint detection"
        )
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
    """Detect diagnostic settings forwarding to workspaces in other subs.

    Only checks resource types in ``_DIAG_RESOURCE_TYPES`` to keep
    the number of API calls bounded (instead of hitting every resource).
    """
    deps: list[dict[str, Any]] = []
    try:
        from azure.mgmt.monitor import MonitorManagementClient
        from azure.mgmt.resource import ResourceManagementClient

        monitor = MonitorManagementClient(credential, subscription_id)
        rm = ResourceManagementClient(credential, subscription_id)

        for resource in rm.resources.list():
            r_type = (resource.type or "").lower()
            if r_type not in _DIAG_RESOURCE_TYPES:
                continue
            resource_id = resource.id or ""
            if not resource_id:
                continue
            try:
                ds_list = monitor.diagnostic_settings.list(
                    resource_id,
                )
                for ds in ds_list.value or []:
                    targets = [
                        ("Log Analytics", ds.workspace_id),
                        ("Storage Account", ds.storage_account_id),
                        (
                            "Event Hub",
                            ds.event_hub_authorization_rule_id,
                        ),
                    ]
                    for target_type, target_id in targets:
                        _check_and_append(
                            deps, subscription_id, sub_set,
                            target_id or "",
                            f"Diagnostic Settings ({target_type})",
                            resource_id, (
                                f"'{resource.name}' sends diagnostics"
                                f" to {target_type} in another sub"
                            ),
                            "Diagnostic data forwarding will break "
                            "after transfer",
                        )
            except Exception:
                # Resource type may not support diagnostic settings
                continue
    except ImportError:
        logger.warning(
            "azure-mgmt-monitor not installed — "
            "skipping diagnostic settings detection"
        )
    return deps


def _detect_route_table_refs(
    credential: TokenCredential,
    subscription_id: str,
    sub_set: set[str],
) -> list[dict[str, Any]]:
    """Detect Route Tables / UDRs with cross-subscription references.

    Checks two things per route table:

    1. **Subnet associations** — the route table's ``subnets`` property
       lists the subnets that use it; if a subnet lives in another
       subscription, that is a cross-sub dependency.
    2. **Route entries** — a route with ``next_hop_type`` equal to
       ``VirtualAppliance`` has a ``next_hop_ip_address``.  We cannot
       resolve an IP to a subscription, but we flag it as a *potential*
       cross-sub dependency for manual review.  Additionally, routes
       may reference ARM resource IDs (e.g. Virtual Network Gateway)
       in another subscription.
    """
    deps: list[dict[str, Any]] = []
    try:
        from azure.mgmt.network import NetworkManagementClient
        client = NetworkManagementClient(credential, subscription_id)

        for rt in client.route_tables.list_all():
            rt_id = rt.id or ""

            # 1. Check subnet associations for cross-sub refs
            for subnet in (rt.subnets or []):
                _check_and_append(
                    deps, subscription_id, sub_set,
                    subnet.id or "", "Route Table (Subnet)",
                    rt_id,
                    f"Route table '{rt.name}' is associated with"
                    f" a subnet in another subscription",
                    "Route table association will be lost after"
                    " transfer if subscriptions are in different"
                    " tenants",
                )

            # 2. Check individual routes
            for route in (rt.routes or []):
                # 2a. VirtualAppliance next-hop — IP-based, flag for review
                if (
                    route.next_hop_type
                    and route.next_hop_type.lower() == "virtualappliance"
                    and route.next_hop_ip_address
                ):
                    # We can't resolve IP → sub, so we just warn
                    deps.append({
                        "source_sub": subscription_id,
                        "target_sub": subscription_id,  # placeholder
                        "type": "Route Table (NVA)",
                        "source_resource": rt_id,
                        "target_resource": route.next_hop_ip_address,
                        "detail": (
                            f"Route '{route.name}' in table"
                            f" '{rt.name}' forwards traffic to"
                            f" NVA IP {route.next_hop_ip_address}"
                        ),
                        "impact": (
                            "If the NVA lives in another subscription,"
                            " routing will break after transfer —"
                            " verify manually"
                        ),
                    })

                # 2b. Scan route address prefix / next-hop for ARM IDs
                for field in (
                    route.next_hop_ip_address or "",
                    getattr(route, "address_prefix", "") or "",
                ):
                    _check_and_append(
                        deps, subscription_id, sub_set,
                        field, "Route Table (Route)",
                        rt_id,
                        f"Route '{route.name}' in table"
                        f" '{rt.name}' references resource in"
                        f" another subscription",
                        "Route entry may break after transfer",
                    )
    except ImportError:
        logger.warning(
            "azure-mgmt-network not installed — "
            "skipping Route Table detection"
        )
    return deps


def _detect_nsg_references(
    credential: TokenCredential,
    subscription_id: str,
    sub_set: set[str],
) -> list[dict[str, Any]]:
    """Detect NSG rules referencing address prefixes in other subs.

    NSG rules can contain ``sourceAddressPrefix`` or
    ``destinationAddressPrefix`` pointing to an Application Security
    Group (ASG) in another subscription.  The rule's
    ``source_application_security_groups`` and
    ``destination_application_security_groups`` lists contain full ARM
    IDs that we check.
    """
    deps: list[dict[str, Any]] = []
    try:
        from azure.mgmt.network import NetworkManagementClient
        client = NetworkManagementClient(credential, subscription_id)

        for nsg in client.network_security_groups.list_all():
            nsg_id = nsg.id or ""
            all_rules = list(nsg.security_rules or [])
            all_rules.extend(nsg.default_security_rules or [])
            for rule in all_rules:
                for asg in (
                    rule.source_application_security_groups or []
                ):
                    _check_and_append(
                        deps, subscription_id, sub_set,
                        asg.id or "", "NSG Rule (Source ASG)",
                        nsg_id,
                        f"NSG '{nsg.name}' rule '{rule.name}' "
                        f"references ASG in another subscription",
                        "NSG rule will lose connectivity to the "
                        "ASG after transfer",
                    )
                for asg in (
                    rule.destination_application_security_groups
                    or []
                ):
                    _check_and_append(
                        deps, subscription_id, sub_set,
                        asg.id or "",
                        "NSG Rule (Destination ASG)",
                        nsg_id,
                        f"NSG '{nsg.name}' rule '{rule.name}' "
                        f"references ASG in another subscription",
                        "NSG rule will lose connectivity to the "
                        "ASG after transfer",
                    )
    except ImportError:
        logger.warning(
            "azure-mgmt-network not installed — "
            "skipping NSG detection"
        )
    return deps


def _detect_load_balancer_refs(
    credential: TokenCredential,
    subscription_id: str,
    sub_set: set[str],
) -> list[dict[str, Any]]:
    """Detect Load Balancers with backend pools or rules referencing other subs.

    Backend address pools can reference VNets/subnets in other
    subscriptions.  Frontend IP configs can reference public IPs or
    subnets cross-sub.
    """
    deps: list[dict[str, Any]] = []
    try:
        from azure.mgmt.network import NetworkManagementClient
        client = NetworkManagementClient(credential, subscription_id)

        for lb in client.load_balancers.list_all():
            lb_id = lb.id or ""
            lb_str = str(lb.serialize()) if hasattr(lb, "serialize") else str(lb)

            # Scan the serialized LB for any cross-sub references
            for match in _SUB_ID_RE.finditer(lb_str):
                found = match.group(1).lower()
                if found in sub_set and found != subscription_id.lower():
                    deps.append({
                        "source_sub": subscription_id,
                        "target_sub": match.group(1),
                        "type": "Load Balancer",
                        "source_resource": lb_id,
                        "target_resource": "(cross-sub reference"
                            " in LB config)",
                        "detail": (
                            f"LB '{lb.name}' references resources"
                            f" in another subscription"
                        ),
                        "impact": (
                            "Load balancer backend/frontend config "
                            "may break after transfer"
                        ),
                    })
                    break  # one dep per LB is enough
    except ImportError:
        logger.warning(
            "azure-mgmt-network not installed — "
            "skipping Load Balancer detection"
        )
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
        key = (
            f"{d['source_sub'].lower()}|"
            f"{d['target_sub'].lower()}|"
            f"{d['type']}|"
            f"{d.get('source_resource', '').lower()}|"
            f"{d.get('target_resource', '').lower()}"
        )
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
