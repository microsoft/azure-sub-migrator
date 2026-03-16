"""Principal mapping — match old-tenant identities to new-tenant identities.

During a cross-tenant subscription transfer, all RBAC role-assignment
principal IDs become invalid because they reference objects in the *source*
tenant's Entra ID directory.  To recreate RBAC in the target tenant we
need a mapping: ``old_principal_id → new_principal_id``.

This module implements **Sharegate-style automatic mapping**:
  1. Extracts all unique principals from an RBAC export.
  2. Batch-resolves their display names / UPNs in the source tenant via
     the Graph JSON batching API (``/$batch``, 20 per request).
  3. Fetches the full directory catalog from the target tenant (all users,
     groups, service principals) and builds lookup indexes.
  4. Matches each source principal to target-tenant objects using a
     multi-strategy algorithm:
       - **UPN exact match** (high confidence)
       - **UPN domain-transform** (``user@source.com`` → ``user@target.com``)
       - **Email exact match** (high confidence)
       - **AppId match** for service principals (high confidence)
       - **Display name exact match** (medium confidence)
       - **Display name prefix/fuzzy match** (low confidence)
  5. Lets the user review, override, and confirm the mapping via the UI.
"""

from __future__ import annotations

from typing import Any

from tenova.logger import get_logger

logger = get_logger("principal_map")


# ──────────────────────────────────────────────────────────────────────
# Extract principals from RBAC export
# ──────────────────────────────────────────────────────────────────────

def extract_principals(rbac_export: dict[str, Any]) -> list[dict[str, Any]]:
    """Return a deduplicated list of principals from an RBAC export.

    Each entry: ``{principal_id, principal_type, scopes: [...]}``.
    """
    seen: dict[str, dict[str, Any]] = {}

    for ra in rbac_export.get("role_assignments", []):
        pid = ra.get("principal_id", "")
        if not pid:
            continue
        if pid in seen:
            seen[pid]["scopes"].append(ra.get("scope", ""))
        else:
            seen[pid] = {
                "principal_id": pid,
                "principal_type": ra.get("principal_type", "Unknown"),
                "scopes": [ra.get("scope", "")],
            }

    result = list(seen.values())
    logger.info("Extracted %d unique principal(s) from RBAC export", len(result))
    return result


# ──────────────────────────────────────────────────────────────────────
# Resolve source-tenant display names
# ──────────────────────────────────────────────────────────────────────

def resolve_source_principals(
    principals: list[dict[str, Any]],
    source_token: str,
) -> list[dict[str, Any]]:
    """Enrich each principal with display name / UPN from the source tenant.

    Uses the Graph JSON batching API (``/$batch``) to resolve all principals
    in batches of 20, instead of making N sequential HTTP calls.
    Principals that cannot be resolved (deleted users, wrong tenant) will
    have ``display_name`` set to ``"(unknown)"``.

    Mutates *principals* in-place and returns the same list.
    """
    from tenova.target_tenant import batch_resolve_objects

    all_ids = [p["principal_id"] for p in principals if p.get("principal_id")]
    resolved = batch_resolve_objects(source_token, all_ids)

    for p in principals:
        pid = p["principal_id"]
        obj = resolved.get(pid)
        if obj:
            odata_type = obj.get("@odata.type", "")
            p["display_name"] = obj.get("displayName", "(unknown)")
            p["upn"] = obj.get("userPrincipalName", "")
            p["mail"] = obj.get("mail", "")
            p["app_id"] = obj.get("appId", "")
            p["object_type"] = _friendly_type(odata_type)
        else:
            p["display_name"] = "(unknown)"
            p["upn"] = ""
            p["mail"] = ""
            p["app_id"] = ""
            p["object_type"] = p.get("principal_type", "Unknown")

    resolved_count = sum(1 for p in principals if p["display_name"] != "(unknown)")
    logger.info(
        "Resolved %d / %d source principal display names",
        resolved_count, len(principals),
    )
    return principals


# ──────────────────────────────────────────────────────────────────────
# Auto-suggest matches in the target tenant
# ──────────────────────────────────────────────────────────────────────

def suggest_mappings(
    principals: list[dict[str, Any]],
    target_token: str,
    *,
    domain_mapping: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Sharegate-style automatic principal mapping.

    Instead of making per-principal Graph search calls, this fetches the
    **entire** target-tenant directory catalog (users, groups, service
    principals) and builds in-memory indexes.  Each source principal is
    then matched against these indexes using multiple strategies, ordered
    by confidence:

      1. **UPN exact match** — high
      2. **UPN domain-transformed match** — high
         (e.g. ``user@contoso.com`` → ``user@fabrikam.com``)
      3. **Email exact match** — high
      4. **AppId match** (service principals) — high
      5. **Display name exact match** (same type) — medium
      6. **Display name case-insensitive match** — low

    Parameters
    ----------
    domain_mapping:
        Optional ``{source_domain: target_domain}`` dict for UPN
        domain transforms.  e.g.  ``{"contoso.com": "fabrikam.com"}``

    Mutates *principals* in-place and returns the same list.
    """
    from tenova.target_tenant import (
        list_all_groups,
        list_all_service_principals,
        list_all_users,
    )

    domain_mapping = domain_mapping or {}

    # ── Phase 1: Fetch full target directory ─────────────────────────
    logger.info("Fetching target tenant directory for auto-matching…")
    target_users = list_all_users(target_token)
    target_groups = list_all_groups(target_token)
    target_sps = list_all_service_principals(target_token)

    # ── Phase 2: Build lookup indexes ────────────────────────────────
    user_by_upn: dict[str, dict] = {}        # lowercase UPN → user
    user_by_mail: dict[str, dict] = {}       # lowercase mail → user
    user_by_name: dict[str, list[dict]] = {} # lowercase displayName → [users]

    for u in target_users:
        upn = (u.get("userPrincipalName") or "").lower()
        mail = (u.get("mail") or "").lower()
        name = (u.get("displayName") or "").lower()
        if upn:
            user_by_upn[upn] = u
        if mail:
            user_by_mail[mail] = u
        if name:
            user_by_name.setdefault(name, []).append(u)

    group_by_name: dict[str, list[dict]] = {}
    for g in target_groups:
        name = (g.get("displayName") or "").lower()
        if name:
            group_by_name.setdefault(name, []).append(g)

    sp_by_app_id: dict[str, dict] = {}       # appId → SP
    sp_by_name: dict[str, list[dict]] = {}   # lowercase displayName → [SPs]
    for sp in target_sps:
        app_id = sp.get("appId", "")
        name = (sp.get("displayName") or "").lower()
        if app_id:
            sp_by_app_id[app_id] = sp
        if name:
            sp_by_name.setdefault(name, []).append(sp)

    logger.info(
        "Target directory indexes: %d users, %d groups, %d SPs",
        len(target_users), len(target_groups), len(target_sps),
    )

    # ── Phase 3: Match each principal ────────────────────────────────
    auto_high = 0
    auto_med = 0
    unmatched = 0

    for p in principals:
        suggestions: list[dict[str, Any]] = []
        seen_ids: set[str] = set()
        obj_type = (p.get("object_type") or p.get("principal_type") or "").lower()

        def _add(target_obj: dict, confidence: str, match_reason: str) -> None:
            tid = target_obj.get("id", "")
            if tid and tid not in seen_ids:
                suggestions.append({
                    "id": tid,
                    "displayName": target_obj.get("displayName", ""),
                    "upn": target_obj.get("userPrincipalName", ""),
                    "confidence": confidence,
                    "match_reason": match_reason,
                })
                seen_ids.add(tid)

        # Strategy 1: UPN exact match
        src_upn = (p.get("upn") or "").lower()
        if src_upn and src_upn in user_by_upn:
            _add(user_by_upn[src_upn], "high", "UPN exact match")

        # Strategy 2: UPN domain-transform
        if src_upn and not suggestions and "@" in src_upn:
            local, src_domain = src_upn.rsplit("@", 1)
            target_domain = domain_mapping.get(src_domain, "")
            if target_domain:
                transformed_upn = f"{local}@{target_domain}"
                if transformed_upn in user_by_upn:
                    _add(user_by_upn[transformed_upn], "high", f"UPN domain-transform ({src_domain}→{target_domain})")

        # Strategy 3: Email exact match
        src_mail = (p.get("mail") or "").lower()
        if src_mail and not suggestions:
            if src_mail in user_by_mail:
                _add(user_by_mail[src_mail], "high", "Email exact match")

        # Strategy 4: AppId match (service principals)
        src_app_id = p.get("app_id", "")
        if src_app_id and not suggestions and src_app_id in sp_by_app_id:
            _add(sp_by_app_id[src_app_id], "high", "AppId match")

        # Strategy 5: Display name exact match (type-aware)
        src_name = (p.get("display_name") or "").lower()
        if src_name and src_name != "(unknown)" and not suggestions:
            if "user" in obj_type and src_name in user_by_name:
                for u in user_by_name[src_name]:
                    _add(u, "medium", "Display name match (user)")
            elif "group" in obj_type and src_name in group_by_name:
                for g in group_by_name[src_name]:
                    _add(g, "medium", "Display name match (group)")
            elif "serviceprincipal" in obj_type or "application" in obj_type:
                if src_name in sp_by_name:
                    for sp in sp_by_name[src_name]:
                        _add(sp, "medium", "Display name match (SP)")
            else:
                # Unknown type — search all three
                for idx in (user_by_name, group_by_name, sp_by_name):
                    if src_name in idx:
                        for obj in idx[src_name]:
                            _add(obj, "low", "Display name match (any type)")

        p["suggestions"] = suggestions

        if suggestions:
            best_conf = suggestions[0]["confidence"]
            if best_conf == "high":
                auto_high += 1
            else:
                auto_med += 1
        else:
            unmatched += 1

    logger.info(
        "Auto-mapping results: %d high, %d medium/low, %d unmatched (of %d)",
        auto_high, auto_med, unmatched, len(principals),
    )
    return principals

    return principals


# ──────────────────────────────────────────────────────────────────────
# Build the final mapping dict
# ──────────────────────────────────────────────────────────────────────

def build_mapping(
    principals: list[dict[str, Any]],
    overrides: dict[str, str] | None = None,
) -> dict[str, str]:
    """Build an ``{old_principal_id: new_principal_id}`` mapping.

    For each principal:
      - If an override is provided (from the UI), use it.
      - Else if a high-confidence suggestion exists, use it.
      - Otherwise the principal is omitted (will be skipped during import).

    Parameters
    ----------
    overrides:
        User-supplied mapping from the web UI form.  Keys are old
        principal IDs, values are new principal IDs.
    """
    overrides = overrides or {}
    mapping: dict[str, str] = {}

    for p in principals:
        old_id = p["principal_id"]

        # User override takes priority
        if old_id in overrides and overrides[old_id]:
            mapping[old_id] = overrides[old_id]
            continue

        # Auto-select high-confidence suggestion
        suggestions = p.get("suggestions", [])
        high = [s for s in suggestions if s.get("confidence") == "high"]
        if high:
            mapping[old_id] = high[0]["id"]

    logger.info(
        "Principal mapping: %d mapped out of %d total",
        len(mapping),
        len(principals),
    )
    return mapping


# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────

def _friendly_type(odata_type: str) -> str:
    """Convert ``#microsoft.graph.user`` → ``User``."""
    mapping = {
        "#microsoft.graph.user": "User",
        "#microsoft.graph.group": "Group",
        "#microsoft.graph.servicePrincipal": "ServicePrincipal",
        "#microsoft.graph.application": "Application",
    }
    return mapping.get(odata_type, odata_type or "Unknown")


# Well-known 1st-party Microsoft application IDs that exist in every tenant.
# These service principals are auto-provisioned — they don't need manual mapping.
_FIRST_PARTY_APP_IDS: frozenset[str] = frozenset({
    # Azure Resource Manager / Portal
    "797f4846-ba00-4fd7-ba43-dac1f8f63013",
    "c44b4083-3bb0-49c1-b47d-974e53cbdf3c",
    # Microsoft Graph
    "00000003-0000-0000-c000-000000000000",
    # AAD / Entra ID
    "00000002-0000-0000-c000-000000000000",
    # Azure Key Vault
    "cfa8b339-82a2-471a-a3c9-0fc0be7a4093",
    # Azure Storage
    "e406a681-f3d4-42a8-90b6-c2b029497af7",
    # Azure Backup
    "262044b1-e2ce-469f-a196-69ab7ada62d3",
    # Azure Policy / Insights
    "0736f41a-0425-4b46-bdb5-1563eff02385",
    # Azure Site Recovery
    "b8340c3b-9267-498f-b21a-15d5547fd85e",
    # Azure Monitor
    "ca7f3f0b-7d91-482c-8e09-c5d840d0eac5",
    # Azure SQL
    "e4ab13ed-33cb-41b4-9be4-e22e2bf028b8",
    # Log Analytics
    "ca7f3f0b-7d91-482c-8e09-c5d840d0eac5",
    # Azure Kubernetes Service
    "6dae42f8-4368-4678-94ff-3960e28e3630",
    # Cloud Infrastructure Entitlement Management (CIEM / Permissions Mgmt)
    "b46c3ac5-9da6-418f-a849-0a07a10b3c6c",
    # CDX (Microsoft Customer Digital Experiences)
    "ce933385-9390-45d1-9512-c8d228571571",
    # SharePoint Online
    "00000003-0000-0ff1-ce00-000000000000",
    # Exchange Online
    "00000002-0000-0ff1-ce00-000000000000",
    # Azure DevOps
    "499b84ac-1321-427f-aa17-267ca6975798",
    # Power BI Service
    "00000009-0000-0000-c000-000000000000",
    # Microsoft Teams
    "cc15fd57-2c6c-4117-a88c-83b1d56b4bbe",
    # Dynamics 365
    "00000007-0000-0000-c000-000000000000",
    # Azure Cosmos DB
    "a232010e-820c-4083-83bb-3ace5fc29d0b",
    # Azure Event Hubs
    "80369ed6-5f11-4dd9-bef3-692475845e77",
    # Azure Service Bus
    "80a10ef9-8168-493d-abf9-3297c4ef6e3c",
})


def classify_principal(principal: dict[str, Any]) -> str:
    """Classify a principal into a mapping category.

    Returns one of:
      - ``"system"``   — 1st-party Microsoft service principal (auto-skip)
      - ``"managed_identity"`` — user/system managed identity (auto-skip)
      - ``"mappable"`` — user, group, or 3rd-party SP that needs mapping

    The classification is stored on the principal dict as ``category``.
    """
    obj_type = (
        principal.get("object_type")
        or principal.get("principal_type")
        or ""
    ).lower()

    # Managed identities — type is usually "ServicePrincipal" but the
    # principal_type from RBAC is "MSI" or the display name contains
    # pattern like "(guid)" suffix typical of system-assigned identities.
    p_type_raw = (principal.get("principal_type") or "").lower()
    if p_type_raw == "msi" or p_type_raw == "managedidentity":
        return "managed_identity"

    # Check appId against well-known 1st-party list
    app_id = principal.get("app_id", "")
    if app_id and app_id in _FIRST_PARTY_APP_IDS:
        return "system"

    # Service principals with "Microsoft" vendor display names are likely 1st-party
    display = (principal.get("display_name") or "").lower()
    if "serviceprincipal" in obj_type:
        # Heuristic: display names starting with common MS prefixes
        ms_prefixes = (
            "microsoft ", "microsoft.", "azure ", "windows azure",
            "o365 ", "office 365", "graph ", "aad ",
            "cloud infrastructure entitlement",
            "cdx-", "cdx ",
        )
        if any(display.startswith(p) for p in ms_prefixes):
            return "system"

        # Catch names containing strong MS-only keywords
        ms_keywords = (
            "azure active directory", "entra",
            "sharepoint", "exchange online",
            "power bi", "dynamics 365", "teams",
        )
        if any(kw in display for kw in ms_keywords):
            return "system"

    # Users and groups always need mapping
    if "user" in obj_type or "group" in obj_type:
        return "mappable"

    # 3rd-party or custom service principals
    return "mappable"
