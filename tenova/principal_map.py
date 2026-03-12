"""Principal mapping — match old-tenant identities to new-tenant identities.

During a cross-tenant subscription transfer, all RBAC role-assignment
principal IDs become invalid because they reference objects in the *source*
tenant's Entra ID directory.  To recreate RBAC in the target tenant we
need a mapping: ``old_principal_id → new_principal_id``.

This module:
  1. Extracts all unique principals from an RBAC export.
  2. Resolves their display names / UPNs in the source tenant via Graph.
  3. Auto-suggests matches in the target tenant by searching Graph for
     the same display name / UPN / mail.
  4. Lets the user confirm or override each mapping via the web UI.
"""

from __future__ import annotations

from typing import Any

from tenova.logger import get_logger
from tenova.target_tenant import (
    get_directory_object,
    search_groups,
    search_service_principals,
    search_users,
)

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

    Queries Microsoft Graph``/directoryObjects/{id}`` for each principal.
    Principals that cannot be resolved (deleted users, broken SPs) will
    have ``display_name`` set to ``"(unknown)"`` — the user can still
    manually map them in the UI.

    Mutates *principals* in-place and returns the same list.
    """
    for p in principals:
        obj = get_directory_object(source_token, p["principal_id"])
        if obj:
            odata_type = obj.get("@odata.type", "")
            p["display_name"] = obj.get("displayName", "(unknown)")
            p["upn"] = obj.get("userPrincipalName", "")
            p["mail"] = obj.get("mail", "")
            p["object_type"] = _friendly_type(odata_type)
        else:
            p["display_name"] = "(unknown)"
            p["upn"] = ""
            p["mail"] = ""
            p["object_type"] = p.get("principal_type", "Unknown")

    return principals


# ──────────────────────────────────────────────────────────────────────
# Auto-suggest matches in the target tenant
# ──────────────────────────────────────────────────────────────────────

def suggest_mappings(
    principals: list[dict[str, Any]],
    target_token: str,
) -> list[dict[str, Any]]:
    """For each principal, search the target tenant for likely matches.

    Adds ``suggestions: [{id, displayName, upn?, confidence}]`` to each
    principal dict.  ``confidence`` is ``"high"`` when UPN or mail matches
    exactly, ``"medium"`` for display-name prefix match.

    Mutates *principals* in-place and returns the same list.
    """
    for p in principals:
        suggestions: list[dict[str, Any]] = []
        seen_ids: set[str] = set()

        obj_type = p.get("object_type", "").lower()

        # --- User-type principals ---
        if "user" in obj_type or p.get("upn"):
            # Try exact UPN match first (high confidence)
            if p.get("upn"):
                matches = search_users(target_token, upn=p["upn"])
                for m in matches:
                    if m["id"] not in seen_ids:
                        suggestions.append({
                            "id": m["id"],
                            "displayName": m.get("displayName", ""),
                            "upn": m.get("userPrincipalName", ""),
                            "confidence": "high",
                        })
                        seen_ids.add(m["id"])

            # Try mail match
            if p.get("mail") and not suggestions:
                matches = search_users(target_token, mail=p["mail"])
                for m in matches:
                    if m["id"] not in seen_ids:
                        suggestions.append({
                            "id": m["id"],
                            "displayName": m.get("displayName", ""),
                            "upn": m.get("userPrincipalName", ""),
                            "confidence": "high",
                        })
                        seen_ids.add(m["id"])

            # Try display name match (medium confidence)
            if p.get("display_name") and p["display_name"] != "(unknown)" and not suggestions:
                matches = search_users(target_token, display_name=p["display_name"])
                for m in matches:
                    if m["id"] not in seen_ids:
                        suggestions.append({
                            "id": m["id"],
                            "displayName": m.get("displayName", ""),
                            "upn": m.get("userPrincipalName", ""),
                            "confidence": "medium",
                        })
                        seen_ids.add(m["id"])

        # --- Group-type principals ---
        elif "group" in obj_type:
            if p.get("display_name") and p["display_name"] != "(unknown)":
                matches = search_groups(target_token, display_name=p["display_name"])
                for m in matches:
                    if m["id"] not in seen_ids:
                        suggestions.append({
                            "id": m["id"],
                            "displayName": m.get("displayName", ""),
                            "confidence": "medium",
                        })
                        seen_ids.add(m["id"])

        # --- Service Principal / Application ---
        elif "serviceprincipal" in obj_type or "application" in obj_type:
            if p.get("display_name") and p["display_name"] != "(unknown)":
                matches = search_service_principals(target_token, display_name=p["display_name"])
                for m in matches:
                    if m["id"] not in seen_ids:
                        suggestions.append({
                            "id": m["id"],
                            "displayName": m.get("displayName", ""),
                            "confidence": "medium",
                        })
                        seen_ids.add(m["id"])

        # --- Fallback: try users + groups + SPs by display name ---
        else:
            if p.get("display_name") and p["display_name"] != "(unknown)":
                for search_fn in (
                    lambda: search_users(target_token, display_name=p["display_name"]),
                    lambda: search_groups(target_token, display_name=p["display_name"]),
                    lambda: search_service_principals(target_token, display_name=p["display_name"]),
                ):
                    matches = search_fn()
                    for m in matches:
                        mid = m.get("id", "")
                        if mid and mid not in seen_ids:
                            suggestions.append({
                                "id": mid,
                                "displayName": m.get("displayName", ""),
                                "confidence": "low",
                            })
                            seen_ids.add(mid)

        p["suggestions"] = suggestions
        if suggestions:
            logger.info(
                "Principal %s ('%s'): %d suggestion(s), best=%s",
                p["principal_id"],
                p.get("display_name", "?"),
                len(suggestions),
                suggestions[0]["confidence"],
            )
        else:
            logger.info(
                "Principal %s ('%s'): no suggestions found",
                p["principal_id"],
                p.get("display_name", "?"),
            )

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
