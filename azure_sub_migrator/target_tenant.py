# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""Target-tenant authentication and Microsoft Graph helpers.

After a cross-tenant subscription transfer, Azure Sub Migrator needs to operate in the
*target* (destination) tenant — e.g. to recreate RBAC, update Key Vault
access policies, and discover matching principals.

This module provides:
  - A second MSAL auth flow against an arbitrary tenant so the user can
    authenticate in the target tenant without signing out of the source.
  - A lightweight Microsoft Graph client for listing users / groups /
    service principals in the target tenant (used for principal mapping).
"""

from __future__ import annotations

from typing import Any

import requests

from azure_sub_migrator.logger import get_logger

logger = get_logger("target_tenant")


# ──────────────────────────────────────────────────────────────────────
# MSAL helpers (called by web/auth_web.py routes)
# ──────────────────────────────────────────────────────────────────────

def build_target_auth_url(
    *,
    client_id: str,
    target_tenant_id: str,
    redirect_uri: str,
    state: str,
    scopes: list[str] | None = None,
) -> str:
    """Return an OAuth2 authorize URL targeting a specific tenant.

    Rather than building a full MSAL ConfidentialClientApplication
    (which needs the client credential), we construct the URL directly
    since we only need the auth-code leg here.
    """
    if scopes is None:
        scopes = [
            "https://graph.microsoft.com/Directory.Read.All",
            "https://graph.microsoft.com/User.Read",
        ]

    scope_str = " ".join(scopes)
    params = (
        f"client_id={client_id}"
        f"&response_type=code"
        f"&redirect_uri={redirect_uri}"
        f"&response_mode=query"
        f"&scope={scope_str}"
        f"&state={state}"
        f"&prompt=select_account"
    )
    url = (
        f"https://login.microsoftonline.com/{target_tenant_id}"
        f"/oauth2/v2.0/authorize?{params}"
    )
    logger.info("Built target-tenant auth URL for tenant %s", target_tenant_id)
    return url


def redeem_target_auth_code(
    *,
    client_id: str,
    client_credential: dict | str,
    target_tenant_id: str,
    code: str,
    redirect_uri: str,
    scopes: list[str] | None = None,
) -> dict[str, Any]:
    """Exchange the authorization code for tokens using MSAL.

    Returns the full MSAL result dict (access_token, id_token_claims, etc.).
    """
    import msal

    if scopes is None:
        scopes = [
            "https://graph.microsoft.com/Directory.Read.All",
            "https://graph.microsoft.com/User.Read",
        ]

    authority = f"https://login.microsoftonline.com/{target_tenant_id}"
    app = msal.ConfidentialClientApplication(
        client_id=client_id,
        client_credential=client_credential,
        authority=authority,
    )
    result = app.acquire_token_by_authorization_code(
        code=code,
        scopes=scopes,
        redirect_uri=redirect_uri,
    )
    if "error" in result:
        logger.error(
            "Target-tenant token exchange failed: %s — %s",
            result.get("error"),
            result.get("error_description"),
        )
    else:
        claims = result.get("id_token_claims", {})
        logger.info(
            "Target-tenant token acquired for user %s in tenant %s",
            claims.get("preferred_username", "?"),
            target_tenant_id,
        )
    return result


# ──────────────────────────────────────────────────────────────────────
# Microsoft Graph helpers (lightweight — no SDK dependency)
# ──────────────────────────────────────────────────────────────────────

GRAPH_BASE = "https://graph.microsoft.com/v1.0"


def _graph_headers(access_token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }


def search_users(
    access_token: str,
    *,
    display_name: str | None = None,
    upn: str | None = None,
    mail: str | None = None,
) -> list[dict[str, Any]]:
    """Search for users in the target tenant via Microsoft Graph.

    At least one of display_name / upn / mail must be provided.
    Returns a list of user objects (id, displayName, userPrincipalName, mail).
    """
    filters: list[str] = []
    if upn:
        filters.append(f"userPrincipalName eq '{upn}'")
    if mail:
        filters.append(f"mail eq '{mail}'")
    if display_name:
        filters.append(f"startswith(displayName, '{display_name}')")

    if not filters:
        return []

    filter_str = " or ".join(filters)
    url = f"{GRAPH_BASE}/users?$filter={filter_str}&$select=id,displayName,userPrincipalName,mail&$top=10"

    try:
        resp = requests.get(url, headers=_graph_headers(access_token), timeout=15)
        resp.raise_for_status()
        return resp.json().get("value", [])
    except Exception as exc:
        logger.warning("Graph user search failed: %s", exc)
        return []


def search_groups(
    access_token: str,
    *,
    display_name: str,
) -> list[dict[str, Any]]:
    """Search for groups in the target tenant by display name."""
    url = (
        f"{GRAPH_BASE}/groups"
        f"?$filter=startswith(displayName, '{display_name}')"
        f"&$select=id,displayName,mail"
        f"&$top=10"
    )
    try:
        resp = requests.get(url, headers=_graph_headers(access_token), timeout=15)
        resp.raise_for_status()
        return resp.json().get("value", [])
    except Exception as exc:
        logger.warning("Graph group search failed: %s", exc)
        return []


def search_service_principals(
    access_token: str,
    *,
    display_name: str,
) -> list[dict[str, Any]]:
    """Search for service principals in the target tenant."""
    url = (
        f"{GRAPH_BASE}/servicePrincipals"
        f"?$filter=startswith(displayName, '{display_name}')"
        f"&$select=id,displayName,appId,servicePrincipalType"
        f"&$top=10"
    )
    try:
        resp = requests.get(url, headers=_graph_headers(access_token), timeout=15)
        resp.raise_for_status()
        return resp.json().get("value", [])
    except Exception as exc:
        logger.warning("Graph SP search failed: %s", exc)
        return []


def get_directory_object(access_token: str, object_id: str) -> dict[str, Any] | None:
    """Resolve a single directory object by its ID."""
    url = f"{GRAPH_BASE}/directoryObjects/{object_id}"
    try:
        resp = requests.get(url, headers=_graph_headers(access_token), timeout=10)
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        logger.warning("Graph directoryObject lookup failed for %s: %s", object_id, exc)
        return None


# ──────────────────────────────────────────────────────────────────────
# Batch resolution (up to 20 objects per request via $batch)
# ──────────────────────────────────────────────────────────────────────

def batch_resolve_objects(
    access_token: str,
    object_ids: list[str],
) -> dict[str, dict[str, Any]]:
    """Resolve multiple directory objects using Graph JSON batching.

    Returns ``{object_id: graph_object}`` for each successfully resolved ID.
    Unresolvable IDs (deleted, wrong tenant) are silently omitted.
    """
    results: dict[str, dict[str, Any]] = {}
    # Graph batching supports up to 20 requests per batch
    batch_size = 20

    for start in range(0, len(object_ids), batch_size):
        chunk = object_ids[start : start + batch_size]
        batch_requests = [
            {
                "id": oid,
                "method": "GET",
                "url": f"/directoryObjects/{oid}",
            }
            for oid in chunk
        ]

        try:
            resp = requests.post(
                f"{GRAPH_BASE}/$batch",
                headers=_graph_headers(access_token),
                json={"requests": batch_requests},
                timeout=30,
            )
            resp.raise_for_status()
            for item in resp.json().get("responses", []):
                if item.get("status") == 200:
                    body = item.get("body", {})
                    results[item["id"]] = body
        except Exception as exc:
            logger.warning("Graph batch resolve failed for chunk starting at %d: %s", start, exc)

    logger.info("Batch-resolved %d / %d directory objects", len(results), len(object_ids))
    return results


# ──────────────────────────────────────────────────────────────────────
# Bulk directory listing (for Sharegate-style auto-matching)
# ──────────────────────────────────────────────────────────────────────

def _paginated_graph_list(
    access_token: str,
    url: str,
    *,
    max_pages: int = 10,
) -> list[dict[str, Any]]:
    """Follow @odata.nextLink to fetch paginated Graph results."""
    all_items: list[dict[str, Any]] = []
    page = 0

    while url and page < max_pages:
        try:
            resp = requests.get(url, headers=_graph_headers(access_token), timeout=30)
            resp.raise_for_status()
            data = resp.json()
            all_items.extend(data.get("value", []))
            url = data.get("@odata.nextLink", "")
            page += 1
        except Exception as exc:
            logger.warning("Graph paginated list failed on page %d: %s", page, exc)
            break

    return all_items


def list_all_users(access_token: str) -> list[dict[str, Any]]:
    """Fetch all users from the tenant (paginated, select key fields)."""
    url = (
        f"{GRAPH_BASE}/users"
        f"?$select=id,displayName,userPrincipalName,mail"
        f"&$top=999"
    )
    users = _paginated_graph_list(access_token, url)
    logger.info("Fetched %d user(s) from directory", len(users))
    return users


def list_all_groups(access_token: str) -> list[dict[str, Any]]:
    """Fetch all groups from the tenant (paginated, select key fields)."""
    url = (
        f"{GRAPH_BASE}/groups"
        f"?$select=id,displayName,mail,mailNickname"
        f"&$top=999"
    )
    groups = _paginated_graph_list(access_token, url)
    logger.info("Fetched %d group(s) from directory", len(groups))
    return groups


def list_all_service_principals(access_token: str) -> list[dict[str, Any]]:
    """Fetch all service principals from the tenant (paginated)."""
    url = (
        f"{GRAPH_BASE}/servicePrincipals"
        f"?$select=id,displayName,appId,servicePrincipalType"
        f"&$top=999"
    )
    sps = _paginated_graph_list(access_token, url)
    logger.info("Fetched %d service principal(s) from directory", len(sps))
    return sps
