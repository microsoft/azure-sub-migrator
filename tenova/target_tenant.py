"""Target-tenant authentication and Microsoft Graph helpers.

After a cross-tenant subscription transfer, Tenova needs to operate in the
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

from tenova.logger import get_logger

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
        scopes = ["https://management.azure.com/user_impersonation"]

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
        scopes = ["https://management.azure.com/user_impersonation"]

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
