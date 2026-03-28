# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""MSAL / Entra ID authentication for the web UI.

Implements the OAuth 2.0 Authorization Code flow so users sign in with
their Microsoft account and we receive an access token scoped to
Azure Resource Manager.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import datetime, timezone
from functools import wraps
from typing import Any
from urllib.parse import urlparse

import msal
from flask import (
    Blueprint,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from markupsafe import escape

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


# ──────────────────────────────────────────────────────────────────────
# Helpers — MSAL token cache persistence
# ──────────────────────────────────────────────────────────────────────

def _load_cache() -> msal.SerializableTokenCache:
    """Load the MSAL token cache from the Flask session.

    We serialise the cache as JSON in ``session['msal_cache']`` so that
    the refresh token survives across requests.  This is critical for
    cross-resource token acquisition (e.g. ARM login → Graph token).
    """
    cache = msal.SerializableTokenCache()
    blob = session.get("msal_cache")
    if blob:
        cache.deserialize(blob)
    return cache


def _save_cache(cache: msal.SerializableTokenCache) -> None:
    """Persist the MSAL token cache back to the Flask session."""
    if cache.has_state_changed:
        session["msal_cache"] = cache.serialize()


def _build_msal_app(
    cache: msal.SerializableTokenCache | None = None,
) -> msal.ConfidentialClientApplication:
    """Build a ConfidentialClientApplication with an optional token cache."""
    return msal.ConfidentialClientApplication(
        client_id=current_app.config["ENTRA_CLIENT_ID"],
        client_credential=current_app.config["ENTRA_CLIENT_CREDENTIAL"],
        authority=current_app.config["ENTRA_AUTHORITY"],
        token_cache=cache,
    )


def _get_token_from_cache() -> dict[str, Any] | None:
    """Try to silently acquire a token from the MSAL cache."""
    cache = _load_cache()
    app = _build_msal_app(cache)
    accounts = app.get_accounts()
    if accounts:
        result = app.acquire_token_silent(
            scopes=current_app.config["ENTRA_SCOPES"],
            account=accounts[0],
        )
        _save_cache(cache)
        if result and "access_token" in result:
            return result
    return None


def login_required(f: Callable) -> Callable:
    """Decorator that redirects to login if the user has no valid session."""

    @wraps(f)
    def decorated(*args: Any, **kwargs: Any) -> Any:
        if "user" not in session:
            return redirect(url_for("auth.login"))
        return f(*args, **kwargs)

    return decorated


def get_access_token() -> str | None:
    """Return a valid ARM access token, refreshing silently if needed."""
    # Try silent refresh first — handles expired tokens automatically
    refreshed = _get_token_from_cache()
    if refreshed:
        session["access_token"] = refreshed["access_token"]
        return refreshed["access_token"]
    # Fallback to whatever is in the session (may be expired)
    return session.get("access_token")


def get_graph_token() -> str | None:
    """Return a Microsoft Graph access token for the source tenant.

    Strategy (ordered by preference):
      1. Silent acquisition via MSAL cache — uses the refresh token from
         the initial ARM login to get a Graph token for a different
         resource.  Requires Directory.Read.All delegated permission with
         admin consent.
      2. Explicit token stored in the session by the consent-graph
         callback (``session['source_graph_token']``).
      3. ``None`` — caller should redirect to ``/auth/consent-graph``.
    """
    # Try MSAL silent acquisition (cross-resource refresh)
    cache = _load_cache()
    app = _build_msal_app(cache)
    accounts = app.get_accounts()
    if accounts:
        graph_scopes = current_app.config.get("GRAPH_SCOPES", [
            "https://graph.microsoft.com/Directory.Read.All",
        ])
        result = app.acquire_token_silent(
            scopes=graph_scopes, account=accounts[0],
        )
        _save_cache(cache)
        if result and "access_token" in result:
            # Also stash it so we have a fallback for this session
            session["source_graph_token"] = result["access_token"]
            return result["access_token"]

    # Fallback: explicit token from consent-graph callback
    return session.get("source_graph_token")


# ──────────────────────────────────────────────────────────────────────
# Routes
# ──────────────────────────────────────────────────────────────────────

# ──────────────────────────────────────────────────────────────────────
# Idle-session timeout (before every request)
# ──────────────────────────────────────────────────────────────────────

@auth_bp.before_app_request
def _enforce_idle_timeout():
    """Clear the session if the user has been idle too long."""
    if "user" not in session:
        return  # not logged in — nothing to enforce

    last = session.get("last_activity")
    if last:
        from datetime import timedelta

        idle_limit = timedelta(
            minutes=current_app.config.get("SESSION_IDLE_MINUTES", 30)
        )
        last_dt = datetime.fromisoformat(last)
        if datetime.now(timezone.utc) - last_dt > idle_limit:
            # Purge task data before clearing the session
            user_oid = session.get("user", {}).get("oid", "")
            if user_oid:
                from web.tasks import cleanup_user_tasks
                cleanup_user_tasks(user_oid)
            session.clear()
            return redirect(url_for("auth.login"))

    # Update last-activity timestamp on every authenticated request
    session["last_activity"] = datetime.now(timezone.utc).isoformat()


@auth_bp.route("/login")
def login():
    """Start the OAuth2 authorization-code flow."""
    session["state"] = str(uuid.uuid4())
    cache = _load_cache()
    app = _build_msal_app(cache)
    auth_url = app.get_authorization_request_url(
        scopes=current_app.config["ENTRA_SCOPES"],
        state=session["state"],
        redirect_uri=request.url_root.rstrip("/") + current_app.config["ENTRA_REDIRECT_PATH"],
        prompt="select_account",  # always show account picker
    )
    # Validate redirect target — strip backslashes, then verify no
    # external netloc beyond our known-good host (prevents open redirect).
    auth_url = auth_url.replace('\\', '')
    parsed = urlparse(auth_url)
    if not parsed.netloc or not parsed.scheme:
        return redirect(auth_url)
    if parsed.scheme == "https" and parsed.netloc == "login.microsoftonline.com":
        return redirect(auth_url)
    flash("Invalid authentication URL.", "danger")
    return redirect(url_for("main.dashboard"))


@auth_bp.route("/callback")
def callback():
    """Handle the redirect from Entra ID after user signs in."""
    # Validate state — redirect gracefully so user can retry
    if request.args.get("state") != session.get("state"):
        session.clear()
        flash("Session expired. Please sign in again.", "warning")
        return redirect(url_for("auth.login"))

    if "error" in request.args:
        return render_template(
            "error.html",
            message=f"Authentication failed: {escape(request.args.get('error_description', 'Unknown error'))}",
        ), 400

    cache = _load_cache()
    app = _build_msal_app(cache)
    result = app.acquire_token_by_authorization_code(
        code=request.args["code"],
        scopes=current_app.config["ENTRA_SCOPES"],
        redirect_uri=request.url_root.rstrip("/") + current_app.config["ENTRA_REDIRECT_PATH"],
    )

    if "error" in result:
        return render_template(
            "error.html",
            message="Authentication failed. Please try signing in again.",
        ), 400

    # Persist the MSAL cache (stores refresh token for cross-resource use)
    _save_cache(cache)

    # Store user info, token, and tenant in session
    claims = result.get("id_token_claims", {})
    session.permanent = True
    session["user"] = claims
    session["access_token"] = result.get("access_token")
    session["tenant_id"] = claims.get("tid", "")  # user's home tenant
    session["last_activity"] = datetime.now(timezone.utc).isoformat()
    return redirect(url_for("main.dashboard"))


@auth_bp.route("/logout")
def logout():
    """Clear task data and session, then redirect to Microsoft logout."""
    # Purge all task results belonging to this user from memory and Redis
    user_oid = session.get("user", {}).get("oid", "")
    if user_oid:
        from web.tasks import cleanup_user_tasks
        cleanup_user_tasks(user_oid)

    session.clear()
    authority = current_app.config["ENTRA_AUTHORITY"]
    return redirect(
        f"{authority}/oauth2/v2.0/logout"
        f"?post_logout_redirect_uri={request.url_root}"
    )


@auth_bp.route("/target-tenant", methods=["POST"])
@login_required
def target_tenant_login():
    """Start a second OAuth flow targeting the destination tenant."""
    from azure_sub_migrator.target_tenant import build_target_auth_url

    target_tenant_id = request.form.get("target_tenant_id", "").strip()
    task_id = request.form.get("task_id", "").strip()

    if not target_tenant_id:
        flash("Target tenant ID is required.", "danger")
        return redirect(url_for("main.dashboard"))

    # Validate UUID format
    import re
    if not re.match(
        r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
        target_tenant_id,
        re.IGNORECASE,
    ):
        flash("Target tenant ID must be a valid UUID.", "danger")
        return redirect(url_for("main.dashboard"))

    session["target_tenant_state"] = str(uuid.uuid4())
    session["target_tenant_id"] = target_tenant_id
    session["target_tenant_task_id"] = task_id

    redirect_uri = (
        request.url_root.rstrip("/")
        + url_for("auth.target_tenant_callback")
    )

    auth_url = build_target_auth_url(
        client_id=current_app.config["ENTRA_CLIENT_ID"],
        target_tenant_id=target_tenant_id,
        redirect_uri=redirect_uri,
        state=session["target_tenant_state"],
    )
    # Validate redirect target — strip backslashes, then verify no
    # external netloc beyond our known-good host (prevents open redirect).
    auth_url = auth_url.replace('\\', '')
    parsed = urlparse(auth_url)
    if not parsed.netloc or not parsed.scheme:
        # Relative URL — safe
        return redirect(auth_url)
    if parsed.scheme == "https" and parsed.netloc == "login.microsoftonline.com":
        # Known-good external host — safe
        return redirect(auth_url)
    flash("Invalid authentication URL.", "danger")
    return redirect(url_for("main.dashboard"))


@auth_bp.route("/target-tenant/callback")
def target_tenant_callback():
    """Handle the redirect after user authenticates in the target tenant."""
    if request.args.get("state") != session.get("target_tenant_state"):
        flash("Session state mismatch. Please try again.", "warning")
        return redirect(url_for("main.dashboard"))

    if "error" in request.args:
        flash(
            f"Target tenant auth failed: {request.args.get('error_description', '')}",
            "danger",
        )
        return redirect(url_for("main.dashboard"))

    from azure_sub_migrator.target_tenant import redeem_target_auth_code

    target_tenant_id = session.get("target_tenant_id", "")
    redirect_uri = (
        request.url_root.rstrip("/")
        + url_for("auth.target_tenant_callback")
    )

    result = redeem_target_auth_code(
        client_id=current_app.config["ENTRA_CLIENT_ID"],
        client_credential=current_app.config["ENTRA_CLIENT_CREDENTIAL"],
        target_tenant_id=target_tenant_id,
        code=request.args["code"],
        redirect_uri=redirect_uri,
    )

    if "error" in result:
        flash(
            f"Token error: {result.get('error_description', '')}",
            "danger",
        )
        return redirect(url_for("main.dashboard"))

    # Store the target tenant tokens and identity separately.
    # access_token = ARM (management.azure.com) for post-transfer operations.
    # target_graph_token = Graph for principal mapping (may be absent if
    # silent acquisition failed — principal mapping will degrade gracefully).
    claims = result.get("id_token_claims", {})
    session["target_access_token"] = result.get("access_token")     # ARM token
    session["target_graph_token"] = result.get("graph_token", "")   # Graph token
    session["target_tenant_user"] = {
        "name": claims.get("name", ""),
        "preferred_username": claims.get("preferred_username", ""),
        "oid": claims.get("oid", ""),
        "tid": claims.get("tid", target_tenant_id),
    }
    session["target_tenant_connected"] = True

    task_id = session.get("target_tenant_task_id", "")
    flash(
        f"Connected to target tenant as {claims.get('preferred_username', 'user')}",
        "success",
    )
    if task_id:
        return redirect(url_for("main.principal_mapping", task_id=task_id))
    return redirect(url_for("main.dashboard") + "?tab=workflow")


# ──────────────────────────────────────────────────────────────────────
# Incremental consent for Microsoft Graph (principal mapping)
# ──────────────────────────────────────────────────────────────────────

@auth_bp.route("/consent-graph")
@login_required
def consent_graph():
    """Redirect the user to grant Graph permissions (incremental consent).

    After consent, the MSAL refresh token can be exchanged for a Graph
    access token via ``get_graph_token()``.
    """
    session["graph_consent_state"] = str(uuid.uuid4())
    cache = _load_cache()
    app = _build_msal_app(cache)
    graph_scopes = current_app.config.get("GRAPH_SCOPES", [
        "https://graph.microsoft.com/Directory.Read.All",
    ])
    auth_url = app.get_authorization_request_url(
        scopes=graph_scopes,
        state=session["graph_consent_state"],
        redirect_uri=(
            request.url_root.rstrip("/")
            + url_for("auth.consent_graph_callback")
        ),
        login_hint=session.get("user", {}).get("preferred_username", ""),
    )
    # Validate redirect target — strip backslashes, then verify no
    # external netloc beyond our known-good host (prevents open redirect).
    auth_url = auth_url.replace('\\', '')
    parsed = urlparse(auth_url)
    if not parsed.netloc or not parsed.scheme:
        return redirect(auth_url)
    if parsed.scheme == "https" and parsed.netloc == "login.microsoftonline.com":
        return redirect(auth_url)
    flash("Invalid authentication URL.", "danger")
    return redirect(url_for("main.dashboard"))


@auth_bp.route("/consent-graph/callback")
def consent_graph_callback():
    """Handle redirect after Graph consent; redeem code to populate cache."""
    if request.args.get("state") != session.get("graph_consent_state"):
        flash("Session state mismatch. Please try again.", "warning")
        return redirect(url_for("main.dashboard"))

    if "error" in request.args:
        desc = request.args.get("error_description", "Unknown error")
        flash(f"Graph consent failed: {desc}", "danger")
        return redirect(url_for("main.dashboard"))

    cache = _load_cache()
    app = _build_msal_app(cache)
    graph_scopes = current_app.config.get("GRAPH_SCOPES", [
        "https://graph.microsoft.com/Directory.Read.All",
    ])
    result = app.acquire_token_by_authorization_code(
        code=request.args["code"],
        scopes=graph_scopes,
        redirect_uri=(
            request.url_root.rstrip("/")
            + url_for("auth.consent_graph_callback")
        ),
    )
    if "error" in result:
        flash(
            f"Graph token error: {result.get('error_description', '')}",
            "danger",
        )
    else:
        _save_cache(cache)
        session["source_graph_token"] = result["access_token"]
        session["graph_consented"] = True
        flash("Graph permissions granted — display names will now resolve.", "success")

    return redirect(url_for("main.dashboard") + "?tab=workflow")


@auth_bp.route("/admin-consent")
def admin_consent():
    """Redirect an external-tenant admin to the Entra admin-consent endpoint.

    This creates a service principal for our app in that tenant so their
    users can sign in.
    """
    client_id = current_app.config["ENTRA_CLIENT_ID"]
    redirect_uri = request.url_root.rstrip("/") + url_for("auth.admin_consent_callback")
    # Use /common/ so any tenant admin can consent
    return redirect(
        f"https://login.microsoftonline.com/common/adminconsent"
        f"?client_id={client_id}"
        f"&redirect_uri={redirect_uri}"
    )


@auth_bp.route("/admin-consent/callback")
def admin_consent_callback():
    """Handle the redirect after admin consent is granted."""
    if "error" in request.args:
        error = request.args.get("error_description", request.args.get("error"))
        return render_template("error.html", message=f"Admin consent failed: {error}"), 400

    tenant = request.args.get("tenant", "your tenant")
    return render_template("consent_success.html", tenant=tenant)
