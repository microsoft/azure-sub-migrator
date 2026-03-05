"""MSAL / Entra ID authentication for the web UI.

Implements the OAuth 2.0 Authorization Code flow so users sign in with
their Microsoft account and we receive an access token scoped to
Azure Resource Manager.
"""

from __future__ import annotations

import uuid
from functools import wraps
from typing import Any, Callable

import msal
from flask import (
    Blueprint,
    current_app,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────

def _build_msal_app() -> msal.ConfidentialClientApplication:
    """Build a ConfidentialClientApplication from Flask config."""
    return msal.ConfidentialClientApplication(
        client_id=current_app.config["ENTRA_CLIENT_ID"],
        client_credential=current_app.config["ENTRA_CLIENT_SECRET"],
        authority=current_app.config["ENTRA_AUTHORITY"],
    )


def _get_token_from_cache() -> dict[str, Any] | None:
    """Try to silently acquire a token from the MSAL cache."""
    app = _build_msal_app()
    accounts = app.get_accounts()
    if accounts:
        result = app.acquire_token_silent(
            scopes=current_app.config["ENTRA_SCOPES"],
            account=accounts[0],
        )
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
    """Return a valid ARM access token from the session, or None."""
    return session.get("access_token")


# ──────────────────────────────────────────────────────────────────────
# Routes
# ──────────────────────────────────────────────────────────────────────

@auth_bp.route("/login")
def login():
    """Start the OAuth2 authorization-code flow."""
    session["state"] = str(uuid.uuid4())
    app = _build_msal_app()
    auth_url = app.get_authorization_request_url(
        scopes=current_app.config["ENTRA_SCOPES"],
        state=session["state"],
        redirect_uri=request.url_root.rstrip("/") + current_app.config["ENTRA_REDIRECT_PATH"],
        prompt="select_account",  # always show account picker
    )
    return redirect(auth_url)


@auth_bp.route("/callback")
def callback():
    """Handle the redirect from Entra ID after user signs in."""
    # Validate state
    if request.args.get("state") != session.get("state"):
        return "State mismatch – possible CSRF. Please try again.", 400

    if "error" in request.args:
        return f"Auth error: {request.args['error_description']}", 400

    app = _build_msal_app()
    result = app.acquire_token_by_authorization_code(
        code=request.args["code"],
        scopes=current_app.config["ENTRA_SCOPES"],
        redirect_uri=request.url_root.rstrip("/") + current_app.config["ENTRA_REDIRECT_PATH"],
    )

    if "error" in result:
        return f"Token error: {result.get('error_description')}", 400

    # Store user info, token, and tenant in session
    claims = result.get("id_token_claims", {})
    session["user"] = claims
    session["access_token"] = result.get("access_token")
    session["tenant_id"] = claims.get("tid", "")  # user's home tenant
    return redirect(url_for("main.dashboard"))


@auth_bp.route("/logout")
def logout():
    """Clear the session and redirect to Microsoft logout."""
    session.clear()
    authority = current_app.config["ENTRA_AUTHORITY"]
    return redirect(
        f"{authority}/oauth2/v2.0/logout"
        f"?post_logout_redirect_uri={request.url_root}"
    )


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
