"""Flask application factory for tenova web UI."""

from __future__ import annotations

import os
import secrets
from datetime import timedelta
from pathlib import Path

from flask import Flask, Response, g, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from werkzeug.middleware.proxy_fix import ProxyFix

csrf = CSRFProtect()
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["120 per minute"],
    storage_uri="memory://",
)


def create_app() -> Flask:
    """Create and configure the Flask application."""
    app = Flask(
        __name__,
        template_folder=str(Path(__file__).parent / "templates"),
        static_folder=str(Path(__file__).parent / "static"),
    )

    # Trust Azure App Service reverse-proxy headers so
    # request.url_root uses https:// instead of http://
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

    # ── Configuration ────────────────────────────────────────────────
    # SECRET_KEY — fail fast if not set in production; auto-generate
    # a random key for local dev so the app still starts.
    flask_secret = os.environ.get("FLASK_SECRET_KEY")
    if not flask_secret:
        if os.environ.get("WEBSITE_HOSTNAME"):  # Azure App Service
            raise RuntimeError(
                "FLASK_SECRET_KEY must be set in App Service configuration"
            )
        flask_secret = secrets.token_hex(32)  # safe random for local dev
    app.secret_key = flask_secret

    # ── Secure cookie settings ───────────────────────────────────────
    is_azure = bool(os.environ.get("WEBSITE_HOSTNAME"))
    app.config["SESSION_COOKIE_SECURE"] = is_azure    # Secure only on HTTPS (Azure)
    app.config["SESSION_COOKIE_HTTPONLY"] = True       # no JS access
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"     # CSRF protection

    # Session idle timeout (default 30 minutes)
    app.config["SESSION_IDLE_MINUTES"] = int(os.environ.get("SESSION_IDLE_MINUTES", "30"))
    app.permanent_session_lifetime = timedelta(
        minutes=app.config["SESSION_IDLE_MINUTES"]
    )

    # Entra ID / MSAL settings
    app.config["ENTRA_CLIENT_ID"] = os.environ.get("ENTRA_CLIENT_ID", "")
    app.config["ENTRA_CLIENT_SECRET"] = os.environ.get("ENTRA_CLIENT_SECRET", "")
    app.config["ENTRA_REDIRECT_PATH"] = os.environ.get("ENTRA_REDIRECT_PATH", "/auth/callback")
    # Use 'organizations' so users from ANY Entra ID tenant can sign in
    app.config["ENTRA_AUTHORITY"] = "https://login.microsoftonline.com/organizations"
    app.config["ENTRA_SCOPES"] = [
        "https://management.azure.com/user_impersonation",
    ]

    # Migration output
    app.config["OUTPUT_DIR"] = os.environ.get("MIGRATION_OUTPUT_DIR", "migration_output")

    # ── Register blueprints ──────────────────────────────────────────
    from web.routes import main_bp
    from web.auth_web import auth_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)

    # ── CSRF protection ──────────────────────────────────────────────
    csrf.init_app(app)
    csrf.exempt(auth_bp)  # OAuth routes use their own state parameter

    # ── Rate limiting ────────────────────────────────────────────────
    limiter.init_app(app)

    # ── CSP nonce (generated per-request for inline scripts) ─────────
    @app.before_request
    def _generate_csp_nonce() -> None:
        g.csp_nonce = secrets.token_urlsafe(16)

    @app.context_processor
    def _inject_csp_nonce() -> dict:
        return {"csp_nonce": getattr(g, "csp_nonce", "")}

    # ── Security headers (applied to every response) ─────────────────
    @app.after_request
    def _set_security_headers(response: Response) -> Response:
        nonce = getattr(g, "csp_nonce", "")
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=()"
        )
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            f"script-src 'nonce-{nonce}' 'self' https://cdn.jsdelivr.net https://code.jquery.com https://cdn.datatables.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdn.datatables.net; "
            "font-src 'self' https://cdn.jsdelivr.net; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'"
        )
        # Prevent caching of authenticated / data-bearing responses
        if "user" in session:
            response.headers["Cache-Control"] = "no-store"
            response.headers["Pragma"] = "no-cache"
        return response

    return app
