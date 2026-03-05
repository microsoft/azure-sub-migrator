"""Flask application factory for tenova web UI."""

from __future__ import annotations

import os
from pathlib import Path

from flask import Flask
from werkzeug.middleware.proxy_fix import ProxyFix


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
    app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret-change-me")

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

    return app
