"""Flask routes for the migration web UI."""

from __future__ import annotations

import json
from flask import (
    Blueprint,
    current_app,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from web.auth_web import login_required, get_access_token
from web.tasks import fetch_subscriptions, get_task, start_scan, start_readiness_check, start_rbac_export

main_bp = Blueprint("main", __name__)


# ──────────────────────────────────────────────────────────────────────
# Landing
# ──────────────────────────────────────────────────────────────────────

@main_bp.route("/")
def index():
    """Show login page or redirect to dashboard."""
    if "user" in session:
        return redirect(url_for("main.dashboard"))
    return render_template("login.html")


# ──────────────────────────────────────────────────────────────────────
# Dashboard
# ──────────────────────────────────────────────────────────────────────

@main_bp.route("/dashboard")
@login_required
def dashboard():
    """List subscriptions the user has access to."""
    token = get_access_token()
    error = None
    subs = []
    try:
        subs = fetch_subscriptions(token)
    except Exception as exc:
        error = str(exc)
    user = session.get("user", {})
    tenant_id = session.get("tenant_id", "")
    return render_template("dashboard.html", subscriptions=subs, user=user, error=error, tenant_id=tenant_id)


# ──────────────────────────────────────────────────────────────────────
# Scan
# ──────────────────────────────────────────────────────────────────────

@main_bp.route("/scan", methods=["POST"])
@login_required
def scan():
    """Start a background subscription scan."""
    subscription_id = request.form.get("subscription_id", "")
    if not subscription_id:
        return jsonify({"error": "subscription_id is required"}), 400

    token = get_access_token()
    task_id = start_scan(token, subscription_id)
    session["last_scan_sub"] = subscription_id
    return redirect(url_for("main.scan_status", task_id=task_id))


@main_bp.route("/scan/<task_id>")
@login_required
def scan_status(task_id: str):
    """Show scan progress / results."""
    task = get_task(task_id)
    if task is None:
        return render_template("error.html", message="Task not found."), 404

    return render_template(
        "scan_results.html",
        task=task,
        task_id=task_id,
        subscription_id=session.get("last_scan_sub", ""),
    )


# ──────────────────────────────────────────────────────────────────────
# API endpoint for polling task status
# ──────────────────────────────────────────────────────────────────────

@main_bp.route("/api/task/<task_id>")
@login_required
def api_task_status(task_id: str):
    """Return task status as JSON (used by the JS polling loop)."""
    task = get_task(task_id)
    if task is None:
        return jsonify({"error": "not found"}), 404

    payload: dict = {
        "task_id": task.task_id,
        "status": task.status.value,
        "task_type": task.task_type,
    }
    # Scan results
    if task.task_type == "scan" and task.result:
        payload["transfer_safe_count"] = len(task.result.get("transfer_safe", []))
        payload["requires_action_count"] = len(task.result.get("requires_action", []))
        payload["transfer_safe"] = task.result.get("transfer_safe", [])
        payload["requires_action"] = task.result.get("requires_action", [])
    # Readiness results
    elif task.task_type == "readiness" and task.result:
        payload["readiness"] = task.result.get("readiness", {})
    # RBAC export results
    elif task.task_type == "rbac_export" and task.result:
        payload["rbac_export"] = task.result.get("rbac_export", {})

    if task.error:
        payload["error"] = task.error

    return jsonify(payload)


# ──────────────────────────────────────────────────────────────────────
# Migration Plan (download JSON)
# ──────────────────────────────────────────────────────────────────────

@main_bp.route("/plan/<task_id>")
@login_required
def migration_plan(task_id: str):
    """Generate and return a migration plan JSON for a completed scan."""
    task = get_task(task_id)
    if task is None or task.result is None:
        return render_template("error.html", message="No completed scan found."), 404

    plan = {
        "subscription_id": session.get("last_scan_sub", ""),
        "total_resources": (
            len(task.result.get("transfer_safe", []))
            + len(task.result.get("requires_action", []))
        ),
        "transfer_safe": task.result.get("transfer_safe", []),
        "requires_action": task.result.get("requires_action", []),
        "summary": {
            "transfer_safe_count": len(task.result.get("transfer_safe", [])),
            "requires_action_count": len(task.result.get("requires_action", [])),
        },
    }
    response = current_app.response_class(
        response=json.dumps(plan, indent=2),
        status=200,
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename=migration_plan_{task_id}.json"},
    )
    return response


# ──────────────────────────────────────────────────────────────────────
# Readiness Check
# ──────────────────────────────────────────────────────────────────────

@main_bp.route("/readiness", methods=["POST"])
@login_required
def readiness():
    """Start a background readiness check."""
    subscription_id = request.form.get("subscription_id", "")
    if not subscription_id:
        return jsonify({"error": "subscription_id is required"}), 400

    token = get_access_token()
    task_id = start_readiness_check(token, subscription_id)
    session["last_readiness_sub"] = subscription_id
    return redirect(url_for("main.readiness_status", task_id=task_id))


@main_bp.route("/readiness/<task_id>")
@login_required
def readiness_status(task_id: str):
    """Show readiness check progress / results."""
    task = get_task(task_id)
    if task is None:
        return render_template("error.html", message="Task not found."), 404

    return render_template(
        "readiness.html",
        task=task,
        task_id=task_id,
        subscription_id=session.get("last_readiness_sub", ""),
    )


# ──────────────────────────────────────────────────────────────────────
# Interactive Migration Checklist
# ──────────────────────────────────────────────────────────────────────

@main_bp.route("/checklist/<task_id>")
@login_required
def checklist(task_id: str):
    """Show interactive migration checklist based on scan results."""
    task = get_task(task_id)
    if task is None or task.result is None:
        return render_template("error.html", message="No completed scan found."), 404

    return render_template(
        "checklist.html",
        task_id=task_id,
        subscription_id=session.get("last_scan_sub", ""),
        scan_data=task.result,
    )


# ──────────────────────────────────────────────────────────────────────
# RBAC Export
# ──────────────────────────────────────────────────────────────────────

@main_bp.route("/export-rbac", methods=["POST"])
@login_required
def export_rbac_route():
    """Start a background RBAC export."""
    subscription_id = request.form.get("subscription_id", "")
    if not subscription_id:
        return jsonify({"error": "subscription_id is required"}), 400

    token = get_access_token()
    task_id = start_rbac_export(token, subscription_id)
    session["last_rbac_sub"] = subscription_id
    return redirect(url_for("main.rbac_export_status", task_id=task_id))


@main_bp.route("/export-rbac/<task_id>")
@login_required
def rbac_export_status(task_id: str):
    """Show RBAC export progress / results."""
    task = get_task(task_id)
    if task is None:
        return render_template("error.html", message="Task not found."), 404

    return render_template(
        "rbac_export.html",
        task=task,
        task_id=task_id,
        subscription_id=session.get("last_rbac_sub", ""),
    )


@main_bp.route("/api/rbac-download/<task_id>")
@login_required
def rbac_download(task_id: str):
    """Download the RBAC export JSON from a completed export task."""
    task = get_task(task_id)
    if task is None or task.result is None:
        return jsonify({"error": "Export not found or not complete"}), 404

    rbac_data = task.result.get("rbac_export", {}).get("export_data", {})
    response = current_app.response_class(
        response=json.dumps(rbac_data, indent=2),
        status=200,
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename=rbac_export_{task_id}.json"},
    )
    return response


# ──────────────────────────────────────────────────────────────────────
# Report Exports (PDF / Excel)
# ──────────────────────────────────────────────────────────────────────

@main_bp.route("/export/pdf/<task_id>")
@login_required
def export_pdf(task_id: str):
    """Download a PDF migration report for a completed scan."""
    task = get_task(task_id)
    if task is None or task.result is None:
        return render_template("error.html", message="No completed scan found."), 404

    from tenova.report_export import generate_pdf

    pdf_bytes = generate_pdf(
        scan_result=task.result,
        subscription_id=session.get("last_scan_sub", ""),
    )
    response = make_response(bytes(pdf_bytes))
    response.headers["Content-Type"] = "application/pdf"
    response.headers["Content-Disposition"] = f"attachment; filename=migration_report_{task_id}.pdf"
    return response


@main_bp.route("/export/excel/<task_id>")
@login_required
def export_excel(task_id: str):
    """Download an Excel migration report for a completed scan."""
    task = get_task(task_id)
    if task is None or task.result is None:
        return render_template("error.html", message="No completed scan found."), 404

    from tenova.report_export import generate_excel

    excel_bytes = generate_excel(
        scan_result=task.result,
        subscription_id=session.get("last_scan_sub", ""),
    )
    response = make_response(excel_bytes)
    response.headers["Content-Type"] = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    response.headers["Content-Disposition"] = f"attachment; filename=migration_report_{task_id}.xlsx"
    return response
