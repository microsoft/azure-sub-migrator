"""Flask routes for the migration web UI."""

from __future__ import annotations

import json
import re

from flask import (
    Blueprint,
    current_app,
    flash,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from web.app import limiter
from web.auth_web import get_access_token, login_required
from web.tasks import (
    fetch_subscriptions,
    get_task,
    start_post_transfer,
    start_pre_transfer,
    start_rbac_export,
    start_readiness_check,
    start_scan,
)

main_bp = Blueprint("main", __name__)

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


def _get_owner_id() -> str:
    """Return the Entra OID of the currently signed-in user."""
    return session.get("user", {}).get("oid", "")


# ──────────────────────────────────────────────────────────────────────
# Health Check (unauthenticated — used by App Service health probes)
# ──────────────────────────────────────────────────────────────────────

@main_bp.route("/healthz")
def healthz():
    """Lightweight liveness probe for Azure App Service health checks."""
    return jsonify(status="healthy"), 200


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
@limiter.limit("10 per minute")
def scan():
    """Start a background subscription scan."""
    subscription_id = request.form.get("subscription_id", "").strip()
    if not subscription_id:
        return jsonify({"error": "subscription_id is required"}), 400
    if not _UUID_RE.match(subscription_id):
        return jsonify({"error": "subscription_id must be a valid UUID"}), 400

    token = get_access_token()
    task_id = start_scan(token, subscription_id, owner_id=_get_owner_id())
    session["last_scan_sub"] = subscription_id
    return redirect(url_for("main.scan_status", task_id=task_id))


@main_bp.route("/scan/<task_id>")
@login_required
def scan_status(task_id: str):
    """Show scan progress / results."""
    task = get_task(task_id, owner_id=_get_owner_id())
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
@limiter.limit("60 per minute")
def api_task_status(task_id: str):
    """Return task status as JSON (used by the JS polling loop)."""
    task = get_task(task_id, owner_id=_get_owner_id())
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
        payload["transfer_notes"] = task.result.get("transfer_notes", {})
        # Children are already nested inside parent entries by the scanner
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
    task = get_task(task_id, owner_id=_get_owner_id())
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
@limiter.limit("10 per minute")
def readiness():
    """Start a background readiness check."""
    subscription_id = request.form.get("subscription_id", "").strip()
    if not subscription_id:
        return jsonify({"error": "subscription_id is required"}), 400
    if not _UUID_RE.match(subscription_id):
        return jsonify({"error": "subscription_id must be a valid UUID"}), 400

    token = get_access_token()
    task_id = start_readiness_check(token, subscription_id, owner_id=_get_owner_id())
    session["last_readiness_sub"] = subscription_id
    return redirect(url_for("main.readiness_status", task_id=task_id))


@main_bp.route("/readiness/<task_id>")
@login_required
def readiness_status(task_id: str):
    """Show readiness check progress / results."""
    task = get_task(task_id, owner_id=_get_owner_id())
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
    task = get_task(task_id, owner_id=_get_owner_id())
    if task is None or task.result is None:
        return render_template("error.html", message="No completed scan found."), 404

    from tenova.runbook import enrich_with_commands

    subscription_id = session.get("last_scan_sub", "")
    enriched = enrich_with_commands(task.result, subscription_id)

    return render_template(
        "checklist.html",
        task_id=task_id,
        subscription_id=subscription_id,
        scan_data=enriched,
    )


# ──────────────────────────────────────────────────────────────────────
# RBAC Export
# ──────────────────────────────────────────────────────────────────────

@main_bp.route("/export-rbac", methods=["POST"])
@login_required
@limiter.limit("10 per minute")
def export_rbac_route():
    """Start a background RBAC export."""
    subscription_id = request.form.get("subscription_id", "").strip()
    if not subscription_id:
        return jsonify({"error": "subscription_id is required"}), 400
    if not _UUID_RE.match(subscription_id):
        return jsonify({"error": "subscription_id must be a valid UUID"}), 400

    token = get_access_token()
    task_id = start_rbac_export(token, subscription_id, owner_id=_get_owner_id())
    session["last_rbac_sub"] = subscription_id
    return redirect(url_for("main.rbac_export_status", task_id=task_id))


@main_bp.route("/export-rbac/<task_id>")
@login_required
def rbac_export_status(task_id: str):
    """Show RBAC export progress / results."""
    task = get_task(task_id, owner_id=_get_owner_id())
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
    task = get_task(task_id, owner_id=_get_owner_id())
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
# Report Exports (PDF / Excel / Runbook)
# ──────────────────────────────────────────────────────────────────────

@main_bp.route("/export/runbook/<task_id>")
@login_required
def export_runbook(task_id: str):
    """Download a Markdown migration runbook for a completed scan."""
    task = get_task(task_id, owner_id=_get_owner_id())
    if task is None or task.result is None:
        return render_template("error.html", message="No completed scan found."), 404

    from tenova.runbook import generate_runbook

    subscription_id = session.get("last_scan_sub", "")
    markdown = generate_runbook(
        scan_result=task.result,
        subscription_id=subscription_id,
    )
    response = make_response(markdown)
    response.headers["Content-Type"] = "text/markdown; charset=utf-8"
    response.headers["Content-Disposition"] = f"attachment; filename=migration_runbook_{task_id}.md"
    return response


@main_bp.route("/export/pdf/<task_id>")
@login_required
def export_pdf(task_id: str):
    """Download a PDF migration report for a completed scan."""
    task = get_task(task_id, owner_id=_get_owner_id())
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
    task = get_task(task_id, owner_id=_get_owner_id())
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


# ──────────────────────────────────────────────────────────────────────
# Post-Transfer: Connect Target Tenant
# ──────────────────────────────────────────────────────────────────────

@main_bp.route("/connect-target/<task_id>")
@login_required
def connect_target(task_id: str):
    """Show the target-tenant connection page."""
    task = get_task(task_id, owner_id=_get_owner_id())
    if task is None or task.result is None:
        return render_template("error.html", message="No completed scan found."), 404

    target_connected = session.get("target_tenant_connected", False)
    target_user = session.get("target_tenant_user", {})

    return render_template(
        "connect_target.html",
        task_id=task_id,
        subscription_id=session.get("last_scan_sub", ""),
        target_connected=target_connected,
        target_user=target_user,
        source_tenant_id=session.get("tenant_id", ""),
    )


# ──────────────────────────────────────────────────────────────────────
# Post-Transfer: Principal Mapping
# ──────────────────────────────────────────────────────────────────────

@main_bp.route("/principal-map/<task_id>")
@login_required
def principal_mapping(task_id: str):
    """Show the principal mapping page."""
    task = get_task(task_id, owner_id=_get_owner_id())
    if task is None or task.result is None:
        return render_template("error.html", message="No completed scan found."), 404

    if not session.get("target_tenant_connected"):
        flash("Please connect to the target tenant first.", "warning")
        return redirect(url_for("main.connect_target", task_id=task_id))

    # Check if we have a stored RBAC export for this scan
    rbac_task_id = session.get("last_rbac_task_id", "")
    rbac_task = get_task(rbac_task_id, owner_id=_get_owner_id()) if rbac_task_id else None
    rbac_export = None
    if rbac_task and rbac_task.result:
        rbac_export = rbac_task.result.get("rbac_export", {}).get("export_data", {})

    # Extract & resolve principals
    from tenova.principal_map import extract_principals, resolve_source_principals, suggest_mappings

    principals: list = []
    if rbac_export:
        principals = extract_principals(rbac_export)
        # Resolve source display names
        source_token = get_access_token()
        if source_token:
            resolve_source_principals(principals, source_token)
        # Auto-suggest matches in target tenant
        target_token = session.get("target_access_token", "")
        if target_token:
            suggest_mappings(principals, target_token)

    return render_template(
        "principal_map.html",
        task_id=task_id,
        subscription_id=session.get("last_scan_sub", ""),
        principals=principals,
        has_rbac_export=rbac_export is not None,
        target_user=session.get("target_tenant_user", {}),
    )


@main_bp.route("/principal-map/<task_id>/save", methods=["POST"])
@login_required
@limiter.limit("10 per minute")
def save_principal_mapping(task_id: str):
    """Save the user-confirmed principal mapping and start post-transfer."""
    task = get_task(task_id, owner_id=_get_owner_id())
    if task is None or task.result is None:
        return render_template("error.html", message="No completed scan found."), 404

    if not session.get("target_tenant_connected"):
        flash("Please connect to the target tenant first.", "warning")
        return redirect(url_for("main.connect_target", task_id=task_id))

    # Collect mapping from form: mapping_<old_id> = <new_id>
    mapping: dict[str, str] = {}
    for key, value in request.form.items():
        if key.startswith("mapping_") and value.strip():
            old_id = key[len("mapping_"):]
            mapping[old_id] = value.strip()

    session["principal_mapping"] = mapping

    # Get RBAC export data if available
    rbac_task_id = session.get("last_rbac_task_id", "")
    rbac_task = get_task(rbac_task_id, owner_id=_get_owner_id()) if rbac_task_id else None
    rbac_export = None
    if rbac_task and rbac_task.result:
        rbac_export = rbac_task.result.get("rbac_export", {}).get("export_data", {})

    # Start post-transfer as a background task
    target_token = session.get("target_access_token", "")
    subscription_id = session.get("last_scan_sub", "")

    pt_task_id = start_post_transfer(
        access_token=target_token,
        subscription_id=subscription_id,
        scan_data=task.result,
        rbac_export=rbac_export,
        principal_mapping=mapping,
        owner_id=_get_owner_id(),
    )

    return redirect(url_for("main.post_transfer_status", task_id=pt_task_id, scan_task_id=task_id))


# ──────────────────────────────────────────────────────────────────────
# Post-Transfer: Execution & Results
# ──────────────────────────────────────────────────────────────────────

@main_bp.route("/post-transfer/<task_id>")
@login_required
def post_transfer_status(task_id: str):
    """Show post-transfer execution progress / results."""
    task = get_task(task_id, owner_id=_get_owner_id())
    if task is None:
        return render_template("error.html", message="Task not found."), 404

    scan_task_id = request.args.get("scan_task_id", "")

    return render_template(
        "post_transfer.html",
        task=task,
        task_id=task_id,
        scan_task_id=scan_task_id,
        subscription_id=session.get("last_scan_sub", ""),
        target_user=session.get("target_tenant_user", {}),
    )


@main_bp.route("/api/post-transfer/<task_id>")
@login_required
@limiter.limit("60 per minute")
def api_post_transfer_status(task_id: str):
    """Return post-transfer task status as JSON (for polling)."""
    task = get_task(task_id, owner_id=_get_owner_id())
    if task is None:
        return jsonify({"error": "not found"}), 404

    payload: dict = {
        "task_id": task.task_id,
        "status": task.status.value,
        "task_type": task.task_type,
    }
    if task.result:
        payload["result"] = task.result
    if task.error:
        payload["error"] = task.error

    return jsonify(payload)


# ──────────────────────────────────────────────────────────────────────
# Pre-Transfer Automation
# ──────────────────────────────────────────────────────────────────────

@main_bp.route("/pre-transfer", methods=["POST"])
@login_required
@limiter.limit("5 per minute")
def pre_transfer():
    """Start pre-transfer exports for a completed scan."""
    scan_task_id = request.form.get("scan_task_id", "").strip()
    if not scan_task_id:
        return jsonify({"error": "scan_task_id is required"}), 400

    scan_task = get_task(scan_task_id, owner_id=_get_owner_id())
    if scan_task is None or scan_task.result is None:
        return render_template("error.html", message="No completed scan found."), 404

    token = get_access_token()
    subscription_id = session.get("last_scan_sub", "")
    task_id = start_pre_transfer(
        token, subscription_id, scan_task.result, owner_id=_get_owner_id(),
    )
    session["last_pre_transfer_task"] = task_id
    return redirect(url_for("main.pre_transfer_status", task_id=task_id, scan_task_id=scan_task_id))


@main_bp.route("/pre-transfer/<task_id>")
@login_required
def pre_transfer_status(task_id: str):
    """Show pre-transfer export progress / results."""
    task = get_task(task_id, owner_id=_get_owner_id())
    if task is None:
        return render_template("error.html", message="Task not found."), 404

    scan_task_id = request.args.get("scan_task_id", "")
    return render_template(
        "pre_transfer.html",
        task=task,
        task_id=task_id,
        scan_task_id=scan_task_id,
        subscription_id=session.get("last_scan_sub", ""),
    )


@main_bp.route("/api/pre-transfer/<task_id>")
@login_required
@limiter.limit("60 per minute")
def api_pre_transfer_status(task_id: str):
    """Return pre-transfer task status as JSON (for polling)."""
    task = get_task(task_id, owner_id=_get_owner_id())
    if task is None:
        return jsonify({"error": "not found"}), 404

    payload: dict = {
        "task_id": task.task_id,
        "status": task.status.value,
        "task_type": task.task_type,
    }
    if task.result:
        payload["steps"] = task.result.get("steps", [])
        payload["summary"] = task.result.get("summary", {})
        payload["overall_status"] = task.result.get("overall_status", "")
    if task.error:
        payload["error"] = task.error

    return jsonify(payload)


# ──────────────────────────────────────────────────────────────────────
# Migration Bundle (Download)
# ──────────────────────────────────────────────────────────────────────

@main_bp.route("/bundle/download/<task_id>")
@login_required
def download_bundle(task_id: str):
    """Download the migration bundle zip from a completed pre-transfer task."""
    task = get_task(task_id, owner_id=_get_owner_id())
    if task is None or task.result is None:
        return render_template("error.html", message="Pre-transfer not complete."), 404

    artifacts = task.result.get("artifacts", {})
    if not artifacts:
        return render_template("error.html", message="No artifacts found."), 404

    from tenova.bundle import create_bundle

    subscription_id = session.get("last_scan_sub", "")
    source_tenant_id = session.get("tenant_id", "")

    bundle_bytes = create_bundle(
        subscription_id=subscription_id,
        source_tenant_id=source_tenant_id,
        artifacts=artifacts,
    )

    response = make_response(bundle_bytes)
    response.headers["Content-Type"] = "application/zip"
    sub_short = subscription_id[:8] if subscription_id else "unknown"
    response.headers["Content-Disposition"] = (
        f"attachment; filename=tenova_bundle_{sub_short}.zip"
    )
    return response


# ──────────────────────────────────────────────────────────────────────
# Migration Bundle (Upload) — for post-transfer restoration
# ──────────────────────────────────────────────────────────────────────

@main_bp.route("/bundle/upload", methods=["GET"])
@login_required
def upload_bundle_page():
    """Show the bundle upload page."""
    return render_template("upload_bundle.html")


@main_bp.route("/bundle/upload", methods=["POST"])
@login_required
@limiter.limit("5 per minute")
def upload_bundle():
    """Process an uploaded migration bundle and show the workflow."""
    if "bundle" not in request.files:
        flash("No file uploaded.", "danger")
        return redirect(url_for("main.upload_bundle_page"))

    uploaded = request.files["bundle"]
    if not uploaded.filename or not uploaded.filename.endswith(".zip"):
        flash("Please upload a .zip migration bundle.", "danger")
        return redirect(url_for("main.upload_bundle_page"))

    from tenova.bundle import BundleError, read_bundle

    try:
        data = uploaded.read()
        bundle = read_bundle(data)
    except BundleError as exc:
        flash(f"Invalid bundle: {exc}", "danger")
        return redirect(url_for("main.upload_bundle_page"))

    # Store bundle data in session for the workflow
    manifest = bundle.get("manifest", {})
    session["bundle_manifest"] = manifest
    session["bundle_artifacts"] = bundle.get("artifacts", {})
    session["last_scan_sub"] = manifest.get("subscription_id", "")

    flash(
        f"Bundle loaded: {len(bundle.get('artifacts', {}))} artifacts "
        f"for subscription {manifest.get('subscription_id', 'unknown')[:8]}…",
        "success",
    )
    return redirect(url_for("main.workflow"))


# ──────────────────────────────────────────────────────────────────────
# Migration Workflow — end-to-end orchestration page
# ──────────────────────────────────────────────────────────────────────

@main_bp.route("/workflow")
@login_required
def workflow():
    """Show the migration workflow dashboard."""
    subscription_id = session.get("last_scan_sub", "")
    bundle_manifest = session.get("bundle_manifest")
    has_bundle = bundle_manifest is not None

    return render_template(
        "workflow.html",
        subscription_id=subscription_id,
        has_bundle=has_bundle,
        bundle_manifest=bundle_manifest,
        source_tenant_id=session.get("tenant_id", ""),
    )
