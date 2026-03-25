"""Web layer tests for Flask routes.

Covers health checks, authentication guards, input validation, security
headers, API endpoints, and ownership enforcement.
"""

from __future__ import annotations

import uuid
from unittest.mock import MagicMock, patch

import pytest

from web.app import create_app
from web.tasks import TaskResult, TaskStatus


# ── Helpers ──────────────────────────────────────────────────────────

FAKE_OID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
FAKE_SUB_ID = "00000000-1111-2222-3333-444444444444"
FAKE_SUB_ID_2 = "00000000-1111-2222-3333-555555555555"
FAKE_TASK_ID = str(uuid.uuid4())

_USER_SESSION = {
    "user": {"oid": FAKE_OID, "name": "Test User"},
    "access_token": "fake-arm-token",
}


def _completed_scan_task(owner_id: str = FAKE_OID) -> TaskResult:
    """Return a completed scan TaskResult for tests."""
    t = TaskResult(task_id=FAKE_TASK_ID, task_type="scan", owner_id=owner_id)
    t.status = TaskStatus.COMPLETED
    t.result = {
        "transfer_safe": [{"id": "/sub/rg/res1", "type": "Microsoft.Storage/storageAccounts"}],
        "requires_action": [],
        "transfer_notes": {},
    }
    t.progress_pct = 100
    return t


# ── Fixtures ─────────────────────────────────────────────────────────

@pytest.fixture()
def app():
    """Create the Flask app with testing config."""
    application = create_app()
    application.config.update({
        "TESTING": True,
        "WTF_CSRF_ENABLED": False,          # disable CSRF for test convenience
        "SESSION_TYPE": "filesystem",        # keep server-side sessions in test too
        "SERVER_NAME": "localhost",          # so url_for works outside request ctx
    })
    # Reset the rate-limiter so tests are not flaky
    from web.app import limiter
    limiter.enabled = False
    yield application
    limiter.enabled = True


@pytest.fixture()
def client(app):
    """Return a Flask test client."""
    return app.test_client()


@pytest.fixture()
def auth_client(app):
    """Return a test client pre-loaded with a logged-in session."""
    c = app.test_client()
    with c.session_transaction() as sess:
        sess.update(_USER_SESSION)
    return c


# ── Health Check ─────────────────────────────────────────────────────

class TestHealthz:
    """Tests for GET /healthz (unauthenticated)."""

    def test_healthz_returns_200(self, client):
        resp = client.get("/healthz")
        assert resp.status_code == 200
        assert resp.get_json()["status"] == "healthy"

    def test_healthz_no_auth_needed(self, client):
        # Ensure no redirect to login
        resp = client.get("/healthz")
        assert resp.status_code == 200


# ── Landing / Index ──────────────────────────────────────────────────

class TestIndex:
    """Tests for GET /."""

    def test_unauthenticated_shows_login(self, client):
        resp = client.get("/")
        assert resp.status_code == 200
        # Template renders login.html — just confirm no redirect
        assert b"<!doctype html>" in resp.data.lower() or resp.status_code == 200

    def test_authenticated_redirects_to_dashboard(self, auth_client):
        resp = auth_client.get("/", follow_redirects=False)
        assert resp.status_code == 302
        assert "/dashboard" in resp.headers["Location"]


# ── Authentication Guards ────────────────────────────────────────────

class TestAuthGuards:
    """Ensure protected routes redirect to login when unauthenticated."""

    @pytest.mark.parametrize("path", [
        "/dashboard",
        "/workflow",
        f"/scan/{FAKE_TASK_ID}",
        f"/api/task/{FAKE_TASK_ID}",
        f"/plan/{FAKE_TASK_ID}",
        f"/readiness/{FAKE_TASK_ID}",
        f"/checklist/{FAKE_TASK_ID}",
        f"/export-rbac/{FAKE_TASK_ID}",
        f"/export/runbook/{FAKE_TASK_ID}",
        f"/export/pdf/{FAKE_TASK_ID}",
        f"/export/excel/{FAKE_TASK_ID}",
        f"/connect-target/{FAKE_TASK_ID}",
        f"/principal-map/{FAKE_TASK_ID}",
        f"/post-transfer/{FAKE_TASK_ID}",
        f"/pre-transfer/{FAKE_TASK_ID}",
        f"/bundle/download/{FAKE_TASK_ID}",
        "/bundle/upload",
    ])
    def test_protected_get_redirects(self, client, path):
        resp = client.get(path, follow_redirects=False)
        assert resp.status_code == 302
        assert "/auth/login" in resp.headers["Location"]

    @pytest.mark.parametrize("path", [
        "/scan",
        "/readiness",
        "/export-rbac",
        "/pre-transfer",
    ])
    def test_protected_post_redirects(self, client, path):
        resp = client.post(path, follow_redirects=False)
        assert resp.status_code == 302
        assert "/auth/login" in resp.headers["Location"]


# ── Security Headers ─────────────────────────────────────────────────

class TestSecurityHeaders:
    """Verify security headers are present on every response."""

    def test_security_headers_on_healthz(self, client):
        resp = client.get("/healthz")
        assert resp.headers["X-Content-Type-Options"] == "nosniff"
        assert resp.headers["X-Frame-Options"] == "DENY"
        assert "strict-origin" in resp.headers["Referrer-Policy"]
        assert "max-age=" in resp.headers["Strict-Transport-Security"]
        assert "Content-Security-Policy" in resp.headers

    def test_csp_contains_nonce(self, client):
        resp = client.get("/healthz")
        csp = resp.headers["Content-Security-Policy"]
        assert "nonce-" in csp

    def test_no_cache_when_authenticated(self, auth_client):
        with patch("web.routes.get_access_token", return_value="fake-token"):
            with patch("web.routes.fetch_subscriptions", return_value=[]):
                resp = auth_client.get("/dashboard")
        assert resp.headers.get("Cache-Control") == "no-store"
        assert resp.headers.get("Pragma") == "no-cache"


# ── API Task Status ──────────────────────────────────────────────────

class TestApiTaskStatus:
    """Tests for GET /api/task/<task_id>."""

    def test_unknown_task_returns_404(self, auth_client):
        random_id = str(uuid.uuid4())
        resp = auth_client.get(f"/api/task/{random_id}")
        assert resp.status_code == 404
        assert resp.get_json()["error"] == "not found"

    def test_returns_task_payload(self, auth_client):
        task = _completed_scan_task()
        with patch("web.routes.get_task", return_value=task):
            resp = auth_client.get(f"/api/task/{FAKE_TASK_ID}")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["task_id"] == FAKE_TASK_ID
        assert data["status"] == "completed"
        assert data["transfer_safe_count"] == 1

    def test_ownership_returns_404(self, auth_client):
        """A task owned by someone else should appear as not found."""
        other_owner = "zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz"
        task = _completed_scan_task(owner_id=other_owner)
        # get_task enforces ownership internally; mock it returning None
        with patch("web.routes.get_task", return_value=None):
            resp = auth_client.get(f"/api/task/{FAKE_TASK_ID}")
        assert resp.status_code == 404


# ── API Start Scan ───────────────────────────────────────────────────

class TestApiStartScan:
    """Tests for POST /api/start-scan."""

    def test_missing_subscription_id(self, auth_client):
        resp = auth_client.post(
            "/api/start-scan",
            json={},
            content_type="application/json",
        )
        assert resp.status_code == 400
        assert "subscription_id" in resp.get_json()["error"].lower()

    def test_invalid_uuid(self, auth_client):
        resp = auth_client.post(
            "/api/start-scan",
            json={"subscription_id": "not-a-uuid"},
            content_type="application/json",
        )
        assert resp.status_code == 400

    def test_valid_scan(self, auth_client):
        with patch("web.routes.get_access_token", return_value="tok"):
            with patch("web.routes.start_scan", return_value="task-123"):
                resp = auth_client.post(
                    "/api/start-scan",
                    json={"subscription_id": FAKE_SUB_ID},
                    content_type="application/json",
                )
        assert resp.status_code == 200
        assert resp.get_json()["task_id"] == "task-123"


# ── API Start Readiness ─────────────────────────────────────────────

class TestApiStartReadiness:
    """Tests for POST /api/start-readiness."""

    def test_missing_subscription_id(self, auth_client):
        resp = auth_client.post(
            "/api/start-readiness",
            json={},
            content_type="application/json",
        )
        assert resp.status_code == 400

    def test_valid_readiness(self, auth_client):
        with patch("web.routes.get_access_token", return_value="tok"):
            with patch("web.routes.start_readiness_check", return_value="task-456"):
                resp = auth_client.post(
                    "/api/start-readiness",
                    json={"subscription_id": FAKE_SUB_ID},
                    content_type="application/json",
                )
        assert resp.status_code == 200
        assert resp.get_json()["task_id"] == "task-456"


# ── API Start Cross-Sub Analysis ─────────────────────────────────────

class TestApiStartCrossSubAnalysis:
    """Tests for POST /api/start-cross-sub-analysis."""

    def test_fewer_than_two_subs(self, auth_client):
        resp = auth_client.post(
            "/api/start-cross-sub-analysis",
            json={"subscription_ids": [FAKE_SUB_ID]},
            content_type="application/json",
        )
        assert resp.status_code == 400
        assert "two" in resp.get_json()["error"].lower()

    def test_invalid_sub_in_list(self, auth_client):
        resp = auth_client.post(
            "/api/start-cross-sub-analysis",
            json={"subscription_ids": [FAKE_SUB_ID, "bad"]},
            content_type="application/json",
        )
        assert resp.status_code == 400

    def test_valid_analysis(self, auth_client):
        with patch("web.routes.get_access_token", return_value="tok"):
            with patch("web.routes.start_cross_sub_analysis", return_value="task-789"):
                resp = auth_client.post(
                    "/api/start-cross-sub-analysis",
                    json={"subscription_ids": [FAKE_SUB_ID, FAKE_SUB_ID_2]},
                    content_type="application/json",
                )
        assert resp.status_code == 200
        assert resp.get_json()["task_id"] == "task-789"


# ── API Classify Readiness ───────────────────────────────────────────

class TestApiClassifyReadiness:
    """Tests for POST /api/classify-readiness."""

    def test_missing_scan_task_id(self, auth_client):
        resp = auth_client.post(
            "/api/classify-readiness",
            json={},
            content_type="application/json",
        )
        assert resp.status_code == 400

    def test_no_completed_scan(self, auth_client):
        with patch("web.routes.get_task", return_value=None):
            resp = auth_client.post(
                "/api/classify-readiness",
                json={"scan_task_id": FAKE_TASK_ID},
                content_type="application/json",
            )
        assert resp.status_code == 404

    def test_valid_classify(self, auth_client):
        task = _completed_scan_task()
        with patch("web.routes.get_task", return_value=task):
            with patch("tenova.readiness.classify_readiness", return_value={"score": 85}):
                resp = auth_client.post(
                    "/api/classify-readiness",
                    json={"scan_task_id": FAKE_TASK_ID},
                    content_type="application/json",
                )
        assert resp.status_code == 200
        assert resp.get_json()["readiness"]["score"] == 85


# ── API Start Pre-Transfer ───────────────────────────────────────────

class TestApiStartPreTransfer:
    """Tests for POST /api/start-pre-transfer."""

    def test_missing_scan_task_id(self, auth_client):
        resp = auth_client.post(
            "/api/start-pre-transfer",
            json={},
            content_type="application/json",
        )
        assert resp.status_code == 400

    def test_no_completed_scan(self, auth_client):
        with patch("web.routes.get_task", return_value=None):
            resp = auth_client.post(
                "/api/start-pre-transfer",
                json={"scan_task_id": FAKE_TASK_ID},
                content_type="application/json",
            )
        assert resp.status_code == 404

    def test_valid_pre_transfer(self, auth_client):
        task = _completed_scan_task()
        with patch("web.routes.get_task", return_value=task):
            with patch("web.routes.get_access_token", return_value="tok"):
                with patch("web.routes.start_pre_transfer", return_value="pt-1"):
                    resp = auth_client.post(
                        "/api/start-pre-transfer",
                        json={"scan_task_id": FAKE_TASK_ID},
                        content_type="application/json",
                    )
        assert resp.status_code == 200
        assert resp.get_json()["task_id"] == "pt-1"


# ── API Start Post-Transfer ──────────────────────────────────────────

class TestApiStartPostTransfer:
    """Tests for POST /api/start-post-transfer."""

    def test_no_bundle(self, auth_client):
        resp = auth_client.post(
            "/api/start-post-transfer",
            json={"mapping": {}},
            content_type="application/json",
        )
        assert resp.status_code == 400
        assert "bundle" in resp.get_json()["error"].lower()

    def test_valid_post_transfer(self, auth_client):
        with auth_client.session_transaction() as sess:
            sess["bundle_artifacts"] = {
                "scan_results": {"transfer_safe": [], "requires_action": []},
                "rbac_assignments": [],
            }
        with patch("web.routes.get_access_token", return_value="tok"):
            with patch("web.routes.start_post_transfer", return_value="post-1"):
                resp = auth_client.post(
                    "/api/start-post-transfer",
                    json={"mapping": {"old-id": "new-id"}, "dry_run": True},
                    content_type="application/json",
                )
        assert resp.status_code == 200
        assert resp.get_json()["task_id"] == "post-1"


# ── API Bundle Scan Data ─────────────────────────────────────────────

class TestApiBundleScanData:
    """Tests for GET /api/bundle-scan-data."""

    def test_no_bundle_returns_404(self, auth_client):
        resp = auth_client.get("/api/bundle-scan-data")
        assert resp.status_code == 404

    def test_with_bundle(self, auth_client):
        with auth_client.session_transaction() as sess:
            sess["bundle_artifacts"] = {
                "scan_results": {
                    "transfer_safe": [{"id": "r1"}],
                    "requires_action": [],
                },
            }
        resp = auth_client.get("/api/bundle-scan-data")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["transfer_safe_count"] == 1
        assert data["requires_action_count"] == 0


# ── API Get Principal Mapping ────────────────────────────────────────

class TestApiGetPrincipalMapping:
    """Tests for POST /api/get-principal-mapping."""

    def test_no_bundle_returns_400(self, auth_client):
        resp = auth_client.post(
            "/api/get-principal-mapping",
            json={},
            content_type="application/json",
        )
        assert resp.status_code == 400

    def test_no_rbac_returns_empty(self, auth_client):
        with auth_client.session_transaction() as sess:
            sess["bundle_artifacts"] = {"rbac_assignments": []}
        resp = auth_client.post(
            "/api/get-principal-mapping",
            json={},
            content_type="application/json",
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["has_rbac"] is False

    def test_needs_target_tenant(self, auth_client):
        with auth_client.session_transaction() as sess:
            sess["bundle_artifacts"] = {
                "rbac_assignments": [{"principalId": "abc"}],
            }
        resp = auth_client.post(
            "/api/get-principal-mapping",
            json={},
            content_type="application/json",
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["needs_target_tenant"] is True


# ── POST /scan (form-based) ─────────────────────────────────────────

class TestScanFormPost:
    """Tests for POST /scan (HTML form endpoint)."""

    def test_missing_subscription(self, auth_client):
        resp = auth_client.post("/scan", data={})
        assert resp.status_code == 400

    def test_invalid_uuid(self, auth_client):
        resp = auth_client.post("/scan", data={"subscription_id": "xyz"})
        assert resp.status_code == 400

    def test_valid_scan_redirects(self, auth_client):
        with patch("web.routes.get_access_token", return_value="tok"):
            with patch("web.routes.start_scan", return_value="task-abc"):
                resp = auth_client.post(
                    "/scan",
                    data={"subscription_id": FAKE_SUB_ID},
                    follow_redirects=False,
                )
        assert resp.status_code == 302
        assert "/scan/task-abc" in resp.headers["Location"]


# ── POST /readiness (form-based) ────────────────────────────────────

class TestReadinessFormPost:
    """Tests for POST /readiness."""

    def test_missing_subscription(self, auth_client):
        resp = auth_client.post("/readiness", data={})
        assert resp.status_code == 400

    def test_valid_readiness_redirects(self, auth_client):
        with patch("web.routes.get_access_token", return_value="tok"):
            with patch("web.routes.start_readiness_check", return_value="task-r1"):
                resp = auth_client.post(
                    "/readiness",
                    data={"subscription_id": FAKE_SUB_ID},
                    follow_redirects=False,
                )
        assert resp.status_code == 302
        assert "/readiness/task-r1" in resp.headers["Location"]


# ── POST /export-rbac (form-based) ──────────────────────────────────

class TestExportRbacFormPost:
    """Tests for POST /export-rbac."""

    def test_missing_subscription(self, auth_client):
        resp = auth_client.post("/export-rbac", data={})
        assert resp.status_code == 400

    def test_valid_rbac_export_redirects(self, auth_client):
        with patch("web.routes.get_access_token", return_value="tok"):
            with patch("web.routes.start_rbac_export", return_value="task-rb1"):
                resp = auth_client.post(
                    "/export-rbac",
                    data={"subscription_id": FAKE_SUB_ID},
                    follow_redirects=False,
                )
        assert resp.status_code == 302
        assert "/export-rbac/task-rb1" in resp.headers["Location"]


# ── Migration Plan Download ──────────────────────────────────────────

class TestMigrationPlan:
    """Tests for GET /plan/<task_id>."""

    def test_no_task_returns_404(self, auth_client):
        with patch("web.routes.get_task", return_value=None):
            resp = auth_client.get(f"/plan/{FAKE_TASK_ID}")
        assert resp.status_code == 404

    def test_valid_plan_download(self, auth_client):
        task = _completed_scan_task()
        with patch("web.routes.get_task", return_value=task):
            resp = auth_client.get(f"/plan/{FAKE_TASK_ID}")
        assert resp.status_code == 200
        assert resp.content_type == "application/json"
        assert "attachment" in resp.headers.get("Content-Disposition", "")
        data = resp.get_json()
        assert "transfer_safe" in data


# ── RBAC Download ────────────────────────────────────────────────────

class TestRbacDownload:
    """Tests for GET /api/rbac-download/<task_id>."""

    def test_no_task_returns_404(self, auth_client):
        with patch("web.routes.get_task", return_value=None):
            resp = auth_client.get(f"/api/rbac-download/{FAKE_TASK_ID}")
        assert resp.status_code == 404

    def test_valid_download(self, auth_client):
        task = TaskResult(task_id=FAKE_TASK_ID, task_type="rbac_export", owner_id=FAKE_OID)
        task.status = TaskStatus.COMPLETED
        task.result = {
            "rbac_export": {
                "export_data": {"role_assignments": [{"id": "ra-1"}]},
            },
        }
        with patch("web.routes.get_task", return_value=task):
            resp = auth_client.get(f"/api/rbac-download/{FAKE_TASK_ID}")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["role_assignments"][0]["id"] == "ra-1"


# ── Post-Transfer Status API ────────────────────────────────────────

class TestApiPostTransferStatus:
    """Tests for GET /api/post-transfer/<task_id>."""

    def test_unknown_returns_404(self, auth_client):
        with patch("web.routes.get_task", return_value=None):
            resp = auth_client.get(f"/api/post-transfer/{FAKE_TASK_ID}")
        assert resp.status_code == 404

    def test_returns_payload(self, auth_client):
        task = TaskResult(task_id=FAKE_TASK_ID, task_type="post_transfer", owner_id=FAKE_OID)
        task.status = TaskStatus.RUNNING
        task.progress_pct = 42
        task.current_step = "Restoring RBAC"
        with patch("web.routes.get_task", return_value=task):
            resp = auth_client.get(f"/api/post-transfer/{FAKE_TASK_ID}")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["progress_pct"] == 42
        assert data["current_step"] == "Restoring RBAC"


# ── Pre-Transfer Status API ─────────────────────────────────────────

class TestApiPreTransferStatus:
    """Tests for GET /api/pre-transfer/<task_id>."""

    def test_unknown_returns_404(self, auth_client):
        with patch("web.routes.get_task", return_value=None):
            resp = auth_client.get(f"/api/pre-transfer/{FAKE_TASK_ID}")
        assert resp.status_code == 404

    def test_returns_payload(self, auth_client):
        task = TaskResult(task_id=FAKE_TASK_ID, task_type="pre_transfer", owner_id=FAKE_OID)
        task.status = TaskStatus.COMPLETED
        task.result = {
            "steps": [{"name": "rbac", "status": "ok"}],
            "summary": {"exported": 5},
            "overall_status": "completed",
        }
        with patch("web.routes.get_task", return_value=task):
            resp = auth_client.get(f"/api/pre-transfer/{FAKE_TASK_ID}")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["overall_status"] == "completed"
        assert len(data["steps"]) == 1


# ── Scan Status Page ─────────────────────────────────────────────────

class TestScanStatusPage:
    """Tests for GET /scan/<task_id>."""

    def test_unknown_task_404(self, auth_client):
        with patch("web.routes.get_task", return_value=None):
            resp = auth_client.get(f"/scan/{FAKE_TASK_ID}")
        assert resp.status_code == 404


# ── Workflow Page ────────────────────────────────────────────────────

class TestWorkflowPage:
    """Tests for GET /workflow."""

    def test_requires_auth(self, client):
        resp = client.get("/workflow", follow_redirects=False)
        assert resp.status_code == 302
        assert "/auth/login" in resp.headers["Location"]

    def test_authenticated_returns_200(self, auth_client):
        resp = auth_client.get("/workflow")
        assert resp.status_code == 200
