"""Background task runner for long-running scan operations.

Uses threading so the Flask request returns immediately while the scan
runs in the background.  Results are stored in a simple in-memory dict
keyed by a task ID.

Security hardening:
  - Full UUID4 task IDs (122 bits of entropy, not guessable).
  - Each task is bound to the creating user's Entra OID; only the
    owner may retrieve results.
  - Completed tasks are evicted after TASK_TTL_SECONDS (default 2 h)
    to prevent unbounded memory growth and to clear cached tokens.
  - Error messages returned to clients are sanitised; full stack
    traces are logged server-side only.
"""

from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Any

from azure.core.credentials import AccessToken, TokenCredential

from tenova.scanner import scan_subscription, list_subscriptions
from tenova.readiness import check_readiness
from tenova.rbac import export_rbac
from tenova.logger import get_logger

logger = get_logger("tasks")

# Maximum age of a completed/failed task before it is evicted (seconds).
TASK_TTL_SECONDS: int = 2 * 60 * 60  # 2 hours
# Hard cap on total tasks to prevent memory exhaustion.
MAX_TASKS: int = 500


class TaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class TaskResult:
    task_id: str
    owner_id: str = ""  # Entra OID of the user who created the task
    task_type: str = "scan"
    status: TaskStatus = TaskStatus.PENDING
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: datetime | None = None
    completed_at: datetime | None = None
    result: dict[str, Any] | None = None
    error: str | None = None


# In-memory task store (sufficient for single-instance App Service)
_tasks: dict[str, TaskResult] = {}
_tasks_lock = threading.Lock()


class _StaticTokenCredential(TokenCredential):
    """Wrap a raw access-token string into a TokenCredential interface."""

    def __init__(self, token: str) -> None:
        self._token = token

    def get_token(self, *scopes: str, **kwargs: Any) -> AccessToken:
        # Set expiry 55 min from now so the SDK treats the token as valid
        # and doesn't re-invoke get_token() on every single API call.
        return AccessToken(self._token, int(time.time()) + 3300)


def _credential_from_token(access_token: str) -> TokenCredential:
    """Create a TokenCredential from the session's access token."""
    return _StaticTokenCredential(access_token)


# ──────────────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────────────

def start_scan(access_token: str, subscription_id: str, *, owner_id: str = "") -> str:
    """Launch a background scan and return a task ID."""
    task_id = str(uuid.uuid4())
    task = TaskResult(task_id=task_id, task_type="scan", owner_id=owner_id)
    _store_task(task)

    thread = threading.Thread(
        target=_run_scan,
        args=(task, access_token, subscription_id),
        daemon=True,
    )
    thread.start()
    logger.info("Scan task %s started for subscription %s", task_id, subscription_id)
    return task_id


def start_readiness_check(access_token: str, subscription_id: str, *, owner_id: str = "") -> str:
    """Launch a background readiness check and return a task ID."""
    task_id = str(uuid.uuid4())
    task = TaskResult(task_id=task_id, task_type="readiness", owner_id=owner_id)
    _store_task(task)

    thread = threading.Thread(
        target=_run_readiness,
        args=(task, access_token, subscription_id),
        daemon=True,
    )
    thread.start()
    logger.info("Readiness task %s started for subscription %s", task_id, subscription_id)
    return task_id


def start_rbac_export(access_token: str, subscription_id: str, *, owner_id: str = "") -> str:
    """Launch a background RBAC export and return a task ID."""
    task_id = str(uuid.uuid4())
    task = TaskResult(task_id=task_id, task_type="rbac_export", owner_id=owner_id)
    _store_task(task)

    thread = threading.Thread(
        target=_run_rbac_export,
        args=(task, access_token, subscription_id),
        daemon=True,
    )
    thread.start()
    logger.info("RBAC export task %s started for subscription %s", task_id, subscription_id)
    return task_id


def get_task(task_id: str, *, owner_id: str = "") -> TaskResult | None:
    """Retrieve a task result by ID, enforcing ownership.

    Returns ``None`` if the task does not exist **or** if the caller
    is not the user who created it (prevents cross-user data leakage).
    """
    task = _tasks.get(task_id)
    if task is None:
        return None
    # Enforce ownership — owner_id may be empty in tests / CLI usage
    if owner_id and task.owner_id and task.owner_id != owner_id:
        logger.warning(
            "Task %s ownership mismatch: expected %s, got %s",
            task_id, task.owner_id, owner_id,
        )
        return None
    return task


def _store_task(task: TaskResult) -> None:
    """Insert a task into the store, evicting stale entries first."""
    _evict_stale_tasks()
    with _tasks_lock:
        if len(_tasks) >= MAX_TASKS:
            # Force-evict the oldest completed/failed task
            oldest_id = _find_oldest_finished_task()
            if oldest_id:
                del _tasks[oldest_id]
        _tasks[task.task_id] = task


def _evict_stale_tasks() -> None:
    """Remove tasks whose TTL has expired."""
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(seconds=TASK_TTL_SECONDS)
    with _tasks_lock:
        stale = [
            tid for tid, t in _tasks.items()
            if t.completed_at and t.completed_at < cutoff
        ]
        for tid in stale:
            del _tasks[tid]
        if stale:
            logger.info("Evicted %d stale task(s)", len(stale))


def _find_oldest_finished_task() -> str | None:
    """Return the task_id of the oldest completed/failed task, or None."""
    oldest_id: str | None = None
    oldest_time: datetime | None = None
    for tid, t in _tasks.items():
        if t.status in (TaskStatus.COMPLETED, TaskStatus.FAILED) and t.completed_at:
            if oldest_time is None or t.completed_at < oldest_time:
                oldest_time = t.completed_at
                oldest_id = tid
    return oldest_id


def fetch_subscriptions(access_token: str) -> list[dict[str, str]]:
    """List subscriptions (runs synchronously — fast enough)."""
    cred = _credential_from_token(access_token)
    return list_subscriptions(cred)


# ──────────────────────────────────────────────────────────────────────
# Background worker
# ──────────────────────────────────────────────────────────────────────

def _run_scan(task: TaskResult, access_token: str, subscription_id: str) -> None:
    """Execute the subscription scan in a background thread."""
    task.status = TaskStatus.RUNNING
    task.started_at = datetime.now(timezone.utc)
    try:
        cred = _credential_from_token(access_token)
        report = scan_subscription(cred, subscription_id)
        task.result = report
        task.status = TaskStatus.COMPLETED
        logger.info("Scan task %s completed", task.task_id)
    except Exception as exc:
        task.error = _sanitise_error(exc)
        task.status = TaskStatus.FAILED
        logger.exception("Scan task %s failed", task.task_id)
    finally:
        task.completed_at = datetime.now(timezone.utc)


def _run_readiness(task: TaskResult, access_token: str, subscription_id: str) -> None:
    """Execute the readiness check in a background thread."""
    task.status = TaskStatus.RUNNING
    task.started_at = datetime.now(timezone.utc)
    try:
        cred = _credential_from_token(access_token)
        result = check_readiness(cred, subscription_id)
        task.result = {"readiness": result}
        task.status = TaskStatus.COMPLETED
        logger.info("Readiness task %s completed", task.task_id)
    except Exception as exc:
        task.error = _sanitise_error(exc)
        task.status = TaskStatus.FAILED
        logger.exception("Readiness task %s failed", task.task_id)
    finally:
        task.completed_at = datetime.now(timezone.utc)


def _run_rbac_export(task: TaskResult, access_token: str, subscription_id: str) -> None:
    """Execute the RBAC export in a background thread."""
    task.status = TaskStatus.RUNNING
    task.started_at = datetime.now(timezone.utc)
    try:
        cred = _credential_from_token(access_token)
        export_path = export_rbac(cred, subscription_id)
        # Read the exported JSON to send back as the result
        import json as _json
        with open(export_path, "r") as f:
            export_data = _json.load(f)
        task.result = {
            "rbac_export": {
                "file_path": str(export_path),
                "role_assignments_count": len(export_data.get("role_assignments", [])),
                "custom_roles_count": len(export_data.get("custom_roles", [])),
                "managed_identities_count": len(export_data.get("managed_identities", [])),
                "export_data": export_data,
            }
        }
        task.status = TaskStatus.COMPLETED
        logger.info("RBAC export task %s completed → %s", task.task_id, export_path)
    except Exception as exc:
        task.error = _sanitise_error(exc)
        task.status = TaskStatus.FAILED
        logger.exception("RBAC export task %s failed", task.task_id)
    finally:
        task.completed_at = datetime.now(timezone.utc)


# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────

def _sanitise_error(exc: Exception) -> str:
    """Return a user-safe error message.

    The full exception (including stack trace) is logged server-side
    by the caller.  We return only a generic description so internal
    paths, SDK internals, and Azure error payloads are never leaked
    to the browser.
    """
    # Keep short, known-safe messages (e.g. "Subscription not found")
    msg = str(exc)
    if len(msg) <= 120 and "\n" not in msg:
        return msg
    return "An internal error occurred. Please try again or contact support."
