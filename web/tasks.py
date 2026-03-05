"""Background task runner for long-running scan operations.

Uses threading so the Flask request returns immediately while the scan
runs in the background.  Results are stored in a simple in-memory dict
keyed by a task ID.
"""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from azure.core.credentials import AccessToken, TokenCredential

from tenova.scanner import scan_subscription, list_subscriptions
from tenova.readiness import check_readiness
from tenova.rbac import export_rbac
from tenova.logger import get_logger

logger = get_logger("tasks")


class TaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class TaskResult:
    task_id: str
    task_type: str = "scan"
    status: TaskStatus = TaskStatus.PENDING
    started_at: datetime | None = None
    completed_at: datetime | None = None
    result: dict[str, Any] | None = None
    error: str | None = None


# In-memory task store (sufficient for single-instance App Service)
_tasks: dict[str, TaskResult] = {}


class _StaticTokenCredential(TokenCredential):
    """Wrap a raw access-token string into a TokenCredential interface."""

    def __init__(self, token: str) -> None:
        self._token = token

    def get_token(self, *scopes: str, **kwargs: Any) -> AccessToken:
        return AccessToken(self._token, 0)


def _credential_from_token(access_token: str) -> TokenCredential:
    """Create a TokenCredential from the session's access token."""
    return _StaticTokenCredential(access_token)


# ──────────────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────────────

def start_scan(access_token: str, subscription_id: str) -> str:
    """Launch a background scan and return a task ID."""
    task_id = str(uuid.uuid4())[:8]
    task = TaskResult(task_id=task_id, task_type="scan")
    _tasks[task_id] = task

    thread = threading.Thread(
        target=_run_scan,
        args=(task, access_token, subscription_id),
        daemon=True,
    )
    thread.start()
    logger.info("Scan task %s started for subscription %s", task_id, subscription_id)
    return task_id


def start_readiness_check(access_token: str, subscription_id: str) -> str:
    """Launch a background readiness check and return a task ID."""
    task_id = str(uuid.uuid4())[:8]
    task = TaskResult(task_id=task_id, task_type="readiness")
    _tasks[task_id] = task

    thread = threading.Thread(
        target=_run_readiness,
        args=(task, access_token, subscription_id),
        daemon=True,
    )
    thread.start()
    logger.info("Readiness task %s started for subscription %s", task_id, subscription_id)
    return task_id


def start_rbac_export(access_token: str, subscription_id: str) -> str:
    """Launch a background RBAC export and return a task ID."""
    task_id = str(uuid.uuid4())[:8]
    task = TaskResult(task_id=task_id, task_type="rbac_export")
    _tasks[task_id] = task

    thread = threading.Thread(
        target=_run_rbac_export,
        args=(task, access_token, subscription_id),
        daemon=True,
    )
    thread.start()
    logger.info("RBAC export task %s started for subscription %s", task_id, subscription_id)
    return task_id


def get_task(task_id: str) -> TaskResult | None:
    """Retrieve a task result by ID."""
    return _tasks.get(task_id)


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
        task.error = str(exc)
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
        task.error = str(exc)
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
        task.error = str(exc)
        task.status = TaskStatus.FAILED
        logger.exception("RBAC export task %s failed", task.task_id)
    finally:
        task.completed_at = datetime.now(timezone.utc)
