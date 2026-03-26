# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""Background task runner for long-running scan operations.

Uses threading so the Flask request returns immediately while the scan
runs in the background.  Results are stored in an in-memory dict keyed
by a task ID, with Redis persistence for completed tasks so results
survive process restarts and are shared across deployment slots.

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

import json as _json
import os
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any

from azure.core.credentials import AccessToken, TokenCredential

from azure_sub_migrator.cross_sub import analyze_cross_sub_dependencies
from azure_sub_migrator.logger import get_logger
from azure_sub_migrator.post_transfer import run_post_transfer
from azure_sub_migrator.pre_transfer import run_pre_transfer
from azure_sub_migrator.rbac import export_rbac
from azure_sub_migrator.readiness import check_readiness
from azure_sub_migrator.scanner import list_subscriptions, scan_subscription

logger = get_logger("tasks")


def _sanitize_log(value: str) -> str:
    """Strip control characters to prevent log injection."""
    return value.replace("\n", "").replace("\r", "").replace("\t", "")

# Maximum age of a completed/failed task before it is evicted (seconds).
TASK_TTL_SECONDS: int = 2 * 60 * 60  # 2 hours
# Hard cap on total tasks to prevent memory exhaustion.
MAX_TASKS: int = 500
# Maximum time a task may run before being marked as failed (seconds).
TASK_TIMEOUT_SECONDS: int = 30 * 60  # 30 minutes


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
    # Progress tracking (updated by background workers)
    progress_pct: int = 0  # 0-100
    current_step: str = ""
    total_steps: int = 0
    steps_completed: int = 0


# Type alias for the progress callback accepted by backend functions.
# Signature: callback(step_name: str, step_number: int, total_steps: int)
ProgressCallback = Callable[[str, int, int], None]


# In-memory task store with Redis persistence.
# Running tasks are kept in memory for speed; on completion they are
# written to Redis so results survive process restarts and are shared
# across App Service deployment slots / scale-out instances.
_tasks: dict[str, TaskResult] = {}
_tasks_lock = threading.Lock()

# ── Redis persistence ────────────────────────────────────────────────

# Preferred: Entra ID passwordless auth (set REDIS_HOST).
# Fallback:  access-key URL auth (set REDIS_URL) — for local dev.
_REDIS_HOST = os.environ.get("REDIS_HOST", "")
_REDIS_PORT = int(os.environ.get("REDIS_PORT", "10000"))
_REDIS_URL = os.environ.get("REDIS_URL", "")
_REDIS_PREFIX = "azsm:task:"
_redis_client = None  # lazy-initialised


def _get_redis():
    """Return a Redis client, or *None* if Redis is unavailable.

    Connection strategy (in priority order):
    1. **REDIS_HOST** → Entra ID (``DefaultAzureCredential``) with a
       custom credential provider.  No secrets to manage.
    2. **REDIS_URL**  → traditional ``rediss://`` access-key URL.
       Kept for local development & backward compatibility.

    Resilience settings follow Azure best practices:
    - 5 s connect / command timeouts
    - exponential-backoff retry (5 attempts, 0.25 s base, 5 s cap)
    - ``health_check_interval=30`` keeps idle connections alive
    """
    global _redis_client  # noqa: PLW0603
    if _redis_client is not None:
        return _redis_client
    if not _REDIS_HOST and not _REDIS_URL:
        return None
    try:
        import redis as _redis_mod
        from redis.backoff import ExponentialBackoff
        from redis.retry import Retry

        _retry = Retry(
            ExponentialBackoff(cap=5, base=0.25), retries=5
        )
        _common_opts = dict(
            decode_responses=True,
            socket_connect_timeout=5,
            socket_timeout=5,
            retry_on_timeout=True,
            retry=_retry,
            retry_on_error=[ConnectionError, TimeoutError, OSError],
            health_check_interval=30,
        )

        if _REDIS_HOST:
            from azure.identity import DefaultAzureCredential

            _credential = DefaultAzureCredential()
            _scope = "https://redis.azure.com/.default"

            class _EntraCredProvider(_redis_mod.CredentialProvider):
                """Entra ID token provider for Azure Managed Redis.

                Azure Managed Redis expects ``AUTH <objectId> <token>``
                where *objectId* is the ``oid`` claim inside the JWT.
                """

                def get_credentials(self):
                    import base64
                    import json as _json_mod

                    token = _credential.get_token(_scope).token
                    # Decode the JWT payload (2nd segment) to extract 'oid'.
                    payload = token.split(".")[1]
                    # Add padding for base64
                    payload += "=" * (-len(payload) % 4)
                    claims = _json_mod.loads(base64.urlsafe_b64decode(payload))
                    oid = claims.get("oid", "")
                    return oid, token

            _redis_client = _redis_mod.Redis(
                host=_REDIS_HOST,
                port=_REDIS_PORT,
                ssl=True,
                credential_provider=_EntraCredProvider(),
                **_common_opts,
            )
        else:
            _redis_client = _redis_mod.from_url(
                _REDIS_URL,
                **_common_opts,
            )

        _redis_client.ping()
        logger.info("Redis persistence connected")
        return _redis_client
    except Exception:
        logger.debug("Redis unavailable — falling back to in-memory only", exc_info=True)
        return None


def _persist_task(task: TaskResult) -> None:
    """Write a completed/failed task to Redis with auto-expiry."""
    r = _get_redis()
    if r is None:
        return
    try:
        data = {
            "task_id": task.task_id,
            "owner_id": task.owner_id,
            "task_type": task.task_type,
            "status": task.status.value,
            "created_at": task.created_at.isoformat() if task.created_at else "",
            "started_at": task.started_at.isoformat() if task.started_at else "",
            "completed_at": task.completed_at.isoformat() if task.completed_at else "",
            "result": _json.dumps(task.result, default=str) if task.result else "",
            "error": task.error or "",
            "progress_pct": str(task.progress_pct),
            "current_step": task.current_step,
            "total_steps": str(task.total_steps),
            "steps_completed": str(task.steps_completed),
        }
        key = f"{_REDIS_PREFIX}{task.task_id}"
        r.hset(key, mapping=data)
        r.expire(key, TASK_TTL_SECONDS)
    except Exception:
        logger.debug("Failed to persist task %s to Redis", task.task_id, exc_info=True)


def _load_persisted_tasks() -> None:
    """Reload completed/failed tasks from Redis on startup."""
    r = _get_redis()
    if r is None:
        return
    try:
        keys = r.keys(f"{_REDIS_PREFIX}*")
        loaded = 0
        for key in keys:
            data = r.hgetall(key)
            if not data or data.get("status") not in ("completed", "failed"):
                continue
            task = TaskResult(
                task_id=data.get("task_id", ""),
                owner_id=data.get("owner_id", ""),
                task_type=data.get("task_type", "scan"),
                status=TaskStatus(data["status"]),
                created_at=(
                    datetime.fromisoformat(data["created_at"])
                    if data.get("created_at")
                    else datetime.now(timezone.utc)
                ),
                started_at=(
                    datetime.fromisoformat(data["started_at"])
                    if data.get("started_at")
                    else None
                ),
                completed_at=(
                    datetime.fromisoformat(data["completed_at"])
                    if data.get("completed_at")
                    else None
                ),
                result=(
                    _json.loads(data["result"])
                    if data.get("result")
                    else None
                ),
                error=data.get("error") or None,
                progress_pct=int(data.get("progress_pct", 0)),
                current_step=data.get("current_step", ""),
                total_steps=int(data.get("total_steps", 0)),
                steps_completed=int(data.get("steps_completed", 0)),
            )
            if task.task_id and task.task_id not in _tasks:
                _tasks[task.task_id] = task
                loaded += 1
        if loaded:
            logger.info("Loaded %d persisted task(s) from Redis", loaded)
    except Exception:
        logger.debug("Could not load persisted tasks from Redis", exc_info=True)


# Initialise on import
try:
    _load_persisted_tasks()
except Exception:
    logger.debug("Redis task persistence unavailable", exc_info=True)


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
    logger.info("Scan task %s started for subscription %s", task_id, _sanitize_log(subscription_id))
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
    logger.info("Readiness task %s started for subscription %s", task_id, _sanitize_log(subscription_id))
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
    logger.info("RBAC export task %s started for subscription %s", task_id, _sanitize_log(subscription_id))
    return task_id


def start_post_transfer(
    access_token: str,
    subscription_id: str,
    scan_data: dict[str, Any],
    rbac_export: dict[str, Any] | None,
    principal_mapping: dict[str, str],
    *,
    owner_id: str = "",
    dry_run: bool = False,
) -> str:
    """Launch post-transfer reconfiguration in the background."""
    task_id = str(uuid.uuid4())
    task = TaskResult(task_id=task_id, task_type="post_transfer", owner_id=owner_id)
    _store_task(task)

    thread = threading.Thread(
        target=_run_post_transfer,
        args=(task, access_token, subscription_id, scan_data, rbac_export, principal_mapping),
        kwargs={"dry_run": dry_run},
        daemon=True,
    )
    thread.start()
    logger.info("Post-transfer task %s started for subscription %s (dry_run=%s)", task_id, _sanitize_log(subscription_id), dry_run)
    return task_id


def start_cross_sub_analysis(
    access_token: str,
    subscription_ids: list[str],
    *,
    owner_id: str = "",
) -> str:
    """Launch a cross-subscription dependency analysis in the background."""
    task_id = str(uuid.uuid4())
    task = TaskResult(task_id=task_id, task_type="cross_sub", owner_id=owner_id)
    _store_task(task)

    thread = threading.Thread(
        target=_run_cross_sub_analysis,
        args=(task, access_token, subscription_ids),
        daemon=True,
    )
    thread.start()
    logger.info(
        "Cross-sub analysis task %s started for %d subscriptions",
        task_id, len(subscription_ids),
    )
    return task_id


def start_pre_transfer(
    access_token: str,
    subscription_id: str,
    scan_data: dict[str, Any],
    *,
    owner_id: str = "",
) -> str:
    """Launch pre-transfer export in the background."""
    task_id = str(uuid.uuid4())
    task = TaskResult(task_id=task_id, task_type="pre_transfer", owner_id=owner_id)
    _store_task(task)

    thread = threading.Thread(
        target=_run_pre_transfer,
        args=(task, access_token, subscription_id, scan_data),
        daemon=True,
    )
    thread.start()
    logger.info("Pre-transfer task %s started for subscription %s", task_id, _sanitize_log(subscription_id))
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
            task_id, _sanitize_log(task.owner_id), _sanitize_log(owner_id),
        )
        return None
    # Passive timeout check — fail tasks that have been running too long
    _check_task_timeout(task)
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
    """Remove tasks whose TTL has expired and time out hung tasks."""
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
    # Also check running tasks for timeout
    for task in list(_tasks.values()):
        _check_task_timeout(task)


def _check_task_timeout(task: TaskResult) -> None:
    """Mark a running task as failed if it has exceeded the timeout."""
    if task.status != TaskStatus.RUNNING or task.started_at is None:
        return
    elapsed = (datetime.now(timezone.utc) - task.started_at).total_seconds()
    if elapsed > TASK_TIMEOUT_SECONDS:
        task.status = TaskStatus.FAILED
        task.error = (
            f"Task timed out after {int(elapsed // 60)} minutes. "
            f"The operation may still be running in Azure — check the "
            f"Azure portal to verify resource state."
        )
        task.completed_at = datetime.now(timezone.utc)
        _persist_task(task)
        logger.warning(
            "Task %s timed out after %d seconds",
            task.task_id, int(elapsed),
        )


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


def _make_progress_callback(task: TaskResult) -> ProgressCallback:
    """Return a progress callback that writes directly to the task object.

    Because TaskResult fields are simple scalars and the GIL guarantees
    atomic writes, this is safe without a lock for the use case of a
    single writer thread + a single reader (the Flask poll endpoint).
    """
    def _cb(step_name: str, step_number: int, total_steps: int) -> None:
        task.current_step = step_name
        task.steps_completed = step_number
        task.total_steps = total_steps
        task.progress_pct = int((step_number / total_steps) * 100) if total_steps > 0 else 0
        logger.debug(
            "Task %s progress: %d/%d (%d%%) — %s",
            task.task_id, step_number, total_steps, task.progress_pct, step_name,
        )
    return _cb


# ──────────────────────────────────────────────────────────────────────
# Background worker
# ──────────────────────────────────────────────────────────────────────

def _run_scan(task: TaskResult, access_token: str, subscription_id: str) -> None:
    """Execute the subscription scan + readiness classification in a background thread."""
    task.status = TaskStatus.RUNNING
    task.started_at = datetime.now(timezone.utc)
    progress = _make_progress_callback(task)
    try:
        cred = _credential_from_token(access_token)
        report = scan_subscription(cred, subscription_id, on_progress=progress)

        # Auto-classify readiness from the scan results (no extra API calls)
        from azure_sub_migrator.readiness import classify_readiness
        progress("Classifying readiness", 6, 7)
        readiness = classify_readiness(report)
        progress("Complete", 7, 7)

        task.result = {**report, "readiness": readiness}
        task.status = TaskStatus.COMPLETED
        logger.info("Scan task %s completed (ready=%s)", task.task_id, readiness.get("ready"))
    except Exception as exc:
        task.error = _sanitise_error(exc)
        task.status = TaskStatus.FAILED
        logger.exception("Scan task %s failed", task.task_id)
    finally:
        task.completed_at = datetime.now(timezone.utc)
        _persist_task(task)


def _run_readiness(task: TaskResult, access_token: str, subscription_id: str) -> None:
    """Execute the readiness check in a background thread."""
    task.status = TaskStatus.RUNNING
    task.started_at = datetime.now(timezone.utc)
    progress = _make_progress_callback(task)
    try:
        cred = _credential_from_token(access_token)
        result = check_readiness(cred, subscription_id, on_progress=progress)
        task.result = {"readiness": result}
        task.status = TaskStatus.COMPLETED
        logger.info("Readiness task %s completed", task.task_id)
    except Exception as exc:
        task.error = _sanitise_error(exc)
        task.status = TaskStatus.FAILED
        logger.exception("Readiness task %s failed", task.task_id)
    finally:
        task.completed_at = datetime.now(timezone.utc)
        _persist_task(task)


def _run_rbac_export(task: TaskResult, access_token: str, subscription_id: str) -> None:
    """Execute the RBAC export in a background thread."""
    task.status = TaskStatus.RUNNING
    task.started_at = datetime.now(timezone.utc)
    progress = _make_progress_callback(task)
    try:
        cred = _credential_from_token(access_token)
        progress("Exporting RBAC assignments", 1, 3)
        export_path = export_rbac(cred, subscription_id)
        # Read the exported JSON to send back as the result
        import json as _json
        progress("Reading export data", 2, 3)
        with open(export_path) as f:
            export_data = _json.load(f)
        progress("Complete", 3, 3)
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
        _persist_task(task)


def _run_post_transfer(
    task: TaskResult,
    access_token: str,
    subscription_id: str,
    scan_data: dict[str, Any],
    rbac_export: dict[str, Any] | None,
    principal_mapping: dict[str, str],
    *,
    bundle_artifacts: dict[str, Any] | None = None,
    dry_run: bool = False,
) -> None:
    """Execute post-transfer reconfiguration in a background thread."""
    task.status = TaskStatus.RUNNING
    task.started_at = datetime.now(timezone.utc)
    progress = _make_progress_callback(task)
    try:
        cred = _credential_from_token(access_token)
        result = run_post_transfer(
            credential=cred,
            subscription_id=subscription_id,
            scan_data=scan_data,
            rbac_export=rbac_export,
            principal_mapping=principal_mapping,
            bundle_artifacts=bundle_artifacts or {},
            dry_run=dry_run,
            on_progress=progress,
        )
        task.result = result
        task.status = TaskStatus.COMPLETED
        logger.info("Post-transfer task %s completed", task.task_id)
    except Exception as exc:
        task.error = _sanitise_error(exc)
        task.status = TaskStatus.FAILED
        logger.exception("Post-transfer task %s failed", task.task_id)
    finally:
        task.completed_at = datetime.now(timezone.utc)
        _persist_task(task)


def _run_pre_transfer(
    task: TaskResult,
    access_token: str,
    subscription_id: str,
    scan_data: dict[str, Any],
) -> None:
    """Execute pre-transfer exports in a background thread."""
    task.status = TaskStatus.RUNNING
    task.started_at = datetime.now(timezone.utc)
    progress = _make_progress_callback(task)
    try:
        cred = _credential_from_token(access_token)
        result = run_pre_transfer(
            credential=cred,
            subscription_id=subscription_id,
            scan_data=scan_data,
            on_progress=progress,
        )
        task.result = result
        task.status = TaskStatus.COMPLETED
        logger.info("Pre-transfer task %s completed", task.task_id)
    except Exception as exc:
        task.error = _sanitise_error(exc)
        task.status = TaskStatus.FAILED
        logger.exception("Pre-transfer task %s failed", task.task_id)
    finally:
        task.completed_at = datetime.now(timezone.utc)
        _persist_task(task)


def _run_cross_sub_analysis(
    task: TaskResult,
    access_token: str,
    subscription_ids: list[str],
) -> None:
    """Execute cross-subscription dependency analysis in a background thread."""
    task.status = TaskStatus.RUNNING
    task.started_at = datetime.now(timezone.utc)
    progress = _make_progress_callback(task)
    try:
        cred = _credential_from_token(access_token)
        result = analyze_cross_sub_dependencies(
            cred, subscription_ids, on_progress=progress,
        )
        task.result = result
        task.status = TaskStatus.COMPLETED
        logger.info(
            "Cross-sub analysis task %s completed: %d dependencies found",
            task.task_id,
            len(result.get("dependencies", [])),
        )
    except Exception as exc:
        task.error = _sanitise_error(exc)
        task.status = TaskStatus.FAILED
        logger.exception("Cross-sub analysis task %s failed", task.task_id)
    finally:
        task.completed_at = datetime.now(timezone.utc)
        _persist_task(task)


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
