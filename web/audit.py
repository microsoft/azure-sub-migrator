# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""Structured audit trail for destructive operations.

Every state-changing action (post-transfer, principal mapping save,
bundle upload, pre-transfer) is logged as a JSON record to a dedicated
``azure_sub_migrator.audit`` logger.  In production the handler should be pointed at
a persistent sink (Azure Monitor, file, etc.); the module configures a
``StreamHandler`` by default so records are always visible in stdout.

Each record contains:
- ``timestamp`` — ISO-8601 UTC
- ``user_oid`` — Entra object ID of the acting user
- ``user_name`` — display name (best-effort)
- ``action`` — machine-readable action tag
- ``detail`` — human-readable description
- ``subscription_id`` — target subscription (when applicable)
- ``ip`` — client IP
- ``task_id`` — background task launched (when applicable)
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from flask import request, session

_audit_logger = logging.getLogger("azure_sub_migrator.audit")

# Ensure at least one handler exists so records are never silently dropped.
if not _audit_logger.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(logging.Formatter("%(message)s"))
    _audit_logger.addHandler(_handler)
_audit_logger.setLevel(logging.INFO)


def audit_log(
    action: str,
    detail: str,
    *,
    subscription_id: str = "",
    task_id: str = "",
    extra: dict[str, Any] | None = None,
) -> None:
    """Emit a structured audit record.

    Parameters
    ----------
    action:
        Machine-readable tag, e.g. ``"post_transfer.start"``
    detail:
        Human-readable description of what was done.
    subscription_id:
        Azure subscription targeted by the operation.
    task_id:
        Background task ID if one was launched.
    extra:
        Arbitrary key/value pairs to include in the record.
    """
    user = session.get("user", {}) if _has_request_context() else {}

    record: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "user_oid": user.get("oid", ""),
        "user_name": user.get("name", ""),
        "action": action,
        "detail": detail,
        "subscription_id": subscription_id,
        "ip": _client_ip(),
        "task_id": task_id,
    }
    if extra:
        record["extra"] = extra

    safe_json = json.dumps(record, default=str).replace('\r\n', '').replace('\n', '')
    _audit_logger.info(safe_json)


def _client_ip() -> str:
    """Best-effort client IP (respects X-Forwarded-For behind proxy)."""
    try:
        return request.headers.get("X-Forwarded-For", request.remote_addr or "")
    except RuntimeError:
        return ""


def _has_request_context() -> bool:
    """Check if we're inside a Flask request context."""
    try:
        _ = request.method  # noqa: F841
        return True
    except RuntimeError:
        return False
