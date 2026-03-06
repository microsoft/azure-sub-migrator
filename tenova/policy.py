"""Azure Policy export for cross-tenant transfer.

Policy assignments, custom policy definitions, and policy set definitions
(initiatives) are **permanently deleted** during a cross-tenant subscription
transfer.  This module provides:

* **Export** — snapshot all policy objects to a JSON file *before* the
  transfer so they can be recreated in the target tenant.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from azure.core.credentials import TokenCredential
from azure.mgmt.resource.policy import PolicyClient

from tenova.exceptions import PolicyExportError
from tenova.logger import get_logger

logger = get_logger("policy")


def _to_serializable(obj: Any) -> Any:
    """Recursively convert Azure SDK model objects to JSON-safe primitives."""
    if obj is None:
        return None
    if isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, dict):
        return {k: _to_serializable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_to_serializable(i) for i in obj]
    # Azure SDK model — convert via as_dict() if available, else vars()
    if hasattr(obj, "as_dict"):
        return obj.as_dict()
    if hasattr(obj, "__dict__"):
        return {k: _to_serializable(v) for k, v in vars(obj).items() if not k.startswith("_")}
    return str(obj)


# ──────────────────────────────────────────────────────────────────────
# Policy Assignments
# ──────────────────────────────────────────────────────────────────────

def list_policy_assignments(
    credential: TokenCredential,
    subscription_id: str,
) -> list[dict[str, Any]]:
    """List all policy assignments in *subscription_id*."""
    try:
        client = PolicyClient(credential, subscription_id)
        assignments: list[dict[str, Any]] = []
        for pa in client.policy_assignments.list():
            assignments.append(
                {
                    "id": pa.id,
                    "name": pa.name,
                    "display_name": pa.display_name or "",
                    "description": pa.description or "",
                    "policy_definition_id": pa.policy_definition_id or "",
                    "scope": pa.scope or "",
                    "enforcement_mode": str(pa.enforcement_mode) if pa.enforcement_mode else "Default",
                    "parameters": _to_serializable(dict(pa.parameters)) if pa.parameters else {},
                    "not_scopes": list(pa.not_scopes) if pa.not_scopes else [],
                    "identity": {
                        "type": str(pa.identity.type) if pa.identity and pa.identity.type else "",
                    } if pa.identity else {},
                }
            )
        logger.info("Found %d policy assignment(s)", len(assignments))
        return assignments
    except Exception as exc:
        raise PolicyExportError(f"Failed to list policy assignments: {exc}") from exc


# ──────────────────────────────────────────────────────────────────────
# Custom Policy Definitions
# ──────────────────────────────────────────────────────────────────────

def list_custom_policy_definitions(
    credential: TokenCredential,
    subscription_id: str,
) -> list[dict[str, Any]]:
    """List all custom policy definitions in *subscription_id*."""
    try:
        client = PolicyClient(credential, subscription_id)
        definitions: list[dict[str, Any]] = []
        for pd in client.policy_definitions.list():
            # Skip built-in policies — only export custom ones
            if pd.policy_type and str(pd.policy_type).lower() == "builtin":
                continue
            definitions.append(
                {
                    "id": pd.id,
                    "name": pd.name,
                    "display_name": pd.display_name or "",
                    "description": pd.description or "",
                    "policy_type": str(pd.policy_type) if pd.policy_type else "",
                    "mode": pd.mode or "",
                    "policy_rule": _to_serializable(pd.policy_rule) if pd.policy_rule else {},
                    "parameters": _to_serializable(dict(pd.parameters)) if pd.parameters else {},
                    "metadata": _to_serializable(dict(pd.metadata)) if pd.metadata else {},
                }
            )
        logger.info("Found %d custom policy definition(s)", len(definitions))
        return definitions
    except Exception as exc:
        raise PolicyExportError(f"Failed to list custom policy definitions: {exc}") from exc


# ──────────────────────────────────────────────────────────────────────
# Policy Set Definitions (Initiatives)
# ──────────────────────────────────────────────────────────────────────

def list_custom_policy_set_definitions(
    credential: TokenCredential,
    subscription_id: str,
) -> list[dict[str, Any]]:
    """List all custom policy set definitions (initiatives) in *subscription_id*."""
    try:
        client = PolicyClient(credential, subscription_id)
        initiatives: list[dict[str, Any]] = []
        for psd in client.policy_set_definitions.list():
            # Skip built-in — only export custom initiatives
            if psd.policy_type and str(psd.policy_type).lower() == "builtin":
                continue
            initiatives.append(
                {
                    "id": psd.id,
                    "name": psd.name,
                    "display_name": psd.display_name or "",
                    "description": psd.description or "",
                    "policy_type": str(psd.policy_type) if psd.policy_type else "",
                    "policy_definitions": [
                        {
                            "policyDefinitionId": ref.policy_definition_id,
                            "parameters": _to_serializable(dict(ref.parameters)) if ref.parameters else {},
                        }
                        for ref in (psd.policy_definitions or [])
                    ],
                    "parameters": _to_serializable(dict(psd.parameters)) if psd.parameters else {},
                    "metadata": _to_serializable(dict(psd.metadata)) if psd.metadata else {},
                }
            )
        logger.info("Found %d custom policy set definition(s) (initiatives)", len(initiatives))
        return initiatives
    except Exception as exc:
        raise PolicyExportError(f"Failed to list policy set definitions: {exc}") from exc


# ──────────────────────────────────────────────────────────────────────
# Export
# ──────────────────────────────────────────────────────────────────────

def export_policies(
    credential: TokenCredential,
    subscription_id: str,
    output_dir: Path | str = "migration_output",
) -> Path:
    """Export policy assignments, custom definitions, and initiatives to JSON.

    Creates a timestamped JSON file containing everything needed to
    recreate Azure Policy configuration in the target tenant.

    Returns the path to the exported JSON file.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    logger.info("Exporting Azure Policy for subscription %s …", subscription_id)

    assignments = list_policy_assignments(credential, subscription_id)
    definitions = list_custom_policy_definitions(credential, subscription_id)
    initiatives = list_custom_policy_set_definitions(credential, subscription_id)

    export_data = {
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "subscription_id": subscription_id,
        "policy_assignments": assignments,
        "custom_policy_definitions": definitions,
        "custom_policy_set_definitions": initiatives,
        "summary": {
            "policy_assignment_count": len(assignments),
            "custom_definition_count": len(definitions),
            "initiative_count": len(initiatives),
        },
    }

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"policy_export_{subscription_id[:8]}_{timestamp}.json"
    filepath = output_dir / filename
    filepath.write_text(json.dumps(export_data, indent=2), encoding="utf-8")

    logger.info(
        "Policy export complete → %s  (%d assignments, %d custom definitions, %d initiatives)",
        filepath,
        len(assignments),
        len(definitions),
        len(initiatives),
    )
    return filepath
