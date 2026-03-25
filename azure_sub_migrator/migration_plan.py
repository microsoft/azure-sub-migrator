# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""Migration plan generator.

Orchestrates scanning → classification → report writing.
"""

from __future__ import annotations

import json
from pathlib import Path

from azure.core.credentials import TokenCredential

from azure_sub_migrator.config import MigrationConfig
from azure_sub_migrator.logger import get_logger
from azure_sub_migrator.reporter import write_plan_report
from azure_sub_migrator.scanner import scan_subscription

logger = get_logger("migration_plan")


def generate_migration_plan(
    credential: TokenCredential,
    config: MigrationConfig,
) -> Path:
    """Build and persist a full migration plan.

    Steps
    -----
    1. Scan the subscription for all resources.
    2. Classify each resource as transfer-safe vs. requires-action.
    3. Write a human-readable migration-plan report.

    Returns the path to the output directory.
    """
    output_dir = config.output_path()
    subscription_id = config.subscription_id

    # 1 ── Scan
    logger.info("Step 1/3 — Scanning subscription %s", subscription_id)
    report = scan_subscription(credential, subscription_id)

    # 2 ── Classify — already done inside scan_subscription
    transfer_safe = report["transfer_safe"]
    requires_action = report["requires_action"]
    logger.info(
        "Step 2/3 — Classification: %d transfer-safe, %d requires-action",
        len(transfer_safe),
        len(requires_action),
    )

    # 3 ── Report
    logger.info("Step 3/3 — Writing migration plan report")
    plan_data = {
        "subscription_id": subscription_id,
        "source_tenant_id": config.source_tenant_id,
        "target_tenant_id": config.target_tenant_id,
        "transfer_safe_resources": transfer_safe,
        "requires_action_resources": requires_action,
    }

    # JSON dump for machine consumption
    json_path = output_dir / "migration_plan.json"
    json_path.write_text(json.dumps(plan_data, indent=2, default=str), encoding="utf-8")
    logger.info("Migration plan JSON saved to %s", json_path)

    # Markdown report for human review
    write_plan_report(plan_data, output_dir / "migration_plan.md")

    return output_dir
