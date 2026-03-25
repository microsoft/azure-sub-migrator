# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""Migration bundle — portable zip archive for cross-tenant transfer.

A migration bundle is a self-contained zip file that captures all
pre-transfer artifacts so they can be imported into the target tenant
after the subscription has moved.  The bundle never touches the server
filesystem in the web flow — it is created in-memory and streamed to
the browser.

Bundle layout::

    manifest.json               version, checksums, timestamps
    scan_results.json           baseline scan
    rbac_assignments.json       role assignments
    rbac_custom_roles.json      custom role definitions
    managed_identities.json     user/system managed identity inventory
    policy_assignments.json     Azure Policy assignments
    policy_definitions.json     custom policy definitions
    resource_locks.json         management locks
    keyvault_policies.json      per-vault access policy snapshots
    principal_mapping.json      old→new principal mapping (may be empty)
"""

from __future__ import annotations

import hashlib
import io
import json
import zipfile
from datetime import datetime, timezone
from typing import Any

from azure_sub_migrator.logger import get_logger

logger = get_logger("bundle")

# Current bundle format version — increment on breaking changes.
BUNDLE_VERSION = 1

# Files that MUST be present for the bundle to be valid.
REQUIRED_FILES = frozenset({"manifest.json", "scan_results.json"})

# All artifact filenames the bundle may contain.
ARTIFACT_FILES = frozenset({
    "scan_results.json",
    "rbac_assignments.json",
    "rbac_custom_roles.json",
    "managed_identities.json",
    "policy_assignments.json",
    "policy_definitions.json",
    "resource_locks.json",
    "keyvault_policies.json",
    "principal_mapping.json",
})

# Maximum bundle size (50 MB) — defence against zip bombs.
MAX_BUNDLE_SIZE = 50 * 1024 * 1024


class BundleError(Exception):
    """Raised when bundle creation or validation fails."""


# ──────────────────────────────────────────────────────────────────────
# Create
# ──────────────────────────────────────────────────────────────────────

def create_bundle(
    subscription_id: str,
    source_tenant_id: str,
    artifacts: dict[str, Any],
) -> bytes:
    """Build a migration bundle zip in memory and return the raw bytes.

    Parameters
    ----------
    subscription_id:
        The Azure subscription being migrated.
    source_tenant_id:
        The Entra tenant the subscription is migrating FROM.
    artifacts:
        Dict mapping artifact names (e.g. ``"scan_results"``) to their
        JSON-serialisable data.  Keys should match the stem of the
        filenames in ``ARTIFACT_FILES`` (without ``.json``).

    Returns
    -------
    bytes
        The in-memory zip file contents, ready to stream to a client.
    """
    buf = io.BytesIO()
    checksums: dict[str, str] = {}
    file_list: list[str] = []

    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in artifacts.items():
            filename = f"{name}.json"
            if filename not in ARTIFACT_FILES:
                logger.warning("Skipping unknown artifact: %s", filename)
                continue
            payload = json.dumps(data, indent=2, default=str).encode("utf-8")
            checksums[filename] = hashlib.sha256(payload).hexdigest()
            file_list.append(filename)
            zf.writestr(filename, payload)

        # Manifest — always written last
        manifest = {
            "bundle_version": BUNDLE_VERSION,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "subscription_id": subscription_id,
            "source_tenant_id": source_tenant_id,
            "files": file_list,
            "checksums": checksums,
        }
        zf.writestr("manifest.json", json.dumps(manifest, indent=2))

    bundle_bytes = buf.getvalue()
    logger.info(
        "Bundle created: %d files, %d bytes",
        len(file_list), len(bundle_bytes),
    )
    return bundle_bytes


# ──────────────────────────────────────────────────────────────────────
# Read / Validate
# ──────────────────────────────────────────────────────────────────────

def read_bundle(data: bytes) -> dict[str, Any]:
    """Parse and validate a migration bundle zip.

    Parameters
    ----------
    data:
        Raw bytes of the zip file (e.g. from an upload).

    Returns
    -------
    dict
        ``{"manifest": {...}, "artifacts": {"scan_results": {...}, ...}}``

    Raises
    ------
    BundleError
        If the bundle is invalid, too large, or corrupted.
    """
    if len(data) > MAX_BUNDLE_SIZE:
        raise BundleError(
            f"Bundle exceeds maximum size ({len(data)} > {MAX_BUNDLE_SIZE} bytes)"
        )

    try:
        buf = io.BytesIO(data)
        with zipfile.ZipFile(buf, "r") as zf:
            # Security: reject path traversal attempts
            for name in zf.namelist():
                if ".." in name or name.startswith("/"):
                    raise BundleError(f"Invalid path in bundle: {name}")

            # Manifest
            if "manifest.json" not in zf.namelist():
                raise BundleError("Bundle missing manifest.json")

            manifest = json.loads(zf.read("manifest.json"))

            # Version check
            version = manifest.get("bundle_version", 0)
            if version > BUNDLE_VERSION:
                raise BundleError(
                    f"Bundle version {version} is newer than supported ({BUNDLE_VERSION})"
                )

            # Required files
            for req in REQUIRED_FILES:
                if req not in zf.namelist():
                    raise BundleError(f"Bundle missing required file: {req}")

            # Read & verify artifacts
            checksums = manifest.get("checksums", {})
            artifacts: dict[str, Any] = {}

            for filename in zf.namelist():
                if filename == "manifest.json":
                    continue
                if filename not in ARTIFACT_FILES:
                    logger.warning("Ignoring unknown file in bundle: %s", filename)
                    continue

                payload = zf.read(filename)

                # Checksum verification
                expected_hash = checksums.get(filename)
                if expected_hash:
                    actual_hash = hashlib.sha256(payload).hexdigest()
                    if actual_hash != expected_hash:
                        raise BundleError(
                            f"Checksum mismatch for {filename}: "
                            f"expected {expected_hash[:12]}…, got {actual_hash[:12]}…"
                        )

                # Parse JSON
                try:
                    artifacts[filename.removesuffix(".json")] = json.loads(payload)
                except json.JSONDecodeError as exc:
                    raise BundleError(f"Invalid JSON in {filename}: {exc}") from exc

    except zipfile.BadZipFile as exc:
        raise BundleError(f"Not a valid zip file: {exc}") from exc

    logger.info(
        "Bundle loaded: version=%d, %d artifacts, subscription=%s",
        manifest.get("bundle_version"),
        len(artifacts),
        manifest.get("subscription_id"),
    )
    return {"manifest": manifest, "artifacts": artifacts}


def get_artifact(
    bundle: dict[str, Any],
    name: str,
    default: Any = None,
) -> Any:
    """Retrieve a specific artifact from a parsed bundle.

    Parameters
    ----------
    bundle:
        The dict returned by :func:`read_bundle`.
    name:
        Artifact stem, e.g. ``"rbac_assignments"``.
    default:
        Returned if the artifact is not present.
    """
    return bundle.get("artifacts", {}).get(name, default)
