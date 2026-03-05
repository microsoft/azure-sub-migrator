"""IaC template generation for impacted resources.

Supports three export formats:
  - ARM JSON templates  (via Azure SDK export)
  - Bicep               (via ``az bicep decompile`` or direct SDK)
  - Terraform           (via ``aztfexport``)
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
from pathlib import Path
from typing import Any

from azure.core.credentials import TokenCredential
from azure.mgmt.resource import ResourceManagementClient

from tenova.constants import IAC_FORMAT_ARM, IAC_FORMAT_BICEP, IAC_FORMAT_TERRAFORM
from tenova.exceptions import ExternalToolError, IaCGenerationError
from tenova.logger import get_logger

logger = get_logger("iac_generator")

# Well-known install locations checked when shutil.which() misses a tool
# that was installed *after* the current process started (stale PATH).
_KNOWN_PATHS: dict[str, list[str]] = {
    "aztfexport": [
        r"C:\Program Files\aztfexport",
        r"C:\Program Files (x86)\aztfexport",
    ],
    "az": [
        r"C:\Program Files\Microsoft SDKs\Azure\CLI2\wbin",
        r"C:\Program Files (x86)\Microsoft SDKs\Azure\CLI2\wbin",
    ],
}


def _get_refreshed_path() -> str:
    """Build a PATH string that merges the current process PATH with the
    latest registry values, so newly installed tools are found without
    losing critical system paths like ``C:\\Windows\\System32``.

    Returns the merged PATH string (does NOT mutate ``os.environ``).
    """
    current = os.environ.get("PATH", "")
    if platform.system() != "Windows":
        return current

    try:
        import winreg

        machine_path = winreg.QueryValueEx(
            winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
            ),
            "Path",
        )[0]
        user_path = winreg.QueryValueEx(
            winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Environment"),
            "Path",
        )[0]

        # Merge: keep every directory that appears in either the current
        # process PATH or the registry, preserving order and deduplicating.
        seen: set[str] = set()
        merged: list[str] = []
        for entry in (current + ";" + machine_path + ";" + user_path).split(";"):
            entry = entry.strip()
            key = entry.lower()
            if key and key not in seen:
                seen.add(key)
                merged.append(entry)
        return ";".join(merged)
    except Exception:
        return current


def _resolve_tool(name: str) -> str | None:
    """Find an external tool on PATH, checking fresh registry paths and
    well-known install locations if the initial lookup fails."""
    # 1. Try the current process PATH
    cmd = shutil.which(name)
    if cmd:
        return cmd

    # 2. Try with refreshed PATH (picks up tools installed after process start)
    refreshed = _get_refreshed_path()
    cmd = shutil.which(name, path=refreshed)
    if cmd:
        return cmd

    # 3. Last resort: check well-known install directories
    for directory in _KNOWN_PATHS.get(name, []):
        for ext in ("", ".exe", ".cmd"):
            candidate = Path(directory) / f"{name}{ext}"
            if candidate.is_file():
                return str(candidate)

    return None


# ──────────────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────────────

def export_arm_template(
    credential: TokenCredential,
    subscription_id: str,
    resource_group: str,
    resource_ids: list[str],
    output_dir: Path,
) -> Path:
    """Export an ARM JSON template for the given resources.

    Uses the Azure SDK ``ResourceManagementClient.resource_groups.begin_export_template``.
    """
    logger.info("Exporting ARM template for resource group '%s'", resource_group)
    try:
        client = ResourceManagementClient(credential, subscription_id)

        export_params: dict[str, Any] = {
            "resources": resource_ids if resource_ids else ["*"],
            "options": "IncludeParameterDefaultValue,IncludeComments",
        }
        poller = client.resource_groups.begin_export_template(
            resource_group_name=resource_group,
            parameters=export_params,
        )
        result = poller.result()
        template = result.template if result.template else {}

        out_file = output_dir / f"{resource_group}_arm.json"
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_text(json.dumps(template, indent=2), encoding="utf-8")

        logger.info("ARM template saved to %s", out_file)
        return out_file

    except Exception as exc:
        raise IaCGenerationError(f"ARM export failed for '{resource_group}': {exc}") from exc


def export_bicep_template(
    arm_template_path: Path,
    output_dir: Path,
) -> Path:
    """Decompile an ARM template into Bicep using the ``az bicep`` CLI.

    Requires Azure CLI with the Bicep extension installed.
    """
    logger.info("Decompiling ARM → Bicep: %s", arm_template_path)
    out_file = output_dir / arm_template_path.with_suffix(".bicep").name

    # Resolve the az CLI executable — on Windows it is az.cmd which
    # requires shell=True or the full path for subprocess to find it.
    use_shell = platform.system() == "Windows"
    az_cmd = _resolve_tool("az")
    if az_cmd is None:
        raise ExternalToolError(
            "Azure CLI ('az') not found on PATH. Install it and the Bicep "
            "extension: https://learn.microsoft.com/cli/azure/install-azure-cli"
        )

    try:
        if use_shell:
            bicep_cmd: str | list[str] = (
                f'"{az_cmd}" bicep decompile --file "{arm_template_path}" --force'
            )
        else:
            bicep_cmd = [az_cmd, "bicep", "decompile", "--file", str(arm_template_path), "--force"]

        subprocess.run(
            bicep_cmd,
            check=True,
            capture_output=True,
            text=True,
            shell=use_shell,
        )
        # az bicep decompile writes alongside the source; move if needed
        generated = arm_template_path.with_suffix(".bicep")
        if generated.exists() and generated != out_file:
            out_file.parent.mkdir(parents=True, exist_ok=True)
            generated.rename(out_file)

        logger.info("Bicep template saved to %s", out_file)
        return out_file

    except FileNotFoundError:
        raise ExternalToolError(
            "Azure CLI ('az') not found. Install it and the Bicep extension: "
            "https://learn.microsoft.com/cli/azure/install-azure-cli"
        )
    except subprocess.CalledProcessError as exc:
        raise IaCGenerationError(f"Bicep decompile failed: {exc.stderr}") from exc


def export_terraform(
    subscription_id: str,
    resource_group: str,
    output_dir: Path,
) -> Path:
    """Export Terraform HCL using ``aztfexport``.

    Requires ``aztfexport`` to be installed and the user to be logged in
    via ``az login``.
    """
    logger.info("Running aztfexport for resource group '%s'", resource_group)
    tf_dir = output_dir / f"{resource_group}_terraform"

    aztfexport_cmd = _resolve_tool("aztfexport")
    if aztfexport_cmd is None:
        raise ExternalToolError(
            "aztfexport not found on PATH. Install it: "
            "https://github.com/Azure/aztfexport#installation"
        )

    # Merge ARM_SUBSCRIPTION_ID into the current environment and ensure
    # the PATH includes registry entries (so aztfexport can find cmd.exe,
    # az CLI, terraform, etc.).
    env = {
        **os.environ,
        "ARM_SUBSCRIPTION_ID": subscription_id,
        "PATH": _get_refreshed_path(),
    }

    # aztfexport can be very slow (minutes per resource group).
    # We set a generous 10-minute timeout per RG and pipe stdin to
    # /dev/null so it can never block on an interactive prompt.
    timeout_seconds = 600

    # Clean up any previous output so aztfexport doesn't complain about
    # a non-empty directory.
    if tf_dir.exists():
        import shutil as _shutil
        _shutil.rmtree(tf_dir, ignore_errors=True)
    tf_dir.mkdir(parents=True, exist_ok=True)

    # aztfexport checks the CWD (not just --output-dir) for emptiness,
    # so we set cwd to the clean output directory.
    tf_dir_str = str(tf_dir)

    # Build the command — flags must come BEFORE the positional resource
    # group name, and aztfexport is a native .exe so shell=True is not needed.
    cmd: list[str] = [
        aztfexport_cmd,
        "resource-group",
        "-n",
        "-f",
        "-o",
        tf_dir_str,
        resource_group,
    ]

    try:
        logger.info(
            "aztfexport running for '%s' (timeout %ds) — this may take a few minutes…",
            resource_group,
            timeout_seconds,
        )
        subprocess.run(
            cmd,
            check=True,
            capture_output=True,
            text=True,
            env=env,
            cwd=tf_dir_str,
            stdin=subprocess.DEVNULL,
            timeout=timeout_seconds,
        )
        logger.info("Terraform files saved to %s", tf_dir)
        return tf_dir

    except FileNotFoundError:
        raise ExternalToolError(
            "aztfexport not found. Install it: "
            "https://github.com/Azure/aztfexport#installation"
        )
    except subprocess.TimeoutExpired:
        raise IaCGenerationError(
            f"aztfexport timed out after {timeout_seconds}s for resource group "
            f"'{resource_group}'. The resource group may have too many resources. "
            f"Try running aztfexport manually."
        )
    except subprocess.CalledProcessError as exc:
        raise IaCGenerationError(f"aztfexport failed: {exc.stderr}") from exc


def generate_iac(
    credential: TokenCredential,
    subscription_id: str,
    resource_groups: list[str],
    resource_ids_by_rg: dict[str, list[str]],
    output_dir: Path,
    formats: list[str] | None = None,
) -> dict[str, list[Path]]:
    """High-level helper: export IaC for every resource group in the requested formats.

    Returns a dict mapping format name → list of generated file/directory paths.
    """
    formats = formats or [IAC_FORMAT_ARM, IAC_FORMAT_BICEP, IAC_FORMAT_TERRAFORM]
    results: dict[str, list[Path]] = {f: [] for f in formats}
    total = len(resource_groups)

    for idx, rg in enumerate(resource_groups, 1):
        logger.info("[%d/%d] Processing resource group '%s'…", idx, total, rg)
        ids = resource_ids_by_rg.get(rg, [])

        if IAC_FORMAT_ARM in formats:
            arm_path = export_arm_template(credential, subscription_id, rg, ids, output_dir)
            results[IAC_FORMAT_ARM].append(arm_path)

            if IAC_FORMAT_BICEP in formats:
                try:
                    bicep_path = export_bicep_template(arm_path, output_dir)
                    results[IAC_FORMAT_BICEP].append(bicep_path)
                except (ExternalToolError, IaCGenerationError) as exc:
                    logger.warning("Bicep export skipped for '%s': %s", rg, exc)

        if IAC_FORMAT_TERRAFORM in formats:
            try:
                tf_path = export_terraform(subscription_id, rg, output_dir)
                results[IAC_FORMAT_TERRAFORM].append(tf_path)
            except (ExternalToolError, IaCGenerationError) as exc:
                logger.warning("Terraform export skipped for '%s': %s", rg, exc)

    return results
