"""Configuration management for tenova."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

import yaml

from tenova.constants import DEFAULT_OUTPUT_DIR


@dataclass
class MigrationConfig:
    """Runtime configuration for a migration session."""

    # Source / target tenants
    source_tenant_id: str = ""
    target_tenant_id: str = ""

    # Subscription being migrated
    subscription_id: str = ""

    # Authentication
    auth_method: str = "cli"  # "cli" | "service_principal" | "managed_identity"
    client_id: str = ""
    client_secret: str = ""

    # Output
    output_dir: str = DEFAULT_OUTPUT_DIR

    # Flags
    dry_run: bool = False
    skip_transfer: bool = False

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    @classmethod
    def from_yaml(cls, path: str | Path) -> MigrationConfig:
        """Load configuration from a YAML file."""
        with open(path, encoding="utf-8") as fh:
            data: dict = yaml.safe_load(fh) or {}
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})

    @classmethod
    def from_env(cls) -> MigrationConfig:
        """Load configuration from environment variables (AZ_MIGRATE_ prefix)."""
        prefix = "AZ_MIGRATE_"
        env_map = {
            f"{prefix}SOURCE_TENANT_ID": "source_tenant_id",
            f"{prefix}TARGET_TENANT_ID": "target_tenant_id",
            f"{prefix}SUBSCRIPTION_ID": "subscription_id",
            f"{prefix}AUTH_METHOD": "auth_method",
            f"{prefix}CLIENT_ID": "client_id",
            f"{prefix}CLIENT_SECRET": "client_secret",
            f"{prefix}OUTPUT_DIR": "output_dir",
        }
        kwargs: dict = {}
        for env_var, attr in env_map.items():
            val = os.environ.get(env_var)
            if val is not None:
                kwargs[attr] = val
        return cls(**kwargs)

    def output_path(self) -> Path:
        """Return the resolved output directory, creating it if needed."""
        p = Path(self.output_dir)
        p.mkdir(parents=True, exist_ok=True)
        return p
