"""Tests for the readiness check module."""

from __future__ import annotations

from unittest.mock import patch

from tenova.readiness import check_readiness


class TestCheckReadiness:
    """Tests for the check_readiness function."""

    @patch("tenova.readiness.list_managed_identities", return_value=[])
    @patch("tenova.readiness.list_custom_roles", return_value=[])
    @patch("tenova.readiness.list_role_assignments", return_value=[])
    @patch("tenova.readiness.scan_subscription")
    def test_ready_when_no_blockers(
        self, mock_scan, mock_assignments, mock_roles, mock_identities, mock_credential
    ):
        """Subscription with only transfer-safe resources is READY."""
        mock_scan.return_value = {
            "transfer_safe": [
                {"name": "vm1", "type": "Microsoft.Compute/virtualMachines"},
            ],
            "requires_action": [],
        }

        result = check_readiness(mock_credential, "sub-1")

        assert result["ready"] is True
        assert len(result["blockers"]) == 0
        assert isinstance(result["warnings"], list)
        assert isinstance(result["info"], list)

    @patch("tenova.readiness.list_managed_identities", return_value=[])
    @patch("tenova.readiness.list_custom_roles", return_value=[])
    @patch("tenova.readiness.list_role_assignments", return_value=[])
    @patch("tenova.readiness.scan_subscription")
    def test_not_ready_with_aks(
        self, mock_scan, mock_assignments, mock_roles, mock_identities, mock_credential
    ):
        """AKS cluster should be flagged as a hard blocker."""
        mock_scan.return_value = {
            "transfer_safe": [],
            "requires_action": [
                {
                    "name": "my-aks",
                    "type": "Microsoft.ContainerService/managedClusters",
                    "timing": "pre",
                    "pre_action": "Delete and recreate in target tenant.",
                    "post_action": "",
                },
            ],
        }

        result = check_readiness(mock_credential, "sub-1")

        assert result["ready"] is False
        assert len(result["blockers"]) == 1
        assert "my-aks" in result["blockers"][0]["name"]
        assert "Cannot be transferred" in result["blockers"][0]["issue"]

    @patch("tenova.readiness.list_managed_identities", return_value=[])
    @patch("tenova.readiness.list_custom_roles", return_value=[])
    @patch("tenova.readiness.list_role_assignments", return_value=[])
    @patch("tenova.readiness.scan_subscription")
    def test_not_ready_with_sql_entra_auth(
        self, mock_scan, mock_assignments, mock_roles, mock_identities, mock_credential
    ):
        """SQL Server with Entra auth should be flagged as a blocker."""
        mock_scan.return_value = {
            "transfer_safe": [],
            "requires_action": [
                {
                    "name": "my-sql",
                    "type": "Microsoft.Sql/servers",
                    "timing": "pre",
                    "pre_action": "Disable Entra authentication.",
                    "post_action": "",
                },
            ],
        }

        result = check_readiness(mock_credential, "sub-1")

        assert result["ready"] is False
        assert len(result["blockers"]) == 1
        assert "Entra authentication" in result["blockers"][0]["issue"]

    @patch("tenova.readiness.list_managed_identities", return_value=[])
    @patch("tenova.readiness.list_custom_roles", return_value=[])
    @patch("tenova.readiness.list_role_assignments", return_value=[])
    @patch("tenova.readiness.scan_subscription")
    def test_keyvault_is_warning_not_blocker(
        self, mock_scan, mock_assignments, mock_roles, mock_identities, mock_credential
    ):
        """Key Vault should be a warning (CMK risk), not a hard blocker."""
        mock_scan.return_value = {
            "transfer_safe": [],
            "requires_action": [
                {
                    "name": "my-kv",
                    "type": "Microsoft.KeyVault/vaults",
                    "timing": "both",
                    "pre_action": "Remove all access policies.",
                    "post_action": "Re-add access policies.",
                },
            ],
        }

        result = check_readiness(mock_credential, "sub-1")

        assert result["ready"] is True  # Warnings don't block
        assert len(result["warnings"]) == 1
        assert "Encryption" in result["warnings"][0]["issue"] or "Key Vault" in result["warnings"][0]["issue"]
        assert len(result["blockers"]) == 0

    @patch("tenova.readiness.list_managed_identities")
    @patch("tenova.readiness.list_custom_roles")
    @patch("tenova.readiness.list_role_assignments")
    @patch("tenova.readiness.scan_subscription")
    def test_info_includes_rbac_counts(
        self, mock_scan, mock_assignments, mock_roles, mock_identities, mock_credential
    ):
        """Info section should include RBAC assignment and identity counts."""
        mock_scan.return_value = {
            "transfer_safe": [{"name": "vm1", "type": "Microsoft.Compute/virtualMachines"}],
            "requires_action": [],
        }
        mock_assignments.return_value = [
            {"id": "a1", "principal_id": "p1", "role_definition_id": "rd1", "scope": "/"},
            {"id": "a2", "principal_id": "p2", "role_definition_id": "rd2", "scope": "/"},
        ]
        mock_roles.return_value = [
            {"id": "cr1", "name": "Custom Reader"},
        ]
        mock_identities.return_value = [
            {"id": "mi1", "name": "my-identity"},
        ]

        result = check_readiness(mock_credential, "sub-1")

        assert result["ready"] is True
        info_text = " ".join(item.get("detail", "") for item in result["info"])
        assert "2 role assignment" in info_text
        assert "1 custom role" in info_text
        assert "1 identity" in info_text

    @patch("tenova.readiness.list_managed_identities", return_value=[])
    @patch("tenova.readiness.list_custom_roles", return_value=[])
    @patch("tenova.readiness.list_role_assignments", return_value=[])
    @patch("tenova.readiness.scan_subscription")
    def test_mixed_blockers_and_warnings(
        self, mock_scan, mock_assignments, mock_roles, mock_identities, mock_credential
    ):
        """Multiple issue types classified correctly in a single scan."""
        mock_scan.return_value = {
            "transfer_safe": [],
            "requires_action": [
                {
                    "name": "aks1",
                    "type": "Microsoft.ContainerService/managedClusters",
                    "timing": "pre",
                    "pre_action": "Delete and recreate.",
                    "post_action": "",
                },
                {
                    "name": "kv1",
                    "type": "Microsoft.KeyVault/vaults",
                    "timing": "both",
                    "pre_action": "Remove access policies.",
                    "post_action": "Re-add access policies.",
                },
                {
                    "name": "sql1",
                    "type": "Microsoft.Sql/servers",
                    "timing": "pre",
                    "pre_action": "Disable Entra auth.",
                    "post_action": "",
                },
            ],
        }

        result = check_readiness(mock_credential, "sub-1")

        assert result["ready"] is False
        assert len(result["blockers"]) == 2  # AKS + SQL
        assert len(result["warnings"]) == 1  # Key Vault
