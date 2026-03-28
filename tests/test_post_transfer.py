# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""Tests for the post-transfer reconfiguration engine."""

from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

from azure_sub_migrator.post_transfer import (
    _document_managed_identity,
    _filter_by_type,
    _restore_rbac,
    _update_app_service_auth,
    _update_keyvault,
    _update_sql_admin,
    run_post_transfer,
)

# ──────────────────────────────────────────────────────────────────────
# _filter_by_type
# ──────────────────────────────────────────────────────────────────────

class TestFilterByType:
    def test_filters_matching(self):
        resources = [
            {"type": "Microsoft.KeyVault/vaults", "name": "kv1"},
            {"type": "Microsoft.Sql/servers", "name": "sql1"},
            {"type": "Microsoft.KeyVault/vaults", "name": "kv2"},
        ]
        result = _filter_by_type(resources, "Microsoft.KeyVault/vaults")
        assert len(result) == 2
        assert all(r["type"] == "Microsoft.KeyVault/vaults" for r in result)

    def test_case_insensitive(self):
        resources = [
            {"type": "microsoft.keyvault/vaults", "name": "kv1"},
        ]
        result = _filter_by_type(resources, "Microsoft.KeyVault/vaults")
        assert len(result) == 1

    def test_returns_empty(self):
        result = _filter_by_type([], "Microsoft.KeyVault/vaults")
        assert result == []


# ──────────────────────────────────────────────────────────────────────
# _restore_rbac
# ──────────────────────────────────────────────────────────────────────

class TestRestoreRbac:
    @patch("azure.mgmt.authorization.AuthorizationManagementClient")
    def test_creates_assignments(self, mock_client_cls, mock_credential):
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client

        rbac_export = {
            "custom_roles": [],
            "role_assignments": [
                {
                    "principal_id": "old-p1",
                    "role_definition_id": "/subscriptions/s/providers/Microsoft.Authorization/roleDefinitions/rd1",
                    "scope": "/subscriptions/s",
                },
            ],
        }
        mapping = {"old-p1": "new-p1"}

        result = _restore_rbac(mock_credential, "sub-1", rbac_export, mapping)

        assert result["status"] == "succeeded"
        assert mock_client.role_assignments.create.called

    @patch("azure.mgmt.authorization.AuthorizationManagementClient")
    def test_skips_unmapped_principals(self, mock_client_cls, mock_credential):
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client

        rbac_export = {
            "custom_roles": [],
            "role_assignments": [
                {
                    "principal_id": "old-unmapped",
                    "role_definition_id": "/rd1",
                    "scope": "/subscriptions/s",
                },
            ],
        }
        mapping = {}  # no mapping for old-unmapped

        result = _restore_rbac(mock_credential, "sub-1", rbac_export, mapping)
        assert result["status"] == "succeeded"


# ──────────────────────────────────────────────────────────────────────
# _update_keyvault
# ──────────────────────────────────────────────────────────────────────

class TestUpdateKeyvault:
    @patch("azure.mgmt.keyvault.KeyVaultManagementClient")
    def test_updates_policies(self, mock_client_cls, mock_credential):
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client

        kv_resource = {
            "name": "myvault",
            "resource_group": "rg-test",
            "type": "Microsoft.KeyVault/vaults",
        }
        mapping = {"old-p1": "new-p1"}

        result = _update_keyvault(mock_credential, "sub-1", kv_resource, mapping)

        # Should at least attempt to get vault info
        assert result["operation"] == "Key Vault: myvault"


# ──────────────────────────────────────────────────────────────────────
# _update_sql_admin
# ──────────────────────────────────────────────────────────────────────

class TestUpdateSqlAdmin:
    def test_updates_admin(self, mock_credential):
        mock_sql_module = MagicMock()
        mock_client = MagicMock()
        mock_sql_module.SqlManagementClient.return_value = mock_client

        sql_resource = {
            "name": "myserver",
            "resource_group": "rg-test",
            "type": "Microsoft.Sql/servers",
        }
        mapping = {"old-admin": "new-admin"}

        with patch.dict(sys.modules, {"azure.mgmt.sql": mock_sql_module}):
            result = _update_sql_admin(mock_credential, "sub-1", sql_resource, mapping)
        assert result["operation"] == "SQL Server AD Admin: myserver"


# ──────────────────────────────────────────────────────────────────────
# _update_app_service_auth
# ──────────────────────────────────────────────────────────────────────

class TestUpdateAppServiceAuth:
    def test_documents_auth(self, mock_credential):
        mock_web_module = MagicMock()
        mock_client = MagicMock()
        mock_web_module.WebSiteManagementClient.return_value = mock_client

        app_resource = {
            "name": "mywebapp",
            "resource_group": "rg-test",
            "type": "Microsoft.Web/sites",
        }

        with patch.dict(sys.modules, {"azure.mgmt.web": mock_web_module}):
            result = _update_app_service_auth(mock_credential, "sub-1", app_resource)
        assert result["operation"] == "App Service Auth: mywebapp"


# ──────────────────────────────────────────────────────────────────────
# _document_managed_identity
# ──────────────────────────────────────────────────────────────────────

class TestDocumentManagedIdentity:
    def test_documents_identity(self, mock_credential):
        mock_msi_module = MagicMock()
        mock_client = MagicMock()
        mock_msi_module.ManagedServiceIdentityClient.return_value = mock_client

        mi_resource = {
            "name": "my-mi",
            "resource_group": "rg-test",
            "type": "Microsoft.ManagedIdentity/userAssignedIdentities",
        }

        with patch.dict(sys.modules, {"azure.mgmt.msi": mock_msi_module}):
            result = _document_managed_identity(mock_credential, "sub-1", mi_resource)
        assert result["operation"] == "Managed Identity: my-mi"


# ──────────────────────────────────────────────────────────────────────
# run_post_transfer (orchestrator)
# ──────────────────────────────────────────────────────────────────────

class TestRunPostTransfer:
    @patch("azure_sub_migrator.post_transfer._document_managed_identity")
    @patch("azure_sub_migrator.post_transfer._update_app_service_auth")
    @patch("azure_sub_migrator.post_transfer._update_sql_admin")
    @patch("azure_sub_migrator.post_transfer._update_keyvault")
    @patch("azure_sub_migrator.post_transfer._restore_rbac")
    def test_orchestrates_all_operations(
        self,
        mock_rbac,
        mock_kv,
        mock_sql,
        mock_app,
        mock_mi,
        mock_credential,
    ):
        mock_rbac.return_value = {"operation": "RBAC", "status": "succeeded"}
        mock_kv.return_value = {"operation": "KeyVault", "status": "succeeded"}
        mock_sql.return_value = {"operation": "SQL", "status": "succeeded"}
        mock_app.return_value = {"operation": "App", "status": "manual"}
        mock_mi.return_value = {"operation": "MI", "status": "succeeded"}

        scan_data = {
            "requires_action": [
                {"type": "Microsoft.KeyVault/vaults", "name": "kv1", "resource_group": "rg"},
                {"type": "Microsoft.Sql/servers", "name": "sql1", "resource_group": "rg"},
                {"type": "Microsoft.Web/sites", "name": "app1", "resource_group": "rg"},
                {"type": "Microsoft.ManagedIdentity/userAssignedIdentities", "name": "mi1", "resource_group": "rg"},
            ],
        }
        rbac_export = {"role_assignments": [], "custom_roles": []}
        mapping = {"old-1": "new-1"}

        result = run_post_transfer(
            mock_credential, "sub-1", scan_data, rbac_export, mapping,
        )

        assert result["summary"]["total"] == 5
        assert result["summary"]["succeeded"] == 4  # RBAC + KV + SQL + MI
        assert mock_rbac.called
        assert mock_kv.called
        assert mock_sql.called
        assert mock_app.called
        assert mock_mi.called

    @patch("azure_sub_migrator.post_transfer._restore_rbac")
    def test_skips_rbac_without_export(self, mock_rbac, mock_credential):
        scan_data = {"requires_action": []}
        result = run_post_transfer(
            mock_credential, "sub-1", scan_data, None, {},
        )
        mock_rbac.assert_not_called()
        assert result["summary"]["total"] == 0

    @patch("azure_sub_migrator.post_transfer._restore_rbac")
    def test_overall_status_on_no_failures(self, mock_rbac, mock_credential):
        mock_rbac.return_value = {"operation": "RBAC", "status": "succeeded"}

        scan_data = {"requires_action": []}
        rbac_export = {"role_assignments": [], "custom_roles": []}

        result = run_post_transfer(
            mock_credential, "sub-1", scan_data, rbac_export, {},
        )
        assert result["overall_status"] == "succeeded"

    @patch("azure_sub_migrator.post_transfer._restore_keyvault_from_snapshot")
    @patch("azure_sub_migrator.post_transfer._restore_resource_locks")
    @patch("azure_sub_migrator.post_transfer._restore_policy_definitions")
    @patch("azure_sub_migrator.post_transfer._restore_policy_assignments")
    def test_bundle_artifacts_triggers_operations_6_through_9(
        self,
        mock_policies,
        mock_policy_defs,
        mock_locks,
        mock_kv_snap,
        mock_credential,
    ):
        """Operations 6-9 must execute when bundle_artifacts has data."""
        mock_policies.return_value = {"operation": "PolicyAssign", "status": "succeeded"}
        mock_policy_defs.return_value = {"operation": "PolicyDef", "status": "succeeded"}
        mock_locks.return_value = {"operation": "Locks", "status": "succeeded"}
        mock_kv_snap.return_value = {"operation": "KVSnapshot", "status": "succeeded"}

        scan_data = {"requires_action": []}
        bundle = {
            "policy_assignments": [{"id": "/sub/providers/Microsoft.Authorization/pa1"}],
            "policy_definitions": [{"id": "/sub/providers/Microsoft.Authorization/pd1"}],
            "resource_locks": [{"id": "/sub/providers/Microsoft.Authorization/locks/lk1"}],
            "keyvault_policies": {"vaults": [{"name": "kv1", "access_policies": []}]},
        }

        result = run_post_transfer(
            mock_credential, "sub-1", scan_data, None, {},
            bundle_artifacts=bundle,
        )

        mock_policies.assert_called_once()
        mock_policy_defs.assert_called_once()
        mock_locks.assert_called_once()
        mock_kv_snap.assert_called_once()
        assert result["summary"]["total"] == 4
        assert result["summary"]["succeeded"] == 4

    @patch("azure_sub_migrator.post_transfer._restore_policy_assignments")
    def test_no_bundle_artifacts_skips_operations_6_through_9(
        self,
        mock_policies,
        mock_credential,
    ):
        """Operations 6-9 must be skipped when bundle_artifacts is empty."""
        scan_data = {"requires_action": []}

        result = run_post_transfer(
            mock_credential, "sub-1", scan_data, None, {},
            bundle_artifacts={},
        )

        mock_policies.assert_not_called()
        assert result["summary"]["total"] == 0
