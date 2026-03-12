"""Tests for the RBAC export/import module."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from tenova.rbac import (
    export_rbac,
    import_rbac,
    list_custom_roles,
    list_managed_identities,
    list_role_assignments,
)


class TestListRoleAssignments:
    @patch("tenova.rbac.AuthorizationManagementClient")
    def test_returns_assignments(self, mock_client_cls, mock_credential):
        ra = MagicMock()
        ra.id = "/subscriptions/s/providers/Microsoft.Authorization/roleAssignments/a1"
        ra.name = "a1"
        ra.principal_id = "p1"
        ra.principal_type = "User"
        ra.role_definition_id = "/subscriptions/s/providers/Microsoft.Authorization/roleDefinitions/rd1"
        ra.scope = "/subscriptions/s"
        mock_client_cls.return_value.role_assignments.list_for_subscription.return_value = [ra]

        result = list_role_assignments(mock_credential, "sub-1")

        assert len(result) == 1
        assert result[0]["principal_id"] == "p1"
        assert result[0]["scope"] == "/subscriptions/s"


class TestListCustomRoles:
    @patch("tenova.rbac.AuthorizationManagementClient")
    def test_returns_custom_roles(self, mock_client_cls, mock_credential):
        rd = MagicMock()
        rd.id = "/subscriptions/s/providers/Microsoft.Authorization/roleDefinitions/cr1"
        rd.role_name = "Custom Reader"
        rd.description = "A custom role"
        rd.role_type = "CustomRole"

        perm = MagicMock()
        perm.actions = ["Microsoft.Resources/*/read"]
        perm.not_actions = []
        perm.data_actions = []
        perm.not_data_actions = []
        rd.permissions = [perm]
        rd.assignable_scopes = ["/subscriptions/s"]

        mock_client_cls.return_value.role_definitions.list.return_value = [rd]

        result = list_custom_roles(mock_credential, "sub-1")

        assert len(result) == 1
        assert result[0]["name"] == "Custom Reader"
        assert "Microsoft.Resources/*/read" in result[0]["permissions"][0]["actions"]

    @patch("tenova.rbac.AuthorizationManagementClient")
    def test_empty_when_no_custom_roles(self, mock_client_cls, mock_credential):
        mock_client_cls.return_value.role_definitions.list.return_value = []

        result = list_custom_roles(mock_credential, "sub-1")

        assert result == []


class TestExportRbac:
    @patch("tenova.rbac.ManagedServiceIdentityClient")
    @patch("tenova.rbac.AuthorizationManagementClient")
    def test_export_creates_json_file(self, mock_auth_cls, mock_msi_cls, mock_credential, tmp_path):
        # Mock role assignments
        ra = MagicMock()
        ra.id = "ra-id"
        ra.name = "ra-name"
        ra.principal_id = "p1"
        ra.principal_type = "User"
        ra.role_definition_id = "rd1"
        ra.scope = "/subscriptions/s"
        mock_auth_cls.return_value.role_assignments.list_for_subscription.return_value = [ra]

        # Mock custom roles — empty
        mock_auth_cls.return_value.role_definitions.list.return_value = []

        # Mock managed identities — empty
        mock_msi_cls.return_value.user_assigned_identities.list_by_subscription.return_value = []

        filepath = export_rbac(mock_credential, "sub-1", output_dir=tmp_path)

        assert filepath.exists()
        data = json.loads(filepath.read_text())
        assert data["subscription_id"] == "sub-1"
        assert len(data["role_assignments"]) == 1
        assert data["role_assignments"][0]["principal_id"] == "p1"
        assert data["summary"]["role_assignment_count"] == 1

    @patch("tenova.rbac.ManagedServiceIdentityClient")
    @patch("tenova.rbac.AuthorizationManagementClient")
    def test_export_includes_custom_roles(self, mock_auth_cls, mock_msi_cls, mock_credential, tmp_path):
        # Mock role assignments — empty
        mock_auth_cls.return_value.role_assignments.list_for_subscription.return_value = []

        # Mock custom roles
        rd = MagicMock()
        rd.id = "cr-id"
        rd.role_name = "My Custom Role"
        rd.description = "Does custom things"
        rd.role_type = "CustomRole"
        rd.permissions = []
        rd.assignable_scopes = ["/subscriptions/s"]
        mock_auth_cls.return_value.role_definitions.list.return_value = [rd]

        # Mock managed identities — empty
        mock_msi_cls.return_value.user_assigned_identities.list_by_subscription.return_value = []

        filepath = export_rbac(mock_credential, "sub-1", output_dir=tmp_path)

        data = json.loads(filepath.read_text())
        assert len(data["custom_roles"]) == 1
        assert data["custom_roles"][0]["name"] == "My Custom Role"
        assert data["summary"]["custom_role_count"] == 1


class TestImportRbac:
    @patch("tenova.rbac.AuthorizationManagementClient")
    def test_import_creates_assignments(self, mock_auth_cls, mock_credential, tmp_path):
        export_data = {
            "subscription_id": "sub-1",
            "role_assignments": [
                {
                    "principal_id": "old-p1",
                    "role_definition_id": "rd1",
                    "scope": "/subscriptions/sub-1",
                },
            ],
            "custom_roles": [],
            "managed_identities": [],
        }
        export_file = tmp_path / "export.json"
        export_file.write_text(json.dumps(export_data))

        mock_auth_cls.return_value.role_assignments.create.return_value = MagicMock()

        result = import_rbac(
            mock_credential,
            "sub-1",
            export_file,
            principal_mapping={"old-p1": "new-p1"},
        )

        assert result["role_assignments_created"] == 1
        assert result["role_assignments_skipped"] == 0
        assert result["role_assignments_failed"] == 0

    @patch("tenova.rbac.AuthorizationManagementClient")
    def test_import_skips_missing_principals(self, mock_auth_cls, mock_credential, tmp_path):
        export_data = {
            "subscription_id": "sub-1",
            "role_assignments": [
                {
                    "principal_id": "old-p1",
                    "role_definition_id": "rd1",
                    "scope": "/subscriptions/sub-1",
                },
            ],
            "custom_roles": [],
            "managed_identities": [],
        }
        export_file = tmp_path / "export.json"
        export_file.write_text(json.dumps(export_data))

        # Simulate PrincipalNotFound error
        mock_auth_cls.return_value.role_assignments.create.side_effect = (
            Exception("PrincipalNotFound: The principal does not exist")
        )

        result = import_rbac(mock_credential, "sub-1", export_file)

        assert result["role_assignments_skipped"] == 1
        assert result["role_assignments_created"] == 0

    @patch("tenova.rbac.AuthorizationManagementClient")
    def test_import_creates_custom_roles(self, mock_auth_cls, mock_credential, tmp_path):
        export_data = {
            "subscription_id": "sub-1",
            "role_assignments": [],
            "custom_roles": [
                {
                    "name": "My Custom Role",
                    "description": "Custom reader",
                    "permissions": [
                        {"actions": ["*/read"], "not_actions": [], "data_actions": [], "not_data_actions": []}
                    ],
                    "assignable_scopes": ["/subscriptions/sub-1"],
                },
            ],
            "managed_identities": [],
        }
        export_file = tmp_path / "export.json"
        export_file.write_text(json.dumps(export_data))

        mock_auth_cls.return_value.role_definitions.create_or_update.return_value = MagicMock()

        result = import_rbac(mock_credential, "sub-1", export_file)

        assert result["custom_roles_created"] == 1
        assert result["custom_roles_failed"] == 0


class TestListManagedIdentities:
    @patch("tenova.rbac.ManagedServiceIdentityClient")
    def test_returns_identities(self, mock_client_cls, mock_credential):
        mi = MagicMock()
        mi.id = "/subscriptions/s/resourceGroups/rg1/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id1"
        mi.name = "my-identity"
        mi.location = "eastus"
        mi.client_id = "c1"
        mi.principal_id = "p1"
        mock_client_cls.return_value.user_assigned_identities.list_by_subscription.return_value = [mi]

        result = list_managed_identities(mock_credential, "sub-1")

        assert len(result) == 1
        assert result[0]["name"] == "my-identity"
        assert result[0]["client_id"] == "c1"
