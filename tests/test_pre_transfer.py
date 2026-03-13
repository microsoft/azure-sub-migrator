"""Tests for the pre-transfer automation engine."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from tenova.pre_transfer import (
    _export_custom_roles,
    _export_keyvault_policies,
    _export_managed_identities,
    _export_policy_assignments,
    _export_policy_definitions,
    _export_rbac_assignments,
    _export_resource_locks,
    _run_step,
    run_pre_transfer,
)

# ──────────────────────────────────────────────────────────────────────
# _run_step helper
# ──────────────────────────────────────────────────────────────────────


class TestRunStep:
    def test_records_success(self):
        results = {"steps": [], "artifacts": {}, "summary": {"total": 0, "succeeded": 0, "failed": 0}}
        _run_step(results, "Test Step", lambda: [1, 2, 3], artifact_key="test_data")

        assert len(results["steps"]) == 1
        assert results["steps"][0]["status"] == "succeeded"
        assert results["steps"][0]["count"] == 3
        assert results["artifacts"]["test_data"] == [1, 2, 3]
        assert results["summary"]["succeeded"] == 1

    def test_records_failure(self):
        results = {"steps": [], "artifacts": {}, "summary": {"total": 0, "succeeded": 0, "failed": 0}}

        def fail():
            raise RuntimeError("boom")

        _run_step(results, "Failing Step", fail, artifact_key="bad")

        assert results["steps"][0]["status"] == "failed"
        assert "boom" in results["steps"][0]["error"]
        assert results["summary"]["failed"] == 1
        assert "bad" not in results["artifacts"]

    def test_counts_dict_items(self):
        results = {"steps": [], "artifacts": {}, "summary": {"total": 0, "succeeded": 0, "failed": 0}}
        _run_step(
            results, "Dict Step",
            lambda: {"items": [1, 2]},
            artifact_key="dict_data",
        )
        assert results["steps"][0]["count"] == 2

    def test_increments_total(self):
        results = {"steps": [], "artifacts": {}, "summary": {"total": 0, "succeeded": 0, "failed": 0}}
        _run_step(results, "Step A", lambda: [], artifact_key="a")
        _run_step(results, "Step B", lambda: [], artifact_key="b")
        assert results["summary"]["total"] == 2


# ──────────────────────────────────────────────────────────────────────
# Individual export functions
# ──────────────────────────────────────────────────────────────────────


class TestExportRbacAssignments:
    @patch("tenova.rbac.list_role_assignments")
    def test_delegates_to_rbac_module(self, mock_list, mock_credential):
        mock_list.return_value = [{"principal_id": "p1"}]
        result = _export_rbac_assignments(mock_credential, "sub-1")
        assert result == [{"principal_id": "p1"}]
        mock_list.assert_called_once_with(mock_credential, "sub-1")


class TestExportCustomRoles:
    @patch("tenova.rbac.list_custom_roles")
    def test_delegates_to_rbac_module(self, mock_list, mock_credential):
        mock_list.return_value = [{"name": "CustomRole"}]
        result = _export_custom_roles(mock_credential, "sub-1")
        assert result == [{"name": "CustomRole"}]


class TestExportManagedIdentities:
    @patch("tenova.rbac.list_managed_identities")
    def test_delegates_to_rbac_module(self, mock_list, mock_credential):
        mock_list.return_value = [{"name": "mi-1"}]
        result = _export_managed_identities(mock_credential, "sub-1")
        assert result == [{"name": "mi-1"}]


class TestExportPolicyAssignments:
    @patch("azure.mgmt.resource.policy.PolicyClient")
    def test_exports_assignments(self, mock_cls, mock_credential):
        pa = MagicMock()
        pa.name = "pa1"
        pa.display_name = "Policy Assignment 1"
        pa.policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/pd1"
        pa.scope = "/subscriptions/sub-1"
        pa.parameters = {}
        pa.description = "desc"
        pa.enforcement_mode = "Default"

        mock_cls.return_value.policy_assignments.list.return_value = [pa]

        result = _export_policy_assignments(mock_credential, "sub-1")
        assert len(result) == 1
        assert result[0]["name"] == "pa1"
        assert result[0]["scope"] == "/subscriptions/sub-1"


class TestExportPolicyDefinitions:
    @patch("azure.mgmt.resource.policy.PolicyClient")
    def test_exports_custom_only(self, mock_cls, mock_credential):
        builtin = MagicMock()
        builtin.policy_type = "BuiltIn"

        custom = MagicMock()
        custom.policy_type = "Custom"
        custom.name = "custom-pd"
        custom.display_name = "My Custom Policy"
        custom.description = "does things"
        custom.policy_rule = {"if": {}, "then": {}}
        custom.parameters = {}
        custom.mode = "All"
        custom.metadata = {}

        mock_cls.return_value.policy_definitions.list.return_value = [builtin, custom]

        result = _export_policy_definitions(mock_credential, "sub-1")
        assert len(result) == 1
        assert result[0]["name"] == "custom-pd"


class TestExportResourceLocks:
    @patch("azure.mgmt.resource.ResourceManagementClient")
    @patch("azure.mgmt.resource.locks.ManagementLockClient")
    def test_exports_locks(self, mock_lock_cls, mock_rm_cls, mock_credential):
        lock = MagicMock()
        lock.name = "lock1"
        lock.level = "CanNotDelete"
        lock.notes = "Important lock"
        lock.id = "/subscriptions/sub-1/providers/Microsoft.Authorization/locks/lock1"

        mock_lock_cls.return_value.management_locks.list_at_subscription_level.return_value = [lock]
        mock_rm_cls.return_value.resource_groups.list.return_value = []

        result = _export_resource_locks(mock_credential, "sub-1")
        assert len(result) == 1
        assert result[0]["name"] == "lock1"
        assert result[0]["level"] == "CanNotDelete"


class TestExportKeyvaultPolicies:
    @patch("azure.mgmt.keyvault.KeyVaultManagementClient")
    def test_exports_vault_policies(self, mock_cls, mock_credential):
        # Build a mock vault
        ap = MagicMock()
        ap.tenant_id = "tenant-1"
        ap.object_id = "oid-1"
        ap.permissions.keys = ["get"]
        ap.permissions.secrets = ["get"]
        ap.permissions.certificates = []
        ap.permissions.storage = []

        vault = MagicMock()
        vault.name = "kv1"
        vault.properties.access_policies = [ap]

        mock_cls.return_value.vaults.get.return_value = vault

        resources = [
            {"name": "kv1", "resource_group": "rg", "type": "Microsoft.KeyVault/vaults"},
        ]
        result = _export_keyvault_policies(mock_credential, "sub-1", resources)
        assert len(result["vaults"]) == 1
        assert result["vaults"][0]["name"] == "kv1"


# ──────────────────────────────────────────────────────────────────────
# run_pre_transfer orchestrator
# ──────────────────────────────────────────────────────────────────────


class TestRunPreTransfer:
    @patch("tenova.pre_transfer._export_keyvault_policies")
    @patch("tenova.pre_transfer._export_resource_locks")
    @patch("tenova.pre_transfer._export_policy_definitions")
    @patch("tenova.pre_transfer._export_policy_assignments")
    @patch("tenova.pre_transfer._export_managed_identities")
    @patch("tenova.pre_transfer._export_custom_roles")
    @patch("tenova.pre_transfer._export_rbac_assignments")
    def test_all_steps_succeed(
        self, mock_rbac, mock_roles, mock_mi, mock_pa, mock_pd, mock_locks, mock_kv,
        mock_credential,
    ):
        mock_rbac.return_value = [{"principal_id": "p1"}]
        mock_roles.return_value = [{"name": "r1"}]
        mock_mi.return_value = [{"name": "mi1"}]
        mock_pa.return_value = [{"name": "pa1"}]
        mock_pd.return_value = [{"name": "pd1"}]
        mock_locks.return_value = [{"name": "lock1"}]
        mock_kv.return_value = {"vaults": [{"name": "kv1"}]}

        scan_data = {"transfer_safe": [], "requires_action": []}
        result = run_pre_transfer(mock_credential, "sub-1", scan_data)

        assert result["overall_status"] == "succeeded"
        assert result["summary"]["total"] == 7
        assert result["summary"]["succeeded"] == 7
        assert result["summary"]["failed"] == 0
        assert "rbac_assignments" in result["artifacts"]
        assert "scan_results" in result["artifacts"]

    @patch("tenova.pre_transfer._export_keyvault_policies")
    @patch("tenova.pre_transfer._export_resource_locks")
    @patch("tenova.pre_transfer._export_policy_definitions")
    @patch("tenova.pre_transfer._export_policy_assignments")
    @patch("tenova.pre_transfer._export_managed_identities")
    @patch("tenova.pre_transfer._export_custom_roles")
    @patch("tenova.pre_transfer._export_rbac_assignments")
    def test_partial_on_failure(
        self, mock_rbac, mock_roles, mock_mi, mock_pa, mock_pd, mock_locks, mock_kv,
        mock_credential,
    ):
        mock_rbac.return_value = [{"principal_id": "p1"}]
        mock_roles.side_effect = RuntimeError("no access")
        mock_mi.return_value = []
        mock_pa.return_value = []
        mock_pd.return_value = []
        mock_locks.return_value = []
        mock_kv.return_value = {"vaults": []}

        scan_data = {"transfer_safe": [], "requires_action": []}
        result = run_pre_transfer(mock_credential, "sub-1", scan_data)

        assert result["overall_status"] == "partial"
        assert result["summary"]["failed"] == 1
        assert result["summary"]["succeeded"] == 6

    @patch("tenova.pre_transfer._export_keyvault_policies")
    @patch("tenova.pre_transfer._export_resource_locks")
    @patch("tenova.pre_transfer._export_policy_definitions")
    @patch("tenova.pre_transfer._export_policy_assignments")
    @patch("tenova.pre_transfer._export_managed_identities")
    @patch("tenova.pre_transfer._export_custom_roles")
    @patch("tenova.pre_transfer._export_rbac_assignments")
    def test_includes_scan_data_as_artifact(
        self, mock_rbac, mock_roles, mock_mi, mock_pa, mock_pd, mock_locks, mock_kv,
        mock_credential,
    ):
        for m in [mock_rbac, mock_roles, mock_mi, mock_pa, mock_pd, mock_locks]:
            m.return_value = []
        mock_kv.return_value = {"vaults": []}

        scan_data = {"transfer_safe": [{"name": "ok-resource"}], "requires_action": []}
        result = run_pre_transfer(mock_credential, "sub-1", scan_data)

        assert result["artifacts"]["scan_results"] == scan_data
