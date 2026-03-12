"""Tests for the resource scanner module."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from tenova.scanner import (
    _build_hierarchy,
    _collect_lock_items,
    _collect_policy_items,
    _collect_rbac_items,
    _extract_display_name,
    _extract_resource_group,
    _find_parent_id,
    _is_impacted,
    list_subscriptions,
    scan_subscription,
)


class TestHelpers:
    def test_extract_resource_group(self):
        rid = "/subscriptions/sub1/resourceGroups/myRG/providers/Microsoft.Compute/virtualMachines/vm1"
        assert _extract_resource_group(rid) == "myRG"

    def test_extract_resource_group_none(self):
        assert _extract_resource_group(None) == ""

    def test_is_impacted_true(self):
        assert _is_impacted("Microsoft.KeyVault/vaults") is True

    def test_is_impacted_false(self):
        assert _is_impacted("Microsoft.Compute/virtualMachines") is False

    def test_is_impacted_case_insensitive(self):
        assert _is_impacted("microsoft.keyvault/vaults") is True

    def test_display_name_top_level_resource(self):
        rid = "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm1"
        assert _extract_display_name(rid, "vm1") == "vm1"

    def test_display_name_child_resource(self):
        rid = (
            "/subscriptions/sub1/resourceGroups/rg1/providers/"
            "Microsoft.Compute/virtualMachines/ArcBox-Win2K22/extensions/AzureMonitorWindowsAgent"
        )
        assert _extract_display_name(rid, "AzureMonitorWindowsAgent") == "ArcBox-Win2K22/AzureMonitorWindowsAgent"

    def test_display_name_none_id(self):
        assert _extract_display_name(None, "fallback") == "fallback"


class TestListSubscriptions:
    @patch("tenova.scanner.SubscriptionClient")
    def test_returns_subscriptions(self, mock_client_cls, mock_credential):
        sub = MagicMock()
        sub.subscription_id = "sub-1"
        sub.display_name = "My Sub"
        sub.state = "Enabled"
        mock_client_cls.return_value.subscriptions.list.return_value = [sub]

        result = list_subscriptions(mock_credential)

        assert len(result) == 1
        assert result[0]["subscription_id"] == "sub-1"
        assert result[0]["display_name"] == "My Sub"


class TestScanSubscription:
    @patch("tenova.scanner._collect_lock_items", return_value=[])
    @patch("tenova.scanner._collect_rbac_items", return_value=[])
    @patch("tenova.scanner._collect_policy_items", return_value=[])
    @patch("tenova.scanner._query_resource_graph", return_value=set())
    @patch("tenova.scanner.ResourceManagementClient")
    def test_classifies_resources_static(
        self, mock_client_cls, mock_graph, mock_policy, mock_rbac, mock_locks, mock_credential
    ):
        """Static list flags Key Vault even when Resource Graph returns nothing."""
        vm = MagicMock()
        vm.id = "/subscriptions/s/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm1"
        vm.name = "vm1"
        vm.type = "Microsoft.Compute/virtualMachines"
        vm.location = "eastus"

        kv = MagicMock()
        kv.id = "/subscriptions/s/resourceGroups/rg1/providers/Microsoft.KeyVault/vaults/kv1"
        kv.name = "kv1"
        kv.type = "Microsoft.KeyVault/vaults"
        kv.location = "eastus"

        mock_client_cls.return_value.resources.list.return_value = [vm, kv]

        result = scan_subscription(mock_credential, "sub-1")

        assert len(result["transfer_safe"]) == 1
        assert result["transfer_safe"][0]["name"] == "vm1"

        assert len(result["requires_action"]) == 1
        assert result["requires_action"][0]["name"] == "kv1"
        assert "timing" in result["requires_action"][0]
        assert result["requires_action"][0]["timing"] == "both"
        assert result["requires_action"][0]["pre_action"] != ""
        assert result["requires_action"][0]["post_action"] != ""
        assert "doc_url" in result["requires_action"][0]
        assert "learn.microsoft.com" in result["requires_action"][0]["doc_url"]
        assert "known impacted type" in result["requires_action"][0]["detection"]

        # Transfer notes are always included (tenant-level items only)
        assert "transfer_notes" in result
        assert isinstance(result["transfer_notes"], dict)
        assert len(result["transfer_notes"]) == 2
        assert "App Registrations" in result["transfer_notes"]
        assert "Entra ID Access Reviews" in result["transfer_notes"]

    @patch("tenova.scanner._collect_lock_items", return_value=[])
    @patch("tenova.scanner._collect_rbac_items", return_value=[])
    @patch("tenova.scanner._collect_policy_items", return_value=[])
    @patch("tenova.scanner._query_resource_graph")
    @patch("tenova.scanner.ResourceManagementClient")
    def test_graph_detects_resource_not_in_static_list(
        self, mock_client_cls, mock_graph, mock_policy, mock_rbac, mock_locks, mock_credential
    ):
        """Resource Graph flags a resource type that is NOT in the static list."""
        # A custom resource type not in IMPACTED_RESOURCE_TYPES
        custom = MagicMock()
        custom.id = "/subscriptions/s/resourceGroups/rg1/providers/Contoso.Widget/widgets/w1"
        custom.name = "w1"
        custom.type = "Contoso.Widget/widgets"
        custom.location = "westus"

        mock_client_cls.return_value.resources.list.return_value = [custom]
        # Resource Graph says this resource has a managed identity
        mock_graph.return_value = {custom.id.lower()}

        result = scan_subscription(mock_credential, "sub-1")

        assert len(result["transfer_safe"]) == 0
        assert len(result["requires_action"]) == 1
        assert result["requires_action"][0]["name"] == "w1"
        assert "runtime" in result["requires_action"][0]["detection"]
        assert "doc_url" in result["requires_action"][0]
        assert "transfer-subscription" in result["requires_action"][0]["doc_url"]

    @patch("tenova.scanner._collect_lock_items", return_value=[])
    @patch("tenova.scanner._collect_rbac_items", return_value=[])
    @patch("tenova.scanner._collect_policy_items", return_value=[])
    @patch("tenova.scanner._query_resource_graph")
    @patch("tenova.scanner.ResourceManagementClient")
    def test_both_layers_flag_resource(
        self, mock_client_cls, mock_graph, mock_policy, mock_rbac, mock_locks, mock_credential
    ):
        """Resource detected by both Graph AND static list shows combined detection."""
        kv = MagicMock()
        kv.id = "/subscriptions/s/resourceGroups/rg1/providers/Microsoft.KeyVault/vaults/kv1"
        kv.name = "kv1"
        kv.type = "Microsoft.KeyVault/vaults"
        kv.location = "eastus"

        mock_client_cls.return_value.resources.list.return_value = [kv]
        mock_graph.return_value = {kv.id.lower()}

        result = scan_subscription(mock_credential, "sub-1")

        assert len(result["requires_action"]) == 1
        detection = result["requires_action"][0]["detection"]
        assert "runtime" in detection
        assert "known impacted type" in detection

    @patch("tenova.scanner._collect_lock_items", return_value=[])
    @patch("tenova.scanner._collect_rbac_items", return_value=[])
    @patch("tenova.scanner._collect_policy_items")
    @patch("tenova.scanner._query_resource_graph", return_value=set())
    @patch("tenova.scanner.ResourceManagementClient")
    def test_policy_items_merged_into_requires_action(
        self, mock_client_cls, mock_graph, mock_policy, mock_rbac, mock_locks, mock_credential
    ):
        """Policy items from _collect_policy_items are appended to requires_action."""
        vm = MagicMock()
        vm.id = "/subscriptions/s/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm1"
        vm.name = "vm1"
        vm.type = "Microsoft.Compute/virtualMachines"
        vm.location = "eastus"

        mock_client_cls.return_value.resources.list.return_value = [vm]

        # Simulate policy items returned
        mock_policy.return_value = [
            {
                "id": "/subscriptions/sub-1/providers/Microsoft.Authorization/policyAssignments",
                "name": "3 policy assignment(s): Require tags, Allowed locations, Audit VMs",
                "type": "Microsoft.Authorization/policyAssignments",
                "location": "subscription-wide",
                "resource_group": "—",
                "detection": "policy API",
                "timing": "pre",
                "pre_action": "Export before transfer",
                "post_action": "Reimport after transfer",
                "doc_url": "https://learn.microsoft.com/en-us/azure/governance/policy/overview",
            },
        ]

        result = scan_subscription(mock_credential, "sub-1")

        assert len(result["transfer_safe"]) == 1
        assert len(result["requires_action"]) == 1
        assert result["requires_action"][0]["type"] == "Microsoft.Authorization/policyAssignments"
        assert "3 policy assignment(s)" in result["requires_action"][0]["name"]
        assert result["requires_action"][0]["detection"] == "policy API"


class TestCollectPolicyItems:
    @patch("tenova.scanner.PolicyClient")
    def test_returns_assignment_summary(self, mock_client_cls, mock_credential):
        """Policy assignments are returned as a single summary entry."""
        pa1 = MagicMock()
        pa1.display_name = "Require tags"
        pa1.name = "pa1"
        pa2 = MagicMock()
        pa2.display_name = "Allowed locations"
        pa2.name = "pa2"
        mock_client_cls.return_value.policy_assignments.list.return_value = [pa1, pa2]
        mock_client_cls.return_value.policy_definitions.list.return_value = []

        result = _collect_policy_items(mock_credential, "sub-1")

        assert len(result) == 1
        assert result[0]["type"] == "Microsoft.Authorization/policyAssignments"
        assert "2 policy assignment(s)" in result[0]["name"]
        assert "Require tags" in result[0]["name"]
        assert "Allowed locations" in result[0]["name"]
        assert result[0]["detection"] == "policy API"
        assert result[0]["timing"] == "pre"

    @patch("tenova.scanner.PolicyClient")
    def test_returns_custom_definition_summary(self, mock_client_cls, mock_credential):
        """Custom policy definitions are returned as a single summary entry."""
        mock_client_cls.return_value.policy_assignments.list.return_value = []

        pd1 = MagicMock()
        pd1.display_name = "Audit storage"
        pd1.name = "custom1"
        mock_client_cls.return_value.policy_definitions.list.return_value = [pd1]

        result = _collect_policy_items(mock_credential, "sub-1")

        assert len(result) == 1
        assert result[0]["type"] == "Microsoft.Authorization/policyDefinitions"
        assert "1 custom policy definition(s)" in result[0]["name"]
        assert "Audit storage" in result[0]["name"]
        # Verify server-side filter was used
        mock_client_cls.return_value.policy_definitions.list.assert_called_once_with(
            filter="policyType eq 'Custom'",
        )

    @patch("tenova.scanner.PolicyClient")
    def test_returns_both_when_both_exist(self, mock_client_cls, mock_credential):
        """Both assignments and custom definitions produce two entries."""
        pa = MagicMock()
        pa.display_name = "Require tags"
        pa.name = "pa1"
        mock_client_cls.return_value.policy_assignments.list.return_value = [pa]

        pd = MagicMock()
        pd.display_name = "Audit storage"
        pd.name = "custom1"
        mock_client_cls.return_value.policy_definitions.list.return_value = [pd]

        result = _collect_policy_items(mock_credential, "sub-1")

        assert len(result) == 2
        types = {r["type"] for r in result}
        assert "Microsoft.Authorization/policyAssignments" in types
        assert "Microsoft.Authorization/policyDefinitions" in types

    @patch("tenova.scanner.PolicyClient")
    def test_returns_empty_when_no_policy_objects(self, mock_client_cls, mock_credential):
        """No items returned when subscription has no policy objects."""
        mock_client_cls.return_value.policy_assignments.list.return_value = []
        mock_client_cls.return_value.policy_definitions.list.return_value = []

        result = _collect_policy_items(mock_credential, "sub-1")

        assert result == []

    @patch("tenova.scanner.PolicyClient")
    def test_truncates_names_beyond_five(self, mock_client_cls, mock_credential):
        """Only the first 5 names are shown, rest truncated with count."""
        assignments = []
        for i in range(8):
            pa = MagicMock()
            pa.display_name = f"Policy {i}"
            pa.name = f"pa{i}"
            assignments.append(pa)
        mock_client_cls.return_value.policy_assignments.list.return_value = assignments
        mock_client_cls.return_value.policy_definitions.list.return_value = []

        result = _collect_policy_items(mock_credential, "sub-1")

        assert len(result) == 1
        assert "8 policy assignment(s)" in result[0]["name"]
        assert "Policy 0" in result[0]["name"]
        assert "Policy 4" in result[0]["name"]
        # Policy 5-7 should not be named individually
        assert "Policy 5" not in result[0]["name"]
        assert "(+3 more)" in result[0]["name"]

    @patch("tenova.scanner.PolicyClient")
    def test_policy_api_failure_returns_empty(self, mock_client_cls, mock_credential):
        """Policy API failure is non-fatal — returns empty list."""
        mock_client_cls.side_effect = Exception("Permission denied")

        result = _collect_policy_items(mock_credential, "sub-1")

        assert result == []


class TestCollectRbacItems:
    @patch("tenova.scanner.AuthorizationManagementClient")
    def test_returns_assignment_count(self, mock_client_cls, mock_credential):
        """Role assignments are returned as a single summary entry with count."""
        ra1 = MagicMock()
        ra2 = MagicMock()
        ra3 = MagicMock()
        mock_client_cls.return_value.role_assignments.list_for_subscription.return_value = [ra1, ra2, ra3]
        mock_client_cls.return_value.role_definitions.list.return_value = []

        result = _collect_rbac_items(mock_credential, "sub-1")

        assert len(result) == 1
        assert result[0]["type"] == "Microsoft.Authorization/roleAssignments"
        assert "3 role assignment(s)" in result[0]["name"]
        assert result[0]["detection"] == "authorization API"
        assert result[0]["timing"] == "pre"

    @patch("tenova.scanner.AuthorizationManagementClient")
    def test_returns_custom_roles(self, mock_client_cls, mock_credential):
        """Custom role definitions are returned as a summary entry."""
        mock_client_cls.return_value.role_assignments.list_for_subscription.return_value = []

        rd1 = MagicMock()
        rd1.role_name = "VM Operator"
        rd1.name = "rd1"
        rd1.role_type = "CustomRole"
        rd2 = MagicMock()
        rd2.role_name = "Storage Reader Plus"
        rd2.name = "rd2"
        rd2.role_type = "CustomRole"
        mock_client_cls.return_value.role_definitions.list.return_value = [rd1, rd2]

        result = _collect_rbac_items(mock_credential, "sub-1")

        assert len(result) == 1
        assert result[0]["type"] == "Microsoft.Authorization/roleDefinitions"
        assert "2 custom role(s)" in result[0]["name"]
        assert "VM Operator" in result[0]["name"]
        assert "Storage Reader Plus" in result[0]["name"]
        # Verify filter was passed
        mock_client_cls.return_value.role_definitions.list.assert_called_once_with(
            "/subscriptions/sub-1",
            filter="type eq 'CustomRole'",
        )

    @patch("tenova.scanner.AuthorizationManagementClient")
    def test_returns_both_assignments_and_custom_roles(self, mock_client_cls, mock_credential):
        """Both assignments and custom roles produce two entries."""
        ra = MagicMock()
        mock_client_cls.return_value.role_assignments.list_for_subscription.return_value = [ra]

        rd = MagicMock()
        rd.role_name = "Custom Role"
        rd.name = "rd1"
        rd.role_type = "CustomRole"
        mock_client_cls.return_value.role_definitions.list.return_value = [rd]

        result = _collect_rbac_items(mock_credential, "sub-1")

        assert len(result) == 2
        types = {r["type"] for r in result}
        assert "Microsoft.Authorization/roleAssignments" in types
        assert "Microsoft.Authorization/roleDefinitions" in types

    @patch("tenova.scanner.AuthorizationManagementClient")
    def test_returns_empty_when_no_rbac(self, mock_client_cls, mock_credential):
        """No items returned when subscription has no assignments or custom roles."""
        mock_client_cls.return_value.role_assignments.list_for_subscription.return_value = []
        mock_client_cls.return_value.role_definitions.list.return_value = []

        result = _collect_rbac_items(mock_credential, "sub-1")

        assert result == []

    @patch("tenova.scanner.AuthorizationManagementClient")
    def test_rbac_api_failure_returns_empty(self, mock_client_cls, mock_credential):
        """RBAC API failure is non-fatal — returns empty list."""
        mock_client_cls.side_effect = Exception("Forbidden")

        result = _collect_rbac_items(mock_credential, "sub-1")

        assert result == []


class TestCollectLockItems:
    @patch("tenova.scanner.ManagementLockClient")
    def test_returns_lock_summary(self, mock_client_cls, mock_credential):
        """Resource locks are returned as a single summary entry."""
        lock1 = MagicMock()
        lock1.name = "prod-lock"
        lock1.level = "CanNotDelete"
        lock2 = MagicMock()
        lock2.name = "critical-lock"
        lock2.level = "ReadOnly"
        mock_client_cls.return_value.management_locks.list_at_subscription_level.return_value = [lock1, lock2]

        result = _collect_lock_items(mock_credential, "sub-1")

        assert len(result) == 1
        assert result[0]["type"] == "Microsoft.Authorization/locks"
        assert "2 resource lock(s)" in result[0]["name"]
        assert "prod-lock" in result[0]["name"]
        assert "critical-lock" in result[0]["name"]
        assert result[0]["detection"] == "locks API"
        assert result[0]["timing"] == "pre"

    @patch("tenova.scanner.ManagementLockClient")
    def test_returns_empty_when_no_locks(self, mock_client_cls, mock_credential):
        """No items returned when subscription has no locks."""
        mock_client_cls.return_value.management_locks.list_at_subscription_level.return_value = []

        result = _collect_lock_items(mock_credential, "sub-1")

        assert result == []

    @patch("tenova.scanner.ManagementLockClient")
    def test_truncates_lock_names_beyond_five(self, mock_client_cls, mock_credential):
        """Only the first 5 lock names are shown, rest truncated."""
        locks = []
        for i in range(7):
            lock = MagicMock()
            lock.name = f"lock-{i}"
            lock.level = "CanNotDelete"
            locks.append(lock)
        mock_client_cls.return_value.management_locks.list_at_subscription_level.return_value = locks

        result = _collect_lock_items(mock_credential, "sub-1")

        assert len(result) == 1
        assert "7 resource lock(s)" in result[0]["name"]
        assert "lock-0" in result[0]["name"]
        assert "lock-4" in result[0]["name"]
        assert "lock-5" not in result[0]["name"]
        assert "(+2 more)" in result[0]["name"]

    @patch("tenova.scanner.ManagementLockClient")
    def test_lock_api_failure_returns_empty(self, mock_client_cls, mock_credential):
        """Lock API failure is non-fatal — returns empty list."""
        mock_client_cls.side_effect = Exception("Not authorized")

        result = _collect_lock_items(mock_credential, "sub-1")

        assert result == []


class TestFindParentId:
    def test_top_level_resource_returns_none(self):
        rid = "/subscriptions/s/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm1"
        assert _find_parent_id(rid) is None

    def test_child_resource_returns_parent(self):
        rid = "/subscriptions/s/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm1/extensions/ext1"
        expected = "/subscriptions/s/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm1"
        assert _find_parent_id(rid) == expected

    def test_deeply_nested_returns_immediate_parent(self):
        rid = (
            "/subscriptions/s/resourceGroups/rg1/providers/"
            "Microsoft.Compute/virtualMachines/vm1/extensions/ext1/subThings/sub1"
        )
        expected = (
            "/subscriptions/s/resourceGroups/rg1/providers/"
            "Microsoft.Compute/virtualMachines/vm1/extensions/ext1"
        )
        assert _find_parent_id(rid) == expected

    def test_empty_string_returns_none(self):
        assert _find_parent_id("") is None

    def test_none_returns_none(self):
        assert _find_parent_id(None) is None

    def test_no_providers_returns_none(self):
        assert _find_parent_id("/subscriptions/s/resourceGroups/rg1") is None


class TestBuildHierarchy:
    def test_child_in_action_promotes_parent_from_safe(self):
        """If a child requires action, its parent moves from safe to action."""
        vm = {
            "id": "/subscriptions/s/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm1",
            "name": "vm1",
            "type": "Microsoft.Compute/virtualMachines",
            "location": "eastus",
            "resource_group": "rg1",
        }
        ext = {
            "id": "/subscriptions/s/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm1/extensions/ext1",
            "name": "vm1/ext1",
            "type": "Microsoft.Compute/virtualMachines/extensions",
            "location": "eastus",
            "resource_group": "rg1",
            "timing": "post",
            "pre_action": "",
            "post_action": "Reinstall extension",
            "doc_url": "https://example.com",
            "detection": "known impacted type",
        }

        new_safe, new_action = _build_hierarchy([vm], [ext])

        # VM should be promoted out of safe
        assert len(new_safe) == 0
        # VM should appear in action with ext nested inside
        assert len(new_action) == 1
        parent = new_action[0]
        assert parent["name"] == "vm1"
        assert parent["promoted"] is True
        assert len(parent["children"]) == 1
        assert parent["children"][0]["name"] == "vm1/ext1"

    def test_child_nested_under_parent_already_in_action(self):
        """If parent is already in requires_action, child nests under it."""
        kv = {
            "id": "/subscriptions/s/resourceGroups/rg1/providers/Microsoft.KeyVault/vaults/kv1",
            "name": "kv1",
            "type": "Microsoft.KeyVault/vaults",
            "location": "eastus",
            "resource_group": "rg1",
            "timing": "both",
            "pre_action": "Export access policies",
            "post_action": "Update tenant ID",
            "doc_url": "https://example.com",
            "detection": "known impacted type",
        }
        # Hypothetical child of Key Vault
        child = {
            "id": "/subscriptions/s/resourceGroups/rg1/providers/Microsoft.KeyVault/vaults/kv1/secrets/sec1",
            "name": "kv1/sec1",
            "type": "Microsoft.KeyVault/vaults/secrets",
            "location": "eastus",
            "resource_group": "rg1",
            "timing": "post",
            "pre_action": "",
            "post_action": "Rotate secret",
            "doc_url": "https://example.com",
            "detection": "known impacted type",
        }

        new_safe, new_action = _build_hierarchy([], [kv, child])

        assert len(new_safe) == 0
        # Only the parent should be top-level, with child nested
        assert len(new_action) == 1
        assert new_action[0]["name"] == "kv1"
        assert len(new_action[0]["children"]) == 1
        assert new_action[0]["children"][0]["name"] == "kv1/sec1"

    def test_multiple_children_nest_under_same_parent(self):
        """Multiple children of the same VM all nest under one promoted parent."""
        vm = {
            "id": "/subscriptions/s/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm1",
            "name": "vm1",
            "type": "Microsoft.Compute/virtualMachines",
            "location": "eastus",
            "resource_group": "rg1",
        }
        ext1 = {
            "id": "/subscriptions/s/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm1/extensions/ext1",
            "name": "vm1/ext1",
            "type": "Microsoft.Compute/virtualMachines/extensions",
            "location": "eastus",
            "resource_group": "rg1",
            "timing": "post",
            "pre_action": "",
            "post_action": "Reinstall",
            "doc_url": "",
            "detection": "known impacted type",
        }
        ext2 = {
            "id": "/subscriptions/s/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm1/extensions/ext2",
            "name": "vm1/ext2",
            "type": "Microsoft.Compute/virtualMachines/extensions",
            "location": "eastus",
            "resource_group": "rg1",
            "timing": "post",
            "pre_action": "",
            "post_action": "Reinstall",
            "doc_url": "",
            "detection": "known impacted type",
        }

        new_safe, new_action = _build_hierarchy([vm], [ext1, ext2])

        assert len(new_safe) == 0
        assert len(new_action) == 1
        assert new_action[0]["name"] == "vm1"
        assert len(new_action[0]["children"]) == 2

    def test_no_children_leaves_lists_unchanged(self):
        """Resources without parent-child relationships stay flat."""
        vm = {
            "id": "/subscriptions/s/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm1",
            "name": "vm1",
            "type": "Microsoft.Compute/virtualMachines",
            "location": "eastus",
            "resource_group": "rg1",
        }
        kv = {
            "id": "/subscriptions/s/resourceGroups/rg1/providers/Microsoft.KeyVault/vaults/kv1",
            "name": "kv1",
            "type": "Microsoft.KeyVault/vaults",
            "location": "eastus",
            "resource_group": "rg1",
            "timing": "both",
            "pre_action": "Export",
            "post_action": "Update",
            "doc_url": "",
            "detection": "known impacted type",
        }

        new_safe, new_action = _build_hierarchy([vm], [kv])

        assert len(new_safe) == 1
        assert new_safe[0]["name"] == "vm1"
        assert len(new_action) == 1
        assert new_action[0]["name"] == "kv1"
        assert "children" not in new_action[0]

    def test_subscription_wide_items_remain_flat(self):
        """Policy/RBAC/lock items (no providers in ID) stay flat."""
        policy = {
            "id": "/subscriptions/sub-1/providers/Microsoft.Authorization/policyAssignments",
            "name": "3 policy assignments",
            "type": "Microsoft.Authorization/policyAssignments",
            "location": "subscription-wide",
            "resource_group": "—",
            "timing": "pre",
            "pre_action": "Export",
            "post_action": "Reimport",
            "doc_url": "",
            "detection": "policy API",
        }

        new_safe, new_action = _build_hierarchy([], [policy])

        assert len(new_action) == 1
        assert new_action[0]["name"] == "3 policy assignments"
