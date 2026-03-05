"""Tests for the resource scanner module."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from tenova.scanner import (
    _extract_resource_group,
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
    @patch("tenova.scanner._query_resource_graph", return_value=set())
    @patch("tenova.scanner.ResourceManagementClient")
    def test_classifies_resources_static(self, mock_client_cls, mock_graph, mock_credential):
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

    @patch("tenova.scanner._query_resource_graph")
    @patch("tenova.scanner.ResourceManagementClient")
    def test_graph_detects_resource_not_in_static_list(self, mock_client_cls, mock_graph, mock_credential):
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

    @patch("tenova.scanner._query_resource_graph")
    @patch("tenova.scanner.ResourceManagementClient")
    def test_both_layers_flag_resource(self, mock_client_cls, mock_graph, mock_credential):
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
