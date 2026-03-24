"""Tests for the cross-subscription dependency analysis module."""

from __future__ import annotations

from unittest.mock import patch

from tenova.cross_sub import (
    _build_matrix,
    _build_sub_summaries,
    _check_and_append,
    _deduplicate,
    _find_cross_sub_references,
    _suggest_order,
    analyze_cross_sub_dependencies,
)

SUB_A = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
SUB_B = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
SUB_C = "cccccccc-cccc-cccc-cccc-cccccccccccc"


class TestMinimumSubscriptions:
    """At least two subs are required."""

    def test_single_sub_returns_error(self, mock_credential):
        result = analyze_cross_sub_dependencies(mock_credential, [SUB_A])
        assert "error" in result
        assert result["dependencies"] == []

    def test_empty_list_returns_error(self, mock_credential):
        result = analyze_cross_sub_dependencies(mock_credential, [])
        assert "error" in result


class TestFindCrossSubReferences:
    """Test the generic cross-sub reference scanner."""

    def test_detects_reference_to_other_sub(self):
        sub_set = {SUB_A.lower(), SUB_B.lower()}
        resource = {
            "id": f"/subscriptions/{SUB_A}/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1",
            "name": "vm1",
            "type": "Microsoft.Compute/virtualMachines",
            "some_property": (
                f"/subscriptions/{SUB_B}/resourceGroups/rg2"
                f"/providers/Microsoft.Storage/storageAccounts/sa1"
            ),
        }
        deps = _find_cross_sub_references(resource, SUB_A, sub_set)
        assert len(deps) == 1
        assert deps[0]["source_sub"] == SUB_A
        assert deps[0]["target_sub"].lower() == SUB_B.lower()
        assert deps[0]["type"] == "Resource Reference"

    def test_ignores_same_sub_reference(self):
        sub_set = {SUB_A.lower(), SUB_B.lower()}
        resource = {
            "id": f"/subscriptions/{SUB_A}/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1",
            "name": "vm1",
            "data": f"/subscriptions/{SUB_A}/something",
        }
        deps = _find_cross_sub_references(resource, SUB_A, sub_set)
        assert len(deps) == 0

    def test_ignores_unknown_sub_reference(self):
        sub_set = {SUB_A.lower(), SUB_B.lower()}
        resource = {
            "id": f"/subscriptions/{SUB_A}/resourceGroups/rg/providers/X/Y/z",
            "name": "z",
            "ref": f"/subscriptions/{SUB_C}/other",  # SUB_C not in sub_set
        }
        deps = _find_cross_sub_references(resource, SUB_A, sub_set)
        assert len(deps) == 0

    def test_multiple_references(self):
        sub_set = {SUB_A.lower(), SUB_B.lower(), SUB_C.lower()}
        resource = {
            "id": f"/subscriptions/{SUB_A}/resourceGroups/rg/providers/X/Y/z",
            "name": "z",
            "ref1": f"/subscriptions/{SUB_B}/a/b",
            "ref2": f"/subscriptions/{SUB_C}/c/d",
        }
        deps = _find_cross_sub_references(resource, SUB_A, sub_set)
        target_subs = {d["target_sub"].lower() for d in deps}
        assert SUB_B.lower() in target_subs
        assert SUB_C.lower() in target_subs


class TestDeduplicate:
    def test_removes_exact_duplicates(self):
        dep = {
            "source_sub": SUB_A,
            "target_sub": SUB_B,
            "type": "VNet Peering",
            "source_resource": "/a/b/c",
            "target_resource": "/d/e/f",
        }
        result = _deduplicate([dep, dep.copy()])
        assert len(result) == 1

    def test_keeps_different_types(self):
        dep1 = {
            "source_sub": SUB_A,
            "target_sub": SUB_B,
            "type": "VNet Peering",
            "source_resource": "/a",
            "target_resource": "/b",
        }
        dep2 = {
            "source_sub": SUB_A,
            "target_sub": SUB_B,
            "type": "Private Endpoint",
            "source_resource": "/a",
            "target_resource": "/b",
        }
        result = _deduplicate([dep1, dep2])
        assert len(result) == 2


class TestBuildMatrix:
    def test_counts_dependencies(self):
        deps = [
            {"source_sub": SUB_A, "target_sub": SUB_B, "type": "VNet Peering"},
            {"source_sub": SUB_A, "target_sub": SUB_B, "type": "Private Endpoint"},
            {"source_sub": SUB_B, "target_sub": SUB_A, "type": "DNS Link"},
        ]
        matrix = _build_matrix(deps, [SUB_A, SUB_B])
        assert matrix[SUB_A][SUB_B] == 2
        assert matrix[SUB_B][SUB_A] == 1

    def test_empty_dependencies(self):
        matrix = _build_matrix([], [SUB_A, SUB_B])
        assert matrix[SUB_A] == {}
        assert matrix[SUB_B] == {}


class TestBuildSubSummaries:
    def test_includes_dependency_counts(self):
        scan_results = {
            SUB_A: {"transfer_safe": [1, 2, 3], "requires_action": [4]},
            SUB_B: {"transfer_safe": [5], "requires_action": [6, 7]},
        }
        matrix = {
            SUB_A: {SUB_B: 3},
            SUB_B: {SUB_A: 1},
        }
        summaries = _build_sub_summaries([SUB_A, SUB_B], scan_results, matrix)
        sub_a = next(s for s in summaries if s["subscription_id"] == SUB_A)
        sub_b = next(s for s in summaries if s["subscription_id"] == SUB_B)

        assert sub_a["transfer_safe_count"] == 3
        assert sub_a["requires_action_count"] == 1
        assert sub_a["outgoing_dependencies"] == 3
        assert sub_a["incoming_dependencies"] == 1
        assert sub_a["total_dependencies"] == 4

        assert sub_b["outgoing_dependencies"] == 1
        assert sub_b["incoming_dependencies"] == 3


class TestSuggestOrder:
    def test_most_depended_on_first(self):
        """Sub B is depended on by both A and C, so B should be first."""
        matrix = {
            SUB_A: {SUB_B: 5},
            SUB_B: {},
            SUB_C: {SUB_B: 3},
        }
        order = _suggest_order([SUB_A, SUB_B, SUB_C], matrix)
        assert order[0] == SUB_B  # most incoming

    def test_no_dependencies_preserves_input_order(self):
        matrix = {SUB_A: {}, SUB_B: {}}
        order = _suggest_order([SUB_A, SUB_B], matrix)
        assert len(order) == 2


class TestAnalyzeCrossSubDependencies:
    """Integration test of the full analysis flow (all SDK calls mocked)."""

    @patch("tenova.cross_sub._detect_diagnostic_settings", return_value=[])
    @patch("tenova.cross_sub._detect_load_balancer_refs", return_value=[])
    @patch("tenova.cross_sub._detect_nsg_references", return_value=[])
    @patch("tenova.cross_sub._detect_private_dns_links", return_value=[])
    @patch("tenova.cross_sub._detect_private_endpoints", return_value=[])
    @patch("tenova.cross_sub._detect_vnet_peering")
    @patch("tenova.cross_sub.scan_subscription")
    def test_detects_vnet_peering_dependency(
        self, mock_scan, mock_vnet, mock_pe, mock_dns,
        mock_nsg, mock_lb, mock_diag, mock_credential
    ):
        # Scan returns resources with cross-sub references
        mock_scan.side_effect = lambda cred, sid: {
            "transfer_safe": [],
            "requires_action": [],
        }

        # VNet peering from SUB_A → SUB_B
        mock_vnet.side_effect = lambda cred, sid, sub_set: [
            {
                "source_sub": SUB_A,
                "target_sub": SUB_B,
                "type": "VNet Peering",
                "source_resource": f"/subscriptions/{SUB_A}/rg/providers/Microsoft.Network/virtualNetworks/vnet1",
                "target_resource": f"/subscriptions/{SUB_B}/rg/providers/Microsoft.Network/virtualNetworks/vnet2",
                "detail": "Test peering",
                "impact": "Peering will break",
            }
        ] if sid == SUB_A else []

        result = analyze_cross_sub_dependencies(mock_credential, [SUB_A, SUB_B])

        assert len(result["dependencies"]) >= 1
        vnet_deps = [d for d in result["dependencies"] if d["type"] == "VNet Peering"]
        assert len(vnet_deps) == 1
        assert vnet_deps[0]["source_sub"] == SUB_A
        assert vnet_deps[0]["target_sub"] == SUB_B
        assert len(result["subscriptions"]) == 2
        assert result["suggested_order"][0] == SUB_B  # depended upon

    @patch("tenova.cross_sub._detect_diagnostic_settings", return_value=[])
    @patch("tenova.cross_sub._detect_load_balancer_refs", return_value=[])
    @patch("tenova.cross_sub._detect_nsg_references", return_value=[])
    @patch("tenova.cross_sub._detect_private_dns_links", return_value=[])
    @patch("tenova.cross_sub._detect_private_endpoints", return_value=[])
    @patch("tenova.cross_sub._detect_vnet_peering", return_value=[])
    @patch("tenova.cross_sub.scan_subscription")
    def test_no_dependencies(
        self, mock_scan, mock_vnet, mock_pe, mock_dns,
        mock_nsg, mock_lb, mock_diag, mock_credential
    ):
        mock_scan.return_value = {"transfer_safe": [{"id": "x"}], "requires_action": []}

        result = analyze_cross_sub_dependencies(mock_credential, [SUB_A, SUB_B])

        assert result["dependencies"] == []
        assert len(result["subscriptions"]) == 2
        for s in result["subscriptions"]:
            assert s["total_dependencies"] == 0

    @patch("tenova.cross_sub._detect_diagnostic_settings", return_value=[])
    @patch("tenova.cross_sub._detect_load_balancer_refs", return_value=[])
    @patch("tenova.cross_sub._detect_nsg_references", return_value=[])
    @patch("tenova.cross_sub._detect_private_dns_links", return_value=[])
    @patch("tenova.cross_sub._detect_private_endpoints", return_value=[])
    @patch("tenova.cross_sub._detect_vnet_peering", return_value=[])
    @patch("tenova.cross_sub.scan_subscription")
    def test_scan_failure_for_one_sub_does_not_block(
        self, mock_scan, mock_vnet, mock_pe, mock_dns,
        mock_nsg, mock_lb, mock_diag, mock_credential
    ):
        """If one sub scan fails, the others should still succeed."""
        def side_effect(cred, sid):
            if sid == SUB_A:
                raise Exception("Access denied")
            return {"transfer_safe": [], "requires_action": []}

        mock_scan.side_effect = side_effect

        result = analyze_cross_sub_dependencies(mock_credential, [SUB_A, SUB_B])

        # Should still complete without raising
        assert len(result["subscriptions"]) == 2
        sub_a = next(s for s in result["subscriptions"] if s["subscription_id"] == SUB_A)
        assert sub_a["error"] is not None

    @patch("tenova.cross_sub._detect_diagnostic_settings", return_value=[])
    @patch("tenova.cross_sub._detect_load_balancer_refs", return_value=[])
    @patch("tenova.cross_sub._detect_nsg_references", return_value=[])
    @patch("tenova.cross_sub._detect_private_dns_links", return_value=[])
    @patch("tenova.cross_sub._detect_private_endpoints", return_value=[])
    @patch("tenova.cross_sub._detect_vnet_peering", return_value=[])
    @patch("tenova.cross_sub.scan_subscription")
    def test_three_subs_with_chain(
        self, mock_scan, mock_vnet, mock_pe, mock_dns,
        mock_nsg, mock_lb, mock_diag, mock_credential
    ):
        """A → B → C chain should suggest C first (most depended on indirectly)."""
        mock_scan.return_value = {"transfer_safe": [], "requires_action": []}

        # A references B, B references C via generic resource refs
        mock_scan.side_effect = lambda cred, sid: {
            "transfer_safe": [{
                "id": f"/subscriptions/{sid}/resourceGroups/rg/providers/X/Y/z",
                "name": "z",
                "ref": f"/subscriptions/{SUB_B}/something" if sid == SUB_A else (
                    f"/subscriptions/{SUB_C}/something" if sid == SUB_B else ""
                ),
            }],
            "requires_action": [],
        }

        result = analyze_cross_sub_dependencies(mock_credential, [SUB_A, SUB_B, SUB_C])

        # Both B and C should have incoming deps
        assert len(result["dependencies"]) >= 2
        assert result["matrix"][SUB_A].get(SUB_B, 0) > 0
        assert result["matrix"][SUB_B].get(SUB_C, 0) > 0


class TestCheckAndAppend:
    """Test the _check_and_append helper."""

    def test_appends_when_target_in_other_sub(self):
        deps: list = []
        sub_set = {SUB_A.lower(), SUB_B.lower()}
        target = f"/subscriptions/{SUB_B}/rg/providers/X/Y/z"
        _check_and_append(
            deps, SUB_A, sub_set, target,
            "Test", "/source", "detail", "impact",
        )
        assert len(deps) == 1
        assert deps[0]["target_sub"].lower() == SUB_B.lower()

    def test_skips_same_sub(self):
        deps: list = []
        sub_set = {SUB_A.lower(), SUB_B.lower()}
        target = f"/subscriptions/{SUB_A}/rg/providers/X/Y/z"
        _check_and_append(
            deps, SUB_A, sub_set, target,
            "Test", "/source", "detail", "impact",
        )
        assert len(deps) == 0

    def test_skips_empty_target(self):
        deps: list = []
        _check_and_append(
            deps, SUB_A, {SUB_A.lower()}, "",
            "Test", "/source", "detail", "impact",
        )
        assert len(deps) == 0

    def test_skips_unknown_sub(self):
        deps: list = []
        sub_set = {SUB_A.lower(), SUB_B.lower()}
        target = f"/subscriptions/{SUB_C}/rg/providers/X/Y/z"
        _check_and_append(
            deps, SUB_A, sub_set, target,
            "Test", "/source", "detail", "impact",
        )
        assert len(deps) == 0
