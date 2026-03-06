"""Tests for the Azure Policy export module."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from tenova.policy import (
    export_policies,
    list_policy_assignments,
    list_custom_policy_definitions,
    list_custom_policy_set_definitions,
)


class TestListPolicyAssignments:
    @patch("tenova.policy.PolicyClient")
    def test_returns_assignments(self, mock_client_cls, mock_credential):
        pa = MagicMock()
        pa.id = "/subscriptions/s/providers/Microsoft.Authorization/policyAssignments/pa1"
        pa.name = "pa1"
        pa.display_name = "Require tags on resources"
        pa.description = "Ensures all resources have tags"
        pa.policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/pd1"
        pa.scope = "/subscriptions/s"
        pa.enforcement_mode = "Default"
        pa.parameters = {"tagName": {"value": "Environment"}}
        pa.not_scopes = ["/subscriptions/s/resourceGroups/excluded-rg"]
        pa.identity = None
        mock_client_cls.return_value.policy_assignments.list.return_value = [pa]

        result = list_policy_assignments(mock_credential, "sub-1")

        assert len(result) == 1
        assert result[0]["name"] == "pa1"
        assert result[0]["display_name"] == "Require tags on resources"
        assert result[0]["scope"] == "/subscriptions/s"
        assert result[0]["parameters"] == {"tagName": {"value": "Environment"}}

    @patch("tenova.policy.PolicyClient")
    def test_empty_when_no_assignments(self, mock_client_cls, mock_credential):
        mock_client_cls.return_value.policy_assignments.list.return_value = []

        result = list_policy_assignments(mock_credential, "sub-1")

        assert result == []


class TestListCustomPolicyDefinitions:
    @patch("tenova.policy.PolicyClient")
    def test_returns_custom_definitions_only(self, mock_client_cls, mock_credential):
        # Custom definition
        custom_pd = MagicMock()
        custom_pd.id = "/subscriptions/s/providers/Microsoft.Authorization/policyDefinitions/custom1"
        custom_pd.name = "custom1"
        custom_pd.display_name = "Custom audit storage"
        custom_pd.description = "Audit storage accounts"
        custom_pd.policy_type = "Custom"
        custom_pd.mode = "Indexed"
        custom_pd.policy_rule = {"if": {"field": "type", "equals": "Microsoft.Storage/storageAccounts"}}
        custom_pd.parameters = {}
        custom_pd.metadata = {"category": "Storage"}

        # Built-in definition (should be skipped)
        builtin_pd = MagicMock()
        builtin_pd.policy_type = "BuiltIn"

        mock_client_cls.return_value.policy_definitions.list.return_value = [builtin_pd, custom_pd]

        result = list_custom_policy_definitions(mock_credential, "sub-1")

        assert len(result) == 1
        assert result[0]["name"] == "custom1"
        assert result[0]["display_name"] == "Custom audit storage"

    @patch("tenova.policy.PolicyClient")
    def test_empty_when_only_builtins(self, mock_client_cls, mock_credential):
        builtin_pd = MagicMock()
        builtin_pd.policy_type = "BuiltIn"
        mock_client_cls.return_value.policy_definitions.list.return_value = [builtin_pd]

        result = list_custom_policy_definitions(mock_credential, "sub-1")

        assert result == []


class TestListCustomPolicySetDefinitions:
    @patch("tenova.policy.PolicyClient")
    def test_returns_custom_initiatives(self, mock_client_cls, mock_credential):
        ref = MagicMock()
        ref.policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/pd1"
        ref.parameters = {}

        psd = MagicMock()
        psd.id = "/subscriptions/s/providers/Microsoft.Authorization/policySetDefinitions/init1"
        psd.name = "init1"
        psd.display_name = "Security initiative"
        psd.description = "Groups security policies"
        psd.policy_type = "Custom"
        psd.policy_definitions = [ref]
        psd.parameters = {}
        psd.metadata = {}
        mock_client_cls.return_value.policy_set_definitions.list.return_value = [psd]

        result = list_custom_policy_set_definitions(mock_credential, "sub-1")

        assert len(result) == 1
        assert result[0]["name"] == "init1"
        assert result[0]["display_name"] == "Security initiative"
        assert len(result[0]["policy_definitions"]) == 1

    @patch("tenova.policy.PolicyClient")
    def test_skips_builtin_initiatives(self, mock_client_cls, mock_credential):
        builtin = MagicMock()
        builtin.policy_type = "BuiltIn"
        mock_client_cls.return_value.policy_set_definitions.list.return_value = [builtin]

        result = list_custom_policy_set_definitions(mock_credential, "sub-1")

        assert result == []


class TestExportPolicies:
    @patch("tenova.policy.PolicyClient")
    def test_export_creates_json_file(self, mock_client_cls, mock_credential, tmp_path):
        # Mock policy assignments
        pa = MagicMock()
        pa.id = "pa-id"
        pa.name = "pa-name"
        pa.display_name = "Test assignment"
        pa.description = ""
        pa.policy_definition_id = "pd-id"
        pa.scope = "/subscriptions/s"
        pa.enforcement_mode = "Default"
        pa.parameters = {}
        pa.not_scopes = []
        pa.identity = None
        mock_client_cls.return_value.policy_assignments.list.return_value = [pa]

        # Mock custom definitions — empty
        mock_client_cls.return_value.policy_definitions.list.return_value = []

        # Mock initiatives — empty
        mock_client_cls.return_value.policy_set_definitions.list.return_value = []

        filepath = export_policies(mock_credential, "sub-1", output_dir=tmp_path)

        assert filepath.exists()
        data = json.loads(filepath.read_text())
        assert data["subscription_id"] == "sub-1"
        assert len(data["policy_assignments"]) == 1
        assert data["policy_assignments"][0]["name"] == "pa-name"
        assert data["summary"]["policy_assignment_count"] == 1
        assert data["summary"]["custom_definition_count"] == 0
        assert data["summary"]["initiative_count"] == 0

    @patch("tenova.policy.PolicyClient")
    def test_export_filename_contains_subscription_prefix(self, mock_client_cls, mock_credential, tmp_path):
        mock_client_cls.return_value.policy_assignments.list.return_value = []
        mock_client_cls.return_value.policy_definitions.list.return_value = []
        mock_client_cls.return_value.policy_set_definitions.list.return_value = []

        filepath = export_policies(mock_credential, "abcd1234-5678", output_dir=tmp_path)

        assert "policy_export_abcd1234" in filepath.name

    @patch("tenova.policy.PolicyClient")
    def test_export_with_all_objects(self, mock_client_cls, mock_credential, tmp_path):
        # Assignment
        pa = MagicMock()
        pa.id = "pa-id"
        pa.name = "pa1"
        pa.display_name = "Assignment 1"
        pa.description = ""
        pa.policy_definition_id = "pd-id"
        pa.scope = "/subscriptions/s"
        pa.enforcement_mode = "Default"
        pa.parameters = {}
        pa.not_scopes = []
        pa.identity = None
        mock_client_cls.return_value.policy_assignments.list.return_value = [pa]

        # Custom definition
        custom_pd = MagicMock()
        custom_pd.id = "pd-id"
        custom_pd.name = "custom1"
        custom_pd.display_name = "Custom def"
        custom_pd.description = ""
        custom_pd.policy_type = "Custom"
        custom_pd.mode = "All"
        custom_pd.policy_rule = {}
        custom_pd.parameters = {}
        custom_pd.metadata = {}
        mock_client_cls.return_value.policy_definitions.list.return_value = [custom_pd]

        # Initiative
        ref = MagicMock()
        ref.policy_definition_id = "pd-id"
        ref.parameters = {}
        psd = MagicMock()
        psd.id = "psd-id"
        psd.name = "init1"
        psd.display_name = "Initiative 1"
        psd.description = ""
        psd.policy_type = "Custom"
        psd.policy_definitions = [ref]
        psd.parameters = {}
        psd.metadata = {}
        mock_client_cls.return_value.policy_set_definitions.list.return_value = [psd]

        filepath = export_policies(mock_credential, "sub-1", output_dir=tmp_path)

        data = json.loads(filepath.read_text())
        assert data["summary"]["policy_assignment_count"] == 1
        assert data["summary"]["custom_definition_count"] == 1
        assert data["summary"]["initiative_count"] == 1
