"""Tests for the runbook generator module."""

from __future__ import annotations

from tenova.runbook import enrich_with_commands, generate_runbook


# ── Shared fixtures ───────────────────────────────────────────────────

_SAMPLE_SCAN = {
    "transfer_safe": [
        {
            "name": "vm-web-01",
            "type": "Microsoft.Compute/virtualMachines",
            "resource_group": "rg-prod",
            "location": "eastus",
        },
        {
            "name": "nsg-web",
            "type": "Microsoft.Network/networkSecurityGroups",
            "resource_group": "rg-prod",
            "location": "eastus",
        },
    ],
    "requires_action": [
        {
            "name": "kv-prod",
            "type": "Microsoft.KeyVault/vaults",
            "resource_group": "rg-prod",
            "location": "eastus",
            "timing": "both",
            "pre_action": "Remove all access policies before transfer.",
            "post_action": "Re-add access policies after transfer.",
            "doc_url": "https://learn.microsoft.com/en-us/azure/key-vault/general/move-subscription",
        },
        {
            "name": "sql-prod",
            "type": "Microsoft.Sql/servers",
            "resource_group": "rg-data",
            "location": "westus",
            "timing": "pre",
            "pre_action": "Disable Entra authentication.",
            "post_action": "",
            "doc_url": "https://learn.microsoft.com/en-us/azure/azure-sql/database/move-resources-across-regions",
        },
    ],
    "transfer_notes": {
        "Conditional Access": "Review and recreate Conditional Access policies referencing this subscription.",
    },
}

_HIERARCHICAL_SCAN = {
    "transfer_safe": [],
    "requires_action": [
        {
            "name": "arc-server-01",
            "type": "Microsoft.HybridCompute/machines",
            "resource_group": "rg-arc",
            "location": "eastus",
            "timing": "post",
            "pre_action": "Document Arc agent config.",
            "post_action": "Re-onboard Arc agent.",
            "doc_url": "",
            "children": [
                {
                    "name": "MicrosoftMonitoringAgent",
                    "type": "Microsoft.HybridCompute/machines/extensions",
                    "resource_group": "rg-arc",
                    "location": "eastus",
                    "timing": "post",
                    "pre_action": "",
                    "post_action": "Reinstall extension.",
                    "doc_url": "",
                },
            ],
        },
    ],
}

_EMPTY_SCAN = {
    "transfer_safe": [],
    "requires_action": [],
}

_SUB_ID = "12345678-aaaa-bbbb-cccc-dddddddddddd"
_TARGET_TENANT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


# ── Basic generation tests ────────────────────────────────────────────

class TestGenerateRunbook:
    def test_returns_string(self):
        result = generate_runbook(_SAMPLE_SCAN, _SUB_ID, _TARGET_TENANT)
        assert isinstance(result, str)

    def test_contains_header(self):
        result = generate_runbook(_SAMPLE_SCAN, _SUB_ID, _TARGET_TENANT)
        assert f"# Migration Runbook — Subscription `{_SUB_ID}`" in result

    def test_contains_subscription_id(self):
        result = generate_runbook(_SAMPLE_SCAN, _SUB_ID, _TARGET_TENANT)
        assert _SUB_ID in result

    def test_contains_target_tenant(self):
        result = generate_runbook(_SAMPLE_SCAN, _SUB_ID, _TARGET_TENANT)
        assert _TARGET_TENANT in result

    def test_contains_three_phases(self):
        result = generate_runbook(_SAMPLE_SCAN, _SUB_ID, _TARGET_TENANT)
        assert "## Phase 1: PRE-TRANSFER" in result
        assert "## Phase 2: TRANSFER" in result
        assert "## Phase 3: POST-TRANSFER" in result

    def test_contains_validation_checklist(self):
        result = generate_runbook(_SAMPLE_SCAN, _SUB_ID, _TARGET_TENANT)
        assert "## Validation Checklist" in result

    def test_contains_rollback_plan(self):
        result = generate_runbook(_SAMPLE_SCAN, _SUB_ID, _TARGET_TENANT)
        assert "## Rollback Plan" in result

    def test_transfer_safe_count(self):
        result = generate_runbook(_SAMPLE_SCAN, _SUB_ID, _TARGET_TENANT)
        assert "**Transfer-Safe Resources:** 2" in result

    def test_requires_action_count(self):
        result = generate_runbook(_SAMPLE_SCAN, _SUB_ID, _TARGET_TENANT)
        assert "**Requires-Action Resources:** 2" in result


# ── CLI command population tests ──────────────────────────────────────

class TestCLICommandPopulation:
    def test_keyvault_commands_populated(self):
        result = generate_runbook(_SAMPLE_SCAN, _SUB_ID, _TARGET_TENANT)
        # Key Vault pre-transfer step should have the vault name
        assert 'az keyvault show --name "kv-prod"' in result
        assert f"--subscription {_SUB_ID}" in result

    def test_sql_commands_populated(self):
        result = generate_runbook(_SAMPLE_SCAN, _SUB_ID, _TARGET_TENANT)
        # SQL Server pre-transfer: disable Entra admin
        assert 'az sql server ad-admin delete --server-name "sql-prod"' in result
        assert '--resource-group "rg-data"' in result

    def test_portal_link_contains_subscription(self):
        result = generate_runbook(_SAMPLE_SCAN, _SUB_ID, _TARGET_TENANT)
        assert f"https://portal.azure.com/#@/resource/subscriptions/{_SUB_ID}/changeDirectory" in result


# ── Transfer notes tests ─────────────────────────────────────────────

class TestTransferNotes:
    def test_transfer_notes_rendered(self):
        result = generate_runbook(_SAMPLE_SCAN, _SUB_ID, _TARGET_TENANT)
        assert "## Tenant-Level Notes" in result
        assert "Conditional Access" in result

    def test_no_transfer_notes_section_when_empty(self):
        result = generate_runbook(_EMPTY_SCAN, _SUB_ID, _TARGET_TENANT)
        assert "## Tenant-Level Notes" not in result


# ── Hierarchical resource tests ───────────────────────────────────────

class TestHierarchicalResources:
    def test_children_are_flattened(self):
        result = generate_runbook(_HIERARCHICAL_SCAN, _SUB_ID, _TARGET_TENANT)
        # Both parent and child should appear
        assert "arc-server-01" in result
        assert "MicrosoftMonitoringAgent" in result

    def test_child_commands_populated(self):
        result = generate_runbook(_HIERARCHICAL_SCAN, _SUB_ID, _TARGET_TENANT)
        # Child type is Microsoft.HybridCompute/machines/extensions
        assert "Reinstall" in result


# ── Empty scan tests ─────────────────────────────────────────────────

class TestEmptyScan:
    def test_empty_scan_returns_valid_markdown(self):
        result = generate_runbook(_EMPTY_SCAN, _SUB_ID, _TARGET_TENANT)
        assert isinstance(result, str)
        assert "# Migration Runbook" in result

    def test_empty_scan_shows_no_pre_steps(self):
        result = generate_runbook(_EMPTY_SCAN, _SUB_ID, _TARGET_TENANT)
        assert "*No pre-transfer steps required.*" in result

    def test_empty_scan_shows_no_post_steps(self):
        result = generate_runbook(_EMPTY_SCAN, _SUB_ID, _TARGET_TENANT)
        assert "*No post-transfer steps required.*" in result

    def test_empty_scan_has_zero_requires_action(self):
        result = generate_runbook(_EMPTY_SCAN, _SUB_ID, _TARGET_TENANT)
        assert "**Requires-Action Resources:** 0" in result


# ── Default target tenant tests ──────────────────────────────────────

class TestDefaultTargetTenant:
    def test_default_placeholder_when_omitted(self):
        result = generate_runbook(_SAMPLE_SCAN, _SUB_ID)
        assert "<TARGET_TENANT_ID>" in result


# ── Manual steps tests ───────────────────────────────────────────────

class TestManualSteps:
    """Resources without CLI templates should appear under Manual Steps."""

    def test_unknown_type_appears_in_manual_steps(self):
        scan = {
            "transfer_safe": [],
            "requires_action": [
                {
                    "name": "custom-widget",
                    "type": "Microsoft.CustomProviders/resourceProviders",
                    "resource_group": "rg-custom",
                    "location": "eastus",
                    "timing": "post",
                    "pre_action": "",
                    "post_action": "Reconfigure the widget.",
                    "doc_url": "https://example.com/docs",
                },
            ],
        }
        result = generate_runbook(scan, _SUB_ID, _TARGET_TENANT)
        assert "## Additional Manual Steps" in result
        assert "custom-widget" in result
        assert "Reconfigure the widget." in result
        assert "https://example.com/docs" in result

    def test_no_manual_section_when_all_templated(self):
        result = generate_runbook(_SAMPLE_SCAN, _SUB_ID, _TARGET_TENANT)
        assert "## Additional Manual Steps" not in result


# ── enrich_with_commands tests ────────────────────────────────────────

class TestEnrichWithCommands:
    def test_returns_dict(self):
        result = enrich_with_commands(_SAMPLE_SCAN, _SUB_ID)
        assert isinstance(result, dict)

    def test_preserves_transfer_safe(self):
        result = enrich_with_commands(_SAMPLE_SCAN, _SUB_ID)
        assert result["transfer_safe"] == _SAMPLE_SCAN["transfer_safe"]

    def test_injects_cli_commands_key(self):
        result = enrich_with_commands(_SAMPLE_SCAN, _SUB_ID)
        for r in result["requires_action"]:
            assert "cli_commands" in r
            assert "pre" in r["cli_commands"]
            assert "post" in r["cli_commands"]

    def test_keyvault_has_pre_commands(self):
        result = enrich_with_commands(_SAMPLE_SCAN, _SUB_ID)
        kv = result["requires_action"][0]
        assert kv["name"] == "kv-prod"
        assert len(kv["cli_commands"]["pre"]) > 0
        # Verify subscription ID is populated
        assert _SUB_ID in kv["cli_commands"]["pre"][0]["command"]

    def test_keyvault_has_post_commands(self):
        result = enrich_with_commands(_SAMPLE_SCAN, _SUB_ID)
        kv = result["requires_action"][0]
        assert len(kv["cli_commands"]["post"]) > 0

    def test_sql_has_pre_commands(self):
        result = enrich_with_commands(_SAMPLE_SCAN, _SUB_ID)
        sql = result["requires_action"][1]
        assert sql["name"] == "sql-prod"
        assert len(sql["cli_commands"]["pre"]) > 0
        assert "sql-prod" in sql["cli_commands"]["pre"][0]["command"]

    def test_command_has_description_and_command(self):
        result = enrich_with_commands(_SAMPLE_SCAN, _SUB_ID)
        kv = result["requires_action"][0]
        cmd = kv["cli_commands"]["pre"][0]
        assert "description" in cmd
        assert "command" in cmd
        assert isinstance(cmd["description"], str)
        assert isinstance(cmd["command"], str)

    def test_unknown_type_has_empty_commands(self):
        scan = {
            "transfer_safe": [],
            "requires_action": [
                {
                    "name": "widget",
                    "type": "Microsoft.CustomProviders/resourceProviders",
                    "resource_group": "rg",
                    "location": "eastus",
                },
            ],
        }
        result = enrich_with_commands(scan, _SUB_ID)
        w = result["requires_action"][0]
        assert w["cli_commands"]["pre"] == []
        assert w["cli_commands"]["post"] == []

    def test_children_are_enriched(self):
        result = enrich_with_commands(_HIERARCHICAL_SCAN, _SUB_ID)
        parent = result["requires_action"][0]
        assert "cli_commands" in parent
        child = parent["children"][0]
        assert "cli_commands" in child
        # Child type is HybridCompute/machines/extensions — has post commands
        assert len(child["cli_commands"]["post"]) > 0

    def test_does_not_mutate_original(self):
        import copy
        original = copy.deepcopy(_SAMPLE_SCAN)
        enrich_with_commands(_SAMPLE_SCAN, _SUB_ID)
        # Original should not have cli_commands injected
        assert "cli_commands" not in _SAMPLE_SCAN["requires_action"][0]
        assert _SAMPLE_SCAN == original

    def test_empty_scan(self):
        result = enrich_with_commands(_EMPTY_SCAN, _SUB_ID)
        assert result["requires_action"] == []

    def test_resource_name_in_commands(self):
        result = enrich_with_commands(_SAMPLE_SCAN, _SUB_ID)
        kv = result["requires_action"][0]
        # Check that resource name appears in at least one command
        all_cmds = kv["cli_commands"]["pre"] + kv["cli_commands"]["post"]
        name_found = any("kv-prod" in c["command"] for c in all_cmds)
        assert name_found
