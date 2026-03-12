"""Tests for the principal mapping module."""

from __future__ import annotations

from unittest.mock import patch

from tenova.principal_map import (
    _friendly_type,
    build_mapping,
    extract_principals,
    resolve_source_principals,
    suggest_mappings,
)

# ──────────────────────────────────────────────────────────────────────
# extract_principals
# ──────────────────────────────────────────────────────────────────────

class TestExtractPrincipals:
    def test_deduplicates(self):
        export = {
            "role_assignments": [
                {"principal_id": "p1", "principal_type": "User", "scope": "/sub/s"},
                {"principal_id": "p1", "principal_type": "User", "scope": "/sub/s/rg"},
                {"principal_id": "p2", "principal_type": "Group", "scope": "/sub/s"},
            ],
        }
        result = extract_principals(export)
        assert len(result) == 2
        p1 = next(p for p in result if p["principal_id"] == "p1")
        assert len(p1["scopes"]) == 2

    def test_empty_export(self):
        result = extract_principals({})
        assert result == []

    def test_skips_empty_principal_id(self):
        export = {
            "role_assignments": [
                {"principal_id": "", "principal_type": "User", "scope": "/sub/s"},
                {"principal_id": "p1", "principal_type": "User", "scope": "/sub/s"},
            ],
        }
        result = extract_principals(export)
        assert len(result) == 1


# ──────────────────────────────────────────────────────────────────────
# resolve_source_principals
# ──────────────────────────────────────────────────────────────────────

class TestResolveSourcePrincipals:
    @patch("tenova.principal_map.get_directory_object")
    def test_enriches_principals(self, mock_get_obj):
        mock_get_obj.return_value = {
            "@odata.type": "#microsoft.graph.user",
            "displayName": "Alice",
            "userPrincipalName": "alice@source.com",
            "mail": "alice@source.com",
        }
        principals = [
            {"principal_id": "p1", "principal_type": "User", "scopes": ["/sub/s"]},
        ]
        result = resolve_source_principals(principals, "source-token")

        assert result[0]["display_name"] == "Alice"
        assert result[0]["upn"] == "alice@source.com"
        assert result[0]["object_type"] == "User"

    @patch("tenova.principal_map.get_directory_object")
    def test_unknown_when_not_found(self, mock_get_obj):
        mock_get_obj.return_value = None
        principals = [
            {"principal_id": "p-gone", "principal_type": "User", "scopes": ["/sub/s"]},
        ]
        result = resolve_source_principals(principals, "source-token")

        assert result[0]["display_name"] == "(unknown)"
        assert result[0]["object_type"] == "User"


# ──────────────────────────────────────────────────────────────────────
# suggest_mappings
# ──────────────────────────────────────────────────────────────────────

class TestSuggestMappings:
    @patch("tenova.principal_map.search_users")
    def test_upn_match_high_confidence(self, mock_search):
        mock_search.return_value = [
            {"id": "new-p1", "displayName": "Alice", "userPrincipalName": "alice@target.com"},
        ]
        principals = [{
            "principal_id": "old-p1",
            "object_type": "User",
            "display_name": "Alice",
            "upn": "alice@target.com",
            "mail": "",
        }]
        result = suggest_mappings(principals, "target-token")

        assert len(result[0]["suggestions"]) == 1
        assert result[0]["suggestions"][0]["confidence"] == "high"
        assert result[0]["suggestions"][0]["id"] == "new-p1"

    @patch("tenova.principal_map.search_groups")
    def test_group_match(self, mock_search):
        mock_search.return_value = [
            {"id": "new-g1", "displayName": "DevTeam"},
        ]
        principals = [{
            "principal_id": "old-g1",
            "object_type": "Group",
            "display_name": "DevTeam",
            "upn": "",
            "mail": "",
        }]
        result = suggest_mappings(principals, "target-token")

        assert len(result[0]["suggestions"]) == 1
        assert result[0]["suggestions"][0]["confidence"] == "medium"

    @patch("tenova.principal_map.search_service_principals")
    def test_sp_match(self, mock_search):
        mock_search.return_value = [
            {"id": "new-sp1", "displayName": "MyApp"},
        ]
        principals = [{
            "principal_id": "old-sp1",
            "object_type": "ServicePrincipal",
            "display_name": "MyApp",
            "upn": "",
            "mail": "",
        }]
        result = suggest_mappings(principals, "target-token")

        assert len(result[0]["suggestions"]) == 1
        assert result[0]["suggestions"][0]["id"] == "new-sp1"

    def test_no_suggestions_for_unknown(self):
        principals = [{
            "principal_id": "old-x",
            "object_type": "Unknown",
            "display_name": "(unknown)",
            "upn": "",
            "mail": "",
        }]
        result = suggest_mappings(principals, "target-token")
        assert result[0]["suggestions"] == []


# ──────────────────────────────────────────────────────────────────────
# build_mapping
# ──────────────────────────────────────────────────────────────────────

class TestBuildMapping:
    def test_uses_override(self):
        principals = [{
            "principal_id": "old-1",
            "suggestions": [{"id": "auto-1", "confidence": "high"}],
        }]
        mapping = build_mapping(principals, overrides={"old-1": "override-1"})
        assert mapping["old-1"] == "override-1"

    def test_auto_selects_high_confidence(self):
        principals = [{
            "principal_id": "old-1",
            "suggestions": [{"id": "auto-1", "confidence": "high"}],
        }]
        mapping = build_mapping(principals)
        assert mapping["old-1"] == "auto-1"

    def test_skips_medium_without_override(self):
        principals = [{
            "principal_id": "old-1",
            "suggestions": [{"id": "auto-1", "confidence": "medium"}],
        }]
        mapping = build_mapping(principals)
        assert "old-1" not in mapping

    def test_empty_override_skips(self):
        principals = [{
            "principal_id": "old-1",
            "suggestions": [{"id": "auto-1", "confidence": "high"}],
        }]
        mapping = build_mapping(principals, overrides={"old-1": ""})
        # Empty override is falsy → falls through to auto, which is high
        assert mapping["old-1"] == "auto-1"

    def test_no_suggestions_no_override(self):
        principals = [{
            "principal_id": "old-1",
            "suggestions": [],
        }]
        mapping = build_mapping(principals)
        assert mapping == {}


# ──────────────────────────────────────────────────────────────────────
# _friendly_type
# ──────────────────────────────────────────────────────────────────────

class TestFriendlyType:
    def test_user(self):
        assert _friendly_type("#microsoft.graph.user") == "User"

    def test_group(self):
        assert _friendly_type("#microsoft.graph.group") == "Group"

    def test_sp(self):
        assert _friendly_type("#microsoft.graph.servicePrincipal") == "ServicePrincipal"

    def test_unknown(self):
        assert _friendly_type("#microsoft.graph.wat") == "#microsoft.graph.wat"

    def test_empty(self):
        assert _friendly_type("") == "Unknown"
