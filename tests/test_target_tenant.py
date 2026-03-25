# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""Tests for the target-tenant OAuth & Graph helpers."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from azure_sub_migrator.target_tenant import (
    build_target_auth_url,
    get_directory_object,
    redeem_target_auth_code,
    search_groups,
    search_service_principals,
    search_users,
)

# ──────────────────────────────────────────────────────────────────────
# build_target_auth_url
# ──────────────────────────────────────────────────────────────────────

class TestBuildTargetAuthUrl:
    def test_returns_url_with_tenant(self):
        url = build_target_auth_url(
            client_id="cid",
            target_tenant_id="tid-123",
            redirect_uri="https://localhost/callback",
            state="some-state",
        )
        assert "login.microsoftonline.com/tid-123" in url
        assert "client_id=cid" in url
        assert "state=some-state" in url
        assert "response_type=code" in url

    def test_default_scope(self):
        url = build_target_auth_url(
            client_id="cid",
            target_tenant_id="tid-123",
            redirect_uri="https://localhost/cb",
            state="s",
        )
        assert "Directory.Read.All" in url
        assert "User.Read" in url

    def test_custom_scopes(self):
        url = build_target_auth_url(
            client_id="cid",
            target_tenant_id="tid",
            redirect_uri="https://localhost/cb",
            state="s",
            scopes=["https://graph.microsoft.com/.default"],
        )
        assert "graph.microsoft.com" in url


# ──────────────────────────────────────────────────────────────────────
# redeem_target_auth_code
# ──────────────────────────────────────────────────────────────────────

class TestRedeemTargetAuthCode:
    @patch("msal.ConfidentialClientApplication")
    def test_success(self, mock_cca_cls):
        mock_app = MagicMock()
        mock_app.acquire_token_by_authorization_code.return_value = {
            "access_token": "at-123",
            "id_token_claims": {"preferred_username": "user@target.com"},
        }
        mock_cca_cls.return_value = mock_app

        result = redeem_target_auth_code(
            client_id="cid",
            client_credential="secret",
            target_tenant_id="tid",
            code="authcode",
            redirect_uri="https://localhost/cb",
        )

        assert result["access_token"] == "at-123"
        mock_cca_cls.assert_called_once_with(
            client_id="cid",
            client_credential="secret",
            authority="https://login.microsoftonline.com/tid",
        )

    @patch("msal.ConfidentialClientApplication")
    def test_error(self, mock_cca_cls):
        mock_app = MagicMock()
        mock_app.acquire_token_by_authorization_code.return_value = {
            "error": "invalid_grant",
            "error_description": "Code expired",
        }
        mock_cca_cls.return_value = mock_app

        result = redeem_target_auth_code(
            client_id="cid",
            client_credential="secret",
            target_tenant_id="tid",
            code="bad-code",
            redirect_uri="https://localhost/cb",
        )

        assert "error" in result


# ──────────────────────────────────────────────────────────────────────
# Graph search functions
# ──────────────────────────────────────────────────────────────────────

class TestSearchUsers:
    @patch("azure_sub_migrator.target_tenant.requests.get")
    def test_returns_users(self, mock_get):
        mock_get.return_value = MagicMock(
            status_code=200,
            json=lambda: {"value": [{"id": "u1", "displayName": "Alice"}]},
        )
        mock_get.return_value.raise_for_status = MagicMock()

        result = search_users("token", upn="alice@example.com")
        assert len(result) == 1
        assert result[0]["displayName"] == "Alice"

    @patch("azure_sub_migrator.target_tenant.requests.get")
    def test_empty_on_no_params(self, mock_get):
        result = search_users("token")
        assert result == []
        mock_get.assert_not_called()

    @patch("azure_sub_migrator.target_tenant.requests.get")
    def test_handles_exception(self, mock_get):
        mock_get.side_effect = Exception("network error")
        result = search_users("token", display_name="Bob")
        assert result == []


class TestSearchGroups:
    @patch("azure_sub_migrator.target_tenant.requests.get")
    def test_returns_groups(self, mock_get):
        mock_get.return_value = MagicMock(
            status_code=200,
            json=lambda: {"value": [{"id": "g1", "displayName": "DevTeam"}]},
        )
        mock_get.return_value.raise_for_status = MagicMock()

        result = search_groups("token", display_name="Dev")
        assert len(result) == 1
        assert result[0]["id"] == "g1"


class TestSearchServicePrincipals:
    @patch("azure_sub_migrator.target_tenant.requests.get")
    def test_returns_sps(self, mock_get):
        mock_get.return_value = MagicMock(
            status_code=200,
            json=lambda: {"value": [{"id": "sp1", "displayName": "MyApp"}]},
        )
        mock_get.return_value.raise_for_status = MagicMock()

        result = search_service_principals("token", display_name="My")
        assert len(result) == 1
        assert result[0]["id"] == "sp1"


class TestGetDirectoryObject:
    @patch("azure_sub_migrator.target_tenant.requests.get")
    def test_returns_object(self, mock_get):
        mock_get.return_value = MagicMock(
            status_code=200,
            json=lambda: {"id": "obj-1", "displayName": "Alice"},
        )
        mock_get.return_value.raise_for_status = MagicMock()

        result = get_directory_object("token", "obj-1")
        assert result["displayName"] == "Alice"

    @patch("azure_sub_migrator.target_tenant.requests.get")
    def test_returns_none_on_404(self, mock_get):
        mock_get.return_value = MagicMock(status_code=404)
        result = get_directory_object("token", "missing-id")
        assert result is None

    @patch("azure_sub_migrator.target_tenant.requests.get")
    def test_returns_none_on_exception(self, mock_get):
        mock_get.side_effect = Exception("fail")
        result = get_directory_object("token", "obj-1")
        assert result is None
