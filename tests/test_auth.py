"""Tests for the authentication module."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from tenova.auth import AuthMethod, get_credential
from tenova.exceptions import AuthenticationError


class TestGetCredential:
    """Tests for ``get_credential``."""

    @patch("tenova.auth.AzureCliCredential")
    def test_cli_credential_success(self, mock_cli_cls):
        """CLI credential should be returned when method is 'cli'."""
        mock_cred = MagicMock()
        mock_token = MagicMock()
        mock_token.token = "tok"
        mock_cred.get_token.return_value = mock_token
        mock_cli_cls.return_value = mock_cred

        result = get_credential(method=AuthMethod.CLI)

        mock_cli_cls.assert_called_once()
        assert result is mock_cred

    @patch("tenova.auth.AzureCliCredential")
    def test_cli_credential_with_tenant(self, mock_cli_cls):
        """tenant_id should be forwarded to AzureCliCredential."""
        mock_cred = MagicMock()
        mock_token = MagicMock()
        mock_token.token = "tok"
        mock_cred.get_token.return_value = mock_token
        mock_cli_cls.return_value = mock_cred

        get_credential(method="cli", tenant_id="my-tenant")

        mock_cli_cls.assert_called_once_with(tenant_id="my-tenant")

    @patch("tenova.auth.ClientSecretCredential")
    def test_service_principal_credential(self, mock_sp_cls):
        mock_cred = MagicMock()
        mock_token = MagicMock()
        mock_token.token = "tok"
        mock_cred.get_token.return_value = mock_token
        mock_sp_cls.return_value = mock_cred

        result = get_credential(
            method=AuthMethod.SERVICE_PRINCIPAL,
            tenant_id="t",
            client_id="c",
            client_secret="s",
        )

        mock_sp_cls.assert_called_once_with(tenant_id="t", client_id="c", client_secret="s")
        assert result is mock_cred

    def test_service_principal_missing_params(self):
        """Should raise AuthenticationError when required params are missing."""
        with pytest.raises(AuthenticationError, match="requires"):
            get_credential(method=AuthMethod.SERVICE_PRINCIPAL, tenant_id="t")

    @patch("tenova.auth.DefaultAzureCredential")
    def test_default_credential(self, mock_default_cls):
        mock_cred = MagicMock()
        mock_token = MagicMock()
        mock_token.token = "tok"
        mock_cred.get_token.return_value = mock_token
        mock_default_cls.return_value = mock_cred

        result = get_credential(method=AuthMethod.DEFAULT)
        assert result is mock_cred

    def test_invalid_auth_method(self):
        """Unknown auth method should raise ValueError."""
        with pytest.raises(ValueError):
            get_credential(method="not_a_real_method")
