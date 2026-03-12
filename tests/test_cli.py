"""Tests for the CLI interface."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from tenova.cli import cli


class TestCLI:
    def test_help(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "Tenova" in result.output

    def test_version(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output

    @patch("tenova.cli.get_credential")
    def test_login_success(self, mock_get_cred):
        mock_cred = MagicMock()
        mock_get_cred.return_value = mock_cred

        runner = CliRunner()
        result = runner.invoke(cli, ["login"], obj={})
        assert result.exit_code == 0
        assert "Authentication successful" in result.output

    @patch("tenova.cli.get_credential", side_effect=Exception("no creds"))
    def test_login_failure(self, mock_get_cred):
        runner = CliRunner()
        result = runner.invoke(cli, ["login"], obj={})
        assert result.exit_code == 1
        assert "Authentication failed" in result.output

    @patch("tenova.scanner.list_subscriptions")
    @patch("tenova.cli.get_credential")
    def test_list_subs(self, mock_get_cred, mock_list_subs):
        mock_get_cred.return_value = MagicMock()
        mock_list_subs.return_value = [
            {"subscription_id": "sub-1", "display_name": "Test", "state": "Enabled"},
        ]

        runner = CliRunner()
        result = runner.invoke(cli, ["list-subs"], obj={})
        assert result.exit_code == 0
        assert "sub-1" in result.output
