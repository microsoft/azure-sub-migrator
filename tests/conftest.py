"""Shared pytest fixtures for tenova tests."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest


@pytest.fixture()
def mock_credential():
    """Return a mock Azure TokenCredential."""
    cred = MagicMock()
    token = MagicMock()
    token.token = "mock-access-token"
    cred.get_token.return_value = token
    return cred


@pytest.fixture()
def sample_subscription_id() -> str:
    return "00000000-0000-0000-0000-000000000001"


@pytest.fixture()
def sample_tenant_id() -> str:
    return "00000000-0000-0000-0000-000000000002"
