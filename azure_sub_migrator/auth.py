# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""Authentication module for azure_sub_migrator.

Supports three credential strategies:
  1. Azure CLI credentials (default) — uses the logged-in ``az`` session.
  2. Service Principal — client-id / client-secret / tenant-id.
  3. Managed Identity — for running inside Azure (VM, Container, etc.).

All strategies return an ``azure.identity`` ``TokenCredential`` that can be
passed directly to any Azure SDK management client.
"""

from __future__ import annotations

from enum import Enum

from azure.core.credentials import TokenCredential
from azure.identity import (
    AzureCliCredential,
    ClientSecretCredential,
    DefaultAzureCredential,
    ManagedIdentityCredential,
)

from azure_sub_migrator.exceptions import AuthenticationError
from azure_sub_migrator.logger import get_logger

logger = get_logger("auth")


class AuthMethod(str, Enum):
    """Supported authentication methods."""

    CLI = "cli"
    SERVICE_PRINCIPAL = "service_principal"
    MANAGED_IDENTITY = "managed_identity"
    DEFAULT = "default"


def get_credential(
    method: str | AuthMethod = AuthMethod.CLI,
    *,
    tenant_id: str | None = None,
    client_id: str | None = None,
    client_secret: str | None = None,
) -> TokenCredential:
    """Return an Azure ``TokenCredential`` for the requested auth method.

    Parameters
    ----------
    method:
        One of ``"cli"``, ``"service_principal"``, ``"managed_identity"``,
        or ``"default"`` (chains multiple providers).
    tenant_id:
        Required for ``service_principal``.
    client_id:
        Required for ``service_principal``; optional for ``managed_identity``.
    client_secret:
        Required for ``service_principal``.

    Returns
    -------
    TokenCredential
        A credential object usable with any Azure SDK client.

    Raises
    ------
    AuthenticationError
        When required parameters are missing or credential creation fails.
    """
    method = AuthMethod(method)
    logger.info("Authenticating with method: %s", method.value)

    try:
        if method == AuthMethod.CLI:
            return _get_cli_credential(tenant_id=tenant_id)

        if method == AuthMethod.SERVICE_PRINCIPAL:
            return _get_service_principal_credential(
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=client_secret,
            )

        if method == AuthMethod.MANAGED_IDENTITY:
            return _get_managed_identity_credential(client_id=client_id)

        # Default: chained credential (CLI → Managed Identity → Environment)
        return _get_default_credential(tenant_id=tenant_id)

    except AuthenticationError:
        raise
    except Exception as exc:
        logger.exception("Authentication failed")
        raise AuthenticationError(f"Failed to authenticate with method '{method.value}': {exc}") from exc


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _get_cli_credential(*, tenant_id: str | None = None) -> AzureCliCredential:
    """Authenticate using the Azure CLI session."""
    kwargs: dict = {}
    if tenant_id:
        kwargs["tenant_id"] = tenant_id
    credential = AzureCliCredential(**kwargs)
    # Eagerly validate — fetch a token to confirm the CLI session is active
    _validate_credential(credential, label="Azure CLI")
    logger.info("Azure CLI credential acquired successfully")
    return credential


def _get_service_principal_credential(
    *,
    tenant_id: str | None,
    client_id: str | None,
    client_secret: str | None,
) -> ClientSecretCredential:
    """Authenticate using a service principal (client-id + secret)."""
    if not all([tenant_id, client_id, client_secret]):
        raise AuthenticationError(
            "Service-principal authentication requires --tenant-id, "
            "--client-id, and --client-secret."
        )
    credential = ClientSecretCredential(
        tenant_id=tenant_id,  # type: ignore[arg-type]
        client_id=client_id,  # type: ignore[arg-type]
        client_secret=client_secret,  # type: ignore[arg-type]
    )
    _validate_credential(credential, label="Service Principal")
    logger.info("Service-principal credential acquired successfully")
    return credential


def _get_managed_identity_credential(
    *, client_id: str | None = None,
) -> ManagedIdentityCredential:
    """Authenticate using a managed identity."""
    kwargs: dict = {}
    if client_id:
        kwargs["client_id"] = client_id
    credential = ManagedIdentityCredential(**kwargs)
    _validate_credential(credential, label="Managed Identity")
    logger.info("Managed-identity credential acquired successfully")
    return credential


def _get_default_credential(*, tenant_id: str | None = None) -> DefaultAzureCredential:
    """Use the ``DefaultAzureCredential`` chain."""
    kwargs: dict = {}
    if tenant_id:
        kwargs["tenant_id"] = tenant_id
    credential = DefaultAzureCredential(**kwargs)
    _validate_credential(credential, label="DefaultAzureCredential")
    logger.info("DefaultAzureCredential acquired successfully")
    return credential


def _validate_credential(credential: TokenCredential, *, label: str) -> None:
    """Eagerly request a token to verify the credential is valid.

    Uses the Azure Resource Manager scope which is universally available.
    """
    scope = "https://management.azure.com/.default"
    try:
        token = credential.get_token(scope)
        if not token.token:
            raise AuthenticationError(f"{label}: received an empty token.")
    except AuthenticationError:
        raise
    except Exception as exc:
        raise AuthenticationError(
            f"{label}: unable to obtain a token for scope '{scope}'. "
            f"Ensure you are logged in or credentials are correct. Detail: {exc}"
        ) from exc
