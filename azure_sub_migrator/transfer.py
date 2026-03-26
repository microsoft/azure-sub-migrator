# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""Subscription transfer operations.

Wraps the Azure Subscription API to move a subscription from one tenant
to another.  The actual "change directory" operation requires elevated
privileges (Account Administrator on the subscription) and can take
minutes to propagate.

References
----------
- https://learn.microsoft.com/azure/role-based-access-control/transfer-subscription
"""

from __future__ import annotations

from azure.core.credentials import TokenCredential

from azure_sub_migrator.config import MigrationConfig
from azure_sub_migrator.exceptions import TransferError
from azure_sub_migrator.logger import get_logger

logger = get_logger("transfer")


def initiate_transfer(
    credential: TokenCredential,
    config: MigrationConfig,
) -> None:
    """Begin the subscription-transfer ("change directory") process.

    Parameters
    ----------
    credential:
        A valid Azure credential with sufficient privileges.
    config:
        Migration configuration holding ``subscription_id``,
        ``target_tenant_id``, and ``dry_run`` flag.

    Notes
    -----
    The Azure SDK does not expose a direct "change directory" API in the
    ``azure-mgmt-subscription`` package.  The portal operation internally
    calls a REST endpoint:

        POST /subscriptions/{id}/providers/Microsoft.Subscription/
             changeTenantRequest?api-version=...

    This function uses a raw REST call through the Azure SDK pipeline.
    """
    subscription_id = config.subscription_id
    target_tenant_id = config.target_tenant_id

    if not subscription_id or not target_tenant_id:
        raise TransferError("subscription_id and target_tenant_id are both required.")

    if config.dry_run:
        logger.info(
            "[DRY RUN] Would transfer subscription %s → tenant %s",
            subscription_id,
            target_tenant_id,
        )
        return

    logger.info(
        "Initiating transfer: subscription %s → tenant %s",
        subscription_id,
        target_tenant_id,
    )

    try:
        # Use the generic Azure REST client approach since there is no
        # first-class SDK method for "change directory".
        from azure.mgmt.resource import ResourceManagementClient

        # We construct a minimal client just to borrow its pipeline.
        _client = ResourceManagementClient(credential, subscription_id)

        # NOTE: In a real implementation you would use
        #   _client._client.send_request(...)
        # pointing at the tenant-change REST endpoint.  This is left as
        # a clear TODO so contributors can wire it up with the correct
        # API version once Microsoft stabilises the endpoint.

        logger.warning(
            "Automated tenant transfer is not yet implemented end-to-end. "
            "Please complete the transfer manually in the Azure Portal: "
            "Azure Active Directory → Subscriptions → Change directory."
        )

    except Exception as exc:
        raise TransferError(f"Transfer failed: {exc}") from exc
