# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""Custom exceptions for azure_sub_migrator."""


class AzTenantMigrateError(Exception):
    """Base exception for the migration tool."""


class AuthenticationError(AzTenantMigrateError):
    """Raised when authentication to Azure fails."""


class SubscriptionNotFoundError(AzTenantMigrateError):
    """Raised when the specified subscription cannot be found."""


class ResourceScanError(AzTenantMigrateError):
    """Raised when resource scanning encounters an error."""


class IaCGenerationError(AzTenantMigrateError):
    """Raised when IaC template generation fails."""


class TransferError(AzTenantMigrateError):
    """Raised when the subscription transfer process fails."""


class RBACError(AzTenantMigrateError):
    """Raised when role-assignment or managed-identity operations fail."""


class ExternalToolError(AzTenantMigrateError):
    """Raised when an external tool (aztfexport, azcopy, etc.) fails."""
