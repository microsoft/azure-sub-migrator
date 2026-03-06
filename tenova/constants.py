"""Constants used across the migration tool.

Classification is based on the official Microsoft documentation for
cross-tenant subscription transfers:
https://learn.microsoft.com/en-us/azure/role-based-access-control/transfer-subscription

IMPORTANT: When you transfer a subscription to a different Entra ID tenant,
**all** resources physically move with the subscription.  Nothing is left
behind.  The real question is which resources BREAK or NEED RECONFIGURATION
after the transfer because they had tenant-bound dependencies (RBAC, managed
identities, Key Vault access policies, AAD-integrated auth, etc.).
"""

# ---------------------------------------------------------------------------
# Reference
# ---------------------------------------------------------------------------
MICROSOFT_TRANSFER_DOC_URL = (
    "https://learn.microsoft.com/en-us/azure/role-based-access-control/transfer-subscription"
)

# ---------------------------------------------------------------------------
# Resource types that REQUIRE ACTION after a cross-tenant transfer
# ---------------------------------------------------------------------------
# These resource types have tenant-bound dependencies.  They will transfer
# with the subscription, but they will be broken or degraded until the
# operator performs the required actions described in REQUIRED_ACTIONS.
IMPACTED_RESOURCE_TYPES: list[str] = [
    # ── Identity & RBAC (always impacted) ──────────────────────────
    # All RBAC role assignments are permanently deleted during transfer.
    # Custom roles are permanently deleted during transfer.    "Microsoft.Authorization/roleAssignments",
    "Microsoft.Authorization/roleDefinitions",    "Microsoft.ManagedIdentity/userAssignedIdentities",
    "Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials",

    # ── Key Vault ──────────────────────────────────────────────────
    # Tenant ID must be updated; all access policies are wiped.
    "Microsoft.KeyVault/vaults",
    "Microsoft.KeyVault/managedHSMs",

    # ── Entra Domain Services ─────────────────────────────────────
    # Cannot operate in a different tenant; must recreate.
    "Microsoft.AAD/domainServices",

    # ── AKS ────────────────────────────────────────────────────────
    # Cannot transfer cluster to a different directory.
    "Microsoft.ContainerService/managedClusters",

    # ── Databases with AAD auth ────────────────────────────────────
    # Azure SQL with Entra auth cannot be transferred.
    "Microsoft.Sql/servers",
    "Microsoft.Sql/managedInstances",
    # MySQL / PostgreSQL with Entra auth cannot be transferred.
    "Microsoft.DBforMySQL/flexibleServers",
    "Microsoft.DBforMySQL/servers",
    "Microsoft.DBforPostgreSQL/flexibleServers",
    "Microsoft.DBforPostgreSQL/servers",

    # ── Storage / Data Lake ────────────────────────────────────────
    # ACLs must be recreated; Kerberos auth needs re-enable.
    "Microsoft.Storage/storageAccounts",

    # ── Compute ────────────────────────────────────────────────────
    # Managed-identity-enabled VMs need identity disable/re-enable.
    "Microsoft.Compute/virtualMachines/extensions",
    # Disk Encryption Sets with CMK need identity + role fix.
    "Microsoft.Compute/diskEncryptionSets",

    # ── Azure Arc ──────────────────────────────────────────────────
    # Arc-connected machines and their extensions have tenant-bound identities.
    "Microsoft.HybridCompute/machines",
    "Microsoft.HybridCompute/machines/extensions",

    # ── Azure Policy ───────────────────────────────────────────────
    # All policy objects (definitions, assignments, exemptions) are deleted.
    "Microsoft.Authorization/policyAssignments",
    "Microsoft.Authorization/policyDefinitions",

    # ── Resource Locks ─────────────────────────────────────────────
    # Resource locks should be exported before transfer and recreated after.
    "Microsoft.Authorization/locks",

    # ── Azure Automation ───────────────────────────────────────────
    "Microsoft.Automation/automationAccounts",

    # ── Azure Data Factory ─────────────────────────────────────────
    "Microsoft.DataFactory/factories",

    # ── Logic Apps ─────────────────────────────────────────────────
    "Microsoft.Logic/workflows",

    # ── API Management ─────────────────────────────────────────────
    "Microsoft.ApiManagement/service",

    # ── App Configuration ──────────────────────────────────────────
    "Microsoft.AppConfiguration/configurationStores",

    # ── Purview / Microsoft Purview ────────────────────────────────
    "Microsoft.Purview/accounts",

    # ── Service Fabric ─────────────────────────────────────────────
    # Cluster must be recreated.
    "Microsoft.ServiceFabric/clusters",
    "Microsoft.ServiceFabric/managedClusters",

    # ── Service Bus ────────────────────────────────────────────────
    # Managed identities must be recreated + role assignments.
    "Microsoft.ServiceBus/namespaces",

    # ── Synapse Analytics ──────────────────────────────────────────
    # Tenant ID + Git config must be updated.
    "Microsoft.Synapse/workspaces",

    # ── Azure Databricks ───────────────────────────────────────────
    # Cannot transfer workspace to a new tenant.
    "Microsoft.Databricks/workspaces",

    # ── Dev Box / Deployment Environments ──────────────────────────
    "Microsoft.DevCenter/devcenters",
    "Microsoft.DevCenter/projects",

    # ── Azure File Sync ────────────────────────────────────────────
    "Microsoft.StorageSync/storageSyncServices",

    # ── Azure Compute Gallery ──────────────────────────────────────
    "Microsoft.Compute/galleries",
]

# ---------------------------------------------------------------------------
# Required actions per resource type with timing (pre / post / both)
# ---------------------------------------------------------------------------
# Based on the official Microsoft transfer documentation:
# https://learn.microsoft.com/en-us/azure/role-based-access-control/transfer-subscription
#
# timing = "pre"  → Must be done BEFORE the transfer or transfer will fail / cause data loss
# timing = "post" → Must be done AFTER the transfer to restore functionality
# timing = "both" → Has steps required both before AND after the transfer
#
REQUIRED_ACTIONS: dict[str, dict[str, str]] = {
    # ── RBAC ────────────────────────────────────────────────────────
    "Microsoft.Authorization/roleAssignments": {
        "timing": "pre",
        "pre": "⚠️ ALL role assignments are PERMANENTLY DELETED during transfer. Export assignments (az role assignment list --all --include-inherited > assignments.json) before transfer.",
        "post": "Map users, groups, and service principals to target-tenant objects. Recreate all role assignments.",
        "doc_url": "https://learn.microsoft.com/en-us/azure/role-based-access-control/transfer-subscription",
    },
    "Microsoft.Authorization/roleDefinitions": {
        "timing": "pre",
        "pre": "⚠️ ALL custom role definitions are PERMANENTLY DELETED during transfer. Export definitions (az role definition list --custom-role-only true > custom_roles.json) before transfer.",
        "post": "Recreate custom role definitions in the target tenant using the exported JSON, then recreate role assignments.",
        "doc_url": "https://learn.microsoft.com/en-us/azure/role-based-access-control/transfer-subscription",
    },

    # ── Identity ───────────────────────────────────────────────────
    "Microsoft.ManagedIdentity/userAssignedIdentities": {
        "timing": "both",
        "pre": "Document all resources using this identity and their role assignments.",
        "post": "Delete, recreate in target tenant, reattach to dependent resources, and recreate role assignments.",
        "doc_url": "https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/how-manage-user-assigned-managed-identities",
    },
    "Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials": {
        "timing": "post",
        "pre": "",
        "post": "Recreate federated identity credentials after recreating the parent identity.",
        "doc_url": "https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/how-manage-user-assigned-managed-identities",
    },

    # ── Key Vault ──────────────────────────────────────────────────
    "Microsoft.KeyVault/vaults": {
        "timing": "both",
        "pre": "⚠️ CRITICAL: If used for encryption-at-rest (Storage/SQL CMK), disable customer-managed keys BEFORE transfer to avoid UNRECOVERABLE DATA LOSS. Export access policies.",
        "post": "Update tenant ID (az keyvault update). Remove old access policies, add new policies for target-tenant principals.",
        "doc_url": "https://learn.microsoft.com/en-us/azure/key-vault/general/move-subscription",
    },
    "Microsoft.KeyVault/managedHSMs": {
        "timing": "both",
        "pre": "Export RBAC assignments and key references.",
        "post": "Update tenant ID and reconfigure RBAC for target-tenant principals.",
        "doc_url": "https://learn.microsoft.com/en-us/azure/key-vault/managed-hsm/overview",
    },

    # ── Entra Domain Services ─────────────────────────────────────
    "Microsoft.AAD/domainServices": {
        "timing": "pre",
        "pre": "⛔ CANNOT be transferred. Delete before transfer and recreate in target tenant. Back up any domain-joined configurations.",
        "post": "",
        "doc_url": "https://learn.microsoft.com/en-us/entra/identity/domain-services/faqs",
    },

    # ── AKS ────────────────────────────────────────────────────────
    "Microsoft.ContainerService/managedClusters": {
        "timing": "pre",
        "pre": "⛔ CANNOT be transferred. Export all workloads (kubectl), Helm charts, and configs before transfer. Cluster must be recreated in target tenant.",
        "post": "",
        "doc_url": "https://learn.microsoft.com/en-us/azure/aks/faq",
    },

    # ── Databases ──────────────────────────────────────────────────
    "Microsoft.Sql/servers": {
        "timing": "both",
        "pre": "⛔ CANNOT transfer with Entra auth enabled. Disable Entra authentication (remove the Entra admin from SQL Server → Microsoft Entra ID settings). Export databases (.bacpac) as backup.",
        "post": "Set a new Entra admin from the target tenant and re-enable Entra authentication.",
        "doc_url": "https://learn.microsoft.com/en-us/azure/azure-sql/database/authentication-aad-configure",
    },
    "Microsoft.Sql/managedInstances": {
        "timing": "both",
        "pre": "⛔ CANNOT transfer with Entra auth enabled. Disable Entra authentication (remove the Entra admin) before transfer.",
        "post": "Set a new Entra admin from the target tenant and re-enable Entra authentication.",
        "doc_url": "https://learn.microsoft.com/en-us/azure/azure-sql/database/authentication-aad-configure",
    },
    "Microsoft.DBforMySQL/flexibleServers": {
        "timing": "both",
        "pre": "⛔ CANNOT transfer with Entra auth enabled. Disable Entra authentication (Portal → Server → Authentication → remove Entra admin) before transfer.",
        "post": "Add a new Entra admin from the target tenant and re-enable Entra authentication.",
        "doc_url": "https://learn.microsoft.com/en-us/azure/mysql/flexible-server/how-to-azure-ad",
    },
    "Microsoft.DBforMySQL/servers": {
        "timing": "both",
        "pre": "⛔ CANNOT transfer with Entra auth enabled. Disable Entra authentication before transfer.",
        "post": "Add a new Entra admin from the target tenant and re-enable Entra authentication.",
        "doc_url": "https://learn.microsoft.com/en-us/azure/mysql/single-server/how-to-configure-sign-in-azure-ad-authentication",
    },
    "Microsoft.DBforPostgreSQL/flexibleServers": {
        "timing": "both",
        "pre": "⛔ CANNOT transfer with Entra auth or CMK enabled. Disable Entra authentication (Portal → Server → Authentication → remove Entra admin) and disable customer-managed keys before transfer.",
        "post": "Add a new Entra admin from the target tenant, re-enable Entra authentication, and reconfigure CMK.",
        "doc_url": "https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/how-to-configure-sign-in-azure-ad-authentication",
    },
    "Microsoft.DBforPostgreSQL/servers": {
        "timing": "both",
        "pre": "⛔ CANNOT transfer with Entra auth enabled. Disable Entra authentication before transfer.",
        "post": "Add a new Entra admin from the target tenant and re-enable Entra authentication.",
        "doc_url": "https://learn.microsoft.com/en-us/azure/postgresql/single-server/how-to-configure-sign-in-azure-ad-authentication",
    },

    # ── Storage / Data Lake ────────────────────────────────────────
    "Microsoft.Storage/storageAccounts": {
        "timing": "both",
        "pre": "Export ADLS Gen2 ACLs (Portal → Storage → Containers → Manage ACL) and Azure Files ACLs. If using Kerberos auth, note the domain and configuration.",
        "post": "Recreate ACLs on all containers/file shares. Disable and re-enable Kerberos authentication if applicable. Rotate storage access keys.",
        "doc_url": "https://learn.microsoft.com/en-us/azure/storage/blobs/data-lake-storage-access-control",
    },

    # ── Compute ────────────────────────────────────────────────────
    "Microsoft.Compute/virtualMachines/extensions": {
        "timing": "post",
        "pre": "",
        "post": "Remove and reinstall VM extensions that use Entra authentication (e.g. AADLoginForWindows, AADSSHLoginForLinux, MicrosoftMonitoringAgent with workspace binding).",
        "doc_url": "https://learn.microsoft.com/en-us/azure/active-directory/devices/howto-vm-sign-in-azure-ad-windows",
    },
    "Microsoft.Compute/diskEncryptionSets": {
        "timing": "both",
        "pre": "Document the Key Vault and key URI used for customer-managed key (CMK) encryption.",
        "post": "Disable and re-enable the system-assigned managed identity. Recreate Key Vault access role assignments (Key Vault Crypto Service Encryption User).",
        "doc_url": "https://learn.microsoft.com/en-us/azure/virtual-machines/disk-encryption",
    },

    # ── Azure Arc ──────────────────────────────────────────────────
    "Microsoft.HybridCompute/machines": {
        "timing": "both",
        "pre": "Document the Arc agent configuration and connected service principal.",
        "post": "Disconnect and re-onboard the Arc agent to the target tenant. The machine's managed identity is broken after transfer.",
        "doc_url": "https://learn.microsoft.com/en-us/azure/azure-arc/servers/overview",
    },
    "Microsoft.HybridCompute/machines/extensions": {
        "timing": "post",
        "pre": "",
        "post": "Remove and reinstall Arc VM extensions after re-onboarding the agent to the target tenant.",
        "doc_url": "https://learn.microsoft.com/en-us/azure/azure-arc/servers/manage-vm-extensions",
    },

    # ── Azure Policy ───────────────────────────────────────────────
    "Microsoft.Authorization/policyAssignments": {
        "timing": "pre",
        "pre": "⚠️ ALL policy assignments are PERMANENTLY DELETED during transfer. Export assignments (az policy assignment list > assignments.json) before transfer.",
        "post": "Reimport and reassign policies in target tenant using the exported JSON.",
        "doc_url": "https://learn.microsoft.com/en-us/azure/governance/policy/overview",
    },
    "Microsoft.Authorization/policyDefinitions": {
        "timing": "pre",
        "pre": "⚠️ ALL custom policy definitions are PERMANENTLY DELETED during transfer. Export definitions (az policy definition list --custom > definitions.json) before transfer.",
        "post": "Recreate custom policy definitions in target tenant using the exported JSON.",
        "doc_url": "https://learn.microsoft.com/en-us/azure/governance/policy/overview",
    },

    # ── Resource Locks ─────────────────────────────────────────────
    "Microsoft.Authorization/locks": {
        "timing": "pre",
        "pre": "⚠️ Resource locks should be exported before transfer. Export locks (az lock list > locks.json) before transfer.",
        "post": "Recreate resource locks (CanNotDelete, ReadOnly) on protected resources in the target tenant.",
        "doc_url": "https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/lock-resources",
    },

    # ── Azure Automation ───────────────────────────────────────────
    "Microsoft.Automation/automationAccounts": {
        "timing": "both",
        "pre": "Export runbooks (Portal → Automation Account → Runbooks → Export), schedules, credentials, and variables.",
        "post": "Delete and recreate the managed identity. Reimport runbooks and reconfigure linked schedules, credentials, and Run As connections.",
        "doc_url": "https://learn.microsoft.com/en-us/azure/automation/automation-security-overview",
    },

    # ── Azure Data Factory ─────────────────────────────────────────
    "Microsoft.DataFactory/factories": {
        "timing": "both",
        "pre": "Export pipeline definitions via ARM template or Git integration. Document all linked service configurations and credentials.",
        "post": "Delete and recreate the managed identity. Reconfigure linked services, update Key Vault references, and re-authorize Git integration.",
        "doc_url": "https://learn.microsoft.com/en-us/azure/data-factory/data-factory-service-identity",
    },

    # ── Logic Apps ─────────────────────────────────────────────────
    "Microsoft.Logic/workflows": {
        "timing": "post",
        "pre": "",
        "post": "Reauthorize API connections that use OAuth/Entra (Office 365, Teams, SharePoint connectors). Reconfigure managed identity bindings.",
        "doc_url": "https://learn.microsoft.com/en-us/azure/logic-apps/logic-apps-securing-a-logic-app",
    },

    # ── API Management ─────────────────────────────────────────────
    "Microsoft.ApiManagement/service": {
        "timing": "post",
        "pre": "",
        "post": "Delete and recreate the managed identity. Reconfigure Entra-based OAuth 2.0 policies (validate-jwt, authorize). Update developer portal identity providers.",
        "doc_url": "https://learn.microsoft.com/en-us/azure/api-management/api-management-howto-use-managed-service-identity",
    },

    # ── App Configuration ──────────────────────────────────────────
    "Microsoft.AppConfiguration/configurationStores": {
        "timing": "post",
        "pre": "",
        "post": "Delete and recreate the managed identity. Recreate RBAC role assignments (App Configuration Data Reader/Owner) for target-tenant principals.",
        "doc_url": "https://learn.microsoft.com/en-us/azure/azure-app-configuration/howto-integrate-azure-managed-service-identity",
    },

    # ── Purview ────────────────────────────────────────────────────
    "Microsoft.Purview/accounts": {
        "timing": "post",
        "pre": "",
        "post": "Delete and recreate the managed identity. Re-register data sources and reconfigure scan rule sets and collection permissions.",
        "doc_url": "https://learn.microsoft.com/en-us/purview/create-microsoft-purview-portal",
    },

    # ── Service Fabric ─────────────────────────────────────────────
    "Microsoft.ServiceFabric/clusters": {
        "timing": "pre",
        "pre": "⛔ Must be recreated. Export application packages (sfctl) and cluster ARM template before transfer.",
        "post": "",
        "doc_url": "https://learn.microsoft.com/en-us/azure/service-fabric/service-fabric-common-questions",
    },
    "Microsoft.ServiceFabric/managedClusters": {
        "timing": "pre",
        "pre": "⛔ Must be recreated. Export applications and cluster configuration before transfer.",
        "post": "",
        "doc_url": "https://learn.microsoft.com/en-us/azure/service-fabric/service-fabric-common-questions",
    },

    # ── Service Bus ────────────────────────────────────────────────
    "Microsoft.ServiceBus/namespaces": {
        "timing": "both",
        "pre": "Document managed identity assignments and note all SAS policy names/keys.",
        "post": "Delete and recreate managed identities. Recreate RBAC role assignments (Azure Service Bus Data Owner/Sender/Receiver). Rotate SAS keys.",
        "doc_url": "https://learn.microsoft.com/en-us/azure/service-bus-messaging/service-bus-managed-service-identity",
    },

    # ── Synapse Analytics ──────────────────────────────────────────
    "Microsoft.Synapse/workspaces": {
        "timing": "both",
        "pre": "Document Git configuration (repo, branch, root folder) and managed identity role assignments.",
        "post": "Update tenant ID and reconnect Git integration. Delete and recreate the managed identity. Reconfigure linked services.",
        "doc_url": "https://learn.microsoft.com/en-us/azure/synapse-analytics/security/how-to-recover-workspace-after-transfer",
    },

    # ── Azure Databricks ───────────────────────────────────────────
    "Microsoft.Databricks/workspaces": {
        "timing": "pre",
        "pre": "⛔ CANNOT be transferred. Export notebooks (Workspace → Export), jobs, cluster configs, and secrets before transfer. Workspace must be recreated.",
        "post": "",
        "doc_url": "https://learn.microsoft.com/en-us/azure/databricks/administration-guide/account-settings/",
    },

    # ── Dev Box / Deployment Environments ──────────────────────────
    "Microsoft.DevCenter/devcenters": {
        "timing": "pre",
        "pre": "⛔ CANNOT operate after transfer. Export dev center configurations (catalogs, environment types, network connections) before transfer. Must recreate in target tenant.",
        "post": "",
        "doc_url": "https://learn.microsoft.com/en-us/azure/dev-box/overview-what-is-microsoft-dev-box",
    },
    "Microsoft.DevCenter/projects": {
        "timing": "pre",
        "pre": "⛔ CANNOT operate after transfer. Export project configurations (pools, environment definitions) before transfer. Must recreate in target tenant.",
        "post": "",
        "doc_url": "https://learn.microsoft.com/en-us/azure/deployment-environments/overview-what-is-azure-deployment-environments",
    },

    # ── Azure File Sync ────────────────────────────────────────────
    "Microsoft.StorageSync/storageSyncServices": {
        "timing": "post",
        "pre": "",
        "post": "Re-register all connected servers in the target tenant. Verify sync group cloud endpoints and server endpoints are working.",
        "doc_url": "https://learn.microsoft.com/en-us/azure/storage/file-sync/file-sync-planning",
    },

    # ── Azure Compute Gallery ──────────────────────────────────────
    "Microsoft.Compute/galleries": {
        "timing": "post",
        "pre": "",
        "post": "Recreate RBAC sharing permissions. Replicate image versions to required regions. Re-share with target-tenant subscriptions if needed.",
        "doc_url": "https://learn.microsoft.com/en-us/azure/virtual-machines/shared-image-galleries",
    },
}

# ---------------------------------------------------------------------------
# Tenant-level transfer notes — items that live in Entra ID (not the
# subscription) and therefore CANNOT be discovered by the scanner APIs.
# Subscription-scoped items (RBAC, custom roles, locks, policies) are
# already surfaced in the Requires Action table via live API discovery.
# ---------------------------------------------------------------------------
TRANSFER_NOTES: dict[str, str] = {
    "App Registrations": (
        "App registrations live in the Entra ID tenant, not the subscription. "
        "If subscription resources depend on app registrations (e.g. App Service "
        "with Entra auth, Logic Apps with OAuth connectors), you must create "
        "equivalent app registrations in the target tenant BEFORE transfer."
    ),
    "Entra ID Access Reviews": (
        "Entra ID access reviews are deleted during transfer. "
        "You must recreate access review policies in the target tenant AFTER transfer."
    ),
}

# Default output directory
DEFAULT_OUTPUT_DIR = "migration_output"
