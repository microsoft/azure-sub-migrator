"""Runbook generator — produces a step-by-step migration checklist.

Takes the output of ``scan_subscription()`` and generates an ordered,
customer-specific runbook with pre-filled Azure CLI commands.  The
runbook is organized into three phases:

    1. **PRE-TRANSFER** — actions to perform *before* "Change Directory"
    2. **TRANSFER** — the actual directory change (manual portal step)
    3. **POST-TRANSFER** — actions to perform *after* the transfer

Each step includes the exact CLI command(s) the operator needs to run,
pre-populated with their subscription ID, resource names, and resource
groups — so they can copy-paste and execute.

Usage
-----
    from tenova.runbook import generate_runbook

    scan_result = scan_subscription(credential, subscription_id)
    markdown = generate_runbook(scan_result, subscription_id)
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

# ──────────────────────────────────────────────────────────────────────
# CLI command templates per resource type
# ──────────────────────────────────────────────────────────────────────
# Each entry maps a resource type to a dict with optional "pre" / "post"
# keys.  Values are lists of ``(description, cli_command)`` tuples.
# Placeholders: {sub}, {rg}, {name}, {id}

_CLI_TEMPLATES: dict[str, dict[str, list[tuple[str, str]]]] = {
    # ── RBAC ──────────────────────────────────────────────────────
    "Microsoft.Authorization/roleAssignments": {
        "pre": [
            (
                "Export all role assignments to JSON",
                'az role assignment list --subscription {sub} --all --output json > rbac_assignments_{sub_short}.json',
            ),
        ],
        "post": [
            (
                "Recreate role assignments using the exported JSON and principal mapping",
                "# For each assignment in rbac_assignments_{sub_short}.json:\n"
                '# az role assignment create --assignee "<NEW_PRINCIPAL_ID>" \\\n'
                '#   --role "<ROLE_DEFINITION_NAME_OR_ID>" \\\n'
                '#   --scope "<SCOPE>"\n'
                "#\n"
                "# TIP: Create a principal_mapping.json that maps old → new principal IDs,\n"
                "# then use the tenova import-rbac command:\n"
                "# tenova import-rbac -s {sub} -f rbac_assignments_{sub_short}.json -m principal_mapping.json",
            ),
        ],
    },
    "Microsoft.Authorization/roleDefinitions": {
        "pre": [
            (
                "Export custom role definitions",
                'az role definition list --custom-role-only true --subscription {sub} --output json > custom_roles_{sub_short}.json',
            ),
        ],
        "post": [
            (
                "Recreate custom role definitions in the target tenant",
                "# For each role in custom_roles_{sub_short}.json:\n"
                '# az role definition create --role-definition "<ROLE_JSON>"',
            ),
        ],
    },

    # ── Managed Identity ──────────────────────────────────────────
    "Microsoft.ManagedIdentity/userAssignedIdentities": {
        "pre": [
            (
                "Document which resources use this managed identity",
                'az identity show --name "{name}" --resource-group "{rg}" --subscription {sub} --output json > identity_{name}.json',
            ),
        ],
        "post": [
            (
                "Recreate the user-assigned identity and update resource bindings",
                '# The identity principal ID changes after transfer.\n'
                '# Re-assign RBAC roles for the new principal ID:\n'
                'az identity show --name "{name}" --resource-group "{rg}" --subscription {sub} --query "principalId" -o tsv',
            ),
        ],
    },
    "Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials": {
        "post": [
            (
                "Recreate federated identity credentials in the target tenant",
                'az identity federated-credential list --identity-name "{name}" --resource-group "{rg}" --subscription {sub} --output json > federated_creds_{name}.json\n'
                "# Recreate each credential after transfer",
            ),
        ],
    },

    # ── Key Vault ─────────────────────────────────────────────────
    "Microsoft.KeyVault/vaults": {
        "pre": [
            (
                "Export Key Vault access policies (will be wiped during transfer)",
                'az keyvault show --name "{name}" --subscription {sub} --query "properties.accessPolicies" --output json > kv_{name}_policies.json',
            ),
            (
                "If this Key Vault is used for CMK encryption, disable customer-managed keys on dependent resources BEFORE transfer to avoid data loss",
                "# Check for CMK references:\n"
                'az keyvault key list --vault-name "{name}" --subscription {sub} --output table',
            ),
        ],
        "post": [
            (
                "Update Key Vault tenant ID (auto-updates on transfer, but verify)",
                'az keyvault show --name "{name}" --subscription {sub} --query "properties.tenantId" -o tsv',
            ),
            (
                "Recreate access policies from the exported JSON",
                "# For each policy in kv_{name}_policies.json:\n"
                '# az keyvault set-policy --name "{name}" \\\n'
                '#   --object-id "<NEW_PRINCIPAL_ID>" \\\n'
                '#   --secret-permissions get list \\\n'
                '#   --key-permissions get list wrapKey unwrapKey',
            ),
        ],
    },
    "Microsoft.KeyVault/managedHSMs": {
        "pre": [
            (
                "Export Managed HSM RBAC assignments",
                'az keyvault role assignment list --hsm-name "{name}" --subscription {sub} --output json > hsm_{name}_rbac.json',
            ),
        ],
        "post": [
            (
                "Reconfigure Managed HSM RBAC for target-tenant principals",
                '# Recreate RBAC from hsm_{name}_rbac.json with new principal IDs',
            ),
        ],
    },

    # ── AKS ───────────────────────────────────────────────────────
    "Microsoft.ContainerService/managedClusters": {
        "pre": [
            (
                "⛔ AKS clusters CANNOT be transferred. Export cluster configuration for recreation",
                'az aks show --name "{name}" --resource-group "{rg}" --subscription {sub} --output json > aks_{name}_config.json',
            ),
            (
                "Export Kubernetes workloads (run from a machine with kubectl access)",
                "# kubectl get all --all-namespaces -o yaml > k8s_workloads_{name}.yaml\n"
                "# Backup persistent volumes and application data separately",
            ),
        ],
    },

    # ── Entra Domain Services ─────────────────────────────────────
    "Microsoft.AAD/domainServices": {
        "pre": [
            (
                "⛔ Entra Domain Services CANNOT operate in a different tenant. Document and plan recreation",
                'az ad ds show --name "{name}" --resource-group "{rg}" --subscription {sub} --output json > aadds_{name}.json',
            ),
        ],
    },

    # ── SQL Server ────────────────────────────────────────────────
    "Microsoft.Sql/servers": {
        "pre": [
            (
                "Disable Entra authentication on SQL Server before transfer",
                'az sql server ad-admin delete --server-name "{name}" --resource-group "{rg}" --subscription {sub}',
            ),
        ],
        "post": [
            (
                "Re-enable Entra admin with a target-tenant principal",
                '# az sql server ad-admin create --server-name "{name}" \\\n'
                '#   --resource-group "{rg}" --subscription {sub} \\\n'
                '#   --display-name "<NEW_ADMIN>" --object-id "<NEW_ADMIN_OID>"',
            ),
        ],
    },
    "Microsoft.Sql/managedInstances": {
        "pre": [
            (
                "Disable Entra authentication on SQL Managed Instance",
                'az sql mi ad-admin delete --managed-instance-name "{name}" --resource-group "{rg}" --subscription {sub}',
            ),
        ],
        "post": [
            (
                "Re-enable Entra admin with a target-tenant principal",
                '# az sql mi ad-admin create --managed-instance-name "{name}" \\\n'
                '#   --resource-group "{rg}" --subscription {sub} \\\n'
                '#   --display-name "<NEW_ADMIN>" --object-id "<NEW_ADMIN_OID>"',
            ),
        ],
    },

    # ── MySQL ─────────────────────────────────────────────────────
    "Microsoft.DBforMySQL/flexibleServers": {
        "pre": [
            (
                "Document Entra admin configuration",
                'az mysql flexible-server ad-admin list --server-name "{name}" --resource-group "{rg}" --subscription {sub} --output json > mysql_{name}_admins.json',
            ),
        ],
        "post": [
            (
                "Reconfigure Entra admin for target tenant",
                '# az mysql flexible-server ad-admin create --server-name "{name}" \\\n'
                '#   --resource-group "{rg}" --subscription {sub} \\\n'
                '#   --display-name "<NEW_ADMIN>" --object-id "<NEW_ADMIN_OID>"',
            ),
        ],
    },
    "Microsoft.DBforMySQL/servers": {
        "pre": [
            (
                "Document Entra admin configuration",
                'az mysql server ad-admin show --server-name "{name}" --resource-group "{rg}" --subscription {sub} --output json > mysql_{name}_admin.json',
            ),
        ],
        "post": [
            (
                "Reconfigure Entra admin for target tenant",
                "# Recreate Entra admin for the target tenant",
            ),
        ],
    },

    # ── PostgreSQL ────────────────────────────────────────────────
    "Microsoft.DBforPostgreSQL/flexibleServers": {
        "pre": [
            (
                "Document Entra admin configuration",
                'az postgres flexible-server ad-admin list --server-name "{name}" --resource-group "{rg}" --subscription {sub} --output json > pg_{name}_admins.json',
            ),
        ],
        "post": [
            (
                "Reconfigure Entra admin for target tenant",
                '# az postgres flexible-server ad-admin create --server-name "{name}" \\\n'
                '#   --resource-group "{rg}" --subscription {sub} \\\n'
                '#   --display-name "<NEW_ADMIN>" --object-id "<NEW_ADMIN_OID>"',
            ),
        ],
    },
    "Microsoft.DBforPostgreSQL/servers": {
        "pre": [
            (
                "Document Entra admin configuration",
                'az postgres server ad-admin show --server-name "{name}" --resource-group "{rg}" --subscription {sub} --output json > pg_{name}_admin.json',
            ),
        ],
        "post": [
            (
                "Reconfigure Entra admin for target tenant",
                "# Recreate Entra admin for the target tenant",
            ),
        ],
    },

    # ── Storage ───────────────────────────────────────────────────
    "Microsoft.Storage/storageAccounts": {
        "pre": [
            (
                "Document RBAC and shared-key settings",
                'az storage account show --name "{name}" --resource-group "{rg}" --subscription {sub} --query "{{allowSharedKeyAccess: allowSharedKeyAccess, identity: identity}}" --output json > storage_{name}_auth.json',
            ),
        ],
        "post": [
            (
                "Reassign RBAC roles (Storage Blob Data Contributor, etc.) to target-tenant principals",
                'az role assignment list --scope "/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Storage/storageAccounts/{name}" --output table\n'
                "# Recreate each assignment with the new principal IDs",
            ),
        ],
    },

    # ── Resource Locks ────────────────────────────────────────────
    "Microsoft.Authorization/locks": {
        "pre": [
            (
                "Export all resource locks",
                'az lock list --subscription {sub} --output json > locks_{sub_short}.json',
            ),
            (
                "Remove all resource locks (they block many post-transfer operations)",
                "# For each lock:\n"
                '# az lock delete --ids "<LOCK_RESOURCE_ID>"',
            ),
        ],
        "post": [
            (
                "Recreate resource locks from the exported JSON",
                "# For each lock in locks_{sub_short}.json:\n"
                '# az lock create --name "<LOCK_NAME>" \\\n'
                '#   --lock-type "<CanNotDelete|ReadOnly>" \\\n'
                '#   --resource-group "<RG>" \\\n'
                '#   --subscription {sub}',
            ),
        ],
    },

    # ── Policy ────────────────────────────────────────────────────
    "Microsoft.Authorization/policyAssignments": {
        "pre": [
            (
                "⚠️ Export all policy assignments (they are PERMANENTLY DELETED during transfer)",
                'az policy assignment list --subscription {sub} --output json > policy_assignments_{sub_short}.json',
            ),
        ],
        "post": [
            (
                "Reimport policy assignments in the target tenant",
                "# For each assignment in policy_assignments_{sub_short}.json:\n"
                '# az policy assignment create --name "<NAME>" \\\n'
                '#   --policy "<POLICY_DEFINITION_ID>" \\\n'
                '#   --scope "/subscriptions/{sub}" \\\n'
                '#   --params "<PARAMETERS_JSON>"',
            ),
        ],
    },
    "Microsoft.Authorization/policyDefinitions": {
        "pre": [
            (
                "Export custom policy definitions",
                'az policy definition list --subscription {sub} --query "[?policyType==\'Custom\']" --output json > policy_definitions_{sub_short}.json',
            ),
        ],
        "post": [
            (
                "Recreate custom policy definitions in the target tenant",
                "# For each definition in policy_definitions_{sub_short}.json:\n"
                '# az policy definition create --name "<NAME>" \\\n'
                '#   --rules "<RULES_JSON>" \\\n'
                '#   --subscription {sub}',
            ),
        ],
    },

    # ── Azure Arc ─────────────────────────────────────────────────
    "Microsoft.HybridCompute/machines": {
        "pre": [
            (
                "Document Arc agent configuration and service principal",
                'az connectedmachine show --name "{name}" --resource-group "{rg}" --subscription {sub} --output json > arc_{name}.json',
            ),
        ],
        "post": [
            (
                "Disconnect and re-onboard the Arc agent to the target tenant",
                "# On the machine itself:\n"
                "# azcmagent disconnect\n"
                '# azcmagent connect --resource-group "{rg}" \\\n'
                '#   --tenant-id "<TARGET_TENANT_ID>" \\\n'
                '#   --subscription-id {sub}',
            ),
        ],
    },
    "Microsoft.HybridCompute/machines/extensions": {
        "post": [
            (
                "Reinstall Arc VM extensions after re-onboarding",
                "# Extensions are automatically removed when Arc agent disconnects.\n"
                "# After re-onboarding, reinstall required extensions:\n"
                '# az connectedmachine extension create --machine-name "{name}" \\\n'
                '#   --resource-group "{rg}" --subscription {sub} \\\n'
                '#   --name "<EXTENSION_NAME>" --publisher "<PUBLISHER>" --type "<TYPE>"',
            ),
        ],
    },

    # ── Arc-enabled SQL Server ────────────────────────────────────
    "Microsoft.AzureArcData/SqlServerInstances": {
        "pre": [
            (
                "Document Arc-enabled SQL Server configuration",
                'az resource show --ids "{id}" --output json > arc_sql_{name}.json',
            ),
        ],
        "post": [
            (
                "After re-onboarding the parent Arc agent, reconfigure SQL Server registration",
                "# The Arc agent re-onboard will automatically rediscover SQL instances.\n"
                "# Verify the instance is re-registered:\n"
                'az resource list --resource-type "Microsoft.AzureArcData/SqlServerInstances" --subscription {sub} --output table',
            ),
        ],
    },
    "Microsoft.AzureArcData/SqlServerInstances/Databases": {
        "post": [
            (
                "Verify databases are rediscovered after Arc agent re-onboarding",
                'az resource list --resource-type "Microsoft.AzureArcData/SqlServerInstances/Databases" --subscription {sub} --output table',
            ),
        ],
    },

    # ── Disk Encryption Sets ──────────────────────────────────────
    "Microsoft.Compute/diskEncryptionSets": {
        "pre": [
            (
                "Document encryption set configuration and Key Vault references",
                'az disk-encryption-set show --name "{name}" --resource-group "{rg}" --subscription {sub} --output json > des_{name}.json',
            ),
        ],
        "post": [
            (
                "Update identity and Key Vault key reference",
                'az disk-encryption-set update --name "{name}" --resource-group "{rg}" --subscription {sub} --key-url "<NEW_KEY_URL>"',
            ),
        ],
    },

    # ── Automation ────────────────────────────────────────────────
    "Microsoft.Automation/automationAccounts": {
        "pre": [
            (
                "Export automation account runbooks and credentials",
                'az automation account show --name "{name}" --resource-group "{rg}" --subscription {sub} --output json > automation_{name}.json',
            ),
        ],
        "post": [
            (
                "Reconfigure Run As accounts and managed identity for the target tenant",
                '# Update managed identity role assignments\n'
                '# Recreate any credential or certificate assets that reference the old tenant',
            ),
        ],
    },

    # ── Data Factory ──────────────────────────────────────────────
    "Microsoft.DataFactory/factories": {
        "pre": [
            (
                "Document linked services and managed identity",
                'az datafactory show --name "{name}" --resource-group "{rg}" --subscription {sub} --output json > adf_{name}.json',
            ),
        ],
        "post": [
            (
                "Reconfigure managed identity and linked service credentials",
                '# Update Key Vault linked services, OAuth connections,\n'
                '# and managed identity role assignments',
            ),
        ],
    },

    # ── Logic Apps ────────────────────────────────────────────────
    "Microsoft.Logic/workflows": {
        "post": [
            (
                "Reauthorize OAuth API connections",
                'az resource list --resource-type "Microsoft.Web/connections" --resource-group "{rg}" --subscription {sub} --output table\n'
                "# Open each connection in the portal and reauthorize",
            ),
        ],
    },

    # ── API Management ────────────────────────────────────────────
    "Microsoft.ApiManagement/service": {
        "post": [
            (
                "Reconfigure managed identity and Entra ID identity provider",
                'az apim show --name "{name}" --resource-group "{rg}" --subscription {sub} --output json > apim_{name}.json\n'
                "# Update identity provider settings to reference the target tenant",
            ),
        ],
    },

    # ── App Configuration ─────────────────────────────────────────
    "Microsoft.AppConfiguration/configurationStores": {
        "post": [
            (
                "Reconfigure managed identity access",
                'az appconfig show --name "{name}" --resource-group "{rg}" --subscription {sub} --output json > appconfig_{name}.json',
            ),
        ],
    },

    # ── Databricks ────────────────────────────────────────────────
    "Microsoft.Databricks/workspaces": {
        "pre": [
            (
                "⛔ Databricks workspaces CANNOT be transferred. Export configuration",
                'az databricks workspace show --name "{name}" --resource-group "{rg}" --subscription {sub} --output json > databricks_{name}.json\n'
                "# Export notebooks, jobs, and cluster configs via Databricks CLI:\n"
                "# databricks workspace export_dir / ./databricks_export/",
            ),
        ],
    },

    # ── Service Fabric ────────────────────────────────────────────
    "Microsoft.ServiceFabric/clusters": {
        "pre": [
            (
                "⛔ Service Fabric clusters must be recreated. Export configuration",
                'az sf cluster show --name "{name}" --resource-group "{rg}" --subscription {sub} --output json > sf_{name}.json',
            ),
        ],
    },
    "Microsoft.ServiceFabric/managedClusters": {
        "pre": [
            (
                "⛔ Service Fabric managed clusters must be recreated. Export configuration",
                'az sf managed-cluster show --cluster-name "{name}" --resource-group "{rg}" --subscription {sub} --output json > sf_managed_{name}.json',
            ),
        ],
    },

    # ── Service Bus ───────────────────────────────────────────────
    "Microsoft.ServiceBus/namespaces": {
        "pre": [
            (
                "Document managed identity and RBAC",
                'az servicebus namespace show --name "{name}" --resource-group "{rg}" --subscription {sub} --output json > sb_{name}.json',
            ),
        ],
        "post": [
            (
                "Recreate managed identity role assignments",
                'az role assignment list --scope "/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.ServiceBus/namespaces/{name}" --output table',
            ),
        ],
    },

    # ── Synapse ───────────────────────────────────────────────────
    "Microsoft.Synapse/workspaces": {
        "pre": [
            (
                "Export Synapse workspace configuration and Git settings",
                'az synapse workspace show --name "{name}" --resource-group "{rg}" --subscription {sub} --output json > synapse_{name}.json',
            ),
        ],
        "post": [
            (
                "Update tenant ID and reconfigure Git integration",
                '# az synapse workspace update --name "{name}" --resource-group "{rg}" --subscription {sub}\n'
                "# Reconfigure Git repository connection with target-tenant credentials",
            ),
        ],
    },

    # ── Purview ───────────────────────────────────────────────────
    "Microsoft.Purview/accounts": {
        "post": [
            (
                "Reconfigure Purview account identity and data source connections",
                "# Update managed identity role assignments and\n"
                "# reauthorize data source scan credentials",
            ),
        ],
    },

    # ── Storage Sync ──────────────────────────────────────────────
    "Microsoft.StorageSync/storageSyncServices": {
        "post": [
            (
                "Re-register servers and verify sync endpoints",
                'az storagesync show --name "{name}" --resource-group "{rg}" --subscription {sub} --output json > storagesync_{name}.json\n'
                "# Re-register all connected servers in the target tenant",
            ),
        ],
    },

    # ── Compute Gallery ───────────────────────────────────────────
    "Microsoft.Compute/galleries": {
        "post": [
            (
                "Recreate sharing permissions and verify image replication",
                'az sig show --gallery-name "{name}" --resource-group "{rg}" --subscription {sub} --output json > gallery_{name}.json\n'
                "# Recreate RBAC sharing and re-share with target-tenant subscriptions",
            ),
        ],
    },

    # ── DevCenter ─────────────────────────────────────────────────
    "Microsoft.DevCenter/devcenters": {
        "pre": [
            (
                "⛔ Dev Centers cannot be transferred. Export configuration",
                'az devcenter admin devcenter show --name "{name}" --resource-group "{rg}" --subscription {sub} --output json > devcenter_{name}.json',
            ),
        ],
    },
    "Microsoft.DevCenter/projects": {
        "pre": [
            (
                "⛔ Dev Center projects cannot be transferred. Export configuration",
                'az devcenter admin project show --name "{name}" --resource-group "{rg}" --subscription {sub} --output json > devcenter_project_{name}.json',
            ),
        ],
    },

    # ── VM Extensions ─────────────────────────────────────────────
    "Microsoft.Compute/virtualMachines/extensions": {
        "post": [
            (
                "Reinstall VM extensions that depend on identity",
                'az vm extension list --vm-name "{name}" --resource-group "{rg}" --subscription {sub} --output table\n'
                "# Reinstall extensions that use managed identity or AAD auth",
            ),
        ],
    },
}


# ──────────────────────────────────────────────────────────────────────
# Runbook generator
# ──────────────────────────────────────────────────────────────────────

def _format_command(
    template: str,
    subscription_id: str,
    resource: dict[str, Any],
) -> str:
    """Fill placeholders in a CLI command template."""
    sub_short = subscription_id[:8]
    return template.format(
        sub=subscription_id,
        sub_short=sub_short,
        rg=resource.get("resource_group", ""),
        name=resource.get("name", ""),
        id=resource.get("id", ""),
    )


def _flatten_resources(
    resources: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Flatten hierarchical resources (parent + children)."""
    flat: list[dict[str, Any]] = []
    for r in resources:
        flat.append(r)
        for child in r.get("children", []):
            flat.append(child)
    return flat


def enrich_with_commands(
    scan_result: dict[str, Any],
    subscription_id: str,
) -> dict[str, Any]:
    """Return a *copy* of ``scan_result`` with CLI commands injected.

    Each item in ``requires_action`` (and its ``children``) receives a
    ``cli_commands`` key — a dict with ``"pre"`` and ``"post"`` lists,
    where each entry is ``{"description": str, "command": str}``.

    This is designed for the interactive checklist UI so that operators
    can see the exact CLI commands alongside each checkbox item.

    Parameters
    ----------
    scan_result:
        Output of ``scan_subscription()``.
    subscription_id:
        The subscription being migrated.

    Returns
    -------
    dict
        A shallow copy of *scan_result* with ``cli_commands`` injected.
    """

    def _inject(resource: dict[str, Any]) -> dict[str, Any]:
        """Return a copy of *resource* with ``cli_commands`` added."""
        enriched = dict(resource)
        rtype = resource.get("type", "")
        templates = _CLI_TEMPLATES.get(rtype)

        pre_cmds: list[dict[str, str]] = []
        post_cmds: list[dict[str, str]] = []

        if templates:
            for desc, cmd in templates.get("pre", []):
                pre_cmds.append({
                    "description": desc,
                    "command": _format_command(cmd, subscription_id, resource),
                })
            for desc, cmd in templates.get("post", []):
                post_cmds.append({
                    "description": desc,
                    "command": _format_command(cmd, subscription_id, resource),
                })

        enriched["cli_commands"] = {"pre": pre_cmds, "post": post_cmds}

        # Recurse into children
        if "children" in resource:
            enriched["children"] = [_inject(c) for c in resource["children"]]

        return enriched

    return {
        **scan_result,
        "requires_action": [_inject(r) for r in scan_result.get("requires_action", [])],
    }


def generate_runbook(
    scan_result: dict[str, Any],
    subscription_id: str,
    target_tenant_id: str = "<TARGET_TENANT_ID>",
) -> str:
    """Generate a Markdown runbook from scan results.

    Parameters
    ----------
    scan_result:
        Output of ``scan_subscription()`` with ``transfer_safe``,
        ``requires_action``, and ``transfer_notes`` keys.
    subscription_id:
        The subscription being migrated.
    target_tenant_id:
        The target tenant ID (optional — used in transfer step).

    Returns
    -------
    str
        The full runbook as a Markdown string.
    """
    requires_action = _flatten_resources(scan_result.get("requires_action", []))
    transfer_notes = scan_result.get("transfer_notes", {})
    transfer_safe_count = len(scan_result.get("transfer_safe", []))

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    subscription_id[:8]

    lines: list[str] = []
    ln = lines.append

    # ── Header ────────────────────────────────────────────────────
    ln(f"# Migration Runbook — Subscription `{subscription_id}`")
    ln("")
    ln(f"Generated by **Tenova** on {now}")
    ln("")
    ln("---")
    ln("")

    # ── Summary ───────────────────────────────────────────────────
    ln("## Summary")
    ln("")
    ln(f"- **Subscription:** `{subscription_id}`")
    ln(f"- **Target Tenant:** `{target_tenant_id}`")
    ln(f"- **Transfer-Safe Resources:** {transfer_safe_count} (no action needed)")
    ln(f"- **Requires-Action Resources:** {len(requires_action)}")
    ln("")

    # ── Transfer Notes ────────────────────────────────────────────
    if transfer_notes:
        ln("## Tenant-Level Notes")
        ln("")
        ln("> These items live in Entra ID, not the subscription. They cannot be")
        ln("> discovered by scanning subscription resources.")
        ln("")
        for title, note in transfer_notes.items():
            ln(f"- **{title}:** {note}")
        ln("")

    # ── Collect steps by phase ────────────────────────────────────
    pre_steps: list[dict[str, Any]] = []
    post_steps: list[dict[str, Any]] = []
    manual_steps: list[dict[str, Any]] = []  # resources with no CLI template

    for resource in requires_action:
        rtype = resource.get("type", "")
        resource.get("timing", "post")
        templates = _CLI_TEMPLATES.get(rtype)

        if templates:
            for desc, cmd in templates.get("pre", []):
                pre_steps.append({
                    "resource": resource,
                    "description": desc,
                    "command": _format_command(cmd, subscription_id, resource),
                })
            for desc, cmd in templates.get("post", []):
                post_steps.append({
                    "resource": resource,
                    "description": desc,
                    "command": _format_command(cmd, subscription_id, resource),
                })
        else:
            # No CLI template — add a manual step with the guidance
            # from the scan result
            manual_steps.append(resource)

    # ── Phase 1: PRE-TRANSFER ─────────────────────────────────────
    ln("---")
    ln("")
    ln("## Phase 1: PRE-TRANSFER")
    ln("")
    ln("> Complete these steps **before** initiating the \"Change Directory\" operation.")
    ln("> Schedule a maintenance window — some steps may cause brief service interruptions.")
    ln("")

    if pre_steps:
        for i, step in enumerate(pre_steps, 1):
            r = step["resource"]
            ln(f"### Step {i}: {step['description']}")
            ln("")
            ln(f"**Resource:** `{r.get('name', '')}` ({r.get('type', '')})")
            if r.get("resource_group") and r["resource_group"] != "—":
                ln(f"**Resource Group:** `{r['resource_group']}`")
            ln("")
            ln("```bash")
            ln(step["command"])
            ln("```")
            ln("")
    else:
        ln("*No pre-transfer steps required.*")
        ln("")

    # ── Phase 2: TRANSFER ─────────────────────────────────────────
    pre_count = len(pre_steps)
    transfer_step = pre_count + 1

    ln("---")
    ln("")
    ln("## Phase 2: TRANSFER")
    ln("")

    ln(f"### Step {transfer_step}: Change Directory")
    ln("")
    ln("Execute the subscription transfer in the Azure Portal:")
    ln("")
    ln("1. Go to **Azure Portal** → **Subscriptions** → select your subscription")
    ln("2. Click **Change directory**")
    ln(f"3. Select target tenant: `{target_tenant_id}`")
    ln("4. Click **Change**")
    ln("5. Wait for the transfer to complete (typically 5-15 minutes)")
    ln("")
    ln(f"**Portal Link:** https://portal.azure.com/#@/resource/subscriptions/{subscription_id}/changeDirectory")
    ln("")
    ln("> ⚠️ After transfer completes, sign out and sign back in to the target tenant")
    ln("> before proceeding to Phase 3.")
    ln("")

    # ── Phase 3: POST-TRANSFER ────────────────────────────────────
    ln("---")
    ln("")
    ln("## Phase 3: POST-TRANSFER")
    ln("")
    ln("> Complete these steps **after** the transfer. Sign in to the **target tenant**")
    ln("> before running these commands.")
    ln("")

    if post_steps:
        for i, step in enumerate(post_steps, transfer_step + 1):
            r = step["resource"]
            ln(f"### Step {i}: {step['description']}")
            ln("")
            ln(f"**Resource:** `{r.get('name', '')}` ({r.get('type', '')})")
            if r.get("resource_group") and r["resource_group"] != "—":
                ln(f"**Resource Group:** `{r['resource_group']}`")
            ln("")
            ln("```bash")
            ln(step["command"])
            ln("```")
            ln("")
    else:
        ln("*No post-transfer steps required.*")
        ln("")

    # ── Manual Steps (no CLI template) ────────────────────────────
    if manual_steps:
        ln("---")
        ln("")
        ln("## Additional Manual Steps")
        ln("")
        ln("> These resources require action but don't have automated CLI commands.")
        ln("> Follow the linked documentation for guidance.")
        ln("")
        for r in manual_steps:
            ln(f"- **`{r.get('name', '')}`** ({r.get('type', '')})")
            r.get("timing", "post").upper()
            pre_action = r.get("pre_action", "")
            post_action = r.get("post_action", "")
            doc_url = r.get("doc_url", "")
            if pre_action:
                ln(f"  - 🔴 **PRE:** {pre_action}")
            if post_action:
                ln(f"  - 🟡 **POST:** {post_action}")
            if doc_url:
                ln(f"  - 📄 [Microsoft Learn Documentation]({doc_url})")
            ln("")

    # ── Validation Checklist ──────────────────────────────────────
    ln("---")
    ln("")
    ln("## Validation Checklist")
    ln("")
    ln("After completing all post-transfer steps, verify:")
    ln("")
    ln(f"- [ ] All Key Vaults show correct tenant ID: `{target_tenant_id}`")
    ln("- [ ] RBAC role assignments are recreated for target-tenant principals")
    ln("- [ ] Managed identities have correct role assignments")
    ln("- [ ] SQL/MySQL/PostgreSQL servers accept Entra authentication")
    ln("- [ ] Application workloads are functional (health checks pass)")
    ln("- [ ] Monitoring and alerting is operational")
    ln("- [ ] Resource locks are reinstated")
    ln("- [ ] Policy assignments are reapplied")
    ln("")

    # ── Rollback ──────────────────────────────────────────────────
    ln("---")
    ln("")
    ln("## Rollback Plan")
    ln("")
    ln("If critical services are broken and cannot be remediated:")
    ln("")
    ln("1. Transfer the subscription **back** to the source tenant using the same")
    ln("   \"Change Directory\" process")
    ln("2. Restore the pre-transfer RBAC assignments from the exported JSON")
    ln("3. Restore resource locks from the exported JSON")
    ln("")
    ln("> **Note:** Transferring back will again wipe RBAC and locks, so keep")
    ln("> the export files until the migration is fully validated.")
    ln("")

    return "\n".join(lines)
