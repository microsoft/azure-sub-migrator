# Requires Az.Accounts, Az.Websites, Az.Network modules
# Install if missing: Install-Module Az.Websites, Az.Network -Scope CurrentUser -Force
<#
.SYNOPSIS
    Create a new App Service (azure-sub-migrator) in the SAME resource group as
    tenova-app, copying all settings for both production and staging slots.

.DESCRIPTION
    This script:
    1. Reads all settings from tenova-app (production + staging slot)
    2. Creates azure-sub-migrator on the same plan in rg-tenova
    3. Copies app settings, site config, managed identity for production
    4. Creates staging slot with its own distinct settings/config
    5. Enables VNet integration on both slots
    6. Outputs the Entra ID redirect URIs you need to register

.PARAMETER ResourceGroup
    Resource group (same for old and new app). Default: rg-tenova

.PARAMETER OldAppName
    Name of the existing App Service. Default: tenova-app

.PARAMETER NewAppName
    Name of the new App Service. Default: azure-sub-migrator

.PARAMETER DryRun
    If set, only shows what would be done without creating resources.

.EXAMPLE
    .\migrate-app-service.ps1 -DryRun
    .\migrate-app-service.ps1
#>

[CmdletBinding()]
param(
    [string]$ResourceGroup = "rg-tenova",
    [string]$OldAppName    = "tenova-app",
    [string]$NewAppName    = "azure-sub-migrator",
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host "`n══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  App Service Migration: $OldAppName → $NewAppName" -ForegroundColor Cyan
Write-Host "  Resource Group: $ResourceGroup (same RG)" -ForegroundColor Cyan
Write-Host "══════════════════════════════════════════════════════════`n" -ForegroundColor Cyan

# ── Step 1: Read production app ────────────────────────────────────
Write-Host "[1/7] Reading production app '$OldAppName'..." -ForegroundColor Yellow
$oldApp = Get-AzWebApp -ResourceGroupName $ResourceGroup -Name $OldAppName
$plan = $oldApp.ServerFarmId
$location = $oldApp.Location

Write-Host "       Location:     $location"
Write-Host "       Plan:         $(($plan -split '/')[-1])"
Write-Host "       Runtime:      $($oldApp.SiteConfig.LinuxFxVersion)"
Write-Host "       HTTPS Only:   $($oldApp.HttpsOnly)"
Write-Host "       Identity:     $($oldApp.Identity.Type)"
Write-Host "       Always On:    $($oldApp.SiteConfig.AlwaysOn)"
Write-Host "       Min TLS:      $($oldApp.SiteConfig.MinTlsVersion)"
Write-Host "       FTP state:    $($oldApp.SiteConfig.FtpsState)"
Write-Host "       Startup cmd:  $($oldApp.SiteConfig.AppCommandLine)"

# Read production app settings
$prodSettings = @{}
foreach ($kv in $oldApp.SiteConfig.AppSettings) {
    $prodSettings[$kv.Name] = $kv.Value
}
Write-Host "       App settings: $($prodSettings.Count) entries"

# ── Step 2: Read staging slot ──────────────────────────────────────
Write-Host "[2/7] Reading staging slot..." -ForegroundColor Yellow
$oldSlot = Get-AzWebAppSlot -ResourceGroupName $ResourceGroup -Name $OldAppName -Slot "staging"

Write-Host "       Runtime:      $($oldSlot.SiteConfig.LinuxFxVersion)"
Write-Host "       Always On:    $($oldSlot.SiteConfig.AlwaysOn)"
Write-Host "       Min TLS:      $($oldSlot.SiteConfig.MinTlsVersion)"
Write-Host "       FTP state:    $($oldSlot.SiteConfig.FtpsState)"
Write-Host "       Startup cmd:  $($oldSlot.SiteConfig.AppCommandLine)"

$stagingSettings = @{}
foreach ($kv in $oldSlot.SiteConfig.AppSettings) {
    $stagingSettings[$kv.Name] = $kv.Value
}
Write-Host "       App settings: $($stagingSettings.Count) entries"

# ── Step 3: Find VNet subnet ──────────────────────────────────────
Write-Host "[3/7] Checking VNet..." -ForegroundColor Yellow
$appSubnetId = $null
$vnets = Get-AzVirtualNetwork -ResourceGroupName $ResourceGroup -ErrorAction SilentlyContinue
foreach ($v in $vnets) {
    foreach ($s in $v.Subnets) {
        foreach ($d in $s.Delegations) {
            if ($d.ServiceName -eq "Microsoft.Web/serverFarms") {
                $appSubnetId = $s.Id
                Write-Host "       Found VNet '$($v.Name)' subnet '$($s.Name)' ($($s.AddressPrefix -join ','))" -ForegroundColor Green
                break
            }
        }
        if ($appSubnetId) { break }
    }
    if ($appSubnetId) { break }
}
if (-not $appSubnetId) {
    Write-Host "       No delegated subnet found" -ForegroundColor DarkGray
}

# ── DRY RUN ────────────────────────────────────────────────────────
if ($DryRun) {
    Write-Host "`n══════════════════════════════════════════════════════════" -ForegroundColor Magenta
    Write-Host "  DRY RUN — No resources will be created" -ForegroundColor Magenta
    Write-Host "══════════════════════════════════════════════════════════" -ForegroundColor Magenta
    Write-Host "`nWould create in $ResourceGroup :"
    Write-Host "  • App Service:     $NewAppName (on plan: $(($plan -split '/')[-1]))"
    Write-Host "  • Production settings: $($prodSettings.Count) entries"
    Write-Host "  • Staging slot settings: $($stagingSettings.Count) entries"
    if ($appSubnetId) {
        Write-Host "  • VNet integration: $(($appSubnetId -split '/')[-1]) (both slots)" -ForegroundColor Green
    }
    Write-Host "`n  Production config:"
    Write-Host "    Runtime:   $($oldApp.SiteConfig.LinuxFxVersion)"
    Write-Host "    AlwaysOn:  $($oldApp.SiteConfig.AlwaysOn)"
    Write-Host "    MinTLS:    $($oldApp.SiteConfig.MinTlsVersion)"
    Write-Host "    FTP:       $($oldApp.SiteConfig.FtpsState)"
    Write-Host "    Startup:   $($oldApp.SiteConfig.AppCommandLine)"
    Write-Host "`n  Staging config:"
    Write-Host "    Runtime:   $($oldSlot.SiteConfig.LinuxFxVersion)"
    Write-Host "    AlwaysOn:  $($oldSlot.SiteConfig.AlwaysOn)"
    Write-Host "    MinTLS:    $($oldSlot.SiteConfig.MinTlsVersion)"
    Write-Host "    FTP:       $($oldSlot.SiteConfig.FtpsState)"
    Write-Host "    Startup:   $($oldSlot.SiteConfig.AppCommandLine)"
    Write-Host "`n  Entra ID redirect URIs to register:"
    Write-Host "    https://$NewAppName.azurewebsites.net/auth/callback"
    Write-Host "    https://$NewAppName-staging.azurewebsites.net/auth/callback"
    Write-Host "    https://$NewAppName.azurewebsites.net/auth/admin-consent-callback"
    Write-Host "    https://$NewAppName.azurewebsites.net/auth/target-callback"
    Write-Host "    https://$NewAppName.azurewebsites.net"
    Write-Host ""
    return
}

# ── Step 4: Create new app with production config ──────────────────
Write-Host "[4/7] Creating app '$NewAppName'..." -ForegroundColor Yellow
$newApp = New-AzWebApp `
    -ResourceGroupName $ResourceGroup `
    -Name $NewAppName `
    -Location $location `
    -AppServicePlan $plan
Write-Host "       App created" -ForegroundColor Green

# Enable system-assigned managed identity
if ($oldApp.Identity.Type -match "SystemAssigned") {
    Write-Host "       Enabling managed identity..." -ForegroundColor Yellow
    Set-AzWebApp -ResourceGroupName $ResourceGroup -Name $NewAppName -AssignIdentity $true | Out-Null
}

# Copy production app settings
Write-Host "       Copying $($prodSettings.Count) app settings..." -ForegroundColor Yellow
Set-AzWebApp -ResourceGroupName $ResourceGroup -Name $NewAppName -AppSettings $prodSettings | Out-Null

# Apply production site config
Write-Host "       Applying site config..." -ForegroundColor Yellow
Set-AzWebApp -ResourceGroupName $ResourceGroup -Name $NewAppName -HttpsOnly $oldApp.HttpsOnly | Out-Null

$prodConfig = @{
    ResourceGroupName = $ResourceGroup
    ResourceType      = "Microsoft.Web/sites/config"
    ResourceName      = "$NewAppName/web"
    ApiVersion        = "2023-12-01"
    PropertyObject    = @{
        linuxFxVersion            = $oldApp.SiteConfig.LinuxFxVersion
        alwaysOn                  = $oldApp.SiteConfig.AlwaysOn
        minTlsVersion             = $oldApp.SiteConfig.MinTlsVersion
        ftpsState                 = $oldApp.SiteConfig.FtpsState
        appCommandLine            = $oldApp.SiteConfig.AppCommandLine
        http20Enabled             = $oldApp.SiteConfig.Http20Enabled
        scmMinTlsVersion          = "1.2"
        webSocketsEnabled         = $false
        remoteDebuggingEnabled    = $false
    }
}
Set-AzResource @prodConfig -Force | Out-Null
Write-Host "       Production config applied" -ForegroundColor Green

# ── Step 5: Create staging slot with its settings ──────────────────
Write-Host "[5/7] Creating staging slot..." -ForegroundColor Yellow
New-AzWebAppSlot -ResourceGroupName $ResourceGroup -Name $NewAppName -Slot "staging" | Out-Null
Write-Host "       Staging slot created" -ForegroundColor Green

# Copy staging app settings
Write-Host "       Copying $($stagingSettings.Count) staging app settings..." -ForegroundColor Yellow
Set-AzWebAppSlot -ResourceGroupName $ResourceGroup -Name $NewAppName -Slot "staging" -AppSettings $stagingSettings | Out-Null

# Apply staging site config
Write-Host "       Applying staging site config..." -ForegroundColor Yellow
$stagingConfig = @{
    ResourceGroupName = $ResourceGroup
    ResourceType      = "Microsoft.Web/sites/slots/config"
    ResourceName      = "$NewAppName/staging/web"
    ApiVersion        = "2023-12-01"
    PropertyObject    = @{
        linuxFxVersion            = $oldSlot.SiteConfig.LinuxFxVersion
        alwaysOn                  = $oldSlot.SiteConfig.AlwaysOn
        minTlsVersion             = $oldSlot.SiteConfig.MinTlsVersion
        ftpsState                 = $oldSlot.SiteConfig.FtpsState
        appCommandLine            = $oldSlot.SiteConfig.AppCommandLine
        http20Enabled             = $oldSlot.SiteConfig.Http20Enabled
        scmMinTlsVersion          = "1.2"
        webSocketsEnabled         = $false
        remoteDebuggingEnabled    = $false
    }
}
Set-AzResource @stagingConfig -Force | Out-Null
Write-Host "       Staging config applied" -ForegroundColor Green

# ── Step 6: VNet integration (both slots) ──────────────────────────
if ($appSubnetId) {
    Write-Host "[6/7] Enabling VNet integration..." -ForegroundColor Yellow

    # Production slot
    Write-Host "       Production slot → $($appSubnetId.Split('/')[-1])" -ForegroundColor Yellow
    $vnetProd = @{
        ResourceGroupName = $ResourceGroup
        ResourceType      = "Microsoft.Web/sites/networkConfig"
        ResourceName      = "$NewAppName/virtualNetwork"
        ApiVersion        = "2023-12-01"
        PropertyObject    = @{ subnetResourceId = $appSubnetId }
    }
    Set-AzResource @vnetProd -Force | Out-Null
    Write-Host "       Production VNet integration done" -ForegroundColor Green

    # Staging slot
    Write-Host "       Staging slot → $($appSubnetId.Split('/')[-1])" -ForegroundColor Yellow
    $vnetStaging = @{
        ResourceGroupName = $ResourceGroup
        ResourceType      = "Microsoft.Web/sites/slots/networkConfig"
        ResourceName      = "$NewAppName/staging/virtualNetwork"
        ApiVersion        = "2023-12-01"
        PropertyObject    = @{ subnetResourceId = $appSubnetId }
    }
    Set-AzResource @vnetStaging -Force | Out-Null
    Write-Host "       Staging VNet integration done" -ForegroundColor Green
} else {
    Write-Host "[6/7] Skipping VNet integration (no subnet found)" -ForegroundColor DarkGray
}

# ── Step 7: Verify ─────────────────────────────────────────────────
Write-Host "[7/7] Verifying new app..." -ForegroundColor Yellow
$verify = Get-AzWebApp -ResourceGroupName $ResourceGroup -Name $NewAppName
Write-Host "       Name:      $($verify.DefaultHostName)"
Write-Host "       Runtime:   $($verify.SiteConfig.LinuxFxVersion)"
Write-Host "       Identity:  $($verify.Identity.Type)"
Write-Host "       Settings:  $($verify.SiteConfig.AppSettings.Count) entries"

$verifySlot = Get-AzWebAppSlot -ResourceGroupName $ResourceGroup -Name $NewAppName -Slot "staging"
Write-Host "       Staging:   $($verifySlot.DefaultHostName)"
Write-Host "       Staging settings: $($verifySlot.SiteConfig.AppSettings.Count) entries"

# ── Summary ────────────────────────────────────────────────────────
Write-Host "`n══════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host "  ✅  App '$NewAppName' created in $ResourceGroup" -ForegroundColor Green
Write-Host "══════════════════════════════════════════════════════════" -ForegroundColor Green

Write-Host "`n📋 NEXT STEPS:" -ForegroundColor Yellow
Write-Host ""
Write-Host "  1. UPDATE ENTRA ID (AzTenantMigrator app registration):" -ForegroundColor White
Write-Host "     Portal → Entra ID → App registrations → AzTenantMigrator → Authentication" -ForegroundColor DarkGray
Write-Host "     Add these redirect URIs:" -ForegroundColor DarkGray
Write-Host "       ✦ https://$NewAppName.azurewebsites.net/auth/callback"
Write-Host "       ✦ https://$NewAppName-staging.azurewebsites.net/auth/callback"
Write-Host "       ✦ https://$NewAppName.azurewebsites.net/auth/admin-consent-callback"
Write-Host "       ✦ https://$NewAppName.azurewebsites.net/auth/target-callback"
Write-Host "       ✦ https://$NewAppName.azurewebsites.net  (post-logout)"
Write-Host ""
Write-Host "  2. UPDATE GITHUB SECRET (AZURE_CREDENTIALS):" -ForegroundColor White
Write-Host "     The service principal needs Contributor on $ResourceGroup" -ForegroundColor DarkGray
Write-Host "     (likely already has it since same RG)" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  3. UPDATE cd.yml:" -ForegroundColor White
Write-Host "     app-name: $OldAppName → $NewAppName" -ForegroundColor DarkGray
Write-Host "     Health check URLs → $NewAppName.azurewebsites.net" -ForegroundColor DarkGray
Write-Host "     (resource-group stays $ResourceGroup)" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  4. PUSH CODE to trigger deployment" -ForegroundColor White
Write-Host ""
Write-Host "  5. VERIFY login at:" -ForegroundColor White
Write-Host "     https://$NewAppName.azurewebsites.net" -ForegroundColor Cyan
Write-Host ""
Write-Host "  6. DELETE old app (after verification):" -ForegroundColor White
Write-Host "     Remove-AzWebApp -ResourceGroupName $ResourceGroup -Name $OldAppName -Force" -ForegroundColor DarkGray
Write-Host ""
