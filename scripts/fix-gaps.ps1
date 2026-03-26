$ErrorActionPreference = "Stop"
$sub = "f7809471-a133-4015-84d5-a5f6a73b11ee"
$rg = "rg-tenova"
$app = "azure-sub-migrator"
$baseId = "/subscriptions/$sub/resourceGroups/$rg/providers/Microsoft.Web/sites/$app"
$lawId = "/subscriptions/$sub/resourceGroups/$rg/providers/Microsoft.OperationalInsights/workspaces/law-tenova"

# ── 1. Verify health check was set on PROD ─────────────────────────
Write-Host "`n[1/6] Checking production health check..." -ForegroundColor Yellow
$prodConf = Get-AzResource -ResourceId "$baseId/config/web" -ApiVersion "2023-12-01"
if ($prodConf.Properties.healthCheckPath -eq "/healthz") {
    Write-Host "       PROD healthCheckPath = /healthz (already set)" -ForegroundColor Green
} else {
    Write-Host "       Setting PROD healthCheckPath..." -ForegroundColor Yellow
    Set-AzResource -ResourceId "$baseId/config/web" -ApiVersion "2023-12-01" -PropertyObject @{
        healthCheckPath = "/healthz"
        httpLoggingEnabled = $true
        logsDirectorySizeLimit = 100
    } -Force | Out-Null
    Write-Host "       PROD healthCheckPath = /healthz" -ForegroundColor Green
}

# ── 2. Set health check on STAGING ─────────────────────────────────
Write-Host "[2/6] Setting staging health check..." -ForegroundColor Yellow
Set-AzResource -ResourceId "$baseId/slots/staging/config/web" -ApiVersion "2023-12-01" -PropertyObject @{
    healthCheckPath = "/healthz"
} -Force | Out-Null
Write-Host "       STAGING healthCheckPath = /healthz" -ForegroundColor Green

# ── 3. Enable HTTP logging + log dir on PROD ──────────────────────
Write-Host "[3/6] Enabling HTTP logging on production..." -ForegroundColor Yellow
Set-AzResource -ResourceId "$baseId/config/web" -ApiVersion "2023-12-01" -PropertyObject @{
    httpLoggingEnabled = $true
    logsDirectorySizeLimit = 100
} -Force | Out-Null
Write-Host "       PROD httpLogging=true, logDirLimit=100" -ForegroundColor Green

# ── 4. Set app log level to Verbose on PROD ───────────────────────
Write-Host "[4/6] Setting app log level to Verbose on production..." -ForegroundColor Yellow
az webapp log config -g $rg -n $app --application-logging filesystem --level verbose -o none 2>$null
Write-Host "       PROD applicationLogs.fileSystem.level = Verbose" -ForegroundColor Green

# ── 5. Create diagnostic settings on PROD (matching tenova-app) ───
Write-Host "[5/6] Creating diagnostic settings on production..." -ForegroundColor Yellow
$existingDiag = az monitor diagnostic-settings list --resource $baseId --query "[?name=='app-diagnostics'].name" -o tsv 2>$null
if ($existingDiag) {
    Write-Host "       Diagnostic settings already exist, skipping" -ForegroundColor DarkGray
} else {
    az monitor diagnostic-settings create `
        --resource $baseId `
        --name "app-diagnostics" `
        --workspace $lawId `
        --logs '[{\"category\":\"AppServiceHTTPLogs\",\"enabled\":true},{\"category\":\"AppServiceConsoleLogs\",\"enabled\":true},{\"category\":\"AppServiceAppLogs\",\"enabled\":true},{\"category\":\"AppServicePlatformLogs\",\"enabled\":true},{\"category\":\"AppServiceAuditLogs\",\"enabled\":false},{\"category\":\"AppServiceIPSecAuditLogs\",\"enabled\":false},{\"category\":\"AppServiceAuthenticationLogs\",\"enabled\":false}]' `
        --metrics '[{\"category\":\"AllMetrics\",\"enabled\":true}]' `
        -o none 2>$null
    Write-Host "       Diagnostic settings created → law-tenova" -ForegroundColor Green
}

# ── 6. Verify all fixes ───────────────────────────────────────────
Write-Host "[6/6] Verifying..." -ForegroundColor Yellow
$v = Get-AzResource -ResourceId "$baseId/config/web" -ApiVersion "2023-12-01"
Write-Host "       PROD healthCheck:   $($v.Properties.healthCheckPath)"
Write-Host "       PROD httpLog:       $($v.Properties.httpLoggingEnabled)"
Write-Host "       PROD logDirLimit:   $($v.Properties.logsDirectorySizeLimit)"

$vs = Get-AzResource -ResourceId "$baseId/slots/staging/config/web" -ApiVersion "2023-12-01"
Write-Host "       STAG healthCheck:   $($vs.Properties.healthCheckPath)"

$diag = az monitor diagnostic-settings list --resource $baseId --query "[].name" -o tsv 2>$null
Write-Host "       PROD diagnostics:   $diag"

Write-Host "`n=== ALL GAPS FIXED ===" -ForegroundColor Green
