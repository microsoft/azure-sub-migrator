$ErrorActionPreference = "Stop"

Write-Host "`n=== CONFIG GAP AUDIT: tenova-app vs azure-sub-migrator ===" -ForegroundColor Cyan

# ── Site config comparison ─────────────────────────────
$q = "{healthCheck:siteConfig.healthCheckPath, httpLog:siteConfig.httpLoggingEnabled, detailErr:siteConfig.detailedErrorLoggingEnabled, reqTrace:siteConfig.requestTracingEnabled, logDirLimit:siteConfig.logsDirectorySizeLimit, autoHeal:siteConfig.autoHealEnabled, workers:siteConfig.numberOfWorkers, ipRestrictions:length(siteConfig.ipSecurityRestrictions)}"

Write-Host "`nFetching old prod..."
$op = az webapp show -g rg-tenova -n tenova-app --query $q 2>$null | ConvertFrom-Json
Write-Host "Fetching old staging..."
$os = az webapp show -g rg-tenova -n tenova-app -s staging --query $q 2>$null | ConvertFrom-Json
Write-Host "Fetching new prod..."
$np = az webapp show -g rg-tenova -n azure-sub-migrator --query $q 2>$null | ConvertFrom-Json
Write-Host "Fetching new staging..."
$ns = az webapp show -g rg-tenova -n azure-sub-migrator -s staging --query $q 2>$null | ConvertFrom-Json

Write-Host "`n--- SITE CONFIG ---" -ForegroundColor Yellow
$headers = "{0,-18} {1,-16} {2,-16} {3,-16} {4,-16} {5}" -f "Setting","OLD-Prod","OLD-Stag","NEW-Prod","NEW-Stag","Status"
Write-Host $headers
Write-Host ("-" * 98)
foreach ($p in "healthCheck","httpLog","detailErr","reqTrace","logDirLimit","autoHeal","workers","ipRestrictions") {
    $pGap = if ("$($op.$p)" -ne "$($np.$p)") { "!" } else { "" }
    $sGap = if ("$($os.$p)" -ne "$($ns.$p)") { "!" } else { "" }
    $status = if ($pGap -or $sGap) { "<-- GAP" } else { "OK" }
    Write-Host ("{0,-18} {1,-16} {2,-16} {3,-16} {4,-16} {5}" -f $p, $op.$p, $os.$p, $np.$p, $ns.$p, $status)
}

# ── Diagnostics settings ──────────────────────────────
Write-Host "`n--- DIAGNOSTIC SETTINGS ---" -ForegroundColor Yellow

$oldId = "/subscriptions/f7809471-a133-4015-84d5-a5f6a73b11ee/resourceGroups/rg-tenova/providers/Microsoft.Web/sites/tenova-app"
$newId = "/subscriptions/f7809471-a133-4015-84d5-a5f6a73b11ee/resourceGroups/rg-tenova/providers/Microsoft.Web/sites/azure-sub-migrator"

Write-Host "OLD prod diagnostics:"
az monitor diagnostic-settings list --resource $oldId -o table 2>$null
Write-Host "`nNEW prod diagnostics:"
az monitor diagnostic-settings list --resource $newId -o table 2>$null

# Check slots too
$oldSlotId = "$oldId/slots/staging"
$newSlotId = "$newId/slots/staging"
Write-Host "`nOLD staging diagnostics:"
az monitor diagnostic-settings list --resource $oldSlotId -o table 2>$null
Write-Host "`nNEW staging diagnostics:"
az monitor diagnostic-settings list --resource $newSlotId -o table 2>$null

# ── Custom domain / SSL ───────────────────────────────
Write-Host "`n--- CUSTOM DOMAINS ---" -ForegroundColor Yellow
Write-Host "OLD prod:"
az webapp show -g rg-tenova -n tenova-app --query "hostNames" -o tsv 2>$null
Write-Host "NEW prod:"
az webapp show -g rg-tenova -n azure-sub-migrator --query "hostNames" -o tsv 2>$null

# ── Logging config ────────────────────────────────────
Write-Host "`n--- APP SERVICE LOGS ---" -ForegroundColor Yellow
Write-Host "OLD prod:"
az webapp log show -g rg-tenova -n tenova-app 2>$null
Write-Host "`nNEW prod:"
az webapp log show -g rg-tenova -n azure-sub-migrator 2>$null

Write-Host "`n=== AUDIT COMPLETE ===" -ForegroundColor Green
