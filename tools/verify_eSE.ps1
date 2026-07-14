param(
  [string]$BaseUrl = "http://127.0.0.1:8080",
  [string]$Token = "",
  [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"
$root = Resolve-Path (Join-Path $PSScriptRoot "..")

function Step($name) {
  Write-Host ""
  Write-Host "== $name ==" -ForegroundColor Cyan
}

Step "Node syntax"
$nodeFiles = @(
  "srchybrid/eSE/security.js",
  "srchybrid/eSE/emule_api.js",
  "srchybrid/eSE/server.js",
  "srchybrid/eSE/routes/emule_routes.js",
  "srchybrid/eSE/routes/v1_routes.js",
  "srchybrid/eSE/pages/app_page.js",
  "srchybrid/eSE/pages/misc_pages.js",
  "eSE-Package/eSE/security.js",
  "eSE-Package/eSE/emule_api.js",
  "eSE-Package/eSE/server.js",
  "eSE-Package/eSE/routes/emule_routes.js",
  "eSE-Package/eSE/routes/v1_routes.js",
  "eSE-Package/eSE/pages/app_page.js",
  "eSE-Package/eSE/pages/misc_pages.js",
  "srchybrid/eSE/live_player_html.js",
  "srchybrid/eSE/live_player_server.js",
  "eSE-Package/eSE/live_player_html.js",
  "eSE-Package/eSE/live_player_server.js"
)
$liveDirs = @(
  "srchybrid/eSE/eSE-live",
  "eSE-Package/eSE/eSE-live"
)
foreach ($dir in $liveDirs) {
  Get-ChildItem -Path (Join-Path $root $dir) -Filter "*.js" | ForEach-Object {
    $nodeFiles += $_.FullName
  }
}
foreach ($file in $nodeFiles) {
  if ([System.IO.Path]::IsPathRooted($file)) {
    $full = $file
  } else {
    $full = Join-Path $root $file
  }
  node --check $full
  if ($LASTEXITCODE -ne 0) { throw "node --check failed for $file" }
}

Step "LiveTV regression tests"
Push-Location (Join-Path $root "srchybrid/eSE")
try {
  npm test
  if ($LASTEXITCODE -ne 0) { throw "LiveTV regression tests failed." }
} finally {
  Pop-Location
}

Step "Portable package parity"
& (Join-Path $root "tools/sync_ese_package.ps1") -VerifyOnly
if ($LASTEXITCODE -ne 0) { throw "Portable package verification failed." }

if (-not $SkipBuild) {
  Step "C++ Release x64 build"
  $msbuildList = Get-Content (Join-Path $root "msbuild_path.txt") | Where-Object { $_ -and (Test-Path $_) }
  if (-not $msbuildList) { throw "MSBuild not found. Check msbuild_path.txt." }
  & $msbuildList[0] (Join-Path $root "srchybrid/emule.vcxproj") /m /p:Configuration=Release /p:Platform=x64 /t:Build /v:minimal /clp:ErrorsOnly
}

Step "Optional HTTP smoke"
try {
  Invoke-WebRequest -Uri ($BaseUrl + "/api/v1/status") -TimeoutSec 3 -UseBasicParsing | Out-Null
  throw "Unauthenticated /api/v1/status unexpectedly succeeded."
} catch {
  if ($_.Exception.Response -and [int]$_.Exception.Response.StatusCode -eq 401) {
    Write-Host "Unauthenticated /api/v1/status returns 401 as expected."
  } elseif ($_.Exception.Message -match "No se puede conectar|No es posible conectar|actively refused|Unable to connect|connection|servidor remoto") {
    Write-Host "Server is not running; HTTP smoke skipped."
    exit 0
  } else {
    throw
  }
}

if ($Token) {
  $headers = @{ "X-ESE-Token" = $Token }
  $status = Invoke-RestMethod -Uri ($BaseUrl + "/api/v1/status") -Headers $headers -TimeoutSec 5
  if (-not $status.ok) { throw "Authenticated /api/v1/status did not return ok=true." }
  Write-Host "Authenticated /api/v1/status ok."
} else {
  Write-Host "Pass -Token to run authenticated smoke tests."
}
