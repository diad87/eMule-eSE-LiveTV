param(
  [switch]$VerifyOnly
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$sourceRoot = Join-Path $root "srchybrid\eSE"
$packageRoot = Join-Path $root "eSE-Package"
$packageSourceRoot = Join-Path $packageRoot "eSE"

$mappings = [System.Collections.Generic.List[object]]::new()

function Add-Mapping([string]$Source, [string]$Destination) {
  $mappings.Add([pscustomobject]@{
    Source = $Source
    Destination = $Destination
  })
}

$topLevelExtensions = @(".js", ".json", ".svg", ".ico", ".html")
$excludedTopLevel = @("config.json", "current_url.txt")

Get-ChildItem -LiteralPath $sourceRoot -File -Force | Where-Object {
  $topLevelExtensions -contains $_.Extension.ToLowerInvariant() -and
  $excludedTopLevel -notcontains $_.Name
} | ForEach-Object {
  Add-Mapping $_.FullName (Join-Path $packageSourceRoot $_.Name)
}

foreach ($directory in @("eSE-live", "pages", "routes", "shared")) {
  $directoryRoot = Join-Path $sourceRoot $directory
  Get-ChildItem -LiteralPath $directoryRoot -Recurse -File -Force | Where-Object {
    $relativeToDirectory = $_.FullName.Substring($directoryRoot.Length + 1)
    -not ($directory -eq "eSE-live" -and $relativeToDirectory.StartsWith("live\", [StringComparison]::OrdinalIgnoreCase))
  } | ForEach-Object {
    $relative = $_.FullName.Substring($sourceRoot.Length + 1)
    Add-Mapping $_.FullName (Join-Path $packageSourceRoot $relative)
  }
}

Add-Mapping (Join-Path $sourceRoot "ese-server.exe") (Join-Path $root "srchybrid\x64\Release\ese-server.exe")
Add-Mapping (Join-Path $sourceRoot "ese-server.exe") (Join-Path $packageRoot "ese-server.exe")
Add-Mapping (Join-Path $root "srchybrid\x64\Release\emule.exe") (Join-Path $packageRoot "emule.exe")
Add-Mapping (Join-Path $root "docs\USER_GUIDE.md") (Join-Path $packageRoot "USER_GUIDE.md")
Add-Mapping (Join-Path $root "docs\LIVETV_STATUS.md") (Join-Path $packageRoot "docs\LIVETV_STATUS.md")

foreach ($mapping in $mappings) {
  if (-not (Test-Path -LiteralPath $mapping.Source -PathType Leaf)) {
    throw "Package source file is missing: $($mapping.Source)"
  }

  if (-not $VerifyOnly) {
    $destinationDirectory = Split-Path -Parent $mapping.Destination
    New-Item -ItemType Directory -Path $destinationDirectory -Force | Out-Null
    Copy-Item -LiteralPath $mapping.Source -Destination $mapping.Destination -Force
  }

  if (-not (Test-Path -LiteralPath $mapping.Destination -PathType Leaf)) {
    throw "Packaged file is missing: $($mapping.Destination)"
  }

  $sourceHash = (Get-FileHash -LiteralPath $mapping.Source -Algorithm SHA256).Hash
  $destinationHash = (Get-FileHash -LiteralPath $mapping.Destination -Algorithm SHA256).Hash
  if ($sourceHash -ne $destinationHash) {
    throw "Package hash mismatch: $($mapping.Destination)"
  }
}

$mode = if ($VerifyOnly) { "verified" } else { "synchronized and verified" }
Write-Host "eSE package $mode ($($mappings.Count) files)." -ForegroundColor Green
