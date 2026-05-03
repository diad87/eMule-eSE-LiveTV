param(
  [switch]$Force
)

$ErrorActionPreference = "Stop"
$root = Resolve-Path (Join-Path $PSScriptRoot "..")
$target = Join-Path $root "srchybrid/Debug"

if (-not (Test-Path $target)) {
  New-Item -ItemType Directory -Path $target | Out-Null
}

$deps = @(
  @{
    Name = "cximage.lib"
    Sources = @(
      "srchybrid/x64/Release/cximage.lib",
      "CxImage/CxImage/x64/Debug/cximage.lib",
      "CxImage/x64/Debug/cximage.lib"
    )
  },
  @{
    Name = "libpng16.lib"
    Sources = @(
      "srchybrid/x64/Debug/libpng16.lib",
      "srchybrid/x64/Release/libpng16.lib",
      "srchybrid/Release/libpng16.lib"
    )
  },
  @{
    Name = "mbedTLS.lib"
    Sources = @(
      "srchybrid/x64/Debug/mbedTLS.lib",
      "srchybrid/x64/Release/mbedTLS.lib",
      "srchybrid/Release/mbedTLS.lib",
      "mbedtls_old_2.7.0/visualc/vs2017/x64/Debug/mbedTLS.lib"
    )
  },
  @{
    Name = "miniupnpc.lib"
    Sources = @(
      "miniupnpc/msvc/x64/Debug/miniupnpc.lib",
      "srchybrid/x64/Release/miniupnpc.lib",
      "miniupnpc/msvc/x64/Release/miniupnpc.lib",
      "srchybrid/Release/miniupnpc.lib"
    )
  }
)

foreach ($dep in $deps) {
  $dst = Join-Path $target $dep.Name
  if ((Test-Path $dst) -and -not $Force) {
    Write-Host "exists $dst"
    continue
  }

  $src = $null
  foreach ($candidate in $dep.Sources) {
    $full = Join-Path $root $candidate
    if (Test-Path $full) {
      $src = $full
      break
    }
  }

  if (-not $src) {
    throw "Missing dependency: $($dep.Name). Tried: $($dep.Sources -join ', ')"
  }

  Copy-Item -LiteralPath $src -Destination $dst -Force
  Write-Host "copied $($dep.Name) <- $src"
}

Write-Host "Debug dependency staging complete: $target"
