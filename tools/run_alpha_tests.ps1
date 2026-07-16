[CmdletBinding()]
param(
    [string]$RepoRoot = '',
    [ValidateSet('Core','Integration','All')][string]$Suite = 'All'
)

$ErrorActionPreference = 'Stop'
if (-not $RepoRoot) { $RepoRoot = Split-Path -Parent $PSScriptRoot }
$RepoRoot = (Resolve-Path $RepoRoot).Path

function Run([string]$Name, [scriptblock]$Body) {
    Write-Host "`n--- $Name ---" -ForegroundColor Cyan
    & $Body
    if ($LASTEXITCODE -ne 0) { throw "$Name failed with exit code $LASTEXITCODE" }
}

if ($Suite -eq 'Core' -or $Suite -eq 'All') {
    Run 'protocol registry' { & python (Join-Path $RepoRoot 'tools\check_protocol_registry.py') }
    Run 'direct port ownership linter' { & python (Join-Path $RepoRoot 'tools\check_direct_port_usage.py') }
    Run 'address wire tests' { & python (Join-Path $RepoRoot 'tests\test_address_wire.py') }
    Run 'tunnel framing tests' { & python (Join-Path $RepoRoot 'tests\test_tunnel_framing.py') }
    Run 'libreach' { & cmd /d /c (Join-Path $RepoRoot 'libreach\make.bat') }
    Run 'libnatmap' { & cmd /d /c (Join-Path $RepoRoot 'libnatmap\make.bat') }
    Run 'libkad6' { & cmd /d /c (Join-Path $RepoRoot 'libkad6\test_all.bat') }
    Run 'eSE npm tests' {
        Push-Location (Join-Path $RepoRoot 'srchybrid\eSE')
        try {
            & npm.cmd ci --no-audit --no-fund
            if ($LASTEXITCODE -eq 0) { & npm.cmd test }
            if ($LASTEXITCODE -eq 0) { & npm.cmd audit --audit-level=high }
        } finally { Pop-Location }
    }
}

if ($Suite -eq 'Integration' -or $Suite -eq 'All') {
    Run 'srchybrid standalone tests' { & cmd /d /c (Join-Path $RepoRoot 'srchybrid\tests\make.bat') }
    Run 'librelaycore release' { & cmd /d /c (Join-Path $RepoRoot 'librelaycore\make.bat') }
    Run 'librelaycore ASan' {
        $env:RELAY_ASAN = '1'
        try { & cmd /d /c (Join-Path $RepoRoot 'librelaycore\make.bat') }
        finally { Remove-Item Env:RELAY_ASAN -ErrorAction SilentlyContinue }
    }
    Run 'relayedge release and ASan' { & cmd /d /c (Join-Path $RepoRoot 'relayedge\make.bat') }
    Run 'librelayclient release and ASan' { & cmd /d /c (Join-Path $RepoRoot 'librelayclient\make.bat') }
}

Write-Host "`nAlpha test suite PASS: $Suite" -ForegroundColor Green
