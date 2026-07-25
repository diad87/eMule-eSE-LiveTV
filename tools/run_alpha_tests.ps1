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

function Find-MSBuild {
    $command = Get-Command MSBuild.exe -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vswhere) {
        $root = & $vswhere -latest -prerelease -products * `
            -requires Microsoft.Component.MSBuild -property installationPath
        if ($root) {
            $candidate = Join-Path $root 'MSBuild\Current\Bin\MSBuild.exe'
            if (Test-Path $candidate) { return $candidate }
        }
    }
    return $null
}

function Ensure-CryptoPP {
    $library = Join-Path $RepoRoot 'cryptopp\x64\Output\Release\cryptlib.lib'
    if (Test-Path $library -PathType Leaf) { return }

    $msbuild = Find-MSBuild
    if (-not $msbuild) {
        throw 'Crypto++ is missing and MSBuild could not be found'
    }
    & $msbuild (Join-Path $RepoRoot 'cryptopp\cryptlib.vcxproj') /t:Build `
        /p:Configuration=Release /p:Platform=x64 /p:PlatformToolset=v143 `
        /m:1 /v:minimal /nologo
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $library -PathType Leaf)) {
        throw 'Crypto++ Release x64 dependency build failed'
    }
}

if ($Suite -eq 'Core' -or $Suite -eq 'All') {
    Run 'WP0 laboratory toolkit' {
        & (Join-Path $RepoRoot 'tools\lab\test_lab_tools.ps1') -RepoRoot $RepoRoot
    }
    Run 'language resources' { & (Join-Path $RepoRoot 'tools\check_languages.ps1') -RepoRoot $RepoRoot }
    Run 'protocol registry' { & python (Join-Path $RepoRoot 'tools\check_protocol_registry.py') }
    Run 'direct port ownership linter' { & python (Join-Path $RepoRoot 'tools\check_direct_port_usage.py') }
    Run 'address wire tests' { & python (Join-Path $RepoRoot 'tests\test_address_wire.py') }
    Run 'server IPv6 source wire tests' { & python (Join-Path $RepoRoot 'tests\test_foundsources_v6_wire.py') }
    Run 'IPv6 callback wire tests' { & python (Join-Path $RepoRoot 'tests\test_callback_v6_wire.py') }
    Run 'IPv6 transport wire tests' { & python (Join-Path $RepoRoot 'tests\test_ipv6_transport_wire.py') }
    Run 'tunnel framing tests' { & python (Join-Path $RepoRoot 'tests\test_tunnel_framing.py') }
    Run 'libreach' { & cmd /d /c (Join-Path $RepoRoot 'libreach\make.bat') }
    Run 'libnatmap' { & cmd /d /c (Join-Path $RepoRoot 'libnatmap\make.bat') }
    Run 'Crypto++ Release x64 dependency' { Ensure-CryptoPP }
    Run 'libkad6' { & cmd /d /c (Join-Path $RepoRoot 'libkad6\test_all.bat') }
    Run 'eSE npm tests' {
        Push-Location (Join-Path $RepoRoot 'srchybrid\eSE')
        try {
            # Windows PowerShell 5.1 turns any native stderr line into an
            # ErrorRecord under Stop, even when the process exits zero. Merge
            # streams inside cmd.exe so npm deprecation warnings remain logged
            # and gate solely on the native exit code.
            $npmOutput = @(& cmd.exe /d /s /c 'npm.cmd ci --no-audit --no-fund 2>&1')
            $npmExit = $LASTEXITCODE
            $npmOutput | ForEach-Object { Write-Host $_ }
            if ($npmExit -ne 0) { throw "npm ci failed with exit code $npmExit" }

            $npmOutput = @(& cmd.exe /d /s /c 'npm.cmd test 2>&1')
            $npmExit = $LASTEXITCODE
            $npmOutput | ForEach-Object { Write-Host $_ }
            if ($npmExit -ne 0) { throw "npm test failed with exit code $npmExit" }

            $npmOutput = @(& cmd.exe /d /s /c 'npm.cmd audit --audit-level=high 2>&1')
            $npmExit = $LASTEXITCODE
            $npmOutput | ForEach-Object { Write-Host $_ }
            if ($npmExit -ne 0) { throw "npm audit failed with exit code $npmExit" }
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

Write-Host "`neSE test suite PASS: $Suite" -ForegroundColor Green
