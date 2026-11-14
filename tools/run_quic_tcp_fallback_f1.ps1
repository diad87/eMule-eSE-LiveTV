[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Executable,
    [Parameter(Mandatory = $true)][string]$NativeDependencyRoot,
    [Parameter(Mandatory = $true)][string]$OutputRoot,
    [ValidateSet('x64', 'Win32')][string]$Architecture = 'x64',
    [ValidateRange(1024, 65535)][int]$TcpPort = 57351,
    [ValidateRange(1024, 65535)][int]$UdpPort = 57352
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'start_v93_detached_process.ps1')
$root = [IO.Path]::GetFullPath($OutputRoot)
& (Join-Path $PSScriptRoot 'prepare_reach_binding_selftest.ps1') -Executable $Executable `
    -NativeDependencyRoot $NativeDependencyRoot -NativeArchitecture $Architecture -SignedQuic `
    -ProfileRoot $root -TcpPort $TcpPort -UdpPort $UdpPort
$prepared = Get-Content -LiteralPath (Join-Path $root 'prepared.json') -Raw | ConvertFrom-Json
$exe = Join-Path $root 'emule.exe'
if ((Get-FileHash -LiteralPath $exe).Hash -ne $prepared.executable_sha256) { throw 'Prepared executable changed.' }

$expectedHash = '2C06ADE942EE3F17A048DD1064B2FAB046A4BB95386D8BB41B68DC6711AC2AF3'
$previousMode = $env:ESE_TCP_FALLBACK_F1
$process = $null
$exitCode = $null
$actualHash = $null
$size = $null
$markers = @()
$verdict = 'FAIL'
try {
    $env:ESE_TCP_FALLBACK_F1 = '1'
    $process = Start-V93DetachedProcess -FilePath $exe -WorkingDirectory $root -ArgumentList @($prepared.arguments)
    $finished = $process.WaitForExit(275000)
    if ($finished) { $exitCode = $process.ExitCode }
    $log = Join-Path $root 'logs/eMule.log'
    if (Test-Path -LiteralPath $log) {
        $markers = @(Select-String -LiteralPath $log -Pattern 'TCP_FALLBACK_F1|REACH_SELFTEST FAIL' | ForEach-Object Line)
    }
    $received = Join-Path $root 'Incoming/quic-tcp-fallback-f1.bin'
    if (Test-Path -LiteralPath $received) {
        $actualHash = (Get-FileHash -LiteralPath $received).Hash
        $size = (Get-Item -LiteralPath $received).Length
    }
    if ($finished -and $exitCode -eq 0 -and $actualHash -eq $expectedHash -and $size -eq 1GB -and
        @($markers -match "TCP_FALLBACK_F1 PASS bytes=1073741824 parts=111 slots=1 fallbacks=1 sha256=$expectedHash").Count -eq 1 -and
        @($markers -match 'TCP_FALLBACK_F1 timing: fallback_ms=\d+ ready_ms=\d+ dropped=[1-9]\d* initials=[1-9]\d*').Count -eq 1) {
        $verdict = 'PASS'
    }
} finally {
    $env:ESE_TCP_FALLBACK_F1 = $previousMode
    if ($process) {
        try {
            if (!$process.HasExited) { $process.StopIncompleteLaunch() }
            [ordered]@{
                schema = 'ese.v93.quic-tcp-fallback-f1/1'
                verdict = $verdict
                architecture = $Architecture
                exit_code = $exitCode
                executable_sha256 = $prepared.executable_sha256
                desktop = $process.Desktop
                expected_sha256 = $expectedHash
                received_sha256 = $actualHash
                received_bytes = $size
                markers = $markers
                scope = 'Product downloader on an explicitly scheduled mixed plan with observed TCP, dropped QUIC Initial, fresh TCP SecureIdent and a wire fixture peer on IPv4 loopback.'
            } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $root 'fallback-f1-evidence.json') -Encoding UTF8
        } finally { $process.Dispose() }
    }
}

$markers | Write-Output
if ($verdict -ne 'PASS') { throw 'TCP fallback did not complete one authenticated switch followed by an exact file transfer.' }
