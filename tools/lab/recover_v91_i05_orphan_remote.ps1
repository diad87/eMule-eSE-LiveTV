[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$JobRequestPath
)

$ErrorActionPreference = 'Stop'
$jobRoot = Split-Path -Parent ([IO.Path]::GetFullPath($JobRequestPath))
$jobsRoot = Split-Path -Parent $jobRoot
$kitRoot = Split-Path -Parent $jobsRoot
$activePath = Join-Path $kitRoot 'ACTIVE-V91-I05-T1.json'
$cleanupPath = Join-Path $kitRoot 'cleanup_v91_i05_downloader.ps1'
$jobRequest = Get-Content -LiteralPath $JobRequestPath -Raw |
    ConvertFrom-Json
$expectedNonce = [string]$jobRequest.request.campaign_nonce
if ($expectedNonce -notmatch '^[0-9a-f]{32}$') {
    throw 'campaign_nonce debe ser 32hex lowercase.'
}
if (-not (Test-Path -LiteralPath $cleanupPath -PathType Leaf)) {
    throw 'No existe el cleanup H3 instalado.'
}

$runnerStopped = $false
if (Test-Path -LiteralPath $activePath -PathType Leaf) {
    $active = Get-Content -LiteralPath $activePath -Raw |
        ConvertFrom-Json
    if ([string]$active.nonce -cne $expectedNonce) {
        throw 'ACTIVE pertenece a otra campaña; se rechaza la recuperación.'
    }
    $runnerPid = [int]$active.control_listener_process_id
    if ($runnerPid -le 0) {
        throw 'ACTIVE no registra un PID de runner válido.'
    }
    $runner = Get-CimInstance Win32_Process -Filter (
        "ProcessId=$runnerPid") -ErrorAction Stop
    if ($null -ne $runner) {
        if ([string]$runner.Name -cne 'powershell.exe' -or
            [string]$runner.CommandLine -notlike
                '*run_v91_i05_downloader_kit.ps1*') {
            throw 'El PID registrado no es el runner H3 esperado.'
        }
        Stop-Process -Id $runnerPid -Force -ErrorAction Stop
        foreach ($attempt in 1..20) {
            Start-Sleep -Milliseconds 250
            if ($null -eq (Get-Process -Id $runnerPid `
                    -ErrorAction SilentlyContinue)) {
                $runnerStopped = $true
                break
            }
        }
        if (-not $runnerStopped) {
            throw 'El runner H3 huérfano no terminó.'
        }
    }
    & $cleanupPath
}

if (Test-Path -LiteralPath $activePath -PathType Leaf) {
    throw 'La recuperación terminó con ACTIVE todavía presente.'
}

[pscustomobject][ordered]@{
    schema = 'ese.v91.i05.t1-orphan-recovery/v1'
    status = 'CLEAN'
    campaign_nonce = $expectedNonce
    runner_stopped = $runnerStopped
    active_exists = $false
    completed_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
} | ConvertTo-Json -Depth 5 -Compress
