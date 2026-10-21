<#
.SYNOPSIS
    Samples direct-reachability state and reports what the gate can observe.

.DESCRIPTION
    Prefers the dedicated reachability endpoint. When it is absent - which is
    the case on main today - it falls back to the legacy surface and records an
    explicit observability gap instead of pretending the sample is complete.

    The point of this script is honesty: HG03 requires 'candidate', 'verified',
    'expired' and 'stale' to be distinguishable WITHOUT reading logs. The legacy
    surface collapses every mapper into one tri-state string, so it cannot
    satisfy that. Running this before booking a lab session tells you whether
    the session would produce admissible evidence.

    Emits 'ese.lab.reach-probe/v1'.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidateSet('A', 'B', 'R', 'controller')]
    [string]$NodeRole,
    [string]$BaseUrl = 'http://127.0.0.1:4711',
    [string]$Token = '',
    [string]$ReachPath = '/api/reach/status',
    [string]$Label = '',
    [string]$Commit = '',
    [string]$OutFile = '',
    [switch]$AllowRemoteApi,
    [switch]$IncludeSensitive
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\common.ps1')

if (-not $OutFile) {
    $OutFile = Join-Path (Get-Location) ('reach-probe-{0}.json' -f $NodeRole.ToLowerInvariant())
}

# Gate rows that require per-plane mapping state. Kept here so the gap report
# names the concrete consequence rather than a vague warning.
$rowsNeedingFullState = @('H93-03', 'H93-07', 'H93-09', 'H93-11', 'HG03', 'HG06')

$reach = Invoke-LabApi -BaseUrl $BaseUrl -Path $ReachPath -Token $Token `
    -AllowRemoteApi:$AllowRemoteApi -AllowUnavailable
$status = Invoke-LabApi -BaseUrl $BaseUrl -Path '/api/status' -Token $Token `
    -AllowRemoteApi:$AllowRemoteApi -AllowUnavailable
$preflight = Invoke-LabApi -BaseUrl $BaseUrl -Path '/api/live/preflight' -Token $Token `
    -AllowRemoteApi:$AllowRemoteApi -AllowUnavailable

# Invoke-LabApi returns a recorded-unavailable object rather than throwing when
# -AllowUnavailable is set; treat any response carrying real fields as present.
function Test-LabResponsePresent {
    param([object]$Response)
    if ($null -eq $Response) { return $false }
    $names = @($Response.PSObject.Properties.Name)
    if ($names -contains 'available' -and -not [bool]$Response.available) { return $false }
    if ($names -contains 'error' -and $Response.error) { return $false }
    return ($names.Count -gt 0)
}

$hasReach = Test-LabResponsePresent -Response $reach
$hasStatus = Test-LabResponsePresent -Response $status

$observed = [ordered]@{
    planes_available       = $hasReach
    mapping_state_readable = $hasReach
    generation_readable    = $hasReach
    legacy_upnp_tristate   = ''
}
if ($hasStatus -and (@($status.PSObject.Properties.Name) -contains 'upnp_ports_forwarded')) {
    $observed.legacy_upnp_tristate = [string]$status.upnp_ports_forwarded
}

$gaps = New-Object System.Collections.ArrayList
if (-not $hasReach) {
    $null = $gaps.Add([ordered]@{
        gap    = 'no_reachability_endpoint'
        detail = ("$ReachPath is not served; per-plane state, lease detail and " +
                  'topology generation are not observable from outside the process')
        blocks = $rowsNeedingFullState
        fix    = ('serialize CDirectReachabilityManager::GetSnapshot() behind a ' +
                  'read-only endpoint, using the cached-snapshot-under-mutex ' +
                  'pattern already used by /api/krp/status')
    })
    $null = $gaps.Add([ordered]@{
        gap    = 'mapper_state_collapsed'
        detail = ('the legacy surface exposes only upnp_ports_forwarded ' +
                  '(true|false|unknown), which cannot distinguish CANDIDATE ' +
                  'from VERIFIED, and carries no mapper, lease or generation')
        blocks = @('HG03', 'HG06')
        fix    = 'same adapter as above'
    })
}

$readiness = 'READY'
if ($gaps.Count -gt 0) { $readiness = 'INSUFFICIENT_OBSERVABILITY' }

$probe = [ordered]@{
    schema           = 'ese.lab.reach-probe/v1'
    captured_at_utc  = Get-LabUtcTimestamp
    node_role        = $NodeRole
    label            = $Label
    commit           = $Commit
    api_origin       = [ordered]@{
        scheme   = ([Uri]$BaseUrl).Scheme
        loopback = ([Uri]$BaseUrl).IsLoopback
        path     = $ReachPath
    }
    gate_readiness   = $readiness
    observability    = $observed
    gaps             = @($gaps)
    reach            = $reach
    status           = $status
    live_preflight   = $preflight
}

$safeProbe = ConvertTo-LabSanitizedValue -InputObject $probe `
    -RedactAddresses:(-not $IncludeSensitive)
$writtenPath = Write-LabJson -Value $safeProbe -Path $OutFile

Write-Host "Reach probe written: $writtenPath" -ForegroundColor Green
if ($readiness -eq 'READY') {
    Write-Host 'Gate readiness: READY' -ForegroundColor Green
} else {
    Write-Host "Gate readiness: $readiness" -ForegroundColor Yellow
    foreach ($gap in $gaps) {
        Write-Host ("  - {0}: blocks {1}" -f $gap.gap, ($gap.blocks -join ', ')) -ForegroundColor Yellow
    }
    Write-Host '  A physical session run now would not produce admissible HG06 evidence.' -ForegroundColor Yellow
}
