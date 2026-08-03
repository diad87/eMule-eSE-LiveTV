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

$reachEnvelope = Invoke-LabApi -BaseUrl $BaseUrl -Path $ReachPath -Token $Token `
    -AllowRemoteApi:$AllowRemoteApi -AllowUnavailable
$statusEnvelope = Invoke-LabApi -BaseUrl $BaseUrl -Path '/api/status' -Token $Token `
    -AllowRemoteApi:$AllowRemoteApi -AllowUnavailable
$preflightEnvelope = Invoke-LabApi -BaseUrl $BaseUrl -Path '/api/live/preflight' -Token $Token `
    -AllowRemoteApi:$AllowRemoteApi -AllowUnavailable

function Get-LabEnvelopeProjection {
    param([object]$Envelope, [string]$Name)

    $problems = New-Object System.Collections.ArrayList
    $data = $null
    if ($null -eq $Envelope) {
        $null = $problems.Add("$Name has no Invoke-LabApi envelope")
        return [pscustomobject]([ordered]@{ data = $null; problems = @($problems) })
    }
    $names = @($Envelope.PSObject.Properties.Name)
    if ($names -notcontains 'available' -or $Envelope.available -isnot [bool]) {
        $null = $problems.Add("$Name envelope has no boolean available field")
    } elseif (-not [bool]$Envelope.available) {
        $null = $problems.Add("$Name transport is unavailable")
    }
    if ($names -notcontains 'data') {
        $null = $problems.Add("$Name envelope has no data payload")
    } else {
        $data = $Envelope.data
    }
    if ($null -eq $data) {
        $null = $problems.Add("$Name envelope has no data payload")
    } elseif ($data -is [string] -or $data -is [Collections.IEnumerable]) {
        $null = $problems.Add("$Name data payload is not an object")
    }
    if ($names -contains 'error' -and -not [string]::IsNullOrWhiteSpace([string]$Envelope.error)) {
        $null = $problems.Add("$Name envelope records a transport error")
    }
    return [pscustomobject]([ordered]@{ data = $data; problems = @($problems) })
}

function Test-ReachObservabilityContract {
    param([object]$Payload)

    # Keep READY tied to the one authoritative contract checker.  A local
    # reduced field list would accept lookalikes that the gate later rejects.
    if ($null -eq $Payload) { return $false }
    $temporaryPayload = [IO.Path]::GetTempFileName()
    try {
        $payloadJson = $Payload | ConvertTo-Json -Depth 32
        [IO.File]::WriteAllText($temporaryPayload, $payloadJson, [Text.Encoding]::UTF8)
        $validator = Join-Path $PSScriptRoot 'validate_reach_status.ps1'
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $validator -Path $temporaryPayload 2>$null | Out-Null
        if ($LASTEXITCODE -ne 0) { return $false }

        # A valid unavailable snapshot is useful diagnostic evidence, but it
        # cannot prove the full per-plane observability needed for READY.
        $payloadFields = @($Payload.PSObject.Properties | ForEach-Object { $_.Name })
        if ($payloadFields -notcontains 'available' -or $Payload.available -isnot [bool] -or -not [bool]$Payload.available) {
            return $false
        }
        if ($payloadFields -notcontains 'planes' -or $null -eq $Payload.planes) { return $false }
        $planeFields = @($Payload.planes.PSObject.Properties | ForEach-Object { $_.Name })
        foreach ($planeName in @('ed2k_tcp_v4', 'kad_udp_v4', 'direct_v6')) {
            if ($planeFields -notcontains $planeName) { return $false }
        }
        return $true
    } catch {
        return $false
    } finally {
        Remove-Item -LiteralPath $temporaryPayload -Force -ErrorAction SilentlyContinue
    }
}

$reachProjection = Get-LabEnvelopeProjection -Envelope $reachEnvelope -Name 'reach'
$statusProjection = Get-LabEnvelopeProjection -Envelope $statusEnvelope -Name 'status'
$preflightProjection = Get-LabEnvelopeProjection -Envelope $preflightEnvelope -Name 'preflight'
$reach = $reachProjection.data
$status = $statusProjection.data
$preflight = $preflightProjection.data
$hasReach = $reachProjection.problems.Count -eq 0 -and (Test-ReachObservabilityContract -Payload $reach)
$hasStatus = $statusProjection.problems.Count -eq 0

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
    foreach ($problem in @($reachProjection.problems)) {
        $null = $gaps.Add([ordered]@{
            gap    = 'reach_envelope_invalid'
            detail = [string]$problem
            blocks = $rowsNeedingFullState
            fix    = 'return a successful Invoke-LabApi envelope whose data is ESE_REACH_STATUS_V1'
        })
    }
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
    api_envelopes    = [ordered]@{
        reach = $reachEnvelope
        status = $statusEnvelope
        live_preflight = $preflightEnvelope
    }
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
