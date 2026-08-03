<#
.SYNOPSIS
    Validates an ESE_REACH_STATUS_V1 payload against the frozen contract.

.DESCRIPTION
    This is the executable specification for the ESE_REACH_STATUS_V1
    /api/reach/status payload. It checks three
    layers, and the interesting failures live in the last two:

      structure - required fields and known enum values;
      semantics - gate_state agrees with state, reason_code agrees with reason,
                  and a plane can never read VERIFIED while its evidence is
                  stale or absent;
      privacy   - no ownership nonce, no internal clock, no full IP address.

    Use -Goldens to self-check the reference payloads, -Path to check a
    captured response, or -Live to check a running node.

    Emits 'ese.lab.reach-status-validation/v1'. Exit code is non-zero on any
    violation so it can gate CI.
#>
[CmdletBinding(DefaultParameterSetName = 'Goldens')]
param(
    [Parameter(ParameterSetName = 'Goldens')][switch]$Goldens,
    [Parameter(Mandatory = $true, ParameterSetName = 'File')][string]$Path,
    [Parameter(Mandatory = $true, ParameterSetName = 'Live')][switch]$Live,
    [Parameter(ParameterSetName = 'Live')][string]$BaseUrl = 'http://127.0.0.1:4711',
    [Parameter(ParameterSetName = 'Live')][string]$Token = '',
    [string]$OutFile = ''
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..\common.ps1')

$planeNames = @('ed2k_tcp_v4', 'kad_udp_v4', 'direct_v6')

$reachabilityStates = @('Disabled', 'Discovering', 'Mapping', 'CandidateMapped',
    'Verifying', 'Reachable', 'Renewing', 'Degraded', 'BlockedByCgnat', 'BlockedByRouter')

# Section 4 of the card. Deliberately not a bijection: Verifying is CANDIDATE
# because verification in progress is not proof.
$gateStateMap = @{
    'Disabled'        = 'DISABLED'
    'Discovering'     = 'DISCOVERING'
    'Mapping'         = 'DISCOVERING'
    'CandidateMapped' = 'CANDIDATE'
    'Verifying'       = 'CANDIDATE'
    'Reachable'       = 'VERIFIED'
    'Renewing'        = 'VERIFIED'
    'Degraded'        = 'WITHDRAWN'
    'BlockedByCgnat'  = 'BLOCKED'
    'BlockedByRouter' = 'BLOCKED'
}

# natmap_types.h:60-83. Append-only and persisted; never renumber.
$reasonCodes = @{
    'None' = 0; 'DisabledByPreference' = 1; 'NoListener' = 2; 'NoRoute' = 3
    'NoGateway' = 4; 'NoMappingProtocol' = 5; 'OperatorDenied' = 6
    'MappingDenied' = 7; 'MappingConflict' = 8; 'MappingTimeout' = 9
    'InvalidResponse' = 10; 'StaleGeneration' = 11; 'LeaseExpired' = 12
    'InterfaceChanged' = 13; 'EndpointDependentMapping' = 14; 'InboundFiltered' = 15
    'ServerCallbackFailed' = 16; 'PeerIncompatible' = 17; 'PortInUse' = 18
    'VerificationTimeout' = 19; 'CgnatWithoutLease' = 20
    'RouterRejectedAllCandidates' = 21
}

$mapperKinds   = @('None', 'Existing', 'UpnpIgd', 'Pcp', 'NatPmp', 'FirewallPinhole')
$transports    = @('Tcp', 'Udp')
$evidenceKinds = @('None', 'MappingLease', 'ServerObservedEndpoint', 'ServerHighId',
    'InboundTcpAccept', 'DirectPeerHandshake')
$endpointSources = @('None', 'LocalInterface', 'ServerObserved', 'UpnpExternalAddress',
    'PcpMap', 'NatPmpPublicAddress', 'PeerProbe', 'ServerIdChange')
$families      = @('IPv4', 'IPv6', 'Unspecified')
$addressClasses = @('unspecified', 'loopback', 'private', 'cgnat', 'linklocal', 'public')

function Get-Field {
    param([object]$Object, [Parameter(Mandatory = $true)][string]$Name, [object]$Default = $null)
    if ($null -eq $Object) { return $Default }
    $propertyNames = @($Object.PSObject.Properties | ForEach-Object { $_.Name })
    if ($propertyNames -contains $Name) { return $Object.$Name }
    return $Default
}

function Test-ReachPayload {
    param([object]$Payload, [string]$Origin, [string]$RawText)

    $violations = New-Object System.Collections.ArrayList
    function Add-Violation { param([string]$Layer, [string]$Message)
        $null = $violations.Add([ordered]@{ layer = $Layer; message = $Message }) }

    # ---- privacy: run against the raw text, so a nested or renamed field
    # ---- cannot smuggle a secret past a structural walk.
    if ($RawText) {
        if ($RawText -match 'ownership_nonce') {
            Add-Violation 'privacy' 'payload mentions ownership_nonce; the PCP credential must never be exported'
        }
        if ($RawText -match 'observed_monotonic_ms') {
            Add-Violation 'privacy' 'payload exports observed_monotonic_ms; internal clock must not leave the process'
        }
        # A dotted quad or a compressed v6 literal means a full address escaped.
        $v4 = [regex]::Matches($RawText, '\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
        foreach ($m in $v4) {
            Add-Violation 'privacy' ("payload contains a full IPv4 literal ({0}); emit family + address_class + port instead" -f $m.Value)
        }
        if ($RawText -match '"[0-9A-Fa-f]{0,4}:[0-9A-Fa-f]{0,4}:[0-9A-Fa-f:]*"') {
            Add-Violation 'privacy' 'payload appears to contain a full IPv6 literal'
        }
    }

    # ---- structure
    $schema = [string](Get-Field -Object $Payload -Name 'schema' -Default '')
    if ($schema -ne 'ESE_REACH_STATUS_V1') {
        Add-Violation 'structure' "schema is '$schema', expected ESE_REACH_STATUS_V1"
    }
    $available = Get-Field -Object $Payload -Name 'available' -Default $null
    if ($null -eq $available) { Add-Violation 'structure' 'missing field: available' }

    $topGen = Get-Field -Object $Payload -Name 'topology_generation' -Default $null
    if ($null -eq $topGen) { Add-Violation 'structure' 'missing field: topology_generation' }

    $planes = Get-Field -Object $Payload -Name 'planes' -Default $null
    if ($null -eq $planes) {
        Add-Violation 'structure' 'missing field: planes'
        return $violations
    }

    # The unavailable shape legitimately carries no planes.
    if ($available -eq $false) { return $violations }

    foreach ($planeName in $planeNames) {
        $plane = Get-Field -Object $planes -Name $planeName -Default $null
        if ($null -eq $plane) {
            Add-Violation 'structure' "missing plane: $planeName"
            continue
        }

        $state = [string](Get-Field -Object $plane -Name 'state' -Default '')
        $gateState = [string](Get-Field -Object $plane -Name 'gate_state' -Default '')
        $reason = [string](Get-Field -Object $plane -Name 'reason' -Default '')
        $reasonCode = Get-Field -Object $plane -Name 'reason_code' -Default $null
        $generation = Get-Field -Object $plane -Name 'generation' -Default $null
        $expired = Get-Field -Object $plane -Name 'expired' -Default $null
        $stale = Get-Field -Object $plane -Name 'stale' -Default $null

        if ($reachabilityStates -notcontains $state) {
            Add-Violation 'structure' "$planeName has unknown state '$state'"
        }
        foreach ($required in @('local', 'mapped', 'advertised', 'lease',
                'primary_evidence', 'inbound_evidence', 'classic_high_id_evidence')) {
            if ($null -eq (Get-Field -Object $plane -Name $required -Default $null)) {
                Add-Violation 'structure' "$planeName is missing field: $required"
            }
        }
        if ($null -eq $expired) { Add-Violation 'structure' "$planeName is missing field: expired" }
        if ($null -eq $stale)   { Add-Violation 'structure' "$planeName is missing field: stale" }
        if ($null -eq $generation) { Add-Violation 'structure' "$planeName is missing field: generation" }

        # ---- semantics: gate_state must follow the section 4 table
        if ($gateStateMap.ContainsKey($state)) {
            $expectedGate = $gateStateMap[$state]
            if ($gateState -ne $expectedGate) {
                Add-Violation 'semantics' "$planeName state '$state' must map to gate_state '$expectedGate', found '$gateState'"
            }
        }

        # ---- semantics: reason name and number must agree
        if ($reasonCodes.ContainsKey($reason)) {
            if ($null -ne $reasonCode -and [int]$reasonCode -ne $reasonCodes[$reason]) {
                Add-Violation 'semantics' ("$planeName reason '$reason' must carry reason_code {0}, found {1}" -f $reasonCodes[$reason], $reasonCode)
            }
        } elseif ($reason) {
            Add-Violation 'structure' "$planeName has unknown reason '$reason'"
        }

        $primary = Get-Field -Object $plane -Name 'primary_evidence' -Default $null
        $inbound = Get-Field -Object $plane -Name 'inbound_evidence' -Default $null
        $primaryKind = [string](Get-Field -Object $primary -Name 'kind' -Default 'None')
        $primaryCurrent = [bool](Get-Field -Object $primary -Name 'current' -Default $false)
        $inboundKind = [string](Get-Field -Object $inbound -Name 'kind' -Default 'None')
        $inboundCurrent = [bool](Get-Field -Object $inbound -Name 'current' -Default $false)

        foreach ($pair in @(@{ n = 'primary_evidence'; k = $primaryKind },
                            @{ n = 'inbound_evidence'; k = $inboundKind })) {
            if ($evidenceKinds -notcontains $pair.k) {
                Add-Violation 'structure' "$planeName $($pair.n) has unknown kind '$($pair.k)'"
            }
        }

        # ---- the load-bearing safety invariants
        if ($gateState -eq 'VERIFIED' -and -not $primaryCurrent) {
            Add-Violation 'semantics' "$planeName reads VERIFIED without current primary evidence; that is a fictitious success"
        }
        if ($gateState -eq 'VERIFIED' -and $stale -eq $true) {
            Add-Violation 'semantics' "$planeName reads VERIFIED while stale; stale evidence never proves reachability"
        }
        if ($gateState -eq 'VERIFIED' -and $expired -eq $true) {
            Add-Violation 'semantics' "$planeName reads VERIFIED while expired"
        }

        # stale must be declared whenever real evidence belongs to another generation
        $shouldBeStale = ($primaryKind -ne 'None' -and -not $primaryCurrent) -or
                         ($inboundKind -ne 'None' -and -not $inboundCurrent)
        if ($shouldBeStale -and $stale -ne $true) {
            Add-Violation 'semantics' "$planeName carries evidence from another generation but stale is not true"
        }
        if (-not $shouldBeStale -and $stale -eq $true) {
            Add-Violation 'semantics' "$planeName declares stale but all evidence is current or absent"
        }

        if ($reason -eq 'LeaseExpired' -and $expired -ne $true) {
            Add-Violation 'semantics' "$planeName has reason LeaseExpired but expired is not true"
        }

        $classic = [bool](Get-Field -Object $plane -Name 'classic_high_id_evidence' -Default $false)
        if ($classic) {
            if ($state -ne 'Reachable' -or $primaryKind -ne 'ServerHighId' -or
                $inboundKind -ne 'InboundTcpAccept' -or -not $primaryCurrent -or -not $inboundCurrent) {
                Add-Violation 'semantics' "$planeName claims classic_high_id_evidence without satisfying HasClassicHighIdEvidence()"
            }
        }

        # ---- endpoints and lease
        foreach ($endpointName in @('local', 'mapped', 'advertised')) {
            $endpoint = Get-Field -Object $plane -Name $endpointName -Default $null
            if ($null -eq $endpoint) { continue }
            $family = [string](Get-Field -Object $endpoint -Name 'family' -Default '')
            $class = [string](Get-Field -Object $endpoint -Name 'address_class' -Default '')
            $source = [string](Get-Field -Object $endpoint -Name 'source' -Default '')
            if ($families -notcontains $family) {
                Add-Violation 'structure' "$planeName.$endpointName has unknown family '$family'"
            }
            if ($addressClasses -notcontains $class) {
                Add-Violation 'structure' "$planeName.$endpointName has unknown address_class '$class'"
            }
            if ($endpointSources -notcontains $source) {
                Add-Violation 'structure' "$planeName.$endpointName has unknown source '$source'"
            }
            if (@($endpoint.PSObject.Properties.Name) -contains 'address') {
                Add-Violation 'privacy' "$planeName.$endpointName exports a raw address field"
            }
        }

        $lease = Get-Field -Object $plane -Name 'lease' -Default $null
        if ($null -ne $lease) {
            $mapper = [string](Get-Field -Object $lease -Name 'mapper' -Default '')
            $transport = [string](Get-Field -Object $lease -Name 'transport' -Default '')
            if ($mapperKinds -notcontains $mapper) {
                Add-Violation 'structure' "$planeName.lease has unknown mapper '$mapper'"
            }
            if ($transports -notcontains $transport) {
                Add-Violation 'structure' "$planeName.lease has unknown transport '$transport'"
            }
        }
    }

    return $violations
}

function Get-LiveReachData {
    param([object]$Envelope)

    $problems = New-Object System.Collections.ArrayList
    $data = $null
    if ($null -eq $Envelope) {
        $null = $problems.Add('Invoke-LabApi returned no transport envelope')
    } else {
        $names = @($Envelope.PSObject.Properties.Name)
        if ($names -notcontains 'available' -or $Envelope.available -isnot [bool]) {
            $null = $problems.Add('Invoke-LabApi envelope has no boolean available field')
        } elseif (-not [bool]$Envelope.available) {
            $null = $problems.Add('reach-status transport is unavailable')
        }
        if ($names -notcontains 'data') {
            $null = $problems.Add('Invoke-LabApi envelope has no reach-status data payload')
        } else {
            $data = $Envelope.data
        }
        if ($null -eq $data) {
            $null = $problems.Add('Invoke-LabApi envelope has no reach-status data payload')
        } elseif ($data -is [string] -or $data -is [Collections.IEnumerable]) {
            $null = $problems.Add('Invoke-LabApi data payload is not a JSON object')
        }
        if ($names -contains 'error' -and -not [string]::IsNullOrWhiteSpace([string]$Envelope.error)) {
            $null = $problems.Add('Invoke-LabApi envelope records a transport error')
        }
    }
    $result = [ordered]@{
        data     = $data
        problems = @($problems)
    }
    return [pscustomobject]$result
}

# ---- input selection ---------------------------------------------------------

$targets = New-Object System.Collections.ArrayList

switch ($PSCmdlet.ParameterSetName) {
    'Live' {
        $envelope = Invoke-LabApi -BaseUrl $BaseUrl -Path '/api/reach/status' -Token $Token -AllowUnavailable
        # `$Live is the switch parameter (PowerShell variable names are case-
        # insensitive), so keep the projection under a distinct name.
        $liveReachProjection = Get-LiveReachData -Envelope $envelope
        $dataText = if ($null -eq $liveReachProjection.data) { '' } else { $liveReachProjection.data | ConvertTo-Json -Depth 32 }
        $null = $targets.Add(@{ origin = "$BaseUrl/api/reach/status"
                                payload = $liveReachProjection.data
                                text = $dataText
                                envelope_problems = @($liveReachProjection.problems) })
    }
    'File' {
        $text = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
        $null = $targets.Add(@{ origin = $Path; payload = ($text | ConvertFrom-Json); text = $text })
    }
    default {
        $goldenDirectory = Join-Path $PSScriptRoot 'goldens'
        foreach ($file in (Get-ChildItem -LiteralPath $goldenDirectory -Filter '*.json' | Sort-Object Name)) {
            $text = Get-Content -LiteralPath $file.FullName -Raw -Encoding UTF8
            $null = $targets.Add(@{ origin = $file.Name; payload = ($text | ConvertFrom-Json); text = $text })
        }
    }
}

$results = New-Object System.Collections.ArrayList
$totalViolations = 0

foreach ($target in $targets) {
    # @() is required: PowerShell unrolls a returned collection, so an empty
    # violation list would come back as $null and .Count would throw.
    $violations = New-Object System.Collections.ArrayList
    $envelopeProblems = @()
    if (@($target.Keys) -contains 'envelope_problems') {
        $envelopeProblems = @($target.envelope_problems)
    }
    foreach ($problem in $envelopeProblems) {
        $null = $violations.Add([ordered]@{ layer = 'transport'; message = [string]$problem })
    }
    foreach ($violation in @(Test-ReachPayload -Payload $target.payload -Origin $target.origin -RawText $target.text)) {
        $null = $violations.Add($violation)
    }
    $totalViolations += $violations.Count
    $null = $results.Add([ordered]@{
        origin     = $target.origin
        verdict    = $(if ($violations.Count -eq 0) { 'PASS' } else { 'FAIL' })
        violations = @($violations)
    })
}

$report = [ordered]@{
    schema           = 'ese.lab.reach-status-validation/v1'
    generated_at_utc = Get-LabUtcTimestamp
    contract         = 'ESE_REACH_STATUS_V1'
    mode             = $PSCmdlet.ParameterSetName
    verdict          = $(if ($totalViolations -eq 0) { 'PASS' } else { 'FAIL' })
    checked          = $results.Count
    total_violations = $totalViolations
    results          = @($results)
}

if ($OutFile) {
    $written = Write-LabJson -Value $report -Path $OutFile
    Write-Host "Validation report written: $written" -ForegroundColor Green
}

foreach ($result in $results) {
    if ($result.verdict -eq 'PASS') {
        Write-Host ("PASS  {0}" -f $result.origin) -ForegroundColor Green
    } else {
        Write-Host ("FAIL  {0}" -f $result.origin) -ForegroundColor Red
        foreach ($violation in $result.violations) {
            Write-Host ("        [{0}] {1}" -f $violation.layer, $violation.message) -ForegroundColor Yellow
        }
    }
}

Write-Host ''
if ($totalViolations -eq 0) {
    Write-Host ("Contract verdict: PASS ({0} payload(s))" -f $results.Count) -ForegroundColor Green
} else {
    Write-Host ("Contract verdict: FAIL ({0} violation(s))" -f $totalViolations) -ForegroundColor Red
    exit 1
}
