[CmdletBinding()]
param(
    [string]$CandidatePackagePath = '',
    [string]$CandidateZipPath = '',
    [string]$ExpectedCommit = '',
    [string]$SourceCandidatePackagePath = '',
    [string]$SourceCandidateZipPath = '',
    [string]$ViewerCandidatePackagePath = '',
    [string]$ViewerCandidateZipPath = '',
    [string]$R01AggregatePath = '',
    [string]$OutputRoot = '',
    [string]$SourceAgentIPv4 = '',
    [ValidateRange(1024, 65535)][int]$SourceAgentPort = 8016,
    [string]$SourceTokenDpapiPath = (
        "$env:LOCALAPPDATA\eSE-Lab-Controller\h1-smallframe-token.dpapi"),
    [string]$ViewerAgentIPv4 = '',
    [ValidateRange(1024, 65535)][int]$ViewerAgentPort = 8015,
    [string]$ViewerTokenDpapiPath = (
        "$env:LOCALAPPDATA\eSE-Lab-Controller\smallframe-token.dpapi"),
    [switch]$SourceDisposableLabAccountAcknowledged,
    [switch]$ViewerDisposableLabAccountAcknowledged,
    [string]$ExpectedSourceLabUserSidSha256 = '',
    [string]$ExpectedViewerLabUserSidSha256 = '',
    [string]$RouteTargetIPv6 = '',
    [ValidateRange(15, 180)][int]$DurationSeconds = 45,
    [ValidateRange(120, 900)][int]$TimeoutSeconds = 420,
    [switch]$SelfTest
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$agentController = Join-Path $PSScriptRoot `
    'control_ese_lab_smallframe_agent.ps1'
$commonScript = Join-Path $PSScriptRoot 'v91_i07_common.ps1'
$preflightScript = Join-Path $PSScriptRoot 'inspect_v91_i07_remote.ps1'
$baselineScript = Join-Path $PSScriptRoot `
    'inspect_v91_i07_baseline_remote.ps1'
$nodeScript = Join-Path $PSScriptRoot 'run_v91_i07_node.ps1'
$wifiScript = Join-Path $PSScriptRoot 'set_v91_i07_wifi_profile.ps1'
$wifiWatchdogScript = Join-Path $PSScriptRoot `
    'restore_v91_i07_wifi_watchdog.ps1'
. (Join-Path $PSScriptRoot 'common.ps1')
. $commonScript

$script:i07UnprovenStagingPaths =
    [Collections.Generic.List[string]]::new()

function Assert-I07StagingCleanupProven {
    if ($script:i07UnprovenStagingPaths.Count -ne 0) {
        throw 'STAGING_CLEANUP_NOT_PROVEN'
    }
}

function Repair-I07StagingCleanup {
    foreach ($path in @($script:i07UnprovenStagingPaths.ToArray())) {
        try { Remove-I07OwnedStagingFile -Path $path } catch {}
    }
    return ($script:i07UnprovenStagingPaths.Count -eq 0)
}

function Get-I07AggregateStatus {
    param(
        [AllowNull()]$Source,
        [AllowNull()]$Viewer,
        [Parameter(Mandatory = $true)][string]$Nonce,
        [Parameter(Mandatory = $true)][string]$CandidateSha256,
        [string]$CandidateCommit = '',
        [string]$BuildInfoSha256 = '',
        [string]$ZipSha256 = '',
        [Int64]$ZipBytes = 0,
        [Parameter(Mandatory = $true)]
        [ValidateRange(15, 180)][int]$ExpectedDurationSeconds,
        [object[]]$ExpectedPackageFiles = @(),
        [string]$ExpectedViewerWlanProfileSha256 = '',
        [string]$ExpectedViewerConnectionProfileSha256 = '',
        [string]$ExpectedViewerInterfaceGuid = ''
    )

    function Get-I07ContractCanonical {
        param([AllowNull()]$Files)
        try {
            $items = @(Assert-I07CriticalPackageContract -Files @($Files))
            return @($items | Sort-Object path | ForEach-Object {
                    '{0}|{1}|{2}' -f [string]$_.path,
                        [Int64]$_.bytes, [string]$_.sha256
                }) -join "`n"
        } catch { return '' }
    }
    $expectedPackageCanonical = if ($ExpectedPackageFiles.Count -eq 0) {
        ''
    } else { Get-I07ContractCanonical -Files $ExpectedPackageFiles }

    function Test-I07RouteEnvelope {
        param(
            [Parameter(Mandatory = $true)]$Node,
            [Parameter(Mandatory = $true)]$Route,
            [Parameter(Mandatory = $true)]
            [ValidateSet('initial', 'final')][string]$Sample
        )
        try {
            if (-not (Test-I07ExactPropertySet -Value $Route -Expected @(
                    'captured_at_utc', 'valid', 'reason', 'remote_address',
                    'remote_class', 'source_address', 'source_class',
                    'interface_index', 'interface_alias', 'interface_guid',
                    'interface_description', 'media_type',
                    'physical_media_type', 'hardware_interface', 'virtual',
                    'destination_prefix', 'next_hop', 'route_metric',
                    'interface_metric', 'address_state', 'prefix_origin',
                    'suffix_origin', 'default_route_present', 'overlay'))) {
                return $false
            }
            $captured = [DateTimeOffset]::MinValue
            $started = [DateTimeOffset]::MinValue
            $capturedValid = [DateTimeOffset]::TryParse(
                [string]$Route.captured_at_utc, [ref]$captured)
            $startedValid = [DateTimeOffset]::TryParse(
                [string]$Node.candidate.started_at_utc, [ref]$started)
            $timingValid = $capturedValid -and $startedValid -and $(
                if ($Sample -ceq 'initial') {
                    $captured -le $started
                } else {
                    $captured -ge $started
                })
            $local = ConvertTo-I07CanonicalIPv6 `
                -Value ([string]$Node.topology.local_ipv6)
            $peer = ConvertTo-I07CanonicalIPv6 `
                -Value ([string]$Node.topology.peer_ipv6)
            return ($timingValid -and
                (Test-I07StrictBoolean -Value $Route.valid) -and
                [bool]$Route.valid -and
                [string]$Route.reason -ceq
                    'native_global_route_selected' -and
                (ConvertTo-I07CanonicalIPv6 `
                    -Value ([string]$Route.source_address)) -ceq $local -and
                (ConvertTo-I07CanonicalIPv6 `
                    -Value ([string]$Route.remote_address)) -ceq $peer -and
                [string]$Route.source_class -ceq 'global-native' -and
                [string]$Route.remote_class -ceq 'global-native' -and
                (Test-I07StrictInteger -Value $Route.interface_index `
                    -Minimum 1) -and
                (Test-I07StrictInteger -Value $Node.topology.interface_index `
                    -Minimum 1) -and
                [Int64]$Route.interface_index -eq
                    [int]$Node.topology.interface_index -and
                ([string]$Route.interface_guid).Trim('{}') -ieq
                    ([string]$Node.topology.interface_guid).Trim('{}') -and
                (Test-I07StrictBoolean -Value $Route.hardware_interface) -and
                [bool]$Route.hardware_interface -and
                (Test-I07StrictBoolean -Value $Route.virtual) -and
                -not [bool]$Route.virtual -and
                (Test-I07StrictBoolean -Value $Route.overlay) -and
                -not [bool]$Route.overlay -and
                (Test-I07StrictBoolean `
                    -Value $Route.default_route_present) -and
                [bool]$Route.default_route_present -and
                [string]$Route.address_state -ceq 'Preferred')
        } catch { return $false }
    }

    function Test-I07ControlEnvelope {
        param([Parameter(Mandatory = $true)]$Node)
        try {
            if (-not (Test-I07ExactPropertySet `
                    -Value $Node.topology.control -Expected @(
                        'bidirectional', 'proven_at_utc', 'local_address',
                        'local_port', 'remote_address', 'remote_port')) -or
                -not (Test-I07ExactPropertySet -Value $Node.topology.ports `
                    -Expected @('tcp', 'udp', 'web', 'peer_tcp', 'control'))) {
                return $false
            }
            foreach ($port in @(
                    $Node.topology.ports.tcp, $Node.topology.ports.udp,
                    $Node.topology.ports.web, $Node.topology.ports.peer_tcp,
                    $Node.topology.ports.control,
                    $Node.topology.control.local_port,
                    $Node.topology.control.remote_port)) {
                if (-not (Test-I07StrictInteger -Value $port `
                        -Minimum 1024 -Maximum 65535)) { return $false }
            }
            $proven = [DateTimeOffset]::MinValue
            $started = [DateTimeOffset]::MinValue
            $provenValid = [DateTimeOffset]::TryParse(
                [string]$Node.topology.control.proven_at_utc, [ref]$proven)
            $startedValid = [DateTimeOffset]::TryParse(
                [string]$Node.candidate.started_at_utc, [ref]$started)
            $local = ConvertTo-I07CanonicalIPv6 `
                -Value ([string]$Node.topology.local_ipv6)
            $peer = ConvertTo-I07CanonicalIPv6 `
                -Value ([string]$Node.topology.peer_ipv6)
            $rolePortValid = if ([string]$Node.role -ceq 'source') {
                [int]$Node.topology.control.local_port -eq
                    [int]$Node.topology.ports.control
            } else {
                [int]$Node.topology.control.remote_port -eq
                    [int]$Node.topology.ports.control
            }
            return ((Test-I07StrictBoolean `
                    -Value $Node.topology.native_path_proven_before_candidate) -and
                [bool]$Node.topology.native_path_proven_before_candidate -and
                (Test-I07StrictBoolean `
                    -Value $Node.topology.control.bidirectional) -and
                [bool]$Node.topology.control.bidirectional -and
                (ConvertTo-I07CanonicalIPv6 -Value (
                    [string]$Node.topology.control.local_address)) -ceq
                        $local -and
                (ConvertTo-I07CanonicalIPv6 -Value (
                    [string]$Node.topology.control.remote_address)) -ceq
                        $peer -and $rolePortValid -and
                $provenValid -and $startedValid -and $proven -le $started -and
                (Test-I07StrictInteger -Value $Node.candidate.pid `
                    -Minimum 1))
        } catch { return $false }
    }

    function Test-I07ApiStatusSummary {
        param(
            [Parameter(Mandatory = $true)]$Summary,
            [switch]$RequireInvariantViolation
        )
        try {
            $boolNames = @(
                'ed2k_connected', 'kad_connected', 'kad2_running',
                'kad2_connected', 'kad6_running', 'kad6_connected',
                'netlab_enabled')
            $maskNames = @('kad_configured_mask', 'kad_running_mask')
            $safeValues = $Summary.safe_scalars
            $names = if ($safeValues -is [Collections.IDictionary]) {
                @($safeValues.Keys)
            } else { @($safeValues.PSObject.Properties.Name) }
            if ((@($names | Sort-Object) -join "`n") -cne
                (@($boolNames + $maskNames | Sort-Object) -join "`n")) {
                return $false
            }
            $canonical = [ordered]@{}
            foreach ($name in $boolNames) {
                $value = if ($safeValues -is [Collections.IDictionary]) {
                    $safeValues[$name]
                } else { $safeValues.$name }
                if (-not (Test-I07StrictBoolean -Value $value)) {
                    return $false
                }
                $canonical[$name] = [bool]$value
            }
            foreach ($name in $maskNames) {
                $value = if ($safeValues -is [Collections.IDictionary]) {
                    $safeValues[$name]
                } else { $safeValues.$name }
                if (-not (Test-I07StrictInteger -Value $value `
                        -Minimum 0 -Maximum 255)) {
                    return $false
                }
                $canonical[$name] = [Int64]$value
            }
            $safeJson = $canonical | ConvertTo-Json -Depth 4 -Compress
            $safeBytes = [Text.Encoding]::UTF8.GetBytes($safeJson)
            $sha = [Security.Cryptography.SHA256]::Create()
            try {
                $safeHash = ([BitConverter]::ToString(
                    $sha.ComputeHash($safeBytes))).Replace('-', '').
                        ToLowerInvariant()
            } finally { $sha.Dispose() }
            $captured = [DateTimeOffset]::MinValue
            $computedIsolation = @($boolNames | Where-Object {
                    [bool]$canonical[$_]
                }).Count -eq 0 -and @($maskNames | Where-Object {
                    [Int64]$canonical[$_] -ne 0
                }).Count -eq 0
            $isolationValid =
                [bool]$Summary.isolation_invariant_satisfied -eq
                    $computedIsolation -and $(
                    if ($RequireInvariantViolation) {
                        -not $computedIsolation
                    } else { $computedIsolation })
            return (
                (Test-I07ExactPropertySet -Value $Summary -Expected @(
                    'schema', 'available', 'contract_valid',
                    'isolation_invariant_satisfied', 'captured_at_utc',
                    'safe_response_sha256', 'safe_response_bytes',
                    'safe_scalars')) -and
                [string]$Summary.schema -ceq
                    'ese.v91.i07-api-status-evidence/v2' -and
                (Test-I07StrictBoolean -Value $Summary.available) -and
                [bool]$Summary.available -and
                (Test-I07StrictBoolean -Value $Summary.contract_valid) -and
                [bool]$Summary.contract_valid -and
                (Test-I07StrictBoolean `
                    -Value $Summary.isolation_invariant_satisfied) -and
                $isolationValid -and
                [DateTimeOffset]::TryParse(
                    [string]$Summary.captured_at_utc, [ref]$captured) -and
                [string]$Summary.safe_response_sha256 -ceq $safeHash -and
                (Test-I07StrictInteger -Value $Summary.safe_response_bytes `
                    -Minimum 1) -and
                [Int64]$Summary.safe_response_bytes -eq $safeBytes.Length)
        } catch { return $false }
    }

    function Test-I07UnavailableApiStatusSummary {
        param([Parameter(Mandatory = $true)]$Summary)
        try {
            return (
                (Test-I07ExactPropertySet -Value $Summary -Expected @(
                    'schema', 'available', 'contract_valid',
                    'isolation_invariant_satisfied', 'captured_at_utc',
                    'safe_response_sha256', 'safe_response_bytes',
                    'safe_scalars')) -and
                [string]$Summary.schema -ceq
                    'ese.v91.i07-api-status-evidence/v2' -and
                (Test-I07StrictBoolean -Value $Summary.available) -and
                -not [bool]$Summary.available -and
                (Test-I07StrictBoolean -Value $Summary.contract_valid) -and
                -not [bool]$Summary.contract_valid -and
                (Test-I07StrictBoolean `
                    -Value $Summary.isolation_invariant_satisfied) -and
                -not [bool]$Summary.isolation_invariant_satisfied -and
                $null -eq $Summary.captured_at_utc -and
                $null -eq $Summary.safe_response_sha256 -and
                (Test-I07StrictInteger -Value $Summary.safe_response_bytes `
                    -Minimum 0 -Maximum 0) -and
                @(Get-I07ObjectPropertyNames `
                    -Value $Summary.safe_scalars).Count -eq 0)
        } catch { return $false }
    }

    function Test-I07TimelineEnvelope {
        param(
            [Parameter(Mandatory = $true)]$Node,
            [switch]$RequireFinal
        )
        try {
            $initialRoute = [DateTimeOffset]::Parse(
                [string]$Node.topology.initial_route.captured_at_utc)
            $control = [DateTimeOffset]::Parse(
                [string]$Node.topology.control.proven_at_utc)
            $started = [DateTimeOffset]::Parse(
                [string]$Node.candidate.started_at_utc)
            $apiPre = [DateTimeOffset]::Parse(
                [string]$Node.product.api_status_initial.captured_at_utc)
            if (-not (Test-I07ApiStatusSummary `
                    -Summary $Node.product.api_status_initial) -or
                $initialRoute -gt $control -or $control -gt $started -or
                $started -gt $apiPre) {
                return $false
            }
            if (-not $RequireFinal) { return $true }
            $finalRoute = [DateTimeOffset]::Parse(
                [string]$Node.topology.final_route.captured_at_utc)
            $apiPost = [DateTimeOffset]::Parse(
                [string]$Node.product.api_status_final.captured_at_utc)
            $completed = [DateTimeOffset]::Parse(
                [string]$Node.completed_at_utc)
            return ((Test-I07ApiStatusSummary `
                    -Summary $Node.product.api_status_final) -and
                $apiPre -le $finalRoute -and $finalRoute -le $apiPost -and
                $apiPost -le $completed)
        } catch { return $false }
    }

    function Get-I07SessionSamplesEvidence {
        param(
            [Parameter(Mandatory = $true)]$Node,
            [switch]$RequirePass
        )
        try {
            $started = [DateTimeOffset]::Parse(
                [string]$Node.candidate.started_at_utc)
            $completed = [DateTimeOffset]::Parse(
                [string]$Node.completed_at_utc)
            $samples = @($Node.product.samples)
            if ($samples.Count -lt 1) { return $null }
            $summary = [ordered]@{
                sample_count = $samples.Count
                first_sample_at_utc = $null; last_sample_at_utc = $null
                maximum_gap_seconds = 0.0
                socket_observed = $false; broadcasting_observed = $false
                api_peer_observed = $false; viewing_observed = $false
                playlist_observed = $false; segment_observed = $false
            }
            $previous = [DateTimeOffset]::MinValue
            foreach ($sample in $samples) {
                $expected = if ([string]$Node.role -ceq 'source') {
                    @('at_utc', 'process_alive', 'broadcasting', 'peer_socket')
                } else {
                    @('at_utc', 'process_alive', 'viewing', 'api_peer',
                        'peer_socket', 'playlist', 'segment')
                }
                $at = [DateTimeOffset]::MinValue
                if (-not (Test-I07ExactPropertySet -Value $sample `
                        -Expected $expected) -or
                    -not (Test-I07StrictString -Value $sample.at_utc) -or
                    -not [DateTimeOffset]::TryParse(
                        [string]$sample.at_utc,
                        [Globalization.CultureInfo]::InvariantCulture,
                        [Globalization.DateTimeStyles]::RoundtripKind,
                        [ref]$at) -or $at.Offset -ne [TimeSpan]::Zero -or
                    $at -lt $started -or $at -gt $completed -or
                    ($previous -ne [DateTimeOffset]::MinValue -and
                        $at -le $previous)) {
                    return $null
                }
                if ($null -eq $summary.first_sample_at_utc) {
                    $summary.first_sample_at_utc = $at.ToString('o')
                }
                if ($previous -ne [DateTimeOffset]::MinValue) {
                    $summary.maximum_gap_seconds = [Math]::Max(
                        [double]$summary.maximum_gap_seconds,
                        ($at - $previous).TotalSeconds)
                }
                $summary.last_sample_at_utc = $at.ToString('o')
                $previous = $at
                foreach ($name in @($expected | Select-Object -Skip 1)) {
                    if (-not (Test-I07StrictBoolean -Value $sample.$name)) {
                        return $null
                    }
                }
                if (-not [bool]$sample.process_alive) { return $null }
                if ([bool]$sample.peer_socket) {
                    $summary.socket_observed = $true
                }
                if ([string]$Node.role -ceq 'source') {
                    if ([bool]$sample.broadcasting) {
                        $summary.broadcasting_observed = $true
                    }
                } else {
                    if ([bool]$sample.api_peer) {
                        $summary.api_peer_observed = $true
                    }
                    if ([bool]$sample.viewing) {
                        $summary.viewing_observed = $true
                    }
                    if ([bool]$sample.playlist) {
                        $summary.playlist_observed = $true
                    }
                    if ([bool]$sample.segment) {
                        $summary.segment_observed = $true
                    }
                }
            }
            if ($RequirePass) {
                $firstAt = [DateTimeOffset]::Parse(
                    [string]$summary.first_sample_at_utc)
                $lastAt = [DateTimeOffset]::Parse(
                    [string]$summary.last_sample_at_utc)
                $allowedGapSeconds = if (
                    [string]$Node.role -ceq 'source') { 8.0 } else { 20.0 }
                if ($samples.Count -lt 2 -or
                    ($lastAt - $firstAt).TotalSeconds -lt
                        ([double]$ExpectedDurationSeconds - 2.0) -or
                    [double]$summary.maximum_gap_seconds -gt
                        $allowedGapSeconds -or
                    ($completed - $lastAt).TotalSeconds -gt
                        $allowedGapSeconds) {
                    return $null
                }
                if ([string]$Node.role -ceq 'source') {
                    if (-not [bool]$summary.socket_observed -or
                        -not [bool]$summary.broadcasting_observed) {
                        return $null
                    }
                } elseif ($samples.Count -lt 10 -or
                    -not [bool]$summary.socket_observed -or
                    -not [bool]$summary.api_peer_observed -or
                    -not [bool]$summary.viewing_observed -or
                    -not [bool]$summary.playlist_observed -or
                    -not [bool]$summary.segment_observed) {
                    return $null
                }
            }
            return [pscustomobject]$summary
        } catch { return $null }
    }

    function Test-I07ProductFailureEvidence {
        param([Parameter(Mandatory = $true)]$Node)
        try {
            $failureEvidence = $Node.product.failure_evidence
            if (-not (Test-I07ExactPropertySet -Value $failureEvidence `
                    -Expected @(
                        'schema', 'reason', 'observed_at_utc', 'listener',
                        'api_operation', 'process_exit',
                        'session_observation')) -or
                [string]$failureEvidence.schema -cne
                    'ese.v91.i07-product-failure-evidence/v1') {
                return $false
            }
            $started = [DateTimeOffset]::Parse(
                [string]$Node.candidate.started_at_utc)
            $completed = [DateTimeOffset]::Parse(
                [string]$Node.completed_at_utc)
            $observed = [DateTimeOffset]::Parse(
                [string]$failureEvidence.observed_at_utc)
            if ($completed -lt $started -or $observed -lt $started -or
                $observed -gt $completed -or
                $observed.Offset -ne [TimeSpan]::Zero) { return $false }
            $branches = @(
                $failureEvidence.listener, $failureEvidence.api_operation,
                $failureEvidence.process_exit,
                $failureEvidence.session_observation)
            if (@($branches | Where-Object { $null -ne $_ }).Count -ne 1) {
                return $false
            }

            function Test-ApiOperation {
                param(
                    [string]$Operation, [bool]$Available,
                    [bool]$ContractValid, [AllowNull()][bool]$Success = $false,
                    [AllowNull()][bool]$Ready = $false
                )
                $value = $failureEvidence.api_operation
                if ($null -eq $value -or
                    -not (Test-I07ExactPropertySet -Value $value -Expected @(
                        'operation', 'available', 'contract_valid', 'success',
                        'ready', 'safe_response_sha256',
                        'safe_response_bytes')) -or
                    -not (Test-I07StrictBoolean -Value $value.available) -or
                    -not (Test-I07StrictBoolean -Value $value.contract_valid) -or
                    -not (Test-I07StrictBoolean -Value $value.success) -or
                    -not (Test-I07StrictBoolean -Value $value.ready) -or
                    -not (Test-I07StrictInteger `
                        -Value $value.safe_response_bytes -Minimum 1)) {
                    return $false
                }
                $safe = [ordered]@{
                    operation = $Operation; available = $Available
                    contract_valid = $ContractValid; success = $Success
                    ready = $Ready
                }
                $json = $safe | ConvertTo-Json -Compress
                $bytes = [Text.Encoding]::UTF8.GetBytes($json)
                $sha = [Security.Cryptography.SHA256]::Create()
                try {
                    $digest = ([BitConverter]::ToString(
                        $sha.ComputeHash($bytes))).Replace('-', '').
                            ToLowerInvariant()
                } finally { $sha.Dispose() }
                return ([string]$value.operation -ceq $Operation -and
                    [bool]$value.available -eq $Available -and
                    [bool]$value.contract_valid -eq $ContractValid -and
                    [bool]$value.success -eq $Success -and
                    [bool]$value.ready -eq $Ready -and
                    [string]$value.safe_response_sha256 -ceq $digest -and
                    [Int64]$value.safe_response_bytes -eq $bytes.Length)
            }

            $code = [string]$Node.failure.code
            $reason = [string]$failureEvidence.reason
            $rolePhase = if ([string]$Node.role -ceq 'source') {
                'source_candidate_start'
            } else { 'viewer_candidate_start' }
            if ($code -cin @(
                    'API_INITIAL_UNRESPONSIVE',
                    'API_INITIAL_ISOLATION_CONTRADICTION')) {
                if ([string]$Node.phase -cne $rolePhase -or
                    -not (Test-I07UnavailableApiStatusSummary `
                        -Summary $Node.product.api_status_final)) {
                    return $false
                }
                if ($code -ceq 'API_INITIAL_UNRESPONSIVE') {
                    return ($reason -ceq 'API_STATUS_UNRESPONSIVE' -and
                        (Test-ApiOperation -Operation 'api_status_initial' `
                            -Available $false -ContractValid $false) -and
                        (Test-I07UnavailableApiStatusSummary `
                            -Summary $Node.product.api_status_initial))
                }
                $captured = [DateTimeOffset]::Parse(
                    [string]$Node.product.api_status_initial.captured_at_utc)
                return ($reason -ceq 'API_ISOLATION_CONTRADICTION' -and
                    (Test-ApiOperation -Operation 'api_status_initial' `
                        -Available $true -ContractValid $true) -and
                    (Test-I07ApiStatusSummary `
                        -Summary $Node.product.api_status_initial `
                        -RequireInvariantViolation) -and
                    $captured -ge $started -and $captured -le $completed)
            }
            if ($code -cin @(
                    'API_FINAL_UNRESPONSIVE',
                    'API_FINAL_ISOLATION_CONTRADICTION')) {
                if ([string]$Node.phase -cne 'route_revalidation' -or
                    -not (Test-I07TimelineEnvelope -Node $Node) -or
                    -not (Test-I07RouteEnvelope -Node $Node `
                        -Route $Node.topology.final_route -Sample final)) {
                    return $false
                }
                $finalRoute = [DateTimeOffset]::Parse(
                    [string]$Node.topology.final_route.captured_at_utc)
                if ($code -ceq 'API_FINAL_UNRESPONSIVE') {
                    return ($reason -ceq 'API_STATUS_UNRESPONSIVE' -and
                        (Test-ApiOperation -Operation 'api_status_final' `
                            -Available $false -ContractValid $false) -and
                        (Test-I07UnavailableApiStatusSummary `
                            -Summary $Node.product.api_status_final))
                }
                $captured = [DateTimeOffset]::Parse(
                    [string]$Node.product.api_status_final.captured_at_utc)
                return ($reason -ceq 'API_ISOLATION_CONTRADICTION' -and
                    (Test-ApiOperation -Operation 'api_status_final' `
                        -Available $true -ContractValid $true) -and
                    (Test-I07ApiStatusSummary `
                        -Summary $Node.product.api_status_final `
                        -RequireInvariantViolation) -and
                    $captured -ge $finalRoute -and $captured -le $completed)
            }

            if ($code -cin @(
                    'SOURCE_START_INVARIANT', 'VIEWER_START_INVARIANT',
                    'SOURCE_SESSION_INVARIANT', 'VIEWER_SESSION_INVARIANT') -and
                -not (Test-I07TimelineEnvelope -Node $Node)) {
                return $false
            }
            if ($code -ceq 'SOURCE_START_INVARIANT') {
                if ([string]$Node.role -cne 'source' -or
                    [string]$Node.phase -cne 'source_candidate_start') {
                    return $false
                }
                if ($reason -ceq 'LISTENER_MISSING') {
                    $listener = $failureEvidence.listener
                    return ($null -ne $listener -and
                        (Test-I07ExactPropertySet -Value $listener -Expected @(
                            'candidate_pid', 'expected_port',
                            'ipv6_listener_count')) -and
                        (Test-I07StrictInteger -Value $listener.candidate_pid `
                            -Minimum 1) -and
                        [Int64]$listener.candidate_pid -eq
                            [Int64]$Node.candidate.pid -and
                        (Test-I07StrictInteger -Value $listener.expected_port `
                            -Minimum 1024 -Maximum 65535) -and
                        [Int64]$listener.expected_port -eq
                            [Int64]$Node.topology.ports.tcp -and
                        (Test-I07StrictInteger `
                            -Value $listener.ipv6_listener_count `
                            -Minimum 0 -Maximum 0))
                }
                $map = @{
                    BROADCAST_API_UNRESPONSIVE = @($false, $false)
                    BROADCAST_API_MALFORMED = @($true, $false)
                }
                if ($reason -ceq 'BROADCAST_NOT_READY') {
                    $op = $failureEvidence.api_operation
                    if ($null -eq $op -or
                        -not (Test-I07StrictBoolean -Value $op.success) -or
                        -not (Test-I07StrictBoolean -Value $op.ready) -or
                        ([bool]$op.success -and [bool]$op.ready)) {
                        return $false
                    }
                    return Test-ApiOperation -Operation 'broadcast_start' `
                        -Available $true -ContractValid $true `
                        -Success ([bool]$op.success) -Ready ([bool]$op.ready)
                }
                if (-not $map.ContainsKey($reason)) { return $false }
                return Test-ApiOperation -Operation 'broadcast_start' `
                    -Available ([bool]$map[$reason][0]) `
                    -ContractValid ([bool]$map[$reason][1])
            }
            if ($code -ceq 'VIEWER_START_INVARIANT') {
                if ([string]$Node.role -cne 'viewer' -or
                    [string]$Node.phase -cne 'viewer_candidate_start') {
                    return $false
                }
                $map = @{
                    DIRECT_JOIN_API_UNRESPONSIVE = @($false, $false)
                    DIRECT_JOIN_API_MALFORMED = @($true, $false)
                }
                if ($reason -ceq 'DIRECT_JOIN_NOT_DIALED') {
                    $op = $failureEvidence.api_operation
                    if ($null -eq $op -or
                        -not (Test-I07StrictBoolean -Value $op.success) -or
                        -not (Test-I07StrictBoolean -Value $op.ready) -or
                        ([bool]$op.success -and [bool]$op.ready)) {
                        return $false
                    }
                    return Test-ApiOperation -Operation 'direct_join' `
                        -Available $true -ContractValid $true `
                        -Success ([bool]$op.success) -Ready ([bool]$op.ready)
                }
                if (-not $map.ContainsKey($reason)) { return $false }
                return Test-ApiOperation -Operation 'direct_join' `
                    -Available ([bool]$map[$reason][0]) `
                    -ContractValid ([bool]$map[$reason][1])
            }

            $expectedSessionCode = if ([string]$Node.role -ceq 'source') {
                'SOURCE_SESSION_INVARIANT'
            } else { 'VIEWER_SESSION_INVARIANT' }
            $expectedSessionPhase = if ([string]$Node.role -ceq 'source') {
                'source_direct_session'
            } else { 'viewer_direct_session' }
            if ($code -cne $expectedSessionCode -or
                [string]$Node.phase -cne $expectedSessionPhase) {
                return $false
            }
            if ($reason -ceq 'CANDIDATE_EXITED') {
                $exit = $failureEvidence.process_exit
                return ($null -ne $exit -and
                    (Test-I07ExactPropertySet -Value $exit -Expected @(
                        'candidate_pid', 'process_alive')) -and
                    (Test-I07StrictInteger -Value $exit.candidate_pid `
                        -Minimum 1) -and
                    [Int64]$exit.candidate_pid -eq [Int64]$Node.candidate.pid -and
                    (Test-I07StrictBoolean -Value $exit.process_alive) -and
                    -not [bool]$exit.process_alive)
            }
            $session = $failureEvidence.session_observation
            $sampleSummary = Get-I07SessionSamplesEvidence -Node $Node
            if ($null -eq $session -or
                $null -eq $sampleSummary -or
                -not (Test-I07ExactPropertySet -Value $session -Expected @(
                    'sample_count', 'observation_started_at_utc',
                    'deadline_at_utc', 'socket_observed',
                    'broadcasting_observed', 'api_peer_observed',
                    'viewing_observed', 'playlist_observed',
                    'segment_observed')) -or
                -not (Test-I07StrictInteger -Value $session.sample_count `
                    -Minimum 2) -or
                [Int64]$session.sample_count -ne @($Node.product.samples).Count) {
                return $false
            }
            $observationStarted = [DateTimeOffset]::MinValue
            $deadlineAt = [DateTimeOffset]::MinValue
            $minimumWindowSeconds = $ExpectedDurationSeconds + $(
                if ([string]$Node.role -ceq 'source') { 60 } else { 0 })
            if (-not [DateTimeOffset]::TryParse(
                    [string]$session.observation_started_at_utc,
                    [ref]$observationStarted) -or
                -not [DateTimeOffset]::TryParse(
                    [string]$session.deadline_at_utc, [ref]$deadlineAt) -or
                $observationStarted.Offset -ne [TimeSpan]::Zero -or
                $deadlineAt.Offset -ne [TimeSpan]::Zero -or
                $observationStarted -lt $started -or
                ($deadlineAt - $observationStarted).TotalSeconds -lt
                    $minimumWindowSeconds -or $observed -lt $deadlineAt) {
                return $false
            }
            $firstSampleAt = [DateTimeOffset]::Parse(
                [string]$sampleSummary.first_sample_at_utc)
            $lastSampleAt = [DateTimeOffset]::Parse(
                [string]$sampleSummary.last_sample_at_utc)
            if ($firstSampleAt -lt $observationStarted -or
                $firstSampleAt -gt $observationStarted.AddSeconds(2) -or
                $lastSampleAt -lt $deadlineAt.AddSeconds(-2) -or
                $observed -lt $lastSampleAt -or
                [Math]::Max(
                    [double]$sampleSummary.maximum_gap_seconds,
                    [Math]::Max(
                        ($firstSampleAt - $observationStarted).TotalSeconds,
                        [Math]::Max(
                            ($deadlineAt - $lastSampleAt).TotalSeconds,
                            ($observed - $lastSampleAt).TotalSeconds))) -gt $(
                    if ([string]$Node.role -ceq 'source') { 8.0 } else {
                        20.0
                    })) {
                return $false
            }
            foreach ($name in @(
                    'socket_observed', 'broadcasting_observed',
                    'api_peer_observed', 'viewing_observed',
                    'playlist_observed', 'segment_observed')) {
                if (-not (Test-I07StrictBoolean -Value $session.$name)) {
                    return $false
                }
                if ([bool]$session.$name -ne [bool]$sampleSummary.$name) {
                    return $false
                }
            }
            $observedFlags = [ordered]@{
                socket_observed = $false; broadcasting_observed = $false
                api_peer_observed = $false; viewing_observed = $false
                playlist_observed = $false; segment_observed = $false
            }
            foreach ($sample in @($Node.product.samples)) {
                $sampleTime = [DateTimeOffset]::MinValue
                $expectedNames = if ([string]$Node.role -ceq 'source') {
                    @('at_utc', 'process_alive', 'broadcasting', 'peer_socket')
                } else {
                    @('at_utc', 'process_alive', 'viewing', 'api_peer',
                        'peer_socket', 'playlist', 'segment')
                }
                if (-not (Test-I07ExactPropertySet -Value $sample `
                        -Expected $expectedNames) -or
                    -not [DateTimeOffset]::TryParse(
                        [string]$sample.at_utc, [ref]$sampleTime)) {
                    return $false
                }
                foreach ($sampleBool in @($expectedNames | Select-Object -Skip 1)) {
                    if (-not (Test-I07StrictBoolean -Value $sample.$sampleBool)) {
                        return $false
                    }
                }
                if ([bool]$sample.peer_socket) {
                    $observedFlags.socket_observed = $true
                }
                if ([string]$Node.role -ceq 'source') {
                    if ([bool]$sample.broadcasting) {
                        $observedFlags.broadcasting_observed = $true
                    }
                } else {
                    if ([bool]$sample.api_peer) {
                        $observedFlags.api_peer_observed = $true
                    }
                    if ([bool]$sample.viewing) {
                        $observedFlags.viewing_observed = $true
                    }
                    if ([bool]$sample.playlist) {
                        $observedFlags.playlist_observed = $true
                    }
                    if ([bool]$sample.segment) {
                        $observedFlags.segment_observed = $true
                    }
                }
            }
            foreach ($name in $observedFlags.Keys) {
                if ([bool]$session.$name -ne [bool]$observedFlags[$name]) {
                    return $false
                }
            }
            if ([string]$Node.role -ceq 'source') {
                return (($reason -ceq 'SOCKET_NOT_OBSERVED' -and
                        -not [bool]$session.socket_observed) -or
                    ($reason -ceq 'BROADCAST_NOT_OBSERVED' -and
                        -not [bool]$session.broadcasting_observed))
            }
            return (($reason -ceq 'SOCKET_NOT_OBSERVED' -and
                    -not [bool]$session.socket_observed) -or
                ($reason -ceq 'API_PEER_NOT_OBSERVED' -and
                    -not [bool]$session.api_peer_observed) -or
                ($reason -ceq 'LIVETV_NOT_OBSERVED' -and
                    (-not [bool]$session.viewing_observed -or
                     -not [bool]$session.playlist_observed -or
                     -not [bool]$session.segment_observed)))
        } catch { return $false }
    }

    function Test-I07ViewerProfileEnvelope {
        param([Parameter(Mandatory = $true)]$Node)
        if ([string]$Node.role -cne 'viewer') { return $true }
        if ([string]::IsNullOrWhiteSpace(
                $ExpectedViewerWlanProfileSha256) -and
            [string]::IsNullOrWhiteSpace(
                $ExpectedViewerConnectionProfileSha256) -and
            [string]::IsNullOrWhiteSpace($ExpectedViewerInterfaceGuid)) {
            return $true
        }
        try {
            $profile = $Node.topology.r01_hotspot_profile
            if (-not (Test-I07ExactPropertySet -Value $profile -Expected @(
                    'connection_profile', 'wlan_profile',
                    'revalidated_immediately_before_candidate',
                    'revalidated_at_utc')) -or
                -not (Test-I07WifiProfileRetentionContract `
                    -Profile ([pscustomobject]@{
                        connection_profile = $profile.connection_profile
                        wlan_profile = $profile.wlan_profile
                    }) `
                    -ConnectionSha256 `
                        $ExpectedViewerConnectionProfileSha256 `
                    -WlanSha256 $ExpectedViewerWlanProfileSha256 `
                    -InterfaceGuid $ExpectedViewerInterfaceGuid)) {
                return $false
            }
            $revalidated = [DateTimeOffset]::MinValue
            $started = [DateTimeOffset]::MinValue
            $timeValid = [DateTimeOffset]::TryParse(
                [string]$profile.revalidated_at_utc, [ref]$revalidated) -and
                [DateTimeOffset]::TryParse(
                    [string]$Node.candidate.started_at_utc, [ref]$started)
            return (
                [string]$profile.connection_profile.profile_sha256 -ceq
                    $ExpectedViewerConnectionProfileSha256 -and
                [string]$profile.wlan_profile.wlan_profile_sha256 -ceq
                    $ExpectedViewerWlanProfileSha256 -and
                ([string]$profile.connection_profile.interface_guid).
                    Trim('{}') -ieq $ExpectedViewerInterfaceGuid.Trim('{}') -and
                ([string]$profile.wlan_profile.interface_guid).Trim('{}') `
                    -ieq $ExpectedViewerInterfaceGuid.Trim('{}') -and
                ([string]$Node.topology.interface_guid).Trim('{}') -ieq
                    $ExpectedViewerInterfaceGuid.Trim('{}') -and
                (Test-I07StrictInteger `
                    -Value $profile.connection_profile.interface_index `
                    -Minimum 1) -and
                [Int64]$profile.connection_profile.interface_index -eq
                    [Int64]$Node.topology.interface_index -and
                (Test-I07StrictBoolean `
                    -Value $profile.revalidated_immediately_before_candidate) -and
                [bool]$profile.revalidated_immediately_before_candidate -and
                $timeValid -and $revalidated -le $started)
        } catch { return $false }
    }

    function Test-I07SocketEnvelope {
        param([Parameter(Mandatory = $true)]$Node)
        try {
            $socket = $Node.product.socket
            if (-not (Test-I07ExactPropertySet -Value $socket -Expected @(
                    'observed', 'count', 'tuples', 'local_address',
                    'interface_index', 'interface_guid', 'hardware_interface',
                    'virtual', 'overlay', 'interface_matches_route'))) {
                return $false
            }
            $local = ConvertTo-I07CanonicalIPv6 `
                -Value ([string]$Node.topology.local_ipv6)
            $peer = ConvertTo-I07CanonicalIPv6 `
                -Value ([string]$Node.topology.peer_ipv6)
            $tupleValid = $false
            foreach ($tuple in @($socket.tuples)) {
                try {
                    if (-not (Test-I07ExactPropertySet -Value $tuple `
                            -Expected @(
                                'local_address', 'local_port',
                                'remote_address', 'remote_port',
                                'owning_process', 'state'))) { continue }
                    if (-not (Test-I07StrictInteger -Value $tuple.local_port `
                                -Minimum 1 -Maximum 65535) -or
                        -not (Test-I07StrictInteger -Value $tuple.remote_port `
                                -Minimum 1 -Maximum 65535) -or
                        -not (Test-I07StrictInteger `
                                -Value $tuple.owning_process -Minimum 1)) {
                        continue
                    }
                    $portValid = if ([string]$Node.role -ceq 'source') {
                        [int]$tuple.local_port -eq
                            [int]$Node.topology.ports.tcp
                    } else {
                        [int]$tuple.remote_port -eq
                            [int]$Node.topology.ports.peer_tcp
                    }
                    if ([int]$tuple.owning_process -eq
                            [int]$Node.candidate.pid -and
                    (ConvertTo-I07CanonicalIPv6 `
                        -Value ([string]$tuple.local_address)) -ceq $local -and
                    (ConvertTo-I07CanonicalIPv6 `
                        -Value ([string]$tuple.remote_address)) -ceq $peer -and
                    [string]$tuple.state -ceq 'Established' -and $portValid) {
                        $tupleValid = $true
                        break
                    }
                } catch {}
            }
            return ((Test-I07StrictBoolean -Value $socket.observed) -and
                [bool]$socket.observed -and
                (Test-I07StrictInteger -Value $socket.count -Minimum 1) -and
                $tupleValid -and
                (ConvertTo-I07CanonicalIPv6 `
                    -Value ([string]$socket.local_address)) -ceq $local -and
                (Test-I07StrictInteger -Value $socket.interface_index `
                    -Minimum 1) -and
                [int]$socket.interface_index -eq
                    [int]$Node.topology.interface_index -and
                ([string]$socket.interface_guid).Trim('{}') -ieq
                    ([string]$Node.topology.interface_guid).Trim('{}') -and
                (Test-I07StrictBoolean -Value $socket.hardware_interface) -and
                [bool]$socket.hardware_interface -and
                (Test-I07StrictBoolean -Value $socket.virtual) -and
                -not [bool]$socket.virtual -and
                (Test-I07StrictBoolean -Value $socket.overlay) -and
                -not [bool]$socket.overlay -and
                (Test-I07StrictBoolean `
                    -Value $socket.interface_matches_route) -and
                [bool]$socket.interface_matches_route)
        } catch { return $false }
    }

    function Test-I07ViewerApiPeerEnvelope {
        param([Parameter(Mandatory = $true)]$Node)
        try {
            $peerAddress = ConvertTo-I07CanonicalIPv6 `
                -Value ([string]$Node.topology.peer_ipv6)
            $evidence = $Node.product.api_peer
            $controlled = $evidence.controlled_peer
            if (-not (Test-I07ExactPropertySet -Value $evidence -Expected @(
                    'schema', 'matched', 'controlled_peer')) -or
                -not (Test-I07ExactPropertySet -Value $controlled -Expected @(
                    'address', 'port', 'isFork', 'dataplaneCap'))) {
                return $false
            }
            return (
                [string]$evidence.schema -ceq
                    'ese.v91.i07-controlled-api-peer/v1' -and
                (Test-I07StrictBoolean -Value $evidence.matched) -and
                [bool]$evidence.matched -and
                (ConvertTo-I07CanonicalIPv6 `
                    -Value ([string]$controlled.address)) -ceq $peerAddress -and
                (Test-I07StrictInteger -Value $controlled.port `
                    -Minimum 1024 -Maximum 65535) -and
                [int]$controlled.port -eq
                    [int]$Node.topology.ports.peer_tcp -and
                (Test-I07StrictBoolean -Value $controlled.isFork) -and
                [bool]$controlled.isFork -and
                (Test-I07StrictBoolean -Value $controlled.dataplaneCap) -and
                [bool]$controlled.dataplaneCap)
        } catch { return $false }
    }

    function Test-I07HlsEnvelope {
        param([Parameter(Mandatory = $true)]$Node)
        try {
            if (-not (Test-I07ExactPropertySet -Value $Node.product.hls `
                    -Expected @(
                        'playlist_seen', 'segment_seen',
                        'segment_path_contained', 'playlist_name',
                        'stream_key_sha256', 'playlist_last_write_utc',
                        'segment_last_write_utc', 'segment_bytes',
                        'minimum_write_utc'))) { return $false }
            $started = [DateTimeOffset]::Parse(
                [string]$Node.candidate.started_at_utc)
            $playlist = [DateTimeOffset]::Parse(
                [string]$Node.product.hls.playlist_last_write_utc)
            $segment = [DateTimeOffset]::Parse(
                [string]$Node.product.hls.segment_last_write_utc)
            $minimum = [DateTimeOffset]::Parse(
                [string]$Node.product.hls.minimum_write_utc)
            return ((Test-I07StrictBoolean `
                    -Value $Node.product.hls.playlist_seen) -and
                [bool]$Node.product.hls.playlist_seen -and
                (Test-I07StrictBoolean `
                    -Value $Node.product.hls.segment_seen) -and
                [bool]$Node.product.hls.segment_seen -and
                (Test-I07StrictBoolean `
                    -Value $Node.product.hls.segment_path_contained) -and
                [bool]$Node.product.hls.segment_path_contained -and
                [string]$Node.product.hls.playlist_name -ceq 'stream.m3u8' -and
                [string]$Node.product.hls.stream_key_sha256 -cmatch
                    '^[0-9a-f]{64}$' -and
                (Test-I07StrictInteger `
                    -Value $Node.product.hls.segment_bytes -Minimum 1) -and
                $minimum.Offset -eq [TimeSpan]::Zero -and
                $playlist.Offset -eq [TimeSpan]::Zero -and
                $segment.Offset -eq [TimeSpan]::Zero -and
                $minimum -eq $started -and
                $playlist -ge $minimum -and $segment -ge $minimum)
        } catch { return $false }
    }

    function Test-I07BroadcastEnvelope {
        param([Parameter(Mandatory = $true)]$Node)
        $value = $Node.product.broadcast
        return ((Test-I07ExactPropertySet -Value $value -Expected @(
                    'success', 'ready', 'stream_key_sha256')) -and
            (Test-I07StrictBoolean -Value $value.success) -and
            [bool]$value.success -and
            (Test-I07StrictBoolean -Value $value.ready) -and
            [bool]$value.ready -and
            (Test-I07StrictString -Value $value.stream_key_sha256) -and
            [string]$value.stream_key_sha256 -cmatch '^[0-9a-f]{64}$')
    }

    function Test-I07DirectJoinEnvelope {
        param([Parameter(Mandatory = $true)]$Node)
        $value = $Node.product.direct_join
        return ((Test-I07ExactPropertySet -Value $value -Expected @(
                    'success', 'dialed', 'joined')) -and
            (Test-I07StrictBoolean -Value $value.success) -and
            [bool]$value.success -and
            (Test-I07StrictBoolean -Value $value.dialed) -and
            [bool]$value.dialed -and
            ($null -eq $value.joined -or
                (Test-I07StrictBoolean -Value $value.joined)))
    }

    function Test-I07PairEnvelope {
        param(
            [Parameter(Mandatory = $true)]$SourceNode,
            [Parameter(Mandatory = $true)]$ViewerNode
        )
        try {
            foreach ($portValue in @(
                    $SourceNode.topology.ports.tcp,
                    $SourceNode.topology.ports.udp,
                    $SourceNode.topology.ports.web,
                    $SourceNode.topology.ports.peer_tcp,
                    $SourceNode.topology.ports.control,
                    $ViewerNode.topology.ports.tcp,
                    $ViewerNode.topology.ports.udp,
                    $ViewerNode.topology.ports.web,
                    $ViewerNode.topology.ports.peer_tcp,
                    $ViewerNode.topology.ports.control)) {
                if (-not (Test-I07StrictInteger -Value $portValue `
                        -Minimum 1024 -Maximum 65535)) { return $false }
            }
            return (
                (ConvertTo-I07CanonicalIPv6 -Value (
                    [string]$SourceNode.topology.local_ipv6)) -ceq
                    (ConvertTo-I07CanonicalIPv6 -Value (
                        [string]$ViewerNode.topology.peer_ipv6)) -and
                (ConvertTo-I07CanonicalIPv6 -Value (
                    [string]$ViewerNode.topology.local_ipv6)) -ceq
                    (ConvertTo-I07CanonicalIPv6 -Value (
                        [string]$SourceNode.topology.peer_ipv6)) -and
                [int]$SourceNode.topology.ports.tcp -eq 48067 -and
                [int]$SourceNode.topology.ports.udp -eq 48077 -and
                [int]$SourceNode.topology.ports.web -eq 48117 -and
                [int]$SourceNode.topology.ports.peer_tcp -eq 48267 -and
                [int]$ViewerNode.topology.ports.tcp -eq 48267 -and
                [int]$ViewerNode.topology.ports.udp -eq 48277 -and
                [int]$ViewerNode.topology.ports.web -eq 48317 -and
                [int]$ViewerNode.topology.ports.peer_tcp -eq 48067 -and
                [int]$SourceNode.topology.ports.control -eq 48907 -and
                [int]$ViewerNode.topology.ports.control -eq 48907 -and
                [string]$SourceNode.product.broadcast.stream_key_sha256 `
                    -cmatch '^[0-9a-f]{64}$' -and
                [string]$SourceNode.product.broadcast.stream_key_sha256 `
                    -ceq [string]$ViewerNode.product.hls.stream_key_sha256)
        } catch { return $false }
    }

    function Get-I07ObjectNames {
        param([AllowNull()]$Value)
        if ($null -eq $Value) { return @() }
        if ($Value -is [Collections.IDictionary]) {
            return @($Value.Keys | ForEach-Object { [string]$_ })
        }
        return @($Value.PSObject.Properties | ForEach-Object {
                [string]$_.Name
            })
    }

    function Test-I07ExactObjectNames {
        param([AllowNull()]$Value, [string[]]$Expected)
        return ((@(Get-I07ObjectNames -Value $Value | Sort-Object) -join
                "`n") -ceq (@($Expected | Sort-Object) -join "`n"))
    }

    function Test-I07BuildEvidenceEnvelope {
        param([Parameter(Mandatory = $true)]$Node)
        try {
            $build = $Node.evidence.build_info
            $fieldNames = @(
                'release', 'commit', 'dirty', 'built_utc', 'node', 'npm',
                'ffmpeg', 'ffmpeg_sha256', 'ffprobe_sha256',
                'nodes_dat_sha256')
            if (-not (Test-I07ExactObjectNames -Value $build -Expected @(
                        'schema', 'original_sha256', 'expected_sha256',
                        'exact', 'fields_valid', 'unknown_line_count',
                        'fields')) -or
                -not (Test-I07ExactObjectNames -Value $build.fields `
                    -Expected $fieldNames)) {
                return $false
            }
            $builtUtc = [DateTimeOffset]::MinValue
            return (
                [string]$build.schema -ceq
                    'ese.v91.i07-build-info-evidence/v1' -and
                [string]$build.original_sha256 -ceq
                    [string]$Node.candidate.build_info_sha256 -and
                [string]$build.expected_sha256 -ceq
                    [string]$Node.candidate.build_info_sha256 -and
                ($build.exact -is [bool]) -and [bool]$build.exact -and
                ($build.fields_valid -is [bool]) -and
                    [bool]$build.fields_valid -and
                (Test-I07StrictInteger -Value $build.unknown_line_count `
                    -Minimum 0 -Maximum 0) -and
                [string]$build.fields.commit -ceq
                    [string]$Node.candidate.commit -and
                [string]$build.fields.commit -cmatch '^[0-9a-f]{40}$' -and
                [string]$build.fields.dirty -ceq 'false' -and
                [string]$build.fields.release -cmatch
                    '^[A-Za-z0-9._+-]{1,80}$' -and
                [DateTimeOffset]::TryParseExact(
                    [string]$build.fields.built_utc,
                    'yyyy-MM-ddTHH:mm:ssZ',
                    [Globalization.CultureInfo]::InvariantCulture,
                    [Globalization.DateTimeStyles]::AssumeUniversal,
                    [ref]$builtUtc) -and
                [string]$build.fields.node -cmatch
                    '^v?[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$' -and
                [string]$build.fields.npm -cmatch
                    '^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$' -and
                [string]$build.fields.ffmpeg -cmatch
                    '^ffmpeg version [A-Za-z0-9 .,_+()=:;-]{1,240}$' -and
                [string]$build.fields.ffmpeg_sha256 -cmatch
                    '^[0-9a-f]{64}$' -and
                [string]$build.fields.ffprobe_sha256 -cmatch
                    '^[0-9a-f]{64}$' -and
                [string]$build.fields.nodes_dat_sha256 -cmatch
                    '^[0-9a-f]{64}$')
        } catch { return $false }
    }

    function Test-I07ConfigEvidenceEnvelope {
        param([Parameter(Mandatory = $true)]$Node)
        try {
            $config = $Node.evidence.effective_config
            if (-not (Test-I07ExactObjectNames -Value $config -Expected @(
                        'schema', 'allowlist_only', 'values_exact', 'role',
                        'entries')) -or
                [string]$config.schema -cne
                    'ese.v91.i07-effective-config/v2' -or
                -not ($config.allowlist_only -is [bool]) -or
                -not [bool]$config.allowlist_only -or
                -not ($config.values_exact -is [bool]) -or
                -not [bool]$config.values_exact -or
                [string]$config.role -cne [string]$Node.role) {
                return $false
            }
            $expected = [ordered]@{
                'eMule/Nick' = if ([string]$Node.role -ceq 'source') {
                    'eSE-A'
                } else { 'eSE-B' }
                'eMule/Port' = [string]$Node.topology.ports.tcp
                'eMule/UDPPort' = [string]$Node.topology.ports.udp
                'eMule/NetworkKademlia' = '0'; 'eMule/NetworkED2K' = '0'
                'eMule/AutoConnect' = '0'; 'Connection/NetworkED2K' = '0'
                'eMule/OpenPortsOnStartUp' = '0'; 'eMule/AutoStart' = '0'
                'eMule/AutoTakeED2KLinks' = '0'
                'eMule/WatchClipboard4ED2kFilelinks' = '0'
                'Connection/KadNetworkMask' = '0'; 'Connection/IPv6Mode' = '2'
                'UPnP/EnableUPnP' = '0'; 'Proxy/ProxyEnableProxy' = '0'
                'Proxy/ProxyEnablePassword' = '0'; 'WebServer/Enabled' = '1'
                'WebServer/Port' = [string]$Node.topology.ports.web
                'WebServer/WebUseUPnP' = '0'
                'WebServer/AllowedIPs' = '127.0.0.1'
                'eSE/EseNetLabEnabled' = '0'; 'eSE/EseNetLabConsent' = '0'
                'eSE/EseNetLabAdvancedConsent' = '0'
                'eSE/EseNetLabContributionConsent' = '0'
                'eSE/EseV9Experimental' = '0'; 'eSE/Kad6BetaExitOptIn' = '0'
                'eSE/Kad6PublicExitOptIn' = '0'
            }
            $observed = [ordered]@{}
            foreach ($entry in @($config.entries)) {
                if (-not (Test-I07ExactObjectNames -Value $entry -Expected @(
                            'section', 'key', 'value')) -or
                    -not ($entry.section -is [string]) -or
                    -not ($entry.key -is [string]) -or
                    -not ($entry.value -is [string])) {
                    return $false
                }
                $name = '{0}/{1}' -f [string]$entry.section,
                    [string]$entry.key
                if ($observed.Contains($name)) { return $false }
                $observed[$name] = [string]$entry.value
            }
            return ($observed.Count -eq $expected.Count -and
                @($expected.Keys | Where-Object {
                        -not $observed.Contains($_) -or
                        [string]$observed[$_] -cne [string]$expected[$_]
                    }).Count -eq 0)
        } catch { return $false }
    }

    function Test-I07LogEvidenceEnvelope {
        param([Parameter(Mandatory = $true)]$Node)
        try {
            $log = $Node.evidence.log_evidence
            if (-not (Test-I07ExactObjectNames -Value $log -Expected @(
                        'schema', 'source_file_count',
                        'inspected_nonempty_line_count',
                        'timestamped_line_count', 'capped_at_200_lines',
                        'events')) -or
                [string]$log.schema -cne 'ese.v91.i07-log-evidence/v1' -or
                -not (Test-I07StrictInteger -Value $log.source_file_count `
                    -Minimum 1) -or
                -not (Test-I07StrictInteger `
                    -Value $log.inspected_nonempty_line_count `
                    -Minimum 1 -Maximum 200) -or
                -not (Test-I07StrictInteger -Value $log.timestamped_line_count `
                    -Minimum 1 -Maximum 200) -or
                [int]$log.timestamped_line_count -gt
                    [int]$log.inspected_nonempty_line_count -or
                -not ($log.capped_at_200_lines -is [bool]) -or
                [bool]$log.capped_at_200_lines -ne
                    ([int]$log.inspected_nonempty_line_count -ge 200) -or
                @($log.events).Count -ne
                    [Math]::Min(20, [int]$log.timestamped_line_count)) {
                return $false
            }
            $timestampPattern =
                '(?i)^(?:\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}|' +
                '\d{1,2}[/. -]\d{1,2}[/. -]\d{2,4}\s+\d{1,2}:\d{2}:\d{2}|' +
                '\[\d{1,2}:\d{2}:\d{2}\])$'
            foreach ($event in @($log.events)) {
                if (-not (Test-I07ExactObjectNames -Value $event -Expected @(
                            'timestamp', 'event_class')) -or
                    -not ($event.timestamp -is [string]) -or
                    [string]$event.timestamp -notmatch $timestampPattern -or
                    -not ($event.event_class -is [string]) -or
                    [string]$event.event_class -cnotin @(
                        'error', 'warning', 'livetv', 'connectivity',
                        'lifecycle', 'other')) {
                    return $false
                }
            }
            return $true
        } catch { return $false }
    }

    function Test-I07NodeEvidenceEnvelope {
        param([Parameter(Mandatory = $true)]$Node)
        try {
            $requiredNames = @(
                'BUILD_INFO.txt', 'build-info-evidence.json',
                'effective-config.json', 'api-status-pre.json',
                'api-status-post.json', 'topology-ports.json',
                'log-evidence.json')
            if (-not (Test-I07ExactObjectNames -Value $Node.evidence `
                    -Expected @(
                        'schema', 'complete', 'directory', 'files',
                        'manifest', 'requirements', 'build_info',
                        'effective_config', 'log_evidence')) -or
                -not (Test-I07ExactObjectNames `
                    -Value $Node.evidence.requirements -Expected @(
                        'build_info_exact', 'build_info_source_sha256',
                        'config_allowlist_only', 'api_pre_retained',
                        'api_post_retained', 'topology_ports_retained',
                        'real_log_line_count',
                        'timestamped_log_line_count')) -or
                -not (Test-I07ExactObjectNames -Value $Node.evidence.manifest `
                    -Expected @('name', 'bytes', 'sha256'))) {
                return $false
            }
            $files = @($Node.evidence.files)
            $names = @($files | ForEach-Object { [string]$_.name })
            foreach ($file in $files) {
                if (-not (Test-I07ExactObjectNames -Value $file `
                        -Expected @('name', 'bytes', 'sha256')) -or
                    -not (Test-I07StrictInteger -Value $file.bytes `
                        -Minimum 1)) {
                    return $false
                }
            }
            $rawBuildFile = @($files | Where-Object {
                    [string]$_.name -ceq 'BUILD_INFO.txt'
                })
            $requirements = $Node.evidence.requirements
            return ((Test-I07StrictBoolean `
                    -Value $Node.cleanup.evidence_retained) -and
                [bool]$Node.cleanup.evidence_retained -and
                [string]$Node.evidence.schema -ceq
                    'ese.v91.i07-retained-evidence/v1' -and
                ($Node.evidence.complete -is [bool]) -and
                    [bool]$Node.evidence.complete -and
                [string]$Node.evidence.directory -ceq 'evidence' -and
                $files.Count -eq $requiredNames.Count -and
                @($names | Select-Object -Unique).Count -eq
                    $requiredNames.Count -and
                (@($names | Sort-Object) -join "`n") -ceq
                    (@($requiredNames | Sort-Object) -join "`n") -and
                @($files | Where-Object {
                        [Int64]$_.bytes -le 0 -or
                        [string]$_.sha256 -notmatch '^[0-9a-f]{64}$'
                    }).Count -eq 0 -and
                $rawBuildFile.Count -eq 1 -and
                [string]$rawBuildFile[0].sha256 -ceq
                    [string]$Node.candidate.build_info_sha256 -and
                [string]$requirements.build_info_source_sha256 -ceq
                    [string]$Node.candidate.build_info_sha256 -and
                [string]$Node.evidence.manifest.name -ceq 'manifest.json' -and
                (Test-I07StrictInteger `
                    -Value $Node.evidence.manifest.bytes -Minimum 1) -and
                [string]$Node.evidence.manifest.sha256 -match
                    '^[0-9a-f]{64}$' -and
                ($requirements.build_info_exact -is [bool]) -and
                    [bool]$requirements.build_info_exact -and
                ($requirements.config_allowlist_only -is [bool]) -and
                    [bool]$requirements.config_allowlist_only -and
                ($requirements.api_pre_retained -is [bool]) -and
                    [bool]$requirements.api_pre_retained -and
                ($requirements.api_post_retained -is [bool]) -and
                    [bool]$requirements.api_post_retained -and
                ($requirements.topology_ports_retained -is [bool]) -and
                    [bool]$requirements.topology_ports_retained -and
                (Test-I07StrictInteger `
                    -Value $requirements.real_log_line_count -Minimum 1) -and
                (Test-I07StrictInteger `
                    -Value $requirements.timestamped_log_line_count `
                    -Minimum 1) -and
                [int]$requirements.real_log_line_count -eq
                    [int]$Node.evidence.log_evidence.
                        inspected_nonempty_line_count -and
                [int]$requirements.timestamped_log_line_count -eq
                    [int]$Node.evidence.log_evidence.
                        timestamped_line_count -and
                (Test-I07BuildEvidenceEnvelope -Node $Node) -and
                (Test-I07ConfigEvidenceEnvelope -Node $Node) -and
                (Test-I07LogEvidenceEnvelope -Node $Node))
        } catch { return $false }
    }

    function Test-I07WebContainmentEnvelope {
        param([Parameter(Mandatory = $true)]$Node)
        try {
            $value = $Node.topology.web_api_containment
            if (-not (Test-I07ExactPropertySet -Value $value -Expected @(
                    'rule_name', 'direction', 'action', 'enabled', 'profile',
                    'protocol', 'local_port', 'local_address',
                    'remote_address', 'program_leaf',
                    'program_matches_candidate',
                    'blocks_physical_ipv4_and_ipv6'))) { return $false }
            return (
                [string]$value.direction -ceq 'Inbound' -and
                [string]$value.action -ceq 'Block' -and
                [string]$value.enabled -ceq 'True' -and
                [string]$value.profile -ceq 'Any' -and
                [string]$value.protocol -ceq 'TCP' -and
                (Test-I07StrictInteger -Value $value.local_port `
                    -Minimum 1024 -Maximum 65535) -and
                [int]$value.local_port -eq [int]$Node.topology.ports.web -and
                [string]$value.local_address -ceq 'Any' -and
                [string]$value.remote_address -ceq 'Any' -and
                (Test-I07StrictBoolean `
                    -Value $value.blocks_physical_ipv4_and_ipv6) -and
                [bool]$value.blocks_physical_ipv4_and_ipv6 -and
                [string]$value.rule_name -ceq
                    "eSE-V91-I07-web-block-$($Node.nonce)-$($Node.role)" -and
                [string]$value.program_leaf -ceq 'emule.exe' -and
                (Test-I07StrictBoolean `
                    -Value $value.program_matches_candidate) -and
                [bool]$value.program_matches_candidate)
        } catch { return $false }
    }

    function Test-I07FailureEnvelope {
        param([Parameter(Mandatory = $true)]$Node)
        try {
            $statusValue = [string]$Node.status
            if ($statusValue -ceq 'PASS') {
                return $null -eq $Node.failure
            }
            if ($statusValue -cnotin @('FAIL', 'LAB_BLOCKED') -or
                $null -eq $Node.failure) {
                return $false
            }
            $names = @($Node.failure.PSObject.Properties.Name | Sort-Object)
            if (($names -join ',') -cne 'category,code' -or
                -not ($Node.failure.category -is [string]) -or
                -not ($Node.failure.code -is [string])) {
                return $false
            }
            if ($statusValue -ceq 'FAIL') {
                return (
                    [string]$Node.failure.category -ceq
                        'PRODUCT_INVARIANT' -and
                    [string]$Node.failure.code -cin @(
                        'SOURCE_START_INVARIANT',
                        'VIEWER_START_INVARIANT',
                        'SOURCE_SESSION_INVARIANT',
                        'VIEWER_SESSION_INVARIANT',
                        'API_INITIAL_UNRESPONSIVE',
                        'API_INITIAL_ISOLATION_CONTRADICTION',
                        'API_FINAL_UNRESPONSIVE',
                        'API_FINAL_ISOLATION_CONTRADICTION'))
            }
            return (
                ([string]$Node.failure.category -ceq
                    'LAB_TOPOLOGY_OR_FIXTURE' -and
                 [string]$Node.failure.code -cin @(
                    'LAB_PRECONDITION_OR_RUNTIME',
                    'UNEXPECTED_LAB_ERROR')) -or
                ([string]$Node.failure.category -ceq 'CLEANUP' -and
                 [string]$Node.failure.code -ceq 'CLEANUP_INCOMPLETE'))
        } catch { return $false }
    }

    function Test-I07NodeEnvelope {
        param(
            [AllowNull()]$Node,
            [Parameter(Mandatory = $true)][string]$ExpectedRole
        )
        if ($null -eq $Node) { return $false }
        try {
            $rootShape = Test-I07ExactPropertySet -Value $Node -Expected @(
                'schema', 'case_id', 'status', 'role', 'nonce',
                'completed_at_utc', 'phase', 'failure', 'candidate',
                'topology', 'product', 'cleanup', 'evidence', 'system_state',
                'process_cleanup')
            $candidateShape = (Test-I07ExactPropertySet `
                -Value $Node.candidate -Expected @(
                    'requested_sha256', 'sha256', 'bytes', 'verified', 'pid',
                    'started_at_utc', 'commit', 'build_info_sha256',
                    'zip_sha256', 'zip_bytes', 'zip_verified', 'zip_binding',
                    'package_files', 'process_identity', 'launch_binding'))
            $topologyShape = Test-I07ExactPropertySet `
                -Value $Node.topology -Expected @(
                    'topology_id', 'native_path_proven_before_candidate',
                    'local_ipv6', 'peer_ipv6', 'interface_index',
                    'interface_guid', 'ports', 'initial_route', 'final_route',
                    'control', 'r01_hotspot_profile', 'web_api_containment')
            $productShape = Test-I07ExactPropertySet `
                -Value $Node.product -Expected @(
                    'broadcast', 'direct_join', 'socket', 'api_peer', 'hls',
                    'api_status_initial', 'api_status_final', 'samples',
                    'failure_evidence')
            $cleanupShape = Test-I07ExactPropertySet `
                -Value $Node.cleanup -Expected @(
                    'process_stopped', 'firewall_removed', 'control_closed',
                    'broadcast_stopped', 'ffmpeg_children_gone', 'hls_removed',
                    'node_removed', 'evidence_retained',
                    'system_state_restored')
            $evidenceShape = Test-I07ExactPropertySet `
                -Value $Node.evidence -Expected @(
                    'schema', 'complete', 'directory', 'files', 'manifest',
                    'requirements', 'build_info', 'effective_config',
                    'log_evidence')
            $statusEvidence = if ([string]$Node.status -ceq 'FAIL') {
                Test-I07ProductFailureEvidence -Node $Node
            } else {
                Test-I07TimelineEnvelope -Node $Node
            }
            $roleShape = if ($ExpectedRole -ceq 'source') {
                $null -eq $Node.topology.r01_hotspot_profile -and
                $null -eq $Node.product.direct_join -and
                $null -eq $Node.product.api_peer -and
                $null -eq $Node.product.hls
            } else { $null -eq $Node.product.broadcast }
            $zipBindingShape = Test-I07ExactPropertySet `
                -Value $Node.candidate.zip_binding -Expected @(
                    'schema', 'verified', 'zip_sha256', 'zip_bytes',
                    'critical_file_count', 'critical_files')
            $identityShape = Test-I07ExactPropertySet `
                -Value $Node.candidate.process_identity -Expected @(
                    'schema', 'process_id', 'start_time_utc',
                    'executable_path_sha256', 'executable_sha256',
                    'user_sid_sha256')
            $launchShape = Test-I07ExactPropertySet `
                -Value $Node.candidate.launch_binding -Expected @(
                    'schema', 'verified', 'static_file_count',
                    'static_manifest_sha256', 'preferences_sha256',
                    'preferences_bytes', 'candidate_sha256')
            $systemStateShape = Test-I07ExactPropertySet `
                -Value $Node.system_state -Expected @(
                    'schema', 'collector_ok', 'complete',
                    'bound_sid_unchanged', 'run_subtree_unchanged',
                    'emule_autostart_absent', 'ed2k_subtree_unchanged',
                    'ed2k_subtree_absent', 'global_firewall_unchanged',
                    'baseline_registry_sha256', 'post_registry_sha256',
                    'baseline_firewall_sha256', 'post_firewall_sha256')
            $processCleanupShape = Test-I07ExactPropertySet `
                -Value $Node.process_cleanup -Expected @(
                    'schema', 'stopped', 'root_identity_matched',
                    'descendants_collector_ok', 'descendant_count',
                    'descendants_stopped')
            $nodePackageCanonical = Get-I07ContractCanonical `
                -Files @($Node.candidate.package_files)
            $nodeZipCanonical = Get-I07ContractCanonical `
                -Files @($Node.candidate.zip_binding.critical_files)
            $candidateFileBinding = $true
            if (-not [string]::IsNullOrWhiteSpace($expectedPackageCanonical)) {
                $emuleContract = @($ExpectedPackageFiles | Where-Object {
                        [string]$_.path -ceq 'emule.exe'
                    })
                $candidateFileBinding = $emuleContract.Count -eq 1 -and
                    [Int64]$Node.candidate.bytes -eq
                        [Int64]$emuleContract[0].bytes
            }
            $expectedSid = if ($ExpectedRole -ceq 'source') {
                [string]$ExpectedSourceLabUserSidSha256
            } else { [string]$ExpectedViewerLabUserSidSha256 }
            $sidBinding = [string]::IsNullOrWhiteSpace($expectedSid) -or
                [string]$Node.candidate.process_identity.user_sid_sha256 `
                    -ceq $expectedSid.ToLowerInvariant()
            $launchManifestBinding =
                [string]::IsNullOrWhiteSpace($expectedPackageCanonical) -or (
                    [Int64]$Node.candidate.launch_binding.static_file_count `
                        -eq $ExpectedPackageFiles.Count -and
                    [string]$Node.candidate.launch_binding.
                        static_manifest_sha256 -ceq
                        (Get-I07PackageManifestSha256 `
                            -Files $ExpectedPackageFiles))
            $systemStateTyped =
                (Test-I07StrictBoolean -Value $Node.system_state.collector_ok) `
                    -and
                (Test-I07StrictBoolean -Value $Node.system_state.complete) -and
                (Test-I07StrictBoolean `
                    -Value $Node.system_state.bound_sid_unchanged) -and
                (Test-I07StrictBoolean `
                    -Value $Node.system_state.run_subtree_unchanged) -and
                (Test-I07StrictBoolean `
                    -Value $Node.system_state.emule_autostart_absent) -and
                (Test-I07StrictBoolean `
                    -Value $Node.system_state.ed2k_subtree_unchanged) -and
                (Test-I07StrictBoolean `
                    -Value $Node.system_state.ed2k_subtree_absent) -and
                (Test-I07StrictBoolean `
                    -Value $Node.system_state.global_firewall_unchanged)
            $systemStateConsistent =
                [bool]$Node.cleanup.system_state_restored -eq (
                    [bool]$Node.system_state.collector_ok -and
                    [bool]$Node.system_state.complete)
            if ([bool]$Node.system_state.collector_ok) {
                $systemStateConsistent = $systemStateConsistent -and
                    [string]$Node.system_state.baseline_registry_sha256 `
                        -cmatch '^[0-9a-f]{64}$' -and
                    [string]$Node.system_state.post_registry_sha256 `
                        -cmatch '^[0-9a-f]{64}$' -and
                    [string]$Node.system_state.baseline_firewall_sha256 `
                        -cmatch '^[0-9a-f]{64}$' -and
                    [string]$Node.system_state.post_firewall_sha256 `
                        -cmatch '^[0-9a-f]{64}$'
            }
            if ([bool]$Node.system_state.complete) {
                $systemStateConsistent = $systemStateConsistent -and
                    [bool]$Node.system_state.collector_ok -and
                    [bool]$Node.system_state.bound_sid_unchanged -and
                    [bool]$Node.system_state.run_subtree_unchanged -and
                    [bool]$Node.system_state.emule_autostart_absent -and
                    [bool]$Node.system_state.ed2k_subtree_unchanged -and
                    [bool]$Node.system_state.ed2k_subtree_absent -and
                    [bool]$Node.system_state.global_firewall_unchanged -and
                    [string]$Node.system_state.baseline_registry_sha256 -ceq
                        [string]$Node.system_state.post_registry_sha256 -and
                    [string]$Node.system_state.baseline_firewall_sha256 -ceq
                        [string]$Node.system_state.post_firewall_sha256
            }
            $processCleanupTyped =
                (Test-I07StrictBoolean `
                    -Value $Node.process_cleanup.stopped) -and
                (Test-I07StrictBoolean `
                    -Value $Node.process_cleanup.root_identity_matched) -and
                (Test-I07StrictBoolean `
                    -Value $Node.process_cleanup.descendants_collector_ok) -and
                (Test-I07StrictInteger `
                    -Value $Node.process_cleanup.descendant_count -Minimum 0) `
                    -and
                (Test-I07StrictBoolean `
                    -Value $Node.process_cleanup.descendants_stopped)
            $processCleanupConsistent =
                (-not [bool]$Node.cleanup.process_stopped -or (
                    [bool]$Node.process_cleanup.stopped -and
                    [bool]$Node.process_cleanup.root_identity_matched)) -and
                (-not [bool]$Node.cleanup.ffmpeg_children_gone -or (
                    [bool]$Node.process_cleanup.descendants_collector_ok -and
                    [bool]$Node.process_cleanup.descendants_stopped))
            return (
                $rootShape -and $candidateShape -and $topologyShape -and
                $productShape -and $cleanupShape -and $evidenceShape -and
                $roleShape -and $identityShape -and $launchShape -and
                $systemStateShape -and $processCleanupShape -and
                $sidBinding -and $launchManifestBinding -and
                $systemStateTyped -and $systemStateConsistent -and
                $processCleanupTyped -and $processCleanupConsistent -and
                (Test-I07NoRawDiagnosticProperties -Value $Node) -and
                $(if ([string]$Node.status -ceq 'FAIL') {
                    $null -ne $Node.product.failure_evidence
                } else { $null -eq $Node.product.failure_evidence }) -and
                [string]$Node.schema -ceq 'ese.v91.i07-node-result/v1' -and
                [string]$Node.case_id -ceq 'V91-I07' -and
                [string]$Node.role -ceq $ExpectedRole -and
                [string]$Node.nonce -ceq $Nonce -and
                (Test-I07FailureEnvelope -Node $Node) -and
                [string]$Node.candidate.requested_sha256 -ceq
                    $CandidateSha256 -and
                (Test-I07StrictBoolean -Value $Node.candidate.verified) -and
                [bool]$Node.candidate.verified -and
                (Test-I07StrictInteger -Value $Node.candidate.bytes `
                    -Minimum 1) -and
                (Test-I07StrictInteger -Value $Node.candidate.pid `
                    -Minimum 1) -and
                [string]$Node.candidate.sha256 -ceq $CandidateSha256 -and
                [string]$Node.candidate.process_identity.schema -ceq
                    'ese.v91.i07-process-identity/v1' -and
                [int]$Node.candidate.process_identity.process_id -eq
                    [int]$Node.candidate.pid -and
                (Test-I07UtcRetentionString -Value `
                    $Node.candidate.process_identity.start_time_utc) -and
                [string]$Node.candidate.process_identity.start_time_utc -ceq
                    [string]$Node.candidate.started_at_utc -and
                [string]$Node.candidate.process_identity.executable_sha256 `
                    -ceq $CandidateSha256 -and
                [string]$Node.candidate.process_identity.
                    executable_path_sha256 -cmatch '^[0-9a-f]{64}$' -and
                [string]$Node.candidate.process_identity.user_sid_sha256 `
                    -cmatch '^[0-9a-f]{64}$' -and
                [string]$Node.candidate.launch_binding.schema -ceq
                    'ese.v91.i07-prelaunch-binding/v1' -and
                (Test-I07StrictBoolean `
                    -Value $Node.candidate.launch_binding.verified) -and
                [bool]$Node.candidate.launch_binding.verified -and
                (Test-I07StrictInteger `
                    -Value $Node.candidate.launch_binding.static_file_count `
                    -Minimum 7 -Maximum 100000) -and
                [string]$Node.candidate.launch_binding.
                    static_manifest_sha256 -cmatch '^[0-9a-f]{64}$' -and
                [string]$Node.candidate.launch_binding.preferences_sha256 `
                    -cmatch '^[0-9a-f]{64}$' -and
                (Test-I07StrictInteger `
                    -Value $Node.candidate.launch_binding.preferences_bytes `
                    -Minimum 1) -and
                [string]$Node.candidate.launch_binding.candidate_sha256 -ceq
                    $CandidateSha256 -and
                [string]$Node.system_state.schema -ceq
                    'ese.v91.i07-system-mutation-postcheck/v1' -and
                (Test-I07StrictBoolean -Value $Node.system_state.collector_ok) `
                    -and
                (Test-I07StrictBoolean -Value $Node.system_state.complete) -and
                [string]$Node.process_cleanup.schema -ceq
                    'ese.v91.i07-process-cleanup/v1' -and
                [int]$Node.process_cleanup.descendant_count -ge 0 -and
                $candidateFileBinding -and $zipBindingShape -and
                -not [string]::IsNullOrWhiteSpace($nodePackageCanonical) -and
                $nodePackageCanonical -ceq $nodeZipCanonical -and
                ([string]::IsNullOrWhiteSpace($CandidateCommit) -or
                    [string]$Node.candidate.commit -ceq $CandidateCommit) -and
                ([string]::IsNullOrWhiteSpace($BuildInfoSha256) -or
                    [string]$Node.candidate.build_info_sha256 -ceq
                        $BuildInfoSha256) -and
                ([string]::IsNullOrWhiteSpace($ZipSha256) -or (
                    [string]$Node.candidate.zip_sha256 -ceq $ZipSha256 -and
                    (Test-I07StrictInteger -Value $Node.candidate.zip_bytes `
                        -Minimum 1) -and
                    [Int64]$Node.candidate.zip_bytes -eq $ZipBytes)) -and
                (Test-I07StrictBoolean -Value $Node.candidate.zip_verified) -and
                [bool]$Node.candidate.zip_verified -and
                [string]$Node.candidate.zip_binding.schema -ceq
                    'ese.v91.i07-node-zip-binding/v2' -and
                (Test-I07StrictBoolean `
                    -Value $Node.candidate.zip_binding.verified) -and
                [bool]$Node.candidate.zip_binding.verified -and
                (Test-I07StrictInteger `
                    -Value $Node.candidate.zip_binding.critical_file_count `
                    -Minimum 7 -Maximum 100000) -and
                [Int64]$Node.candidate.zip_binding.critical_file_count -eq
                    @($Node.candidate.package_files).Count -and
                [string]$Node.candidate.zip_binding.zip_sha256 -ceq
                    [string]$Node.candidate.zip_sha256 -and
                (Test-I07StrictInteger `
                    -Value $Node.candidate.zip_binding.zip_bytes `
                    -Minimum 1) -and
                [Int64]$Node.candidate.zip_binding.zip_bytes -eq
                    [Int64]$Node.candidate.zip_bytes -and
                ([string]::IsNullOrWhiteSpace($expectedPackageCanonical) -or
                    $nodePackageCanonical -ceq $expectedPackageCanonical) -and
                (Test-I07RouteEnvelope -Node $Node `
                    -Route $Node.topology.initial_route -Sample initial) -and
                (Test-I07ControlEnvelope -Node $Node) -and
                $statusEvidence -and
                (Test-I07ViewerProfileEnvelope -Node $Node)
            )
        } catch { return $false }
    }

    $sourceEnvelope = Test-I07NodeEnvelope -Node $Source `
        -ExpectedRole source
    $viewerEnvelope = Test-I07NodeEnvelope -Node $Viewer `
        -ExpectedRole viewer
    $sourceProductFail = $sourceEnvelope -and
        [string]$Source.status -ceq 'FAIL' -and
        [string]$Source.failure.category -ceq 'PRODUCT_INVARIANT'
    $viewerProductFail = $viewerEnvelope -and
        [string]$Viewer.status -ceq 'FAIL' -and
        [string]$Viewer.failure.category -ceq 'PRODUCT_INVARIANT'
    if ($sourceProductFail -or $viewerProductFail) {
        return 'FAIL'
    }
    if ($null -eq $Source -or $null -eq $Viewer) { return 'BLOCKED' }
    $script:i07AggregateDebug = [ordered]@{
        source_envelope = $sourceEnvelope
        viewer_envelope = $viewerEnvelope
        source_final_route = Test-I07RouteEnvelope -Node $Source `
            -Route $Source.topology.final_route -Sample final
        viewer_final_route = Test-I07RouteEnvelope -Node $Viewer `
            -Route $Viewer.topology.final_route -Sample final
        pair = Test-I07PairEnvelope -SourceNode $Source -ViewerNode $Viewer
        source_socket = Test-I07SocketEnvelope -Node $Source
        viewer_socket = Test-I07SocketEnvelope -Node $Viewer
        viewer_api_peer = Test-I07ViewerApiPeerEnvelope -Node $Viewer
        viewer_hls = Test-I07HlsEnvelope -Node $Viewer
        source_timeline = Test-I07TimelineEnvelope -Node $Source -RequireFinal
        viewer_timeline = Test-I07TimelineEnvelope -Node $Viewer -RequireFinal
        source_api_pre = Test-I07ApiStatusSummary `
            -Summary $Source.product.api_status_initial
        viewer_api_pre = Test-I07ApiStatusSummary `
            -Summary $Viewer.product.api_status_initial
        source_evidence = Test-I07NodeEvidenceEnvelope -Node $Source
        viewer_evidence = Test-I07NodeEvidenceEnvelope -Node $Viewer
    }
    $passBooleanValues = @(
        $Viewer.product.direct_join.success,
        $Viewer.product.direct_join.dialed,
        $Source.product.broadcast.success,
        $Source.product.broadcast.ready,
        $Source.cleanup.process_stopped,
        $Source.cleanup.firewall_removed,
        $Source.cleanup.control_closed,
        $Source.cleanup.broadcast_stopped,
        $Source.cleanup.ffmpeg_children_gone,
        $Source.cleanup.hls_removed,
        $Source.cleanup.node_removed,
        $Viewer.cleanup.process_stopped,
        $Viewer.cleanup.firewall_removed,
        $Viewer.cleanup.control_closed,
        $Viewer.cleanup.broadcast_stopped,
        $Viewer.cleanup.ffmpeg_children_gone,
        $Viewer.cleanup.hls_removed,
        $Viewer.cleanup.node_removed)
    $strictPassBooleans = @($passBooleanValues | Where-Object {
            -not (Test-I07StrictBoolean -Value $_) -or -not [bool]$_
        }).Count -eq 0
    $pass = (
        $sourceEnvelope -and $viewerEnvelope -and
        $strictPassBooleans -and
        [string]$Source.status -ceq 'PASS' -and
        [string]$Viewer.status -ceq 'PASS' -and
        [string]$Source.phase -ceq 'route_revalidation' -and
        [string]$Viewer.phase -ceq 'route_revalidation' -and
        (Test-I07RouteEnvelope -Node $Source `
            -Route $Source.topology.final_route -Sample final) -and
        (Test-I07RouteEnvelope -Node $Viewer `
            -Route $Viewer.topology.final_route -Sample final) -and
        (Test-I07PairEnvelope -SourceNode $Source `
            -ViewerNode $Viewer) -and
        (Test-I07SocketEnvelope -Node $Source) -and
        (Test-I07SocketEnvelope -Node $Viewer) -and
        (Test-I07DirectJoinEnvelope -Node $Viewer) -and
        (Test-I07ViewerApiPeerEnvelope -Node $Viewer) -and
        (Test-I07HlsEnvelope -Node $Viewer) -and
        (Test-I07TimelineEnvelope -Node $Source -RequireFinal) -and
        (Test-I07TimelineEnvelope -Node $Viewer -RequireFinal) -and
        $null -ne (Get-I07SessionSamplesEvidence -Node $Source `
            -RequirePass) -and
        $null -ne (Get-I07SessionSamplesEvidence -Node $Viewer `
            -RequirePass) -and
        (Test-I07BroadcastEnvelope -Node $Source) -and
        (Test-I07NodeEvidenceEnvelope -Node $Source) -and
        (Test-I07NodeEvidenceEnvelope -Node $Viewer) -and
        (Test-I07WebContainmentEnvelope -Node $Source) -and
        (Test-I07WebContainmentEnvelope -Node $Viewer) -and
        [bool]$Source.cleanup.process_stopped -and
        [bool]$Source.cleanup.firewall_removed -and
        [bool]$Source.cleanup.control_closed -and
        [bool]$Source.cleanup.broadcast_stopped -and
        [bool]$Source.cleanup.ffmpeg_children_gone -and
        [bool]$Source.cleanup.hls_removed -and
        [bool]$Source.cleanup.node_removed -and
        [bool]$Viewer.cleanup.process_stopped -and
        [bool]$Viewer.cleanup.firewall_removed -and
        [bool]$Viewer.cleanup.control_closed -and
        [bool]$Viewer.cleanup.broadcast_stopped -and
        [bool]$Viewer.cleanup.ffmpeg_children_gone -and
        [bool]$Viewer.cleanup.hls_removed -and
        [bool]$Viewer.cleanup.node_removed
    )
    if ($pass) { return 'PASS' }
    return 'BLOCKED'
}

function ConvertFrom-I07Utf8JsonBytes {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    if ($Bytes.Length -lt 1) { throw 'JSON snapshot is empty.' }
    $offset = 0
    if ($Bytes.Length -ge 3 -and $Bytes[0] -eq 0xEF -and
        $Bytes[1] -eq 0xBB -and $Bytes[2] -eq 0xBF) {
        $offset = 3
    } elseif ($Bytes.Length -ge 2 -and (
            ($Bytes[0] -eq 0xFF -and $Bytes[1] -eq 0xFE) -or
            ($Bytes[0] -eq 0xFE -and $Bytes[1] -eq 0xFF))) {
        throw 'Only UTF-8 JSON snapshots are accepted.'
    }
    if ($Bytes.Length -le $offset) { throw 'JSON snapshot is empty.' }
    $strictUtf8 = [Text.UTF8Encoding]::new($false, $true)
    $text = $strictUtf8.GetString($Bytes, $offset, $Bytes.Length - $offset)
    if ($text.Length -gt 0 -and $text[0] -eq [char]0xFEFF) {
        throw 'JSON snapshot contains an embedded byte-order mark.'
    }
    return $text | ConvertFrom-Json
}

function Read-I07JsonByteSnapshot {
    param([Parameter(Mandatory = $true)][string]$Path)
    $full = [IO.Path]::GetFullPath($Path)
    $bytes = [IO.File]::ReadAllBytes($full)
    if ($bytes.Length -lt 1) { throw 'JSON snapshot is empty.' }
    $value = ConvertFrom-I07Utf8JsonBytes -Bytes $bytes
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $digest = ([BitConverter]::ToString(
            $sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    } finally { $sha.Dispose() }
    return [pscustomobject][ordered]@{
        bytes_value = $bytes; byte_count = [Int64]$bytes.Length
        sha256 = $digest; value = $value
    }
}

function Write-I07HeldSnapshot {
    param(
        [Parameter(Mandatory = $true)]$Snapshot,
        [Parameter(Mandatory = $true)][string]$Path
    )
    $full = [IO.Path]::GetFullPath($Path)
    $temporary = $full + '.new-' + [Guid]::NewGuid().ToString('N')
    try {
        [IO.File]::WriteAllBytes($temporary, [byte[]]$Snapshot.bytes_value)
        $item = Get-Item -LiteralPath $temporary
        if ([Int64]$item.Length -ne [Int64]$Snapshot.byte_count -or
            (Get-LabSha256 -Path $temporary) -cne [string]$Snapshot.sha256) {
            throw 'Held JSON snapshot copy does not match its exact bytes.'
        }
        Move-Item -LiteralPath $temporary -Destination $full -Force
    } finally {
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
    }
}

function Test-I07HeldSnapshotCopy {
    param(
        [Parameter(Mandatory = $true)]$Snapshot,
        [Parameter(Mandatory = $true)][string]$Path
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
    $item = Get-Item -LiteralPath $Path
    return ([Int64]$item.Length -eq [Int64]$Snapshot.byte_count -and
        (Get-LabSha256 -Path $Path) -ceq [string]$Snapshot.sha256)
}

function Test-I07R01AggregateContract {
    param(
        [Parameter(Mandatory = $true)]$Aggregate,
        [Parameter(Mandatory = $true)][string]$ExpectedVersion,
        [Parameter(Mandatory = $true)][string]$ExpectedCommit,
        [Parameter(Mandatory = $true)][string]$ExpectedEmuleSha256,
        [Parameter(Mandatory = $true)][string]$ExpectedBuildInfoSha256,
        [Parameter(Mandatory = $true)][string]$ExpectedZipSha256,
        [Parameter(Mandatory = $true)][Int64]$ExpectedZipBytes
    )

    try {
        $homeWlan = ([string]$Aggregate.
            requested_home_wlan_profile_sha256).ToLowerInvariant()
        $hotspotWlan = ([string]$Aggregate.
            requested_hotspot_wlan_profile_sha256).ToLowerInvariant()
        $homeConnection = ([string]$Aggregate.topology.
            home_connection_profile_sha256).ToLowerInvariant()
        $hotspotConnection = ([string]$Aggregate.topology.
            hotspot_connection_profile_sha256).ToLowerInvariant()
        $mobileWlan = [string]$Aggregate.remote.topology.mobile.
            wlan_profile_sha256
        $initialWlan = [string]$Aggregate.remote.topology.initial.
            wlan_profile_sha256
        $mobileConnection = [string]$Aggregate.remote.topology.mobile.
            connection_profile.name_sha256
        $initialConnection = [string]$Aggregate.remote.topology.initial.
            connection_profile.name_sha256
        $initialGuid = [Guid]::Empty
        $mobileGuid = [Guid]::Empty
        $initialGuidValid = [Guid]::TryParse(
            [string]$Aggregate.remote.topology.initial.interface_guid,
            [ref]$initialGuid) -and $initialGuid -ne [Guid]::Empty
        $mobileGuidValid = [Guid]::TryParse(
            [string]$Aggregate.remote.topology.mobile.interface_guid,
            [ref]$mobileGuid) -and $mobileGuid -ne [Guid]::Empty
        $remoteBinding = $Aggregate.remote.candidate.remote_package_binding
        return (
            [string]$Aggregate.schema -ceq 'ese.v91.r01-campaign/v1' -and
            [string]$Aggregate.case_id -ceq 'V91-R01' -and
            [string]$Aggregate.status -ceq 'PASS' -and
            [string]$Aggregate.topology.id -ceq 'T3' -and
            [string]$Aggregate.remote.case_id -ceq 'V91-R01' -and
            [string]$Aggregate.remote.topology.id -ceq 'T3' -and
            [string]$Aggregate.remote.status -ceq 'REMOTE_PASS' -and
            [string]$Aggregate.candidate.version -ceq $ExpectedVersion -and
            [string]$Aggregate.candidate.commit -ceq $ExpectedCommit -and
            [string]$Aggregate.candidate.dirty -ceq 'false' -and
            [string]$Aggregate.candidate.emule_sha256 -ceq
                $ExpectedEmuleSha256 -and
            [string]$Aggregate.candidate.build_info_sha256 -ceq
                $ExpectedBuildInfoSha256 -and
            [string]$Aggregate.candidate.zip_sha256 -ceq
                $ExpectedZipSha256 -and
            (Test-I07StrictInteger -Value $Aggregate.candidate.zip_bytes `
                -Minimum 1) -and
            [Int64]$Aggregate.candidate.zip_bytes -eq $ExpectedZipBytes -and
            [string]$Aggregate.remote.candidate.version -ceq
                $ExpectedVersion -and
            [string]$Aggregate.remote.candidate.commit -ceq
                $ExpectedCommit -and
            (Test-I07StrictBoolean -Value $Aggregate.remote.candidate.dirty) -and
            -not [bool]$Aggregate.remote.candidate.dirty -and
            [string]$Aggregate.remote.candidate.emule_sha256 -ceq
                $ExpectedEmuleSha256 -and
            [string]$Aggregate.remote.candidate.build_info_sha256 -ceq
                $ExpectedBuildInfoSha256 -and
            [string]$Aggregate.remote.candidate.zip_sha256 -ceq
                $ExpectedZipSha256 -and
            (Test-I07StrictInteger `
                -Value $Aggregate.remote.candidate.zip_bytes -Minimum 1) -and
            [Int64]$Aggregate.remote.candidate.zip_bytes -eq
                $ExpectedZipBytes -and
            [string]$remoteBinding.schema -ceq
                'ese.v91.r01-remote-package-binding/v1' -and
            [string]$remoteBinding.remote_zip_sha256 -ceq
                $ExpectedZipSha256 -and
            (Test-I07StrictInteger -Value $remoteBinding.remote_zip_bytes `
                -Minimum 1) -and
            [Int64]$remoteBinding.remote_zip_bytes -eq $ExpectedZipBytes -and
            (Test-I07StrictBoolean `
                -Value $remoteBinding.extracted_file_set_exact) -and
            [bool]$remoteBinding.extracted_file_set_exact -and
            (Test-I07StrictBoolean `
                -Value $remoteBinding.extracted_bytes_and_sha256_exact) -and
            [bool]$remoteBinding.extracted_bytes_and_sha256_exact -and
            $homeWlan -cmatch '^[0-9a-f]{64}$' -and
            $hotspotWlan -cmatch '^[0-9a-f]{64}$' -and
            $homeConnection -cmatch '^[0-9a-f]{64}$' -and
            $hotspotConnection -cmatch '^[0-9a-f]{64}$' -and
            $homeWlan -cne $hotspotWlan -and
            $homeConnection -cne $hotspotConnection -and
            [string]$Aggregate.topology.home_profile_sha256 -ceq
                $homeConnection -and
            [string]$Aggregate.topology.hotspot_profile_sha256 -ceq
                $hotspotConnection -and
            $initialGuidValid -and $mobileGuidValid -and
            $initialGuid -eq $mobileGuid -and
            $mobileWlan -ceq $hotspotWlan -and
            $initialWlan -ceq $homeWlan -and
            $mobileConnection -ceq $hotspotConnection -and
            $initialConnection -ceq $homeConnection -and
            (Test-I07StrictBoolean -Value $Aggregate.cleanup.complete) -and
            [bool]$Aggregate.cleanup.complete -and
            (Test-I07StrictBoolean `
                -Value $Aggregate.remote.cleanup.home_restored) -and
            [bool]$Aggregate.remote.cleanup.home_restored -and
            (Test-I07StrictBoolean `
                -Value $Aggregate.remote.cleanup.node_removed) -and
            [bool]$Aggregate.remote.cleanup.node_removed -and
            (Test-I07StrictBoolean `
                -Value $Aggregate.remote.cleanup.wifi_watchdog_safe) -and
            [bool]$Aggregate.remote.cleanup.wifi_watchdog_safe)
    } catch { return $false }
}

function Test-I07R01PrerequisiteContract {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)]$SourceSnapshot
    )
    try {
        if (-not (Test-I07ExactPropertySet -Value $Value -Expected @(
                'schema', 'case_id', 'status', 'topology_id',
                'source_aggregate_sha256', 'source_aggregate_bytes',
                'candidate', 'remote_candidate', 'profile_fingerprints',
                'interface_guid', 'cleanup')) -or
            [string]$Value.schema -cne
                'ese.v91.i07-r01-prerequisite/v1' -or
            [string]$Value.case_id -cne 'V91-R01' -or
            [string]$Value.status -cne 'PASS' -or
            [string]$Value.topology_id -cne 'T3' -or
            -not (Test-I07Sha256RetentionString `
                -Value $Value.source_aggregate_sha256) -or
            [string]$Value.source_aggregate_sha256 -cne
                [string]$SourceSnapshot.sha256 -or
            -not (Test-I07StrictInteger `
                -Value $Value.source_aggregate_bytes -Minimum 1) -or
            [Int64]$Value.source_aggregate_bytes -ne
                [Int64]$SourceSnapshot.byte_count -or
            -not (Test-I07ExactPropertySet -Value $Value.candidate `
                -Expected @('version', 'commit', 'dirty', 'emule_sha256',
                    'build_info_sha256', 'zip_sha256', 'zip_bytes')) -or
            -not (Test-I07ExactPropertySet -Value $Value.remote_candidate `
                -Expected @('version', 'commit', 'dirty', 'emule_sha256',
                    'build_info_sha256', 'zip_sha256', 'zip_bytes',
                    'package_binding')) -or
            -not (Test-I07ExactPropertySet `
                -Value $Value.remote_candidate.package_binding -Expected @(
                    'schema', 'remote_zip_sha256', 'remote_zip_bytes',
                    'extracted_file_set_exact',
                    'extracted_bytes_and_sha256_exact')) -or
            -not (Test-I07ExactPropertySet `
                -Value $Value.profile_fingerprints -Expected @(
                    'home_wlan_sha256', 'hotspot_wlan_sha256',
                    'home_connection_sha256',
                    'hotspot_connection_sha256')) -or
            -not (Test-I07ExactPropertySet -Value $Value.cleanup -Expected @(
                'aggregate_complete', 'remote_home_restored',
                'remote_node_removed', 'remote_wifi_watchdog_safe'))) {
            return $false
        }
        foreach ($candidate in @($Value.candidate,
                $Value.remote_candidate)) {
            if ([string]$candidate.version -cnotmatch
                    '^[A-Za-z0-9._+-]{1,64}$' -or
                [string]$candidate.commit -cnotmatch '^[0-9a-f]{40}$' -or
                -not (Test-I07Sha256RetentionString `
                    -Value $candidate.emule_sha256) -or
                -not (Test-I07Sha256RetentionString `
                    -Value $candidate.build_info_sha256) -or
                -not (Test-I07Sha256RetentionString `
                    -Value $candidate.zip_sha256) -or
                -not (Test-I07StrictInteger -Value $candidate.zip_bytes `
                    -Minimum 1)) { return $false }
        }
        if ([string]$Value.candidate.dirty -cne 'false' -or
            -not (Test-I07StrictBoolean `
                -Value $Value.remote_candidate.dirty) -or
            [bool]$Value.remote_candidate.dirty -or
            [string]$Value.candidate.version -cne
                [string]$Value.remote_candidate.version -or
            [string]$Value.candidate.commit -cne
                [string]$Value.remote_candidate.commit -or
            [string]$Value.candidate.emule_sha256 -cne
                [string]$Value.remote_candidate.emule_sha256 -or
            [string]$Value.candidate.build_info_sha256 -cne
                [string]$Value.remote_candidate.build_info_sha256 -or
            [string]$Value.candidate.zip_sha256 -cne
                [string]$Value.remote_candidate.zip_sha256 -or
            [Int64]$Value.candidate.zip_bytes -ne
                [Int64]$Value.remote_candidate.zip_bytes) { return $false }
        $binding = $Value.remote_candidate.package_binding
        if ([string]$binding.schema -cne
                'ese.v91.r01-remote-package-binding/v1' -or
            [string]$binding.remote_zip_sha256 -cne
                [string]$Value.candidate.zip_sha256 -or
            -not (Test-I07StrictInteger -Value $binding.remote_zip_bytes `
                -Minimum 1) -or
            [Int64]$binding.remote_zip_bytes -ne
                [Int64]$Value.candidate.zip_bytes -or
            -not (Test-I07StrictBoolean `
                -Value $binding.extracted_file_set_exact) -or
            -not [bool]$binding.extracted_file_set_exact -or
            -not (Test-I07StrictBoolean `
                -Value $binding.extracted_bytes_and_sha256_exact) -or
            -not [bool]$binding.extracted_bytes_and_sha256_exact) {
            return $false
        }
        foreach ($property in $Value.profile_fingerprints.PSObject.Properties) {
            if (-not (Test-I07Sha256RetentionString `
                    -Value $property.Value)) { return $false }
        }
        if ([string]$Value.profile_fingerprints.home_wlan_sha256 -ceq
                [string]$Value.profile_fingerprints.hotspot_wlan_sha256 -or
            [string]$Value.profile_fingerprints.home_connection_sha256 -ceq
                [string]$Value.profile_fingerprints.
                    hotspot_connection_sha256 -or
            -not (Test-I07GuidRetentionString -Value $Value.interface_guid)) {
            return $false
        }
        foreach ($property in $Value.cleanup.PSObject.Properties) {
            if (-not (Test-I07StrictBoolean -Value $property.Value) -or
                -not [bool]$property.Value) { return $false }
        }
        return ((Test-I07NoRawDiagnosticProperties -Value $Value) -and
            (Test-I07SafeRetentionScalarTree -Value $Value))
    } catch { return $false }
}

function New-I07R01PrerequisiteValue {
    param(
        [Parameter(Mandatory = $true)]$Aggregate,
        [Parameter(Mandatory = $true)]$CandidateIdentity,
        [Parameter(Mandatory = $true)][string]$SourceDigest,
        [Parameter(Mandatory = $true)][Int64]$SourceBytes
    )
    if (-not (Test-I07R01AggregateContract -Aggregate $Aggregate `
            -ExpectedVersion ([string]$CandidateIdentity.version) `
            -ExpectedCommit ([string]$CandidateIdentity.commit) `
            -ExpectedEmuleSha256 ([string]$CandidateIdentity.emule_sha256) `
            -ExpectedBuildInfoSha256 `
                ([string]$CandidateIdentity.build_info_sha256) `
            -ExpectedZipSha256 ([string]$CandidateIdentity.zip_sha256) `
            -ExpectedZipBytes ([Int64]$CandidateIdentity.zip_bytes))) {
        throw 'R01 source aggregate is not an authenticated PASS dependency.'
    }
    $binding = $Aggregate.remote.candidate.remote_package_binding
    $guid = ConvertTo-I07RetentionGuid -Value (
        [string]$Aggregate.remote.topology.mobile.interface_guid)
    $value = [pscustomobject][ordered]@{
        schema = 'ese.v91.i07-r01-prerequisite/v1'
        case_id = 'V91-R01'; status = 'PASS'; topology_id = 'T3'
        source_aggregate_sha256 = $SourceDigest
        source_aggregate_bytes = $SourceBytes
        candidate = [pscustomobject][ordered]@{
            version = [string]$Aggregate.candidate.version
            commit = [string]$Aggregate.candidate.commit
            dirty = [string]$Aggregate.candidate.dirty
            emule_sha256 = [string]$Aggregate.candidate.emule_sha256
            build_info_sha256 =
                [string]$Aggregate.candidate.build_info_sha256
            zip_sha256 = [string]$Aggregate.candidate.zip_sha256
            zip_bytes = [Int64]$Aggregate.candidate.zip_bytes
        }
        remote_candidate = [pscustomobject][ordered]@{
            version = [string]$Aggregate.remote.candidate.version
            commit = [string]$Aggregate.remote.candidate.commit
            dirty = $Aggregate.remote.candidate.dirty
            emule_sha256 =
                [string]$Aggregate.remote.candidate.emule_sha256
            build_info_sha256 =
                [string]$Aggregate.remote.candidate.build_info_sha256
            zip_sha256 = [string]$Aggregate.remote.candidate.zip_sha256
            zip_bytes = [Int64]$Aggregate.remote.candidate.zip_bytes
            package_binding = [pscustomobject][ordered]@{
                schema = [string]$binding.schema
                remote_zip_sha256 = [string]$binding.remote_zip_sha256
                remote_zip_bytes = [Int64]$binding.remote_zip_bytes
                extracted_file_set_exact =
                    $binding.extracted_file_set_exact
                extracted_bytes_and_sha256_exact =
                    $binding.extracted_bytes_and_sha256_exact
            }
        }
        profile_fingerprints = [pscustomobject][ordered]@{
            home_wlan_sha256 =
                [string]$Aggregate.requested_home_wlan_profile_sha256
            hotspot_wlan_sha256 =
                [string]$Aggregate.requested_hotspot_wlan_profile_sha256
            home_connection_sha256 =
                [string]$Aggregate.topology.home_connection_profile_sha256
            hotspot_connection_sha256 =
                [string]$Aggregate.topology.
                    hotspot_connection_profile_sha256
        }
        interface_guid = $guid
        cleanup = [pscustomobject][ordered]@{
            aggregate_complete = $Aggregate.cleanup.complete
            remote_home_restored = $Aggregate.remote.cleanup.home_restored
            remote_node_removed = $Aggregate.remote.cleanup.node_removed
            remote_wifi_watchdog_safe =
                $Aggregate.remote.cleanup.wifi_watchdog_safe
        }
    }
    return $value
}

function Test-I07R01PrerequisiteProvenanceContract {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)]$SourceSnapshot,
        [Parameter(Mandatory = $true)]$CandidateIdentity
    )
    try {
        $bytes = [byte[]]$SourceSnapshot.bytes_value
        if ($bytes.Length -lt 1 -or $bytes.Length -ne
                [Int64]$SourceSnapshot.byte_count) { return $false }
        $hasher = [Security.Cryptography.SHA256]::Create()
        try {
            $digest = ([BitConverter]::ToString(
                $hasher.ComputeHash($bytes))).Replace('-', '').
                    ToLowerInvariant()
        } finally { $hasher.Dispose() }
        if ($digest -cne [string]$SourceSnapshot.sha256) { return $false }
        $aggregate = ConvertFrom-I07Utf8JsonBytes -Bytes $bytes
        if (($aggregate | ConvertTo-Json -Depth 24 -Compress) -cne
            ($SourceSnapshot.value | ConvertTo-Json -Depth 24 -Compress)) {
            return $false
        }
        if (-not (Test-I07R01AggregateContract -Aggregate $aggregate `
                -ExpectedVersion ([string]$CandidateIdentity.version) `
                -ExpectedCommit ([string]$CandidateIdentity.commit) `
                -ExpectedEmuleSha256 `
                    ([string]$CandidateIdentity.emule_sha256) `
                -ExpectedBuildInfoSha256 `
                    ([string]$CandidateIdentity.build_info_sha256) `
                -ExpectedZipSha256 `
                    ([string]$CandidateIdentity.zip_sha256) `
                -ExpectedZipBytes ([Int64]$CandidateIdentity.zip_bytes))) {
            return $false
        }
        $expected = New-I07R01PrerequisiteValue -Aggregate $aggregate `
            -CandidateIdentity $CandidateIdentity `
            -SourceDigest $digest -SourceBytes $bytes.Length
        return ((Test-I07R01PrerequisiteContract -Value $Value `
                -SourceSnapshot $SourceSnapshot) -and
            (($Value | ConvertTo-Json -Depth 24 -Compress) -ceq
             ($expected | ConvertTo-Json -Depth 24 -Compress)))
    } catch { return $false }
}

function New-I07R01PrerequisiteSnapshot {
    param(
        [Parameter(Mandatory = $true)]$Aggregate,
        [Parameter(Mandatory = $true)]$SourceSnapshot,
        [Parameter(Mandatory = $true)]$CandidateIdentity
    )
    $bytes = [byte[]]$SourceSnapshot.bytes_value
    $parsed = ConvertFrom-I07Utf8JsonBytes -Bytes $bytes
    if (($Aggregate | ConvertTo-Json -Depth 24 -Compress) -cne
        ($parsed | ConvertTo-Json -Depth 24 -Compress)) {
        throw 'R01 aggregate is not derived from source bytes.'
    }
    $hasher = [Security.Cryptography.SHA256]::Create()
    try {
        $digest = ([BitConverter]::ToString(
            $hasher.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    } finally { $hasher.Dispose() }
    $value = New-I07R01PrerequisiteValue -Aggregate $parsed `
        -CandidateIdentity $CandidateIdentity `
        -SourceDigest $digest -SourceBytes $bytes.Length
    if (-not (Test-I07R01PrerequisiteProvenanceContract -Value $value `
            -SourceSnapshot $SourceSnapshot `
            -CandidateIdentity $CandidateIdentity)) {
        throw 'Sanitized R01 prerequisite violated source provenance.'
    }
    $snapshot = New-I07CanonicalJsonSnapshot -Value $value
    $reloaded = ConvertFrom-I07Utf8JsonBytes `
        -Bytes ([byte[]]$snapshot.bytes_value)
    if (-not (Test-I07R01PrerequisiteProvenanceContract -Value $reloaded `
            -SourceSnapshot $SourceSnapshot `
            -CandidateIdentity $CandidateIdentity)) {
        throw 'Serialized R01 prerequisite failed provenance reload.'
    }
    return [pscustomobject][ordered]@{
        bytes_value = $snapshot.bytes_value
        byte_count = [Int64]$snapshot.byte_count
        sha256 = [string]$snapshot.sha256
        value = $reloaded
    }
}

function Invoke-I07ControllerSelfTest {
    $nonce = '0123456789abcdef0123456789abcdef'
    $sha = 'a' * 64
    $wlanSha = 'b' * 64
    $connectionSha = 'c' * 64
    function New-I07SelfTestNode {
        param([string]$Role, [string]$Status = 'PASS')
        $isSource = $Role -ceq 'source'
        $local = if ($isSource) { '2a02:26f7:abcd::10' } else {
            '2a02:26f7:abcd::20'
        }
        $peer = if ($isSource) { '2a02:26f7:abcd::20' } else {
            '2a02:26f7:abcd::10'
        }
        $guid = if ($isSource) {
            '11111111-1111-1111-1111-111111111111'
        } else { '22222222-2222-2222-2222-222222222222' }
        $ifIndex = if ($isSource) { 11 } else { 22 }
        $tcp = if ($isSource) { 48067 } else { 48267 }
        $udp = if ($isSource) { 48077 } else { 48277 }
        $web = if ($isSource) { 48117 } else { 48317 }
        $peerTcp = if ($isSource) { 48267 } else { 48067 }
        $candidatePid = if ($isSource) { 101 } else { 202 }
        $candidateCommit = '1' * 40
        $configExpected = [ordered]@{
            'eMule/Nick' = if ($isSource) { 'eSE-A' } else { 'eSE-B' }
            'eMule/Port' = [string]$tcp
            'eMule/UDPPort' = [string]$udp
            'eMule/NetworkKademlia' = '0'; 'eMule/NetworkED2K' = '0'
            'eMule/AutoConnect' = '0'; 'Connection/NetworkED2K' = '0'
            'eMule/OpenPortsOnStartUp' = '0'; 'eMule/AutoStart' = '0'
            'eMule/AutoTakeED2KLinks' = '0'
            'eMule/WatchClipboard4ED2kFilelinks' = '0'
            'Connection/KadNetworkMask' = '0'; 'Connection/IPv6Mode' = '2'
            'UPnP/EnableUPnP' = '0'; 'Proxy/ProxyEnableProxy' = '0'
            'Proxy/ProxyEnablePassword' = '0'; 'WebServer/Enabled' = '1'
            'WebServer/Port' = [string]$web
            'WebServer/WebUseUPnP' = '0'
            'WebServer/AllowedIPs' = '127.0.0.1'
            'eSE/EseNetLabEnabled' = '0'; 'eSE/EseNetLabConsent' = '0'
            'eSE/EseNetLabAdvancedConsent' = '0'
            'eSE/EseNetLabContributionConsent' = '0'
            'eSE/EseV9Experimental' = '0'; 'eSE/Kad6BetaExitOptIn' = '0'
            'eSE/Kad6PublicExitOptIn' = '0'
        }
        $configEntries = @($configExpected.Keys | ForEach-Object {
                $parts = $_.Split('/')
                [pscustomobject]@{
                    section = $parts[0]; key = $parts[1]
                    value = [string]$configExpected[$_]
                }
            })
        $provenAt = '2026-07-31T10:00:01.0000000+00:00'
        $startedAt = '2026-07-31T10:00:02.0000000+00:00'
        $route = [pscustomobject]@{
            captured_at_utc = '2026-07-31T10:00:00.0000000+00:00'
            valid = $true; source_address = $local; remote_address = $peer
            reason = 'native_global_route_selected'
            interface_alias = 'fixture'
            interface_description = 'fixture adapter'; media_type = '802.3'
            physical_media_type = '802.3'; destination_prefix = '::/0'
            next_hop = 'fe80::1'; route_metric = 1; interface_metric = 1
            prefix_origin = 'RouterAdvertisement'; suffix_origin = 'Link'
            source_class = 'global-native'; remote_class = 'global-native'
            interface_index = $ifIndex; interface_guid = $guid
            hardware_interface = $true; virtual = $false; overlay = $false
            default_route_present = $true; address_state = 'Preferred'
        }
        $finalRoute = [pscustomobject]@{
            captured_at_utc = '2026-07-31T10:00:19.0000000+00:00'
            valid = $true; source_address = $local; remote_address = $peer
            reason = 'native_global_route_selected'
            interface_alias = 'fixture'
            interface_description = 'fixture adapter'; media_type = '802.3'
            physical_media_type = '802.3'; destination_prefix = '::/0'
            next_hop = 'fe80::1'; route_metric = 1; interface_metric = 1
            prefix_origin = 'RouterAdvertisement'; suffix_origin = 'Link'
            source_class = 'global-native'; remote_class = 'global-native'
            interface_index = $ifIndex; interface_guid = $guid
            hardware_interface = $true; virtual = $false; overlay = $false
            default_route_present = $true; address_state = 'Preferred'
        }
        $apiFixture = [pscustomobject]@{
            ed2k_connected = $false; kad_connected = $false
            kad_configured_mask = 0; kad_running_mask = 0
            kad2_running = $false; kad2_connected = $false
            kad6_running = $false; kad6_connected = $false
            netlab_enabled = $false
        }
        $apiInitial = Get-I07ApiEvidenceSummary -Value $apiFixture `
            -CapturedAt ([DateTimeOffset]::Parse(
                '2026-07-31T10:00:02.5000000+00:00'))
        $apiFinal = Get-I07ApiEvidenceSummary -Value $apiFixture `
            -CapturedAt ([DateTimeOffset]::Parse(
                '2026-07-31T10:00:19.5000000+00:00'))
        $control = [pscustomobject]@{
            bidirectional = $true; proven_at_utc = $provenAt
            local_address = $local; remote_address = $peer
            local_port = if ($isSource) { 48907 } else { 55001 }
            remote_port = if ($isSource) { 55001 } else { 48907 }
        }
        $socketTuple = [pscustomobject]@{
            local_address = $local; remote_address = $peer
            local_port = if ($isSource) { $tcp } else { 55002 }
            remote_port = if ($isSource) { 55002 } else { $peerTcp }
            owning_process = $candidatePid; state = 'Established'
        }
        $packageFixture = @(
            'BUILD_INFO.txt', 'emule.exe', 'eMule.tmpl', 'ese-server.exe',
            'ffmpeg.exe', 'ffprobe.exe', 'SHA256SUMS.txt' |
                ForEach-Object {
                    [pscustomobject]@{
                        path = $_
                        bytes = if ($_ -ceq 'emule.exe') { 12345 } else { 1 }
                        sha256 = if ($_ -ceq 'emule.exe') { $sha } else {
                            '5' * 64
                        }
                    }
                })
        return [pscustomobject]@{
          schema = 'ese.v91.i07-node-result/v1'
          case_id = 'V91-I07'
          status = $Status; role = $Role; nonce = $nonce
          completed_at_utc = '2026-07-31T10:00:20.0000000+00:00'
          phase = if ($Status -ceq 'PASS') { 'route_revalidation' } else {
              'source_candidate_start'
          }
          candidate = [pscustomobject]@{
              requested_sha256 = $sha
              verified = $true; sha256 = $sha; bytes = 12345
              zip_verified = $true
              pid = $candidatePid; started_at_utc = $startedAt
              commit = $candidateCommit
              build_info_sha256 = 'd' * 64
              zip_sha256 = '4' * 64; zip_bytes = 123
              zip_binding = [pscustomobject]@{
                  schema = 'ese.v91.i07-node-zip-binding/v2'
                  verified = $true; critical_file_count = 7
                  zip_sha256 = '4' * 64; zip_bytes = 123
                  critical_files = $packageFixture
              }
              package_files = $packageFixture
              process_identity = [pscustomobject]@{
                  schema = 'ese.v91.i07-process-identity/v1'
                  process_id = $candidatePid; start_time_utc = $startedAt
                  executable_path_sha256 = '2' * 64
                  executable_sha256 = $sha; user_sid_sha256 = '3' * 64
              }
              launch_binding = [pscustomobject]@{
                  schema = 'ese.v91.i07-prelaunch-binding/v1'
                  verified = $true; static_file_count = 7
                  static_manifest_sha256 =
                      Get-I07PackageManifestSha256 -Files $packageFixture
                  preferences_sha256 = '5' * 64; preferences_bytes = 100
                  candidate_sha256 = $sha
              }
          }
          topology = [pscustomobject]@{
              native_path_proven_before_candidate = $true
              topology_id = 'T3'; local_ipv6 = $local; peer_ipv6 = $peer
              interface_index = $ifIndex; interface_guid = $guid
              ports = [pscustomobject]@{
                  tcp = $tcp; udp = $udp; web = $web; peer_tcp = $peerTcp
                  control = 48907
              }
              initial_route = $route; final_route = $finalRoute
              control = $control
              web_api_containment = [pscustomobject]@{
                  rule_name = "eSE-V91-I07-web-block-$nonce-$Role"
                  direction = 'Inbound'; action = 'Block'; enabled = 'True'
                  profile = 'Any'; protocol = 'TCP'; local_port = $web
                  local_address = 'Any'; remote_address = 'Any'
                  program_leaf = 'emule.exe'
                  program_matches_candidate = $true
                  blocks_physical_ipv4_and_ipv6 = $true
              }
              r01_hotspot_profile = if ($isSource) { $null } else {
                  [pscustomobject]@{
                      revalidated_immediately_before_candidate = $true
                      revalidated_at_utc =
                          '2026-07-31T10:00:01.5000000+00:00'
                      connection_profile = [pscustomobject]@{
                          schema =
                              'ese.v91.r01-hotspot-profile-fingerprint/v1'
                          interface_index = $ifIndex
                          profile_sha256 = $connectionSha
                          interface_guid = $guid
                          network_category = 'Public'
                          ipv4_connectivity = 'Internet'
                          ipv6_connectivity = 'Internet'
                      }
                      wlan_profile = [pscustomobject]@{
                          schema = 'ese.v91.i07-current-wlan-profile/v1'
                          interface_index = $ifIndex
                          wlan_profile_sha256 = $wlanSha
                          interface_guid = $guid
                      }
                  }
              }
          }
          product = [pscustomobject]@{
              socket = [pscustomobject]@{
                  observed = $true; count = 1; tuples = @($socketTuple)
                  local_address = $local; interface_index = $ifIndex
                  interface_guid = $guid; hardware_interface = $true
                  virtual = $false; overlay = $false
                  interface_matches_route = $true
              }
              direct_join = if ($isSource) { $null } else { [pscustomobject]@{
                  success = $true; dialed = $true; joined = $true
              }}
              api_peer = if ($isSource) { $null } else { [pscustomobject]@{
                  schema = 'ese.v91.i07-controlled-api-peer/v1'
                  matched = $true
                  controlled_peer = [pscustomobject]@{
                      address = $peer; port = $peerTcp
                      isFork = $true; dataplaneCap = $true
                  }
              }}
              hls = if ($isSource) { $null } else { [pscustomobject]@{
                  playlist_seen = $true; segment_seen = $true
                  segment_path_contained = $true
                  playlist_name = 'stream.m3u8'; stream_key_sha256 = '9' * 64
                  segment_bytes = 1024
                  minimum_write_utc =
                      '2026-07-31T10:00:02.0000000+00:00'
                  playlist_last_write_utc = '2026-07-31T10:00:18.0000000+00:00'
                  segment_last_write_utc = '2026-07-31T10:00:18.0000000+00:00'
              }}
              broadcast = if ($isSource) { [pscustomobject]@{
                  success = $true; ready = $true; stream_key_sha256 = '9' * 64
              } } else { $null }
              api_status_initial = $apiInitial
              api_status_final = $apiFinal
              samples = @(1..16 |
                  ForEach-Object {
                      $sampleAt = ([DateTimeOffset]::Parse(
                          '2026-07-31T10:00:03.0000000+00:00').
                              AddSeconds($_ - 1)).ToString('o')
                      if ($isSource) {
                          [pscustomobject]@{
                              at_utc = $sampleAt
                              process_alive = $true
                              broadcasting = $true; peer_socket = $true
                          }
                      } else {
                          [pscustomobject]@{
                              at_utc = $sampleAt
                              process_alive = $true; viewing = $true
                              api_peer = $true; peer_socket = $true
                              playlist = $true; segment = $true
                          }
                      }
                  })
              failure_evidence = $null
          }
          cleanup = [pscustomobject]@{
              process_stopped = $true; firewall_removed = $true
              control_closed = $true; broadcast_stopped = $true
              ffmpeg_children_gone = $true; hls_removed = $true
              node_removed = $true
              evidence_retained = $true
              system_state_restored = $true
          }
          evidence = [pscustomobject]@{
              schema = 'ese.v91.i07-retained-evidence/v1'
              complete = $true
              directory = 'evidence'
              files = @(
                  'BUILD_INFO.txt', 'build-info-evidence.json',
                  'effective-config.json',
                  'api-status-pre.json', 'api-status-post.json',
                  'topology-ports.json', 'log-evidence.json' |
                      ForEach-Object { [pscustomobject]@{
                          name = $_; bytes = 1
                          sha256 = if ($_ -ceq 'BUILD_INFO.txt') {
                              'd' * 64
                          } else { 'e' * 64 }
                      }}
              )
              manifest = [pscustomobject]@{
                  name = 'manifest.json'; bytes = 1; sha256 = 'f' * 64
              }
               requirements = [pscustomobject]@{
                   build_info_exact = $true; config_allowlist_only = $true
                   build_info_source_sha256 = 'd' * 64
                  api_pre_retained = $true; api_post_retained = $true
                  topology_ports_retained = $true; real_log_line_count = 1
                  timestamped_log_line_count = 1
              }
              build_info = [pscustomobject]@{
                  schema = 'ese.v91.i07-build-info-evidence/v1'
                  original_sha256 = 'd' * 64; expected_sha256 = 'd' * 64
                  exact = $true; fields_valid = $true
                  unknown_line_count = 0
                  fields = [pscustomobject]@{
                      release = 'v0.70b-eSE9.1.0-rc.2'
                      commit = $candidateCommit; dirty = 'false'
                      built_utc = '2026-07-31T09:00:00Z'
                      node = 'v22.17.0'; npm = '10.9.2'
                      ffmpeg = 'ffmpeg version 7.1'
                      ffmpeg_sha256 = '6' * 64
                      ffprobe_sha256 = '7' * 64
                      nodes_dat_sha256 = '8' * 64
                  }
              }
              effective_config = [pscustomobject]@{
                  schema = 'ese.v91.i07-effective-config/v2'
                  allowlist_only = $true; values_exact = $true
                  role = $Role; entries = $configEntries
              }
              log_evidence = [pscustomobject]@{
                  schema = 'ese.v91.i07-log-evidence/v1'
                  source_file_count = 1
                  inspected_nonempty_line_count = 1
                  timestamped_line_count = 1
                  capped_at_200_lines = $false
                  events = @([pscustomobject]@{
                      timestamp = '2026-07-31 12:34:56'
                      event_class = 'lifecycle'
                  })
              }
          }
          system_state = [pscustomobject]@{
              schema = 'ese.v91.i07-system-mutation-postcheck/v1'
              collector_ok = $true; complete = $true
              bound_sid_unchanged = $true; run_subtree_unchanged = $true
              emule_autostart_absent = $true
              ed2k_subtree_unchanged = $true; ed2k_subtree_absent = $true
              global_firewall_unchanged = $true
              baseline_registry_sha256 = '6' * 64
              post_registry_sha256 = '6' * 64
              baseline_firewall_sha256 = '7' * 64
              post_firewall_sha256 = '7' * 64
          }
          process_cleanup = [pscustomobject]@{
              schema = 'ese.v91.i07-process-cleanup/v1'
              stopped = $true; root_identity_matched = $true
              descendants_collector_ok = $true; descendant_count = 1
              descendants_stopped = $true
          }
          failure = if ($Status -ceq 'FAIL') {
              [pscustomobject]@{
                  category = 'PRODUCT_INVARIANT'
                  code = 'PRODUCT_INVARIANT'
              }
          } else { $null }
        }
    }
    $node = New-I07SelfTestNode -Role source
    $viewer = New-I07SelfTestNode -Role viewer
    if (-not (Test-I07ExternalJsonBoundary -Value $viewer -Kind node)) {
        throw 'I07 raw boundary rejected a valid node fixture.'
    }
    $retentionContext = [pscustomobject][ordered]@{
        role = 'viewer'; nonce = $nonce; candidate_sha256 = $sha
        commit = '1' * 40; build_info_sha256 = 'd' * 64
        zip_sha256 = '4' * 64; zip_bytes = 123
        package_files = @($viewer.candidate.package_files)
        expected_user_sid_sha256 = '3' * 64
        local_ipv6 = '2a02:26f7:abcd::20'
        peer_ipv6 = '2a02:26f7:abcd::10'; interface_index = 22
        interface_guid = '22222222-2222-2222-2222-222222222222'
    }
    if (-not (Test-I07NodeRetentionContext -Value $viewer `
            -Context $retentionContext)) {
        throw 'I07 node retention rejected its source-bound fixture.'
    }
    $savedUserSid = [string]$viewer.candidate.process_identity.user_sid_sha256
    $viewer.candidate.process_identity.user_sid_sha256 = '9' * 64
    if (Test-I07NodeRetentionContext -Value $viewer `
            -Context $retentionContext) {
        throw 'I07 node retention accepted a foreign account SID.'
    }
    $viewer.candidate.process_identity.user_sid_sha256 = $savedUserSid
    $savedLaunchManifest =
        [string]$viewer.candidate.launch_binding.static_manifest_sha256
    $viewer.candidate.launch_binding.static_manifest_sha256 = '9' * 64
    if (Test-I07NodeRetentionContext -Value $viewer `
            -Context $retentionContext) {
        throw 'I07 node retention accepted a stale prelaunch manifest.'
    }
    $viewer.candidate.launch_binding.static_manifest_sha256 =
        $savedLaunchManifest
    $viewer | Add-Member -NotePropertyName message `
        -NotePropertyValue 'C:\private\raw-error.txt'
    if (Test-I07ExternalJsonBoundary -Value $viewer -Kind node) {
        throw 'I07 raw boundary accepted a root diagnostic.'
    }
    $viewer.PSObject.Properties.Remove('message')
    $viewer.product.samples[0] | Add-Member -NotePropertyName token `
        -NotePropertyValue ('a' * 64)
    if (Test-I07ExternalJsonBoundary -Value $viewer -Kind node) {
        throw 'I07 raw boundary accepted a nested secret diagnostic.'
    }
    $viewer.product.samples[0].PSObject.Properties.Remove('token')
    if ((Get-I07AggregateStatus -Source $node -Viewer $viewer `
            -Nonce $nonce -CandidateSha256 $sha -ExpectedDurationSeconds 15 `
            -ExpectedViewerWlanProfileSha256 $wlanSha `
            -ExpectedViewerConnectionProfileSha256 $connectionSha `
            -ExpectedViewerInterfaceGuid `
                '22222222-2222-2222-2222-222222222222') -cne 'PASS') {
        throw ('I07 aggregate self-test rejected a valid fixture: ' +
            ($script:i07AggregateDebug | ConvertTo-Json -Compress))
    }
    $selfTestR01PassSnapshot = New-I07CanonicalJsonSnapshot -Value (
        [pscustomobject][ordered]@{
            schema = 'ese.v91.i07-r01-prerequisite/v1'
            case_id = 'V91-R01'; status = 'PASS'; topology_id = 'T3'
            fixture = $true
        })
    function New-I07SelfTestPassContext {
        param([ValidateSet('source', 'viewer')][string]$Role)
        $isSource = $Role -ceq 'source'
        $raw = if ($isSource) { $node } else { $viewer }
        return [pscustomobject][ordered]@{
            role = $Role; nonce = $nonce
            candidate_version = '9.1.0-rc.2'
            candidate_commit = '1' * 40; candidate_sha256 = $sha
            build_info_sha256 = 'd' * 64
            zip_sha256 = '4' * 64; zip_bytes = [Int64]123
            package_files = @($raw.candidate.package_files)
            duration_seconds = [Int64]15
            r01_prerequisite_sha256 =
                [string]$selfTestR01PassSnapshot.sha256
            r01_prerequisite_bytes =
                [Int64]$selfTestR01PassSnapshot.byte_count
            hotspot_connection_profile_sha256 = $connectionSha
            hotspot_wlan_profile_sha256 = $wlanSha
            local_ipv6 = [string]$raw.topology.local_ipv6
            peer_ipv6 = [string]$raw.topology.peer_ipv6
            interface_index = [Int64]$raw.topology.interface_index
            interface_guid = [string]$raw.topology.interface_guid
            tcp_port = [Int64]$raw.topology.ports.tcp
            udp_port = [Int64]$raw.topology.ports.udp
            web_port = [Int64]$raw.topology.ports.web
            peer_tcp_port = [Int64]$raw.topology.ports.peer_tcp
            control_port = [Int64]$raw.topology.ports.control
        }
    }
    $sourcePassContext = New-I07SelfTestPassContext -Role source
    $viewerPassContext = New-I07SelfTestPassContext -Role viewer
    $sourcePassSourceSnapshot = New-I07CanonicalJsonSnapshot -Value $node
    $snapshotInputSha = [string]$node.candidate.requested_sha256
    $snapshotHeldSha = [string]$sourcePassSourceSnapshot.sha256
    $node.candidate.requested_sha256 = '0' * 64
    if ([string]$sourcePassSourceSnapshot.value.candidate.requested_sha256 `
            -cne $snapshotInputSha -or
        [string]$sourcePassSourceSnapshot.sha256 -cne $snapshotHeldSha) {
        throw 'I07 canonical snapshot retained a mutable source reference.'
    }
    $node.candidate.requested_sha256 = $snapshotInputSha
    $viewerNoBomSnapshot = New-I07CanonicalJsonSnapshot -Value $viewer
    $viewerBomBytes = [byte[]](@(0xef, 0xbb, 0xbf) +
        @([byte[]]$viewerNoBomSnapshot.bytes_value))
    $viewerBomHasher = [Security.Cryptography.SHA256]::Create()
    try {
        $viewerBomDigest = ([BitConverter]::ToString(
            $viewerBomHasher.ComputeHash($viewerBomBytes))).Replace(
                '-', '').ToLowerInvariant()
    } finally { $viewerBomHasher.Dispose() }
    $viewerPassSourceSnapshot = [pscustomobject][ordered]@{
        bytes_value = $viewerBomBytes
        byte_count = [Int64]$viewerBomBytes.Length
        sha256 = $viewerBomDigest
        value = $viewer
    }
    $sourcePassFixture = New-I07PassProofSnapshot `
        -SourceSnapshot $sourcePassSourceSnapshot `
        -Context $sourcePassContext
    $viewerPassFixture = New-I07PassProofSnapshot `
        -SourceSnapshot $viewerPassSourceSnapshot `
        -Context $viewerPassContext
    if (-not (Test-I07PassProofContract `
            -Value $sourcePassFixture.value `
            -SourceSnapshot $sourcePassSourceSnapshot `
            -Context $sourcePassContext) -or
        -not (Test-I07PassProofContract `
            -Value $viewerPassFixture.value `
            -SourceSnapshot $viewerPassSourceSnapshot `
            -Context $viewerPassContext) -or
        -not (Test-I07PassProofPairContract `
            -Source $sourcePassFixture.value `
            -Viewer $viewerPassFixture.value)) {
        throw 'I07 PASS proof rejected its authenticated pair fixtures.'
    }
    $mutatedPairViewer = ($viewerPassFixture.value |
        ConvertTo-Json -Depth 24 -Compress) | ConvertFrom-Json
    $mutatedPairViewer.expected_duration_seconds = 16
    if (Test-I07PassProofPairContract -Source $sourcePassFixture.value `
            -Viewer $mutatedPairViewer) {
        throw 'I07 PASS pair accepted different requested durations.'
    }
    $mutatedPairViewer = ($viewerPassFixture.value |
        ConvertTo-Json -Depth 24 -Compress) | ConvertFrom-Json
    $mutatedPairViewer.topology.socket.tuple.remote_port = 48068
    if (Test-I07PassProofPairContract -Source $sourcePassFixture.value `
            -Viewer $mutatedPairViewer) {
        throw 'I07 PASS pair accepted a cross-node tuple mismatch.'
    }
    $mutatedPass = ($sourcePassFixture.value |
        ConvertTo-Json -Depth 24 -Compress) | ConvertFrom-Json
    $mutatedPass.topology.initial_route.route_metric = 2
    if (Test-I07PassProofContract -Value $mutatedPass `
            -SourceSnapshot $sourcePassSourceSnapshot `
            -Context $sourcePassContext) {
        throw 'I07 PASS proof accepted a projected route mutation.'
    }
    $mutatedPass = ($sourcePassFixture.value |
        ConvertTo-Json -Depth 24 -Compress) | ConvertFrom-Json
    $mutatedPass.evidence.files[0].sha256 = '0' * 64
    if (Test-I07PassProofContract -Value $mutatedPass `
            -SourceSnapshot $sourcePassSourceSnapshot `
            -Context $sourcePassContext) {
        throw 'I07 PASS proof accepted a projected evidence mutation.'
    }
    $badSourceSnapshot = [pscustomobject][ordered]@{
        bytes_value = $sourcePassSourceSnapshot.bytes_value
        byte_count = $sourcePassSourceSnapshot.byte_count
        sha256 = '0' * 64; value = $sourcePassSourceSnapshot.value
    }
    if (Test-I07PassProofContract -Value $sourcePassFixture.value `
            -SourceSnapshot $badSourceSnapshot `
            -Context $sourcePassContext) {
        throw 'I07 PASS proof accepted a stale source digest.'
    }
    $badSourceSnapshot.sha256 = $sourcePassSourceSnapshot.sha256
    $badSourceSnapshot.byte_count =
        [Int64]$sourcePassSourceSnapshot.byte_count + 1
    if (Test-I07PassProofContract -Value $sourcePassFixture.value `
            -SourceSnapshot $badSourceSnapshot `
            -Context $sourcePassContext) {
        throw 'I07 PASS proof accepted a stale source byte count.'
    }
    $badSourceSnapshot.byte_count = $sourcePassSourceSnapshot.byte_count
    $badSourceSnapshot.value = $viewer
    if (Test-I07PassProofContract -Value $sourcePassFixture.value `
            -SourceSnapshot $badSourceSnapshot `
            -Context $sourcePassContext) {
        throw 'I07 PASS proof accepted a source value/bytes swap.'
    }
    foreach ($invalidBytes in @(
            [byte[]]@(0x7b, 0xff, 0x7d),
            [Text.Encoding]::Unicode.GetBytes('{"safe":true}'))) {
        try {
            $null = ConvertFrom-I07Utf8JsonBytes -Bytes $invalidBytes
            throw 'I07 accepted invalid staged JSON encoding.'
        } catch {
            if ([string]$_.Exception.Message -ceq
                'I07 accepted invalid staged JSON encoding.') { throw }
        }
    }
    $savedSourceSamples = @($node.product.samples)
    $node.product.samples = @($savedSourceSamples | Select-Object -First 1)
    if ((Get-I07AggregateStatus -Source $node -Viewer $viewer `
            -Nonce $nonce -CandidateSha256 $sha `
            -ExpectedDurationSeconds 15) -cne 'BLOCKED') {
        throw 'I07 accepted a one-sample source PASS window.'
    }
    $node.product.samples = @($savedSourceSamples)
    $savedViewerSamples = @($viewer.product.samples)
    $viewer.product.samples = @($savedViewerSamples | Select-Object -First 10)
    if ((Get-I07AggregateStatus -Source $node -Viewer $viewer `
            -Nonce $nonce -CandidateSha256 $sha `
            -ExpectedDurationSeconds 15) -cne 'BLOCKED') {
        throw 'I07 accepted ten compressed viewer samples as a PASS window.'
    }
    $viewer.product.samples = @($savedViewerSamples)
    if ((Get-I07AggregateStatus -Source $node -Viewer $viewer `
            -Nonce $nonce -CandidateSha256 $sha `
            -ExpectedDurationSeconds 30) -cne 'BLOCKED') {
        throw 'I07 accepted samples shorter than the requested duration.'
    }
    $viewer.phase = 'complete'
    if ((Get-I07AggregateStatus -Source $node -Viewer $viewer `
            -Nonce $nonce -CandidateSha256 $sha `
            -ExpectedDurationSeconds 15) -cne 'BLOCKED') {
        throw 'I07 accepted a PASS node from a non-terminal proof phase.'
    }
    $viewer.phase = 'route_revalidation'
    $viewer.topology.initial_route | Add-Member -NotePropertyName benign_extra `
        -NotePropertyValue 'unexpected'
    if ((Get-I07AggregateStatus -Source $node -Viewer $viewer `
            -Nonce $nonce -CandidateSha256 $sha -ExpectedDurationSeconds 15) -cne 'BLOCKED') {
        throw 'I07 accepted an extra nested route property.'
    }
    $viewer.topology.initial_route.PSObject.Properties.Remove('benign_extra')
    $viewer.candidate.verified = 'true'
    if ((Get-I07AggregateStatus -Source $node -Viewer $viewer `
            -Nonce $nonce -CandidateSha256 $sha -ExpectedDurationSeconds 15) -cne 'BLOCKED') {
        throw 'I07 accepted a string candidate verification boolean.'
    }
    $viewer.candidate.verified = $true
    $viewer.product.socket.count = '1'
    if ((Get-I07AggregateStatus -Source $node -Viewer $viewer `
            -Nonce $nonce -CandidateSha256 $sha -ExpectedDurationSeconds 15) -cne 'BLOCKED') {
        throw 'I07 accepted a string socket count.'
    }
    $viewer.product.socket.count = 1
    $viewer.product.samples[0].viewing = 'false'
    if ((Get-I07AggregateStatus -Source $node -Viewer $viewer `
            -Nonce $nonce -CandidateSha256 $sha -ExpectedDurationSeconds 15) -cne 'BLOCKED') {
        throw 'I07 accepted a string session boolean.'
    }
    $viewer.product.samples[0].viewing = $true
    $viewer.product.direct_join | Add-Member -NotePropertyName extra `
        -NotePropertyValue $true
    if ((Get-I07AggregateStatus -Source $node -Viewer $viewer `
            -Nonce $nonce -CandidateSha256 $sha -ExpectedDurationSeconds 15) -cne 'BLOCKED') {
        throw 'I07 accepted an extra direct_join property.'
    }
    $viewer.product.direct_join.PSObject.Properties.Remove('extra')
    $viewer.candidate.requested_sha256 = '0' * 64
    if ((Get-I07AggregateStatus -Source $node -Viewer $viewer `
            -Nonce $nonce -CandidateSha256 $sha -ExpectedDurationSeconds 15) -cne 'BLOCKED') {
        throw 'I07 accepted a stale requested candidate digest.'
    }
    $viewer.candidate.requested_sha256 = $sha
    $viewer.candidate.zip_binding.zip_sha256 = '0' * 64
    if ((Get-I07AggregateStatus -Source $node -Viewer $viewer `
            -Nonce $nonce -CandidateSha256 $sha -ExpectedDurationSeconds 15) -cne 'BLOCKED') {
        throw 'I07 accepted a node ZIP binding contradiction.'
    }
    $viewer.candidate.zip_binding.zip_sha256 = '4' * 64
    $savedConfigEntries = @($viewer.evidence.effective_config.entries)
    $viewer.evidence.effective_config.entries = @(
        $savedConfigEntries | Select-Object -Skip 1)
    if ((Get-I07AggregateStatus -Source $node -Viewer $viewer `
            -Nonce $nonce -CandidateSha256 $sha -ExpectedDurationSeconds 15) -cne 'BLOCKED') {
        throw 'I07 aggregate accepted a missing effective-config entry.'
    }
    $viewer.evidence.effective_config.entries = @($savedConfigEntries)
    $savedNick = [string]$savedConfigEntries[0].value
    $savedConfigEntries[0].value = 'wrong-role-alias'
    if ((Get-I07AggregateStatus -Source $node -Viewer $viewer `
            -Nonce $nonce -CandidateSha256 $sha -ExpectedDurationSeconds 15) -cne 'BLOCKED') {
        throw 'I07 aggregate accepted a wrong effective-config value.'
    }
    $savedConfigEntries[0].value = $savedNick
    $viewer.evidence.effective_config.entries = @($savedConfigEntries +
        [pscustomobject]@{
            section = 'Private'; key = 'Password'; value = 'secret'
        })
    if ((Get-I07AggregateStatus -Source $node -Viewer $viewer `
            -Nonce $nonce -CandidateSha256 $sha -ExpectedDurationSeconds 15) -cne 'BLOCKED') {
        throw 'I07 aggregate accepted an extra effective-config entry.'
    }
    $viewer.evidence.effective_config.entries = @($savedConfigEntries +
        $savedConfigEntries[0])
    if ((Get-I07AggregateStatus -Source $node -Viewer $viewer `
            -Nonce $nonce -CandidateSha256 $sha -ExpectedDurationSeconds 15) -cne 'BLOCKED') {
        throw 'I07 aggregate accepted a duplicate effective-config entry.'
    }
    $viewer.evidence.effective_config.entries = @($savedConfigEntries)
    $savedBuildCommit = [string]$viewer.evidence.build_info.fields.commit
    $viewer.evidence.build_info.fields.commit = '2' * 40
    if ((Get-I07AggregateStatus -Source $node -Viewer $viewer `
            -Nonce $nonce -CandidateSha256 $sha -ExpectedDurationSeconds 15) -cne 'BLOCKED') {
        throw 'I07 aggregate accepted contradictory BUILD_INFO evidence.'
    }
    $viewer.evidence.build_info.fields.commit = $savedBuildCommit
    $savedLogTimestamp =
        [string]$viewer.evidence.log_evidence.events[0].timestamp
    $viewer.evidence.log_evidence.events[0].timestamp =
        'private fake log without timestamp'
    if ((Get-I07AggregateStatus -Source $node -Viewer $viewer `
            -Nonce $nonce -CandidateSha256 $sha -ExpectedDurationSeconds 15) -cne 'BLOCKED') {
        throw 'I07 aggregate accepted a synthetic log event.'
    }
    $viewer.evidence.log_evidence.events[0].timestamp = $savedLogTimestamp
    $viewer.product.hls.stream_key_sha256 = '8' * 64
    if ((Get-I07AggregateStatus -Source $node -Viewer $viewer `
            -Nonce $nonce -CandidateSha256 $sha -ExpectedDurationSeconds 15) -cne 'BLOCKED') {
        throw 'I07 aggregate accepted an HLS stream not bound to Source.'
    }
    $viewer.product.hls.stream_key_sha256 = '9' * 64
    $viewer.product.api_status_final.captured_at_utc =
        '2026-07-31T10:00:02.0000000+00:00'
    if ((Get-I07AggregateStatus -Source $node -Viewer $viewer `
            -Nonce $nonce -CandidateSha256 $sha -ExpectedDurationSeconds 15) -cne 'BLOCKED') {
        throw 'I07 aggregate accepted an API post-sample before final route.'
    }
    $viewer.product.api_status_final.captured_at_utc =
        '2026-07-31T10:00:19.5000000+00:00'
    $viewer.topology.initial_route.captured_at_utc =
        '2026-07-31T10:00:04.0000000+00:00'
    if ((Get-I07AggregateStatus -Source $node -Viewer $viewer `
            -Nonce $nonce -CandidateSha256 $sha -ExpectedDurationSeconds 15) -cne 'BLOCKED') {
        throw 'I07 aggregate accepted a post-candidate initial route.'
    }
    $viewer.topology.initial_route.captured_at_utc =
        '2026-07-31T10:00:00.0000000+00:00'
    $viewer.topology.final_route.captured_at_utc =
        '2026-07-31T10:00:00.0000000+00:00'
    if ((Get-I07AggregateStatus -Source $node -Viewer $viewer `
            -Nonce $nonce -CandidateSha256 $sha -ExpectedDurationSeconds 15) -cne 'BLOCKED') {
        throw 'I07 aggregate accepted a pre-candidate final route.'
    }
    $viewer.topology.final_route.captured_at_utc =
        '2026-07-31T10:00:19.0000000+00:00'
    $viewer.product.direct_join.dialed = $false
    if ((Get-I07AggregateStatus -Source $node -Viewer $viewer `
            -Nonce $nonce -CandidateSha256 $sha -ExpectedDurationSeconds 15) -cne 'BLOCKED') {
        throw 'I07 aggregate self-test accepted incomplete direct evidence.'
    }
    $viewer.product.direct_join.dialed = $true
    $viewer.evidence.complete = $false
    if ((Get-I07AggregateStatus -Source $node -Viewer $viewer `
            -Nonce $nonce -CandidateSha256 $sha -ExpectedDurationSeconds 15) -cne 'BLOCKED') {
        throw 'I07 aggregate self-test accepted incomplete retained evidence.'
    }
    $viewer.evidence.complete = $true
    $viewer.product.socket.tuples[0].owning_process = 999
    if ((Get-I07AggregateStatus -Source $node -Viewer $viewer `
            -Nonce $nonce -CandidateSha256 $sha -ExpectedDurationSeconds 15) -cne 'BLOCKED') {
        throw 'I07 aggregate self-test accepted a foreign socket PID.'
    }
    $viewer.product.socket.tuples[0].owning_process = 202
    if ((Get-I07AggregateStatus -Source $node -Viewer $viewer `
            -Nonce $nonce -CandidateSha256 $sha -ExpectedDurationSeconds 15 `
            -ExpectedViewerWlanProfileSha256 ('9' * 64) `
            -ExpectedViewerConnectionProfileSha256 $connectionSha `
            -ExpectedViewerInterfaceGuid `
                '22222222-2222-2222-2222-222222222222') -cne 'BLOCKED') {
        throw 'I07 aggregate self-test accepted a stale hotspot WLAN hash.'
    }
    $healthyLabelFail = New-I07SelfTestNode -Role viewer
    $healthyLabelFail.status = 'FAIL'
    $healthyLabelFail.phase = 'viewer_direct_session'
    $healthyLabelFail.failure = [pscustomobject]@{
        category = 'PRODUCT_INVARIANT'; code = 'VIEWER_SESSION_INVARIANT'
    }
    if ((Get-I07AggregateStatus -Source $null -Viewer $healthyLabelFail `
            -Nonce $nonce -CandidateSha256 $sha -ExpectedDurationSeconds 15) -cne 'BLOCKED') {
        throw 'I07 accepted healthy product evidence under a forged FAIL label.'
    }
    $failViewer = New-I07SelfTestNode -Role viewer
    $sampleIndex = 0
    foreach ($sample in $failViewer.product.samples) {
        $sample.peer_socket = $false
        $sample.at_utc = ([DateTimeOffset]::Parse(
            '2026-07-31T10:00:02.5000000+00:00').AddSeconds(
                (15.0 / 15.0) * $sampleIndex)).ToString('o')
        ++$sampleIndex
    }
    $failViewer.completed_at_utc = '2026-07-31T10:00:20.0000000+00:00'
    $failViewer.status = 'FAIL'
    $failViewer.phase = 'viewer_direct_session'
    $failViewer.failure = [pscustomobject]@{
        category = 'PRODUCT_INVARIANT'; code = 'VIEWER_SESSION_INVARIANT'
    }
    $failViewer.product.failure_evidence = [pscustomobject]@{
        schema = 'ese.v91.i07-product-failure-evidence/v1'
        reason = 'SOCKET_NOT_OBSERVED'
        observed_at_utc = '2026-07-31T10:00:18.5000000+00:00'
        listener = $null; api_operation = $null; process_exit = $null
        session_observation = [pscustomobject]@{
            sample_count = 16; socket_observed = $false
            observation_started_at_utc =
                '2026-07-31T10:00:02.5000000+00:00'
            deadline_at_utc = '2026-07-31T10:00:17.5000000+00:00'
            broadcasting_observed = $false; api_peer_observed = $true
            viewing_observed = $true; playlist_observed = $true
            segment_observed = $true
        }
    }
    if ((Get-I07AggregateStatus -Source $null -Viewer $failViewer `
            -Nonce $nonce -CandidateSha256 $sha -ExpectedDurationSeconds 15) -cne 'FAIL') {
        throw 'I07 rejected a causally authenticated product FAIL.'
    }
    $failSourceSnapshot = New-I07CanonicalJsonSnapshot -Value $failViewer
    $failProofContext = New-I07FailureProofContext -Role viewer `
        -Nonce $nonce -DurationSeconds 15 `
        -CandidateIdentity ([pscustomobject]@{
            version = '9.1.0-rc.2'; commit = '1' * 40
            emule_sha256 = $sha; bytes = [Int64]12345
            build_info_sha256 = 'd' * 64
            zip_sha256 = '4' * 64; zip_bytes = [Int64]123
            package_files = @($failViewer.candidate.package_files)
        })
    $failProof = New-I07FailureProofSnapshot -Node $failViewer `
        -SourceSnapshot $failSourceSnapshot -Context $failProofContext
    if (-not (Test-I07FailureProofContract -Value $failProof.value)) {
        throw 'I07 rejected its sanitized causal failure proof.'
    }
    $savedProofPhase = [string]$failProof.value.failure.phase
    $failProof.value.failure.phase =
        'System.Net.WebException connection refused while opening endpoint'
    if (Test-I07FailureProofContract -Value $failProof.value) {
        throw 'I07 failure proof accepted raw prose in a fixed phase.'
    }
    $failProof.value.failure.phase = $savedProofPhase
    $savedProofReason = [string]$failProof.value.failure.reason
    $failProof.value.failure.reason =
        'System.Net.WebException connection refused while opening endpoint'
    if (Test-I07FailureProofContract -Value $failProof.value) {
        throw 'I07 failure proof accepted raw prose in a fixed reason.'
    }
    $failProof.value.failure.reason = $savedProofReason
    $failProof.value.cleanup.process_stopped = $false
    if (-not (Test-I07FailureProofContract -Value $failProof.value)) {
        throw 'I07 failure proof discarded a typed false cleanup outcome.'
    }
    if (Test-I07FailureProofProvenanceContract -Value $failProof.value `
            -SourceSnapshot $failSourceSnapshot `
            -Context $failProofContext) {
        throw 'I07 failure proof accepted a valid-looking projection mutation.'
    }
    $failProof.value.cleanup.process_stopped = 'false'
    if (Test-I07FailureProofContract -Value $failProof.value) {
        throw 'I07 failure proof accepted a string cleanup boolean.'
    }
    $failProof.value.cleanup.process_stopped = $true
    if (-not (Test-I07FailureProofProvenanceContract `
            -Value $failProof.value -SourceSnapshot $failSourceSnapshot `
            -Context $failProofContext)) {
        throw 'I07 failure proof did not recover source provenance.'
    }
    foreach ($badFailureSource in @(
            [pscustomobject]@{
                bytes_value = $failSourceSnapshot.bytes_value
                byte_count = $failSourceSnapshot.byte_count
                sha256 = '0' * 64; value = $failSourceSnapshot.value
            },
            [pscustomobject]@{
                bytes_value = $failSourceSnapshot.bytes_value
                byte_count = [Int64]$failSourceSnapshot.byte_count + 1
                sha256 = $failSourceSnapshot.sha256
                value = $failSourceSnapshot.value
            },
            [pscustomobject]@{
                bytes_value = $failSourceSnapshot.bytes_value
                byte_count = $failSourceSnapshot.byte_count
                sha256 = $failSourceSnapshot.sha256; value = $node
            })) {
        if (Test-I07FailureProofProvenanceContract `
                -Value $failProof.value -SourceSnapshot $badFailureSource `
                -Context $failProofContext) {
            throw 'I07 failure proof accepted stale source provenance.'
        }
    }
    try {
        $null = New-I07FailureProofSnapshot -Node $failViewer `
            -SourceSnapshot $sourcePassSourceSnapshot `
            -Context $failProofContext
        throw 'I07 failure proof accepted Node A with snapshot B.'
    } catch {
        if ([string]$_.Exception.Message -ceq
            'I07 failure proof accepted Node A with snapshot B.') { throw }
    }
    $savedProofFirst = [string]$failProof.value.session_summary.
        first_sample_at_utc
    $failProof.value.session_summary.first_sample_at_utc =
        [string]$failProof.value.failure.causal.session_observation.
            deadline_at_utc
    if (Test-I07FailureProofContract -Value $failProof.value) {
        throw 'I07 failure proof accepted samples only at the deadline.'
    }
    $failProof.value.session_summary.first_sample_at_utc = $savedProofFirst
    $savedFailureSamples = @($failViewer.product.samples)
    $failViewer.product.samples = @([pscustomobject]@{
        at_utc = '2026-07-31T10:00:17.5000000+00:00'
        process_alive = $true; viewing = $true; api_peer = $true
        peer_socket = $false; playlist = $true; segment = $true
    })
    $failViewer.product.failure_evidence.session_observation.sample_count = 1
    if ((Get-I07AggregateStatus -Source $null -Viewer $failViewer `
            -Nonce $nonce -CandidateSha256 $sha -ExpectedDurationSeconds 15) `
            -cne 'BLOCKED') {
        throw 'I07 accepted a one-sample forged absence at the deadline.'
    }
    $failViewer.product.samples = @(
        [pscustomobject]@{
            at_utc = '2026-07-31T10:00:17.4000000+00:00'
            process_alive = $true; viewing = $true; api_peer = $true
            peer_socket = $false; playlist = $true; segment = $true
        },
        [pscustomobject]@{
            at_utc = '2026-07-31T10:00:17.5000000+00:00'
            process_alive = $true; viewing = $true; api_peer = $true
            peer_socket = $false; playlist = $true; segment = $true
        })
    $failViewer.product.failure_evidence.session_observation.sample_count = 2
    if ((Get-I07AggregateStatus -Source $null -Viewer $failViewer `
            -Nonce $nonce -CandidateSha256 $sha -ExpectedDurationSeconds 15) `
            -cne 'BLOCKED') {
        throw 'I07 accepted two forged samples only at the deadline.'
    }
    $failViewer.product.samples = @($savedFailureSamples)
    $failViewer.product.failure_evidence.session_observation.sample_count = 16
    $failViewer.failure.code = 'viewer_session_invariant'
    if ((Get-I07AggregateStatus -Source $null -Viewer $failViewer `
            -Nonce $nonce -CandidateSha256 $sha -ExpectedDurationSeconds 15) -cne 'BLOCKED') {
        throw 'I07 accepted a case-variant product failure code.'
    }
    $failViewer.failure.code = 'VIEWER_SESSION_INVARIANT'
    $failViewer.phase = 'viewer_candidate_start'
    if ((Get-I07AggregateStatus -Source $null -Viewer $failViewer `
            -Nonce $nonce -CandidateSha256 $sha -ExpectedDurationSeconds 15) -cne 'BLOCKED') {
        throw 'I07 accepted a product failure under the wrong phase.'
    }
    $failViewer.phase = 'viewer_direct_session'
    $failViewer.product.failure_evidence.reason = 'API_PEER_NOT_OBSERVED'
    if ((Get-I07AggregateStatus -Source $null -Viewer $failViewer `
            -Nonce $nonce -CandidateSha256 $sha -ExpectedDurationSeconds 15) -cne 'BLOCKED') {
        throw 'I07 accepted product evidence contradicting its reason.'
    }
    $failViewer.product.failure_evidence.reason = 'SOCKET_NOT_OBSERVED'
    $failViewer.failure.PSObject.Properties.Remove('code')
    if ((Get-I07AggregateStatus -Source $null -Viewer $failViewer `
            -Nonce $nonce -CandidateSha256 $sha -ExpectedDurationSeconds 15) -cne 'BLOCKED') {
        throw 'I07 aggregate accepted a FAIL without its fixed code.'
    }
    $failViewer.failure | Add-Member -NotePropertyName code `
        -NotePropertyValue 'WRONG_PRODUCT_CODE'
    if ((Get-I07AggregateStatus -Source $null -Viewer $failViewer `
            -Nonce $nonce -CandidateSha256 $sha -ExpectedDurationSeconds 15) -cne 'BLOCKED') {
        throw 'I07 aggregate accepted a FAIL with the wrong code.'
    }
    $failViewer.failure.code = 'VIEWER_SESSION_INVARIANT'
    if ((Get-I07AggregateStatus -Source $null -Viewer $failViewer `
            -Nonce $nonce -CandidateSha256 $sha -ExpectedDurationSeconds 15) `
            -cne 'FAIL') { throw 'I07 FAIL fixture did not recover.' }
    $failViewer.failure | Add-Member -NotePropertyName message `
        -NotePropertyValue 'C:\Users\fixture\secret.txt?key=private'
    if ((Get-I07AggregateStatus -Source $null -Viewer $failViewer `
            -Nonce $nonce -CandidateSha256 $sha -ExpectedDurationSeconds 15) -cne 'BLOCKED') {
        throw 'I07 aggregate accepted extra raw FAIL diagnostics.'
    }
    $failViewer.failure.PSObject.Properties.Remove('message')
    $failViewer.product.failure_evidence | Add-Member `
        -NotePropertyName token -NotePropertyValue ('a' * 64)
    if ((Get-I07AggregateStatus -Source $null -Viewer $failViewer `
            -Nonce $nonce -CandidateSha256 $sha -ExpectedDurationSeconds 15) `
            -cne 'BLOCKED') {
        throw 'I07 accepted a raw nested failure diagnostic.'
    }
    $failViewer.product.failure_evidence.PSObject.Properties.Remove('token')
    $failViewer.product.samples[0] | Add-Member -NotePropertyName password `
        -NotePropertyValue 'secret'
    if ((Get-I07AggregateStatus -Source $null -Viewer $failViewer `
            -Nonce $nonce -CandidateSha256 $sha -ExpectedDurationSeconds 15) `
            -cne 'BLOCKED') {
        throw 'I07 accepted a raw nested sample diagnostic.'
    }
    $failViewer.product.samples[0].PSObject.Properties.Remove('password')
    if ((Get-I07AggregateStatus -Source $null -Viewer $failViewer `
            -Nonce $nonce -CandidateSha256 $sha -ExpectedDurationSeconds 15) `
            -cne 'FAIL') { throw 'I07 FAIL fixture was not restored.' }
    $node.failure = [pscustomobject]@{
        category = 'PRODUCT_INVARIANT'; code = 'SOURCE_SESSION_INVARIANT'
    }
    if ((Get-I07AggregateStatus -Source $node -Viewer $viewer `
            -Nonce $nonce -CandidateSha256 $sha -ExpectedDurationSeconds 15) -cne 'BLOCKED') {
        throw 'I07 aggregate accepted PASS with a failure envelope.'
    }
    $node.failure = $null
    $failViewer.topology.initial_route.source_class = 'ula'
    if ((Get-I07AggregateStatus -Source $null -Viewer $failViewer `
            -Nonce $nonce -CandidateSha256 $sha -ExpectedDurationSeconds 15) -cne 'BLOCKED') {
        throw 'I07 aggregate self-test accepted a forged FAIL route.'
    }
    $failViewer.topology.initial_route.source_class = 'global-native'
    $failViewer.topology.initial_route.captured_at_utc =
        '2026-07-31T10:00:04.0000000+00:00'
    if ((Get-I07AggregateStatus -Source $null -Viewer $failViewer `
            -Nonce $nonce -CandidateSha256 $sha -ExpectedDurationSeconds 15) -cne 'BLOCKED') {
        throw 'I07 aggregate accepted a post-candidate FAIL route.'
    }
    $failViewer.topology.initial_route.captured_at_utc =
        '2026-07-31T10:00:00.0000000+00:00'
    $failViewer.topology.control.proven_at_utc =
        '2026-07-31T10:00:04.0000000+00:00'
    if ((Get-I07AggregateStatus -Source $null -Viewer $failViewer `
            -Nonce $nonce -CandidateSha256 $sha -ExpectedDurationSeconds 15) -cne 'BLOCKED') {
        throw 'I07 aggregate self-test accepted post-candidate control proof.'
    }
    $failViewer.topology.control.proven_at_utc =
        '2026-07-31T10:00:01.0000000+00:00'
    $failViewer.candidate.zip_verified = $false
    if ((Get-I07AggregateStatus -Source $null -Viewer $failViewer `
            -Nonce $nonce -CandidateSha256 $sha -ExpectedDurationSeconds 15) -cne 'BLOCKED') {
        throw 'I07 aggregate self-test accepted an unverified node ZIP.'
    }
    $failViewer.candidate.zip_verified = $true
    $failViewer.nonce = 'ffffffffffffffffffffffffffffffff'
    if ((Get-I07AggregateStatus -Source $null -Viewer $failViewer `
            -Nonce $nonce -CandidateSha256 $sha -ExpectedDurationSeconds 15) -cne 'BLOCKED') {
        throw 'I07 aggregate self-test accepted a stale FAIL nonce.'
    }
    $failViewer.nonce = $nonce
    $failViewer.schema = 'ese.v91.i07-node-result/v0'
    if ((Get-I07AggregateStatus -Source $null -Viewer $failViewer `
            -Nonce $nonce -CandidateSha256 $sha -ExpectedDurationSeconds 15) -cne 'BLOCKED') {
        throw 'I07 aggregate self-test accepted a malformed FAIL schema.'
    }
    function New-I07SelfTestApiOperation {
        param(
            [string]$Operation, [bool]$Available,
            [bool]$ContractValid, [bool]$Success = $false,
            [bool]$Ready = $false
        )
        $safe = [ordered]@{
            operation = $Operation; available = $Available
            contract_valid = $ContractValid; success = $Success; ready = $Ready
        }
        $json = $safe | ConvertTo-Json -Compress
        $bytes = [Text.Encoding]::UTF8.GetBytes($json)
        $hasher = [Security.Cryptography.SHA256]::Create()
        try {
            $digest = ([BitConverter]::ToString(
                $hasher.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
        } finally { $hasher.Dispose() }
        return [pscustomobject]@{
            operation = $Operation; available = $Available
            contract_valid = $ContractValid; success = $Success; ready = $Ready
            safe_response_sha256 = $digest
            safe_response_bytes = $bytes.Length
        }
    }
    $apiViolation = [pscustomobject]@{
        ed2k_connected = $true; kad_connected = $false
        kad_configured_mask = 0; kad_running_mask = 0
        kad2_running = $false; kad2_connected = $false
        kad6_running = $false; kad6_connected = $false
        netlab_enabled = $false
    }
    foreach ($apiCase in @(
        [pscustomobject]@{
            code = 'API_INITIAL_UNRESPONSIVE'; phase = 'viewer_candidate_start'
            reason = 'API_STATUS_UNRESPONSIVE'; operation = 'api_status_initial'
            initial = 'unavailable'; final = 'unavailable'
            available = $false; contract = $false
        },
        [pscustomobject]@{
            code = 'API_INITIAL_ISOLATION_CONTRADICTION'
            phase = 'viewer_candidate_start'
            reason = 'API_ISOLATION_CONTRADICTION'
            operation = 'api_status_initial'; initial = 'violation'
            final = 'unavailable'; available = $true; contract = $true
        },
        [pscustomobject]@{
            code = 'API_FINAL_UNRESPONSIVE'; phase = 'route_revalidation'
            reason = 'API_STATUS_UNRESPONSIVE'; operation = 'api_status_final'
            initial = 'valid'; final = 'unavailable'
            available = $false; contract = $false
        },
        [pscustomobject]@{
            code = 'API_FINAL_ISOLATION_CONTRADICTION'
            phase = 'route_revalidation'
            reason = 'API_ISOLATION_CONTRADICTION'
            operation = 'api_status_final'; initial = 'valid'
            final = 'violation'; available = $true; contract = $true
        })) {
        $apiFail = New-I07SelfTestNode -Role viewer
        $unavailable = Get-I07ApiEvidenceSummary -Value $null
        if ($apiCase.initial -ceq 'unavailable') {
            $apiFail.product.api_status_initial = $unavailable
        } elseif ($apiCase.initial -ceq 'violation') {
            $apiFail.product.api_status_initial = Get-I07ApiEvidenceSummary `
                -Value $apiViolation -CapturedAt ([DateTimeOffset]::Parse(
                    '2026-07-31T10:00:02.5000000+00:00'))
        }
        if ($apiCase.final -ceq 'unavailable') {
            $apiFail.product.api_status_final = $unavailable
        } elseif ($apiCase.final -ceq 'violation') {
            $apiFail.product.api_status_final = Get-I07ApiEvidenceSummary `
                -Value $apiViolation -CapturedAt ([DateTimeOffset]::Parse(
                    '2026-07-31T10:00:19.5000000+00:00'))
        }
        $apiFail.status = 'FAIL'; $apiFail.phase = $apiCase.phase
        $apiFail.failure = [pscustomobject]@{
            category = 'PRODUCT_INVARIANT'; code = $apiCase.code
        }
        $apiFail.product.failure_evidence = [pscustomobject]@{
            schema = 'ese.v91.i07-product-failure-evidence/v1'
            reason = $apiCase.reason
            observed_at_utc = if ($apiCase.operation -ceq
                    'api_status_final') {
                '2026-07-31T10:00:19.7500000+00:00'
            } else { '2026-07-31T10:00:04.5000000+00:00' }
            listener = $null
            api_operation = New-I07SelfTestApiOperation `
                -Operation $apiCase.operation `
                -Available $apiCase.available `
                -ContractValid $apiCase.contract
            process_exit = $null; session_observation = $null
        }
        if ((Get-I07AggregateStatus -Source $null -Viewer $apiFail `
                -Nonce $nonce -CandidateSha256 $sha -ExpectedDurationSeconds 15) -cne 'FAIL') {
            throw "I07 rejected authenticated API FAIL $($apiCase.code)."
        }
        $apiSourceSnapshot = New-I07CanonicalJsonSnapshot -Value $apiFail
        $apiFailureContext = New-I07FailureProofContext -Role viewer `
            -Nonce $nonce -DurationSeconds 15 `
            -CandidateIdentity ([pscustomobject]@{
                version = '9.1.0-rc.2'; commit = '1' * 40
                emule_sha256 = $sha; bytes = [Int64]12345
                build_info_sha256 = 'd' * 64
                zip_sha256 = '4' * 64; zip_bytes = [Int64]123
                package_files = @($apiFail.candidate.package_files)
            })
        $apiProof = New-I07FailureProofSnapshot -Node $apiFail `
            -SourceSnapshot $apiSourceSnapshot -Context $apiFailureContext
        if (-not (Test-I07FailureProofContract -Value $apiProof.value)) {
            throw "I07 rejected sanitized API proof $($apiCase.code)."
        }
        $proofApiStatus = if ($apiCase.operation -ceq
                'api_status_initial') {
            $apiProof.value.api_status_initial
        } else { $apiProof.value.api_status_final }
        if ($apiCase.code -clike '*ISOLATION_CONTRADICTION') {
            $proofApiStatus.isolation_invariant_satisfied = $true
            if (Test-I07FailureProofContract -Value $apiProof.value) {
                throw "I07 accepted healthy API state as $($apiCase.code)."
            }
            $proofApiStatus.isolation_invariant_satisfied = $false
        }
        $apiFail.product.failure_evidence.reason = 'FORGED_REASON'
        if ((Get-I07AggregateStatus -Source $null -Viewer $apiFail `
                -Nonce $nonce -CandidateSha256 $sha -ExpectedDurationSeconds 15) -cne 'BLOCKED') {
            throw "I07 accepted forged API FAIL $($apiCase.code)."
        }
    }

    $r01HomeWlan = '1' * 64
    $r01HotspotWlan = '2' * 64
    $r01HomeConnection = '3' * 64
    $r01HotspotConnection = '4' * 64
    $r01CandidateIdentity = [pscustomobject]@{
        version = '9.1.0-rc.2'; commit = '1' * 40
        emule_sha256 = $sha; build_info_sha256 = 'd' * 64
        zip_sha256 = '4' * 64; zip_bytes = [Int64]123
    }
    $r01Expected = @{
        ExpectedVersion = $r01CandidateIdentity.version
        ExpectedCommit = $r01CandidateIdentity.commit
        ExpectedEmuleSha256 = $r01CandidateIdentity.emule_sha256
        ExpectedBuildInfoSha256 = $r01CandidateIdentity.build_info_sha256
        ExpectedZipSha256 = $r01CandidateIdentity.zip_sha256
        ExpectedZipBytes = $r01CandidateIdentity.zip_bytes
    }
    $r01Fixture = [pscustomobject]@{
        schema = 'ese.v91.r01-campaign/v1'
        case_id = 'V91-R01'
        status = 'PASS'
        requested_home_wlan_profile_sha256 = $r01HomeWlan
        requested_hotspot_wlan_profile_sha256 = $r01HotspotWlan
        candidate = [pscustomobject]@{
            version = $r01Expected.ExpectedVersion
            commit = $r01Expected.ExpectedCommit; dirty = 'false'
            emule_sha256 = $r01Expected.ExpectedEmuleSha256
            build_info_sha256 = $r01Expected.ExpectedBuildInfoSha256
            zip_sha256 = $r01Expected.ExpectedZipSha256
            zip_bytes = $r01Expected.ExpectedZipBytes
        }
        topology = [pscustomobject]@{
            id = 'T3'
            home_connection_profile_sha256 = $r01HomeConnection
            hotspot_connection_profile_sha256 = $r01HotspotConnection
            home_profile_sha256 = $r01HomeConnection
            hotspot_profile_sha256 = $r01HotspotConnection
        }
        remote = [pscustomobject]@{
            case_id = 'V91-R01'
            status = 'REMOTE_PASS'
            topology = [pscustomobject]@{
                id = 'T3'
                initial = [pscustomobject]@{
                    interface_guid =
                        '22222222-2222-2222-2222-222222222222'
                    wlan_profile_sha256 = $r01HomeWlan
                    connection_profile = [pscustomobject]@{
                        name_sha256 = $r01HomeConnection
                    }
                }
                mobile = [pscustomobject]@{
                    interface_guid =
                        '22222222-2222-2222-2222-222222222222'
                    wlan_profile_sha256 = $r01HotspotWlan
                    connection_profile = [pscustomobject]@{
                        name_sha256 = $r01HotspotConnection
                    }
                }
            }
            candidate = [pscustomobject]@{
                version = $r01Expected.ExpectedVersion
                commit = $r01Expected.ExpectedCommit; dirty = $false
                emule_sha256 = $r01Expected.ExpectedEmuleSha256
                build_info_sha256 = $r01Expected.ExpectedBuildInfoSha256
                zip_sha256 = $r01Expected.ExpectedZipSha256
                zip_bytes = $r01Expected.ExpectedZipBytes
                remote_package_binding = [pscustomobject]@{
                    schema = 'ese.v91.r01-remote-package-binding/v1'
                    remote_zip_sha256 = $r01Expected.ExpectedZipSha256
                    remote_zip_bytes = $r01Expected.ExpectedZipBytes
                    extracted_file_set_exact = $true
                    extracted_bytes_and_sha256_exact = $true
                }
            }
            cleanup = [pscustomobject]@{
                home_restored = $true; node_removed = $true
                wifi_watchdog_safe = $true
            }
        }
        cleanup = [pscustomobject]@{ complete = $true }
    }
    if (-not (Test-I07R01AggregateContract -Aggregate $r01Fixture `
            @r01Expected)) {
        throw 'I07 rejected a valid R01 dependency fixture.'
    }
    $r01Sentinel = 'R01-RAW-SENTINEL-' + ('f' * 32)
    $r01Fixture | Add-Member -NotePropertyName raw_response `
        -NotePropertyValue $r01Sentinel
    $r01SourceSnapshot = New-I07CanonicalJsonSnapshot -Value $r01Fixture
    $r01Prerequisite = New-I07R01PrerequisiteSnapshot `
        -Aggregate $r01Fixture -SourceSnapshot $r01SourceSnapshot `
        -CandidateIdentity $r01CandidateIdentity
    $r01PrerequisiteJson = [Text.Encoding]::UTF8.GetString(
        [byte[]]$r01Prerequisite.bytes_value)
    if (-not (Test-I07R01PrerequisiteContract `
            -Value $r01Prerequisite.value `
            -SourceSnapshot $r01SourceSnapshot) -or
        -not (Test-I07R01PrerequisiteProvenanceContract `
            -Value $r01Prerequisite.value `
            -SourceSnapshot $r01SourceSnapshot `
            -CandidateIdentity $r01CandidateIdentity) -or
        $r01PrerequisiteJson.Contains($r01Sentinel) -or
        $r01PrerequisiteJson.Contains(
            (Get-I07TextSha256 -Value $r01Sentinel))) {
        throw 'I07 R01 prerequisite retained an external raw sentinel.'
    }
    $savedHomeFingerprint = [string]$r01Prerequisite.value.
        profile_fingerprints.home_wlan_sha256
    $r01Prerequisite.value.profile_fingerprints.home_wlan_sha256 = '9' * 64
    if (-not (Test-I07R01PrerequisiteContract `
            -Value $r01Prerequisite.value `
            -SourceSnapshot $r01SourceSnapshot) -or
        (Test-I07R01PrerequisiteProvenanceContract `
            -Value $r01Prerequisite.value `
            -SourceSnapshot $r01SourceSnapshot `
            -CandidateIdentity $r01CandidateIdentity)) {
        throw 'I07 R01 provenance did not reject a valid-looking projection.'
    }
    $r01Prerequisite.value.profile_fingerprints.home_wlan_sha256 =
        $savedHomeFingerprint
    foreach ($badR01Source in @(
            [pscustomobject]@{
                bytes_value = $r01SourceSnapshot.bytes_value
                byte_count = $r01SourceSnapshot.byte_count
                sha256 = '0' * 64; value = $r01SourceSnapshot.value
            },
            [pscustomobject]@{
                bytes_value = $r01SourceSnapshot.bytes_value
                byte_count = [Int64]$r01SourceSnapshot.byte_count + 1
                sha256 = $r01SourceSnapshot.sha256
                value = $r01SourceSnapshot.value
            },
            [pscustomobject]@{
                bytes_value = $r01SourceSnapshot.bytes_value
                byte_count = $r01SourceSnapshot.byte_count
                sha256 = $r01SourceSnapshot.sha256; value = $node
            })) {
        if (Test-I07R01PrerequisiteProvenanceContract `
                -Value $r01Prerequisite.value `
                -SourceSnapshot $badR01Source `
                -CandidateIdentity $r01CandidateIdentity) {
            throw 'I07 R01 prerequisite accepted stale source provenance.'
        }
    }
    $r01Other = (($r01SourceSnapshot.value |
        ConvertTo-Json -Depth 24 -Compress) | ConvertFrom-Json)
    $r01Other.candidate.commit = '0' * 40
    try {
        $null = New-I07R01PrerequisiteSnapshot -Aggregate $r01Other `
            -SourceSnapshot $r01SourceSnapshot `
            -CandidateIdentity $r01CandidateIdentity
        throw 'I07 R01 prerequisite accepted Aggregate A with snapshot B.'
    } catch {
        if ([string]$_.Exception.Message -ceq
            'I07 R01 prerequisite accepted Aggregate A with snapshot B.') {
            throw
        }
    }
    $r01Fixture.PSObject.Properties.Remove('raw_response')
    $savedSourceBytes = [Int64]$r01Prerequisite.value.
        source_aggregate_bytes
    $r01Prerequisite.value.source_aggregate_bytes = $savedSourceBytes + 1
    if (Test-I07R01PrerequisiteContract -Value $r01Prerequisite.value `
            -SourceSnapshot $r01SourceSnapshot) {
        throw 'I07 R01 prerequisite accepted false source provenance.'
    }
    $r01Prerequisite.value.source_aggregate_bytes = $savedSourceBytes
    $r01Fixture.case_id = 'V91-R00'
    if (Test-I07R01AggregateContract -Aggregate $r01Fixture @r01Expected) {
        throw 'I07 accepted an R01 dependency with the wrong case ID.'
    }
    $r01Fixture.case_id = 'V91-R01'
    $r01Fixture.topology.id = 'T2'
    if (Test-I07R01AggregateContract -Aggregate $r01Fixture @r01Expected) {
        throw 'I07 accepted an R01 dependency outside topology T3.'
    }
    $r01Fixture.topology.id = 'T3'
    $r01Fixture.requested_hotspot_wlan_profile_sha256 = $r01HomeWlan
    $r01Fixture.remote.topology.mobile.wlan_profile_sha256 = $r01HomeWlan
    if (Test-I07R01AggregateContract -Aggregate $r01Fixture @r01Expected) {
        throw 'I07 accepted identical Home and hotspot WLAN profiles.'
    }
    $r01Fixture.requested_hotspot_wlan_profile_sha256 = $r01HotspotWlan
    $r01Fixture.remote.topology.mobile.wlan_profile_sha256 = $r01HotspotWlan
    $r01Fixture.topology.hotspot_connection_profile_sha256 =
        $r01HomeConnection
    $r01Fixture.topology.hotspot_profile_sha256 = $r01HomeConnection
    $r01Fixture.remote.topology.mobile.connection_profile.name_sha256 =
        $r01HomeConnection
    if (Test-I07R01AggregateContract -Aggregate $r01Fixture @r01Expected) {
        throw 'I07 accepted identical Home and hotspot NLA profiles.'
    }
    $r01Fixture.topology.hotspot_connection_profile_sha256 =
        $r01HotspotConnection
    $r01Fixture.topology.hotspot_profile_sha256 = $r01HotspotConnection
    $r01Fixture.remote.topology.mobile.connection_profile.name_sha256 =
        $r01HotspotConnection
    $r01Fixture.candidate.commit = '0' * 40
    if (Test-I07R01AggregateContract -Aggregate $r01Fixture @r01Expected) {
        throw 'I07 accepted a stale R01 candidate identity.'
    }
    $r01Fixture.candidate.commit = $r01Expected.ExpectedCommit
    $r01Fixture.remote.topology.mobile.interface_guid =
        '33333333-3333-3333-3333-333333333333'
    if (Test-I07R01AggregateContract -Aggregate $r01Fixture @r01Expected) {
        throw 'I07 accepted mismatched R01 interface GUIDs.'
    }
    $r01Fixture.remote.topology.mobile.interface_guid =
        '22222222-2222-2222-2222-222222222222'
    $r01Fixture.cleanup.complete = $false
    if (Test-I07R01AggregateContract -Aggregate $r01Fixture @r01Expected) {
        throw 'I07 accepted incomplete R01 cleanup.'
    }
    $r01Fixture.cleanup.complete = $true
    $r01Fixture.remote.candidate.remote_package_binding.
        extracted_file_set_exact = $false
    if (Test-I07R01AggregateContract -Aggregate $r01Fixture @r01Expected) {
        throw 'I07 accepted contradictory remote package evidence.'
    }
    $r01Fixture.remote.candidate.remote_package_binding.
        extracted_file_set_exact = $true
    $invalidR01Cases = @(
        [pscustomobject]@{
            name = 'status'; mutate = {
                param($Value) $Value.status = 'FAIL'
            }
        },
        [pscustomobject]@{
            name = 'case'; mutate = {
                param($Value) $Value.case_id = 'V91-R00'
            }
        },
        [pscustomobject]@{
            name = 'topology'; mutate = {
                param($Value) $Value.topology.id = 'T2'
            }
        },
        [pscustomobject]@{
            name = 'local candidate'; mutate = {
                param($Value) $Value.candidate.commit = '0' * 40
            }
        },
        [pscustomobject]@{
            name = 'remote candidate'; mutate = {
                param($Value) $Value.remote.candidate.commit = '0' * 40
            }
        }
    )
    foreach ($invalidR01Case in $invalidR01Cases) {
        $invalidR01 = (($r01SourceSnapshot.value |
            ConvertTo-Json -Depth 24 -Compress) | ConvertFrom-Json)
        & $invalidR01Case.mutate $invalidR01
        $invalidR01Snapshot = New-I07CanonicalJsonSnapshot `
            -Value $invalidR01
        try {
            $null = New-I07R01PrerequisiteSnapshot `
                -Aggregate $invalidR01 `
                -SourceSnapshot $invalidR01Snapshot `
                -CandidateIdentity $r01CandidateIdentity
            throw ("I07 R01 provenance accepted wrong " +
                [string]$invalidR01Case.name + '.')
        } catch {
            if ([string]$_.Exception.Message -ceq
                    ("I07 R01 provenance accepted wrong " +
                    [string]$invalidR01Case.name + '.')) { throw }
        }
    }
    $selfTestR01PassSnapshot = $r01Prerequisite
    $sourcePassContext.r01_prerequisite_sha256 =
        [string]$selfTestR01PassSnapshot.sha256
    $sourcePassContext.r01_prerequisite_bytes =
        [Int64]$selfTestR01PassSnapshot.byte_count
    $viewerPassContext.r01_prerequisite_sha256 =
        [string]$selfTestR01PassSnapshot.sha256
    $viewerPassContext.r01_prerequisite_bytes =
        [Int64]$selfTestR01PassSnapshot.byte_count
    $sourcePassFixture = New-I07PassProofSnapshot `
        -SourceSnapshot $sourcePassSourceSnapshot `
        -Context $sourcePassContext
    $viewerPassFixture = New-I07PassProofSnapshot `
        -SourceSnapshot $viewerPassSourceSnapshot `
        -Context $viewerPassContext
    $snapshotRoot = Join-Path ([IO.Path]::GetTempPath()) (
        'ese-i07-r01-snapshot-' + [Guid]::NewGuid().ToString('N'))
    try {
        New-Item -ItemType Directory -Path $snapshotRoot -Force | Out-Null
        $snapshotSource = Join-Path $snapshotRoot 'source.json'
        $snapshotCopy = Join-Path $snapshotRoot 'held.json'
        [IO.File]::WriteAllText($snapshotSource, '{"generation":1}',
            [Text.UTF8Encoding]::new($true))
        $held = Read-I07JsonByteSnapshot -Path $snapshotSource
        [IO.File]::WriteAllText($snapshotSource, '{"generation":2}',
            [Text.UTF8Encoding]::new($false))
        Write-I07HeldSnapshot -Snapshot $held -Path $snapshotCopy
        if ([int]$held.value.generation -ne 1 -or
            -not (Test-I07HeldSnapshotCopy -Snapshot $held `
                -Path $snapshotCopy)) {
            throw 'I07 R01 snapshot changed after its source path changed.'
        }
        [IO.File]::AppendAllText($snapshotCopy, ' ')
        if (Test-I07HeldSnapshotCopy -Snapshot $held -Path $snapshotCopy) {
            throw 'I07 accepted an altered retained R01 snapshot.'
        }
    } finally {
        if (Test-Path -LiteralPath $snapshotRoot) {
            $null = Remove-I07TreeNoReparse -Path $snapshotRoot `
                -ExpectedParent ([IO.Path]::GetTempPath())
        }
    }
    $ownedStage = Join-Path ([IO.Path]::GetTempPath()) (
        'ese-i07-stage-' + [Guid]::NewGuid().ToString('N') + '.json')
    [IO.File]::WriteAllText($ownedStage, '{"safe":true}',
        [Text.UTF8Encoding]::new($false))
    Remove-I07OwnedStagingFile -Path $ownedStage
    if (Test-Path -LiteralPath $ownedStage) {
        throw 'I07 staging cleanup left an owned regular file behind.'
    }
    $unsafeStage = Join-Path ([IO.Path]::GetTempPath()) (
        'not-owned-' + [Guid]::NewGuid().ToString('N') + '.json')
    [IO.File]::WriteAllText($unsafeStage, '{"safe":true}',
        [Text.UTF8Encoding]::new($false))
    try {
        Remove-I07OwnedStagingFile -Path $unsafeStage
        throw 'I07 staging cleanup accepted a non-owned path.'
    } catch {
        if ([string]$_.Exception.Message -ceq
            'I07 staging cleanup accepted a non-owned path.') { throw }
        if ([string]$_.Exception.Message -cne
            'STAGING_CLEANUP_NOT_PROVEN') { throw }
    }
    if (-not (Test-Path -LiteralPath $unsafeStage -PathType Leaf)) {
        throw 'I07 staging cleanup altered a non-owned path.'
    }
    Remove-Item -LiteralPath $unsafeStage -Force
    $lockedStage = Join-Path ([IO.Path]::GetTempPath()) (
        'ese-i07-stage-' + [Guid]::NewGuid().ToString('N') + '.json')
    [IO.File]::WriteAllText($lockedStage, '{"safe":true}',
        [Text.UTF8Encoding]::new($false))
    $lockedHandle = [IO.File]::Open(
        $lockedStage, [IO.FileMode]::Open, [IO.FileAccess]::Read,
        [IO.FileShare]::None)
    try {
        try {
            Remove-I07OwnedStagingFile -Path $lockedStage
            throw 'I07 staging cleanup accepted a locked residual.'
        } catch {
            if ([string]$_.Exception.Message -ceq
                'I07 staging cleanup accepted a locked residual.') { throw }
            if ([string]$_.Exception.Message -cne
                'STAGING_CLEANUP_NOT_PROVEN') { throw }
        }
        try {
            Assert-I07StagingCleanupProven
            throw 'I07 staging cleanup failure was silently swallowed.'
        } catch {
            if ([string]$_.Exception.Message -ceq
                'I07 staging cleanup failure was silently swallowed.') {
                throw
            }
            if ([string]$_.Exception.Message -cne
                'STAGING_CLEANUP_NOT_PROVEN') { throw }
        }
    } finally { $lockedHandle.Dispose() }
    Remove-I07OwnedStagingFile -Path $lockedStage
    Assert-I07StagingCleanupProven
    $junctionTarget = Join-Path ([IO.Path]::GetTempPath()) (
        'ese-i07-stage-target-' + [Guid]::NewGuid().ToString('N'))
    $junctionStage = Join-Path ([IO.Path]::GetTempPath()) (
        'ese-i07-stage-' + [Guid]::NewGuid().ToString('N') + '.json')
    try {
        New-Item -ItemType Directory -Path $junctionTarget -Force |
            Out-Null
        [IO.File]::WriteAllText((Join-Path $junctionTarget 'sentinel.txt'),
            'external', [Text.UTF8Encoding]::new($false))
        $null = New-Item -ItemType Junction -Path $junctionStage `
            -Target $junctionTarget
        try {
            Remove-I07OwnedStagingFile -Path $junctionStage
            throw 'I07 staging cleanup accepted a reparse staging path.'
        } catch {
            if ([string]$_.Exception.Message -ceq
                'I07 staging cleanup accepted a reparse staging path.') {
                throw
            }
            if ([string]$_.Exception.Message -cne
                'STAGING_CLEANUP_NOT_PROVEN') { throw }
        }
        [IO.Directory]::Delete($junctionStage)
        Remove-I07OwnedStagingFile -Path $junctionStage
        Assert-I07StagingCleanupProven
        if (-not (Test-Path -LiteralPath (
                Join-Path $junctionTarget 'sentinel.txt') -PathType Leaf)) {
            throw 'I07 staging reparse rejection altered its target.'
        }
    } finally {
        if (Test-Path -LiteralPath $junctionStage) {
            try { [IO.Directory]::Delete($junctionStage) } catch {}
        }
        if (Test-Path -LiteralPath $junctionTarget) {
            Remove-Item -LiteralPath $junctionTarget -Recurse -Force
        }
        if (-not (Test-Path -LiteralPath $junctionStage)) {
            Remove-I07OwnedStagingFile -Path $junctionStage
        }
    }
    $sourceClock = [pscustomobject]@{
        offset_lower_ms = -200.0; offset_upper_ms = 100.0
    }
    $viewerClock = [pscustomobject]@{
        offset_lower_ms = -100.0; offset_upper_ms = 150.0
    }
    $pairClock = Get-I07PairClockEvidence -Source $sourceClock `
        -Viewer $viewerClock
    if (-not [bool]$pairClock.valid -or
        [double]$pairClock.absolute_pair_offset_bound_ms -ne 350.0) {
        throw 'I07 pair-clock self-test rejected a bounded fixture.'
    }
    $viewerClock.offset_lower_ms = 950.0
    $viewerClock.offset_upper_ms = 1200.0
    if ([bool](Get-I07PairClockEvidence -Source $sourceClock `
            -Viewer $viewerClock).valid) {
        throw 'I07 pair-clock self-test accepted excessive clock skew.'
    }
    $controllerText = Get-Content -LiteralPath $PSCommandPath -Raw
    if ($controllerText -match '(?m)^\s*-ProfileSha256\s') {
        throw 'I07 controller retains an obsolete ProfileSha256 callsite.'
    }
    $wifiCalls = [regex]::Matches(
        $controllerText,
        '(?ms)Invoke-I07WifiTransition\s+-Action\s+(?:home|hotspot).*?' +
        '(?=\r?\n(?:if\s*\(|\$|\}))')
    if ($wifiCalls.Count -ne 4 -or @($wifiCalls | Where-Object {
            $_.Value -notmatch '-WlanProfileSha256\s' -or
            $_.Value -notmatch '-ConnectionProfileSha256\s' -or
            $_.Value -notmatch '-Nonce\s' -or
            $_.Value -notmatch '-HomeWlanProfileSha256\s' -or
            $_.Value -notmatch '-HomeConnectionProfileSha256\s'
        }).Count -ne 0) {
        throw 'I07 Wi-Fi transition callsites are not uniformly lease-bound.'
    }
    $privacyRoot = Join-Path ([IO.Path]::GetTempPath()) (
        'ese-i07-public-selftest-' + [Guid]::NewGuid().ToString('N'))
    $privacyPrivate = Join-Path $privacyRoot 'private'
    $passRoot = $privacyRoot + '-pass'
    $passPrivate = Join-Path $passRoot 'private'
    $failRoot = $privacyRoot + '-fail'
    $failPrivate = Join-Path $failRoot 'private'
    $externalRoot = $privacyRoot + '-external'
    $junctionPath = Join-Path $privacyPrivate 'nested-junction'
    $rootJunctionRun = $privacyRoot + '-root-junction-run'
    $rootJunctionPath = Join-Path $rootJunctionRun 'private'
    $knownSsid = 'Known-I07-SSID'
    $knownSsidSha = Get-I07TextSha256 -Value $knownSsid
    $rawControllerError =
        'controller_error=C:\Users\fixture\token.txt?key=' + ('d' * 32)
    try {
        New-Item -ItemType Directory -Path $privacyPrivate -Force |
            Out-Null
        [ordered]@{
            ssid = $knownSsid
            ssid_sha256 = $knownSsidSha
            path = 'C:\Users\fixture\private.json'
            ipv4 = '192.0.2.15'
            interface_guid = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
            token = 'a' * 64
            stream_key = 'b' * 32
            user_hash = 'c' * 32
            password = 'private-password'
            url = 'http://[2001:db8::15]/live?key=' + ('b' * 32)
            exception = $rawControllerError
            controller_error = $rawControllerError
        } | ConvertTo-Json | Set-Content -LiteralPath (
            Join-Path $privacyPrivate 'manifest.json') -Encoding UTF8
        $publicFixture = New-I07PublicAggregate -Status BLOCKED `
            -OutcomeCode READINESS_NOT_PROVEN -Candidate ([pscustomobject]@{
                version = '9.1.0-rc.2'; commit = '1' * 40
                emule_sha256 = '2' * 64; build_info_sha256 = '3' * 64
                zip_sha256 = '4' * 64; zip_bytes = 123
            }) -Checks ([ordered]@{
                r01_dependency_valid = $false
                agents_ready = $false
                baseline_clean = $false
                hotspot_transition_pass = $false
                hotspot_profile_match = $false
                source_preflight_pass = $false
                viewer_preflight_pass = $false
                source_result_received = $false
                viewer_result_received = $false
                product_evidence_complete = $false
                home_restore_pass = $false
                cleanup_terminal = $false
            }) -PrivateRoot $privacyPrivate -RunRoot $privacyRoot `
            -ExpectedNonce $nonce -ExpectedDurationSeconds 15 `
            -SensitiveValues @(
                $knownSsid, $knownSsidSha, 'C:\Users\fixture\private.json',
                '192.0.2.15', 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
                ('a' * 64), ('b' * 32), ('c' * 32), 'private-password',
                '?key=', $rawControllerError)
        $publicJson = $publicFixture | ConvertTo-Json -Depth 10 -Compress
        if ($publicJson -match [regex]::Escape($knownSsid) -or
            $publicJson -match [regex]::Escape($knownSsidSha) -or
            $publicJson -match 'C:\\Users|192\.0\.2\.15|2001:db8|\?key=' -or
            $publicJson -match 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' -or
            $publicJson -match 'controller_error|exception') {
            throw 'I07 public aggregate retained private fixture content.'
        }
        $publicFixture.checks.r01_dependency_valid = $true
        try {
            $null = Assert-I07PublicAggregatePrivacy `
                -Aggregate $publicFixture
            throw 'I07 BLOCKED accepted R01 true without its prerequisite.'
        } catch {
            if ([string]$_.Exception.Message -ceq
                'I07 BLOCKED accepted R01 true without its prerequisite.') {
                throw
            }
        }
        $publicFixture.checks.r01_dependency_valid = $false
        $publicFixture.outcome_code = 'PASS'
        try {
            $null = Assert-I07PublicAggregatePrivacy `
                -Aggregate $publicFixture
            throw 'I07 public aggregate accepted an incoherent outcome.'
        } catch {
            if ([string]$_.Exception.Message -ceq
                'I07 public aggregate accepted an incoherent outcome.') {
                throw
            }
        }
        $publicFixture.outcome_code = 'READINESS_NOT_PROVEN'
        $blockedProductArtifactNames = @(
            'source-pass-proof.json', 'viewer-pass-proof.json',
            'source-failure-proof.json', 'viewer-failure-proof.json')
        foreach ($name in $blockedProductArtifactNames) {
            Set-Content -LiteralPath (Join-Path $privacyPrivate $name) `
                -Value '{"raw_response":"must-not-be-retained"}' `
                -Encoding UTF8
        }
        $publicFixture.private_artifacts = @(
            Get-I07PrivateArtifactReferences -PrivateRoot $privacyPrivate `
                -RunRoot $privacyRoot)
        try {
            $null = Assert-I07PublicAggregatePrivacy -Aggregate $publicFixture
            throw 'BLOCKED_FULL_NODE_ARTIFACTS accepted.'
        } catch {
            if ([string]$_.Exception.Message -ceq
                'BLOCKED_FULL_NODE_ARTIFACTS accepted.') { throw }
        }
        foreach ($name in $blockedProductArtifactNames) {
            Remove-Item -LiteralPath (Join-Path $privacyPrivate $name) `
                -Force
        }
        $publicFixture.private_artifacts = @(
            Get-I07PrivateArtifactReferences -PrivateRoot $privacyPrivate `
                -RunRoot $privacyRoot)
        Set-Content -LiteralPath (Join-Path $privacyPrivate (
            '192.0.2.15-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa.json')) `
            -Value '{}' -Encoding UTF8
        try {
            $null = Get-I07PrivateArtifactReferences `
                -PrivateRoot $privacyPrivate -RunRoot $privacyRoot
            throw 'I07 public artifacts accepted a private identifier path.'
        } catch {
            if ([string]$_.Exception.Message -ceq
                'I07 public artifacts accepted a private identifier path.') {
                throw
            }
        }
        Remove-Item -LiteralPath (Join-Path $privacyPrivate (
            '192.0.2.15-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa.json')) `
            -Force

        New-Item -ItemType Directory -Path $externalRoot -Force |
            Out-Null
        Set-Content -LiteralPath (Join-Path $externalRoot 'sentinel.txt') `
            -Value 'external-sentinel' -Encoding UTF8
        $null = New-Item -ItemType Junction -Path $junctionPath `
            -Target $externalRoot
        try {
            $null = Get-I07PrivateArtifactReferences `
                -PrivateRoot $privacyPrivate -RunRoot $privacyRoot
            throw 'I07 public artifacts followed a nested junction.'
        } catch {
            if ([string]$_.Exception.Message -ceq
                'I07 public artifacts followed a nested junction.') {
                throw
            }
        }
        [IO.Directory]::Delete($junctionPath)
        if (-not (Test-Path -LiteralPath (
                Join-Path $externalRoot 'sentinel.txt') -PathType Leaf)) {
            throw 'I07 junction rejection damaged external evidence.'
        }
        New-Item -ItemType Directory -Path $rootJunctionRun -Force |
            Out-Null
        $null = New-Item -ItemType Junction -Path $rootJunctionPath `
            -Target $externalRoot
        try {
            $null = Get-I07PrivateArtifactReferences `
                -PrivateRoot $rootJunctionPath -RunRoot $rootJunctionRun
            throw 'I07 public artifacts accepted a junction private root.'
        } catch {
            if ([string]$_.Exception.Message -ceq
                'I07 public artifacts accepted a junction private root.') {
                throw
            }
        }
        [IO.Directory]::Delete($rootJunctionPath)
        if (-not (Test-Path -LiteralPath (
                Join-Path $externalRoot 'sentinel.txt') -PathType Leaf)) {
            throw 'I07 root-junction rejection damaged external evidence.'
        }

        New-Item -ItemType Directory -Path $passPrivate -Force |
            Out-Null
        $passArtifactNames = @(
            'manifest.json',
            'r01-prerequisite.json',
            'source-baseline-request.json', 'source-baseline-result.json',
            'viewer-baseline-request.json', 'viewer-baseline-result.json',
            'viewer-hotspot-transition.json',
            'viewer-hotspot-transition.json.request.json',
            'source-preflight-request.json', 'source-preflight-result.json',
            'viewer-preflight-request.json', 'viewer-preflight-result.json',
            'source-request.json', 'source-pass-proof.json',
            'viewer-request.json', 'viewer-pass-proof.json',
            'viewer-home-restore.json',
            'viewer-home-restore.json.request.json')
        foreach ($name in $passArtifactNames) {
            $path = Join-Path $passPrivate $name
            if ($name -ceq 'r01-prerequisite.json') {
                [IO.File]::WriteAllBytes($path,
                    [byte[]]$selfTestR01PassSnapshot.bytes_value)
            } elseif ($name -ceq 'source-pass-proof.json') {
                [IO.File]::WriteAllBytes($path,
                    [byte[]]$sourcePassFixture.bytes_value)
            } elseif ($name -ceq 'viewer-pass-proof.json') {
                [IO.File]::WriteAllBytes($path,
                    [byte[]]$viewerPassFixture.bytes_value)
            } else {
                Set-Content -LiteralPath $path -Value '{"safe":true}' `
                    -Encoding UTF8
            }
        }
        $trueChecks = [ordered]@{
            r01_dependency_valid = $true; agents_ready = $true
            baseline_clean = $true; hotspot_transition_pass = $true
            hotspot_profile_match = $true; source_preflight_pass = $true
            viewer_preflight_pass = $true; source_result_received = $true
            viewer_result_received = $true
            product_evidence_complete = $true; home_restore_pass = $true
            cleanup_terminal = $true
        }
        $passFixture = New-I07PublicAggregate -Status PASS `
            -OutcomeCode PASS -Candidate ([pscustomobject]@{
                version = '9.1.0-rc.2'; commit = '1' * 40
                emule_sha256 = $sha; build_info_sha256 = 'd' * 64
                zip_sha256 = '4' * 64; zip_bytes = 123
            }) -Checks $trueChecks -PrivateRoot $passPrivate `
            -RunRoot $passRoot -ExpectedNonce $nonce `
            -ExpectedDurationSeconds 15 `
            -SourcePassProofSnapshot $sourcePassFixture `
            -ViewerPassProofSnapshot $viewerPassFixture `
            -SourceResultSnapshot $sourcePassSourceSnapshot `
            -ViewerResultSnapshot $viewerPassSourceSnapshot `
            -SourcePassContext $sourcePassContext `
            -ViewerPassContext $viewerPassContext `
            -R01PrerequisiteSnapshot $selfTestR01PassSnapshot `
            -R01SourceSnapshot $r01SourceSnapshot
        $passBundleArgs = @{
            Status = 'PASS'; Candidate = $passFixture.candidate
            Artifacts = @($passFixture.private_artifacts)
            PrivateRoot = $passPrivate; ExpectedNonce = $nonce
            ExpectedDurationSeconds = 15
            SourcePassProofSnapshot = $sourcePassFixture
            ViewerPassProofSnapshot = $viewerPassFixture
            SourceResultSnapshot = $sourcePassSourceSnapshot
            ViewerResultSnapshot = $viewerPassSourceSnapshot
            SourcePassContext = $sourcePassContext
            ViewerPassContext = $viewerPassContext
            R01PrerequisiteSnapshot = $selfTestR01PassSnapshot
            R01SourceSnapshot = $r01SourceSnapshot
        }
        $badPassArgs = $passBundleArgs.Clone()
        $badCandidate = (($passFixture.candidate |
            ConvertTo-Json -Compress) | ConvertFrom-Json)
        $badCandidate.zip_bytes = [Int64]$badCandidate.zip_bytes + 1
        $badPassArgs.Candidate = $badCandidate
        if (Test-I07TerminalProofBundle @badPassArgs) {
            throw 'I07 terminal PASS accepted a different candidate tuple.'
        }
        $badPassArgs = $passBundleArgs.Clone()
        $badPassArgs.ExpectedNonce = 'f' * 32
        if (Test-I07TerminalProofBundle @badPassArgs) {
            throw 'I07 terminal PASS accepted a different nonce.'
        }
        $badPassArgs = $passBundleArgs.Clone()
        $badPassArgs.ExpectedDurationSeconds = 16
        if (Test-I07TerminalProofBundle @badPassArgs) {
            throw 'I07 terminal PASS accepted a different duration.'
        }
        $badPassArgs = $passBundleArgs.Clone()
        $badPassArgs.SourcePassProofSnapshot = $viewerPassFixture
        $badPassArgs.ViewerPassProofSnapshot = $sourcePassFixture
        if (Test-I07TerminalProofBundle @badPassArgs) {
            throw 'I07 terminal PASS accepted swapped role proofs.'
        }
        $badArtifactRefs = @($passFixture.private_artifacts |
            ForEach-Object { [pscustomobject][ordered]@{
                path = [string]$_.path; bytes = [Int64]$_.bytes
                sha256 = [string]$_.sha256
            } })
        $badR01Refs = @($badArtifactRefs | Where-Object {
            [string]$_.path -ceq 'private/r01-prerequisite.json'
        })
        if ($badR01Refs.Count -ne 1) {
            throw 'I07 terminal PASS R01 fixture ref is missing.'
        }
        $badR01Refs[0].sha256 = '0' * 64
        $badPassArgs = $passBundleArgs.Clone()
        $badPassArgs.Artifacts = $badArtifactRefs
        if (Test-I07TerminalProofBundle @badPassArgs) {
            throw 'I07 terminal PASS accepted a stale R01 artifact ref.'
        }
        $sourcePassPath = Join-Path $passPrivate 'source-pass-proof.json'
        try {
            [IO.File]::AppendAllText($sourcePassPath, ' ')
            if (Test-I07TerminalProofBundle @passBundleArgs) {
                throw 'I07 terminal PASS accepted altered proof bytes.'
            }
        } finally {
            [IO.File]::WriteAllBytes($sourcePassPath,
                [byte[]]$sourcePassFixture.bytes_value)
        }
        $badSourcePassValue = (($sourcePassFixture.value |
            ConvertTo-Json -Depth 24 -Compress) | ConvertFrom-Json)
        $badSourcePassValue.PSObject.Properties.Remove('role')
        $badSourcePassSnapshot = New-I07CanonicalJsonSnapshot `
            -Value $badSourcePassValue
        try {
            [IO.File]::WriteAllBytes($sourcePassPath,
                [byte[]]$badSourcePassSnapshot.bytes_value)
            $badPassArgs = $passBundleArgs.Clone()
            $badPassArgs.SourcePassProofSnapshot = $badSourcePassSnapshot
            $badPassArgs.Artifacts = @(Get-I07PrivateArtifactReferences `
                -PrivateRoot $passPrivate -RunRoot $passRoot)
            if (Test-I07TerminalProofBundle @badPassArgs) {
                throw 'I07 terminal PASS accepted an invalid proof shape.'
            }
        } finally {
            [IO.File]::WriteAllBytes($sourcePassPath,
                [byte[]]$sourcePassFixture.bytes_value)
        }
        $passFixture.checks.agents_ready = $false
        try {
            $null = Assert-I07PublicAggregatePrivacy -Aggregate $passFixture
            throw 'I07 public PASS accepted a false check.'
        } catch {
            if ([string]$_.Exception.Message -ceq
                'I07 public PASS accepted a false check.') { throw }
        }
        $passFixture.checks.agents_ready = $true
        $savedArtifacts = @($passFixture.private_artifacts)
        $passFixture.private_artifacts = @($savedArtifacts | Select-Object `
            -Skip 1)
        try {
            $null = Assert-I07PublicAggregatePrivacy -Aggregate $passFixture
            throw 'I07 public PASS accepted an omitted artifact.'
        } catch {
            if ([string]$_.Exception.Message -ceq
                'I07 public PASS accepted an omitted artifact.') { throw }
        }
        $passFixture.private_artifacts = @($savedArtifacts +
            $savedArtifacts[0])
        try {
            $null = Assert-I07PublicAggregatePrivacy -Aggregate $passFixture
            throw 'I07 public PASS accepted a duplicate artifact.'
        } catch {
            if ([string]$_.Exception.Message -ceq
                'I07 public PASS accepted a duplicate artifact.') { throw }
        }
        $passFixture.private_artifacts = @($savedArtifacts)
        $savedFirstBytes = [Int64]$passFixture.private_artifacts[0].bytes
        $passFixture.private_artifacts[0].bytes = 0
        try {
            $null = Assert-I07PublicAggregatePrivacy -Aggregate $passFixture
            throw 'I07 public PASS accepted a zero-byte artifact.'
        } catch {
            if ([string]$_.Exception.Message -ceq
                'I07 public PASS accepted a zero-byte artifact.') { throw }
        }
        $passFixture.private_artifacts[0].bytes = $savedFirstBytes
        $passFixture.private_artifacts = @()
        try {
            $null = Assert-I07PublicAggregatePrivacy -Aggregate $passFixture
            throw 'I07 public PASS accepted an empty artifact set.'
        } catch {
            if ([string]$_.Exception.Message -ceq
                'I07 public PASS accepted an empty artifact set.') { throw }
        }
        $passFixture.private_artifacts = @($savedArtifacts)
        $passFixture.checks.PSObject.Properties.Remove('agents_ready')
        try {
            $null = Assert-I07PublicAggregatePrivacy -Aggregate $passFixture
            throw 'I07 public PASS accepted an omitted check.'
        } catch {
            if ([string]$_.Exception.Message -ceq
                'I07 public PASS accepted an omitted check.') { throw }
        }

        New-Item -ItemType Directory -Path $failPrivate -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $failPrivate 'manifest.json') `
            -Value '{"safe":true}' -Encoding UTF8
        [IO.File]::WriteAllBytes(
            (Join-Path $failPrivate 'r01-prerequisite.json'),
            [byte[]]$selfTestR01PassSnapshot.bytes_value)
        [IO.File]::WriteAllBytes(
            (Join-Path $failPrivate 'viewer-failure-proof.json'),
            [byte[]]$failProof.bytes_value)
        $failChecks = [ordered]@{
            r01_dependency_valid = $true; agents_ready = $true
            baseline_clean = $true; hotspot_transition_pass = $true
            hotspot_profile_match = $true; source_preflight_pass = $true
            viewer_preflight_pass = $true; source_result_received = $false
            viewer_result_received = $true
            product_evidence_complete = $true; home_restore_pass = $true
            cleanup_terminal = $true
        }
        $publicFail = New-I07PublicAggregate -Status FAIL `
            -OutcomeCode PRODUCT_INVARIANT -Candidate ([pscustomobject]@{
                version = '9.1.0-rc.2'; commit = '1' * 40
                emule_sha256 = $sha; build_info_sha256 = 'd' * 64
                zip_sha256 = '4' * 64; zip_bytes = 123
            }) -Checks $failChecks -PrivateRoot $failPrivate `
            -RunRoot $failRoot -ExpectedNonce $nonce `
            -ExpectedDurationSeconds 15 `
            -ViewerFailureProofSnapshot $failProof `
            -ViewerResultSnapshot $failSourceSnapshot `
            -ViewerFailureContext $failProofContext `
            -R01PrerequisiteSnapshot $selfTestR01PassSnapshot `
            -R01SourceSnapshot $r01SourceSnapshot
        $failBundleArgs = @{
            Status = 'FAIL'; Candidate = $publicFail.candidate
            Artifacts = @($publicFail.private_artifacts)
            PrivateRoot = $failPrivate; ExpectedNonce = $nonce
            ExpectedDurationSeconds = 15
            ViewerFailureProofSnapshot = $failProof
            ViewerResultSnapshot = $failSourceSnapshot
            ViewerFailureContext = $failProofContext
            R01PrerequisiteSnapshot = $selfTestR01PassSnapshot
            R01SourceSnapshot = $r01SourceSnapshot
        }
        $badFailArgs = $failBundleArgs.Clone()
        $badFailCandidate = (($publicFail.candidate |
            ConvertTo-Json -Compress) | ConvertFrom-Json)
        $badFailCandidate.emule_sha256 = '0' * 64
        $badFailArgs.Candidate = $badFailCandidate
        if (Test-I07TerminalProofBundle @badFailArgs) {
            throw 'I07 terminal FAIL accepted a different candidate tuple.'
        }
        $badFailArgs = $failBundleArgs.Clone()
        $badFailArgs.ExpectedNonce = 'f' * 32
        if (Test-I07TerminalProofBundle @badFailArgs) {
            throw 'I07 terminal FAIL accepted a different nonce.'
        }
        $badFailRefs = @($publicFail.private_artifacts |
            ForEach-Object { [pscustomobject][ordered]@{
                path = [string]$_.path; bytes = [Int64]$_.bytes
                sha256 = [string]$_.sha256
            } })
        $badViewerFailRefs = @($badFailRefs | Where-Object {
            [string]$_.path -ceq 'private/viewer-failure-proof.json'
        })
        if ($badViewerFailRefs.Count -ne 1) {
            throw 'I07 terminal FAIL proof fixture ref is missing.'
        }
        $badViewerFailRefs[0].sha256 = '0' * 64
        $badFailArgs = $failBundleArgs.Clone()
        $badFailArgs.Artifacts = $badFailRefs
        if (Test-I07TerminalProofBundle @badFailArgs) {
            throw 'I07 terminal FAIL accepted a stale proof artifact ref.'
        }
        $savedFailArtifacts = @($publicFail.private_artifacts)
        $publicFail.private_artifacts = @(
            $savedFailArtifacts | Where-Object {
                [string]$_.path -cne
                    'private/viewer-failure-proof.json'
            })
        try {
            $null = Assert-I07PublicAggregatePrivacy -Aggregate $publicFail
            throw 'I07 public FAIL accepted no sanitized proof.'
        } catch {
            if ([string]$_.Exception.Message -ceq
                'I07 public FAIL accepted no sanitized proof.') { throw }
        }
        $publicFail.private_artifacts = @($savedFailArtifacts)
        Set-Content -LiteralPath (
            Join-Path $failPrivate 'viewer-pass-proof.json') `
            -Value '{"safe":true}' -Encoding UTF8
        $publicFail.private_artifacts = @(Get-I07PrivateArtifactReferences `
            -PrivateRoot $failPrivate -RunRoot $failRoot)
        try {
            $null = Assert-I07PublicAggregatePrivacy -Aggregate $publicFail
            throw 'I07 public FAIL accepted a PASS proof artifact.'
        } catch {
            if ([string]$_.Exception.Message -ceq
                'I07 public FAIL accepted a PASS proof artifact.') { throw }
        }
    } finally {
        if (Test-Path -LiteralPath $junctionPath) {
            try { [IO.Directory]::Delete($junctionPath) } catch {}
        }
        if (Test-Path -LiteralPath $rootJunctionPath) {
            try { [IO.Directory]::Delete($rootJunctionPath) } catch {}
        }
        Remove-Item -LiteralPath $privacyRoot -Recurse -Force `
            -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $passRoot -Recurse -Force `
            -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $failRoot -Recurse -Force `
            -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $externalRoot -Recurse -Force `
            -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $rootJunctionRun -Recurse -Force `
            -ErrorAction SilentlyContinue
    }
    return [pscustomobject]@{
        status = 'PASS'
        aggregate_contract_suite = 'PASS'
        r01_source_binding_suite = 'PASS'
        terminal_proof_bundle_suite = 'PASS'
        public_privacy_suite = 'PASS'
        staging_cleanup_suite = 'PASS'
        detached_snapshot_suite = 'PASS'
        clock_fixture_suite = 'PASS'
        wifi_callsites = $wifiCalls.Count
    }
}

foreach ($path in @(
    $agentController, $commonScript, $preflightScript, $nodeScript,
    $baselineScript, $wifiScript, $wifiWatchdogScript)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required I07 tool is missing: $path"
    }
}
if ([string]::IsNullOrWhiteSpace($OutputRoot)) {
    $OutputRoot = Join-Path $PSScriptRoot '..\..\lab-runs\v91-i07'
}

function Invoke-I07Agent {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('source', 'viewer')][string]$Role,
        [Parameter(Mandatory = $true)][string]$Command,
        [hashtable]$Extra = @{}
    )
    $isSource = $Role -ceq 'source'
    $arguments = @{
        Command = $Command
        AgentIPv4 = if ($isSource) {
            $SourceAgentIPv4
        } else { $ViewerAgentIPv4 }
        Port = if ($isSource) { $SourceAgentPort } else { $ViewerAgentPort }
        TokenDpapiPath = if ($isSource) {
            $SourceTokenDpapiPath
        } else { $ViewerTokenDpapiPath }
    }
    foreach ($key in $Extra.Keys) { $arguments[$key] = $Extra[$key] }
    & $agentController @arguments
}

function Test-I07UtcRetentionString {
    param([AllowNull()]$Value)
    if (-not (Test-I07StrictString -Value $Value)) { return $false }
    $parsed = [DateTimeOffset]::MinValue
    return ([DateTimeOffset]::TryParse(
            [string]$Value,
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind,
            [ref]$parsed) -and $parsed.Offset -eq [TimeSpan]::Zero)
}

function Test-I07Sha256RetentionString {
    param([AllowNull()]$Value)
    return ((Test-I07StrictString -Value $Value) -and
        [string]$Value -cmatch '^[0-9a-f]{64}$')
}

function Test-I07NonceRetentionString {
    param([AllowNull()]$Value)
    return ((Test-I07StrictString -Value $Value) -and
        [string]$Value -cmatch '^[0-9a-f]{32}$')
}

function Test-I07GuidRetentionString {
    param([AllowNull()]$Value, [switch]$AllowEmpty)
    if ($AllowEmpty -and $Value -is [string] -and
        [string]::IsNullOrEmpty([string]$Value)) { return $true }
    if (-not (Test-I07StrictString -Value $Value)) { return $false }
    $guid = [Guid]::Empty
    return ([Guid]::TryParse([string]$Value, [ref]$guid) -and
        $guid -ne [Guid]::Empty)
}

function ConvertTo-I07RetentionGuid {
    param([Parameter(Mandatory = $true)][string]$Value)
    $guid = [Guid]::Empty
    if (-not [Guid]::TryParse($Value, [ref]$guid) -or
        $guid -eq [Guid]::Empty) { throw 'Invalid retained GUID.' }
    return $guid.ToString('D').ToLowerInvariant()
}

function Test-I07IPv6RetentionString {
    param([AllowNull()]$Value, [switch]$AllowEmpty)
    if ($AllowEmpty -and $Value -is [string] -and
        [string]::IsNullOrEmpty([string]$Value)) { return $true }
    if (-not (Test-I07StrictString -Value $Value)) { return $false }
    $address = $null
    return ([Net.IPAddress]::TryParse([string]$Value, [ref]$address) -and
        $address.AddressFamily -eq
            [Net.Sockets.AddressFamily]::InterNetworkV6)
}

function Test-I07SafeRetentionScalarTree {
    param([AllowNull()]$Value, [int]$Depth = 0)
    if ($Depth -gt 32) { return $false }
    if ($null -eq $Value -or $Value.GetType().IsPrimitive -or
        $Value -is [decimal]) { return $true }
    if ($Value -is [string]) {
        $text = [string]$Value
        return ($text.Length -le 512 -and
            $text -notmatch '[\x00-\x08\x0b\x0c\x0e-\x1f]' -and
            $text -notmatch '(?i)(?:^|[\s''"=])(?:[a-z]:\\|\\\\|/home/|/users/)' -and
            $text -notmatch '(?i)\b(?:https?|file)://' -and
            $text -notmatch '(?i)(?:token|password|secret|authorization|cookie|stream[_-]?key)\s*[:=]')
    }
    if ($Value -is [Collections.IDictionary]) {
        foreach ($key in $Value.Keys) {
            if (-not (Test-I07SafeRetentionScalarTree -Value $Value[$key] `
                    -Depth ($Depth + 1))) { return $false }
        }
        return $true
    }
    if ($Value -is [Collections.IEnumerable] -and
        -not ($Value -is [pscustomobject])) {
        foreach ($item in $Value) {
            if (-not (Test-I07SafeRetentionScalarTree -Value $item `
                    -Depth ($Depth + 1))) { return $false }
        }
        return $true
    }
    foreach ($property in $Value.PSObject.Properties) {
        if (-not (Test-I07SafeRetentionScalarTree -Value $property.Value `
                -Depth ($Depth + 1))) { return $false }
    }
    return $true
}

function Test-I07WifiProfileRetentionContract {
    param(
        [Parameter(Mandatory = $true)]$Profile,
        [Parameter(Mandatory = $true)][string]$ConnectionSha256,
        [Parameter(Mandatory = $true)][string]$WlanSha256,
        [Parameter(Mandatory = $true)][string]$InterfaceGuid
    )
    try {
        if (-not (Test-I07ExactPropertySet -Value $Profile -Expected @(
                'connection_profile', 'wlan_profile'))) { return $false }
        $connection = $Profile.connection_profile
        $wlan = $Profile.wlan_profile
        if (-not (Test-I07ExactPropertySet -Value $connection -Expected @(
                'schema', 'interface_index', 'interface_guid',
                'profile_sha256', 'network_category', 'ipv4_connectivity',
                'ipv6_connectivity')) -or
            -not (Test-I07ExactPropertySet -Value $wlan -Expected @(
                'schema', 'interface_index', 'interface_guid',
                'wlan_profile_sha256')) -or
            [string]$connection.schema -cne
                'ese.v91.r01-hotspot-profile-fingerprint/v1' -or
            [string]$wlan.schema -cne
                'ese.v91.i07-current-wlan-profile/v1' -or
            -not (Test-I07StrictInteger -Value $connection.interface_index `
                -Minimum 1) -or
            -not (Test-I07StrictInteger -Value $wlan.interface_index `
                -Minimum 1) -or
            [Int64]$connection.interface_index -ne
                [Int64]$wlan.interface_index -or
            -not (Test-I07Sha256RetentionString `
                -Value $connection.profile_sha256) -or
            -not (Test-I07Sha256RetentionString `
                -Value $wlan.wlan_profile_sha256) -or
            [string]$connection.profile_sha256 -cne $ConnectionSha256 -or
            [string]$wlan.wlan_profile_sha256 -cne $WlanSha256 -or
            [string]$connection.network_category -cnotin @(
                'Public', 'Private', 'DomainAuthenticated') -or
            [string]$connection.ipv4_connectivity -cnotin @(
                'Disconnected', 'NoTraffic', 'Subnet', 'LocalNetwork',
                'Internet', 'ConstrainedInternet', 'Unknown') -or
            [string]$connection.ipv6_connectivity -cnotin @(
                'Disconnected', 'NoTraffic', 'Subnet', 'LocalNetwork',
                'Internet', 'ConstrainedInternet', 'Unknown')) {
            return $false
        }
        $expectedGuid = ConvertTo-I07RetentionGuid -Value $InterfaceGuid
        return ((ConvertTo-I07RetentionGuid `
                    -Value ([string]$connection.interface_guid)) -ceq
                $expectedGuid -and
            (ConvertTo-I07RetentionGuid `
                    -Value ([string]$wlan.interface_guid)) -ceq
                $expectedGuid)
    } catch { return $false }
}

function Test-I07BaselineRetentionContext {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)]$Context
    )
    try {
        $actualTcp = @($Value.tcp_ports | ForEach-Object {
                [Int64]$_.port } | Sort-Object)
        $actualUdp = @($Value.udp_ports | ForEach-Object {
                [Int64]$_.port } | Sort-Object)
        $expectedTcp = @($Context.tcp_ports | ForEach-Object {
                [Int64]$_ } | Sort-Object)
        $expectedUdp = @($Context.udp_ports | ForEach-Object {
                [Int64]$_ } | Sort-Object)
        return ([string]$Value.role -ceq [string]$Context.role -and
            [string]$Value.nonce -ceq [string]$Context.nonce -and
            (@($actualTcp) -join ',') -ceq (@($expectedTcp) -join ',') -and
            (@($actualUdp) -join ',') -ceq (@($expectedUdp) -join ','))
    } catch { return $false }
}

function Test-I07PreflightRetentionContext {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)]$Context
    )
    try {
        $actualRemote = ConvertTo-I07CanonicalIPv6 `
            -Value ([string]$Value.selected_route.remote_address)
        $expectedRemote = ConvertTo-I07CanonicalIPv6 `
            -Value ([string]$Context.route_target_ipv6)
        return ([string]$Value.role -ceq [string]$Context.role -and
            [string]$Value.nonce -ceq [string]$Context.nonce -and
            [string]$Value.candidate_sha256 -ceq
                [string]$Context.candidate_sha256 -and
            $actualRemote -ceq $expectedRemote -and
            (Get-I07IPv6Class -Address ([Net.IPAddress]::Parse(
                $actualRemote))) -ceq 'global-native' -and
            [string]$Value.selected_route.remote_class -ceq
                'global-native')
    } catch { return $false }
}

function Test-I07WifiRetentionContext {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)]$Context
    )
    try {
        if ([string]$Value.action -cne [string]$Context.action -or
            [string]$Value.nonce -cne [string]$Context.nonce -or
            [string]$Value.target_wlan_profile_sha256 -cne
                [string]$Context.target_wlan_profile_sha256 -or
            [string]$Value.expected_connection_profile_sha256 -cne
                [string]$Context.expected_connection_profile_sha256 -or
            [string]$Value.home_wlan_profile_sha256 -cne
                [string]$Context.home_wlan_profile_sha256 -or
            [string]$Value.home_connection_profile_sha256 -cne
                [string]$Context.home_connection_profile_sha256 -or
            (ConvertTo-I07RetentionGuid `
                -Value ([string]$Value.interface_guid)) -cne
            (ConvertTo-I07RetentionGuid `
                -Value ([string]$Context.interface_guid))) {
            return $false
        }
        if ([string]$Value.status -cne 'PASS') { return $true }
        if ([string]$Value.action -ceq 'hotspot') {
            $armed = [DateTimeOffset]::Parse(
                [string]$Value.watchdog.armed_at_utc)
            $deadline = [DateTimeOffset]::Parse(
                [string]$Value.watchdog.deadline_utc)
            return (($deadline - $armed).TotalSeconds -ge
                    ([int]$Context.lease_seconds - 20) -and
                ($deadline - $armed).TotalSeconds -le
                    [int]$Context.lease_seconds)
        }
        if (-not (Test-I07StrictInteger `
                -Value $Context.expected_watchdog_pid -Minimum 1) -or
            [string]::IsNullOrWhiteSpace(
                [string]$Context.expected_watchdog_armed_at_utc) -or
            [string]::IsNullOrWhiteSpace(
                [string]$Context.expected_watchdog_deadline_utc) -or
            [Int64]$Value.watchdog.watchdog_pid -ne
                [Int64]$Context.expected_watchdog_pid -or
            [Int64]$Value.watchdog_disarm.watchdog_pid -ne
                [Int64]$Context.expected_watchdog_pid) { return $false }
        $expectedArmed = [DateTimeOffset]::Parse(
            [string]$Context.expected_watchdog_armed_at_utc)
        $expectedDeadline = [DateTimeOffset]::Parse(
            [string]$Context.expected_watchdog_deadline_utc)
        $watchStarted = [DateTimeOffset]::Parse(
            [string]$Value.watchdog.started_at_utc)
        $watchCompleted = [DateTimeOffset]::Parse(
            [string]$Value.watchdog.completed_at_utc)
        $disarmed = [DateTimeOffset]::Parse(
            [string]$Value.watchdog_disarm.disarmed_at_utc)
        $completed = [DateTimeOffset]::Parse(
            [string]$Value.completed_at_utc)
        return ($watchStarted -le $expectedArmed -and
            $expectedArmed -le $watchCompleted -and
            $watchCompleted -le $disarmed -and $disarmed -le $completed -and
            $completed -lt $expectedDeadline)
    } catch { return $false }
}

function Test-I07NodeRetentionContext {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)]$Context
    )
    try {
        if ([string]$Value.role -cne [string]$Context.role -or
            [string]$Value.nonce -cne [string]$Context.nonce -or
            [string]$Value.candidate.requested_sha256 -cne
                [string]$Context.candidate_sha256) { return $false }
        if ([string]$Value.status -ceq 'LAB_BLOCKED' -and
            (Get-I07ObjectPropertyNames -Value $Value.candidate).Count -eq 2) {
            return ((Test-I07StrictBoolean -Value $Value.candidate.verified) `
                -and -not [bool]$Value.candidate.verified)
        }
        $candidate = $Value.candidate
        if (-not (Test-I07StrictBoolean -Value $candidate.verified) -or
            -not [bool]$candidate.verified -or
            [string]$candidate.sha256 -cne
                [string]$Context.candidate_sha256 -or
            [string]$candidate.commit -cne [string]$Context.commit -or
            [string]$candidate.build_info_sha256 -cne
                [string]$Context.build_info_sha256 -or
            [string]$candidate.zip_sha256 -cne
                [string]$Context.zip_sha256 -or
            -not (Test-I07StrictInteger -Value $candidate.zip_bytes `
                -Minimum 1) -or
            [Int64]$candidate.zip_bytes -ne [Int64]$Context.zip_bytes -or
            -not (Test-I07StrictBoolean -Value $candidate.zip_verified) -or
            -not [bool]$candidate.zip_verified) { return $false }
        $actualFiles = @(Assert-I07CriticalPackageContract `
            -Files $candidate.package_files | Sort-Object path)
        $expectedFiles = @(Assert-I07CriticalPackageContract `
            -Files $Context.package_files | Sort-Object path)
        $actualCanonical = @($actualFiles | ForEach-Object {
                '{0}|{1}|{2}' -f $_.path, [Int64]$_.bytes, $_.sha256
            }) -join "`n"
        $expectedCanonical = @($expectedFiles | ForEach-Object {
                '{0}|{1}|{2}' -f $_.path, [Int64]$_.bytes, $_.sha256
            }) -join "`n"
        if ($actualCanonical -cne $expectedCanonical) { return $false }
        $binding = $candidate.zip_binding
        if (-not (Test-I07ExactPropertySet -Value $binding -Expected @(
                'schema', 'verified', 'zip_sha256', 'zip_bytes',
                'critical_file_count', 'critical_files')) -or
            [string]$binding.schema -cne
                'ese.v91.i07-node-zip-binding/v2' -or
            -not (Test-I07StrictBoolean -Value $binding.verified) -or
            -not [bool]$binding.verified -or
            [string]$binding.zip_sha256 -cne
                [string]$Context.zip_sha256 -or
            -not (Test-I07StrictInteger -Value $binding.zip_bytes `
                -Minimum 1) -or
            [Int64]$binding.zip_bytes -ne [Int64]$Context.zip_bytes -or
            -not (Test-I07StrictInteger `
                -Value $binding.critical_file_count -Minimum 7 -Maximum 100000) -or
            [Int64]$binding.critical_file_count -ne $expectedFiles.Count) {
            return $false
        }
        $bindingFiles = @(Assert-I07CriticalPackageContract `
            -Files $binding.critical_files | Sort-Object path)
        $bindingCanonical = @($bindingFiles | ForEach-Object {
                '{0}|{1}|{2}' -f $_.path, [Int64]$_.bytes, $_.sha256
            }) -join "`n"
        if ($bindingCanonical -cne $expectedCanonical -or
            [string]$Value.topology.topology_id -cne 'T3') { return $false }
        $identity = $candidate.process_identity
        $launch = $candidate.launch_binding
        if (-not (Test-I07ExactPropertySet -Value $identity -Expected @(
                'schema', 'process_id', 'start_time_utc',
                'executable_path_sha256', 'executable_sha256',
                'user_sid_sha256')) -or
            [string]$identity.schema -cne
                'ese.v91.i07-process-identity/v1' -or
            -not (Test-I07StrictInteger -Value $identity.process_id `
                -Minimum 1) -or
            [Int64]$identity.process_id -ne [Int64]$candidate.pid -or
            -not (Test-I07UtcRetentionString `
                -Value $identity.start_time_utc) -or
            [string]$identity.start_time_utc -cne
                [string]$candidate.started_at_utc -or
            [string]$identity.executable_path_sha256 -cnotmatch
                '^[0-9a-f]{64}$' -or
            [string]$identity.executable_sha256 -cne
                [string]$Context.candidate_sha256 -or
            [string]$identity.user_sid_sha256 -cne
                [string]$Context.expected_user_sid_sha256 -or
            -not (Test-I07ExactPropertySet -Value $launch -Expected @(
                'schema', 'verified', 'static_file_count',
                'static_manifest_sha256', 'preferences_sha256',
                'preferences_bytes', 'candidate_sha256')) -or
            [string]$launch.schema -cne
                'ese.v91.i07-prelaunch-binding/v1' -or
            -not (Test-I07StrictBoolean -Value $launch.verified) -or
            -not [bool]$launch.verified -or
            -not (Test-I07StrictInteger -Value $launch.static_file_count `
                -Minimum 7 -Maximum 100000) -or
            [Int64]$launch.static_file_count -ne $expectedFiles.Count -or
            [string]$launch.static_manifest_sha256 -cne
                (Get-I07PackageManifestSha256 -Files $expectedFiles) -or
            [string]$launch.preferences_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            -not (Test-I07StrictInteger -Value $launch.preferences_bytes `
                -Minimum 1) -or
            [string]$launch.candidate_sha256 -cne
                [string]$Context.candidate_sha256) {
            return $false
        }
        if ($null -ne $Context.PSObject.Properties['local_ipv6']) {
            if ((ConvertTo-I07CanonicalIPv6 `
                    -Value ([string]$Value.topology.local_ipv6)) -cne
                    (ConvertTo-I07CanonicalIPv6 `
                        -Value ([string]$Context.local_ipv6)) -or
                (ConvertTo-I07CanonicalIPv6 `
                    -Value ([string]$Value.topology.peer_ipv6)) -cne
                    (ConvertTo-I07CanonicalIPv6 `
                        -Value ([string]$Context.peer_ipv6)) -or
                [Int64]$Value.topology.interface_index -ne
                    [Int64]$Context.interface_index -or
                (ConvertTo-I07RetentionGuid `
                    -Value ([string]$Value.topology.interface_guid)) -cne
                    (ConvertTo-I07RetentionGuid `
                        -Value ([string]$Context.interface_guid))) {
                return $false
            }
        }
        return $true
    } catch { return $false }
}

function New-I07RetentionContextValidator {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('node', 'baseline', 'preflight', 'wifi')][string]$Kind,
        [Parameter(Mandatory = $true)]$Context
    )
    $capturedKind = $Kind
    $capturedContext = $Context
    return {
        param($Value)
        switch -CaseSensitive ($capturedKind) {
            'node' {
                return Test-I07NodeRetentionContext -Value $Value `
                    -Context $capturedContext
            }
            'baseline' {
                return Test-I07BaselineRetentionContext -Value $Value `
                    -Context $capturedContext
            }
            'preflight' {
                return Test-I07PreflightRetentionContext -Value $Value `
                    -Context $capturedContext
            }
            'wifi' {
                return Test-I07WifiRetentionContext -Value $Value `
                    -Context $capturedContext
            }
        }
        return $false
    }.GetNewClosure()
}

function Test-I07ExternalJsonBoundary {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)]
        [ValidateSet('node', 'baseline', 'preflight', 'wifi')][string]$Kind
    )
    if (-not (Test-I07NoRawDiagnosticProperties -Value $Value)) {
        return $false
    }
    if ($Kind -ceq 'node') {
        $candidateFull = @(
            'requested_sha256', 'sha256', 'bytes', 'verified', 'pid',
            'started_at_utc', 'commit', 'build_info_sha256', 'zip_sha256',
            'zip_bytes', 'zip_verified', 'zip_binding', 'package_files',
            'process_identity', 'launch_binding')
        $candidateMinimal = @('requested_sha256', 'verified')
        return (
            (Test-I07ExactPropertySet -Value $Value -Expected @(
                'schema', 'case_id', 'status', 'role', 'nonce',
                'completed_at_utc', 'phase', 'failure', 'candidate',
                'topology', 'product', 'cleanup', 'evidence', 'system_state',
                'process_cleanup')) -and
            [string]$Value.schema -ceq 'ese.v91.i07-node-result/v1' -and
            [string]$Value.case_id -ceq 'V91-I07' -and
            [string]$Value.status -cin @('PASS', 'FAIL', 'LAB_BLOCKED') -and
            [string]$Value.role -cin @('source', 'viewer') -and
            (Test-I07NonceRetentionString -Value $Value.nonce) -and
            (Test-I07UtcRetentionString -Value $Value.completed_at_utc) -and
            [string]$Value.phase -cin @(
                'request_validation', 'source_candidate_start',
                'source_direct_session', 'viewer_candidate_start',
                'viewer_direct_session', 'route_revalidation', 'complete') -and
            (Test-I07SafeRetentionScalarTree -Value $Value) -and
            ((Test-I07ExactPropertySet -Value $Value.candidate `
                -Expected $candidateFull) -or
             (Test-I07ExactPropertySet -Value $Value.candidate `
                -Expected $candidateMinimal)) -and
            (Test-I07ExactPropertySet -Value $Value.topology -Expected @(
                'topology_id', 'native_path_proven_before_candidate',
                'local_ipv6', 'peer_ipv6', 'interface_index',
                'interface_guid', 'ports', 'initial_route', 'final_route',
                'control', 'r01_hotspot_profile', 'web_api_containment')) -and
            (Test-I07ExactPropertySet -Value $Value.product -Expected @(
                'broadcast', 'direct_join', 'socket', 'api_peer', 'hls',
                'api_status_initial', 'api_status_final', 'samples',
                'failure_evidence')) -and
            (Test-I07ExactPropertySet -Value $Value.cleanup -Expected @(
                'process_stopped', 'firewall_removed', 'control_closed',
                'broadcast_stopped', 'ffmpeg_children_gone', 'hls_removed',
                'node_removed', 'evidence_retained',
                'system_state_restored')) -and
            ($null -eq $Value.system_state -or
             (Test-I07ExactPropertySet -Value $Value.system_state -Expected @(
                'schema', 'collector_ok', 'complete',
                'bound_sid_unchanged', 'run_subtree_unchanged',
                'emule_autostart_absent', 'ed2k_subtree_unchanged',
                'ed2k_subtree_absent', 'global_firewall_unchanged',
                'baseline_registry_sha256', 'post_registry_sha256',
                'baseline_firewall_sha256', 'post_firewall_sha256'))) -and
            ($null -eq $Value.process_cleanup -or
             (Test-I07ExactPropertySet -Value $Value.process_cleanup -Expected @(
                'schema', 'stopped', 'root_identity_matched',
                'descendants_collector_ok', 'descendant_count',
                'descendants_stopped'))) -and
            ($null -eq $Value.evidence -or
             (Test-I07ExactPropertySet -Value $Value.evidence -Expected @(
                'schema', 'complete', 'directory', 'files', 'manifest',
                'requirements', 'build_info', 'effective_config',
                'log_evidence'))))
    }
    if ($Kind -ceq 'baseline') {
        if (-not (Test-I07ExactPropertySet -Value $Value -Expected @(
                'schema', 'case_id', 'status', 'role', 'nonce',
                'sampled_at_utc', 'emule_process_count', 'tcp_ports',
                'udp_ports', 'error_code')) -or
            [string]$Value.schema -cne
                'ese.v91.i07-baseline-result/v1' -or
            [string]$Value.case_id -cne 'V91-I07' -or
            [string]$Value.status -cnotin @(
                'PREFLIGHT_PASS', 'LAB_BLOCKED') -or
            [string]$Value.role -cnotin @('source', 'viewer') -or
            -not (Test-I07NonceRetentionString -Value $Value.nonce) -or
            -not (Test-I07UtcRetentionString -Value $Value.sampled_at_utc) -or
            -not (Test-I07StrictInteger -Value $Value.emule_process_count `
                -Minimum -1) -or
            -not ($Value.tcp_ports -is [Array]) -or
            -not ($Value.udp_ports -is [Array])) { return $false }
        $allPorts = @($Value.tcp_ports) + @($Value.udp_ports)
        foreach ($row in @($Value.tcp_ports) + @($Value.udp_ports)) {
            if (-not (Test-I07ExactPropertySet -Value $row -Expected @(
                    'port', 'available', 'owner_count')) -or
                -not (Test-I07StrictInteger -Value $row.port `
                    -Minimum 1024 -Maximum 65535) -or
                -not (Test-I07StrictBoolean -Value $row.available) -or
                -not (Test-I07StrictInteger -Value $row.owner_count `
                    -Minimum 0) -or
                [bool]$row.available -ne
                    ([Int64]$row.owner_count -eq 0)) { return $false }
        }
        if (@($allPorts | ForEach-Object { [Int64]$_.port } |
                Select-Object -Unique).Count -ne $allPorts.Count) {
            return $false
        }
        if ([string]$Value.status -ceq 'PREFLIGHT_PASS') {
            return ($null -eq $Value.error_code -and
                [Int64]$Value.emule_process_count -eq 0 -and
                $allPorts.Count -gt 0 -and
                @($allPorts | Where-Object {
                        -not [bool]$_.available -or
                        [Int64]$_.owner_count -ne 0
                    }).Count -eq 0)
        }
        return ([string]$Value.error_code -ceq
                'BASELINE_NOT_CLEAN_OR_UNAVAILABLE')
    }
    if ($Kind -ceq 'preflight') {
        $route = $Value.selected_route
        if (-not (Test-I07ExactPropertySet -Value $Value -Expected @(
                'schema', 'case_id', 'status', 'created_at_utc', 'role',
                'nonce', 'candidate_sha256', 'selected_route',
                'inventory_summary', 'checks', 'limitation_code')) -or
            [string]$Value.schema -cne 'ese.v91.i07-preflight/v2' -or
            [string]$Value.case_id -cne 'V91-I07' -or
            [string]$Value.status -cnotin @(
                'PREFLIGHT_PASS', 'LAB_BLOCKED') -or
            [string]$Value.role -cnotin @('source', 'viewer') -or
            -not (Test-I07NonceRetentionString -Value $Value.nonce) -or
            -not (Test-I07Sha256RetentionString `
                -Value $Value.candidate_sha256) -or
            -not (Test-I07UtcRetentionString -Value $Value.created_at_utc) -or
            -not (Test-I07ExactPropertySet -Value $route -Expected @(
                'captured_at_utc', 'valid', 'source_address',
                'remote_address', 'source_class', 'remote_class',
                'interface_index', 'interface_guid', 'hardware_interface',
                'virtual', 'overlay', 'default_route_present',
                'address_state')) -or
            -not (Test-I07UtcRetentionString `
                -Value $route.captured_at_utc) -or
            -not (Test-I07StrictBoolean -Value $route.valid) -or
            -not (Test-I07StrictInteger -Value $route.interface_index `
                -Minimum 0) -or
            -not (Test-I07IPv6RetentionString `
                -Value $route.remote_address) -or
            -not (Test-I07IPv6RetentionString `
                -Value $route.source_address -AllowEmpty) -or
            -not (Test-I07GuidRetentionString `
                -Value $route.interface_guid -AllowEmpty) -or
            [string]$route.remote_class -cne 'global-native' -or
            [string]$route.source_class -cnotin @(
                '', 'global-native', 'ula', 'link-local', 'loopback',
                'multicast', 'unspecified', 'ipv4-mapped',
                'nat64-well-known', 'nat64-local-use', 'teredo', '6to4',
                'benchmark', 'documentation', 'orchid', 'orchidv2',
                'non-global', 'not-ipv6', 'invalid') -or
            [string]$route.address_state -cnotin @(
                '', 'Preferred', 'Deprecated', 'Tentative', 'Duplicate',
                'Invalid')) { return $false }
        foreach ($name in @('hardware_interface', 'virtual', 'overlay',
                'default_route_present')) {
            if (-not (Test-I07StrictBoolean -Value $route.$name)) {
                return $false
            }
        }
        $inventory = $Value.inventory_summary; $checks = $Value.checks
        if (-not (Test-I07ExactPropertySet -Value $inventory -Expected @(
                'address_count', 'class_counts',
                'eligible_native_global_count')) -or
            -not (Test-I07StrictInteger -Value $inventory.address_count `
                -Minimum 0) -or
            -not (Test-I07StrictInteger `
                -Value $inventory.eligible_native_global_count -Minimum 0) -or
            -not (Test-I07ExactPropertySet -Value $checks -Expected @(
                'selected_source_is_global_native',
                'selected_interface_is_hardware',
                'selected_interface_is_virtual',
                'selected_interface_is_overlay',
                'default_route_on_selected_interface',
                'selected_route_is_native'))) { return $false }
        $allowedClasses = @(
            'global-native', 'ula', 'link-local', 'loopback', 'multicast',
            'unspecified', 'ipv4-mapped', 'nat64-well-known',
            'nat64-local-use', 'teredo', '6to4', 'benchmark',
            'documentation', 'orchid', 'orchidv2', 'non-global',
            'not-ipv6', 'invalid')
        $classNames = @(Get-I07ObjectPropertyNames `
            -Value $inventory.class_counts)
        $classTotal = 0L
        foreach ($name in $classNames) {
            if ([string]$name -cnotin $allowedClasses -or
                -not (Test-I07StrictInteger `
                    -Value $inventory.class_counts.$name -Minimum 0)) {
                return $false
            }
            $classTotal += [Int64]$inventory.class_counts.$name
        }
        foreach ($name in @(Get-I07ObjectPropertyNames -Value $checks)) {
            if (-not (Test-I07StrictBoolean -Value $checks.$name)) {
                return $false
            }
        }
        $globalCount = if ($classNames -ccontains 'global-native') {
            [Int64]$inventory.class_counts.'global-native'
        } else { 0L }
        if ($classTotal -ne [Int64]$inventory.address_count -or
            [Int64]$inventory.eligible_native_global_count -gt $globalCount -or
            [bool]$checks.selected_source_is_global_native -ne
                ([string]$route.source_class -ceq 'global-native') -or
            [bool]$checks.selected_interface_is_hardware -ne
                [bool]$route.hardware_interface -or
            [bool]$checks.selected_interface_is_virtual -ne
                [bool]$route.virtual -or
            [bool]$checks.selected_interface_is_overlay -ne
                [bool]$route.overlay -or
            [bool]$checks.default_route_on_selected_interface -ne
                [bool]$route.default_route_present -or
            [bool]$checks.selected_route_is_native -ne [bool]$route.valid) {
            return $false
        }
        if ([string]$Value.status -ceq 'PREFLIGHT_PASS') {
            $guid = [Guid]::Empty
            return ([bool]$route.valid -and
                [string]$route.source_class -ceq 'global-native' -and
                (Get-I07IPv6Class -Address ([Net.IPAddress]::Parse(
                    [string]$route.source_address)) -ceq 'global-native') -and
                [Int64]$route.interface_index -gt 0 -and
                [Guid]::TryParse([string]$route.interface_guid, [ref]$guid) -and
                $guid -ne [Guid]::Empty -and
                [bool]$route.hardware_interface -and
                -not [bool]$route.virtual -and -not [bool]$route.overlay -and
                [bool]$route.default_route_present -and
                [string]$route.address_state -ceq 'Preferred' -and
                $null -eq $Value.limitation_code)
        }
        return (-not [bool]$route.valid -and
            [string]$Value.limitation_code -ceq 'NATIVE_ROUTE_NOT_PROVEN')
    }
    if (-not (Test-I07ExactPropertySet -Value $Value -Expected @(
            'schema', 'case_id', 'action', 'status', 'nonce',
            'completed_at_utc', 'target_wlan_profile_sha256',
            'expected_connection_profile_sha256',
            'home_wlan_profile_sha256', 'home_connection_profile_sha256',
            'interface_guid', 'profile', 'watchdog', 'watchdog_disarm',
            'error_code')) -or
        [string]$Value.schema -cne 'ese.v91.i07-wifi-transition/v2' -or
        [string]$Value.case_id -cne 'V91-I07' -or
        [string]$Value.action -cnotin @('hotspot', 'home') -or
        [string]$Value.status -cnotin @('PASS', 'LAB_BLOCKED') -or
        -not (Test-I07NonceRetentionString -Value $Value.nonce) -or
        -not (Test-I07UtcRetentionString -Value $Value.completed_at_utc) -or
        -not (Test-I07Sha256RetentionString `
            -Value $Value.target_wlan_profile_sha256) -or
        -not (Test-I07Sha256RetentionString `
            -Value $Value.expected_connection_profile_sha256) -or
        -not (Test-I07Sha256RetentionString `
            -Value $Value.home_wlan_profile_sha256) -or
        -not (Test-I07Sha256RetentionString `
            -Value $Value.home_connection_profile_sha256) -or
        -not (Test-I07GuidRetentionString -Value $Value.interface_guid)) {
        return $false
    }
    if ([string]$Value.status -ceq 'LAB_BLOCKED') {
        return ([string]$Value.error_code -ceq
                'WIFI_TRANSITION_NOT_PROVEN' -and
            $null -eq $Value.profile -and $null -eq $Value.watchdog -and
            $null -eq $Value.watchdog_disarm)
    }
    if ($null -ne $Value.error_code -or
        -not (Test-I07ExactPropertySet -Value $Value.profile -Expected @(
            'connection_profile', 'wlan_profile'))) { return $false }
    $connection = $Value.profile.connection_profile
    $wlan = $Value.profile.wlan_profile
    if (-not (Test-I07WifiProfileRetentionContract `
            -Profile $Value.profile `
            -ConnectionSha256 ([string]$Value.
                expected_connection_profile_sha256) `
            -WlanSha256 ([string]$Value.target_wlan_profile_sha256) `
            -InterfaceGuid ([string]$Value.interface_guid)) -or
        -not (Test-I07ExactPropertySet -Value $connection -Expected @(
            'schema', 'interface_index', 'interface_guid', 'profile_sha256',
            'network_category', 'ipv4_connectivity', 'ipv6_connectivity')) -or
        -not (Test-I07ExactPropertySet -Value $wlan -Expected @(
            'schema', 'interface_index', 'interface_guid',
            'wlan_profile_sha256')) -or
        -not (Test-I07StrictInteger -Value $connection.interface_index `
            -Minimum 1) -or
        -not (Test-I07StrictInteger -Value $wlan.interface_index -Minimum 1) -or
        [Int64]$connection.interface_index -ne [Int64]$wlan.interface_index -or
        [string]$connection.profile_sha256 -cne
            [string]$Value.expected_connection_profile_sha256 -or
        [string]$wlan.wlan_profile_sha256 -cne
            [string]$Value.target_wlan_profile_sha256) { return $false }
    $rootGuid = [Guid]::Empty; $connectionGuid = [Guid]::Empty
    $wlanGuid = [Guid]::Empty
    if (-not [Guid]::TryParse([string]$Value.interface_guid,
            [ref]$rootGuid) -or $rootGuid -eq [Guid]::Empty -or
        -not [Guid]::TryParse([string]$connection.interface_guid,
            [ref]$connectionGuid) -or
        -not [Guid]::TryParse([string]$wlan.interface_guid,
            [ref]$wlanGuid) -or $rootGuid -ne $connectionGuid -or
        $rootGuid -ne $wlanGuid) { return $false }
    if ([string]$Value.action -ceq 'hotspot') {
        $watchdog = $Value.watchdog
        $armed = [DateTimeOffset]::MinValue
        $deadline = [DateTimeOffset]::MinValue
        $transitionCompleted = [DateTimeOffset]::MinValue
        return ($null -eq $Value.watchdog_disarm -and
            (Test-I07ExactPropertySet -Value $watchdog -Expected @(
                'schema', 'case_id', 'status', 'nonce', 'watchdog_pid',
                'armed_at_utc', 'deadline_utc',
                'home_wlan_profile_sha256',
                'home_connection_profile_sha256', 'interface_guid')) -and
            [string]$watchdog.schema -ceq
                'ese.v91.i07-home-watchdog-armed/v1' -and
            [string]$watchdog.case_id -ceq 'V91-I07' -and
            [string]$watchdog.status -ceq 'ARMED' -and
            [string]$watchdog.nonce -ceq [string]$Value.nonce -and
            (Test-I07StrictInteger -Value $watchdog.watchdog_pid -Minimum 1) -and
            [string]$watchdog.home_wlan_profile_sha256 -ceq
                [string]$Value.home_wlan_profile_sha256 -and
            [string]$watchdog.home_connection_profile_sha256 -ceq
                [string]$Value.home_connection_profile_sha256 -and
            ([Guid]::Parse([string]$watchdog.interface_guid)) -eq $rootGuid -and
            [DateTimeOffset]::TryParse([string]$watchdog.armed_at_utc,
                [ref]$armed) -and
            [DateTimeOffset]::TryParse([string]$watchdog.deadline_utc,
                [ref]$deadline) -and $armed.Offset -eq [TimeSpan]::Zero -and
            $deadline.Offset -eq [TimeSpan]::Zero -and
            [DateTimeOffset]::TryParse([string]$Value.completed_at_utc,
                [ref]$transitionCompleted) -and
            $transitionCompleted.Offset -eq [TimeSpan]::Zero -and
            $armed -le $transitionCompleted -and
            $transitionCompleted -lt $deadline -and $deadline -gt $armed)
    }
    $watchdog = $Value.watchdog; $disarm = $Value.watchdog_disarm
    $watchStarted = [DateTimeOffset]::MinValue
    $watchCompleted = [DateTimeOffset]::MinValue
    $disarmedAt = [DateTimeOffset]::MinValue
    $transitionCompleted = [DateTimeOffset]::MinValue
    return (
        (Test-I07ExactPropertySet -Value $watchdog -Expected @(
            'schema', 'case_id', 'status', 'nonce', 'watchdog_pid', 'trigger',
            'restore_signal_valid', 'started_at_utc', 'completed_at_utc',
            'profile', 'error_code')) -and
        [string]$watchdog.schema -ceq
            'ese.v91.i07-home-watchdog-result/v1' -and
        [string]$watchdog.case_id -ceq 'V91-I07' -and
        [string]$watchdog.status -ceq 'PASS' -and
        [string]$watchdog.nonce -ceq [string]$Value.nonce -and
        [string]$watchdog.trigger -ceq 'controller_restore' -and
        (Test-I07StrictBoolean -Value $watchdog.restore_signal_valid) -and
        [bool]$watchdog.restore_signal_valid -and
        (Test-I07StrictInteger -Value $watchdog.watchdog_pid -Minimum 1) -and
        $null -eq $watchdog.error_code -and
        [DateTimeOffset]::TryParse([string]$watchdog.started_at_utc,
            [ref]$watchStarted) -and
        [DateTimeOffset]::TryParse([string]$watchdog.completed_at_utc,
            [ref]$watchCompleted) -and
        $watchStarted.Offset -eq [TimeSpan]::Zero -and
        $watchCompleted.Offset -eq [TimeSpan]::Zero -and
        $watchCompleted -ge $watchStarted -and
        (Test-I07WifiProfileRetentionContract `
            -Profile $watchdog.profile `
            -ConnectionSha256 ([string]$Value.
                home_connection_profile_sha256) `
            -WlanSha256 ([string]$Value.home_wlan_profile_sha256) `
            -InterfaceGuid ([string]$Value.interface_guid)) -and
        [string]$watchdog.profile.connection_profile.profile_sha256 -ceq
            [string]$Value.home_connection_profile_sha256 -and
        [string]$watchdog.profile.wlan_profile.wlan_profile_sha256 -ceq
            [string]$Value.home_wlan_profile_sha256 -and
        ([Guid]::Parse([string]$watchdog.profile.connection_profile.
            interface_guid)) -eq $rootGuid -and
        ([Guid]::Parse([string]$watchdog.profile.wlan_profile.
            interface_guid)) -eq $rootGuid -and
        (Test-I07ExactPropertySet -Value $disarm -Expected @(
            'schema', 'case_id', 'status', 'nonce', 'watchdog_pid',
            'process_exited', 'restore_trigger', 'disarmed_at_utc')) -and
        [string]$disarm.schema -ceq
            'ese.v91.i07-home-watchdog-disarmed/v1' -and
        [string]$disarm.case_id -ceq 'V91-I07' -and
        [string]$disarm.status -ceq 'PASS' -and
        [string]$disarm.nonce -ceq [string]$Value.nonce -and
        (Test-I07StrictInteger -Value $disarm.watchdog_pid -Minimum 1) -and
        [Int64]$disarm.watchdog_pid -eq [Int64]$watchdog.watchdog_pid -and
        (Test-I07StrictBoolean -Value $disarm.process_exited) -and
        [bool]$disarm.process_exited -and
        [string]$disarm.restore_trigger -ceq 'controller_restore' -and
        [DateTimeOffset]::TryParse([string]$disarm.disarmed_at_utc,
            [ref]$disarmedAt) -and $disarmedAt.Offset -eq [TimeSpan]::Zero -and
        [DateTimeOffset]::TryParse([string]$Value.completed_at_utc,
            [ref]$transitionCompleted) -and
        $transitionCompleted.Offset -eq [TimeSpan]::Zero -and
        $disarmedAt -ge $watchCompleted -and
        $disarmedAt -le $transitionCompleted)
}

function Remove-I07OwnedStagingFile {
    param([Parameter(Mandatory = $true)][string]$Path)
    $failure = 'STAGING_CLEANUP_NOT_PROVEN'
    $owned = $false
    $full = ''
    try {
        $tempRoot = [IO.Path]::GetFullPath(
            [IO.Path]::GetTempPath()).TrimEnd('\')
        $full = [IO.Path]::GetFullPath($Path)
        $parent = [IO.Path]::GetDirectoryName($full).TrimEnd('\')
        $leaf = [IO.Path]::GetFileName($full)
        if (-not $parent.Equals(
                $tempRoot, [StringComparison]::OrdinalIgnoreCase) -or
            $leaf -cnotmatch '^ese-i07-stage-[0-9a-f]{32}\.json$') {
            throw $failure
        }
        $owned = $true
        if (-not (Test-Path -LiteralPath $full)) {
            $null = $script:i07UnprovenStagingPaths.Remove($full)
            return
        }
        $item = Get-Item -LiteralPath $full -Force -ErrorAction Stop
        if ($item.PSIsContainer -or
            ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw $failure
        }
        for ($attempt = 1; $attempt -le 3; ++$attempt) {
            try {
                Remove-Item -LiteralPath $full -Force -ErrorAction Stop
            } catch {}
            if (-not (Test-Path -LiteralPath $full)) {
                $null = $script:i07UnprovenStagingPaths.Remove($full)
                return
            }
            if ($attempt -lt 3) { Start-Sleep -Milliseconds 100 }
        }
        throw $failure
    } catch {
        if ($owned -and -not [string]::IsNullOrWhiteSpace($full) -and
            -not $script:i07UnprovenStagingPaths.Contains($full)) {
            $script:i07UnprovenStagingPaths.Add($full)
        }
        throw $failure
    }
}

function Receive-I07StagedJson {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('source', 'viewer')][string]$Role,
        [Parameter(Mandatory = $true)][string]$RemotePath,
        [Parameter(Mandatory = $true)]
        [ValidateSet('node', 'baseline', 'preflight', 'wifi')][string]$Kind,
        [Parameter(Mandatory = $true)][scriptblock]$ContextValidator
    )
    $staging = Join-Path ([IO.Path]::GetTempPath()) (
        'ese-i07-stage-' + [Guid]::NewGuid().ToString('N') + '.json')
    try {
        Invoke-I07Agent -Role $Role -Command download -Extra @{
            RemotePath = $RemotePath; OutputPath = $staging
        } | Out-Null
        $snapshot = Read-I07JsonByteSnapshot -Path $staging
        if (-not (Test-I07ExternalJsonBoundary -Value $snapshot.value `
                -Kind $Kind)) {
            throw "Rejected unsafe or malformed $Kind result before retention."
        }
        $contextValid = & $ContextValidator $snapshot.value
        if (-not (Test-I07StrictBoolean -Value $contextValid) -or
            -not [bool]$contextValid) {
            throw "Rejected context-mismatched $Kind result before retention."
        }
        return $snapshot
    } finally {
        Remove-I07OwnedStagingFile -Path $staging
    }
}

function Get-I07AgentReadiness {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('source', 'viewer')][string]$Role
    )
    $t0 = [DateTimeOffset]::UtcNow
    $ping = Invoke-I07Agent -Role $Role -Command ping
    $t1 = [DateTimeOffset]::UtcNow
    $shapeValid = Test-I07ExactPropertySet -Value $ping -Expected @(
        'schema', 'state', 'job_id', 'protocol', 'utc_now', 'capabilities')
    $schemaValue = if ($null -eq $ping.PSObject.Properties['schema']) {
        ''
    } else { [string]$ping.schema }
    $protocolTypeValid = $null -ne $ping.PSObject.Properties['protocol'] -and
        (Test-I07StrictInteger -Value $ping.protocol -Minimum 2 -Maximum 2)
    $protocolValue = if (-not $protocolTypeValid) {
        0
    } else { [int]$ping.protocol }
    $stateValue = if ($null -eq $ping.PSObject.Properties['state']) {
        ''
    } else { [string]$ping.state }
    $utcValue = if ($null -eq $ping.PSObject.Properties['utc_now']) {
        ''
    } else { [string]$ping.utc_now }
    $capabilities = if (
        $null -eq $ping.PSObject.Properties['capabilities']) {
        @()
    } else { @($ping.capabilities) }
    $capabilitiesValid = $ping.capabilities -is [Array] -and
        $capabilities.Count -eq 1 -and
        (Test-I07StrictString -Value $capabilities[0]) -and
        [string]$capabilities[0] -ceq 'cooperative_cancel'
    $stringTypesValid =
        (Test-I07StrictString -Value $ping.schema) -and
        (Test-I07StrictString -Value $ping.state) -and
        (Test-I07StrictString -Value $ping.utc_now) -and
        (Test-I07StrictString -Value $ping.job_id -AllowEmpty)
    $remoteUtc = [DateTimeOffset]::MinValue
    $parsed = [DateTimeOffset]::TryParse(
        $utcValue,
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::RoundtripKind,
        [ref]$remoteUtc)
    $lowerMs = if ($parsed) {
        ($remoteUtc.ToUniversalTime() - $t1).TotalMilliseconds
    } else { [double]::PositiveInfinity }
    $upperMs = if ($parsed) {
        ($remoteUtc.ToUniversalTime() - $t0).TotalMilliseconds
    } else { [double]::PositiveInfinity }
    $boundMs = [Math]::Max([Math]::Abs($lowerMs), [Math]::Abs($upperMs))
    $rttMs = ($t1 - $t0).TotalMilliseconds
    $valid = (
        $shapeValid -and $stringTypesValid -and
        (Test-I07NoRawDiagnosticProperties -Value $ping) -and
        $schemaValue -ceq 'ese.lab.smallframe-ping/v2' -and
        $protocolTypeValid -and $capabilitiesValid -and
        $protocolValue -eq 2 -and
        $stateValue -ceq 'IDLE' -and
        [string]$ping.job_id -ceq '' -and
        $capabilities -ccontains 'cooperative_cancel' -and
        $parsed -and $rttMs -ge 0 -and $rttMs -le 2000 -and
        $boundMs -le 1000
    )
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.i07-agent-readiness/v1'
        role = $Role
        valid = $valid
        protocol = $protocolValue
        cooperative_cancel = $capabilities -ccontains 'cooperative_cancel'
        idle = $stateValue -ceq 'IDLE'
        controller_t0_utc = $t0.ToString('o')
        agent_utc = if ($parsed) { $remoteUtc.ToUniversalTime().ToString('o') } else { $null }
        controller_t1_utc = $t1.ToString('o')
        rtt_ms = [Math]::Round($rttMs, 3)
        offset_lower_ms = if ($parsed) { [Math]::Round($lowerMs, 3) } else { $null }
        offset_upper_ms = if ($parsed) { [Math]::Round($upperMs, 3) } else { $null }
        absolute_offset_bound_ms = if ($parsed) {
            [Math]::Round($boundMs, 3)
        } else { $null }
    }
}

function Get-I07PairClockEvidence {
    param(
        [Parameter(Mandatory = $true)]$Source,
        [Parameter(Mandatory = $true)]$Viewer
    )
    if ($null -eq $Source.offset_lower_ms -or
        $null -eq $Source.offset_upper_ms -or
        $null -eq $Viewer.offset_lower_ms -or
        $null -eq $Viewer.offset_upper_ms) {
        return [pscustomobject][ordered]@{
            schema = 'ese.v91.i07-pair-clock/v1'
            valid = $false
            source_minus_viewer_lower_ms = $null
            source_minus_viewer_upper_ms = $null
            absolute_pair_offset_bound_ms = $null
        }
    }
    $lower = [double]$Source.offset_lower_ms -
        [double]$Viewer.offset_upper_ms
    $upper = [double]$Source.offset_upper_ms -
        [double]$Viewer.offset_lower_ms
    $bound = [Math]::Max([Math]::Abs($lower), [Math]::Abs($upper))
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.i07-pair-clock/v1'
        valid = $bound -le 1000
        source_minus_viewer_lower_ms = [Math]::Round($lower, 3)
        source_minus_viewer_upper_ms = [Math]::Round($upper, 3)
        absolute_pair_offset_bound_ms = [Math]::Round($bound, 3)
    }
}

function Get-I07TextSha256 {
    param([Parameter(Mandatory = $true)][string]$Value)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash(
            [Text.Encoding]::UTF8.GetBytes($Value)
        ))).Replace('-', '').ToLowerInvariant()
    } finally { $sha.Dispose() }
}

function New-I07CanonicalJsonSnapshot {
    param([Parameter(Mandatory = $true)]$Value)
    $json = $Value | ConvertTo-Json -Depth 24 -Compress
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($json)
    $detachedValue = ConvertFrom-I07Utf8JsonBytes -Bytes $bytes
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $digest = ([BitConverter]::ToString(
            $sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    } finally { $sha.Dispose() }
    return [pscustomobject][ordered]@{
        bytes_value = $bytes; byte_count = [Int64]$bytes.Length
        sha256 = $digest; value = $detachedValue
    }
}

function ConvertTo-I07FailureProofRoute {
    param([AllowNull()]$Route)
    if ($null -eq $Route) { return $null }
    return [pscustomobject][ordered]@{
        captured_at_utc = [string]$Route.captured_at_utc
        source_address = [string]$Route.source_address
        remote_address = [string]$Route.remote_address
        source_class = [string]$Route.source_class
        remote_class = [string]$Route.remote_class
        interface_index = [Int64]$Route.interface_index
        interface_guid = ConvertTo-I07RetentionGuid `
            -Value ([string]$Route.interface_guid)
        hardware_interface = [bool]$Route.hardware_interface
        virtual = [bool]$Route.virtual; overlay = [bool]$Route.overlay
        default_route_present = [bool]$Route.default_route_present
        address_state = [string]$Route.address_state
    }
}

function ConvertTo-I07FailureProofApiStatus {
    param([Parameter(Mandatory = $true)]$Status)
    $safe = [ordered]@{}
    $safeNames = @(Get-I07ObjectPropertyNames -Value $Status.safe_scalars)
    foreach ($name in @(
            'ed2k_connected', 'kad_connected', 'kad2_running',
            'kad2_connected', 'kad6_running', 'kad6_connected',
            'netlab_enabled', 'kad_configured_mask', 'kad_running_mask')) {
        if ($safeNames -ccontains $name) {
            $safe[$name] = $Status.safe_scalars.$name
        }
    }
    return [pscustomobject][ordered]@{
        schema = [string]$Status.schema
        available = $Status.available
        contract_valid = $Status.contract_valid
        isolation_invariant_satisfied =
            $Status.isolation_invariant_satisfied
        captured_at_utc = if ($null -eq $Status.captured_at_utc) {
            $null
        } else { [string]$Status.captured_at_utc }
        safe_response_sha256 = if ($null -eq $Status.safe_response_sha256) {
            $null
        } else { [string]$Status.safe_response_sha256 }
        safe_response_bytes = $Status.safe_response_bytes
        safe_scalars = [pscustomobject]$safe
    }
}

function Get-I07FailureProofSessionSummary {
    param([Parameter(Mandatory = $true)]$Node)
    $samples = @($Node.product.samples)
    if ($samples.Count -lt 1) { return $null }
    $first = [DateTimeOffset]::MinValue
    $last = [DateTimeOffset]::MinValue
    $previous = [DateTimeOffset]::MinValue
    $maxGap = 0.0
    foreach ($sample in $samples) {
        $at = [DateTimeOffset]::Parse([string]$sample.at_utc)
        if ($first -eq [DateTimeOffset]::MinValue) { $first = $at }
        if ($previous -ne [DateTimeOffset]::MinValue) {
            $maxGap = [Math]::Max($maxGap, ($at - $previous).TotalSeconds)
        }
        $previous = $at; $last = $at
    }
    $session = $Node.product.failure_evidence.session_observation
    return [pscustomobject][ordered]@{
        sample_count = [Int64]$samples.Count
        first_sample_at_utc = $first.ToString('o')
        last_sample_at_utc = $last.ToString('o')
        maximum_gap_seconds = [Math]::Round($maxGap, 6)
        socket_observed = [bool]$session.socket_observed
        broadcasting_observed = [bool]$session.broadcasting_observed
        api_peer_observed = [bool]$session.api_peer_observed
        viewing_observed = [bool]$session.viewing_observed
        playlist_observed = [bool]$session.playlist_observed
        segment_observed = [bool]$session.segment_observed
    }
}

function Test-I07FailureProofRouteContract {
    param([AllowNull()]$Route, [switch]$AllowNull)
    if ($null -eq $Route) { return [bool]$AllowNull }
    return ((Test-I07ExactPropertySet -Value $Route -Expected @(
            'captured_at_utc', 'source_address', 'remote_address',
            'source_class', 'remote_class', 'interface_index',
            'interface_guid', 'hardware_interface', 'virtual', 'overlay',
            'default_route_present', 'address_state')) -and
        (Test-I07UtcRetentionString -Value $Route.captured_at_utc) -and
        (Test-I07IPv6RetentionString -Value $Route.source_address) -and
        (Test-I07IPv6RetentionString -Value $Route.remote_address) -and
        [string]$Route.source_class -ceq 'global-native' -and
        [string]$Route.remote_class -ceq 'global-native' -and
        (Test-I07StrictInteger -Value $Route.interface_index -Minimum 1) -and
        (Test-I07GuidRetentionString -Value $Route.interface_guid) -and
        [string]$Route.address_state -ceq 'Preferred' -and
        (Test-I07StrictBoolean -Value $Route.hardware_interface) -and
        [bool]$Route.hardware_interface -and
        (Test-I07StrictBoolean -Value $Route.virtual) -and
        -not [bool]$Route.virtual -and
        (Test-I07StrictBoolean -Value $Route.overlay) -and
        -not [bool]$Route.overlay -and
        (Test-I07StrictBoolean -Value $Route.default_route_present) -and
        [bool]$Route.default_route_present)
}

function Test-I07FailureProofApiStatusContract {
    param([Parameter(Mandatory = $true)]$Status)
    try {
        if (-not (Test-I07ExactPropertySet -Value $Status -Expected @(
                'schema', 'available', 'contract_valid',
                'isolation_invariant_satisfied', 'captured_at_utc',
                'safe_response_sha256', 'safe_response_bytes',
                'safe_scalars')) -or
            [string]$Status.schema -cne
                'ese.v91.i07-api-status-evidence/v2') { return $false }
        foreach ($name in @('available', 'contract_valid',
                'isolation_invariant_satisfied')) {
            if (-not (Test-I07StrictBoolean -Value $Status.$name)) {
                return $false
            }
        }
        $safeScalarNames = @(Get-I07ObjectPropertyNames `
            -Value $Status.safe_scalars)
        if (-not [bool]$Status.available) {
            return (-not [bool]$Status.contract_valid -and
                -not [bool]$Status.isolation_invariant_satisfied -and
                $null -eq $Status.safe_response_sha256 -and
                (Test-I07StrictInteger -Value $Status.safe_response_bytes `
                    -Minimum 0 -Maximum 0) -and
                $safeScalarNames.Count -eq 0 -and
                ($null -eq $Status.captured_at_utc -or
                    (Test-I07UtcRetentionString `
                        -Value $Status.captured_at_utc)))
        }
        $expectedScalars = @(
            'ed2k_connected', 'kad_connected', 'kad2_running',
            'kad2_connected', 'kad6_running', 'kad6_connected',
            'netlab_enabled', 'kad_configured_mask', 'kad_running_mask')
        if (-not [bool]$Status.contract_valid -or
            -not (Test-I07UtcRetentionString `
                -Value $Status.captured_at_utc) -or
            -not (Test-I07Sha256RetentionString `
                -Value $Status.safe_response_sha256) -or
            -not (Test-I07StrictInteger -Value $Status.safe_response_bytes `
                -Minimum 1) -or
            -not (Test-I07ExactPropertySet -Value $Status.safe_scalars `
                -Expected $expectedScalars)) { return $false }
        foreach ($name in @($expectedScalars | Select-Object -First 7)) {
            if (-not (Test-I07StrictBoolean `
                    -Value $Status.safe_scalars.$name)) { return $false }
        }
        foreach ($name in @($expectedScalars | Select-Object -Last 2)) {
            if (-not (Test-I07StrictInteger `
                    -Value $Status.safe_scalars.$name -Minimum 0 `
                    -Maximum 255)) { return $false }
        }
        $safe = [ordered]@{}
        foreach ($name in $expectedScalars) {
            $safe[$name] = $Status.safe_scalars.$name
        }
        $json = $safe | ConvertTo-Json -Compress
        $bytes = [Text.Encoding]::UTF8.GetBytes($json)
        $digest = Get-I07TextSha256 -Value $json
        $invariant = @($expectedScalars | Where-Object {
                if ($_ -like '*mask') {
                    [Int64]$safe[$_] -ne 0
                } else { [bool]$safe[$_] }
            }).Count -eq 0
        return ([Int64]$Status.safe_response_bytes -eq $bytes.Length -and
            [string]$Status.safe_response_sha256 -ceq $digest -and
            [bool]$Status.isolation_invariant_satisfied -eq $invariant)
    } catch { return $false }
}

function Test-I07FailureProofContract {
    param([Parameter(Mandatory = $true)]$Value)
    try {
        if (-not (Test-I07ExactPropertySet -Value $Value -Expected @(
                'schema', 'case_id', 'status', 'role', 'nonce',
                'topology_id', 'expected_duration_seconds',
                'completed_at_utc', 'source_result_sha256',
                'source_result_bytes', 'candidate', 'route', 'final_route',
                'control', 'viewer_hotspot', 'api_status_initial',
                'api_status_final', 'session_summary', 'failure',
                'cleanup')) -or
            [string]$Value.schema -cne 'ese.v91.i07-failure-proof/v1' -or
            [string]$Value.case_id -cne 'V91-I07' -or
            [string]$Value.status -cne 'FAIL' -or
            [string]$Value.role -cnotin @('source', 'viewer') -or
            -not (Test-I07NonceRetentionString -Value $Value.nonce) -or
            [string]$Value.topology_id -cne 'T3' -or
            -not (Test-I07StrictInteger `
                -Value $Value.expected_duration_seconds `
                -Minimum 15 -Maximum 180) -or
            -not (Test-I07UtcRetentionString `
                -Value $Value.completed_at_utc) -or
            -not (Test-I07Sha256RetentionString `
                -Value $Value.source_result_sha256) -or
            -not (Test-I07StrictInteger -Value $Value.source_result_bytes `
                -Minimum 1) -or
            -not (Test-I07ExactPropertySet -Value $Value.candidate `
                -Expected @('version', 'commit', 'emule_sha256', 'bytes',
                    'build_info_sha256', 'zip_sha256', 'zip_bytes', 'pid',
                    'started_at_utc', 'verified')) -or
            [string]$Value.candidate.version -cnotmatch
                '^[A-Za-z0-9._+-]{1,64}$' -or
            [string]$Value.candidate.commit -cnotmatch '^[0-9a-f]{40}$' -or
            -not (Test-I07Sha256RetentionString `
                -Value $Value.candidate.emule_sha256) -or
            -not (Test-I07StrictInteger -Value $Value.candidate.bytes `
                -Minimum 1) -or
            -not (Test-I07Sha256RetentionString `
                -Value $Value.candidate.build_info_sha256) -or
            -not (Test-I07Sha256RetentionString `
                -Value $Value.candidate.zip_sha256) -or
            -not (Test-I07StrictInteger -Value $Value.candidate.zip_bytes `
                -Minimum 1) -or
            -not (Test-I07StrictInteger -Value $Value.candidate.pid `
                -Minimum 1) -or
            -not (Test-I07UtcRetentionString `
                -Value $Value.candidate.started_at_utc) -or
            -not (Test-I07StrictBoolean -Value $Value.candidate.verified) -or
            -not [bool]$Value.candidate.verified) { return $false }
        if (-not (Test-I07FailureProofRouteContract -Route $Value.route) -or
            -not (Test-I07FailureProofRouteContract `
                -Route $Value.final_route -AllowNull) -or
            -not (Test-I07FailureProofApiStatusContract `
                -Status $Value.api_status_initial) -or
            -not (Test-I07FailureProofApiStatusContract `
                -Status $Value.api_status_final) -or
            -not (Test-I07ExactPropertySet -Value $Value.route -Expected @(
                'captured_at_utc', 'source_address', 'remote_address',
                'source_class', 'remote_class', 'interface_index',
                'interface_guid', 'hardware_interface', 'virtual', 'overlay',
                'default_route_present', 'address_state')) -or
            -not (Test-I07UtcRetentionString `
                -Value $Value.route.captured_at_utc) -or
            -not (Test-I07IPv6RetentionString `
                -Value $Value.route.source_address) -or
            -not (Test-I07IPv6RetentionString `
                -Value $Value.route.remote_address) -or
            [string]$Value.route.source_class -cne 'global-native' -or
            [string]$Value.route.remote_class -cne 'global-native' -or
            -not (Test-I07StrictInteger -Value $Value.route.interface_index `
                -Minimum 1) -or
            -not (Test-I07GuidRetentionString `
                -Value $Value.route.interface_guid) -or
            [string]$Value.route.address_state -cne 'Preferred') {
            return $false
        }
        foreach ($name in @('hardware_interface', 'virtual', 'overlay',
                'default_route_present')) {
            if (-not (Test-I07StrictBoolean -Value $Value.route.$name)) {
                return $false
            }
        }
        if (-not [bool]$Value.route.hardware_interface -or
            [bool]$Value.route.virtual -or [bool]$Value.route.overlay -or
            -not [bool]$Value.route.default_route_present -or
            -not (Test-I07ExactPropertySet -Value $Value.control -Expected @(
                'bidirectional', 'proven_at_utc', 'local_address',
                'local_port', 'remote_address', 'remote_port')) -or
            -not (Test-I07StrictBoolean -Value $Value.control.bidirectional) -or
            -not [bool]$Value.control.bidirectional -or
            -not (Test-I07UtcRetentionString `
                -Value $Value.control.proven_at_utc) -or
            -not (Test-I07IPv6RetentionString `
                -Value $Value.control.local_address) -or
            -not (Test-I07IPv6RetentionString `
                -Value $Value.control.remote_address) -or
            -not (Test-I07StrictInteger -Value $Value.control.local_port `
                -Minimum 1024 -Maximum 65535) -or
            -not (Test-I07StrictInteger -Value $Value.control.remote_port `
                -Minimum 1024 -Maximum 65535)) { return $false }
        if ([string]$Value.role -ceq 'source') {
            if ($null -ne $Value.viewer_hotspot) { return $false }
        } elseif (-not (Test-I07ExactPropertySet `
                -Value $Value.viewer_hotspot -Expected @(
                    'connection_profile_sha256', 'wlan_profile_sha256',
                    'interface_guid', 'revalidated_at_utc')) -or
            -not (Test-I07Sha256RetentionString `
                -Value $Value.viewer_hotspot.connection_profile_sha256) -or
            -not (Test-I07Sha256RetentionString `
                -Value $Value.viewer_hotspot.wlan_profile_sha256) -or
            -not (Test-I07GuidRetentionString `
                -Value $Value.viewer_hotspot.interface_guid) -or
            -not (Test-I07UtcRetentionString `
                -Value $Value.viewer_hotspot.revalidated_at_utc)) {
            return $false
        }
        if (-not (Test-I07ExactPropertySet -Value $Value.failure -Expected @(
                'category', 'code', 'phase', 'reason', 'observed_at_utc',
                'causal')) -or
            [string]$Value.failure.category -cne 'PRODUCT_INVARIANT' -or
            [string]$Value.failure.code -cnotin @(
                'SOURCE_START_INVARIANT', 'VIEWER_START_INVARIANT',
                'SOURCE_SESSION_INVARIANT', 'VIEWER_SESSION_INVARIANT',
                'API_INITIAL_UNRESPONSIVE',
                'API_INITIAL_ISOLATION_CONTRADICTION',
                'API_FINAL_UNRESPONSIVE',
                'API_FINAL_ISOLATION_CONTRADICTION') -or
            -not (Test-I07UtcRetentionString `
                -Value $Value.failure.observed_at_utc) -or
            -not (Test-I07ExactPropertySet -Value $Value.failure.causal `
                -Expected @('kind', 'listener', 'api_operation',
                    'process_exit', 'session_observation')) -or
            [string]$Value.failure.causal.kind -cnotin @(
                'listener', 'api_operation', 'process_exit',
                'session_observation') -or
            @($Value.failure.causal.PSObject.Properties | Where-Object {
                    $_.Name -cne 'kind' -and $null -ne $_.Value
                }).Count -ne 1) { return $false }
        $code = [string]$Value.failure.code
        $reason = [string]$Value.failure.reason
        $role = [string]$Value.role
        $expectedPhase = switch -CaseSensitive ($code) {
            'SOURCE_START_INVARIANT' { 'source_candidate_start' }
            'VIEWER_START_INVARIANT' { 'viewer_candidate_start' }
            'SOURCE_SESSION_INVARIANT' { 'source_direct_session' }
            'VIEWER_SESSION_INVARIANT' { 'viewer_direct_session' }
            'API_INITIAL_UNRESPONSIVE' {
                if ($role -ceq 'source') { 'source_candidate_start' } else {
                    'viewer_candidate_start'
                }
            }
            'API_INITIAL_ISOLATION_CONTRADICTION' {
                if ($role -ceq 'source') { 'source_candidate_start' } else {
                    'viewer_candidate_start'
                }
            }
            'API_FINAL_UNRESPONSIVE' { 'route_revalidation' }
            'API_FINAL_ISOLATION_CONTRADICTION' { 'route_revalidation' }
        }
        $allowedReasons = switch -CaseSensitive ($code) {
            'SOURCE_START_INVARIANT' { @(
                'LISTENER_MISSING', 'BROADCAST_API_UNRESPONSIVE',
                'BROADCAST_API_MALFORMED', 'BROADCAST_NOT_READY') }
            'VIEWER_START_INVARIANT' { @(
                'DIRECT_JOIN_API_UNRESPONSIVE',
                'DIRECT_JOIN_API_MALFORMED', 'DIRECT_JOIN_NOT_DIALED') }
            'SOURCE_SESSION_INVARIANT' { @(
                'CANDIDATE_EXITED', 'SOCKET_NOT_OBSERVED',
                'BROADCAST_NOT_OBSERVED') }
            'VIEWER_SESSION_INVARIANT' { @(
                'CANDIDATE_EXITED', 'SOCKET_NOT_OBSERVED',
                'API_PEER_NOT_OBSERVED', 'LIVETV_NOT_OBSERVED') }
            'API_INITIAL_UNRESPONSIVE' { @('API_STATUS_UNRESPONSIVE') }
            'API_FINAL_UNRESPONSIVE' { @('API_STATUS_UNRESPONSIVE') }
            'API_INITIAL_ISOLATION_CONTRADICTION' {
                @('API_ISOLATION_CONTRADICTION') }
            'API_FINAL_ISOLATION_CONTRADICTION' {
                @('API_ISOLATION_CONTRADICTION') }
        }
        if ([string]$Value.failure.phase -cne $expectedPhase -or
            $reason -cnotin $allowedReasons -or
            ($code -clike 'SOURCE_*' -and $role -cne 'source') -or
            ($code -clike 'VIEWER_*' -and $role -cne 'viewer')) {
            return $false
        }
        $expectedKind = if ($reason -ceq 'LISTENER_MISSING') {
            'listener'
        } elseif ($reason -ceq 'CANDIDATE_EXITED') {
            'process_exit'
        } elseif ($reason -cin @(
                'SOCKET_NOT_OBSERVED', 'BROADCAST_NOT_OBSERVED',
                'API_PEER_NOT_OBSERVED', 'LIVETV_NOT_OBSERVED')) {
            'session_observation'
        } else { 'api_operation' }
        if ([string]$Value.failure.causal.kind -cne $expectedKind) {
            return $false
        }
        if ($expectedKind -ceq 'listener') {
            $listener = $Value.failure.causal.listener
            if (-not (Test-I07ExactPropertySet -Value $listener -Expected @(
                    'candidate_pid', 'expected_port',
                    'ipv6_listener_count')) -or
                -not (Test-I07StrictInteger -Value $listener.candidate_pid `
                    -Minimum 1) -or
                [Int64]$listener.candidate_pid -ne
                    [Int64]$Value.candidate.pid -or
                -not (Test-I07StrictInteger -Value $listener.expected_port `
                    -Minimum 1024 -Maximum 65535) -or
                -not (Test-I07StrictInteger `
                    -Value $listener.ipv6_listener_count `
                    -Minimum 0 -Maximum 0)) { return $false }
        } elseif ($expectedKind -ceq 'process_exit') {
            $processExit = $Value.failure.causal.process_exit
            if (-not (Test-I07ExactPropertySet -Value $processExit `
                    -Expected @('candidate_pid', 'process_alive')) -or
                -not (Test-I07StrictInteger `
                    -Value $processExit.candidate_pid -Minimum 1) -or
                [Int64]$processExit.candidate_pid -ne
                    [Int64]$Value.candidate.pid -or
                -not (Test-I07StrictBoolean `
                    -Value $processExit.process_alive) -or
                [bool]$processExit.process_alive) { return $false }
        } elseif ($expectedKind -ceq 'api_operation') {
            $op = $Value.failure.causal.api_operation
            if (-not (Test-I07ExactPropertySet -Value $op -Expected @(
                    'operation', 'available', 'contract_valid', 'success',
                    'ready', 'safe_response_sha256',
                    'safe_response_bytes')) -or
                [string]$op.operation -cnotin @(
                    'api_status_initial', 'api_status_final',
                    'broadcast_start', 'direct_join') -or
                -not (Test-I07StrictBoolean -Value $op.available) -or
                -not (Test-I07StrictBoolean -Value $op.contract_valid) -or
                -not (Test-I07StrictBoolean -Value $op.success) -or
                -not (Test-I07StrictBoolean -Value $op.ready) -or
                -not (Test-I07Sha256RetentionString `
                    -Value $op.safe_response_sha256) -or
                -not (Test-I07StrictInteger `
                    -Value $op.safe_response_bytes -Minimum 1)) {
                return $false
            }
            $safeOp = [ordered]@{
                operation = [string]$op.operation
                available = [bool]$op.available
                contract_valid = [bool]$op.contract_valid
                success = [bool]$op.success; ready = [bool]$op.ready
            }
            $safeJson = $safeOp | ConvertTo-Json -Compress
            if ([string]$op.safe_response_sha256 -cne
                    (Get-I07TextSha256 -Value $safeJson) -or
                [Int64]$op.safe_response_bytes -ne
                    [Text.Encoding]::UTF8.GetByteCount($safeJson)) {
                return $false
            }
            $expectedOperation = if ($code -clike 'API_INITIAL_*') {
                'api_status_initial'
            } elseif ($code -clike 'API_FINAL_*') {
                'api_status_final'
            } elseif ($code -ceq 'SOURCE_START_INVARIANT') {
                'broadcast_start'
            } else { 'direct_join' }
            $expectedFlags = switch -CaseSensitive ($reason) {
                { $_ -cin @('API_STATUS_UNRESPONSIVE',
                        'BROADCAST_API_UNRESPONSIVE',
                        'DIRECT_JOIN_API_UNRESPONSIVE') } {
                    @($false, $false) }
                { $_ -cin @('BROADCAST_API_MALFORMED',
                        'DIRECT_JOIN_API_MALFORMED') } { @($true, $false) }
                default { @($true, $true) }
            }
            if ([string]$op.operation -cne $expectedOperation -or
                [bool]$op.available -ne [bool]$expectedFlags[0] -or
                [bool]$op.contract_valid -ne [bool]$expectedFlags[1] -or
                ($reason -cin @('BROADCAST_NOT_READY',
                        'DIRECT_JOIN_NOT_DIALED') -and
                    [bool]$op.success -and [bool]$op.ready)) {
                return $false
            }
        } else {
            $session = $Value.failure.causal.session_observation
            if (-not (Test-I07ExactPropertySet -Value $session -Expected @(
                    'sample_count', 'observation_started_at_utc',
                    'deadline_at_utc', 'socket_observed',
                    'broadcasting_observed', 'api_peer_observed',
                    'viewing_observed', 'playlist_observed',
                    'segment_observed')) -or
                -not (Test-I07StrictInteger -Value $session.sample_count `
                    -Minimum 2) -or
                -not (Test-I07UtcRetentionString `
                    -Value $session.observation_started_at_utc) -or
                -not (Test-I07UtcRetentionString `
                    -Value $session.deadline_at_utc)) { return $false }
            foreach ($name in @(
                    'socket_observed', 'broadcasting_observed',
                    'api_peer_observed', 'viewing_observed',
                    'playlist_observed', 'segment_observed')) {
                if (-not (Test-I07StrictBoolean -Value $session.$name)) {
                    return $false
                }
            }
        }
        $sessionReasons = @(
            'SOCKET_NOT_OBSERVED', 'BROADCAST_NOT_OBSERVED',
            'API_PEER_NOT_OBSERVED', 'LIVETV_NOT_OBSERVED')
        if ([string]$Value.failure.reason -cin $sessionReasons) {
            if ($null -eq $Value.session_summary -or
                -not (Test-I07ExactPropertySet `
                    -Value $Value.session_summary -Expected @(
                        'sample_count', 'first_sample_at_utc',
                        'last_sample_at_utc', 'maximum_gap_seconds',
                        'socket_observed', 'broadcasting_observed',
                        'api_peer_observed', 'viewing_observed',
                        'playlist_observed', 'segment_observed')) -or
                -not (Test-I07StrictInteger `
                    -Value $Value.session_summary.sample_count -Minimum 2) -or
                -not (Test-I07UtcRetentionString `
                    -Value $Value.session_summary.first_sample_at_utc) -or
                -not (Test-I07UtcRetentionString `
                    -Value $Value.session_summary.last_sample_at_utc) -or
                -not (($Value.session_summary.maximum_gap_seconds -is
                    [double]) -or (Test-I07StrictInteger `
                        -Value $Value.session_summary.maximum_gap_seconds `
                        -Minimum 0)) -or
                [double]$Value.session_summary.maximum_gap_seconds -lt 0) {
                return $false
            }
            foreach ($name in @(
                    'socket_observed', 'broadcasting_observed',
                    'api_peer_observed', 'viewing_observed',
                    'playlist_observed', 'segment_observed')) {
                if (-not (Test-I07StrictBoolean `
                        -Value $Value.session_summary.$name)) {
                    return $false
                }
            }
            $session = $Value.failure.causal.session_observation
            $observationStarted = [DateTimeOffset]::Parse(
                [string]$session.observation_started_at_utc)
            $deadline = [DateTimeOffset]::Parse(
                [string]$session.deadline_at_utc)
            $firstSample = [DateTimeOffset]::Parse(
                [string]$Value.session_summary.first_sample_at_utc)
            $lastSample = [DateTimeOffset]::Parse(
                [string]$Value.session_summary.last_sample_at_utc)
            $observedAt = [DateTimeOffset]::Parse(
                [string]$Value.failure.observed_at_utc)
            $requiredWindow = [Int64]$Value.expected_duration_seconds + $(
                if ([string]$Value.role -ceq 'source') { 60 } else { 0 })
            $allowedGap = if ([string]$Value.role -ceq 'source') {
                8.0
            } else { 20.0 }
            if ([string]$Value.failure.causal.kind -cne
                    'session_observation' -or
                [Int64]$Value.session_summary.sample_count -ne
                    [Int64]$session.sample_count -or
                ($deadline - $observationStarted).TotalSeconds -lt
                    $requiredWindow -or
                $firstSample -lt $observationStarted -or
                $firstSample -gt $observationStarted.AddSeconds(2) -or
                $lastSample -lt $deadline.AddSeconds(-2) -or
                $observedAt -lt $deadline -or $observedAt -lt $lastSample -or
                [double]$Value.session_summary.maximum_gap_seconds -gt
                    $allowedGap -or
                ($observedAt - $lastSample).TotalSeconds -gt $allowedGap) {
                return $false
            }
            foreach ($name in @(
                    'socket_observed', 'broadcasting_observed',
                    'api_peer_observed', 'viewing_observed',
                    'playlist_observed', 'segment_observed')) {
                if ([bool]$Value.session_summary.$name -ne
                    [bool]$session.$name) { return $false }
            }
        } elseif ($null -ne $Value.session_summary) { return $false }
        if ([string]$Value.failure.code -clike 'API_FINAL_*') {
            if ($null -eq $Value.final_route) { return $false }
        }
        if ([string]$Value.failure.code -clike '*ISOLATION_CONTRADICTION') {
            $api = if ([string]$Value.failure.code -clike 'API_INITIAL_*') {
                $Value.api_status_initial
            } else { $Value.api_status_final }
            if (-not [bool]$api.available -or
                -not [bool]$api.contract_valid -or
                [bool]$api.isolation_invariant_satisfied) { return $false }
        }
        if (-not (Test-I07ExactPropertySet -Value $Value.cleanup -Expected @(
                'process_stopped', 'firewall_removed', 'control_closed',
                'broadcast_stopped', 'ffmpeg_children_gone', 'hls_removed',
                'node_removed', 'evidence_retained',
                'system_state_restored'))) { return $false }
        foreach ($property in $Value.cleanup.PSObject.Properties) {
            if (-not (Test-I07StrictBoolean -Value $property.Value)) {
                return $false
            }
        }
        return ((Test-I07NoRawDiagnosticProperties -Value $Value) -and
            (Test-I07SafeRetentionScalarTree -Value $Value))
    } catch { return $false }
}

function Test-I07NodePackageIdentity {
    param(
        [Parameter(Mandatory = $true)]$Node,
        [Parameter(Mandatory = $true)]$Context
    )
    try {
        $expected = @(Assert-I07CriticalPackageContract `
            -Files @($Context.package_files) | Sort-Object path)
        $nodeFiles = @(Assert-I07CriticalPackageContract `
            -Files @($Node.candidate.package_files) | Sort-Object path)
        $zipFiles = @(Assert-I07CriticalPackageContract `
            -Files @($Node.candidate.zip_binding.critical_files) |
                Sort-Object path)
        function Get-Canonical([object[]]$Files) {
            return @($Files | ForEach-Object {
                    '{0}|{1}|{2}' -f $_.path, [Int64]$_.bytes, $_.sha256
                }) -join "`n"
        }
        $emule = @($expected | Where-Object path -ceq 'emule.exe')
        return (
            (Test-I07ExactPropertySet `
                -Value $Node.candidate.zip_binding -Expected @(
                    'schema', 'verified', 'zip_sha256', 'zip_bytes',
                    'critical_file_count', 'critical_files')) -and
            (Test-I07StrictInteger `
                -Value $Node.candidate.zip_binding.zip_bytes -Minimum 1) -and
            (Test-I07StrictInteger `
                -Value $Node.candidate.zip_binding.critical_file_count `
                -Minimum 7 -Maximum 100000) -and
            (Test-I07StrictInteger -Value $Node.candidate.bytes -Minimum 1) -and
            (Test-I07StrictInteger `
                -Value $Node.candidate.zip_bytes -Minimum 1) -and
            (Test-I07StrictInteger -Value $Context.zip_bytes -Minimum 1) -and
            [string]$Node.candidate.zip_binding.schema -ceq
                'ese.v91.i07-node-zip-binding/v2' -and
            (Test-I07StrictBoolean `
                -Value $Node.candidate.zip_binding.verified) -and
            [bool]$Node.candidate.zip_binding.verified -and
            [string]$Node.candidate.zip_binding.zip_sha256 -ceq
                [string]$Node.candidate.zip_sha256 -and
            [Int64]$Node.candidate.zip_binding.zip_bytes -eq
                [Int64]$Node.candidate.zip_bytes -and
            [Int64]$Node.candidate.zip_binding.critical_file_count -eq
                $expected.Count -and
            (Get-Canonical $expected) -ceq (Get-Canonical $nodeFiles) -and
            (Get-Canonical $expected) -ceq (Get-Canonical $zipFiles) -and
            $emule.Count -eq 1 -and
            [string]$emule[0].sha256 -ceq
                [string]$Node.candidate.sha256 -and
            [Int64]$emule[0].bytes -eq [Int64]$Node.candidate.bytes)
    } catch { return $false }
}

function New-I07FailureProofContext {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('source', 'viewer')][string]$Role,
        [Parameter(Mandatory = $true)][string]$Nonce,
        [Parameter(Mandatory = $true)]$CandidateIdentity,
        [Parameter(Mandatory = $true)][int]$DurationSeconds
    )
    return [pscustomobject][ordered]@{
        role = $Role; nonce = $Nonce
        candidate_version = [string]$CandidateIdentity.version
        candidate_commit = [string]$CandidateIdentity.commit
        candidate_sha256 = [string]$CandidateIdentity.emule_sha256
        candidate_bytes = [Int64]$CandidateIdentity.bytes
        build_info_sha256 = [string]$CandidateIdentity.build_info_sha256
        zip_sha256 = [string]$CandidateIdentity.zip_sha256
        zip_bytes = [Int64]$CandidateIdentity.zip_bytes
        package_files = @($CandidateIdentity.package_files)
        duration_seconds = [Int64]$DurationSeconds
    }
}

function New-I07FailureProofValue {
    param(
        [Parameter(Mandatory = $true)]$Node,
        [Parameter(Mandatory = $true)]$Context,
        [Parameter(Mandatory = $true)][string]$SourceDigest,
        [Parameter(Mandatory = $true)][Int64]$SourceBytes
    )
    if ([string]$Node.schema -cne 'ese.v91.i07-node-result/v1' -or
        [string]$Node.case_id -cne 'V91-I07' -or
        [string]$Node.topology.topology_id -cne 'T3' -or
        [string]$Node.status -cne 'FAIL' -or
        [string]$Node.role -cne [string]$Context.role -or
        [string]$Node.nonce -cne [string]$Context.nonce -or
        [string]$Node.failure.category -cne 'PRODUCT_INVARIANT' -or
        [string]$Node.candidate.requested_sha256 -cne
            [string]$Context.candidate_sha256 -or
        [string]$Node.candidate.commit -cne
            [string]$Context.candidate_commit -or
        [string]$Node.candidate.sha256 -cne
            [string]$Context.candidate_sha256 -or
        [Int64]$Node.candidate.bytes -ne
            [Int64]$Context.candidate_bytes -or
        -not (Test-I07StrictBoolean -Value $Node.candidate.verified) -or
        -not [bool]$Node.candidate.verified -or
        -not (Test-I07StrictBoolean -Value $Node.candidate.zip_verified) -or
        -not [bool]$Node.candidate.zip_verified -or
        [string]$Node.candidate.build_info_sha256 -cne
            [string]$Context.build_info_sha256 -or
        [string]$Node.candidate.zip_sha256 -cne
            [string]$Context.zip_sha256 -or
        [Int64]$Node.candidate.zip_bytes -ne
            [Int64]$Context.zip_bytes -or
        -not (Test-I07NodePackageIdentity -Node $Node -Context $Context)) {
        throw 'I07 failure proof source identity is not authenticated.'
    }
    $failureEvidence = $Node.product.failure_evidence
    $causal = [ordered]@{
        kind = ''
        listener = $null; api_operation = $null
        process_exit = $null; session_observation = $null
    }
    if ($null -ne $failureEvidence.listener) {
        $causal.kind = 'listener'
        $causal.listener = [pscustomobject][ordered]@{
            candidate_pid = [Int64]$failureEvidence.listener.candidate_pid
            expected_port = [Int64]$failureEvidence.listener.expected_port
            ipv6_listener_count =
                [Int64]$failureEvidence.listener.ipv6_listener_count
        }
    } elseif ($null -ne $failureEvidence.api_operation) {
        $op = $failureEvidence.api_operation
        $causal.kind = 'api_operation'
        $causal.api_operation = [pscustomobject][ordered]@{
            operation = [string]$op.operation
            available = [bool]$op.available
            contract_valid = [bool]$op.contract_valid
            success = [bool]$op.success; ready = [bool]$op.ready
            safe_response_sha256 = [string]$op.safe_response_sha256
            safe_response_bytes = [Int64]$op.safe_response_bytes
        }
    } elseif ($null -ne $failureEvidence.process_exit) {
        $causal.kind = 'process_exit'
        $causal.process_exit = [pscustomobject][ordered]@{
            candidate_pid =
                [Int64]$failureEvidence.process_exit.candidate_pid
            process_alive = [bool]$failureEvidence.process_exit.process_alive
        }
    } elseif ($null -ne $failureEvidence.session_observation) {
        $session = $failureEvidence.session_observation
        $causal.kind = 'session_observation'
        $causal.session_observation = [pscustomobject][ordered]@{
            sample_count = [Int64]$session.sample_count
            observation_started_at_utc =
                [string]$session.observation_started_at_utc
            deadline_at_utc = [string]$session.deadline_at_utc
            socket_observed = [bool]$session.socket_observed
            broadcasting_observed = [bool]$session.broadcasting_observed
            api_peer_observed = [bool]$session.api_peer_observed
            viewing_observed = [bool]$session.viewing_observed
            playlist_observed = [bool]$session.playlist_observed
            segment_observed = [bool]$session.segment_observed
        }
    } else { throw 'Authenticated FAIL lacks one causal branch.' }
    $route = $Node.topology.initial_route
    $control = $Node.topology.control
    $viewerHotspot = if ([string]$Node.role -ceq 'viewer') {
        $profile = $Node.topology.r01_hotspot_profile
        [pscustomobject][ordered]@{
            connection_profile_sha256 =
                [string]$profile.connection_profile.profile_sha256
            wlan_profile_sha256 =
                [string]$profile.wlan_profile.wlan_profile_sha256
            interface_guid =
                (ConvertTo-I07RetentionGuid -Value (
                    [string]$profile.connection_profile.interface_guid))
            revalidated_at_utc = [string]$profile.revalidated_at_utc
        }
    } else { $null }
    $proof = [pscustomobject][ordered]@{
        schema = 'ese.v91.i07-failure-proof/v1'
        case_id = 'V91-I07'; status = 'FAIL'
        role = [string]$Node.role; nonce = [string]$Node.nonce
        topology_id = 'T3'
        expected_duration_seconds = [Int64]$Context.duration_seconds
        completed_at_utc = [string]$Node.completed_at_utc
        source_result_sha256 = $SourceDigest
        source_result_bytes = $SourceBytes
        candidate = [pscustomobject][ordered]@{
            version = [string]$Context.candidate_version
            commit = [string]$Node.candidate.commit
            emule_sha256 = [string]$Node.candidate.sha256
            bytes = [Int64]$Node.candidate.bytes
            build_info_sha256 = [string]$Node.candidate.build_info_sha256
            zip_sha256 = [string]$Node.candidate.zip_sha256
            zip_bytes = [Int64]$Node.candidate.zip_bytes
            pid = [Int64]$Node.candidate.pid
            started_at_utc = [string]$Node.candidate.started_at_utc
            verified = [bool]$Node.candidate.verified
        }
        route = [pscustomobject][ordered]@{
            captured_at_utc = [string]$route.captured_at_utc
            source_address = [string]$route.source_address
            remote_address = [string]$route.remote_address
            source_class = [string]$route.source_class
            remote_class = [string]$route.remote_class
            interface_index = [Int64]$route.interface_index
            interface_guid = ConvertTo-I07RetentionGuid `
                -Value ([string]$route.interface_guid)
            hardware_interface = [bool]$route.hardware_interface
            virtual = [bool]$route.virtual; overlay = [bool]$route.overlay
            default_route_present = [bool]$route.default_route_present
            address_state = [string]$route.address_state
        }
        final_route = ConvertTo-I07FailureProofRoute `
            -Route $Node.topology.final_route
        control = [pscustomobject][ordered]@{
            bidirectional = [bool]$control.bidirectional
            proven_at_utc = [string]$control.proven_at_utc
            local_address = [string]$control.local_address
            local_port = [Int64]$control.local_port
            remote_address = [string]$control.remote_address
            remote_port = [Int64]$control.remote_port
        }
        viewer_hotspot = $viewerHotspot
        api_status_initial = ConvertTo-I07FailureProofApiStatus `
            -Status $Node.product.api_status_initial
        api_status_final = ConvertTo-I07FailureProofApiStatus `
            -Status $Node.product.api_status_final
        session_summary = if ($causal.kind -ceq 'session_observation') {
            Get-I07FailureProofSessionSummary -Node $Node
        } else { $null }
        failure = [pscustomobject][ordered]@{
            category = [string]$Node.failure.category
            code = [string]$Node.failure.code; phase = [string]$Node.phase
            reason = [string]$failureEvidence.reason
            observed_at_utc = [string]$failureEvidence.observed_at_utc
            causal = [pscustomobject]$causal
        }
        cleanup = [pscustomobject][ordered]@{
            process_stopped = $Node.cleanup.process_stopped
            firewall_removed = $Node.cleanup.firewall_removed
            control_closed = $Node.cleanup.control_closed
            broadcast_stopped = $Node.cleanup.broadcast_stopped
            ffmpeg_children_gone = $Node.cleanup.ffmpeg_children_gone
            hls_removed = $Node.cleanup.hls_removed
            node_removed = $Node.cleanup.node_removed
            evidence_retained = $Node.cleanup.evidence_retained
            system_state_restored = $Node.cleanup.system_state_restored
        }
    }
    return $proof
}

function Test-I07FailureProofProvenanceContract {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)]$SourceSnapshot,
        [Parameter(Mandatory = $true)]$Context
    )
    try {
        $bytes = [byte[]]$SourceSnapshot.bytes_value
        if ($bytes.Length -lt 1 -or $bytes.Length -ne
                [Int64]$SourceSnapshot.byte_count) { return $false }
        $hasher = [Security.Cryptography.SHA256]::Create()
        try {
            $digest = ([BitConverter]::ToString(
                $hasher.ComputeHash($bytes))).Replace('-', '').
                    ToLowerInvariant()
        } finally { $hasher.Dispose() }
        if ($digest -cne [string]$SourceSnapshot.sha256) { return $false }
        $node = ConvertFrom-I07Utf8JsonBytes -Bytes $bytes
        if (($node | ConvertTo-Json -Depth 24 -Compress) -cne
            ($SourceSnapshot.value | ConvertTo-Json -Depth 24 -Compress)) {
            return $false
        }
        $expected = New-I07FailureProofValue -Node $node `
            -Context $Context -SourceDigest $digest `
            -SourceBytes $bytes.Length
        $semantic = Test-I07FailureProofContract -Value $Value
        $canonical = (($Value | ConvertTo-Json -Depth 24 -Compress) -ceq
            ($expected | ConvertTo-Json -Depth 24 -Compress))
        $script:i07FailureProofProvenanceDebug = [ordered]@{
            semantic = $semantic; canonical = $canonical
            route = Test-I07FailureProofRouteContract -Route $Value.route
            final_route = Test-I07FailureProofRouteContract `
                -Route $Value.final_route -AllowNull
            api_initial = Test-I07FailureProofApiStatusContract `
                -Status $Value.api_status_initial
            api_final = Test-I07FailureProofApiStatusContract `
                -Status $Value.api_status_final
            no_raw = Test-I07NoRawDiagnosticProperties -Value $Value
            safe = Test-I07SafeRetentionScalarTree -Value $Value
        }
        return ($semantic -and $canonical)
    } catch { return $false }
}

function New-I07FailureProofSnapshot {
    param(
        [Parameter(Mandatory = $true)]$Node,
        [Parameter(Mandatory = $true)]$SourceSnapshot,
        [Parameter(Mandatory = $true)]$Context
    )
    $bytes = [byte[]]$SourceSnapshot.bytes_value
    $parsed = ConvertFrom-I07Utf8JsonBytes -Bytes $bytes
    if (($Node | ConvertTo-Json -Depth 24 -Compress) -cne
        ($parsed | ConvertTo-Json -Depth 24 -Compress)) {
        throw 'I07 failure proof node is not derived from source bytes.'
    }
    $hasher = [Security.Cryptography.SHA256]::Create()
    try {
        $digest = ([BitConverter]::ToString(
            $hasher.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    } finally { $hasher.Dispose() }
    $proof = New-I07FailureProofValue -Node $parsed -Context $Context `
        -SourceDigest $digest -SourceBytes $bytes.Length
    if (-not (Test-I07FailureProofProvenanceContract -Value $proof `
            -SourceSnapshot $SourceSnapshot -Context $Context)) {
        throw 'Sanitized I07 failure proof violated source provenance.'
    }
    $snapshot = New-I07CanonicalJsonSnapshot -Value $proof
    $reloaded = ConvertFrom-I07Utf8JsonBytes `
        -Bytes ([byte[]]$snapshot.bytes_value)
    if (-not (Test-I07FailureProofProvenanceContract -Value $reloaded `
            -SourceSnapshot $SourceSnapshot -Context $Context)) {
        throw ('Serialized I07 failure proof failed provenance reload: ' +
            ($script:i07FailureProofProvenanceDebug |
                ConvertTo-Json -Compress))
    }
    return [pscustomobject][ordered]@{
        bytes_value = $snapshot.bytes_value
        byte_count = [Int64]$snapshot.byte_count
        sha256 = [string]$snapshot.sha256
        value = $reloaded
    }
}

function ConvertTo-I07PassProofRoute {
    param([Parameter(Mandatory = $true)]$Route)
    $rawNames = @(
        'captured_at_utc', 'valid', 'reason', 'remote_address',
        'remote_class', 'source_address', 'source_class', 'interface_index',
        'interface_alias', 'interface_guid', 'interface_description',
        'media_type', 'physical_media_type', 'hardware_interface', 'virtual',
        'destination_prefix', 'next_hop', 'route_metric', 'interface_metric',
        'address_state', 'prefix_origin', 'suffix_origin',
        'default_route_present', 'overlay')
    $mediaTypes = @('802.3', 'Native 802.11', 'Wireless WAN')
    $prefixOrigins = @('Manual', 'Dhcp', 'RouterAdvertisement', 'WellKnown')
    $suffixOrigins = @('Manual', 'Dhcp', 'Link', 'Random', 'WellKnown')
    $nextHop = ConvertTo-I07CanonicalIPv6 -Value ([string]$Route.next_hop)
    if (-not (Test-I07ExactPropertySet -Value $Route -Expected $rawNames) -or
        -not (Test-I07UtcRetentionString -Value $Route.captured_at_utc) -or
        -not (Test-I07StrictBoolean -Value $Route.valid) -or
        -not [bool]$Route.valid -or
        [string]$Route.reason -cne 'native_global_route_selected' -or
        [string]$Route.source_class -cne 'global-native' -or
        [string]$Route.remote_class -cne 'global-native' -or
        -not (Test-I07StrictInteger -Value $Route.interface_index `
            -Minimum 1) -or
        [string]$Route.media_type -cnotin $mediaTypes -or
        [string]$Route.physical_media_type -cnotin $mediaTypes -or
        [string]$Route.destination_prefix -cne '::/0' -or
        [string]$Route.next_hop -cne $nextHop -or
        -not (Test-I07StrictInteger -Value $Route.route_metric -Minimum 0) -or
        -not (Test-I07StrictInteger -Value $Route.interface_metric `
            -Minimum 0) -or
        [string]$Route.address_state -cne 'Preferred' -or
        [string]$Route.prefix_origin -cnotin $prefixOrigins -or
        [string]$Route.suffix_origin -cnotin $suffixOrigins) {
        throw 'I07 PASS route cannot be projected into its closed contract.'
    }
    foreach ($name in @('hardware_interface', 'virtual', 'overlay',
            'default_route_present')) {
        if (-not (Test-I07StrictBoolean -Value $Route.$name)) {
            throw 'I07 PASS route contains a non-boolean adapter field.'
        }
    }
    if (-not [bool]$Route.hardware_interface -or [bool]$Route.virtual -or
        [bool]$Route.overlay -or -not [bool]$Route.default_route_present) {
        throw 'I07 PASS route is not a native physical default route.'
    }
    return [pscustomobject][ordered]@{
        captured_at_utc = [string]$Route.captured_at_utc
        reason = 'native_global_route_selected'
        source_address = ConvertTo-I07CanonicalIPv6 `
            -Value ([string]$Route.source_address)
        remote_address = ConvertTo-I07CanonicalIPv6 `
            -Value ([string]$Route.remote_address)
        source_class = 'global-native'; remote_class = 'global-native'
        interface_index = [Int64]$Route.interface_index
        interface_guid = ConvertTo-I07RetentionGuid `
            -Value ([string]$Route.interface_guid)
        media_type = [string]$Route.media_type
        physical_media_type = [string]$Route.physical_media_type
        hardware_interface = [bool]$Route.hardware_interface
        virtual = [bool]$Route.virtual
        destination_prefix = '::/0'; next_hop = $nextHop
        route_metric = [Int64]$Route.route_metric
        interface_metric = [Int64]$Route.interface_metric
        address_state = 'Preferred'
        prefix_origin = [string]$Route.prefix_origin
        suffix_origin = [string]$Route.suffix_origin
        default_route_present = [bool]$Route.default_route_present
        overlay = [bool]$Route.overlay
    }
}

function Get-I07PassProofSocket {
    param([Parameter(Mandatory = $true)]$Node)
    $socket = $Node.product.socket
    $local = ConvertTo-I07CanonicalIPv6 `
        -Value ([string]$Node.topology.local_ipv6)
    $peer = ConvertTo-I07CanonicalIPv6 `
        -Value ([string]$Node.topology.peer_ipv6)
    $matching = [Collections.Generic.List[object]]::new()
    foreach ($tuple in @($socket.tuples)) {
        try {
            if (-not (Test-I07ExactPropertySet -Value $tuple -Expected @(
                    'local_address', 'local_port', 'remote_address',
                    'remote_port', 'owning_process', 'state')) -or
                -not (Test-I07StrictInteger -Value $tuple.local_port `
                    -Minimum 1 -Maximum 65535) -or
                -not (Test-I07StrictInteger -Value $tuple.remote_port `
                    -Minimum 1 -Maximum 65535) -or
                -not (Test-I07StrictInteger -Value $tuple.owning_process `
                    -Minimum 1) -or
                [Int64]$tuple.owning_process -ne [Int64]$Node.candidate.pid -or
                (ConvertTo-I07CanonicalIPv6 `
                    -Value ([string]$tuple.local_address)) -cne $local -or
                (ConvertTo-I07CanonicalIPv6 `
                    -Value ([string]$tuple.remote_address)) -cne $peer -or
                [string]$tuple.state -cne 'Established') { continue }
            $portMatches = if ([string]$Node.role -ceq 'source') {
                [Int64]$tuple.local_port -eq [Int64]$Node.topology.ports.tcp
            } else {
                [Int64]$tuple.remote_port -eq
                    [Int64]$Node.topology.ports.peer_tcp
            }
            if (-not $portMatches) { continue }
            $matching.Add([pscustomobject][ordered]@{
                local_address = $local
                local_port = [Int64]$tuple.local_port
                remote_address = $peer
                remote_port = [Int64]$tuple.remote_port
                owning_process = [Int64]$tuple.owning_process
                state = 'Established'
            })
        } catch {}
    }
    if ($matching.Count -lt 1) {
        throw 'I07 PASS proof found no exact candidate peer socket.'
    }
    $tuple = @($matching | Sort-Object local_port, remote_port,
        owning_process)[0]
    return [pscustomobject][ordered]@{
        tuple_count = [Int64]1
        tuple = $tuple
        interface_index = [Int64]$socket.interface_index
        interface_guid = ConvertTo-I07RetentionGuid `
            -Value ([string]$socket.interface_guid)
        hardware_interface = [bool]$socket.hardware_interface
        virtual = [bool]$socket.virtual; overlay = [bool]$socket.overlay
        interface_matches_route = [bool]$socket.interface_matches_route
    }
}

function Get-I07PassProofSessionSummary {
    param([Parameter(Mandatory = $true)]$Node)
    $samples = @($Node.product.samples)
    if ($samples.Count -lt 1) { throw 'I07 PASS has no session samples.' }
    $first = [DateTimeOffset]::MinValue
    $last = [DateTimeOffset]::MinValue
    $previous = [DateTimeOffset]::MinValue
    $maximumGap = 0.0
    $flags = [ordered]@{
        socket_observed = $false; broadcasting_observed = $false
        api_peer_observed = $false; viewing_observed = $false
        playlist_observed = $false; segment_observed = $false
    }
    foreach ($sample in $samples) {
        $at = [DateTimeOffset]::MinValue
        if (-not (Test-I07UtcRetentionString -Value $sample.at_utc) -or
            -not [DateTimeOffset]::TryParse([string]$sample.at_utc,
                [ref]$at)) { throw 'I07 PASS sample time is malformed.' }
        if ($first -eq [DateTimeOffset]::MinValue) { $first = $at }
        if ($previous -ne [DateTimeOffset]::MinValue) {
            $maximumGap = [Math]::Max(
                $maximumGap, ($at - $previous).TotalSeconds)
        }
        $previous = $at; $last = $at
        if ([bool]$sample.peer_socket) { $flags.socket_observed = $true }
        if ([string]$Node.role -ceq 'source') {
            if ([bool]$sample.broadcasting) {
                $flags.broadcasting_observed = $true
            }
        } else {
            if ([bool]$sample.api_peer) { $flags.api_peer_observed = $true }
            if ([bool]$sample.viewing) { $flags.viewing_observed = $true }
            if ([bool]$sample.playlist) { $flags.playlist_observed = $true }
            if ([bool]$sample.segment) { $flags.segment_observed = $true }
        }
    }
    return [pscustomobject][ordered]@{
        sample_count = [Int64]$samples.Count
        first_sample_at_utc = $first.ToString('o')
        last_sample_at_utc = $last.ToString('o')
        maximum_gap_milliseconds =
            [Int64][Math]::Round($maximumGap * 1000.0)
        socket_observed = [bool]$flags.socket_observed
        broadcasting_observed = [bool]$flags.broadcasting_observed
        api_peer_observed = [bool]$flags.api_peer_observed
        viewing_observed = [bool]$flags.viewing_observed
        playlist_observed = [bool]$flags.playlist_observed
        segment_observed = [bool]$flags.segment_observed
    }
}

function Get-I07PassProofEvidence {
    param([Parameter(Mandatory = $true)]$Evidence)
    $files = @($Evidence.files | ForEach-Object {
            [pscustomobject][ordered]@{
                name = [string]$_.name; bytes = [Int64]$_.bytes
                sha256 = [string]$_.sha256
            }
        })
    $eventClasses = @($Evidence.log_evidence.events | ForEach-Object {
            [string]$_.event_class
        } | Sort-Object -Unique)
    return [pscustomobject][ordered]@{
        complete = [bool]$Evidence.complete
        manifest = [pscustomobject][ordered]@{
            name = [string]$Evidence.manifest.name
            bytes = [Int64]$Evidence.manifest.bytes
            sha256 = [string]$Evidence.manifest.sha256
        }
        files = $files
        requirements = [pscustomobject][ordered]@{
            build_info_exact = $Evidence.requirements.build_info_exact
            build_info_source_sha256 =
                [string]$Evidence.requirements.build_info_source_sha256
            config_allowlist_only =
                $Evidence.requirements.config_allowlist_only
            api_pre_retained = $Evidence.requirements.api_pre_retained
            api_post_retained = $Evidence.requirements.api_post_retained
            topology_ports_retained =
                $Evidence.requirements.topology_ports_retained
            real_log_line_count =
                [Int64]$Evidence.requirements.real_log_line_count
            timestamped_log_line_count =
                [Int64]$Evidence.requirements.timestamped_log_line_count
        }
        build_info = [pscustomobject][ordered]@{
            original_sha256 = [string]$Evidence.build_info.original_sha256
            expected_sha256 = [string]$Evidence.build_info.expected_sha256
            exact = $Evidence.build_info.exact
            fields_valid = $Evidence.build_info.fields_valid
            unknown_line_count =
                [Int64]$Evidence.build_info.unknown_line_count
        }
        effective_config = [pscustomobject][ordered]@{
            allowlist_only = $Evidence.effective_config.allowlist_only
            values_exact = $Evidence.effective_config.values_exact
            role = [string]$Evidence.effective_config.role
            entry_count = [Int64]@($Evidence.effective_config.entries).Count
        }
        log_evidence = [pscustomobject][ordered]@{
            source_file_count =
                [Int64]$Evidence.log_evidence.source_file_count
            inspected_nonempty_line_count =
                [Int64]$Evidence.log_evidence.inspected_nonempty_line_count
            timestamped_line_count =
                [Int64]$Evidence.log_evidence.timestamped_line_count
            capped_at_200_lines =
                $Evidence.log_evidence.capped_at_200_lines
            event_count = [Int64]@($Evidence.log_evidence.events).Count
            event_classes = $eventClasses
        }
    }
}

function New-I07PassProofValue {
    param(
        [Parameter(Mandatory = $true)]$Node,
        [Parameter(Mandatory = $true)]$Context,
        [Parameter(Mandatory = $true)][string]$SourceDigest,
        [Parameter(Mandatory = $true)][Int64]$SourceBytes
    )
    $node = $Node
    if ([string]$node.schema -cne 'ese.v91.i07-node-result/v1' -or
        [string]$node.case_id -cne 'V91-I07' -or
        [string]$node.topology.topology_id -cne 'T3' -or
        [string]$node.status -cne 'PASS' -or
        [string]$node.phase -cne 'route_revalidation' -or
        [string]$node.role -cne [string]$Context.role -or
        [string]$node.nonce -cne [string]$Context.nonce -or
        $null -ne $node.failure -or
        $null -ne $node.product.failure_evidence -or
        [string]$node.candidate.requested_sha256 -cne
            [string]$Context.candidate_sha256 -or
        [string]$node.candidate.commit -cne
            [string]$Context.candidate_commit -or
        [string]$node.candidate.sha256 -cne
            [string]$Context.candidate_sha256 -or
        [string]$node.candidate.build_info_sha256 -cne
            [string]$Context.build_info_sha256 -or
        [string]$node.candidate.zip_sha256 -cne
            [string]$Context.zip_sha256 -or
        [Int64]$node.candidate.zip_bytes -ne [Int64]$Context.zip_bytes -or
        -not (Test-I07StrictBoolean -Value $node.candidate.verified) -or
        -not [bool]$node.candidate.verified -or
        -not (Test-I07StrictBoolean -Value $node.candidate.zip_verified) -or
        -not [bool]$node.candidate.zip_verified -or
        -not (Test-I07NodePackageIdentity -Node $node -Context $Context)) {
        throw 'I07 PASS proof requires an authenticated PASS node.'
    }
    $initialRoute = ConvertTo-I07PassProofRoute `
        -Route $node.topology.initial_route
    $finalRoute = ConvertTo-I07PassProofRoute `
        -Route $node.topology.final_route
    $control = $node.topology.control
    $viewerHotspot = if ([string]$node.role -ceq 'viewer') {
        $profile = $node.topology.r01_hotspot_profile
        [pscustomobject][ordered]@{
            connection_profile_sha256 =
                [string]$profile.connection_profile.profile_sha256
            wlan_profile_sha256 =
                [string]$profile.wlan_profile.wlan_profile_sha256
            interface_guid = ConvertTo-I07RetentionGuid `
                -Value ([string]$profile.connection_profile.interface_guid)
            revalidated_at_utc = [string]$profile.revalidated_at_utc
        }
    } else { $null }
    $web = $node.topology.web_api_containment
    $broadcast = if ([string]$node.role -ceq 'source') {
        [pscustomobject][ordered]@{
            success = $node.product.broadcast.success
            ready = $node.product.broadcast.ready
            stream_key_sha256 =
                [string]$node.product.broadcast.stream_key_sha256
        }
    } else { $null }
    $directJoin = if ([string]$node.role -ceq 'viewer') {
        [pscustomobject][ordered]@{
            success = $node.product.direct_join.success
            dialed = $node.product.direct_join.dialed
            joined = $node.product.direct_join.joined
        }
    } else { $null }
    $apiPeer = if ([string]$node.role -ceq 'viewer') {
        $controlled = $node.product.api_peer.controlled_peer
        [pscustomobject][ordered]@{
            matched = $node.product.api_peer.matched
            address = ConvertTo-I07CanonicalIPv6 `
                -Value ([string]$controlled.address)
            port = [Int64]$controlled.port
            is_fork = $controlled.isFork
            dataplane_capable = $controlled.dataplaneCap
        }
    } else { $null }
    $hls = if ([string]$node.role -ceq 'viewer') {
        [pscustomobject][ordered]@{
            playlist_seen = $node.product.hls.playlist_seen
            segment_seen = $node.product.hls.segment_seen
            segment_path_contained =
                $node.product.hls.segment_path_contained
            playlist_name = [string]$node.product.hls.playlist_name
            stream_key_sha256 = [string]$node.product.hls.stream_key_sha256
            segment_bytes = [Int64]$node.product.hls.segment_bytes
            minimum_write_utc = [string]$node.product.hls.minimum_write_utc
            playlist_last_write_utc =
                [string]$node.product.hls.playlist_last_write_utc
            segment_last_write_utc =
                [string]$node.product.hls.segment_last_write_utc
        }
    } else { $null }
    $packageFiles = @(Assert-I07CriticalPackageContract `
        -Files @($node.candidate.package_files) | Sort-Object path |
        ForEach-Object {
            [pscustomobject][ordered]@{
                path = [string]$_.path; bytes = [Int64]$_.bytes
                sha256 = [string]$_.sha256
            }
        })
    $proof = [pscustomobject][ordered]@{
        schema = 'ese.v91.i07-pass-proof/v1'
        case_id = 'V91-I07'; status = 'PASS'
        role = [string]$node.role; nonce = [string]$node.nonce
        topology_id = 'T3'
        expected_duration_seconds = [Int64]$Context.duration_seconds
        completed_at_utc = [string]$node.completed_at_utc
        source_result_sha256 = $SourceDigest
        source_result_bytes = $SourceBytes
        r01_prerequisite_sha256 =
            [string]$Context.r01_prerequisite_sha256
        r01_prerequisite_bytes =
            [Int64]$Context.r01_prerequisite_bytes
        candidate = [pscustomobject][ordered]@{
            version = [string]$Context.candidate_version
            commit = [string]$node.candidate.commit
            emule_sha256 = [string]$node.candidate.sha256
            bytes = [Int64]$node.candidate.bytes
            build_info_sha256 = [string]$node.candidate.build_info_sha256
            zip_sha256 = [string]$node.candidate.zip_sha256
            zip_bytes = [Int64]$node.candidate.zip_bytes
            pid = [Int64]$node.candidate.pid
            started_at_utc = [string]$node.candidate.started_at_utc
            verified = $node.candidate.verified
            package_files = $packageFiles
        }
        topology = [pscustomobject][ordered]@{
            local_ipv6 = ConvertTo-I07CanonicalIPv6 `
                -Value ([string]$node.topology.local_ipv6)
            peer_ipv6 = ConvertTo-I07CanonicalIPv6 `
                -Value ([string]$node.topology.peer_ipv6)
            interface_index = [Int64]$node.topology.interface_index
            interface_guid = ConvertTo-I07RetentionGuid `
                -Value ([string]$node.topology.interface_guid)
            ports = [pscustomobject][ordered]@{
                tcp = [Int64]$node.topology.ports.tcp
                udp = [Int64]$node.topology.ports.udp
                web = [Int64]$node.topology.ports.web
                peer_tcp = [Int64]$node.topology.ports.peer_tcp
                control = [Int64]$node.topology.ports.control
            }
            initial_route = $initialRoute; final_route = $finalRoute
            control = [pscustomobject][ordered]@{
                bidirectional = $control.bidirectional
                proven_at_utc = [string]$control.proven_at_utc
                local_address = ConvertTo-I07CanonicalIPv6 `
                    -Value ([string]$control.local_address)
                local_port = [Int64]$control.local_port
                remote_address = ConvertTo-I07CanonicalIPv6 `
                    -Value ([string]$control.remote_address)
                remote_port = [Int64]$control.remote_port
            }
            viewer_hotspot = $viewerHotspot
            web_containment = [pscustomobject][ordered]@{
                satisfied = $web.blocks_physical_ipv4_and_ipv6
                local_port = [Int64]$web.local_port
                program_leaf = [string]$web.program_leaf
            }
            socket = Get-I07PassProofSocket -Node $node
        }
        product = [pscustomobject][ordered]@{
            broadcast = $broadcast; direct_join = $directJoin
            api_peer = $apiPeer; hls = $hls
            api_status_initial = ConvertTo-I07FailureProofApiStatus `
                -Status $node.product.api_status_initial
            api_status_final = ConvertTo-I07FailureProofApiStatus `
                -Status $node.product.api_status_final
            session_summary = Get-I07PassProofSessionSummary -Node $node
        }
        evidence = Get-I07PassProofEvidence -Evidence $node.evidence
        cleanup = [pscustomobject][ordered]@{
            process_stopped = $node.cleanup.process_stopped
            firewall_removed = $node.cleanup.firewall_removed
            control_closed = $node.cleanup.control_closed
            broadcast_stopped = $node.cleanup.broadcast_stopped
            ffmpeg_children_gone = $node.cleanup.ffmpeg_children_gone
            hls_removed = $node.cleanup.hls_removed
            node_removed = $node.cleanup.node_removed
            evidence_retained = $node.cleanup.evidence_retained
            system_state_restored = $node.cleanup.system_state_restored
        }
    }
    return $proof
}

function New-I07PassProofSnapshot {
    param(
        [Parameter(Mandatory = $true)]$SourceSnapshot,
        [Parameter(Mandatory = $true)]$Context
    )
    $sourceBytes = [byte[]]$SourceSnapshot.bytes_value
    if ($sourceBytes.Length -lt 1 -or
        [Int64]$sourceBytes.Length -ne [Int64]$SourceSnapshot.byte_count) {
        throw 'I07 PASS source snapshot byte count is inconsistent.'
    }
    $sourceHasher = [Security.Cryptography.SHA256]::Create()
    try {
        $sourceDigest = ([BitConverter]::ToString(
            $sourceHasher.ComputeHash($sourceBytes))).Replace('-', '').
                ToLowerInvariant()
    } finally { $sourceHasher.Dispose() }
    if ($sourceDigest -cne [string]$SourceSnapshot.sha256) {
        throw 'I07 PASS source snapshot SHA-256 is inconsistent.'
    }
    $node = ConvertFrom-I07Utf8JsonBytes -Bytes $sourceBytes
    $declaredJson = $SourceSnapshot.value | ConvertTo-Json -Depth 24 -Compress
    $parsedJson = $node | ConvertTo-Json -Depth 24 -Compress
    if ($declaredJson -cne $parsedJson) {
        throw 'I07 PASS source snapshot value is not derived from its bytes.'
    }
    $proof = New-I07PassProofValue -Node $node -Context $Context `
        -SourceDigest $sourceDigest -SourceBytes $sourceBytes.Length
    if (-not (Test-I07PassProofContract -Value $proof `
            -SourceSnapshot $SourceSnapshot -Context $Context)) {
        throw 'Sanitized I07 PASS proof violated its exact contract.'
    }
    $snapshot = New-I07CanonicalJsonSnapshot -Value $proof
    $json = [Text.UTF8Encoding]::new($false).GetString(
        [byte[]]$snapshot.bytes_value)
    $reloaded = $json | ConvertFrom-Json
    if (-not (Test-I07PassProofContract -Value $reloaded `
            -SourceSnapshot $SourceSnapshot -Context $Context)) {
        throw 'Serialized I07 PASS proof failed exact reload validation.'
    }
    return [pscustomobject][ordered]@{
        bytes_value = $snapshot.bytes_value
        byte_count = [Int64]$snapshot.byte_count
        sha256 = [string]$snapshot.sha256
        value = $reloaded
    }
}

function Test-I07PassProofRouteContract {
    param([Parameter(Mandatory = $true)]$Route)
    try {
        $mediaTypes = @('802.3', 'Native 802.11', 'Wireless WAN')
        $prefixOrigins = @(
            'Manual', 'Dhcp', 'RouterAdvertisement', 'WellKnown')
        $suffixOrigins = @(
            'Manual', 'Dhcp', 'Link', 'Random', 'WellKnown')
        foreach ($name in @('hardware_interface', 'virtual', 'overlay',
                'default_route_present')) {
            if (-not (Test-I07StrictBoolean -Value $Route.$name)) {
                return $false
            }
        }
        $source = ConvertTo-I07CanonicalIPv6 `
            -Value ([string]$Route.source_address)
        $remote = ConvertTo-I07CanonicalIPv6 `
            -Value ([string]$Route.remote_address)
        $nextHop = ConvertTo-I07CanonicalIPv6 `
            -Value ([string]$Route.next_hop)
        return (
            (Test-I07ExactPropertySet -Value $Route -Expected @(
                'captured_at_utc', 'reason', 'source_address',
                'remote_address', 'source_class', 'remote_class',
                'interface_index', 'interface_guid', 'media_type',
                'physical_media_type', 'hardware_interface', 'virtual',
                'destination_prefix', 'next_hop', 'route_metric',
                'interface_metric', 'address_state', 'prefix_origin',
                'suffix_origin', 'default_route_present', 'overlay')) -and
            (Test-I07UtcRetentionString -Value $Route.captured_at_utc) -and
            [string]$Route.reason -ceq 'native_global_route_selected' -and
            [string]$Route.source_address -ceq $source -and
            [string]$Route.remote_address -ceq $remote -and
            (Get-I07IPv6Class -Address ([Net.IPAddress]::Parse($source))) `
                -ceq 'global-native' -and
            (Get-I07IPv6Class -Address ([Net.IPAddress]::Parse($remote))) `
                -ceq 'global-native' -and
            [string]$Route.source_class -ceq 'global-native' -and
            [string]$Route.remote_class -ceq 'global-native' -and
            (Test-I07StrictInteger -Value $Route.interface_index `
                -Minimum 1) -and
            (Test-I07GuidRetentionString -Value $Route.interface_guid) -and
            [string]$Route.media_type -cin $mediaTypes -and
            [string]$Route.physical_media_type -cin $mediaTypes -and
            [bool]$Route.hardware_interface -and -not [bool]$Route.virtual -and
            [string]$Route.destination_prefix -ceq '::/0' -and
            [string]$Route.next_hop -ceq $nextHop -and
            (Test-I07StrictInteger -Value $Route.route_metric -Minimum 0) -and
            (Test-I07StrictInteger -Value $Route.interface_metric `
                -Minimum 0) -and
            [string]$Route.address_state -ceq 'Preferred' -and
            [string]$Route.prefix_origin -cin $prefixOrigins -and
            [string]$Route.suffix_origin -cin $suffixOrigins -and
            [bool]$Route.default_route_present -and -not [bool]$Route.overlay)
    } catch { return $false }
}

function Test-I07PassProofEvidenceContract {
    param(
        [Parameter(Mandatory = $true)]$Evidence,
        [Parameter(Mandatory = $true)]$Candidate,
        [Parameter(Mandatory = $true)][string]$Role
    )
    try {
        if (-not (Test-I07ExactPropertySet -Value $Evidence -Expected @(
                'complete', 'manifest', 'files', 'requirements',
                'build_info', 'effective_config', 'log_evidence')) -or
            -not (Test-I07StrictBoolean -Value $Evidence.complete) -or
            -not [bool]$Evidence.complete -or
            -not (Test-I07ExactPropertySet -Value $Evidence.manifest `
                -Expected @('name', 'bytes', 'sha256')) -or
            [string]$Evidence.manifest.name -cne 'manifest.json' -or
            -not (Test-I07StrictInteger -Value $Evidence.manifest.bytes `
                -Minimum 1) -or
            -not (Test-I07Sha256RetentionString `
                -Value $Evidence.manifest.sha256)) { return $false }
        $expectedNames = @(
            'BUILD_INFO.txt', 'build-info-evidence.json',
            'effective-config.json', 'api-status-pre.json',
            'api-status-post.json', 'topology-ports.json',
            'log-evidence.json')
        $files = @($Evidence.files)
        if ($files.Count -ne $expectedNames.Count) { return $false }
        $observedNames = @()
        foreach ($file in $files) {
            if (-not (Test-I07ExactPropertySet -Value $file -Expected @(
                    'name', 'bytes', 'sha256')) -or
                [string]$file.name -cnotin $expectedNames -or
                -not (Test-I07StrictInteger -Value $file.bytes -Minimum 1) -or
                -not (Test-I07Sha256RetentionString -Value $file.sha256)) {
                return $false
            }
            $observedNames += [string]$file.name
        }
        if (@($observedNames | Select-Object -Unique).Count -ne
                $expectedNames.Count -or
            (@($observedNames | Sort-Object) -join "`n") -cne
                (@($expectedNames | Sort-Object) -join "`n")) {
            return $false
        }
        $rawBuild = @($files | Where-Object {
                [string]$_.name -ceq 'BUILD_INFO.txt'
            })
        $requirements = $Evidence.requirements
        if ($rawBuild.Count -ne 1 -or
            [string]$rawBuild[0].sha256 -cne
                [string]$Candidate.build_info_sha256 -or
            -not (Test-I07ExactPropertySet -Value $requirements -Expected @(
                'build_info_exact', 'build_info_source_sha256',
                'config_allowlist_only', 'api_pre_retained',
                'api_post_retained', 'topology_ports_retained',
                'real_log_line_count', 'timestamped_log_line_count')) -or
            [string]$requirements.build_info_source_sha256 -cne
                [string]$Candidate.build_info_sha256) { return $false }
        foreach ($name in @(
                'build_info_exact', 'config_allowlist_only',
                'api_pre_retained', 'api_post_retained',
                'topology_ports_retained')) {
            if (-not (Test-I07StrictBoolean -Value $requirements.$name) -or
                -not [bool]$requirements.$name) { return $false }
        }
        if (-not (Test-I07StrictInteger `
                -Value $requirements.real_log_line_count -Minimum 1 `
                -Maximum 200) -or
            -not (Test-I07StrictInteger `
                -Value $requirements.timestamped_log_line_count -Minimum 1 `
                -Maximum 200)) { return $false }
        $build = $Evidence.build_info
        if (-not (Test-I07ExactPropertySet -Value $build -Expected @(
                'original_sha256', 'expected_sha256', 'exact',
                'fields_valid', 'unknown_line_count')) -or
            [string]$build.original_sha256 -cne
                [string]$Candidate.build_info_sha256 -or
            [string]$build.expected_sha256 -cne
                [string]$Candidate.build_info_sha256 -or
            -not (Test-I07StrictBoolean -Value $build.exact) -or
            -not [bool]$build.exact -or
            -not (Test-I07StrictBoolean -Value $build.fields_valid) -or
            -not [bool]$build.fields_valid -or
            -not (Test-I07StrictInteger -Value $build.unknown_line_count `
                -Minimum 0 -Maximum 0)) { return $false }
        $config = $Evidence.effective_config
        if (-not (Test-I07ExactPropertySet -Value $config -Expected @(
                'allowlist_only', 'values_exact', 'role', 'entry_count')) -or
            -not (Test-I07StrictBoolean -Value $config.allowlist_only) -or
            -not [bool]$config.allowlist_only -or
            -not (Test-I07StrictBoolean -Value $config.values_exact) -or
            -not [bool]$config.values_exact -or
            [string]$config.role -cne $Role -or
            -not (Test-I07StrictInteger -Value $config.entry_count `
                -Minimum 27 -Maximum 27)) { return $false }
        $log = $Evidence.log_evidence
        if (-not (Test-I07ExactPropertySet -Value $log -Expected @(
                'source_file_count', 'inspected_nonempty_line_count',
                'timestamped_line_count', 'capped_at_200_lines',
                'event_count', 'event_classes')) -or
            -not (Test-I07StrictInteger -Value $log.source_file_count `
                -Minimum 1) -or
            -not (Test-I07StrictInteger `
                -Value $log.inspected_nonempty_line_count -Minimum 1 `
                -Maximum 200) -or
            -not (Test-I07StrictInteger -Value $log.timestamped_line_count `
                -Minimum 1 -Maximum 200) -or
            [Int64]$log.timestamped_line_count -gt
                [Int64]$log.inspected_nonempty_line_count -or
            -not (Test-I07StrictBoolean -Value $log.capped_at_200_lines) -or
            [bool]$log.capped_at_200_lines -ne
                ([Int64]$log.inspected_nonempty_line_count -ge 200) -or
            -not (Test-I07StrictInteger -Value $log.event_count `
                -Minimum 1 -Maximum 20) -or
            [Int64]$log.event_count -ne [Math]::Min(
                20, [Int64]$log.timestamped_line_count) -or
            [Int64]$requirements.real_log_line_count -ne
                [Int64]$log.inspected_nonempty_line_count -or
            [Int64]$requirements.timestamped_log_line_count -ne
                [Int64]$log.timestamped_line_count) { return $false }
        $classes = @($log.event_classes)
        if ($classes.Count -lt 1 -or
            @($classes | Select-Object -Unique).Count -ne $classes.Count -or
            ($classes -join "`n") -cne (@($classes | Sort-Object) -join "`n") -or
            @($classes | Where-Object {
                    [string]$_ -cnotin @(
                        'error', 'warning', 'livetv', 'connectivity',
                        'lifecycle', 'other')
                }).Count -ne 0) { return $false }
        return $true
    } catch { return $false }
}

function Test-I07PassProofContract {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)]$SourceSnapshot,
        [Parameter(Mandatory = $true)]$Context
    )
    try {
        $sourceBytes = [byte[]]$SourceSnapshot.bytes_value
        if ($sourceBytes.Length -lt 1 -or
            [Int64]$sourceBytes.Length -ne [Int64]$SourceSnapshot.byte_count) {
            return $false
        }
        $hasher = [Security.Cryptography.SHA256]::Create()
        try {
            $sourceDigest = ([BitConverter]::ToString(
                $hasher.ComputeHash($sourceBytes))).Replace('-', '').
                    ToLowerInvariant()
        } finally { $hasher.Dispose() }
        if ($sourceDigest -cne [string]$SourceSnapshot.sha256 -or
            [string]$Value.source_result_sha256 -cne $sourceDigest -or
            [Int64]$Value.source_result_bytes -ne $sourceBytes.Length) {
            return $false
        }
        $sourceNode = ConvertFrom-I07Utf8JsonBytes -Bytes $sourceBytes
        $declaredSourceJson = $SourceSnapshot.value |
            ConvertTo-Json -Depth 24 -Compress
        $parsedSourceJson = $sourceNode |
            ConvertTo-Json -Depth 24 -Compress
        if ($declaredSourceJson -cne $parsedSourceJson) { return $false }
        $expectedValue = New-I07PassProofValue -Node $sourceNode `
            -Context $Context -SourceDigest $sourceDigest `
            -SourceBytes $sourceBytes.Length
        $expectedJson = $expectedValue | ConvertTo-Json -Depth 24 -Compress
        $observedJson = $Value | ConvertTo-Json -Depth 24 -Compress
        if ($observedJson -cne $expectedJson) { return $false }
        if (-not (Test-I07ExactPropertySet -Value $Value -Expected @(
                'schema', 'case_id', 'status', 'role', 'nonce',
                'topology_id', 'expected_duration_seconds',
                'completed_at_utc', 'source_result_sha256',
                'source_result_bytes', 'r01_prerequisite_sha256',
                'r01_prerequisite_bytes', 'candidate', 'topology',
                'product', 'evidence', 'cleanup')) -or
            [string]$Value.schema -cne 'ese.v91.i07-pass-proof/v1' -or
            [string]$Value.case_id -cne 'V91-I07' -or
            [string]$Value.status -cne 'PASS' -or
            [string]$Value.role -cnotin @('source', 'viewer') -or
            [string]$Value.role -cne [string]$Context.role -or
            -not (Test-I07NonceRetentionString -Value $Value.nonce) -or
            [string]$Value.nonce -cne [string]$Context.nonce -or
            [string]$Value.topology_id -cne 'T3' -or
            -not (Test-I07StrictInteger `
                -Value $Value.expected_duration_seconds `
                -Minimum 15 -Maximum 180) -or
            [Int64]$Value.expected_duration_seconds -ne
                [Int64]$Context.duration_seconds -or
            -not (Test-I07UtcRetentionString `
                -Value $Value.completed_at_utc) -or
            -not (Test-I07Sha256RetentionString `
                -Value $Value.r01_prerequisite_sha256) -or
            [string]$Value.r01_prerequisite_sha256 -cne
                [string]$Context.r01_prerequisite_sha256 -or
            -not (Test-I07StrictInteger `
                -Value $Value.r01_prerequisite_bytes -Minimum 1) -or
            [Int64]$Value.r01_prerequisite_bytes -ne
                [Int64]$Context.r01_prerequisite_bytes) { return $false }

        $candidate = $Value.candidate
        if (-not (Test-I07ExactPropertySet -Value $candidate -Expected @(
                'version', 'commit', 'emule_sha256', 'bytes',
                'build_info_sha256', 'zip_sha256', 'zip_bytes', 'pid',
                'started_at_utc', 'verified', 'package_files')) -or
            [string]$candidate.version -cne
                [string]$Context.candidate_version -or
            [string]$candidate.version -cnotmatch
                '^[A-Za-z0-9._+-]{1,64}$' -or
            [string]$candidate.commit -cne
                [string]$Context.candidate_commit -or
            [string]$candidate.commit -cnotmatch '^[0-9a-f]{40}$' -or
            [string]$candidate.emule_sha256 -cne
                [string]$Context.candidate_sha256 -or
            -not (Test-I07Sha256RetentionString `
                -Value $candidate.emule_sha256) -or
            -not (Test-I07StrictInteger -Value $candidate.bytes -Minimum 1) -or
            [string]$candidate.build_info_sha256 -cne
                [string]$Context.build_info_sha256 -or
            -not (Test-I07Sha256RetentionString `
                -Value $candidate.build_info_sha256) -or
            [string]$candidate.zip_sha256 -cne [string]$Context.zip_sha256 -or
            -not (Test-I07Sha256RetentionString `
                -Value $candidate.zip_sha256) -or
            -not (Test-I07StrictInteger -Value $candidate.zip_bytes `
                -Minimum 1) -or
            [Int64]$candidate.zip_bytes -ne [Int64]$Context.zip_bytes -or
            -not (Test-I07StrictInteger -Value $candidate.pid -Minimum 1) -or
            -not (Test-I07UtcRetentionString `
                -Value $candidate.started_at_utc) -or
            -not (Test-I07StrictBoolean -Value $candidate.verified) -or
            -not [bool]$candidate.verified) { return $false }
        $candidateFiles = @(Assert-I07CriticalPackageContract `
            -Files @($candidate.package_files) | Sort-Object path)
        $expectedFiles = @(Assert-I07CriticalPackageContract `
            -Files @($Context.package_files) | Sort-Object path)
        $candidateFileText = @($candidateFiles | ForEach-Object {
                '{0}|{1}|{2}' -f $_.path, [Int64]$_.bytes, $_.sha256
            }) -join "`n"
        $expectedFileText = @($expectedFiles | ForEach-Object {
                '{0}|{1}|{2}' -f $_.path, [Int64]$_.bytes, $_.sha256
            }) -join "`n"
        $emuleFile = @($candidateFiles | Where-Object path -ceq 'emule.exe')
        if ($candidateFileText -cne $expectedFileText -or
            $emuleFile.Count -ne 1 -or
            [string]$emuleFile[0].sha256 -cne
                [string]$candidate.emule_sha256 -or
            [Int64]$emuleFile[0].bytes -ne [Int64]$candidate.bytes) {
            return $false
        }

        $topology = $Value.topology
        if (-not (Test-I07ExactPropertySet -Value $topology -Expected @(
                'local_ipv6', 'peer_ipv6', 'interface_index',
                'interface_guid', 'ports', 'initial_route', 'final_route',
                'control', 'viewer_hotspot', 'web_containment', 'socket')) -or
            -not (Test-I07ExactPropertySet -Value $topology.ports -Expected @(
                'tcp', 'udp', 'web', 'peer_tcp', 'control'))) {
            return $false
        }
        $local = ConvertTo-I07CanonicalIPv6 `
            -Value ([string]$topology.local_ipv6)
        $peer = ConvertTo-I07CanonicalIPv6 `
            -Value ([string]$topology.peer_ipv6)
        if ($local -cne (ConvertTo-I07CanonicalIPv6 `
                -Value ([string]$Context.local_ipv6)) -or
            $peer -cne (ConvertTo-I07CanonicalIPv6 `
                -Value ([string]$Context.peer_ipv6)) -or
            (Get-I07IPv6Class -Address ([Net.IPAddress]::Parse($local))) `
                -cne 'global-native' -or
            (Get-I07IPv6Class -Address ([Net.IPAddress]::Parse($peer))) `
                -cne 'global-native' -or
            -not (Test-I07StrictInteger -Value $topology.interface_index `
                -Minimum 1) -or
            [Int64]$topology.interface_index -ne
                [Int64]$Context.interface_index -or
            (ConvertTo-I07RetentionGuid `
                -Value ([string]$topology.interface_guid)) -cne
                (ConvertTo-I07RetentionGuid `
                    -Value ([string]$Context.interface_guid))) { return $false }
        foreach ($name in @('tcp', 'udp', 'web', 'peer_tcp', 'control')) {
            if (-not (Test-I07StrictInteger -Value $topology.ports.$name `
                    -Minimum 1024 -Maximum 65535) -or
                [Int64]$topology.ports.$name -ne
                    [Int64]$Context.("${name}_port")) { return $false }
        }
        if (-not (Test-I07PassProofRouteContract `
                -Route $topology.initial_route) -or
            -not (Test-I07PassProofRouteContract `
                -Route $topology.final_route)) { return $false }
        foreach ($route in @($topology.initial_route, $topology.final_route)) {
            if ([string]$route.source_address -cne $local -or
                [string]$route.remote_address -cne $peer -or
                [Int64]$route.interface_index -ne
                    [Int64]$topology.interface_index -or
                [string]$route.interface_guid -cne
                    [string]$topology.interface_guid) { return $false }
        }
        $control = $topology.control
        if (-not (Test-I07ExactPropertySet -Value $control -Expected @(
                'bidirectional', 'proven_at_utc', 'local_address',
                'local_port', 'remote_address', 'remote_port')) -or
            -not (Test-I07StrictBoolean -Value $control.bidirectional) -or
            -not [bool]$control.bidirectional -or
            -not (Test-I07UtcRetentionString -Value $control.proven_at_utc) -or
            [string]$control.local_address -cne $local -or
            [string]$control.remote_address -cne $peer -or
            -not (Test-I07StrictInteger -Value $control.local_port `
                -Minimum 1024 -Maximum 65535) -or
            -not (Test-I07StrictInteger -Value $control.remote_port `
                -Minimum 1024 -Maximum 65535)) { return $false }
        if (([string]$Value.role -ceq 'source' -and
                [Int64]$control.local_port -ne
                    [Int64]$topology.ports.control) -or
            ([string]$Value.role -ceq 'viewer' -and
                [Int64]$control.remote_port -ne
                    [Int64]$topology.ports.control)) { return $false }

        if ([string]$Value.role -ceq 'source') {
            if ($null -ne $topology.viewer_hotspot) { return $false }
        } else {
            $hotspot = $topology.viewer_hotspot
            if (-not (Test-I07ExactPropertySet -Value $hotspot -Expected @(
                    'connection_profile_sha256', 'wlan_profile_sha256',
                    'interface_guid', 'revalidated_at_utc')) -or
                [string]$hotspot.connection_profile_sha256 -cne
                    [string]$Context.hotspot_connection_profile_sha256 -or
                [string]$hotspot.wlan_profile_sha256 -cne
                    [string]$Context.hotspot_wlan_profile_sha256 -or
                [string]$hotspot.interface_guid -cne
                    [string]$topology.interface_guid -or
                -not (Test-I07UtcRetentionString `
                    -Value $hotspot.revalidated_at_utc)) { return $false }
        }
        $web = $topology.web_containment
        if (-not (Test-I07ExactPropertySet -Value $web -Expected @(
                'satisfied', 'local_port', 'program_leaf')) -or
            -not (Test-I07StrictBoolean -Value $web.satisfied) -or
            -not [bool]$web.satisfied -or
            -not (Test-I07StrictInteger -Value $web.local_port `
                -Minimum 1024 -Maximum 65535) -or
            [Int64]$web.local_port -ne [Int64]$topology.ports.web -or
            [string]$web.program_leaf -cne 'emule.exe') { return $false }
        $socket = $topology.socket
        if (-not (Test-I07ExactPropertySet -Value $socket -Expected @(
                'tuple_count', 'tuple', 'interface_index', 'interface_guid',
                'hardware_interface', 'virtual', 'overlay',
                'interface_matches_route')) -or
            -not (Test-I07StrictInteger -Value $socket.tuple_count `
                -Minimum 1 -Maximum 1) -or
            -not (Test-I07ExactPropertySet -Value $socket.tuple -Expected @(
                'local_address', 'local_port', 'remote_address',
                'remote_port', 'owning_process', 'state')) -or
            [string]$socket.tuple.local_address -cne $local -or
            [string]$socket.tuple.remote_address -cne $peer -or
            -not (Test-I07StrictInteger -Value $socket.tuple.local_port `
                -Minimum 1 -Maximum 65535) -or
            -not (Test-I07StrictInteger -Value $socket.tuple.remote_port `
                -Minimum 1 -Maximum 65535) -or
            -not (Test-I07StrictInteger -Value $socket.tuple.owning_process `
                -Minimum 1) -or
            [Int64]$socket.tuple.owning_process -ne
                [Int64]$candidate.pid -or
            [string]$socket.tuple.state -cne 'Established' -or
            [Int64]$socket.interface_index -ne
                [Int64]$topology.interface_index -or
            [string]$socket.interface_guid -cne
                [string]$topology.interface_guid) { return $false }
        foreach ($name in @('hardware_interface', 'virtual', 'overlay',
                'interface_matches_route')) {
            if (-not (Test-I07StrictBoolean -Value $socket.$name)) {
                return $false
            }
        }
        if (-not [bool]$socket.hardware_interface -or [bool]$socket.virtual -or
            [bool]$socket.overlay -or
            -not [bool]$socket.interface_matches_route -or
            ([string]$Value.role -ceq 'source' -and
                [Int64]$socket.tuple.local_port -ne
                    [Int64]$topology.ports.tcp) -or
            ([string]$Value.role -ceq 'viewer' -and
                [Int64]$socket.tuple.remote_port -ne
                    [Int64]$topology.ports.peer_tcp)) { return $false }

        $product = $Value.product
        if (-not (Test-I07ExactPropertySet -Value $product -Expected @(
                'broadcast', 'direct_join', 'api_peer', 'hls',
                'api_status_initial', 'api_status_final',
                'session_summary')) -or
            -not (Test-I07FailureProofApiStatusContract `
                -Status $product.api_status_initial) -or
            -not (Test-I07FailureProofApiStatusContract `
                -Status $product.api_status_final) -or
            -not [bool]$product.api_status_initial.available -or
            -not [bool]$product.api_status_initial.contract_valid -or
            -not [bool]$product.api_status_initial.
                isolation_invariant_satisfied -or
            -not [bool]$product.api_status_final.available -or
            -not [bool]$product.api_status_final.contract_valid -or
            -not [bool]$product.api_status_final.
                isolation_invariant_satisfied) { return $false }
        $session = $product.session_summary
        if (-not (Test-I07ExactPropertySet -Value $session -Expected @(
                'sample_count', 'first_sample_at_utc', 'last_sample_at_utc',
                'maximum_gap_milliseconds', 'socket_observed',
                'broadcasting_observed', 'api_peer_observed',
                'viewing_observed', 'playlist_observed',
                'segment_observed')) -or
            -not (Test-I07StrictInteger -Value $session.sample_count `
                -Minimum 2) -or
            -not (Test-I07UtcRetentionString `
                -Value $session.first_sample_at_utc) -or
            -not (Test-I07UtcRetentionString `
                -Value $session.last_sample_at_utc) -or
            -not (Test-I07StrictInteger `
                -Value $session.maximum_gap_milliseconds -Minimum 0)) {
            return $false
        }
        foreach ($name in @(
                'socket_observed', 'broadcasting_observed',
                'api_peer_observed', 'viewing_observed',
                'playlist_observed', 'segment_observed')) {
            if (-not (Test-I07StrictBoolean -Value $session.$name)) {
                return $false
            }
        }
        $started = [DateTimeOffset]::Parse(
            [string]$candidate.started_at_utc)
        $initialAt = [DateTimeOffset]::Parse(
            [string]$topology.initial_route.captured_at_utc)
        $controlAt = [DateTimeOffset]::Parse([string]$control.proven_at_utc)
        $apiInitialAt = [DateTimeOffset]::Parse(
            [string]$product.api_status_initial.captured_at_utc)
        $firstAt = [DateTimeOffset]::Parse(
            [string]$session.first_sample_at_utc)
        $lastAt = [DateTimeOffset]::Parse(
            [string]$session.last_sample_at_utc)
        $finalAt = [DateTimeOffset]::Parse(
            [string]$topology.final_route.captured_at_utc)
        $apiFinalAt = [DateTimeOffset]::Parse(
            [string]$product.api_status_final.captured_at_utc)
        $completed = [DateTimeOffset]::Parse([string]$Value.completed_at_utc)
        $allowedGapMs = if ([string]$Value.role -ceq 'source') {
            8000
        } else { 20000 }
        if ($initialAt -gt $controlAt -or $controlAt -gt $started -or
            $started -gt $apiInitialAt -or $firstAt -lt $started -or
            $firstAt -gt $lastAt -or $lastAt -gt $finalAt -or
            $apiInitialAt -gt $finalAt -or $finalAt -gt $apiFinalAt -or
            $apiFinalAt -gt $completed -or
            ($lastAt - $firstAt).TotalSeconds -lt
                ([double]$Value.expected_duration_seconds - 2.0) -or
            [Int64]$session.maximum_gap_milliseconds -gt $allowedGapMs -or
            ($completed - $lastAt).TotalMilliseconds -gt $allowedGapMs) {
            return $false
        }
        if ([string]$Value.role -ceq 'source') {
            if ($null -eq $product.broadcast -or
                $null -ne $product.direct_join -or
                $null -ne $product.api_peer -or $null -ne $product.hls -or
                -not (Test-I07ExactPropertySet -Value $product.broadcast `
                    -Expected @('success', 'ready', 'stream_key_sha256')) -or
                -not (Test-I07StrictBoolean `
                    -Value $product.broadcast.success) -or
                -not [bool]$product.broadcast.success -or
                -not (Test-I07StrictBoolean `
                    -Value $product.broadcast.ready) -or
                -not [bool]$product.broadcast.ready -or
                -not (Test-I07Sha256RetentionString `
                    -Value $product.broadcast.stream_key_sha256) -or
                -not [bool]$session.socket_observed -or
                -not [bool]$session.broadcasting_observed) { return $false }
        } else {
            if ($null -ne $product.broadcast -or
                -not (Test-I07ExactPropertySet -Value $product.direct_join `
                    -Expected @('success', 'dialed', 'joined'))) {
                return $false
            }
            foreach ($name in @('success', 'dialed')) {
                if (-not (Test-I07StrictBoolean `
                        -Value $product.direct_join.$name) -or
                    -not [bool]$product.direct_join.$name) { return $false }
            }
            if ($null -ne $product.direct_join.joined -and
                -not (Test-I07StrictBoolean `
                    -Value $product.direct_join.joined)) { return $false }
            $apiPeer = $product.api_peer
            if (-not (Test-I07ExactPropertySet -Value $apiPeer -Expected @(
                    'matched', 'address', 'port', 'is_fork',
                    'dataplane_capable')) -or
                -not (Test-I07StrictBoolean -Value $apiPeer.matched) -or
                -not [bool]$apiPeer.matched -or
                [string]$apiPeer.address -cne $peer -or
                -not (Test-I07StrictInteger -Value $apiPeer.port `
                    -Minimum 1024 -Maximum 65535) -or
                [Int64]$apiPeer.port -ne [Int64]$topology.ports.peer_tcp -or
                -not (Test-I07StrictBoolean -Value $apiPeer.is_fork) -or
                -not [bool]$apiPeer.is_fork -or
                -not (Test-I07StrictBoolean `
                    -Value $apiPeer.dataplane_capable) -or
                -not [bool]$apiPeer.dataplane_capable) { return $false }
            $hls = $product.hls
            if (-not (Test-I07ExactPropertySet -Value $hls -Expected @(
                    'playlist_seen', 'segment_seen',
                    'segment_path_contained', 'playlist_name',
                    'stream_key_sha256', 'segment_bytes',
                    'minimum_write_utc', 'playlist_last_write_utc',
                    'segment_last_write_utc')) -or
                [string]$hls.playlist_name -cne 'stream.m3u8' -or
                -not (Test-I07Sha256RetentionString `
                    -Value $hls.stream_key_sha256) -or
                -not (Test-I07StrictInteger -Value $hls.segment_bytes `
                    -Minimum 1) -or
                -not (Test-I07UtcRetentionString `
                    -Value $hls.minimum_write_utc) -or
                -not (Test-I07UtcRetentionString `
                    -Value $hls.playlist_last_write_utc) -or
                -not (Test-I07UtcRetentionString `
                    -Value $hls.segment_last_write_utc)) { return $false }
            foreach ($name in @(
                    'playlist_seen', 'segment_seen',
                    'segment_path_contained')) {
                if (-not (Test-I07StrictBoolean -Value $hls.$name) -or
                    -not [bool]$hls.$name) { return $false }
            }
            $minimumWrite = [DateTimeOffset]::Parse(
                [string]$hls.minimum_write_utc)
            $playlistWrite = [DateTimeOffset]::Parse(
                [string]$hls.playlist_last_write_utc)
            $segmentWrite = [DateTimeOffset]::Parse(
                [string]$hls.segment_last_write_utc)
            if ($minimumWrite -ne $started -or
                $playlistWrite -lt $minimumWrite -or
                $segmentWrite -lt $minimumWrite -or
                [Int64]$session.sample_count -lt 10 -or
                -not [bool]$session.socket_observed -or
                -not [bool]$session.api_peer_observed -or
                -not [bool]$session.viewing_observed -or
                -not [bool]$session.playlist_observed -or
                -not [bool]$session.segment_observed) { return $false }
        }
        if (-not (Test-I07PassProofEvidenceContract `
                -Evidence $Value.evidence -Candidate $candidate `
                -Role ([string]$Value.role)) -or
            -not (Test-I07ExactPropertySet -Value $Value.cleanup -Expected @(
                'process_stopped', 'firewall_removed', 'control_closed',
                'broadcast_stopped', 'ffmpeg_children_gone', 'hls_removed',
                'node_removed', 'evidence_retained',
                'system_state_restored'))) { return $false }
        foreach ($property in $Value.cleanup.PSObject.Properties) {
            if (-not (Test-I07StrictBoolean -Value $property.Value) -or
                -not [bool]$property.Value) { return $false }
        }
        return ((Test-I07NoRawDiagnosticProperties -Value $Value) -and
            (Test-I07SafeRetentionScalarTree -Value $Value))
    } catch { return $false }
}

function Test-I07PassProofPairContract {
    param(
        [Parameter(Mandatory = $true)]$Source,
        [Parameter(Mandatory = $true)]$Viewer
    )
    try {
        $sourceFiles = @(Assert-I07CriticalPackageContract `
            -Files @($Source.candidate.package_files) | Sort-Object path)
        $viewerFiles = @(Assert-I07CriticalPackageContract `
            -Files @($Viewer.candidate.package_files) | Sort-Object path)
        $sourceFileText = @($sourceFiles | ForEach-Object {
                '{0}|{1}|{2}' -f $_.path, [Int64]$_.bytes, $_.sha256
            }) -join "`n"
        $viewerFileText = @($viewerFiles | ForEach-Object {
                '{0}|{1}|{2}' -f $_.path, [Int64]$_.bytes, $_.sha256
            }) -join "`n"
        $sourceTuple = $Source.topology.socket.tuple
        $viewerTuple = $Viewer.topology.socket.tuple
        return (
            [string]$Source.role -ceq 'source' -and
            [string]$Viewer.role -ceq 'viewer' -and
            [string]$Source.nonce -ceq [string]$Viewer.nonce -and
            [Int64]$Source.expected_duration_seconds -eq
                [Int64]$Viewer.expected_duration_seconds -and
            [string]$Source.r01_prerequisite_sha256 -ceq
                [string]$Viewer.r01_prerequisite_sha256 -and
            [Int64]$Source.r01_prerequisite_bytes -eq
                [Int64]$Viewer.r01_prerequisite_bytes -and
            [string]$Source.candidate.version -ceq
                [string]$Viewer.candidate.version -and
            [string]$Source.candidate.commit -ceq
                [string]$Viewer.candidate.commit -and
            [string]$Source.candidate.emule_sha256 -ceq
                [string]$Viewer.candidate.emule_sha256 -and
            [string]$Source.candidate.build_info_sha256 -ceq
                [string]$Viewer.candidate.build_info_sha256 -and
            [string]$Source.candidate.zip_sha256 -ceq
                [string]$Viewer.candidate.zip_sha256 -and
            [Int64]$Source.candidate.zip_bytes -eq
                [Int64]$Viewer.candidate.zip_bytes -and
            $sourceFileText -ceq $viewerFileText -and
            [string]$Source.topology.local_ipv6 -ceq
                [string]$Viewer.topology.peer_ipv6 -and
            [string]$Viewer.topology.local_ipv6 -ceq
                [string]$Source.topology.peer_ipv6 -and
            [Int64]$Source.topology.ports.tcp -eq 48067 -and
            [Int64]$Source.topology.ports.udp -eq 48077 -and
            [Int64]$Source.topology.ports.web -eq 48117 -and
            [Int64]$Source.topology.ports.peer_tcp -eq 48267 -and
            [Int64]$Viewer.topology.ports.tcp -eq 48267 -and
            [Int64]$Viewer.topology.ports.udp -eq 48277 -and
            [Int64]$Viewer.topology.ports.web -eq 48317 -and
            [Int64]$Viewer.topology.ports.peer_tcp -eq 48067 -and
            [Int64]$Source.topology.ports.control -eq 48907 -and
            [Int64]$Viewer.topology.ports.control -eq 48907 -and
            [string]$sourceTuple.local_address -ceq
                [string]$Viewer.topology.peer_ipv6 -and
            [string]$sourceTuple.remote_address -ceq
                [string]$Viewer.topology.local_ipv6 -and
            [string]$viewerTuple.local_address -ceq
                [string]$Source.topology.peer_ipv6 -and
            [string]$viewerTuple.remote_address -ceq
                [string]$Source.topology.local_ipv6 -and
            [Int64]$sourceTuple.local_port -eq
                [Int64]$viewerTuple.remote_port -and
            [Int64]$sourceTuple.remote_port -eq
                [Int64]$viewerTuple.local_port -and
            [Int64]$Source.topology.control.local_port -eq
                [Int64]$Viewer.topology.control.remote_port -and
            [Int64]$Source.topology.control.remote_port -eq
                [Int64]$Viewer.topology.control.local_port -and
            [string]$Source.product.broadcast.stream_key_sha256 -ceq
                [string]$Viewer.product.hls.stream_key_sha256)
    } catch { return $false }
}

function Test-I07TerminalProofBundle {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('PASS', 'FAIL', 'BLOCKED')][string]$Status,
        [Parameter(Mandatory = $true)]$Candidate,
        [Parameter(Mandatory = $true)][object[]]$Artifacts,
        [Parameter(Mandatory = $true)][string]$PrivateRoot,
        [Parameter(Mandatory = $true)][string]$ExpectedNonce,
        [Parameter(Mandatory = $true)][int]$ExpectedDurationSeconds,
        [AllowNull()]$SourcePassProofSnapshot,
        [AllowNull()]$ViewerPassProofSnapshot,
        [AllowNull()]$SourceFailureProofSnapshot,
        [AllowNull()]$ViewerFailureProofSnapshot,
        [AllowNull()]$SourceResultSnapshot,
        [AllowNull()]$ViewerResultSnapshot,
        [AllowNull()]$SourcePassContext,
        [AllowNull()]$ViewerPassContext,
        [AllowNull()]$SourceFailureContext,
        [AllowNull()]$ViewerFailureContext,
        [AllowNull()]$R01PrerequisiteSnapshot,
        [AllowNull()]$R01SourceSnapshot
    )
    try {
        function Test-Candidate {
            param($ProofCandidate)
            return (
                [string]$ProofCandidate.version -ceq
                    [string]$Candidate.version -and
                [string]$ProofCandidate.commit -ceq
                    [string]$Candidate.commit -and
                [string]$ProofCandidate.emule_sha256 -ceq
                    [string]$Candidate.emule_sha256 -and
                [string]$ProofCandidate.build_info_sha256 -ceq
                    [string]$Candidate.build_info_sha256 -and
                [string]$ProofCandidate.zip_sha256 -ceq
                    [string]$Candidate.zip_sha256 -and
                [Int64]$ProofCandidate.zip_bytes -eq
                    [Int64]$Candidate.zip_bytes)
        }
        function Read-BoundProof {
            param([string]$Name, $Snapshot)
            if ($null -eq $Snapshot) { return $null }
            $relative = 'private/' + $Name
            $references = @($Artifacts | Where-Object {
                    [string]$_.path -ceq $relative
                })
            $path = Join-Path $PrivateRoot $Name
            $actual = Read-I07JsonByteSnapshot -Path $path
            if ($references.Count -ne 1 -or
                [Int64]$references[0].bytes -ne
                    [Int64]$actual.byte_count -or
                [string]$references[0].sha256 -cne
                    [string]$actual.sha256 -or
                [Int64]$actual.byte_count -ne
                    [Int64]$Snapshot.byte_count -or
                [string]$actual.sha256 -cne [string]$Snapshot.sha256) {
                throw 'proof binding mismatch'
            }
            return $actual.value
        }
        if ($null -eq $R01PrerequisiteSnapshot -or
            $null -eq $R01SourceSnapshot) { return $false }
        $r01Refs = @($Artifacts | Where-Object {
                [string]$_.path -ceq 'private/r01-prerequisite.json'
            })
        if ($r01Refs.Count -ne 1) { return $false }
        $r01Actual = Read-I07JsonByteSnapshot -Path (
            Join-Path $PrivateRoot 'r01-prerequisite.json')
        if ([string]$r01Actual.sha256 -cne
                [string]$R01PrerequisiteSnapshot.sha256 -or
            [Int64]$r01Actual.byte_count -ne
                [Int64]$R01PrerequisiteSnapshot.byte_count -or
            [string]$r01Actual.sha256 -cne
                [string]$r01Refs[0].sha256 -or
            [Int64]$r01Actual.byte_count -ne
                [Int64]$r01Refs[0].bytes -or
            -not (Test-I07R01PrerequisiteProvenanceContract `
                -Value $r01Actual.value `
                -SourceSnapshot $R01SourceSnapshot `
                -CandidateIdentity $Candidate) -or
            -not (Test-Candidate `
                -ProofCandidate $r01Actual.value.candidate) -or
            -not (Test-Candidate `
                -ProofCandidate $r01Actual.value.remote_candidate)) {
            return $false
        }
        if ($Status -ceq 'BLOCKED') { return $true }
        if ($Status -ceq 'PASS') {
            if ($null -eq $SourcePassProofSnapshot -or
                $null -eq $ViewerPassProofSnapshot -or
                $null -ne $SourceFailureProofSnapshot -or
                $null -ne $ViewerFailureProofSnapshot) { return $false }
            $source = Read-BoundProof -Name 'source-pass-proof.json' `
                -Snapshot $SourcePassProofSnapshot
            $viewer = Read-BoundProof -Name 'viewer-pass-proof.json' `
                -Snapshot $ViewerPassProofSnapshot
            if ([string]$source.schema -cne
                    'ese.v91.i07-pass-proof/v1' -or
                [string]$viewer.schema -cne
                    'ese.v91.i07-pass-proof/v1' -or
                [string]$source.case_id -cne 'V91-I07' -or
                [string]$viewer.case_id -cne 'V91-I07' -or
                [string]$source.status -cne 'PASS' -or
                [string]$viewer.status -cne 'PASS' -or
                [string]$source.role -cne 'source' -or
                [string]$viewer.role -cne 'viewer' -or
                [string]$source.nonce -cne $ExpectedNonce -or
                [string]$viewer.nonce -cne $ExpectedNonce -or
                [Int64]$source.expected_duration_seconds -ne
                    $ExpectedDurationSeconds -or
                [Int64]$viewer.expected_duration_seconds -ne
                    $ExpectedDurationSeconds -or
                -not (Test-I07PassProofContract -Value $source `
                    -SourceSnapshot $SourceResultSnapshot `
                    -Context $SourcePassContext) -or
                -not (Test-I07PassProofContract -Value $viewer `
                    -SourceSnapshot $ViewerResultSnapshot `
                    -Context $ViewerPassContext) -or
                -not (Test-Candidate -ProofCandidate $source.candidate) -or
                -not (Test-Candidate -ProofCandidate $viewer.candidate) -or
                -not (Test-I07PassProofPairContract `
                    -Source $source -Viewer $viewer)) { return $false }
            return (
                [string]$source.r01_prerequisite_sha256 -ceq
                    [string]$r01Actual.sha256 -and
                [Int64]$source.r01_prerequisite_bytes -eq
                    [Int64]$r01Actual.byte_count -and
                [string]$viewer.r01_prerequisite_sha256 -ceq
                    [string]$r01Actual.sha256 -and
                [Int64]$viewer.r01_prerequisite_bytes -eq
                    [Int64]$r01Actual.byte_count)
        }
        if ($null -ne $SourcePassProofSnapshot -or
            $null -ne $ViewerPassProofSnapshot) { return $false }
        $proofs = [Collections.Generic.List[object]]::new()
        foreach ($entry in @(
                [pscustomobject]@{
                    role = 'source'; name = 'source-failure-proof.json'
                    snapshot = $SourceFailureProofSnapshot
                },
                [pscustomobject]@{
                    role = 'viewer'; name = 'viewer-failure-proof.json'
                    snapshot = $ViewerFailureProofSnapshot
                })) {
            if ($null -eq $entry.snapshot) { continue }
            $proof = Read-BoundProof -Name $entry.name `
                -Snapshot $entry.snapshot
            $rawSnapshot = if ($entry.role -ceq 'source') {
                $SourceResultSnapshot
            } else { $ViewerResultSnapshot }
            $failureContext = if ($entry.role -ceq 'source') {
                $SourceFailureContext
            } else { $ViewerFailureContext }
            if ($null -eq $rawSnapshot -or $null -eq $failureContext -or
                -not (Test-I07FailureProofProvenanceContract `
                    -Value $proof -SourceSnapshot $rawSnapshot `
                    -Context $failureContext) -or
                -not (Test-I07FailureProofContract -Value $proof) -or
                [string]$proof.schema -cne
                    'ese.v91.i07-failure-proof/v1' -or
                [string]$proof.case_id -cne 'V91-I07' -or
                [string]$proof.status -cne 'FAIL' -or
                [string]$proof.role -cne [string]$entry.role -or
                [string]$proof.nonce -cne $ExpectedNonce -or
                [Int64]$proof.expected_duration_seconds -ne
                    $ExpectedDurationSeconds -or
                -not (Test-Candidate -ProofCandidate $proof.candidate)) {
                return $false
            }
            $proofs.Add($proof)
        }
        return ($proofs.Count -ge 1 -and $proofs.Count -le 2 -and
            ($proofs.Count -eq 1 -or (
                [string]$proofs[0].nonce -ceq [string]$proofs[1].nonce -and
                [Int64]$proofs[0].expected_duration_seconds -eq
                    [Int64]$proofs[1].expected_duration_seconds)))
    } catch { return $false }
}

function Get-I07PrivateArtifactReferences {
    param(
        [Parameter(Mandatory = $true)][string]$PrivateRoot,
        [Parameter(Mandatory = $true)][string]$RunRoot
    )
    $runFull = [IO.Path]::GetFullPath($RunRoot).TrimEnd('\')
    $privateFull = [IO.Path]::GetFullPath($PrivateRoot).TrimEnd('\')
    if (-not $privateFull.StartsWith(
            ($runFull + '\'), [StringComparison]::OrdinalIgnoreCase)) {
        throw 'I07 private evidence root must be contained by its run root.'
    }
    if (-not (Test-Path -LiteralPath $privateFull -PathType Container)) {
        return @()
    }
    $privateItem = Get-Item -LiteralPath $privateFull -Force
    if ($privateItem.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw 'I07 private evidence root cannot be a reparse point.'
    }
    $prefix = $privateFull + '\'
    $allowedRelativeNames = @(
        'manifest.json',
        'r01-prerequisite.json',
        'source-baseline-request.json', 'source-baseline-result.json',
        'viewer-baseline-request.json', 'viewer-baseline-result.json',
        'viewer-hotspot-transition.json',
        'viewer-hotspot-transition.json.request.json',
        'source-preflight-request.json', 'source-preflight-result.json',
        'viewer-preflight-request.json', 'viewer-preflight-result.json',
        'source-request.json', 'viewer-request.json',
        'source-pass-proof.json', 'viewer-pass-proof.json',
        'source-failure-proof.json', 'viewer-failure-proof.json',
        'viewer-home-restore.json',
        'viewer-home-restore.json.request.json',
        'viewer-home-restore-after-error.json',
        'viewer-home-restore-after-error.json.request.json',
        'recovered-source-baseline.json',
        'recovered-viewer-baseline.json',
        'recovered-source-preflight.json',
        'recovered-viewer-preflight.json',
        'recovered-viewer-wifi.json')
    $files = [Collections.Generic.List[object]]::new()
    $pending = [Collections.Generic.Queue[string]]::new()
    $pending.Enqueue($privateFull)
    while ($pending.Count -gt 0) {
        $directory = $pending.Dequeue()
        foreach ($item in @(Get-ChildItem -LiteralPath $directory -Force)) {
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw 'I07 private evidence tree contains a reparse point.'
            }
            if ($item.PSIsContainer) {
                $pending.Enqueue([string]$item.FullName)
            } else { $files.Add($item) }
        }
    }
    return @($files | Sort-Object FullName | ForEach-Object {
            $full = [IO.Path]::GetFullPath($_.FullName)
            if (-not $full.StartsWith(
                    $prefix, [StringComparison]::OrdinalIgnoreCase) -or
                ($_.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                throw 'I07 private artifact escaped its normal evidence root.'
            }
            $relative = $full.Substring($prefix.Length).Replace('\', '/')
            if ($relative -match '(^|/)\.\.(/|$)' -or
                $relative -notmatch '^[A-Za-z0-9._/-]+$' -or
                $relative -cnotin $allowedRelativeNames) {
                throw 'I07 private artifact has an unsafe relative name.'
            }
            [pscustomobject][ordered]@{
                path = 'private/' + $relative
                bytes = [Int64]$_.Length
                sha256 = Get-LabSha256 -Path $full
            }
        })
}

function Assert-I07PublicAggregatePrivacy {
    param(
        [Parameter(Mandatory = $true)]$Aggregate,
        [string[]]$SensitiveValues = @()
    )
    $rootNames = @($Aggregate.PSObject.Properties.Name | Sort-Object)
    $expectedRootNames = @(
        'aliases', 'candidate', 'case_id', 'checks', 'completed_at_utc',
        'outcome_code', 'private_artifacts', 'schema', 'status', 'topology_id'
    ) | Sort-Object
    $completed = [DateTimeOffset]::MinValue
    $completedValid = [DateTimeOffset]::TryParse(
        [string]$Aggregate.completed_at_utc,
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::RoundtripKind,
        [ref]$completed) -and $completed.Offset -eq [TimeSpan]::Zero
    $outcomeCoherent = $(
        if ([string]$Aggregate.status -ceq 'PASS') {
            [string]$Aggregate.outcome_code -ceq 'PASS'
        } elseif ([string]$Aggregate.status -ceq 'FAIL') {
            [string]$Aggregate.outcome_code -ceq 'PRODUCT_INVARIANT'
        } else {
            [string]$Aggregate.outcome_code -cnotin @(
                'PASS', 'PRODUCT_INVARIANT')
        })
    if (($rootNames -join "`n") -cne ($expectedRootNames -join "`n") -or
        [string]$Aggregate.schema -cne 'ese.v91.i07-public-aggregate/v1' -or
        [string]$Aggregate.case_id -cne 'V91-I07' -or
        [string]$Aggregate.topology_id -cne 'T3' -or
        [string]$Aggregate.status -cnotin @('PASS', 'FAIL', 'BLOCKED') -or
        [string]$Aggregate.outcome_code -cnotin @(
            'PASS', 'PRODUCT_INVARIANT', 'READINESS_NOT_PROVEN',
            'BASELINE_NOT_CLEAN', 'HOTSPOT_TRANSITION_NOT_PROVEN',
            'NATIVE_IPV6_NOT_PROVEN', 'HOME_RESTORE_NOT_PROVEN',
            'EVIDENCE_INCOMPLETE', 'CONTROLLER_ABORTED') -or
        -not $completedValid -or -not $outcomeCoherent -or
        [string]$Aggregate.aliases.source -cne 'eSE-A' -or
        [string]$Aggregate.aliases.viewer -cne 'eSE-B') {
        throw 'I07 public aggregate violated its root allowlist.'
    }
    $aliasNames = @($Aggregate.aliases.PSObject.Properties.Name | Sort-Object)
    if (($aliasNames -join ',') -cne 'source,viewer') {
        throw 'I07 public aliases violated their allowlist.'
    }
    $candidateNames = @(
        $Aggregate.candidate.PSObject.Properties.Name | Sort-Object)
    $expectedCandidateNames = @(
        'build_info_sha256', 'commit', 'emule_sha256', 'version',
        'zip_bytes', 'zip_sha256') | Sort-Object
    if (($candidateNames -join "`n") -cne
            ($expectedCandidateNames -join "`n") -or
        [string]$Aggregate.candidate.version -notmatch
            '^[A-Za-z0-9._+-]{1,64}$' -or
        [string]$Aggregate.candidate.commit -notmatch '^[0-9a-f]{40}$' -or
        [string]$Aggregate.candidate.emule_sha256 -notmatch
            '^[0-9a-f]{64}$' -or
        [string]$Aggregate.candidate.build_info_sha256 -notmatch
            '^[0-9a-f]{64}$' -or
        [string]$Aggregate.candidate.zip_sha256 -notmatch
            '^[0-9a-f]{64}$' -or
        [Int64]$Aggregate.candidate.zip_bytes -le 0) {
        throw 'I07 public candidate identity violated its allowlist.'
    }
    $allowedChecks = @(
        'agents_ready', 'baseline_clean', 'r01_dependency_valid',
        'hotspot_transition_pass', 'hotspot_profile_match',
        'source_preflight_pass', 'viewer_preflight_pass',
        'source_result_received', 'viewer_result_received',
        'product_evidence_complete', 'home_restore_pass',
        'cleanup_terminal')
    $checkNames = @($Aggregate.checks.PSObject.Properties.Name | Sort-Object)
    if (($checkNames -join "`n") -cne
            (@($allowedChecks | Sort-Object) -join "`n")) {
        throw 'I07 public checks must contain the exact boolean allowlist.'
    }
    foreach ($property in $Aggregate.checks.PSObject.Properties) {
        if ([string]$property.Name -cnotin $allowedChecks -or
            -not ($property.Value -is [bool])) {
            throw 'I07 public checks violated their boolean allowlist.'
        }
    }
    if ([string]$Aggregate.status -ceq 'PASS' -and
        @($Aggregate.checks.PSObject.Properties | Where-Object {
                -not [bool]$_.Value
            }).Count -ne 0) {
        throw 'I07 PASS requires every public check to be true.'
    }
    foreach ($artifact in @($Aggregate.private_artifacts)) {
        $artifactNames = @($artifact.PSObject.Properties.Name | Sort-Object)
        if (($artifactNames -join ',') -cne 'bytes,path,sha256' -or
            [string]$artifact.path -notmatch
                '^private/[A-Za-z0-9._/-]+$' -or
            [string]$artifact.path -match '(^|/)\.\.(/|$)' -or
            [Int64]$artifact.bytes -le 0 -or
            [string]$artifact.sha256 -notmatch '^[0-9a-f]{64}$') {
            throw 'I07 public artifact reference violated its allowlist.'
        }
    }
    $artifactPaths = @($Aggregate.private_artifacts | ForEach-Object {
            [string]$_.path
        })
    if ($artifactPaths.Count -lt 1 -or
        @($artifactPaths | Select-Object -Unique).Count -ne
            $artifactPaths.Count -or
        ($artifactPaths -join "`n") -cne
            (@($artifactPaths | Sort-Object) -join "`n") -or
        $artifactPaths -cnotcontains 'private/manifest.json') {
        throw 'I07 public artifact references must be nonempty and unique.'
    }
    $hasR01Artifact = $artifactPaths -ccontains
        'private/r01-prerequisite.json'
    if ([bool]$Aggregate.checks.r01_dependency_valid -ne $hasR01Artifact) {
        throw 'I07 R01 check and retained prerequisite must agree.'
    }
    if ([string]$Aggregate.status -ceq 'PASS') {
        $passArtifacts = @(
            'private/manifest.json',
            'private/r01-prerequisite.json',
            'private/source-baseline-request.json',
            'private/source-baseline-result.json',
            'private/viewer-baseline-request.json',
            'private/viewer-baseline-result.json',
            'private/viewer-hotspot-transition.json',
            'private/viewer-hotspot-transition.json.request.json',
            'private/source-preflight-request.json',
            'private/source-preflight-result.json',
            'private/viewer-preflight-request.json',
            'private/viewer-preflight-result.json',
            'private/source-request.json', 'private/source-pass-proof.json',
            'private/viewer-request.json', 'private/viewer-pass-proof.json',
            'private/viewer-home-restore.json',
            'private/viewer-home-restore.json.request.json') | Sort-Object
        if (($artifactPaths -join "`n") -cne ($passArtifacts -join "`n")) {
            throw 'I07 PASS requires the exact private evidence set.'
        }
    } elseif ([string]$Aggregate.status -ceq 'FAIL') {
        $sourceProof = $artifactPaths -ccontains
            'private/source-failure-proof.json'
        $viewerProof = $artifactPaths -ccontains
            'private/viewer-failure-proof.json'
        if ((-not $sourceProof -and -not $viewerProof) -or
            $artifactPaths -ccontains 'private/source-result.json' -or
            $artifactPaths -ccontains 'private/viewer-result.json' -or
            $artifactPaths -ccontains 'private/recovered-source-node.json' -or
            $artifactPaths -ccontains 'private/recovered-viewer-node.json' -or
            $artifactPaths -ccontains 'private/source-pass-proof.json' -or
            $artifactPaths -ccontains 'private/viewer-pass-proof.json' -or
            -not [bool]$Aggregate.checks.product_evidence_complete -or
            [bool]$Aggregate.checks.source_result_received -ne $sourceProof -or
            [bool]$Aggregate.checks.viewer_result_received -ne $viewerProof) {
            throw 'I07 FAIL requires coherent sanitized failure proof only.'
        }
    } else {
        $blockedProductArtifacts = @(
            'private/source-result.json',
            'private/viewer-result.json',
            'private/recovered-source-node.json',
            'private/recovered-viewer-node.json',
            'private/source-pass-proof.json',
            'private/viewer-pass-proof.json',
            'private/source-failure-proof.json',
            'private/viewer-failure-proof.json')
        if (@($blockedProductArtifacts | Where-Object {
                    $artifactPaths -ccontains $_
                }).Count -ne 0 -or
            [bool]$Aggregate.checks.source_result_received -or
            [bool]$Aggregate.checks.viewer_result_received) {
            throw 'I07 BLOCKED cannot retain node results or failure proofs.'
        }
    }
    $json = $Aggregate | ConvertTo-Json -Depth 10 -Compress
    foreach ($sensitive in @($SensitiveValues | Where-Object {
                -not [string]::IsNullOrWhiteSpace([string]$_)
            } | Select-Object -Unique)) {
        $value = [string]$sensitive
        if ($json.IndexOf($value, [StringComparison]::OrdinalIgnoreCase) `
                -ge 0 -or
            $json.IndexOf((Get-I07TextSha256 -Value $value),
                [StringComparison]::OrdinalIgnoreCase) -ge 0) {
            throw 'I07 public aggregate contains a sensitive value or digest.'
        }
    }
    return $true
}

function Clear-I07ProductEvidenceForTerminal {
    param(
        [Parameter(Mandatory = $true)][string]$PrivateRoot,
        [Parameter(Mandatory = $true)][bool]$KeepFailureProofs
    )
    $root = [IO.Path]::GetFullPath($PrivateRoot).TrimEnd('\')
    $leafNames = @(
        'source-result.json', 'viewer-result.json',
        'recovered-source-node.json', 'recovered-viewer-node.json',
        'source-pass-proof.json', 'viewer-pass-proof.json')
    if (-not $KeepFailureProofs) {
        $leafNames += @(
            'source-failure-proof.json', 'viewer-failure-proof.json')
    }
    foreach ($leafName in $leafNames) {
        $path = [IO.Path]::GetFullPath((Join-Path $root $leafName))
        if (-not $path.StartsWith(
                ($root + '\'), [StringComparison]::OrdinalIgnoreCase)) {
            throw 'I07 product evidence cleanup escaped its private root.'
        }
        if (-not (Test-Path -LiteralPath $path)) { continue }
        $item = Get-Item -LiteralPath $path -Force
        if ($item.PSIsContainer -or
            ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'I07 product evidence cleanup rejected an unsafe artifact.'
        }
        Remove-Item -LiteralPath $path -Force
    }
}

function New-I07PublicAggregate {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('PASS', 'FAIL', 'BLOCKED')][string]$Status,
        [Parameter(Mandatory = $true)][string]$OutcomeCode,
        [Parameter(Mandatory = $true)]$Candidate,
        [Parameter(Mandatory = $true)]$Checks,
        [Parameter(Mandatory = $true)][string]$PrivateRoot,
        [Parameter(Mandatory = $true)][string]$RunRoot,
        [Parameter(Mandatory = $true)][string]$ExpectedNonce,
        [Parameter(Mandatory = $true)][int]$ExpectedDurationSeconds,
        [AllowNull()]$SourcePassProofSnapshot,
        [AllowNull()]$ViewerPassProofSnapshot,
        [AllowNull()]$SourceFailureProofSnapshot,
        [AllowNull()]$ViewerFailureProofSnapshot,
        [AllowNull()]$SourceResultSnapshot,
        [AllowNull()]$ViewerResultSnapshot,
        [AllowNull()]$SourcePassContext,
        [AllowNull()]$ViewerPassContext,
        [AllowNull()]$SourceFailureContext,
        [AllowNull()]$ViewerFailureContext,
        [AllowNull()]$R01PrerequisiteSnapshot,
        [AllowNull()]$R01SourceSnapshot,
        [string[]]$SensitiveValues = @()
    )
    $aggregate = [pscustomobject][ordered]@{
        schema = 'ese.v91.i07-public-aggregate/v1'
        case_id = 'V91-I07'
        topology_id = 'T3'
        status = $Status
        outcome_code = $OutcomeCode
        completed_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
        aliases = [pscustomobject][ordered]@{
            source = 'eSE-A'
            viewer = 'eSE-B'
        }
        candidate = [pscustomobject][ordered]@{
            version = [string]$Candidate.version
            commit = ([string]$Candidate.commit).ToLowerInvariant()
            emule_sha256 = ([string]$Candidate.emule_sha256).ToLowerInvariant()
            build_info_sha256 =
                ([string]$Candidate.build_info_sha256).ToLowerInvariant()
            zip_sha256 = ([string]$Candidate.zip_sha256).ToLowerInvariant()
            zip_bytes = [Int64]$Candidate.zip_bytes
        }
        checks = [pscustomobject]$Checks
        private_artifacts = @(Get-I07PrivateArtifactReferences `
            -PrivateRoot $PrivateRoot -RunRoot $RunRoot)
    }
    $null = Assert-I07PublicAggregatePrivacy -Aggregate $aggregate `
        -SensitiveValues $SensitiveValues
    $mustBindR01 = [bool]$aggregate.checks.r01_dependency_valid
    if (($Status -cin @('PASS', 'FAIL') -or $mustBindR01) -and
        -not (Test-I07TerminalProofBundle -Status $Status `
            -Candidate $aggregate.candidate `
            -Artifacts @($aggregate.private_artifacts) `
            -PrivateRoot $PrivateRoot -ExpectedNonce $ExpectedNonce `
            -ExpectedDurationSeconds $ExpectedDurationSeconds `
            -SourcePassProofSnapshot $SourcePassProofSnapshot `
            -ViewerPassProofSnapshot $ViewerPassProofSnapshot `
            -SourceFailureProofSnapshot $SourceFailureProofSnapshot `
            -ViewerFailureProofSnapshot $ViewerFailureProofSnapshot `
            -SourceResultSnapshot $SourceResultSnapshot `
            -ViewerResultSnapshot $ViewerResultSnapshot `
            -SourcePassContext $SourcePassContext `
            -ViewerPassContext $ViewerPassContext `
            -SourceFailureContext $SourceFailureContext `
            -ViewerFailureContext $ViewerFailureContext `
            -R01PrerequisiteSnapshot $R01PrerequisiteSnapshot `
            -R01SourceSnapshot $R01SourceSnapshot)) {
        throw 'I07 terminal proof bundle is not bound to its aggregate.'
    }
    return $aggregate
}

$script:i07RunRoot = ''
$script:i07PrivateRoot = ''
$script:i07ManifestPath = ''
$script:i07AggregatePath = ''
$script:i07StartedJobs = [Collections.Generic.List[object]]::new()
$script:i07ContextValidators = @{}
$script:i07WifiSwitched = $false
$script:i07HomeProfileSha = ''
$script:i07HomeWlanProfileSha = ''
$script:i07HotspotInterfaceGuid = ''
$script:i07Nonce = ''
$script:i07LeaseSeconds = 900
$script:i07HotspotWatchdogPid = 0
$script:i07HotspotWatchdogArmedAt = ''
$script:i07HotspotWatchdogDeadline = ''
$script:i07CandidateSha = ''
$script:i07CandidateBytes = 0L
$script:i07CandidateVersion = ''
$script:i07CandidateCommit = ''
$script:i07BuildInfoSha = ''
$script:i07ZipSha = ''
$script:i07ZipBytes = 0L
$script:i07PackageFiles = @()
$script:i07HotspotWlanSha = ''
$script:i07HotspotConnectionSha = ''
$script:i07SensitiveValues = @()
$script:i07SourcePassProofSnapshot = $null
$script:i07ViewerPassProofSnapshot = $null
$script:i07SourceFailureProofSnapshot = $null
$script:i07ViewerFailureProofSnapshot = $null
$script:i07SourceResultSnapshot = $null
$script:i07ViewerResultSnapshot = $null
$script:i07SourcePassContext = $null
$script:i07ViewerPassContext = $null
$script:i07SourceFailureContext = $null
$script:i07ViewerFailureContext = $null
$script:i07R01PrerequisiteSnapshot = $null
$script:i07R01SourceSnapshot = $null
$script:i07PublicChecks = [ordered]@{
    r01_dependency_valid = $false
    agents_ready = $false
    baseline_clean = $false
    hotspot_transition_pass = $false
    hotspot_profile_match = $false
    source_preflight_pass = $false
    viewer_preflight_pass = $false
    source_result_received = $false
    viewer_result_received = $false
    product_evidence_complete = $false
    home_restore_pass = $false
    cleanup_terminal = $false
}

if ($SelfTest) {
    Invoke-I07ControllerSelfTest
    exit 0
}

function Wait-I07Job {
    param(
        [ValidateSet('source', 'viewer')][string]$Role,
        [Parameter(Mandatory = $true)][string]$JobId,
        [Parameter(Mandatory = $true)][DateTimeOffset]$Deadline
    )
    do {
        try {
            $state = Invoke-I07Agent -Role $Role -Command job `
                -Extra @{ JobId = $JobId }
            if ([string]$state.state -cin @('COMPLETE', 'ERROR', 'STOPPED')) {
                return $state
            }
        } catch {
            if ([string]$_.Exception.Message -match 'job_missing') {
                return [pscustomobject][ordered]@{
                    schema = 'ese.lab.smallframe-job/v1'
                    job_id = $JobId
                    state = 'NOT_FOUND'
                    exit_code = $null
                    updated_at_utc =
                        [DateTimeOffset]::UtcNow.ToString('o')
                }
            }
        }
        Start-Sleep -Milliseconds 500
    } while ([DateTimeOffset]::UtcNow -lt $Deadline)
    throw "$Role job $JobId timed out."
}

function Publish-I07Aggregate {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Value
    )
    $temporary = $Path + '.new'
    $Value | ConvertTo-Json -Depth 24 |
        Set-Content -LiteralPath $temporary -Encoding UTF8
    Move-Item -LiteralPath $temporary -Destination $Path -Force
}

function Publish-I07PublicResult {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('PASS', 'FAIL', 'BLOCKED')][string]$Status,
        [Parameter(Mandatory = $true)][string]$OutcomeCode
    )
    Assert-I07StagingCleanupProven
    if ($Status -ceq 'PASS' -and (
            $null -eq $script:i07SourceResultSnapshot -or
            $null -eq $script:i07ViewerResultSnapshot -or
            $null -eq $script:i07SourcePassProofSnapshot -or
            $null -eq $script:i07ViewerPassProofSnapshot -or
            $null -eq $script:i07SourcePassContext -or
            $null -eq $script:i07ViewerPassContext -or
            -not (Test-I07PassProofContract `
                -Value $script:i07SourcePassProofSnapshot.value `
                -SourceSnapshot $script:i07SourceResultSnapshot `
                -Context $script:i07SourcePassContext) -or
            -not (Test-I07PassProofContract `
                -Value $script:i07ViewerPassProofSnapshot.value `
                -SourceSnapshot $script:i07ViewerResultSnapshot `
                -Context $script:i07ViewerPassContext))) {
        throw 'I07 public PASS lost source-bound proof context.'
    }
    if ($Status -ceq 'FAIL') {
        $sourceFailureBound = $null -ne
            $script:i07SourceFailureProofSnapshot
        $viewerFailureBound = $null -ne
            $script:i07ViewerFailureProofSnapshot
        if (-not $sourceFailureBound -and -not $viewerFailureBound) {
            throw 'I07 public FAIL lost every source-bound proof.'
        }
        if ($sourceFailureBound -and (
                $null -eq $script:i07SourceResultSnapshot -or
                $null -eq $script:i07SourceFailureContext -or
                -not (Test-I07FailureProofProvenanceContract `
                    -Value $script:i07SourceFailureProofSnapshot.value `
                    -SourceSnapshot $script:i07SourceResultSnapshot `
                    -Context $script:i07SourceFailureContext))) {
            throw 'I07 public Source FAIL lost proof provenance.'
        }
        if ($viewerFailureBound -and (
                $null -eq $script:i07ViewerResultSnapshot -or
                $null -eq $script:i07ViewerFailureContext -or
                -not (Test-I07FailureProofProvenanceContract `
                    -Value $script:i07ViewerFailureProofSnapshot.value `
                    -SourceSnapshot $script:i07ViewerResultSnapshot `
                    -Context $script:i07ViewerFailureContext))) {
            throw 'I07 public Viewer FAIL lost proof provenance.'
        }
    }
    $value = New-I07PublicAggregate -Status $Status `
        -OutcomeCode $OutcomeCode -Candidate ([pscustomobject]@{
            version = $script:i07CandidateVersion
            commit = $script:i07CandidateCommit
            emule_sha256 = $script:i07CandidateSha
            build_info_sha256 = $script:i07BuildInfoSha
            zip_sha256 = $script:i07ZipSha
            zip_bytes = $script:i07ZipBytes
        }) -Checks $script:i07PublicChecks `
        -PrivateRoot $script:i07PrivateRoot `
        -RunRoot $script:i07RunRoot `
        -ExpectedNonce $script:i07Nonce `
        -ExpectedDurationSeconds $DurationSeconds `
        -SourcePassProofSnapshot $script:i07SourcePassProofSnapshot `
        -ViewerPassProofSnapshot $script:i07ViewerPassProofSnapshot `
        -SourceFailureProofSnapshot $script:i07SourceFailureProofSnapshot `
        -ViewerFailureProofSnapshot $script:i07ViewerFailureProofSnapshot `
        -SourceResultSnapshot $script:i07SourceResultSnapshot `
        -ViewerResultSnapshot $script:i07ViewerResultSnapshot `
        -SourcePassContext $script:i07SourcePassContext `
        -ViewerPassContext $script:i07ViewerPassContext `
        -SourceFailureContext $script:i07SourceFailureContext `
        -ViewerFailureContext $script:i07ViewerFailureContext `
        -R01PrerequisiteSnapshot $script:i07R01PrerequisiteSnapshot `
        -R01SourceSnapshot $script:i07R01SourceSnapshot `
        -SensitiveValues $script:i07SensitiveValues
    Publish-I07Aggregate -Path $script:i07AggregatePath -Value $value
    return $value
}

function Invoke-I07WifiTransition {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('hotspot', 'home')][string]$Action,
        [Parameter(Mandatory = $true)][string]$WlanProfileSha256,
        [Parameter(Mandatory = $true)][string]$ConnectionProfileSha256,
        [Parameter(Mandatory = $true)][string]$Nonce,
        [Parameter(Mandatory = $true)][string]$HomeWlanProfileSha256,
        [Parameter(Mandatory = $true)][string]$HomeConnectionProfileSha256,
        [Parameter(Mandatory = $true)][string]$InterfaceGuid,
        [Parameter(Mandatory = $true)][string]$OutputPath,
        [ValidateRange(300, 1800)][int]$LeaseSeconds = 900
    )
    $jobId = [Guid]::NewGuid().ToString('N')
    $remoteRoot = "injected/$jobId"
    Invoke-I07Agent -Role viewer -Command upload -Extra @{
        SourcePath = $commonScript
        RemotePath = "$remoteRoot/v91_i07_common.ps1"
    } | Out-Null
    Invoke-I07Agent -Role viewer -Command upload -Extra @{
        SourcePath = $wifiScript
        RemotePath = "$remoteRoot/set_v91_i07_wifi_profile.ps1"
    } | Out-Null
    Invoke-I07Agent -Role viewer -Command upload -Extra @{
        SourcePath = $wifiWatchdogScript
        RemotePath = "$remoteRoot/restore_v91_i07_wifi_watchdog.ps1"
    } | Out-Null
    $requestPath = $OutputPath + '.request.json'
    [ordered]@{
        schema = 'ese.v91.i07-wifi-request/v2'
        nonce = $Nonce
        action = $Action
        target_wlan_profile_sha256 = $WlanProfileSha256
        expected_connection_profile_sha256 = $ConnectionProfileSha256
        home_wlan_profile_sha256 = $HomeWlanProfileSha256
        home_connection_profile_sha256 = $HomeConnectionProfileSha256
        interface_guid = $InterfaceGuid
        lease_seconds = $LeaseSeconds
    } | ConvertTo-Json | Set-Content -LiteralPath $requestPath -Encoding UTF8
    $context = [pscustomobject][ordered]@{
        action = $Action; nonce = $Nonce
        target_wlan_profile_sha256 = $WlanProfileSha256
        expected_connection_profile_sha256 = $ConnectionProfileSha256
        home_wlan_profile_sha256 = $HomeWlanProfileSha256
        home_connection_profile_sha256 = $HomeConnectionProfileSha256
        interface_guid = $InterfaceGuid; lease_seconds = $LeaseSeconds
        expected_watchdog_pid = $script:i07HotspotWatchdogPid
        expected_watchdog_armed_at_utc =
            $script:i07HotspotWatchdogArmedAt
        expected_watchdog_deadline_utc =
            $script:i07HotspotWatchdogDeadline
    }
    $validator = New-I07RetentionContextValidator -Kind wifi `
        -Context $context
    $script:i07ContextValidators[$jobId] = $validator
    $script:i07StartedJobs.Add([pscustomobject]@{
        role = 'viewer'; kind = 'wifi'; job_id = $jobId
    })
    Invoke-I07Agent -Role viewer -Command run -Extra @{
        JobId = $jobId
        RemotePath = "$remoteRoot/set_v91_i07_wifi_profile.ps1"
        JobRequestPath = $requestPath
    } | Out-Null
    $null = Wait-I07Job -Role viewer -JobId $jobId `
        -Deadline ([DateTimeOffset]::UtcNow.AddSeconds(150))
    $snapshot = Receive-I07StagedJson -Role viewer `
        -RemotePath "jobs/$jobId/result.json" -Kind wifi `
        -ContextValidator $validator
    $result = $snapshot.value
    if ([string]$result.schema -cne 'ese.v91.i07-wifi-transition/v2' -or
        [string]$result.case_id -cne 'V91-I07' -or
        [string]$result.action -cne $Action -or
        [string]$result.nonce -cne $Nonce -or
        [string]$result.target_wlan_profile_sha256 -cne
            $WlanProfileSha256 -or
        [string]$result.expected_connection_profile_sha256 -cne
            $ConnectionProfileSha256 -or
        [string]$result.home_wlan_profile_sha256 -cne
            $HomeWlanProfileSha256 -or
        [string]$result.home_connection_profile_sha256 -cne
            $HomeConnectionProfileSha256 -or
        ([string]$result.interface_guid).Trim('{}') -ine
            $InterfaceGuid.Trim('{}')) {
        throw 'Viewer returned an invalid I07 Wi-Fi transition envelope.'
    }
    if ($Action -ceq 'hotspot' -and
        [string]$result.status -ceq 'PASS' -and (
            [string]$result.watchdog.schema -cne
                'ese.v91.i07-home-watchdog-armed/v1' -or
            [string]$result.watchdog.status -cne 'ARMED' -or
            [string]$result.watchdog.nonce -cne $Nonce)) {
        throw 'Viewer entered hotspot without a typed armed Home watchdog.'
    }
    if ($Action -ceq 'home' -and
        [string]$result.status -ceq 'PASS' -and (
            [string]$result.watchdog.schema -cne
                'ese.v91.i07-home-watchdog-result/v1' -or
            [string]$result.watchdog.status -cne 'PASS' -or
            [string]$result.watchdog.trigger -cne 'controller_restore' -or
            -not [bool]$result.watchdog.restore_signal_valid -or
            [string]$result.watchdog_disarm.schema -cne
                'ese.v91.i07-home-watchdog-disarmed/v1' -or
            [string]$result.watchdog_disarm.status -cne 'PASS' -or
            -not [bool]$result.watchdog_disarm.process_exited)) {
        throw 'Viewer Home watchdog did not restore and disarm normally.'
    }
    if ($Action -ceq 'hotspot' -and
        [string]$result.status -ceq 'PASS') {
        $script:i07HotspotWatchdogPid = [int]$result.watchdog.watchdog_pid
        $script:i07HotspotWatchdogArmedAt =
            [string]$result.watchdog.armed_at_utc
        $script:i07HotspotWatchdogDeadline =
            [string]$result.watchdog.deadline_utc
    }
    Write-I07HeldSnapshot -Snapshot $snapshot -Path $OutputPath
    return $result
}

function Get-I07ZipFileHash {
    param(
        [Parameter(Mandatory = $true)]$Archive,
        [Parameter(Mandatory = $true)][string]$LeafName
    )
    $entries = @($Archive.Entries | Where-Object {
            [string]$_.Name -ceq $LeafName
        })
    if ($entries.Count -ne 1) {
        throw "Candidate ZIP must contain exactly one $LeafName entry."
    }
    $stream = $entries[0].Open()
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $hash = ([BitConverter]::ToString(
            $sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
        $stream.Dispose()
    }
    return [pscustomobject]@{
        path = [string]$entries[0].FullName
        bytes = [Int64]$entries[0].Length
        sha256 = $hash
    }
}

trap {
    if ($SelfTest) {
        [Console]::Error.WriteLine([string]$_)
        [Console]::Error.WriteLine([string]$_.ScriptStackTrace)
        exit 1
    }
    $recoveredSource = $null
    $recoveredViewer = $null
    $recoveredNodeSnapshots = @{}
    $terminalJobs = 0
    $hasFail = $false
    $publishedTerminal = $false
    $script:i07SourcePassProofSnapshot = $null
    $script:i07ViewerPassProofSnapshot = $null
    $script:i07SourceFailureProofSnapshot = $null
    $script:i07ViewerFailureProofSnapshot = $null
    $script:i07SourceResultSnapshot = $null
    $script:i07ViewerResultSnapshot = $null
    $script:i07SourcePassContext = $null
    $script:i07ViewerPassContext = $null
    $script:i07SourceFailureContext = $null
    $script:i07ViewerFailureContext = $null
    $null = Repair-I07StagingCleanup
    $startedSnapshot = @($script:i07StartedJobs.ToArray())
    if ($startedSnapshot.Count -gt 0) {
        foreach ($started in $startedSnapshot) {
            try {
                Invoke-I07Agent -Role ([string]$started.role) `
                    -Command cancel -Extra @{
                        JobId = [string]$started.job_id
                    } | Out-Null
            } catch {}
        }
        $cleanupDeadline = [DateTimeOffset]::UtcNow.AddSeconds(300)
        foreach ($started in $startedSnapshot) {
            try {
                $null = Wait-I07Job -Role ([string]$started.role) `
                    -JobId ([string]$started.job_id) `
                    -Deadline $cleanupDeadline
                ++$terminalJobs
                $path = Join-Path $script:i07PrivateRoot (
                    "recovered-$($started.role)-$($started.kind).json")
                $remoteResult = if ([string]$started.kind -ceq 'node') {
                    "jobs/$($started.job_id)/i07-result.json"
                } else { "jobs/$($started.job_id)/result.json" }
                $boundaryKind = switch ([string]$started.kind) {
                    'node' { 'node' }; 'baseline' { 'baseline' }
                    'preflight' { 'preflight' }; 'wifi' { 'wifi' }
                    default { throw 'Unknown recovery artifact kind.' }
                }
                $validator = $script:i07ContextValidators[
                    [string]$started.job_id]
                if ($null -eq $validator) {
                    throw 'Missing recovery context validator.'
                }
                $recoveredSnapshot = Receive-I07StagedJson `
                    -Role ([string]$started.role) -RemotePath $remoteResult `
                    -Kind $boundaryKind -ContextValidator $validator
                $value = $recoveredSnapshot.value
                if ([string]$started.kind -ceq 'node') {
                    $recoveredNodeSnapshots[[string]$started.role] =
                        [pscustomobject]@{
                            snapshot = $recoveredSnapshot; path = $path
                        }
                    if ([string]$started.role -ceq 'source') {
                        $recoveredSource = $value
                    } elseif ([string]$started.role -ceq 'viewer') {
                        $recoveredViewer = $value
                    }
                } else {
                    Write-I07HeldSnapshot -Snapshot $recoveredSnapshot `
                        -Path $path
                }
            } catch {}
        }
    }
    $restoreResult = $null
    if ($script:i07WifiSwitched -and
        -not [string]::IsNullOrWhiteSpace($script:i07RunRoot)) {
        try {
            $restoreResult = Invoke-I07WifiTransition -Action home `
                -WlanProfileSha256 $script:i07HomeWlanProfileSha `
                -ConnectionProfileSha256 $script:i07HomeProfileSha `
                -Nonce $script:i07Nonce `
                -HomeWlanProfileSha256 $script:i07HomeWlanProfileSha `
                -HomeConnectionProfileSha256 $script:i07HomeProfileSha `
                -InterfaceGuid $script:i07HotspotInterfaceGuid `
                -OutputPath (Join-Path $script:i07PrivateRoot `
                    'viewer-home-restore-after-error.json') `
                -LeaseSeconds $script:i07LeaseSeconds
            if ([string]$restoreResult.status -ceq 'PASS') {
                $script:i07WifiSwitched = $false
                $script:i07PublicChecks.home_restore_pass = $true
            }
        } catch {}
    }
    if (-not [string]::IsNullOrWhiteSpace($script:i07AggregatePath) -and
        (Repair-I07StagingCleanup)) {
        if ($script:i07CandidateSha -match '^[0-9a-f]{64}$' -and
            $script:i07CandidateCommit -match '^[0-9a-f]{40}$' -and
            $script:i07BuildInfoSha -match '^[0-9a-f]{64}$' -and
            $script:i07ZipSha -match '^[0-9a-f]{64}$' -and
            $script:i07ZipBytes -gt 0) {
            $recoveredStatus = Get-I07AggregateStatus `
                -Source $recoveredSource -Viewer $recoveredViewer `
                -Nonce $script:i07Nonce `
                -CandidateSha256 $script:i07CandidateSha `
                -CandidateCommit $script:i07CandidateCommit `
                -BuildInfoSha256 $script:i07BuildInfoSha `
                -ZipSha256 $script:i07ZipSha `
                -ZipBytes $script:i07ZipBytes `
                -ExpectedDurationSeconds $DurationSeconds `
                -ExpectedPackageFiles $script:i07PackageFiles `
                -ExpectedViewerWlanProfileSha256 `
                    $script:i07HotspotWlanSha `
                -ExpectedViewerConnectionProfileSha256 `
                    $script:i07HotspotConnectionSha `
                -ExpectedViewerInterfaceGuid `
                    $script:i07HotspotInterfaceGuid
            if ($recoveredStatus -ceq 'FAIL') {
                $proofCount = 0
                foreach ($role in @('source', 'viewer')) {
                    if (-not $recoveredNodeSnapshots.ContainsKey($role)) {
                        continue
                    }
                    $singleStatus = Get-I07AggregateStatus `
                        -Source $(if ($role -ceq 'source') {
                            $recoveredSource
                        } else { $null }) `
                        -Viewer $(if ($role -ceq 'viewer') {
                            $recoveredViewer
                        } else { $null }) `
                        -Nonce $script:i07Nonce `
                        -CandidateSha256 $script:i07CandidateSha `
                        -CandidateCommit $script:i07CandidateCommit `
                        -BuildInfoSha256 $script:i07BuildInfoSha `
                        -ZipSha256 $script:i07ZipSha `
                        -ZipBytes $script:i07ZipBytes `
                        -ExpectedDurationSeconds $DurationSeconds `
                        -ExpectedPackageFiles $script:i07PackageFiles `
                        -ExpectedViewerWlanProfileSha256 `
                            $script:i07HotspotWlanSha `
                        -ExpectedViewerConnectionProfileSha256 `
                            $script:i07HotspotConnectionSha `
                        -ExpectedViewerInterfaceGuid `
                            $script:i07HotspotInterfaceGuid
                    if ($singleStatus -ceq 'FAIL') {
                        $held = $recoveredNodeSnapshots[$role]
                        $node = if ($role -ceq 'source') {
                            $recoveredSource
                        } else { $recoveredViewer }
                        $failureContext = New-I07FailureProofContext `
                            -Role $role -Nonce $script:i07Nonce `
                            -DurationSeconds $DurationSeconds `
                            -CandidateIdentity ([pscustomobject]@{
                                version = $script:i07CandidateVersion
                                commit = $script:i07CandidateCommit
                                emule_sha256 = $script:i07CandidateSha
                                bytes = $script:i07CandidateBytes
                                build_info_sha256 = $script:i07BuildInfoSha
                                zip_sha256 = $script:i07ZipSha
                                zip_bytes = $script:i07ZipBytes
                                package_files = $script:i07PackageFiles
                            })
                        $proof = New-I07FailureProofSnapshot -Node $node `
                            -SourceSnapshot $held.snapshot `
                            -Context $failureContext
                        $proofPath = Join-Path $script:i07PrivateRoot `
                            "${role}-failure-proof.json"
                        Write-I07HeldSnapshot -Snapshot $proof `
                            -Path $proofPath
                        $reloadedProof = Read-I07JsonByteSnapshot `
                            -Path $proofPath
                        if (-not (Test-I07HeldSnapshotCopy `
                                -Snapshot $proof -Path $proofPath) -or
                            -not (Test-I07FailureProofProvenanceContract `
                                -Value $reloadedProof.value `
                                -SourceSnapshot $held.snapshot `
                                -Context $failureContext)) {
                            throw 'Recovered FAIL proof lost provenance.'
                        }
                        if ($role -ceq 'source') {
                            $script:i07SourceFailureProofSnapshot =
                                $reloadedProof
                            $script:i07SourceResultSnapshot = $held.snapshot
                            $script:i07SourceFailureContext = $failureContext
                        } else {
                            $script:i07ViewerFailureProofSnapshot =
                                $reloadedProof
                            $script:i07ViewerResultSnapshot = $held.snapshot
                            $script:i07ViewerFailureContext = $failureContext
                        }
                        ++$proofCount
                    }
                }
                $hasFail = $proofCount -gt 0
            }
        }
        $script:i07PublicChecks.cleanup_terminal =
            $terminalJobs -eq $startedSnapshot.Count
        try {
            Clear-I07ProductEvidenceForTerminal `
                -PrivateRoot $script:i07PrivateRoot `
                -KeepFailureProofs $hasFail
            $sourceProofPresent = Test-Path -LiteralPath (
                Join-Path $script:i07PrivateRoot `
                    'source-failure-proof.json') -PathType Leaf
            $viewerProofPresent = Test-Path -LiteralPath (
                Join-Path $script:i07PrivateRoot `
                    'viewer-failure-proof.json') -PathType Leaf
            $hasFail = $hasFail -and (
                $sourceProofPresent -or $viewerProofPresent)
            $script:i07PublicChecks.source_result_received =
                $hasFail -and $sourceProofPresent
            $script:i07PublicChecks.viewer_result_received =
                $hasFail -and $viewerProofPresent
            $script:i07PublicChecks.product_evidence_complete = $hasFail
            $null = Publish-I07PublicResult `
                -Status $(if ($hasFail) { 'FAIL' } else { 'BLOCKED' }) `
                -OutcomeCode $(if ($hasFail) {
                    'PRODUCT_INVARIANT'
                } else { 'CONTROLLER_ABORTED' })
            $publishedTerminal = $true
        } catch {}
    }
    if (-not (Repair-I07StagingCleanup)) {
        [Console]::Error.WriteLine('STAGING_CLEANUP_NOT_PROVEN')
        exit 3
    }
    [Console]::Error.WriteLine(
        'I07_CONTROLLER_ABORTED: see private typed artifacts.')
    if ($hasFail -and $publishedTerminal) { exit 1 }
    exit 2
}

$requiredArguments = [ordered]@{
    CandidatePackagePath = $CandidatePackagePath
    CandidateZipPath = $CandidateZipPath
    ExpectedCommit = $ExpectedCommit
    ViewerCandidatePackagePath = $ViewerCandidatePackagePath
    SourceCandidateZipPath = $SourceCandidateZipPath
    ViewerCandidateZipPath = $ViewerCandidateZipPath
    R01AggregatePath = $R01AggregatePath
    SourceAgentIPv4 = $SourceAgentIPv4
    ViewerAgentIPv4 = $ViewerAgentIPv4
    ExpectedSourceLabUserSidSha256 = $ExpectedSourceLabUserSidSha256
    ExpectedViewerLabUserSidSha256 = $ExpectedViewerLabUserSidSha256
    RouteTargetIPv6 = $RouteTargetIPv6
}
foreach ($entry in $requiredArguments.GetEnumerator()) {
    if ([string]::IsNullOrWhiteSpace([string]$entry.Value)) {
        throw "$($entry.Key) is required for a formal I07 run."
    }
}
if (-not $SourceDisposableLabAccountAcknowledged -or
    -not $ViewerDisposableLabAccountAcknowledged) {
    throw 'I07 requires explicitly acknowledged disposable lab accounts on both nodes.'
}
if ($ExpectedSourceLabUserSidSha256 -cnotmatch '^[0-9a-fA-F]{64}$' -or
    $ExpectedViewerLabUserSidSha256 -cnotmatch '^[0-9a-fA-F]{64}$') {
    throw 'I07 requires the exact SHA-256 of each disposable lab account SID.'
}
$candidate = Get-LabCandidateInfo -PackagePath $CandidatePackagePath `
    -ExpectedCommit $ExpectedCommit
$candidateSha = [string]$candidate.emule_sha256
$candidateExe = Join-Path $candidate.package_path 'emule.exe'
$candidateBytes = [Int64](Get-Item -LiteralPath $candidateExe).Length
$script:i07CandidateBytes = $candidateBytes
$zipFullPath = [IO.Path]::GetFullPath($CandidateZipPath)
if (-not (Test-Path -LiteralPath $zipFullPath -PathType Leaf)) {
    throw "CandidateZipPath is missing: $zipFullPath"
}
$zipSha = Get-LabSha256 -Path $zipFullPath
$zipBytes = [Int64](Get-Item -LiteralPath $zipFullPath).Length
$script:i07CandidateSha = $candidateSha
$script:i07CandidateVersion = [string]$candidate.version
$script:i07CandidateCommit = [string]$candidate.commit
$script:i07BuildInfoSha = [string]$candidate.build_info_sha256
$script:i07ZipSha = $zipSha
$script:i07ZipBytes = $zipBytes
$packageIdentity = Get-I07PackageIdentity `
    -PackagePath ([string]$candidate.package_path)
$packageFiles = @(Assert-I07CriticalPackageContract `
    -Files @($packageIdentity.files))
$script:i07PackageFiles = $packageFiles
$controllerZipBinding = Get-I07CriticalZipEvidence `
    -ZipPath $zipFullPath -ExpectedFiles $packageFiles `
    -ExpectedZipSha256 $zipSha -ExpectedZipBytes $zipBytes
if (-not [bool]$controllerZipBinding.verified -or
    [Int64]$controllerZipBinding.critical_file_count -ne $packageFiles.Count) {
    throw 'The controller could not bind the complete package to the ZIP.'
}
if ([string]::IsNullOrWhiteSpace($SourceCandidatePackagePath)) {
    $SourceCandidatePackagePath = [string]$candidate.package_path
}
$r01Snapshot = Read-I07JsonByteSnapshot -Path $R01AggregatePath
$r01 = $r01Snapshot.value
if (-not (Test-I07R01AggregateContract -Aggregate $r01 `
        -ExpectedVersion ([string]$candidate.version) `
        -ExpectedCommit ([string]$candidate.commit) `
        -ExpectedEmuleSha256 $candidateSha `
        -ExpectedBuildInfoSha256 ([string]$candidate.build_info_sha256) `
        -ExpectedZipSha256 $zipSha -ExpectedZipBytes $zipBytes)) {
    throw 'R01AggregatePath is not a PASS with a qualified hotspot snapshot.'
}
$r01PrerequisiteSnapshot = New-I07R01PrerequisiteSnapshot `
    -Aggregate $r01 -SourceSnapshot $r01Snapshot `
    -CandidateIdentity ([pscustomobject]@{
        version = [string]$candidate.version
        commit = [string]$candidate.commit
        emule_sha256 = $candidateSha
        build_info_sha256 = [string]$candidate.build_info_sha256
        zip_sha256 = $zipSha
        zip_bytes = [Int64]$zipBytes
    })
$script:i07R01PrerequisiteSnapshot = $r01PrerequisiteSnapshot
$script:i07R01SourceSnapshot = $r01Snapshot
$script:i07PublicChecks.r01_dependency_valid = $true
$hotspotProfileSha =
    ([string]$r01.topology.hotspot_connection_profile_sha256).ToLowerInvariant()
$hotspotInterfaceGuid = ([Guid]::Parse(
    [string]$r01.remote.topology.mobile.interface_guid)).ToString('D')
$homeProfileSha =
    ([string]$r01.topology.home_connection_profile_sha256).ToLowerInvariant()
$hotspotWlanProfileSha =
    ([string]$r01.requested_hotspot_wlan_profile_sha256).ToLowerInvariant()
$homeWlanProfileSha =
    ([string]$r01.requested_home_wlan_profile_sha256).ToLowerInvariant()
$script:i07HotspotWlanSha = $hotspotWlanProfileSha
$script:i07HotspotConnectionSha = $hotspotProfileSha

$runId = [Guid]::NewGuid().ToString('N')
$nonce = [Guid]::NewGuid().ToString('N')
$runRoot = Join-Path ([IO.Path]::GetFullPath($OutputRoot)) $runId
New-Item -ItemType Directory -Path $runRoot -Force | Out-Null
$privateRoot = Join-Path $runRoot 'private'
New-Item -ItemType Directory -Path $privateRoot -Force | Out-Null
$r01SnapshotPath = Join-Path $privateRoot 'r01-prerequisite.json'
Write-I07HeldSnapshot -Snapshot $r01PrerequisiteSnapshot `
    -Path $r01SnapshotPath
$manifestPath = Join-Path $privateRoot 'manifest.json'
$aggregatePath = Join-Path $runRoot 'aggregate-result.json'
$script:i07RunRoot = $runRoot
$script:i07PrivateRoot = $privateRoot
$script:i07ManifestPath = $manifestPath
$script:i07AggregatePath = $aggregatePath
$script:i07SensitiveValues = @(
    $SourceAgentIPv4, $ViewerAgentIPv4, $SourceTokenDpapiPath,
    $ViewerTokenDpapiPath, $CandidatePackagePath, $CandidateZipPath,
    $SourceCandidatePackagePath, $ViewerCandidatePackagePath,
    $SourceCandidateZipPath, $ViewerCandidateZipPath, $R01AggregatePath,
    $ExpectedSourceLabUserSidSha256, $ExpectedViewerLabUserSidSha256,
    $runId, $nonce, $hotspotProfileSha, $hotspotInterfaceGuid,
    $homeProfileSha, $hotspotWlanProfileSha, $homeWlanProfileSha)

$sourceReadiness = Get-I07AgentReadiness -Role source
$viewerReadiness = Get-I07AgentReadiness -Role viewer
$pairClock = Get-I07PairClockEvidence -Source $sourceReadiness `
    -Viewer $viewerReadiness
$manifest = [ordered]@{
    schema = 'ese.v91.i07-manifest/v1'
    case_id = 'V91-I07'
    topology = 'T3'
    run_id = $runId
    nonce = $nonce
    created_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
    candidate = [ordered]@{
        version = [string]$candidate.version
        commit = [string]$candidate.commit
        sha256 = $candidateSha
        bytes = $candidateBytes
        build_info_sha256 = [string]$candidate.build_info_sha256
        zip_sha256 = $zipSha
        zip_bytes = $zipBytes
        package_files = $packageFiles
    }
    source = [ordered]@{
        baseline_job_id = [Guid]::NewGuid().ToString('N')
        preflight_job_id = [Guid]::NewGuid().ToString('N')
        job_id = [Guid]::NewGuid().ToString('N')
    }
    viewer = [ordered]@{
        baseline_job_id = [Guid]::NewGuid().ToString('N')
        preflight_job_id = [Guid]::NewGuid().ToString('N')
        job_id = [Guid]::NewGuid().ToString('N')
    }
    r01 = [ordered]@{
        prerequisite_bytes = [Int64]$r01PrerequisiteSnapshot.byte_count
        prerequisite_sha256 = [string]$r01PrerequisiteSnapshot.sha256
        hotspot_connection_profile_sha256 = $hotspotProfileSha
        hotspot_interface_guid = $hotspotInterfaceGuid
        home_connection_profile_sha256 = $homeProfileSha
        hotspot_wlan_profile_sha256 = $hotspotWlanProfileSha
        home_wlan_profile_sha256 = $homeWlanProfileSha
    }
    agent_readiness_before_wifi_mutation = [ordered]@{
        source = $sourceReadiness
        viewer = $viewerReadiness
        pair_clock = $pairClock
    }
}
Publish-I07Aggregate -Path $manifestPath -Value $manifest
if (-not (Test-I07HeldSnapshotCopy -Snapshot $r01PrerequisiteSnapshot `
        -Path $r01SnapshotPath)) {
    throw 'The retained R01 prerequisite changed before campaign mutation.'
}
$script:i07PublicChecks.agents_ready =
    [bool]$sourceReadiness.valid -and [bool]$viewerReadiness.valid -and
    [bool]$pairClock.valid
if (-not [bool]$sourceReadiness.valid -or
    -not [bool]$viewerReadiness.valid -or
    -not [bool]$pairClock.valid) {
    $readinessAggregate = Publish-I07PublicResult -Status BLOCKED `
        -OutcomeCode READINESS_NOT_PROVEN
    $readinessAggregate
    exit 2
}

$baselineContracts = [ordered]@{
    source = [ordered]@{
        tcp_ports = @(48067, 48117, 48907)
        udp_ports = @(48077)
    }
    viewer = [ordered]@{
        tcp_ports = @(48267, 48317)
        udp_ports = @(48277)
    }
}
foreach ($role in @('source', 'viewer')) {
    $baselineJob = [string]$manifest.$role.baseline_job_id
    $remoteRoot = "injected/$baselineJob"
    Invoke-I07Agent -Role $role -Command upload -Extra @{
        SourcePath = $baselineScript
        RemotePath = "$remoteRoot/inspect_v91_i07_baseline_remote.ps1"
    } | Out-Null
    $requestPath = Join-Path $privateRoot "$role-baseline-request.json"
    [ordered]@{
        schema = 'ese.v91.i07-baseline-request/v1'
        nonce = $nonce
        role = $role
        tcp_ports = @($baselineContracts.$role.tcp_ports)
        udp_ports = @($baselineContracts.$role.udp_ports)
    } | ConvertTo-Json -Depth 4 |
        Set-Content -LiteralPath $requestPath -Encoding UTF8
    $baselineContext = [pscustomobject][ordered]@{
        role = $role; nonce = $nonce
        tcp_ports = @($baselineContracts.$role.tcp_ports)
        udp_ports = @($baselineContracts.$role.udp_ports)
    }
    $script:i07ContextValidators[$baselineJob] =
        New-I07RetentionContextValidator -Kind baseline `
            -Context $baselineContext
    $script:i07StartedJobs.Add([pscustomobject]@{
        role = $role; kind = 'baseline'; job_id = $baselineJob
    })
    Invoke-I07Agent -Role $role -Command run -Extra @{
        JobId = $baselineJob
        RemotePath = "$remoteRoot/inspect_v91_i07_baseline_remote.ps1"
        JobRequestPath = $requestPath
    } | Out-Null
}
$baselineDeadline = [DateTimeOffset]::UtcNow.AddSeconds(90)
$baselineResults = [ordered]@{}
foreach ($role in @('source', 'viewer')) {
    $baselineJob = [string]$manifest.$role.baseline_job_id
    $null = Wait-I07Job -Role $role -JobId $baselineJob `
        -Deadline $baselineDeadline
    $outputPath = Join-Path $privateRoot "$role-baseline-result.json"
    $baselineSnapshot = Receive-I07StagedJson -Role $role `
        -RemotePath "jobs/$baselineJob/result.json" `
        -Kind baseline -ContextValidator (
            $script:i07ContextValidators[$baselineJob])
    Write-I07HeldSnapshot -Snapshot $baselineSnapshot -Path $outputPath
    $baselineResults[$role] = $baselineSnapshot.value
}
$baselineValid = $true
foreach ($role in @('source', 'viewer')) {
    $value = $baselineResults[$role]
    $expectedTcp = @($baselineContracts.$role.tcp_ports | Sort-Object)
    $actualTcp = @($value.tcp_ports | ForEach-Object { [int]$_.port } |
        Sort-Object)
    $expectedUdp = @($baselineContracts.$role.udp_ports | Sort-Object)
    $actualUdp = @($value.udp_ports | ForEach-Object { [int]$_.port } |
        Sort-Object)
    $baselineValid = $baselineValid -and
        [string]$value.schema -ceq 'ese.v91.i07-baseline-result/v1' -and
        [string]$value.case_id -ceq 'V91-I07' -and
        [string]$value.status -ceq 'PREFLIGHT_PASS' -and
        [string]$value.role -ceq $role -and
        [string]$value.nonce -ceq $nonce -and
        [int]$value.emule_process_count -eq 0 -and
        (@($actualTcp) -join ',') -ceq (@($expectedTcp) -join ',') -and
        (@($actualUdp) -join ',') -ceq (@($expectedUdp) -join ',') -and
        @($value.tcp_ports | Where-Object {
                -not [bool]$_.available -or [int]$_.owner_count -ne 0
            }).Count -eq 0 -and
        @($value.udp_ports | Where-Object {
                -not [bool]$_.available -or [int]$_.owner_count -ne 0
            }).Count -eq 0
}
$manifest['pre_mutation_baseline'] = $baselineResults
Publish-I07Aggregate -Path $manifestPath -Value $manifest
$script:i07PublicChecks.baseline_clean = $baselineValid
if (-not $baselineValid) {
    $baselineAggregate = Publish-I07PublicResult -Status BLOCKED `
        -OutcomeCode BASELINE_NOT_CLEAN
    $baselineAggregate
    exit 2
}

$script:i07HomeProfileSha = $homeProfileSha
$script:i07HomeWlanProfileSha = $homeWlanProfileSha
$script:i07HotspotInterfaceGuid = $hotspotInterfaceGuid
$script:i07Nonce = $nonce
$script:i07LeaseSeconds = [Math]::Min(
    1800, [Math]::Max(900, $TimeoutSeconds + 480))
$script:i07WifiSwitched = $true
$hotspotTransition = Invoke-I07WifiTransition -Action hotspot `
    -WlanProfileSha256 $hotspotWlanProfileSha `
    -ConnectionProfileSha256 $hotspotProfileSha `
    -Nonce $nonce -HomeWlanProfileSha256 $homeWlanProfileSha `
    -HomeConnectionProfileSha256 $homeProfileSha `
    -InterfaceGuid $hotspotInterfaceGuid `
    -OutputPath (Join-Path $privateRoot 'viewer-hotspot-transition.json') `
    -LeaseSeconds $script:i07LeaseSeconds
if ([string]$hotspotTransition.status -cne 'PASS') {
    throw 'The viewer could not enter the R01-qualified hotspot profile.'
}
$script:i07PublicChecks.hotspot_transition_pass = $true
$script:i07PublicChecks.hotspot_profile_match = $true
$manifest['hotspot_transition'] = $hotspotTransition
Publish-I07Aggregate -Path $manifestPath -Value $manifest

foreach ($role in @('source', 'viewer')) {
    $preflightJob = [string]$manifest.$role.preflight_job_id
    $remoteRoot = "injected/$preflightJob"
    Invoke-I07Agent -Role $role -Command upload -Extra @{
        SourcePath = $commonScript
        RemotePath = "$remoteRoot/v91_i07_common.ps1"
    } | Out-Null
    Invoke-I07Agent -Role $role -Command upload -Extra @{
        SourcePath = $preflightScript
        RemotePath = "$remoteRoot/inspect_v91_i07_remote.ps1"
    } | Out-Null
    $requestPath = Join-Path $privateRoot "$role-preflight-request.json"
    $routeTarget = $RouteTargetIPv6
    [ordered]@{
        role = $role
        nonce = $nonce
        candidate_sha256 = $candidateSha
        route_target_ipv6 = $routeTarget
    } | ConvertTo-Json | Set-Content -LiteralPath $requestPath -Encoding UTF8
    $preflightContext = [pscustomobject][ordered]@{
        role = $role; nonce = $nonce; candidate_sha256 = $candidateSha
        candidate_version = [string]$candidate.version
        route_target_ipv6 = $routeTarget
    }
    $script:i07ContextValidators[$preflightJob] =
        New-I07RetentionContextValidator -Kind preflight `
            -Context $preflightContext
    $script:i07StartedJobs.Add([pscustomobject]@{
        role = $role; kind = 'preflight'; job_id = $preflightJob
    })
    Invoke-I07Agent -Role $role -Command run -Extra @{
        JobId = $preflightJob
        RemotePath = "$remoteRoot/inspect_v91_i07_remote.ps1"
        JobRequestPath = $requestPath
    } | Out-Null
}

$preflightDeadline = [DateTimeOffset]::UtcNow.AddSeconds(120)
$preflightSnapshots = [ordered]@{}
foreach ($role in @('source', 'viewer')) {
    $null = Wait-I07Job -Role $role `
        -JobId ([string]$manifest.$role.preflight_job_id) `
        -Deadline $preflightDeadline
    $outputPath = Join-Path $privateRoot "$role-preflight-result.json"
    $preflightSnapshot = Receive-I07StagedJson -Role $role `
        -RemotePath "jobs/$($manifest.$role.preflight_job_id)/result.json" `
        -Kind preflight -ContextValidator (
            $script:i07ContextValidators[
                [string]$manifest.$role.preflight_job_id])
    Write-I07HeldSnapshot -Snapshot $preflightSnapshot -Path $outputPath
    $preflightSnapshots[$role] = [pscustomobject]@{
        snapshot = $preflightSnapshot; path = $outputPath
    }
}
$sourcePreflight = $preflightSnapshots.source.snapshot.value
$viewerPreflight = $preflightSnapshots.viewer.snapshot.value
foreach ($role in @('source', 'viewer')) {
    $held = $preflightSnapshots[$role]
    if (-not (Test-I07HeldSnapshotCopy -Snapshot $held.snapshot `
            -Path $held.path)) {
        throw 'A retained preflight result changed before node requests.'
    }
}

function Test-I07PreflightEnvelope {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][string]$ExpectedRole
    )
    try {
        $route = $Value.selected_route
        $sourceAddress = ConvertTo-I07CanonicalIPv6 `
            -Value ([string]$route.source_address)
        $identityValid = (
            [string]$Value.schema -ceq 'ese.v91.i07-preflight/v2' -and
            [string]$Value.case_id -ceq 'V91-I07' -and
            [string]$Value.role -ceq $ExpectedRole -and
            [string]$Value.nonce -ceq $nonce -and
            [string]$Value.candidate_sha256 -ceq $candidateSha -and
            [string]$Value.status -cin @('PREFLIGHT_PASS', 'LAB_BLOCKED')
        )
        if (-not $identityValid) { return $false }
        if ([string]$Value.status -ceq 'LAB_BLOCKED') {
            return -not [bool]$route.valid
        }
        return (
            [bool]$route.valid -and
            [string]$route.remote_class -ceq 'global-native' -and
            [string]$route.source_class -ceq 'global-native' -and
            (Get-I07IPv6Class -Address ([Net.IPAddress]::Parse(
                $sourceAddress))) -ceq 'global-native' -and
            [bool]$route.hardware_interface -and
            -not [bool]$route.virtual -and -not [bool]$route.overlay -and
            [bool]$route.default_route_present -and
            [string]$route.address_state -ceq 'Preferred' -and
            [int]$route.interface_index -gt 0 -and
            -not [string]::IsNullOrWhiteSpace([string]$route.interface_guid)
        )
    } catch { return $false }
}
$sourcePreflightEnvelope = Test-I07PreflightEnvelope `
    -Value $sourcePreflight -ExpectedRole source
$viewerPreflightEnvelope = Test-I07PreflightEnvelope `
    -Value $viewerPreflight -ExpectedRole viewer

if (-not $sourcePreflightEnvelope -or -not $viewerPreflightEnvelope) {
    throw 'I07 received a stale or malformed preflight envelope.'
}
if (([string]$viewerPreflight.selected_route.interface_guid).Trim('{}') `
        -ine $hotspotInterfaceGuid.Trim('{}')) {
    throw 'I07 viewer discovery is not on the R01-qualified hotspot NIC.'
}
$script:i07PublicChecks.source_preflight_pass =
    [string]$sourcePreflight.status -ceq 'PREFLIGHT_PASS'
$script:i07PublicChecks.viewer_preflight_pass =
    [string]$viewerPreflight.status -ceq 'PREFLIGHT_PASS'

if ([string]$sourcePreflight.status -cne 'PREFLIGHT_PASS' -or
    [string]$viewerPreflight.status -cne 'PREFLIGHT_PASS') {
    $homeRestore = Invoke-I07WifiTransition -Action home `
        -WlanProfileSha256 $homeWlanProfileSha `
        -ConnectionProfileSha256 $homeProfileSha `
        -Nonce $nonce -HomeWlanProfileSha256 $homeWlanProfileSha `
        -HomeConnectionProfileSha256 $homeProfileSha `
        -InterfaceGuid $hotspotInterfaceGuid `
        -OutputPath (Join-Path $privateRoot 'viewer-home-restore.json') `
        -LeaseSeconds $script:i07LeaseSeconds
    if ([string]$homeRestore.status -cne 'PASS') {
        throw 'The viewer home Wi-Fi profile could not be restored.'
    }
    $script:i07WifiSwitched = $false
    $script:i07PublicChecks.home_restore_pass = $true
    $script:i07PublicChecks.cleanup_terminal = $true
    $aggregate = Publish-I07PublicResult -Status BLOCKED `
        -OutcomeCode NATIVE_IPV6_NOT_PROVEN
    $aggregate
    exit 2
}

$sourceIPv6 = [string]$sourcePreflight.selected_route.source_address
$viewerIPv6 = [string]$viewerPreflight.selected_route.source_address
$script:i07SensitiveValues += @(
    $sourceIPv6, $viewerIPv6,
    [string]$sourcePreflight.selected_route.interface_guid,
    [string]$viewerPreflight.selected_route.interface_guid)
$sourceRequestPath = Join-Path $privateRoot 'source-request.json'
$viewerRequestPath = Join-Path $privateRoot 'viewer-request.json'
$baseRequest = [ordered]@{
    nonce = $nonce
    candidate_sha256 = $candidateSha
    control_port = 48907
    duration_seconds = $DurationSeconds
}
$sourceRequest = [ordered]@{
    role = 'source'
    nonce = $nonce
    candidate_sha256 = $candidateSha
    candidate_package_path = $SourceCandidatePackagePath
    candidate_commit = [string]$candidate.commit
    candidate_build_info_sha256 = [string]$candidate.build_info_sha256
    candidate_zip_sha256 = $zipSha
    candidate_zip_bytes = $zipBytes
    candidate_zip_path = $SourceCandidateZipPath
    package_files = $packageFiles
    disposable_lab_account_acknowledged = $true
    expected_lab_user_sid_sha256 =
        $ExpectedSourceLabUserSidSha256.ToLowerInvariant()
    local_ipv6 = $sourceIPv6
    peer_ipv6 = $viewerIPv6
    interface_index = [int]$sourcePreflight.selected_route.interface_index
    interface_guid = [string]$sourcePreflight.selected_route.interface_guid
    tcp_port = 48067
    udp_port = 48077
    web_port = 48117
    peer_tcp_port = 48267
    control_port = [int]$baseRequest.control_port
    duration_seconds = [int]$baseRequest.duration_seconds
}
$viewerRequest = [ordered]@{
    role = 'viewer'
    nonce = $nonce
    candidate_sha256 = $candidateSha
    candidate_package_path = $ViewerCandidatePackagePath
    candidate_commit = [string]$candidate.commit
    candidate_build_info_sha256 = [string]$candidate.build_info_sha256
    candidate_zip_sha256 = $zipSha
    candidate_zip_bytes = $zipBytes
    candidate_zip_path = $ViewerCandidateZipPath
    package_files = $packageFiles
    disposable_lab_account_acknowledged = $true
    expected_lab_user_sid_sha256 =
        $ExpectedViewerLabUserSidSha256.ToLowerInvariant()
    hotspot_wlan_profile_sha256 = $hotspotWlanProfileSha
    hotspot_connection_profile_sha256 = $hotspotProfileSha
    local_ipv6 = $viewerIPv6
    peer_ipv6 = $sourceIPv6
    interface_index = [int]$viewerPreflight.selected_route.interface_index
    interface_guid = [string]$viewerPreflight.selected_route.interface_guid
    tcp_port = 48267
    udp_port = 48277
    web_port = 48317
    peer_tcp_port = 48067
    control_port = [int]$baseRequest.control_port
    duration_seconds = [int]$baseRequest.duration_seconds
}
$sourceRequest | ConvertTo-Json -Depth 8 |
    Set-Content -LiteralPath $sourceRequestPath -Encoding UTF8
$viewerRequest | ConvertTo-Json -Depth 8 |
    Set-Content -LiteralPath $viewerRequestPath -Encoding UTF8

foreach ($role in @('source', 'viewer')) {
    $jobId = [string]$manifest.$role.job_id
    $requestContext = if ($role -ceq 'source') {
        $sourceRequest
    } else { $viewerRequest }
    $nodeContext = [pscustomobject][ordered]@{
        role = $role; nonce = $nonce; candidate_sha256 = $candidateSha
        commit = [string]$candidate.commit
        build_info_sha256 = [string]$candidate.build_info_sha256
        zip_sha256 = $zipSha; zip_bytes = $zipBytes
        package_files = $packageFiles
        expected_user_sid_sha256 =
            [string]$requestContext.expected_lab_user_sid_sha256
        local_ipv6 = [string]$requestContext.local_ipv6
        peer_ipv6 = [string]$requestContext.peer_ipv6
        interface_index = [int]$requestContext.interface_index
        interface_guid = [string]$requestContext.interface_guid
    }
    $script:i07ContextValidators[$jobId] =
        New-I07RetentionContextValidator -Kind node -Context $nodeContext
    $remoteRoot = "injected/$jobId"
    Invoke-I07Agent -Role $role -Command upload -Extra @{
        SourcePath = $commonScript
        RemotePath = "$remoteRoot/v91_i07_common.ps1"
    } | Out-Null
    Invoke-I07Agent -Role $role -Command upload -Extra @{
        SourcePath = $nodeScript
        RemotePath = "$remoteRoot/run_v91_i07_node.ps1"
    } | Out-Null
}

$script:i07StartedJobs.Add([pscustomobject]@{
    role = 'source'; kind = 'node'; job_id = [string]$manifest.source.job_id
})
Invoke-I07Agent -Role source -Command run -Extra @{
    JobId = [string]$manifest.source.job_id
    RemotePath = "injected/$($manifest.source.job_id)/run_v91_i07_node.ps1"
    JobRequestPath = $sourceRequestPath
} | Out-Null
Start-Sleep -Seconds 1
$script:i07StartedJobs.Add([pscustomobject]@{
    role = 'viewer'; kind = 'node'; job_id = [string]$manifest.viewer.job_id
})
Invoke-I07Agent -Role viewer -Command run -Extra @{
    JobId = [string]$manifest.viewer.job_id
    RemotePath = "injected/$($manifest.viewer.job_id)/run_v91_i07_node.ps1"
    JobRequestPath = $viewerRequestPath
} | Out-Null

$jobDeadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
$sourceState = Wait-I07Job -Role source `
    -JobId ([string]$manifest.source.job_id) -Deadline $jobDeadline
$viewerState = Wait-I07Job -Role viewer `
    -JobId ([string]$manifest.viewer.job_id) -Deadline $jobDeadline

$sourcePassProofPath = Join-Path $privateRoot 'source-pass-proof.json'
$viewerPassProofPath = Join-Path $privateRoot 'viewer-pass-proof.json'
$sourceResult = $null
$viewerResult = $null
$sourceResultSnapshot = $null
$viewerResultSnapshot = $null
$sourceFailureProofSnapshot = $null
$viewerFailureProofSnapshot = $null
$sourcePassProofSnapshot = $null
$viewerPassProofSnapshot = $null
try {
    $sourceResultSnapshot = Receive-I07StagedJson -Role source `
        -RemotePath "jobs/$($manifest.source.job_id)/i07-result.json" `
        -Kind node -ContextValidator (
            $script:i07ContextValidators[[string]$manifest.source.job_id])
    $sourceResult = $sourceResultSnapshot.value
} catch { Assert-I07StagingCleanupProven }
try {
    $viewerResultSnapshot = Receive-I07StagedJson -Role viewer `
        -RemotePath "jobs/$($manifest.viewer.job_id)/i07-result.json" `
        -Kind node -ContextValidator (
            $script:i07ContextValidators[[string]$manifest.viewer.job_id])
    $viewerResult = $viewerResultSnapshot.value
} catch { Assert-I07StagingCleanupProven }

$aggregateStatus = Get-I07AggregateStatus -Source $sourceResult `
    -Viewer $viewerResult -Nonce $nonce -CandidateSha256 $candidateSha `
    -CandidateCommit ([string]$candidate.commit) `
    -BuildInfoSha256 ([string]$candidate.build_info_sha256) `
    -ZipSha256 $zipSha -ZipBytes $zipBytes `
    -ExpectedDurationSeconds $DurationSeconds `
    -ExpectedPackageFiles $packageFiles `
    -ExpectedViewerWlanProfileSha256 $hotspotWlanProfileSha `
    -ExpectedViewerConnectionProfileSha256 $hotspotProfileSha `
    -ExpectedViewerInterfaceGuid $hotspotInterfaceGuid
$aggregateArguments = @{
    Nonce = $nonce; CandidateSha256 = $candidateSha
    CandidateCommit = [string]$candidate.commit
    BuildInfoSha256 = [string]$candidate.build_info_sha256
    ZipSha256 = $zipSha; ZipBytes = $zipBytes
    ExpectedDurationSeconds = $DurationSeconds
    ExpectedPackageFiles = $packageFiles
    ExpectedViewerWlanProfileSha256 = $hotspotWlanProfileSha
    ExpectedViewerConnectionProfileSha256 = $hotspotProfileSha
    ExpectedViewerInterfaceGuid = $hotspotInterfaceGuid
}
$commonPassContext = [ordered]@{
    nonce = $nonce; candidate_version = [string]$candidate.version
    candidate_sha256 = $candidateSha
    candidate_commit = [string]$candidate.commit
    build_info_sha256 = [string]$candidate.build_info_sha256
    zip_sha256 = $zipSha; zip_bytes = $zipBytes
    package_files = $packageFiles; duration_seconds = $DurationSeconds
    r01_prerequisite_sha256 = [string]$r01PrerequisiteSnapshot.sha256
    r01_prerequisite_bytes = [Int64]$r01PrerequisiteSnapshot.byte_count
    hotspot_wlan_profile_sha256 = $hotspotWlanProfileSha
    hotspot_connection_profile_sha256 = $hotspotProfileSha
}
$sourcePassContext = [pscustomobject][ordered]@{
    role = 'source'; nonce = $commonPassContext.nonce
    candidate_version = $commonPassContext.candidate_version
    candidate_sha256 = $commonPassContext.candidate_sha256
    candidate_commit = $commonPassContext.candidate_commit
    build_info_sha256 = $commonPassContext.build_info_sha256
    zip_sha256 = $commonPassContext.zip_sha256
    zip_bytes = $commonPassContext.zip_bytes
    package_files = $commonPassContext.package_files
    duration_seconds = $commonPassContext.duration_seconds
    r01_prerequisite_sha256 = $commonPassContext.r01_prerequisite_sha256
    r01_prerequisite_bytes = $commonPassContext.r01_prerequisite_bytes
    hotspot_wlan_profile_sha256 = $commonPassContext.hotspot_wlan_profile_sha256
    hotspot_connection_profile_sha256 =
        $commonPassContext.hotspot_connection_profile_sha256
    local_ipv6 = [string]$sourceRequest.local_ipv6
    peer_ipv6 = [string]$sourceRequest.peer_ipv6
    interface_index = [Int64]$sourceRequest.interface_index
    interface_guid = [string]$sourceRequest.interface_guid
    tcp_port = [Int64]$sourceRequest.tcp_port
    udp_port = [Int64]$sourceRequest.udp_port
    web_port = [Int64]$sourceRequest.web_port
    peer_tcp_port = [Int64]$sourceRequest.peer_tcp_port
    control_port = [Int64]$sourceRequest.control_port
}
$viewerPassContext = [pscustomobject][ordered]@{
    role = 'viewer'; nonce = $commonPassContext.nonce
    candidate_version = $commonPassContext.candidate_version
    candidate_sha256 = $commonPassContext.candidate_sha256
    candidate_commit = $commonPassContext.candidate_commit
    build_info_sha256 = $commonPassContext.build_info_sha256
    zip_sha256 = $commonPassContext.zip_sha256
    zip_bytes = $commonPassContext.zip_bytes
    package_files = $commonPassContext.package_files
    duration_seconds = $commonPassContext.duration_seconds
    r01_prerequisite_sha256 = $commonPassContext.r01_prerequisite_sha256
    r01_prerequisite_bytes = $commonPassContext.r01_prerequisite_bytes
    hotspot_wlan_profile_sha256 = $commonPassContext.hotspot_wlan_profile_sha256
    hotspot_connection_profile_sha256 =
        $commonPassContext.hotspot_connection_profile_sha256
    local_ipv6 = [string]$viewerRequest.local_ipv6
    peer_ipv6 = [string]$viewerRequest.peer_ipv6
    interface_index = [Int64]$viewerRequest.interface_index
    interface_guid = [string]$viewerRequest.interface_guid
    tcp_port = [Int64]$viewerRequest.tcp_port
    udp_port = [Int64]$viewerRequest.udp_port
    web_port = [Int64]$viewerRequest.web_port
    peer_tcp_port = [Int64]$viewerRequest.peer_tcp_port
    control_port = [Int64]$viewerRequest.control_port
}
$failureCandidateIdentity = [pscustomobject][ordered]@{
    version = [string]$candidate.version
    commit = [string]$candidate.commit
    emule_sha256 = $candidateSha; bytes = $candidateBytes
    build_info_sha256 = [string]$candidate.build_info_sha256
    zip_sha256 = $zipSha; zip_bytes = $zipBytes
    package_files = $packageFiles
}
$sourceFailureContext = $null
$viewerFailureContext = $null
if ($aggregateStatus -ceq 'PASS') {
    if ($null -eq $sourceResultSnapshot -or
        $null -eq $viewerResultSnapshot) {
        throw 'I07 PASS lost its in-memory source node snapshots.'
    }
    $sourcePassProofSnapshot = New-I07PassProofSnapshot `
        -SourceSnapshot $sourceResultSnapshot -Context $sourcePassContext
    $viewerPassProofSnapshot = New-I07PassProofSnapshot `
        -SourceSnapshot $viewerResultSnapshot -Context $viewerPassContext
    if (-not (Test-I07PassProofPairContract `
            -Source $sourcePassProofSnapshot.value `
            -Viewer $viewerPassProofSnapshot.value)) {
        throw 'I07 PASS pair proof did not cross-bind both nodes.'
    }
} elseif ($aggregateStatus -ceq 'FAIL') {
    if ($null -ne $sourceResultSnapshot -and
        (Get-I07AggregateStatus -Source $sourceResult -Viewer $null `
            @aggregateArguments) -ceq 'FAIL') {
        $sourceFailureContext = New-I07FailureProofContext -Role source `
            -Nonce $nonce -CandidateIdentity $failureCandidateIdentity `
            -DurationSeconds $DurationSeconds
        $sourceFailureProofSnapshot = New-I07FailureProofSnapshot `
            -Node $sourceResult `
            -SourceSnapshot $sourceResultSnapshot `
            -Context $sourceFailureContext
    }
    if ($null -ne $viewerResultSnapshot -and
        (Get-I07AggregateStatus -Source $null -Viewer $viewerResult `
            @aggregateArguments) -ceq 'FAIL') {
        $viewerFailureContext = New-I07FailureProofContext -Role viewer `
            -Nonce $nonce -CandidateIdentity $failureCandidateIdentity `
            -DurationSeconds $DurationSeconds
        $viewerFailureProofSnapshot = New-I07FailureProofSnapshot `
            -Node $viewerResult `
            -SourceSnapshot $viewerResultSnapshot `
            -Context $viewerFailureContext
    }
}
$homeRestore = Invoke-I07WifiTransition -Action home `
    -WlanProfileSha256 $homeWlanProfileSha `
    -ConnectionProfileSha256 $homeProfileSha `
    -Nonce $nonce -HomeWlanProfileSha256 $homeWlanProfileSha `
    -HomeConnectionProfileSha256 $homeProfileSha `
    -InterfaceGuid $hotspotInterfaceGuid `
    -OutputPath (Join-Path $privateRoot 'viewer-home-restore.json') `
    -LeaseSeconds $script:i07LeaseSeconds
$script:i07WifiSwitched =
    [string]$homeRestore.status -cne 'PASS'
if ($script:i07WifiSwitched) {
    throw 'The viewer home Wi-Fi profile could not be restored.'
}
$script:i07PublicChecks.home_restore_pass = $true
$script:i07PublicChecks.cleanup_terminal =
    [string]$sourceState.state -cin @('COMPLETE', 'ERROR', 'STOPPED') -and
    [string]$viewerState.state -cin @('COMPLETE', 'ERROR', 'STOPPED')
if (-not $script:i07PublicChecks.cleanup_terminal) {
    throw 'I07 node jobs did not reach terminal cleanup state.'
}
if ($aggregateStatus -ceq 'PASS') {
    if ($null -eq $sourcePassProofSnapshot -or
        $null -eq $viewerPassProofSnapshot) {
        throw 'I07 PASS lost its sanitized proof snapshots.'
    }
    Write-I07HeldSnapshot -Snapshot $sourcePassProofSnapshot `
        -Path $sourcePassProofPath
    Write-I07HeldSnapshot -Snapshot $viewerPassProofSnapshot `
        -Path $viewerPassProofPath
    $sourceReloaded = Read-I07JsonByteSnapshot -Path $sourcePassProofPath
    $viewerReloaded = Read-I07JsonByteSnapshot -Path $viewerPassProofPath
    if (-not (Test-I07HeldSnapshotCopy -Snapshot $sourcePassProofSnapshot `
            -Path $sourcePassProofPath) -or
        -not (Test-I07HeldSnapshotCopy -Snapshot $viewerPassProofSnapshot `
            -Path $viewerPassProofPath) -or
        -not (Test-I07PassProofContract -Value $sourceReloaded.value `
            -SourceSnapshot $sourceResultSnapshot `
            -Context $sourcePassContext) -or
        -not (Test-I07PassProofContract -Value $viewerReloaded.value `
            -SourceSnapshot $viewerResultSnapshot `
            -Context $viewerPassContext) -or
        -not (Test-I07PassProofPairContract -Source $sourceReloaded.value `
            -Viewer $viewerReloaded.value)) {
        throw 'I07 retained PASS proofs failed exact reload validation.'
    }
    $script:i07SourcePassProofSnapshot = $sourceReloaded
    $script:i07ViewerPassProofSnapshot = $viewerReloaded
    $script:i07SourceResultSnapshot = $sourceResultSnapshot
    $script:i07ViewerResultSnapshot = $viewerResultSnapshot
    $script:i07SourcePassContext = $sourcePassContext
    $script:i07ViewerPassContext = $viewerPassContext
    $script:i07PublicChecks.source_result_received = $true
    $script:i07PublicChecks.viewer_result_received = $true
    $script:i07PublicChecks.product_evidence_complete = $true
} elseif ($aggregateStatus -ceq 'FAIL') {
    if ($null -ne $sourceFailureProofSnapshot) {
        $sourceFailurePath = Join-Path $privateRoot `
            'source-failure-proof.json'
        Write-I07HeldSnapshot -Snapshot $sourceFailureProofSnapshot `
            -Path $sourceFailurePath
        $sourceFailureReloaded = Read-I07JsonByteSnapshot `
            -Path $sourceFailurePath
        if (-not (Test-I07HeldSnapshotCopy `
                -Snapshot $sourceFailureProofSnapshot `
                -Path $sourceFailurePath) -or
            -not (Test-I07FailureProofProvenanceContract `
                -Value $sourceFailureReloaded.value `
                -SourceSnapshot $sourceResultSnapshot `
                -Context $sourceFailureContext)) {
            throw 'I07 retained Source failure proof lost provenance.'
        }
        $script:i07SourceFailureProofSnapshot = $sourceFailureReloaded
        $script:i07SourceResultSnapshot = $sourceResultSnapshot
        $script:i07SourceFailureContext = $sourceFailureContext
        $script:i07PublicChecks.source_result_received = $true
    }
    if ($null -ne $viewerFailureProofSnapshot) {
        $viewerFailurePath = Join-Path $privateRoot `
            'viewer-failure-proof.json'
        Write-I07HeldSnapshot -Snapshot $viewerFailureProofSnapshot `
            -Path $viewerFailurePath
        $viewerFailureReloaded = Read-I07JsonByteSnapshot `
            -Path $viewerFailurePath
        if (-not (Test-I07HeldSnapshotCopy `
                -Snapshot $viewerFailureProofSnapshot `
                -Path $viewerFailurePath) -or
            -not (Test-I07FailureProofProvenanceContract `
                -Value $viewerFailureReloaded.value `
                -SourceSnapshot $viewerResultSnapshot `
                -Context $viewerFailureContext)) {
            throw 'I07 retained Viewer failure proof lost provenance.'
        }
        $script:i07ViewerFailureProofSnapshot = $viewerFailureReloaded
        $script:i07ViewerResultSnapshot = $viewerResultSnapshot
        $script:i07ViewerFailureContext = $viewerFailureContext
        $script:i07PublicChecks.viewer_result_received = $true
    }
    $script:i07PublicChecks.product_evidence_complete =
        $script:i07PublicChecks.source_result_received -or
        $script:i07PublicChecks.viewer_result_received
    if (-not $script:i07PublicChecks.product_evidence_complete) {
        throw 'I07 FAIL produced no sanitized failure proof.'
    }
}
$aggregate = Publish-I07PublicResult -Status $aggregateStatus `
    -OutcomeCode $(if ($aggregateStatus -ceq 'PASS') {
        'PASS'
    } elseif ($aggregateStatus -ceq 'FAIL') {
        'PRODUCT_INVARIANT'
    } else { 'EVIDENCE_INCOMPLETE' })
$aggregate
if ($aggregateStatus -ceq 'PASS') { exit 0 }
if ($aggregateStatus -ceq 'FAIL') { exit 1 }
exit 2
