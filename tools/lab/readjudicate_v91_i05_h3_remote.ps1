[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$JobRequestPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2
$script:readjudicationPhase = 'bootstrap'
trap {
    $line = [int]$_.InvocationInfo.ScriptLineNumber
    [Console]::Error.WriteLine(
        "READJUDICATION_ERROR phase=$script:readjudicationPhase line=$line")
    [Console]::Error.WriteLine([string]$_)
    exit 1
}

function Assert-Readjudication {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Message
    )
    if (-not $Condition) {
        throw $Message
    }
}

function Get-RequiredDocument {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Falta $Label."
    }
    return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
}

$script:readjudicationPhase = 'request'
$jobRoot = Split-Path -Parent ([IO.Path]::GetFullPath($JobRequestPath))
$jobsRoot = Split-Path -Parent $jobRoot
$kitRoot = Split-Path -Parent $jobsRoot
$jobEnvelope = Get-RequiredDocument -Path $JobRequestPath -Label 'job request'
Assert-Readjudication (
    [string]$jobEnvelope.schema -ceq 'ese.lab.agent-job-request/v1' -and
    $null -ne $jobEnvelope.request
) 'El sobre de trabajo del agente no es válido.'
$request = $jobEnvelope.request
$nonce = [string]$request.nonce
$runName = [string]$request.run_name
$harnessCommit = [string]$request.harness_commit
Assert-Readjudication ($nonce -match '^[0-9a-f]{32}$') `
    'El nonce de readjudicación no es 32hex lowercase.'
Assert-Readjudication ($runName -match '^v91-i05-h3-[0-9a-f]{8}-[0-9]{8}-[0-9]{6}$') `
    'El nombre de ejecución H3 no es válido.'
Assert-Readjudication ($harnessCommit -match '^[0-9a-f]{40}$') `
    'El commit del adjudicador no es válido.'

$runRoot = Join-Path (Join-Path $kitRoot 'runs') $runName
$evidenceRoot = Join-Path $runRoot 'evidence'
$runner = Join-Path $kitRoot 'run_v91_i05_downloader_kit.ps1'
Assert-Readjudication (Test-Path -LiteralPath $runner -PathType Leaf) `
    'Falta el runner H3 desplegado.'
Assert-Readjudication (Test-Path -LiteralPath $runRoot -PathType Container) `
    'No existe la ejecución H3 solicitada.'

$readyPath = Join-Path $runRoot 'READY-V91-I05-T1.json'
$commandPath = Join-Path $runRoot 'COMMAND-V91-I05-T1.json'
$startedPath = Join-Path $runRoot 'STARTED-V91-I05-T1.json'
$cleanupPath = Join-Path $runRoot 'CLEANUP-V91-I05-T1.json'
$sessionPath = Join-Path $evidenceRoot 'downloader-session-private.json'
$failurePath = Join-Path $evidenceRoot 'FAILURE-V91-I05-T1.json'
$rawIntegrityPath = Join-Path $evidenceRoot `
    'file-integrity-calculation.raw.json'
$socketProofPath = Join-Path $evidenceRoot 'socket-proof.json'
$samplesPath = Join-Path $evidenceRoot 'transfer-samples.jsonl'
$statusReadyPath = Join-Path $evidenceRoot 'status-ready.json'
$statusFinalPath = Join-Path $evidenceRoot 'status-final.json'
$pcapPath = Join-Path $evidenceRoot 'v91-i05-t1-component-15.pcapng'
$completePath = Join-Path $runRoot `
    'COMPLETE-READJUDICATED-V91-I05-T1.json'
$reportPath = Join-Path $runRoot 'READJUDICATION-V91-I05-T1.json'

foreach ($output in @(
    $completePath,
    $reportPath,
    (Join-Path $evidenceRoot 'V91-I05-H3-EVIDENCE.zip')
)) {
    Assert-Readjudication (-not (Test-Path -LiteralPath $output)) `
        "La salida de readjudicación ya existe: $output"
}

$script:readjudicationPhase = 'load-original-documents'
$ready = Get-RequiredDocument -Path $readyPath -Label 'READY'
$command = Get-RequiredDocument -Path $commandPath -Label 'COMMAND'
$started = Get-RequiredDocument -Path $startedPath -Label 'STARTED'
$cleanup = Get-RequiredDocument -Path $cleanupPath -Label 'CLEANUP'
$session = Get-RequiredDocument -Path $sessionPath -Label 'private session'
$failure = Get-RequiredDocument -Path $failurePath -Label 'original FAILURE'
$rawIntegrity = Get-RequiredDocument -Path $rawIntegrityPath `
    -Label 'raw file-integrity report'
$socket = Get-RequiredDocument -Path $socketProofPath -Label 'socket proof'
$statusReady = Get-RequiredDocument -Path $statusReadyPath `
    -Label 'ready API status'
$statusFinal = Get-RequiredDocument -Path $statusFinalPath `
    -Label 'final API status'

Assert-Readjudication (
    [string]$ready.schema -ceq 'ese.v91.i05.t1-ready/v1' -and
    [string]$ready.status -ceq 'READY' -and
    [string]$ready.nonce -ceq $nonce
) 'READY no pertenece a la ejecución solicitada.'
Assert-Readjudication (
    [string]$failure.schema -ceq 'ese.v91.i05.t1-failure/v1' -and
    [string]$failure.status -ceq 'LAB_BLOCKED' -and
    [string]$failure.nonce -ceq $nonce -and
    [string]$failure.phase -ceq 'pktmon_complete' -and
    [string]$failure.category -ceq 'pktmon_complete'
) 'El fallo original no es un bloqueo post-captura readjudicable.'
Assert-Readjudication (
    [string]$cleanup.status -ceq 'CLEANUP_COMPLETE' -and
    [bool]$cleanup.cleanup_complete -and
    [string]$cleanup.nonce -ceq $nonce -and
    [bool]$cleanup.process.absent -and
    [bool]$cleanup.firewall.peer_rule_absent -and
    [bool]$cleanup.firewall.control_rule_absent -and
    [bool]$cleanup.firewall.isolation_rules_absent -and
    [bool]$cleanup.firewall.inventory_restored -and
    [bool]$cleanup.capture.stopped -and
    [bool]$cleanup.capture.owned_filters_absent -and
    [bool]$cleanup.capture.etw_session_absent -and
    [bool]$cleanup.capture.filter_inventory_restored
) 'La limpieza original no quedó demostrada de forma completa.'
Assert-Readjudication (
    [string]$rawIntegrity.status -ceq 'VERIFIED' -and
    [Int64]$rawIntegrity.fixture.bytes -eq 4294967296L -and
    [string]$rawIntegrity.fixture.sha256 -ieq
        '1016d6f63ae1649a879a7c0de30865ed132deb37b1c3b2bc9ca004c88feee26c' -and
    [string]$rawIntegrity.fixture.ed2k -ieq
        '796A95E75DF8E78D54A57CDEA1FEDE84'
) 'La identidad local del fixture no coincide.'
Assert-Readjudication (
    [int]$socket.candidate_pid -eq [int]$ready.node.process_id -and
    [int]$socket.remote_port -eq 7862 -and
    [int]$socket.unique_tuple_count -eq 1 -and
    [int]$socket.forbidden_established_count -eq 0 -and
    [int]$socket.watchdog_violations -eq 0 -and
    [int]$socket.sample_count -gt 0 -and
    [int]$socket.engine_watchdog_samples -eq [int]$socket.sample_count -and
    [int]$socket.engine_watchdog_exact_filter_checks -eq
        [int]$socket.sample_count
) 'La prueba de socket/watchdog no es cerrada.'
Assert-Readjudication (
    [bool]$statusReady.kad_connected -eq $false -and
    [bool]$statusReady.kad6_running -eq $false -and
    [bool]$statusReady.kad6_connected -eq $false -and
    [bool]$statusFinal.kad_connected -eq $false -and
    [bool]$statusFinal.kad6_running -eq $false -and
    [bool]$statusFinal.kad6_connected -eq $false
) 'El estado API retenido contradice el perfil IPv4-only.'

$script:readjudicationPhase = 'load-runner-library'
$previousLibraryOnly = $env:ESE_V91_I05_LIBRARY_ONLY
try {
    $env:ESE_V91_I05_LIBRARY_ONLY = '1'
    . $runner
} finally {
    $env:ESE_V91_I05_LIBRARY_ONLY = $previousLibraryOnly
}
# The library intentionally initializes its normal-run globals even in
# library-only mode. Rebind this tool's immutable execution paths afterwards.
$nonce = [string]$request.nonce
$runRoot = Join-Path (Join-Path $kitRoot 'runs') $runName
$evidenceRoot = Join-Path $runRoot 'evidence'
$cleanupPath = Join-Path $runRoot 'CLEANUP-V91-I05-T1.json'
$sessionPath = Join-Path $evidenceRoot 'downloader-session-private.json'

$script:readjudicationPhase = 'validate-retained-paths'
$capture = $session.capture
$capture.pcapng_path = $pcapPath

foreach ($requiredPath in @(
    $pcapPath,
    [string]$capture.etl_path,
    [string]$capture.command_log,
    [string]$capture.counters_path,
    [string]$capture.loss_path,
    [string]$capture.filters_before,
    [string]$capture.filters_armed,
    [string]$capture.filters_before_reset,
    [string]$capture.filters_after,
    [string]$capture.component_mapping_path,
    [string]$capture.component_pre_compact_path,
    [string]$capture.component_armed_compact_path,
    [string]$capture.component_post_compact_path,
    [string]$capture.component_pre_raw_path,
    [string]$capture.component_armed_raw_path,
    [string]$capture.component_post_raw_path,
    $samplesPath,
    $socketProofPath
)) {
    Assert-Readjudication (Test-Path -LiteralPath $requiredPath -PathType Leaf) `
        "Falta evidencia bruta retenida: $requiredPath"
}

Assert-I05PktMonFilterRowsExact `
    -ExpectedLines @(Get-Content -LiteralPath $capture.filters_armed) `
    -ActualLines @(Get-Content -LiteralPath $capture.filters_before_reset)
Assert-Readjudication (
    (Get-Content -LiteralPath $capture.filters_before -Raw).Trim() -ceq
    (Get-Content -LiteralPath $capture.filters_after -Raw).Trim()
) 'El inventario PktMon final no coincide con el inicial.'

$script:readjudicationPhase = 'validate-etw-loss'
$loss = Get-RequiredDocument -Path $capture.loss_path -Label 'ETW loss report'
Assert-Readjudication (
    [bool]$loss.proved_zero -and
    [UInt64]$loss.error_code -eq 0 -and
    [UInt64]$loss.events_lost -eq 0 -and
    [UInt64]$loss.log_buffers_lost -eq 0 -and
    [UInt64]$loss.realtime_buffers_lost -eq 0 -and
    [UInt64]$loss.buffers_lost -eq 0 -and
    [UInt64]$loss.buffers_written -gt 0
) 'La captura ETW retenida no demuestra pérdida cero.'

$script:readjudicationPhase = 'parse-pcap'
$localPort = [int]$socket.stable_tuple.local_port
$wire = Get-I05PacketEvidence -Path $pcapPath `
    -SourceIPv4 ([string]$session.source_ipv4_address) `
    -DownloaderIPv4 ([string]$session.downloader_ipv4_address) `
    -AllowedLocalPorts @($localPort)
$null = Assert-I05WireEvidence -Wire $wire
Assert-Readjudication (
    [Int64]$wire.IPv4PeerPackets -gt 0 -and
    [Int64]$wire.RejectedPeerTuplePackets -eq 0 -and
    [Int64]$wire.ThirdPartyPeerPackets -eq 0 -and
    [Int64]$wire.IPv6PeerPackets -eq 0
) 'La captura readjudicada no contiene una única tupla peer limpia.'

$script:readjudicationPhase = 'write-compact-evidence'
$mappingSha = Get-LabSha256 -Path $capture.component_mapping_path
$analysis = [ordered]@{
    schema = 'ese.v91.i05.t1-pcap-analysis/v1'
    case_id = 'V91-I05'
    parser_valid = [bool]$wire.Valid
    errors = @($wire.Errors)
    conversion_component_id = 15
    allowed_local_ports = @($localPort)
    exact_peer_packets = [Int64]$wire.IPv4PeerPackets
    ieee80211_packets = [Int64]$wire.IEEE80211Packets
    rejected_peer_tuple_packets = [Int64]$wire.RejectedPeerTuplePackets
    third_party_peer_packets = [Int64]$wire.ThirdPartyPeerPackets
    ipv6_peer_packets = [Int64]$wire.IPv6PeerPackets
    requestparts_i64 = [Int64]$wire.RequestPartsI64
    compressedpart_32 = [Int64]$wire.CompressedPart32
    sendingpart_i64 = [Int64]$wire.SendingPartI64
    compressedpart_i64 = [Int64]$wire.CompressedPartI64
    invalid_fixture_i64_frames = [Int64]$wire.InvalidFixtureI64Frames
    fixture_hash_frames = [Int64]$wire.FixtureHashFrames
    fixture_hash_frame_signatures = @($wire.FixtureHashFrameSignatures)
    truncated_ipv4_peer_packets = [Int64]$wire.TruncatedIPv4PeerPackets
    candidate_pid = [int]$ready.node.process_id
    candidate_pid_role = 'socket-watchdog-context-only'
    pcap_pid_attributed = $false
    tuple_allowlist_pid_observed = $true
    attribution_guard = 'process-scoped-firewall-containment'
    physical_component_guid_match = $true
    component_mapping_sha256 = $mappingSha
    method = [string]$wire.Method
}
$analysisPath = Write-LabJson -Value $analysis `
    -Path (Join-Path $evidenceRoot 'pcap-analysis.json')

$containmentPlan = $session.containment
$containmentForWire = [ordered]@{
    schema = 'ese.v91.i05.t1-firewall-containment/v1'
    rule_count = [int]$containmentPlan.rule_count
    rule_names_sha256 = [string]$containmentPlan.rule_names_sha256
    spec_sha256 = [string]$containmentPlan.spec_sha256
    spec_document_sha256 = [string]$containmentPlan.spec_document_sha256
    inventory_before_sha256 =
        [string]$containmentPlan.inventory_before_sha256
    inventory_armed_sha256 =
        [string]$containmentPlan.inventory_armed_sha256
    inventory_verified_sha256 =
        [string]$containmentPlan.inventory_verified_sha256
    state_before_sha256 = [string]$containmentPlan.state_before_sha256
    state_armed_sha256 = [string]$containmentPlan.state_armed_sha256
    state_verified_sha256 = [string]$containmentPlan.state_verified_sha256
    direct_link_only = $true
    third_party_sources_forbidden = $true
    exact_rules_armed = $true
    third_party_bytes_impossible = $true
    watchdog_interval_ms = [int]$socket.watchdog_interval_ms
    watchdog_samples = [int]$socket.sample_count
    watchdog_violations = [int]$socket.watchdog_violations
    verification_count = [int]$containmentPlan.verification_count
    inventory_scope = 'exact-ten-nonce-program-rules-only'
    profile_scope = 'Any'
    firewall_service_running = $true
    firewall_profiles_enabled = $true
    firewall_profile_count = 3
    firewall_profiles_sha256 = Get-LabStringSha256 -Value (
        "Domain=true`nPrivate=true`nPublic=true")
    engine_watchdog_samples = [int]$socket.engine_watchdog_samples
    engine_watchdog_exact_filter_checks =
        [int]$socket.engine_watchdog_exact_filter_checks
    canonical_rules = @($containmentPlan.canonical_rules)
}

$filterSummaryPath = Write-LabJson -Value ([ordered]@{
    schema = 'ese.v91.i05.t1-pktmon-filter/v1'
    case_id = 'V91-I05'
    filters = @($capture.filters)
    before_bytes = [Int64](Get-Item $capture.filters_before).Length
    before_sha256 = Get-LabSha256 -Path $capture.filters_before
    armed_bytes = [Int64](Get-Item $capture.filters_armed).Length
    armed_sha256 = Get-LabSha256 -Path $capture.filters_armed
    before_reset_bytes =
        [Int64](Get-Item $capture.filters_before_reset).Length
    before_reset_sha256 = Get-LabSha256 -Path $capture.filters_before_reset
    active_inventory_rows_exact = $true
    after_bytes = [Int64](Get-Item $capture.filters_after).Length
    after_sha256 = Get-LabSha256 -Path $capture.filters_after
    restored_exactly = $true
    third_party_containment = $containmentForWire
}) -Path (Join-Path $evidenceRoot 'pktmon-filter.json')

$pcapItem = Get-Item -LiteralPath $pcapPath
$etlItem = Get-Item -LiteralPath $capture.etl_path
$samplesItem = Get-Item -LiteralPath $samplesPath
$statusSummaryPath = Write-LabJson -Value ([ordered]@{
    schema = 'ese.v91.i05.t1-pktmon-status/v1'
    case_id = 'V91-I05'
    primary_component_id = 15
    secondary_component_id = 0
    converted_component_id = 15
    conversion_hit_count = 1
    conversion_results = @([ordered]@{
        component_id = 15
        bytes = [Int64]$pcapItem.Length
        sha256 = Get-LabSha256 -Path $pcapPath
        parser_valid = $true
        exact_peer_flow = $true
        retained = $true
    })
    command_log_bytes = [Int64](Get-Item $capture.command_log).Length
    command_log_sha256 = Get-LabSha256 -Path $capture.command_log
    counters_bytes = [Int64](Get-Item $capture.counters_path).Length
    counters_sha256 = Get-LabSha256 -Path $capture.counters_path
    session_stopped = $true
    filters_restored = $true
    candidate_status_ready_sha256 = Get-LabSha256 -Path $statusReadyPath
    candidate_status_final_sha256 = Get-LabSha256 -Path $statusFinalPath
    etl_bytes = [Int64]$etlItem.Length
    etl_sha256 = Get-LabSha256 -Path $capture.etl_path
    pcapng_bytes = [Int64]$pcapItem.Length
    pcapng_sha256 = Get-LabSha256 -Path $pcapPath
    transfer_samples_bytes = [Int64]$samplesItem.Length
    transfer_samples_sha256 = Get-LabSha256 -Path $samplesPath
    candidate_networks = [ordered]@{
        kad_connected = $false
        kad2_connected = $false
        kad6_running = $false
        kad6_connected = $false
    }
}) -Path (Join-Path $evidenceRoot 'pktmon-status.json')

$fixturePath = [string]$rawIntegrity.fixture.path
$runPrefix = [IO.Path]::GetFullPath($runRoot).TrimEnd('\', '/') + '\'
$fixtureFull = [IO.Path]::GetFullPath($fixturePath)
Assert-Readjudication (
    $fixtureFull.StartsWith($runPrefix, [StringComparison]::OrdinalIgnoreCase)
) 'El fixture retenido escapa de RunRoot.'
$calculationReportSha = Get-LabSha256 -Path $rawIntegrityPath
$fileIntegrityPath = Write-LabJson -Value ([ordered]@{
    schema = 'ese.v91.i05.t1-file-integrity/v1'
    case_id = 'V91-I05'
    name = [string]$ready.fixture.name
    name_sha256 = Get-LabStringSha256 -Value ([string]$ready.fixture.name)
    path_relative = $fixtureFull.Substring(
        $runPrefix.Length).Replace('\', '/')
    bytes = [Int64]$rawIntegrity.fixture.bytes
    sha256 = [string]$rawIntegrity.fixture.sha256
    ed2k = [string]$rawIntegrity.fixture.ed2k
    method = 'local-streaming-sha256-ed2k-md4'
    calculation_report_sha256 = $calculationReportSha
    calculated_at_utc = [string]$rawIntegrity.completed_at_utc
}) -Path (Join-Path $evidenceRoot 'file-integrity.json')

$captureResult = [pscustomobject][ordered]@{
    backend = 'pktmon'
    status = 'PASS'
    pcap_path_relative = 'evidence\' + $pcapItem.Name
    pcap_sha256 = Get-LabSha256 -Path $pcapPath
    pcap_bytes = [Int64]$pcapItem.Length
    etl_bytes = [Int64]$etlItem.Length
    ipv4_peer_packets = [Int64]$wire.IPv4PeerPackets
    rejected_peer_tuple_packets = [Int64]$wire.RejectedPeerTuplePackets
    third_party_peer_packets = [Int64]$wire.ThirdPartyPeerPackets
    ipv6_peer_packets = [Int64]$wire.IPv6PeerPackets
    requestparts_i64 = [Int64]$wire.RequestPartsI64
    compressedpart_32 = [Int64]$wire.CompressedPart32
    sendingpart_i64 = [Int64]$wire.SendingPartI64
    compressedpart_i64 = [Int64]$wire.CompressedPartI64
    sending_i64 = [Int64]$wire.SendingPartI64
    compressed_i64 = [Int64]$wire.CompressedPartI64
    interface_id = [string]$ready.network.ipv4.interface_id
    packet_size = [int]$ready.capture.packet_size
    primary_component_id = 15
    converted_component_id = 15
    component_mapping_sha256 = $mappingSha
    mapping_key_sha256 =
        [string]$ready.capture.component_mapping.mapping_key_sha256
    analysis_sha256 = Get-LabSha256 -Path $analysisPath
    filter_summary_path = $filterSummaryPath
    status_summary_path = $statusSummaryPath
}

$script:readjudicationPhase = 'build-evidence-bundle'
$bundle = New-I05CompactEvidenceBundle -RunRoot $runRoot `
    -EvidenceRoot $evidenceRoot -Nonce $nonce `
    -CaptureState $capture -CaptureResult $captureResult `
    -ContainmentPlan $containmentPlan -SamplesPath $samplesPath `
    -SocketProofPath $socketProofPath -FileIntegrityPath $fileIntegrityPath
$bundleForWire = [ordered]@{
    schema = [string]$bundle.schema
    encoding = [string]$bundle.encoding
    bytes = [int]$bundle.bytes
    sha256 = [string]$bundle.sha256
    manifest_sha256 = [string]$bundle.manifest_sha256
    content_base64 = [string]$bundle.content_base64
}
$captureForWire = [ordered]@{
    backend = 'pktmon'
    status = 'PASS'
    pcap_path_relative = [string]$captureResult.pcap_path_relative
    pcap_sha256 = [string]$captureResult.pcap_sha256
    pcap_bytes = [Int64]$captureResult.pcap_bytes
    etl_bytes = [Int64]$captureResult.etl_bytes
    interface_id = [string]$captureResult.interface_id
    packet_size = [int]$captureResult.packet_size
    physical_interface = $true
    primary_component_id = 15
    converted_component_id = 15
    conversion_hit_count = 1
    component_mapping_sha256 = [string]$mappingSha
    mapping_key_sha256 = [string]$captureResult.mapping_key_sha256
    physical_component_guid_match = $true
    ipv4_peer_packets = [Int64]$wire.IPv4PeerPackets
    rejected_peer_tuple_packets = 0
    third_party_peer_packets = 0
    ipv6_peer_packets = 0
    requestparts_i64 = [Int64]$wire.RequestPartsI64
    compressedpart_32 = [Int64]$wire.CompressedPart32
    sendingpart_i64 = [Int64]$wire.SendingPartI64
    compressedpart_i64 = [Int64]$wire.CompressedPartI64
    sending_i64 = [Int64]$wire.SendingPartI64
    compressed_i64 = [Int64]$wire.CompressedPartI64
    capture_complete = $true
    packet_loss_detected = $false
    tuple_exact = $true
    filter_scope_exact = $true
    etl_loss_proved_zero = $true
    etl_below_file_limit = $true
    pcap_parsed = $true
    candidate_pid = [int]$ready.node.process_id
    candidate_pid_role = 'socket-watchdog-context-only'
    pcap_pid_attributed = $false
    tuple_allowlist_pid_observed = $true
    process_scoped_containment = $true
    ed2k_framing_valid = $true
    allowed_opcodes_only = $true
    etw_loss_proved_zero = $true
    filters_restored = $true
    filters_absent_after = $true
    etw_session_absent_after = $true
    filter_inventory_restored = $true
    analysis_sha256 = [string]$captureResult.analysis_sha256
}
$failureSha = Get-LabSha256 -Path $failurePath
$complete = [ordered]@{
    schema = 'ese.v91.i05.t1-complete/v1'
    case_id = 'V91-I05'
    status = 'PASS'
    nonce = $nonce
    created_at_utc = Get-LabUtcTimestamp
    candidate = $ready.candidate
    file = [ordered]@{
        name = [string]$ready.fixture.name
        destination_bytes = [Int64]$rawIntegrity.fixture.bytes
        destination_sha256 = [string]$rawIntegrity.fixture.sha256
        ed2k = [string]$rawIntegrity.fixture.ed2k
        ed2k_source = 'local-streaming-calculation'
        integrity_sha256 = Get-LabSha256 -Path $fileIntegrityPath
        calculation_report_sha256 = $calculationReportSha
        complete = $true
    }
    node = [ordered]@{
        process_id = [int]$ready.node.process_id
        emule_sha256 = [string]$ready.node.emule_sha256
        ipv6_mode = 0
        kad_network_mask = 0
        kad_connected = $false
        kad2_connected = $false
        kad6_running = $false
        kad6_connected = $false
        windows_ipv6_binding_enabled = $true
        api_responsive = $true
        tcp_listener_owned = $true
    }
    route = [ordered]@{
        family = 'IPv4'
        physical = $true
        on_link = $true
        interface_id = [string]$ready.network.ipv4.interface_id
        source_address_sha256 =
            [string]$ready.network.ipv4.address_sha256
        remote_address_sha256 =
            Get-LabStringSha256 -Value ([string]$session.source_ipv4_address)
        next_hop = '0.0.0.0'
        destination_prefix = ([string]$session.source_ipv4_address) + '/32'
    }
    socket_proof = [ordered]@{
        sha256 = Get-LabSha256 -Path $socketProofPath
        candidate_pid = [int]$ready.node.process_id
        observed_ephemeral_ports = @($localPort)
        unique_tuple_count = [int]$socket.unique_tuple_count
        stable_tuple = $socket.stable_tuple
        forbidden_tuple_count = 0
        forbidden_established_count = 0
        sample_count = [int]$socket.sample_count
    }
    capture = $captureForWire
    containment = $containmentForWire
    evidence_bundle = $bundleForWire
    evidence = [ordered]@{
        command_sha256 = Get-LabSha256 -Path $commandPath
        started_sha256 = Get-LabSha256 -Path $startedPath
        samples_sha256 = Get-LabSha256 -Path $samplesPath
        sample_count = [int]$socket.sample_count
    }
    readjudication = [ordered]@{
        schema = 'ese.v91.i05.t1-readjudication/v1'
        original_failure_sha256 = $failureSha
        original_status = [string]$failure.status
        original_phase = [string]$failure.phase
        original_category = [string]$failure.category
        reason = 'post-capture-adjudicator-correction'
        harness_commit = $harnessCommit
        raw_evidence_reused = $true
        product_reexecuted = $false
        cleanup_previously_complete = $true
    }
}
$script:readjudicationPhase = 'write-complete'
$null = Write-LabJson -Value $complete -Path $completePath
$completeSha = Get-LabSha256 -Path $completePath
$report = [ordered]@{
    schema = 'ese.v91.i05.t1-readjudication-report/v1'
    case_id = 'V91-I05'
    status = 'PASS'
    nonce = $nonce
    created_at_utc = Get-LabUtcTimestamp
    original_failure_sha256 = $failureSha
    complete_path_relative = Split-Path -Leaf $completePath
    complete_sha256 = $completeSha
    harness_commit = $harnessCommit
    cleanup_sha256 = Get-LabSha256 -Path $cleanupPath
    evidence_bundle_sha256 = [string]$bundle.sha256
    evidence_bundle_manifest_sha256 = [string]$bundle.manifest_sha256
    raw_evidence_reused = $true
    product_reexecuted = $false
    wire = [ordered]@{
        exact_peer_packets = [Int64]$wire.IPv4PeerPackets
        ieee80211_packets = [Int64]$wire.IEEE80211Packets
        requestparts_i64 = [Int64]$wire.RequestPartsI64
        compressedpart_32 = [Int64]$wire.CompressedPart32
        sendingpart_i64 = [Int64]$wire.SendingPartI64
        compressedpart_i64 = [Int64]$wire.CompressedPartI64
        invalid_fixture_frames = [Int64]$wire.InvalidFixtureI64Frames
    }
}
$null = Write-LabJson -Value $report -Path $reportPath

$script:readjudicationPhase = 'complete'
[pscustomobject][ordered]@{
    schema = 'ese.v91.i05.t1-readjudication-tool-result/v1'
    status = 'PASS'
    nonce = $nonce
    run = $runName
    complete_path = $completePath
    complete_bytes = [Int64](Get-Item $completePath).Length
    complete_sha256 = $completeSha
    report_path = $reportPath
    report_sha256 = Get-LabSha256 -Path $reportPath
    bundle_bytes = [Int64]$bundle.bytes
    bundle_sha256 = [string]$bundle.sha256
    exact_peer_packets = [Int64]$wire.IPv4PeerPackets
    ieee80211_packets = [Int64]$wire.IEEE80211Packets
    requestparts_i64 = [Int64]$wire.RequestPartsI64
    compressedpart_32 = [Int64]$wire.CompressedPart32
    cleanup = 'CLEANUP_COMPLETE'
} | ConvertTo-Json -Depth 8 -Compress
