[CmdletBinding()]
param(
    [string]$JobRequestPath = '',
    [switch]$SelfTest
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
. (Join-Path $PSScriptRoot 'v91_i07_common.ps1')

if ($SelfTest) {
    Invoke-I07SelfTest
    exit 0
}
if ([string]::IsNullOrWhiteSpace($JobRequestPath) -or
    -not (Test-Path -LiteralPath $JobRequestPath -PathType Leaf)) {
    throw 'JobRequestPath is required.'
}

$request = Get-Content -LiteralPath $JobRequestPath -Raw | ConvertFrom-Json
$wrapper = $request.PSObject.Properties['request']
if ($null -ne $wrapper) { $request = $wrapper.Value }
$jobRoot = Split-Path -Parent ([IO.Path]::GetFullPath($JobRequestPath))
$resultPath = Join-Path $jobRoot 'i07-result.json'
$progressPath = Join-Path $jobRoot 'progress.json'
$nodePath = Join-Path $jobRoot 'node'
$evidencePath = Join-Path $jobRoot 'evidence'
$cancelPath = Join-Path $jobRoot 'cancel-request.json'
$process = $null
$controlClient = $null
$controlListener = $null
$reader = $null
$writer = $null
$ruleNames = [Collections.Generic.List[string]]::new()
$ruleBindings = [Collections.Generic.List[object]]::new()
$phase = 'request_validation'
$status = 'LAB_BLOCKED'
$failureCategory = ''
$failureCode = ''
$topologyProven = $false
$candidate = $null
$packageFiles = @()
$zipEvidence = $null
$candidateStartedAt = $null
$controlEvidence = $null
$routeInitial = $null
$routeFinal = $null
$broadcastEvidence = $null
$joinEvidence = $null
$apiPeerEvidence = $null
$socketEvidence = $null
$playlistEvidence = $null
$profileEvidence = $null
$webContainmentEvidence = $null
$apiStatusInitial = $null
$apiStatusFinal = $null
$apiStatusInitialAt = $null
$apiStatusFinalAt = $null
$retainedEvidence = $null
$systemMutationTransaction = $null
$systemMutationPostcheck = $null
$processIdentity = $null
$launchBinding = $null
$processCleanupEvidence = $null
$streamKey = ''
$password = ''
$ownedFfmpeg = @()
$samples = [Collections.Generic.List[object]]::new()
$script:I07ProductFailureEvidence = $null
$cleanup = [ordered]@{
    process_stopped = $true
    firewall_removed = $true
    control_closed = $true
    broadcast_stopped = $true
    ffmpeg_children_gone = $true
    hls_removed = $true
    node_removed = $true
    evidence_retained = $false
    system_state_restored = $false
}

function Write-I07Progress {
    param(
        [Parameter(Mandatory = $true)][string]$CurrentPhase,
        [AllowNull()]$Detail = $null
    )
    Write-I07JsonAtomic -Path $progressPath -Value ([ordered]@{
        schema = 'ese.v91.i07-progress/v1'
        case_id = 'V91-I07'
        role = if ($null -ne $request.PSObject.Properties['role']) {
            [string]$request.role
        } else { '' }
        phase = $CurrentPhase
        updated_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
    })
}

function Throw-I07Lab {
    param([Parameter(Mandatory = $true)][string]$Message)
    throw "I07_LAB::$Message"
}

function Throw-I07Product {
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [ValidateSet(
            'SOURCE_START_INVARIANT',
            'VIEWER_START_INVARIANT',
            'SOURCE_SESSION_INVARIANT',
            'VIEWER_SESSION_INVARIANT',
            'API_INITIAL_UNRESPONSIVE',
            'API_INITIAL_ISOLATION_CONTRADICTION',
            'API_FINAL_UNRESPONSIVE',
            'API_FINAL_ISOLATION_CONTRADICTION')]
        [Parameter(Mandatory = $true)][string]$Code,
        [Parameter(Mandatory = $true)][string]$Reason,
        [AllowNull()]$Listener = $null,
        [AllowNull()]$ApiOperation = $null,
        [AllowNull()]$ProcessExit = $null,
        [AllowNull()]$SessionObservation = $null
    )
    $script:I07ProductFailureEvidence = [ordered]@{
        schema = 'ese.v91.i07-product-failure-evidence/v1'
        reason = $Reason
        observed_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
        listener = $Listener
        api_operation = $ApiOperation
        process_exit = $ProcessExit
        session_observation = $SessionObservation
    }
    throw "I07_PRODUCT::$Code::$Message"
}

function New-I07ApiOperationFailureEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$Operation,
        [Parameter(Mandatory = $true)][bool]$Available,
        [Parameter(Mandatory = $true)][bool]$ContractValid,
        [Parameter(Mandatory = $true)][bool]$Success,
        [Parameter(Mandatory = $true)][bool]$Ready
    )
    $safe = [ordered]@{
        operation = $Operation; available = $Available
        contract_valid = $ContractValid; success = $Success; ready = $Ready
    }
    $safeJson = $safe | ConvertTo-Json -Compress
    $bytes = [Text.Encoding]::UTF8.GetBytes($safeJson)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $digest = ([BitConverter]::ToString(
            $sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    } finally { $sha.Dispose() }
    return [ordered]@{
        operation = $Operation; available = $Available
        contract_valid = $ContractValid; success = $Success; ready = $Ready
        safe_response_sha256 = $digest; safe_response_bytes = $bytes.Length
    }
}

function New-I07SessionFailureEvidence {
    param(
        [Parameter(Mandatory = $true)][int]$SampleCount,
        [Parameter(Mandatory = $true)][DateTimeOffset]$ObservationStartedAt,
        [Parameter(Mandatory = $true)][DateTimeOffset]$DeadlineAt,
        [Parameter(Mandatory = $true)][bool]$SocketObserved,
        [Parameter(Mandatory = $true)][bool]$BroadcastingObserved,
        [Parameter(Mandatory = $true)][bool]$ApiPeerObserved,
        [Parameter(Mandatory = $true)][bool]$ViewingObserved,
        [Parameter(Mandatory = $true)][bool]$PlaylistObserved,
        [Parameter(Mandatory = $true)][bool]$SegmentObserved
    )
    return [ordered]@{
        sample_count = $SampleCount
        observation_started_at_utc = $ObservationStartedAt.ToString('o')
        deadline_at_utc = $DeadlineAt.ToString('o')
        socket_observed = $SocketObserved
        broadcasting_observed = $BroadcastingObserved
        api_peer_observed = $ApiPeerObserved
        viewing_observed = $ViewingObserved
        playlist_observed = $PlaylistObserved
        segment_observed = $SegmentObserved
    }
}

function Assert-I07ApiIsolationStatus {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][DateTimeOffset]$CapturedAt,
        [Parameter(Mandatory = $true)]
        [ValidateSet('initial', 'final')][string]$Sample
    )
    $summary = Get-I07ApiEvidenceSummary -Value $Value `
        -CapturedAt $CapturedAt
    if (-not [bool]$summary.contract_valid) {
        Throw-I07Lab 'Candidate API isolation contract is missing or malformed.'
    }
    if (-not [bool]$summary.isolation_invariant_satisfied) {
        Throw-I07Product `
            -Message 'Candidate violated the isolated-network API invariant.' `
            -Code $(if ($Sample -ceq 'initial') {
                'API_INITIAL_ISOLATION_CONTRADICTION'
            } else { 'API_FINAL_ISOLATION_CONTRADICTION' }) `
            -Reason 'API_ISOLATION_CONTRADICTION' `
            -ApiOperation (New-I07ApiOperationFailureEvidence `
                -Operation ("api_status_$Sample") -Available $true `
                -ContractValid $true -Success $false -Ready $false)
    }
    return $summary
}

function Assert-I07NotCancelled {
    if (Test-Path -LiteralPath $cancelPath -PathType Leaf) {
        Throw-I07Lab 'Cooperative cancellation was requested by the controller.'
    }
}

function Read-I07ControlLine {
    param(
        [Parameter(Mandatory = $true)][IO.StreamReader]$StreamReader,
        [ValidateRange(1, 300)][int]$TimeoutSeconds
    )
    $task = $StreamReader.ReadLineAsync()
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
    while (-not $task.IsCompleted -and
        [DateTimeOffset]::UtcNow -lt $deadline) {
        Assert-I07NotCancelled
        $null = $task.Wait(250)
    }
    if (-not $task.IsCompleted) {
        Throw-I07Lab "Control read timed out after $TimeoutSeconds seconds."
    }
    $line = [string]$task.Result
    if ([string]::IsNullOrWhiteSpace($line)) {
        Throw-I07Lab 'Control channel closed without a complete message.'
    }
    try { return $line | ConvertFrom-Json }
    catch { Throw-I07Lab 'Control channel returned malformed JSON.' }
}

function Write-I07ControlMessage {
    param(
        [Parameter(Mandatory = $true)][IO.StreamWriter]$StreamWriter,
        [Parameter(Mandatory = $true)]$Message
    )
    $StreamWriter.WriteLine(($Message | ConvertTo-Json -Depth 8 -Compress))
    $StreamWriter.Flush()
}

function Test-I07LocalPortAvailable {
    param(
        [ValidateSet('TCP', 'UDP')][string]$Protocol,
        [ValidateRange(1024, 65535)][int]$Port
    )
    if ($Protocol -ceq 'TCP') {
        return @(Get-NetTCPConnection -ErrorAction Stop | Where-Object {
                [int]$_.LocalPort -eq $Port
            }).Count -eq 0
    }
    return @(Get-NetUDPEndpoint -ErrorAction Stop | Where-Object {
            [int]$_.LocalPort -eq $Port
        }).Count -eq 0
}

function Start-I07CandidateProcess {
    param(
        [Parameter(Mandatory = $true)]$CandidateNode,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory
    )
    $arguments = @(
        '--portable', '--ignoreinstances', '--headless',
        "--metrics-port=$($CandidateNode.web_port)",
        "--tcp-port=$($CandidateNode.tcp_port)",
        "--udp-port=$($CandidateNode.udp_port)"
    )
    return Start-Process -FilePath ([string]$CandidateNode.exe_path) `
        -ArgumentList $arguments -WorkingDirectory $WorkingDirectory `
        -WindowStyle Hidden -PassThru
}

function Get-I07LiveDebug {
    param([ValidateRange(1024, 65535)][int]$Port)
    Invoke-RestMethod -Uri "http://127.0.0.1:$Port/api/live/debug" `
        -TimeoutSec 5
}

function Get-I07PrivacyPeers {
    param([ValidateRange(1024, 65535)][int]$Port)
    Invoke-RestMethod -Uri (
        "http://127.0.0.1:$Port/api/live/privacy/peers") -TimeoutSec 5
}

function Get-I07ExactNodeFfmpegProcesses {
    param([Parameter(Mandatory = $true)][string]$ExpectedPath)
    $fullPath = [IO.Path]::GetFullPath($ExpectedPath)
    return @(Get-CimInstance Win32_Process `
        -Filter "Name='ffmpeg.exe'" -ErrorAction Stop | Where-Object {
            -not [string]::IsNullOrWhiteSpace(
                [string]$_.ExecutablePath) -and
            [IO.Path]::GetFullPath([string]$_.ExecutablePath) -ieq $fullPath
        })
}

try {
    if (-not (Test-I07StrictString -Value $request.role) -or
        [string]$request.role -cnotin @('source', 'viewer')) {
        Throw-I07Lab 'The node request role is malformed.'
    }
    $requestRole = [string]$request.role
    $expectedRequestNames = @(
        'role', 'nonce', 'candidate_sha256', 'candidate_package_path',
        'candidate_commit', 'candidate_build_info_sha256',
        'candidate_zip_sha256', 'candidate_zip_bytes', 'candidate_zip_path',
        'package_files', 'disposable_lab_account_acknowledged',
        'expected_lab_user_sid_sha256',
        'local_ipv6', 'peer_ipv6', 'interface_index',
        'interface_guid', 'tcp_port', 'udp_port', 'web_port',
        'peer_tcp_port', 'control_port', 'duration_seconds')
    if ($requestRole -ceq 'viewer') {
        $expectedRequestNames += @(
            'hotspot_wlan_profile_sha256',
            'hotspot_connection_profile_sha256')
    }
    $requestGuid = [Guid]::Empty
    if (-not (Test-I07ExactPropertySet -Value $request `
            -Expected $expectedRequestNames) -or
        -not (Test-I07StrictString -Value $request.nonce) -or
        [string]$request.nonce -cnotmatch '^[0-9a-f]{32}$' -or
        -not (Test-I07StrictString -Value $request.candidate_sha256) -or
        [string]$request.candidate_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        -not (Test-I07StrictString `
            -Value $request.candidate_package_path) -or
        -not (Test-I07StrictString -Value $request.candidate_commit) -or
        [string]$request.candidate_commit -cnotmatch '^[0-9a-f]{40}$' -or
        -not (Test-I07StrictString `
            -Value $request.candidate_build_info_sha256) -or
        [string]$request.candidate_build_info_sha256 -cnotmatch
            '^[0-9a-f]{64}$' -or
        -not (Test-I07StrictString -Value $request.candidate_zip_sha256) -or
        [string]$request.candidate_zip_sha256 -cnotmatch
            '^[0-9a-f]{64}$' -or
        -not (Test-I07StrictInteger -Value $request.candidate_zip_bytes `
            -Minimum 1) -or
        -not (Test-I07StrictString -Value $request.candidate_zip_path) -or
        -not ($request.package_files -is [Array]) -or
        -not (Test-I07StrictBoolean `
            -Value $request.disposable_lab_account_acknowledged) -or
        -not [bool]$request.disposable_lab_account_acknowledged -or
        -not (Test-I07StrictString `
            -Value $request.expected_lab_user_sid_sha256) -or
        [string]$request.expected_lab_user_sid_sha256 -cnotmatch
            '^[0-9a-f]{64}$' -or
        -not (Test-I07StrictString -Value $request.local_ipv6) -or
        -not (Test-I07StrictString -Value $request.peer_ipv6) -or
        -not (Test-I07StrictInteger -Value $request.interface_index `
            -Minimum 1) -or
        -not (Test-I07StrictString -Value $request.interface_guid) -or
        -not [Guid]::TryParse([string]$request.interface_guid,
            [ref]$requestGuid) -or $requestGuid -eq [Guid]::Empty -or
        -not (Test-I07StrictInteger -Value $request.duration_seconds `
            -Minimum 15 -Maximum 180)) {
        Throw-I07Lab 'The node request shape or scalar types are invalid.'
    }
    foreach ($portName in @(
            'tcp_port', 'udp_port', 'web_port', 'peer_tcp_port',
            'control_port')) {
        if (-not (Test-I07StrictInteger -Value $request.$portName `
                -Minimum 1024 -Maximum 65535)) {
            Throw-I07Lab 'The node request contains a non-integer port.'
        }
    }
    try {
        $null = Assert-I07CriticalPackageContract `
            -Files @($request.package_files)
    } catch { Throw-I07Lab $_.Exception.Message }
    if ($requestRole -ceq 'viewer' -and (
            -not (Test-I07StrictString `
                -Value $request.hotspot_wlan_profile_sha256) -or
            [string]$request.hotspot_wlan_profile_sha256 -cnotmatch
                '^[0-9a-f]{64}$' -or
            -not (Test-I07StrictString `
                -Value $request.hotspot_connection_profile_sha256) -or
            [string]$request.hotspot_connection_profile_sha256 -cnotmatch
                '^[0-9a-f]{64}$')) {
        Throw-I07Lab 'The viewer hotspot fingerprints are malformed.'
    }
    $role = ([string]$request.role).ToLowerInvariant()
    if ($role -cnotin @('source', 'viewer')) {
        Throw-I07Lab "Invalid role '$role'."
    }
    $nonce = ([string]$request.nonce).ToLowerInvariant()
    $candidateSha = ([string]$request.candidate_sha256).ToLowerInvariant()
    if ($nonce -notmatch '^[0-9a-f]{32}$' -or
        $candidateSha -notmatch '^[0-9a-f]{64}$') {
        Throw-I07Lab 'The nonce or candidate SHA-256 contract is invalid.'
    }
    $localIPv6 = ConvertTo-I07CanonicalIPv6 `
        -Value ([string]$request.local_ipv6) -Context 'local_ipv6'
    $peerIPv6 = ConvertTo-I07CanonicalIPv6 `
        -Value ([string]$request.peer_ipv6) -Context 'peer_ipv6'
    if ((Get-I07IPv6Class ([Net.IPAddress]::Parse($localIPv6))) -cne
        'global-native' -or
        (Get-I07IPv6Class ([Net.IPAddress]::Parse($peerIPv6))) -cne
        'global-native') {
        Throw-I07Lab 'Both fixed endpoints must be native global IPv6.'
    }
    $interfaceIndex = [int]$request.interface_index
    $interfaceGuid = [string]$request.interface_guid
    $tcpPort = [int]$request.tcp_port
    $udpPort = [int]$request.udp_port
    $webPort = [int]$request.web_port
    $peerTcpPort = [int]$request.peer_tcp_port
    $controlPort = [int]$request.control_port
    $durationSeconds = [int]$request.duration_seconds
    $ports = @($tcpPort, $udpPort, $webPort, $peerTcpPort, $controlPort)
    if ($interfaceIndex -le 0 -or
        [string]::IsNullOrWhiteSpace($interfaceGuid) -or
        -not (Test-I07PortContract -Ports $ports)) {
        Throw-I07Lab 'Interface or port contract is invalid.'
    }
    if ($durationSeconds -lt 15 -or $durationSeconds -gt 180) {
        Throw-I07Lab 'duration_seconds must be between 15 and 180.'
    }
    $candidatePackagePath = [IO.Path]::GetFullPath(
        [string]$request.candidate_package_path)
    $candidateCommit = ([string]$request.candidate_commit).ToLowerInvariant()
    $buildInfoSha =
        ([string]$request.candidate_build_info_sha256).ToLowerInvariant()
    $candidateZipSha =
        ([string]$request.candidate_zip_sha256).ToLowerInvariant()
    $candidateZipBytes = [Int64]$request.candidate_zip_bytes
    try {
        $packageFiles = @(Assert-I07CriticalPackageContract `
            -Files @($request.package_files))
    } catch { Throw-I07Lab $_.Exception.Message }
    $candidateZipPath = [IO.Path]::GetFullPath(
        [string]$request.candidate_zip_path)
    if ($candidateCommit -notmatch '^[0-9a-f]{40}$' -or
        $buildInfoSha -notmatch '^[0-9a-f]{64}$' -or
        $candidateZipSha -notmatch '^[0-9a-f]{64}$' -or
        $candidateZipBytes -le 0) {
        Throw-I07Lab 'The exact candidate package contract is incomplete.'
    }
    try {
        $zipEvidence = Get-I07CriticalZipEvidence `
            -ZipPath $candidateZipPath -ExpectedFiles $packageFiles `
            -ExpectedZipSha256 $candidateZipSha `
            -ExpectedZipBytes $candidateZipBytes
    } catch { Throw-I07Lab $_.Exception.Message }

    try {
        $systemMutationTransaction = Start-I07SystemMutationTransaction `
            -DisposableAccountAcknowledged (
                [bool]$request.disposable_lab_account_acknowledged) `
            -ExpectedUserSidSha256 (
                [string]$request.expected_lab_user_sid_sha256)
    } catch { Throw-I07Lab $_.Exception.Message }

    Write-I07Progress -CurrentPhase 'preflight_starting'
    if (@(Get-CimInstance Win32_Process -Filter "Name='emule.exe'" `
            -ErrorAction Stop).Count -gt 0) {
        Throw-I07Lab 'A pre-existing eMule process would contaminate I07.'
    }
    foreach ($portCheck in @(
        @('TCP', $tcpPort), @('TCP', $webPort), @('UDP', $udpPort)
    )) {
        if (-not (Test-I07LocalPortAvailable -Protocol $portCheck[0] `
                -Port ([int]$portCheck[1]))) {
            Throw-I07Lab "$($portCheck[0]) port $($portCheck[1]) is busy."
        }
    }
    if ($role -ceq 'source' -and
        -not (Test-I07LocalPortAvailable -Protocol TCP -Port $controlPort)) {
        Throw-I07Lab "TCP control port $controlPort is busy."
    }

    $routeInitial = Get-I07NativeRouteEvidence -RemoteIPv6 $peerIPv6 `
        -ExpectedInterfaceIndex $interfaceIndex `
        -ExpectedSourceIPv6 $localIPv6 `
        -ExpectedInterfaceGuid $interfaceGuid
    if (-not [bool]$routeInitial.valid) {
        Throw-I07Lab "Exact peer route is not native: $($routeInitial.reason)."
    }
    if ($role -ceq 'viewer') {
        $media = @(
            [string]$routeInitial.media_type,
            [string]$routeInitial.physical_media_type,
            [string]$routeInitial.interface_description
        ) -join ' '
        if ($media -notmatch '(?i)802\.11|wi-?fi|wireless') {
            Throw-I07Lab 'The mobile viewer route is not on a physical Wi-Fi adapter.'
        }
        $expectedProfile = (
            [string]$request.hotspot_connection_profile_sha256
        ).ToLowerInvariant()
        if ($expectedProfile -notmatch '^[0-9a-f]{64}$') {
            Throw-I07Lab 'R01 hotspot profile fingerprint is missing from I07.'
        }
        try {
            $connectionProfileEvidence = Get-I07NetworkProfileEvidence `
                -InterfaceIndex $interfaceIndex
            $wlanProfileEvidence = Get-I07CurrentWlanProfileEvidence `
                -InterfaceIndex $interfaceIndex
        } catch { Throw-I07Lab $_.Exception.Message }
        $expectedWlanProfile = (
            [string]$request.hotspot_wlan_profile_sha256
        ).ToLowerInvariant()
        if ($expectedWlanProfile -notmatch '^[0-9a-f]{64}$' -or
            [string]$connectionProfileEvidence.profile_sha256 -cne
                $expectedProfile -or
            [string]$wlanProfileEvidence.wlan_profile_sha256 -cne
                $expectedWlanProfile -or
            ([string]$connectionProfileEvidence.interface_guid).Trim('{}') `
                -ine $interfaceGuid.Trim('{}') -or
            ([string]$wlanProfileEvidence.interface_guid).Trim('{}') -ine
                $interfaceGuid.Trim('{}')) {
            Throw-I07Lab 'The viewer is not on the R01-qualified hotspot profile.'
        }
        $profileEvidence = [pscustomobject][ordered]@{
            connection_profile = $connectionProfileEvidence
            wlan_profile = $wlanProfileEvidence
        }
    }
    $password = [Guid]::NewGuid().ToString('N')
    try {
        $candidate = New-I07CandidateNode `
            -PackagePath $candidatePackagePath `
            -ExpectedSha256 $candidateSha `
            -ExpectedPackageFiles $packageFiles -NodePath $nodePath `
            -Role $role `
            -BindIPv6 $localIPv6 -TcpPort $tcpPort -UdpPort $udpPort `
            -WebPort $webPort -Password $password
    } catch {
        Throw-I07Lab $_.Exception.Message
    }
    try {
        if (@(Get-I07ExactNodeFfmpegProcesses -ExpectedPath (
                Join-Path $nodePath 'ffmpeg.exe')).Count -ne 0) {
            Throw-I07Lab 'A pre-candidate FFmpeg already owns the nonce node path.'
        }
    } catch {
        if ([string]$_.Exception.Message -like 'I07_LAB::*') { throw }
        Throw-I07Lab "Could not establish the FFmpeg baseline: $($_.Exception.Message)"
    }
    $buildInfoPath = Join-Path $candidate.package_path 'BUILD_INFO.txt'
    $buildValues = @{}
    foreach ($line in Get-Content -LiteralPath $buildInfoPath) {
        if ($line -match '^\s*([^:]+):\s*(.*?)\s*$') {
            $buildValues[$Matches[1].Trim().ToLowerInvariant()] =
                $Matches[2].Trim()
        }
    }
    if ([string]$buildValues['commit'] -ine $candidateCommit -or
        [string]$buildValues['dirty'] -cne 'false' -or
        (Get-FileHash -LiteralPath $buildInfoPath -Algorithm SHA256).Hash `
            -ine $buildInfoSha) {
        Throw-I07Lab 'Remote package BUILD_INFO does not match the clean candidate.'
    }
    Write-I07Progress -CurrentPhase 'candidate_verified' -Detail $candidate

    $webBlockRule = "eSE-V91-I07-web-block-$nonce-$role"
    $webRuleBinding = [pscustomobject]@{
        name = $webBlockRule
        tuple = [pscustomobject]@{
            action = 'Block'; direction = 'Inbound'; protocol = 'TCP'
            local_port = [string]$webPort
            local_address = @('Any'); remote_address = @('Any')
            program = [string]$candidate.exe_path
            interface_alias = @('Any')
        }
        snapshot = $null
    }
    $ruleBindings.Add($webRuleBinding)
    try {
        New-NetFirewallRule -Name $webBlockRule -DisplayName $webBlockRule `
            -Direction Inbound -Action Block -Protocol TCP `
            -LocalPort $webPort -LocalAddress Any -RemoteAddress Any `
            -Program ([string]$candidate.exe_path) `
            -Profile Any -Enabled True |
            Out-Null
        $ruleNames.Add($webBlockRule)
        $webRuleBinding.snapshot = Get-I07BoundFirewallRuleSnapshot `
            -Name $webBlockRule -ExpectedAction Block `
            -ExpectedDirection Inbound -ExpectedProtocol TCP `
            -ExpectedLocalPort ([string]$webPort) `
            -ExpectedLocalAddress @('Any') -ExpectedRemoteAddress @('Any') `
            -ExpectedProgram ([string]$candidate.exe_path) `
            -ExpectedInterfaceAlias @('Any')
        $rule = Get-NetFirewallRule -Name $webBlockRule -ErrorAction Stop
        $portFilter = $rule | Get-NetFirewallPortFilter
        $appFilter = $rule | Get-NetFirewallApplicationFilter
        $addressFilter = $rule | Get-NetFirewallAddressFilter
        if ([string]$rule.Action -cne 'Block' -or
            [string]$rule.Enabled -cne 'True' -or
            [string]$rule.Direction -cne 'Inbound' -or
            [string]$rule.Profile -cne 'Any' -or
            [string]$portFilter.Protocol -cne 'TCP' -or
            [string]$portFilter.LocalPort -cne [string]$webPort -or
            [string]$addressFilter.LocalAddress -cne 'Any' -or
            [string]$addressFilter.RemoteAddress -cne 'Any' -or
            [string]$appFilter.Program -ine [string]$candidate.exe_path) {
            throw 'Web/API firewall containment could not be verified.'
        }
        $webContainmentEvidence = [pscustomobject][ordered]@{
            rule_name = $webBlockRule
            direction = [string]$rule.Direction
            action = [string]$rule.Action
            enabled = [string]$rule.Enabled
            profile = [string]$rule.Profile
            protocol = [string]$portFilter.Protocol
            local_port = [int]$portFilter.LocalPort
            local_address = [string]$addressFilter.LocalAddress
            remote_address = [string]$addressFilter.RemoteAddress
            program_leaf = [IO.Path]::GetFileName(
                [string]$appFilter.Program)
            program_matches_candidate =
                [string]$appFilter.Program -ieq [string]$candidate.exe_path
            blocks_physical_ipv4_and_ipv6 = $true
        }
    } catch {
        Throw-I07Lab "Could not contain the candidate Web/API port: $($_.Exception.Message)"
    }

    if ($role -ceq 'source') {
        $controlRule = "eSE-V91-I07-control-$nonce"
        $candidateRule = "eSE-V91-I07-candidate-$nonce"
        $controlRuleBinding = [pscustomobject]@{
            name = $controlRule
            tuple = [pscustomobject]@{
                action = 'Allow'; direction = 'Inbound'; protocol = 'TCP'
                local_port = [string]$controlPort
                local_address = @("$localIPv6/128")
                remote_address = @("$peerIPv6/128")
                program = 'Any'
                interface_alias = @([string]$routeInitial.interface_alias)
            }
            snapshot = $null
        }
        $candidateRuleBinding = [pscustomobject]@{
            name = $candidateRule
            tuple = [pscustomobject]@{
                action = 'Allow'; direction = 'Inbound'; protocol = 'TCP'
                local_port = [string]$tcpPort
                local_address = @("$localIPv6/128")
                remote_address = @("$peerIPv6/128")
                program = [string]$candidate.exe_path
                interface_alias = @([string]$routeInitial.interface_alias)
            }
            snapshot = $null
        }
        $ruleBindings.Add($controlRuleBinding)
        $ruleBindings.Add($candidateRuleBinding)
        try {
            New-NetFirewallRule -Name $controlRule -DisplayName $controlRule `
                -Direction Inbound -Action Allow -Protocol TCP `
                -LocalPort $controlPort -LocalAddress "$localIPv6/128" `
                -RemoteAddress "$peerIPv6/128" `
                -InterfaceAlias ([string]$routeInitial.interface_alias) |
                Out-Null
            $ruleNames.Add($controlRule)
            $controlRuleBinding.snapshot =
                Get-I07BoundFirewallRuleSnapshot -Name $controlRule `
                    -ExpectedAction Allow -ExpectedDirection Inbound `
                    -ExpectedProtocol TCP `
                    -ExpectedLocalPort ([string]$controlPort) `
                    -ExpectedLocalAddress @("$localIPv6/128") `
                    -ExpectedRemoteAddress @("$peerIPv6/128") `
                    -ExpectedProgram Any `
                    -ExpectedInterfaceAlias @(
                        [string]$routeInitial.interface_alias)
            New-NetFirewallRule -Name $candidateRule `
                -DisplayName $candidateRule -Direction Inbound `
                -Action Allow -Protocol TCP -LocalPort $tcpPort `
                -LocalAddress "$localIPv6/128" `
                -RemoteAddress "$peerIPv6/128" `
                -InterfaceAlias ([string]$routeInitial.interface_alias) `
                -Program ([string]$candidate.exe_path) | Out-Null
            $ruleNames.Add($candidateRule)
            $candidateRuleBinding.snapshot =
                Get-I07BoundFirewallRuleSnapshot -Name $candidateRule `
                    -ExpectedAction Allow -ExpectedDirection Inbound `
                    -ExpectedProtocol TCP `
                    -ExpectedLocalPort ([string]$tcpPort) `
                    -ExpectedLocalAddress @("$localIPv6/128") `
                    -ExpectedRemoteAddress @("$peerIPv6/128") `
                    -ExpectedProgram ([string]$candidate.exe_path) `
                    -ExpectedInterfaceAlias @(
                        [string]$routeInitial.interface_alias)
        } catch {
            Throw-I07Lab "Could not install nonce-owned firewall rules: $($_.Exception.Message)"
        }

        $controlListener = [Net.Sockets.TcpListener]::new(
            [Net.IPAddress]::Parse($localIPv6), $controlPort)
        $controlListener.Start(1)
        Write-I07Progress -CurrentPhase 'native_control_listening' `
            -Detail ([ordered]@{
                local_ipv6 = $localIPv6
                port = $controlPort
                interface_guid = $interfaceGuid
            })
        $accept = $controlListener.BeginAcceptTcpClient($null, $null)
        $acceptDeadline = [DateTimeOffset]::UtcNow.AddSeconds(180)
        while (-not $accept.IsCompleted -and
            [DateTimeOffset]::UtcNow -lt $acceptDeadline) {
            Assert-I07NotCancelled
            $null = $accept.AsyncWaitHandle.WaitOne(500)
        }
        if (-not $accept.IsCompleted) {
            Throw-I07Lab 'The mobile peer could not reach the native control listener.'
        }
        $controlClient = $controlListener.EndAcceptTcpClient($accept)
        $controlClient.ReceiveTimeout = 180000
        $controlClient.SendTimeout = 30000
        $localEndpoint = [Net.IPEndPoint]$controlClient.Client.LocalEndPoint
        $remoteEndpoint = [Net.IPEndPoint]$controlClient.Client.RemoteEndPoint
        $controlLocal = ConvertTo-I07CanonicalIPv6 `
            -Value $localEndpoint.Address.ToString()
        $controlRemote = ConvertTo-I07CanonicalIPv6 `
            -Value $remoteEndpoint.Address.ToString()
        if ($controlLocal -cne $localIPv6 -or $controlRemote -cne $peerIPv6) {
            Throw-I07Lab 'Native control endpoints did not match the fixed topology.'
        }
        $reader = [IO.StreamReader]::new(
            $controlClient.GetStream(), [Text.UTF8Encoding]::new($false),
            $false, 1024, $true)
        $writer = [IO.StreamWriter]::new(
            $controlClient.GetStream(), [Text.UTF8Encoding]::new($false),
            1024, $true)
        $writer.NewLine = "`n"
        $hello = Read-I07ControlLine -StreamReader $reader -TimeoutSeconds 30
        if ([string]$hello.schema -cne 'ese.v91.i07-control-hello/v1' -or
            [string]$hello.nonce -cne $nonce -or
            [string]$hello.candidate_sha256 -cne $candidateSha -or
            (ConvertTo-I07CanonicalIPv6 -Value ([string]$hello.viewer_ipv6)) `
                -cne $peerIPv6) {
            Throw-I07Lab 'Native control hello did not match the campaign contract.'
        }
        Write-I07ControlMessage -StreamWriter $writer -Message ([ordered]@{
            schema = 'ese.v91.i07-control-ack/v1'
            nonce = $nonce
            source_ipv6 = $localIPv6
            observed_viewer_ipv6 = $controlRemote
        })
        $ack = Read-I07ControlLine -StreamReader $reader -TimeoutSeconds 30
        if ([string]$ack.schema -cne 'ese.v91.i07-control-ack-ok/v1' -or
            [string]$ack.nonce -cne $nonce) {
            Throw-I07Lab 'Bidirectional native control acknowledgement failed.'
        }
        $topologyProven = $true
        $controlEvidence = [ordered]@{
            bidirectional = $true
            proven_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
            local_address = $controlLocal
            local_port = [int]$localEndpoint.Port
            remote_address = $controlRemote
            remote_port = [int]$remoteEndpoint.Port
        }
        Write-I07Progress -CurrentPhase 'native_path_proven' `
            -Detail $controlEvidence

        $phase = 'source_candidate_start'
        try {
            $launchBinding = Get-I07PreparedNodeLaunchBinding `
                -CandidateNode $candidate `
                -ExpectedPackageFiles $packageFiles
            $process = Start-I07CandidateProcess -CandidateNode $candidate `
                -WorkingDirectory $nodePath
            $processIdentity = Get-I07ProcessIdentity -Process $process `
                -ExpectedPath ([string]$candidate.exe_path) `
                -ExpectedFileSha256 $candidateSha `
                -ExpectedUserSidSha256 (
                    [string]$request.expected_lab_user_sid_sha256)
        } catch { Throw-I07Lab "Candidate launch failed: $($_.Exception.Message)" }
        $candidateStartedAt = [DateTimeOffset]::Parse(
            [string]$processIdentity.start_time_utc)
        try {
            $apiStatusInitial = Wait-I07Api -Process $process -Port $webPort `
                -CancellationCheck { Assert-I07NotCancelled }
            $apiStatusInitialAt = [DateTimeOffset]::UtcNow
            $null = Assert-I07ApiIsolationStatus -Value $apiStatusInitial `
                -CapturedAt $apiStatusInitialAt -Sample initial
        } catch {
            $apiWaitMessage = [string]$_.Exception.Message
            if ($apiWaitMessage.StartsWith('I07_LAB::',
                    [StringComparison]::Ordinal) -or
                $apiWaitMessage.StartsWith('I07_PRODUCT::',
                    [StringComparison]::Ordinal)) {
                throw $apiWaitMessage
            }
            Throw-I07Product -Message $apiWaitMessage `
                -Code API_INITIAL_UNRESPONSIVE `
                -Reason 'API_STATUS_UNRESPONSIVE' `
                -ApiOperation (New-I07ApiOperationFailureEvidence `
                    -Operation 'api_status_initial' -Available $false `
                    -ContractValid $false -Success $false -Ready $false)
        }
        $listenerRows = @(Get-NetTCPConnection -ErrorAction Stop |
            Where-Object {
                [int]$_.OwningProcess -eq [int]$process.Id -and
                [string]$_.State -ceq 'Listen' -and
                [int]$_.LocalPort -eq $tcpPort -and
                ([string]$_.LocalAddress).Contains(':')
            })
        if ($listenerRows.Count -lt 1) {
            Throw-I07Product `
                -Message 'Source candidate did not expose its IPv6 peer listener.' `
                -Code SOURCE_START_INVARIANT -Reason 'LISTENER_MISSING' `
                -Listener ([ordered]@{
                    candidate_pid = [int]$process.Id
                    expected_port = $tcpPort
                    ipv6_listener_count = [int]$listenerRows.Count
                })
        }
        try {
            $broadcast = Invoke-RestMethod -Uri (
                "http://127.0.0.1:$webPort/api/live/broadcast/start" +
                '?source=testpattern&title=V91-I07-T3&bitrate=4000'
            ) -TimeoutSec 30
        } catch {
            Throw-I07Product -Message ([string]$_.Exception.Message) `
                -Code SOURCE_START_INVARIANT `
                -Reason 'BROADCAST_API_UNRESPONSIVE' `
                -ApiOperation (New-I07ApiOperationFailureEvidence `
                    -Operation 'broadcast_start' -Available $false `
                    -ContractValid $false -Success $false -Ready $false)
        }
        if (-not (Test-I07StrictBoolean -Value $broadcast.success) -or
            -not (Test-I07StrictBoolean -Value $broadcast.ready) -or
            -not (Test-I07StrictString -Value $broadcast.link)) {
            Throw-I07Product `
                -Message 'Source broadcast API returned malformed types.' `
                -Code SOURCE_START_INVARIANT `
                -Reason 'BROADCAST_API_MALFORMED' `
                -ApiOperation (New-I07ApiOperationFailureEvidence `
                    -Operation 'broadcast_start' -Available $true `
                    -ContractValid $false -Success $false -Ready $false)
        }
        $keyMatch = [regex]::Match(
            [string]$broadcast.link, '\|live\|([0-9A-Fa-f]{32})\|')
        if (-not $keyMatch.Success) {
            Throw-I07Product `
                -Message 'Source broadcast API returned a malformed link.' `
                -Code SOURCE_START_INVARIANT `
                -Reason 'BROADCAST_API_MALFORMED' `
                -ApiOperation (New-I07ApiOperationFailureEvidence `
                    -Operation 'broadcast_start' -Available $true `
                    -ContractValid $false -Success $false -Ready $false)
        }
        if (-not [bool]$broadcast.success -or -not [bool]$broadcast.ready) {
            Throw-I07Product `
                -Message 'Source candidate did not create a ready LiveTV stream.' `
                -Code SOURCE_START_INVARIANT -Reason 'BROADCAST_NOT_READY' `
                -ApiOperation (New-I07ApiOperationFailureEvidence `
                    -Operation 'broadcast_start' -Available $true `
                    -ContractValid $true -Success ([bool]$broadcast.success) `
                    -Ready ([bool]$broadcast.ready))
        }
        $streamKey = $keyMatch.Groups[1].Value.ToLowerInvariant()
        Start-Sleep -Milliseconds 500
        $ownedFfmpeg = @(Get-CimInstance Win32_Process `
            -Filter "ParentProcessId=$($process.Id)" `
            -ErrorAction Stop | Where-Object {
                [string]$_.Name -ieq 'ffmpeg.exe' -and
                [string]$_.ExecutablePath -ieq (
                    Join-Path $nodePath 'ffmpeg.exe')
            } | ForEach-Object {
                [ordered]@{
                    pid = [int]$_.ProcessId
                    parent_pid = [int]$_.ParentProcessId
                    executable_path = [string]$_.ExecutablePath
                    creation_date = [string]$_.CreationDate
                }
            })
        if ($ownedFfmpeg.Count -ne 1) {
            Throw-I07Lab 'The source did not expose exactly one nonce-owned FFmpeg child.'
        }
        $broadcastEvidence = [ordered]@{
            success = [bool]$broadcast.success
            ready = [bool]$broadcast.ready
            stream_key_sha256 = (
                [BitConverter]::ToString(
                    [Security.Cryptography.SHA256]::Create().ComputeHash(
                        [Text.Encoding]::UTF8.GetBytes($streamKey)
                    )).Replace('-', '').ToLowerInvariant())
        }
        Write-I07ControlMessage -StreamWriter $writer -Message ([ordered]@{
            schema = 'ese.v91.i07-source-ready/v1'
            nonce = $nonce
            candidate_sha256 = $candidateSha
            source_ipv6 = $localIPv6
            source_tcp_port = $tcpPort
            stream_key = $streamKey
        })
        Write-I07Progress -CurrentPhase 'source_ready'

        $phase = 'source_direct_session'
        $completionTask = $reader.ReadLineAsync()
        $sessionStartedAt = [DateTimeOffset]::MinValue
        $deadline = [DateTimeOffset]::MaxValue
        $socketSeen = $false
        $broadcastSeen = $false
        do {
            Assert-I07NotCancelled
            $process.Refresh()
            if ($process.HasExited) {
                Throw-I07Product `
                    -Message "Source candidate exited with code $($process.ExitCode)." `
                    -Code SOURCE_SESSION_INVARIANT `
                    -Reason 'CANDIDATE_EXITED' `
                    -ProcessExit ([ordered]@{
                        candidate_pid = [int]$process.Id
                        process_alive = $false
                    })
            }
            try {
                $debug = Get-I07LiveDebug -Port $webPort
                $broadcasting =
                    (Test-I07StrictBoolean -Value $debug.broadcasting) -and
                    [bool]$debug.broadcasting
            } catch { $broadcasting = $false }
            $socket = Get-I07CandidateSocketEvidence `
                -ProcessId $process.Id -LocalIPv6 $localIPv6 `
                -PeerIPv6 $peerIPv6 -ExpectedInterfaceGuid $interfaceGuid `
                -PeerTcpPort $peerTcpPort -LocalTcpPort $tcpPort `
                -Role source
            if ([bool]$socket.observed) {
                $socketSeen = $true
                $socketEvidence = $socket
            }
            if ($broadcasting) { $broadcastSeen = $true }
            $sampleAt = [DateTimeOffset]::UtcNow
            if ($sessionStartedAt -eq [DateTimeOffset]::MinValue) {
                $sessionStartedAt = $sampleAt
                $deadline = $sessionStartedAt.AddSeconds(
                    $durationSeconds + 60)
            }
            $samples.Add([ordered]@{
                at_utc = $sampleAt.ToString('o')
                process_alive = $true
                broadcasting = $broadcasting
                peer_socket = [bool]$socket.observed
            })
            Write-I07Progress -CurrentPhase 'source_direct_session' `
                -Detail $samples[$samples.Count - 1]
            if ($completionTask.IsCompleted -and $socketSeen -and
                $broadcastSeen) { break }
            Start-Sleep -Seconds 1
        } while ([DateTimeOffset]::UtcNow -lt $deadline)
        if (-not $completionTask.IsCompleted) {
            Throw-I07Lab 'Viewer completion message did not arrive.'
        }
        $completionLine = [string]$completionTask.Result
        try { $completion = $completionLine | ConvertFrom-Json }
        catch { Throw-I07Lab 'Viewer completion message was malformed.' }
        if ([string]$completion.schema -cne
                'ese.v91.i07-viewer-complete/v1' -or
            [string]$completion.nonce -cne $nonce) {
            Throw-I07Lab 'Viewer completion message did not match the campaign.'
        }
        if ([string]$completion.status -cne 'PASS') {
            Throw-I07Lab `
                'The paired viewer reported that its direct route was not proven.'
        }
        if (-not $socketSeen) {
            Throw-I07Product `
                -Message 'Source PID never owned the exact inbound IPv6 peer socket.' `
                -Code SOURCE_SESSION_INVARIANT -Reason 'SOCKET_NOT_OBSERVED' `
                -SessionObservation (New-I07SessionFailureEvidence `
                    -SampleCount $samples.Count `
                    -ObservationStartedAt $sessionStartedAt `
                    -DeadlineAt $deadline -SocketObserved $socketSeen `
                    -BroadcastingObserved $broadcastSeen `
                    -ApiPeerObserved $false -ViewingObserved $false `
                    -PlaylistObserved $false -SegmentObserved $false)
        }
        if (-not $broadcastSeen) {
            Throw-I07Product `
                -Message 'Source LiveTV state was not observable during the session.' `
                -Code SOURCE_SESSION_INVARIANT `
                -Reason 'BROADCAST_NOT_OBSERVED' `
                -SessionObservation (New-I07SessionFailureEvidence `
                    -SampleCount $samples.Count `
                    -ObservationStartedAt $sessionStartedAt `
                    -DeadlineAt $deadline -SocketObserved $socketSeen `
                    -BroadcastingObserved $broadcastSeen `
                    -ApiPeerObserved $false -ViewingObserved $false `
                    -PlaylistObserved $false -SegmentObserved $false)
        }
    } else {
        Write-I07Progress -CurrentPhase 'native_control_connecting'
        $connectDeadline = [DateTimeOffset]::UtcNow.AddSeconds(180)
        do {
            Assert-I07NotCancelled
            if ($null -ne $controlClient) { $controlClient.Dispose() }
            $controlClient = [Net.Sockets.TcpClient]::new(
                [Net.Sockets.AddressFamily]::InterNetworkV6)
            try {
                $controlClient.Client.Bind([Net.IPEndPoint]::new(
                    [Net.IPAddress]::Parse($localIPv6), 0))
                $connect = $controlClient.BeginConnect(
                    $peerIPv6, $controlPort, $null, $null)
                if ($connect.AsyncWaitHandle.WaitOne(750)) {
                    $controlClient.EndConnect($connect)
                    break
                }
            } catch {}
            Start-Sleep -Milliseconds 500
        } while ([DateTimeOffset]::UtcNow -lt $connectDeadline)
        if (-not $controlClient.Connected) {
            Throw-I07Lab 'Could not reach the controlled peer over native IPv6.'
        }
        $controlClient.ReceiveTimeout = 180000
        $controlClient.SendTimeout = 30000
        $localEndpoint = [Net.IPEndPoint]$controlClient.Client.LocalEndPoint
        $remoteEndpoint = [Net.IPEndPoint]$controlClient.Client.RemoteEndPoint
        $controlLocal = ConvertTo-I07CanonicalIPv6 `
            -Value $localEndpoint.Address.ToString()
        $controlRemote = ConvertTo-I07CanonicalIPv6 `
            -Value $remoteEndpoint.Address.ToString()
        if ($controlLocal -cne $localIPv6 -or $controlRemote -cne $peerIPv6) {
            Throw-I07Lab 'Outbound native control endpoints changed unexpectedly.'
        }
        $reader = [IO.StreamReader]::new(
            $controlClient.GetStream(), [Text.UTF8Encoding]::new($false),
            $false, 1024, $true)
        $writer = [IO.StreamWriter]::new(
            $controlClient.GetStream(), [Text.UTF8Encoding]::new($false),
            1024, $true)
        $writer.NewLine = "`n"
        Write-I07ControlMessage -StreamWriter $writer -Message ([ordered]@{
            schema = 'ese.v91.i07-control-hello/v1'
            nonce = $nonce
            candidate_sha256 = $candidateSha
            viewer_ipv6 = $localIPv6
        })
        $controlAck = Read-I07ControlLine -StreamReader $reader `
            -TimeoutSeconds 30
        if ([string]$controlAck.schema -cne
                'ese.v91.i07-control-ack/v1' -or
            [string]$controlAck.nonce -cne $nonce -or
            (ConvertTo-I07CanonicalIPv6 `
                -Value ([string]$controlAck.source_ipv6)) -cne $peerIPv6 -or
            (ConvertTo-I07CanonicalIPv6 `
                -Value ([string]$controlAck.observed_viewer_ipv6)) -cne
                $localIPv6) {
            Throw-I07Lab 'Native control acknowledgement did not prove the fixed path.'
        }
        Write-I07ControlMessage -StreamWriter $writer -Message ([ordered]@{
            schema = 'ese.v91.i07-control-ack-ok/v1'
            nonce = $nonce
        })
        $topologyProven = $true
        $controlEvidence = [ordered]@{
            bidirectional = $true
            proven_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
            local_address = $controlLocal
            local_port = [int]$localEndpoint.Port
            remote_address = $controlRemote
            remote_port = [int]$remoteEndpoint.Port
        }
        Write-I07Progress -CurrentPhase 'native_path_proven' `
            -Detail $controlEvidence

        $ready = Read-I07ControlLine -StreamReader $reader -TimeoutSeconds 90
        if ([string]$ready.schema -cne 'ese.v91.i07-source-ready/v1' -or
            [string]$ready.nonce -cne $nonce -or
            [string]$ready.candidate_sha256 -cne $candidateSha -or
            (ConvertTo-I07CanonicalIPv6 `
                -Value ([string]$ready.source_ipv6)) -cne $peerIPv6 -or
            [int]$ready.source_tcp_port -ne $peerTcpPort -or
            [string]$ready.stream_key -notmatch '^[0-9a-f]{32}$') {
            Throw-I07Lab 'Controlled source descriptor did not match the campaign.'
        }
        $streamKey = [string]$ready.stream_key
        $hlsRoot = [IO.Path]::GetFullPath((Join-Path $env:TEMP 'eMule_RTMP'))
        $staleHls = [IO.Path]::GetFullPath((Join-Path $hlsRoot $streamKey))
        if (-not $staleHls.StartsWith(
                ($hlsRoot.TrimEnd('\') + '\'),
                [StringComparison]::OrdinalIgnoreCase)) {
            Throw-I07Lab 'The nonce-owned HLS path escaped its root.'
        }
        try {
            if (-not (Remove-I07TreeNoReparse -Path $staleHls `
                    -ExpectedParent $hlsRoot)) {
                Throw-I07Lab 'The stale nonce-owned HLS tree was not removed.'
            }
        } catch {
            if ([string]$_.Exception.Message -like 'I07_LAB::*') { throw }
            Throw-I07Lab "Safe stale-HLS cleanup failed: $($_.Exception.Message)"
        }

        try {
            $connectionProfileEvidence = Get-I07NetworkProfileEvidence `
                -InterfaceIndex $interfaceIndex
            $wlanProfileEvidence = Get-I07CurrentWlanProfileEvidence `
                -InterfaceIndex $interfaceIndex
        } catch { Throw-I07Lab $_.Exception.Message }
        if ([string]$connectionProfileEvidence.profile_sha256 -cne
                ([string]$request.hotspot_connection_profile_sha256).
                    ToLowerInvariant() -or
            [string]$wlanProfileEvidence.wlan_profile_sha256 -cne
                ([string]$request.hotspot_wlan_profile_sha256).
                    ToLowerInvariant() -or
            ([string]$connectionProfileEvidence.interface_guid).Trim('{}') `
                -ine $interfaceGuid.Trim('{}') -or
            ([string]$wlanProfileEvidence.interface_guid).Trim('{}') -ine
                $interfaceGuid.Trim('{}')) {
            Throw-I07Lab 'The viewer hotspot binding changed before candidate start.'
        }
        $profileEvidence = [pscustomobject][ordered]@{
            connection_profile = $connectionProfileEvidence
            wlan_profile = $wlanProfileEvidence
            revalidated_immediately_before_candidate = $true
            revalidated_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
        }

        $phase = 'viewer_candidate_start'
        try {
            $launchBinding = Get-I07PreparedNodeLaunchBinding `
                -CandidateNode $candidate `
                -ExpectedPackageFiles $packageFiles
            $process = Start-I07CandidateProcess -CandidateNode $candidate `
                -WorkingDirectory $nodePath
            $processIdentity = Get-I07ProcessIdentity -Process $process `
                -ExpectedPath ([string]$candidate.exe_path) `
                -ExpectedFileSha256 $candidateSha `
                -ExpectedUserSidSha256 (
                    [string]$request.expected_lab_user_sid_sha256)
        } catch { Throw-I07Lab "Candidate launch failed: $($_.Exception.Message)" }
        $candidateStartedAt = [DateTimeOffset]::Parse(
            [string]$processIdentity.start_time_utc)
        try {
            $apiStatusInitial = Wait-I07Api -Process $process -Port $webPort `
                -CancellationCheck { Assert-I07NotCancelled }
            $apiStatusInitialAt = [DateTimeOffset]::UtcNow
            $null = Assert-I07ApiIsolationStatus -Value $apiStatusInitial `
                -CapturedAt $apiStatusInitialAt -Sample initial
        } catch {
            $apiWaitMessage = [string]$_.Exception.Message
            if ($apiWaitMessage.StartsWith('I07_LAB::',
                    [StringComparison]::Ordinal) -or
                $apiWaitMessage.StartsWith('I07_PRODUCT::',
                    [StringComparison]::Ordinal)) {
                throw $apiWaitMessage
            }
            Throw-I07Product -Message $apiWaitMessage `
                -Code API_INITIAL_UNRESPONSIVE `
                -Reason 'API_STATUS_UNRESPONSIVE' `
                -ApiOperation (New-I07ApiOperationFailureEvidence `
                    -Operation 'api_status_initial' -Available $false `
                    -ContractValid $false -Success $false -Ready $false)
        }
        try {
            $join = Invoke-RestMethod -Uri (
                "http://127.0.0.1:$webPort/api/live/direct_join" +
                "?key=$streamKey" +
                "&ip=$([Uri]::EscapeDataString($peerIPv6))" +
                "&port=$peerTcpPort&title=V91-I07-T3"
            ) -TimeoutSec 20
        } catch {
            Throw-I07Product -Message ([string]$_.Exception.Message) `
                -Code VIEWER_START_INVARIANT `
                -Reason 'DIRECT_JOIN_API_UNRESPONSIVE' `
                -ApiOperation (New-I07ApiOperationFailureEvidence `
                    -Operation 'direct_join' -Available $false `
                    -ContractValid $false -Success $false -Ready $false)
        }
        if (-not (Test-I07StrictBoolean -Value $join.success) -or
            -not (Test-I07StrictBoolean -Value $join.dialed) -or
            ($null -ne $join.PSObject.Properties['joined'] -and
             -not (Test-I07StrictBoolean -Value $join.joined))) {
            Throw-I07Product `
                -Message 'Viewer direct_join API returned malformed types.' `
                -Code VIEWER_START_INVARIANT `
                -Reason 'DIRECT_JOIN_API_MALFORMED' `
                -ApiOperation (New-I07ApiOperationFailureEvidence `
                    -Operation 'direct_join' -Available $true `
                    -ContractValid $false -Success $false -Ready $false)
        }
        $joinEvidence = [ordered]@{
            success = [bool]$join.success
            dialed = [bool]$join.dialed
            joined = if ($null -ne $join.PSObject.Properties['joined']) {
                [bool]$join.joined
            } else { $null }
        }
        if (-not [bool]$join.success -or -not [bool]$join.dialed) {
            Throw-I07Product `
                -Message 'Viewer direct_join did not dial the controlled IPv6 peer.' `
                -Code VIEWER_START_INVARIANT `
                -Reason 'DIRECT_JOIN_NOT_DIALED' `
                -ApiOperation (New-I07ApiOperationFailureEvidence `
                    -Operation 'direct_join' -Available $true `
                    -ContractValid $true -Success ([bool]$join.success) `
                    -Ready ([bool]$join.dialed))
        }
        Write-I07Progress -CurrentPhase 'viewer_direct_join_started' `
            -Detail $joinEvidence

        $phase = 'viewer_direct_session'
        $sessionStartedAt = [DateTimeOffset]::MinValue
        $deadline = [DateTimeOffset]::MaxValue
        $socketSeen = $false
        $apiPeerSeen = $false
        $viewingSeen = $false
        $playlistSeen = $false
        $segmentSeen = $false
        do {
            Assert-I07NotCancelled
            $process.Refresh()
            if ($process.HasExited) {
                Throw-I07Product `
                    -Message "Viewer candidate exited with code $($process.ExitCode)." `
                    -Code VIEWER_SESSION_INVARIANT `
                    -Reason 'CANDIDATE_EXITED' `
                    -ProcessExit ([ordered]@{
                        candidate_pid = [int]$process.Id
                        process_alive = $false
                    })
            }
            try {
                $null = Invoke-RestMethod -Uri (
                    "http://127.0.0.1:$webPort/api/live/player-alive" +
                    "?key=$streamKey") -TimeoutSec 5
            } catch {}
            try {
                $debug = Get-I07LiveDebug -Port $webPort
                $viewing = (Test-I07StrictBoolean -Value $debug.viewing) -and
                    [bool]$debug.viewing
            } catch { $viewing = $false }
            try {
                $peers = Get-I07PrivacyPeers -Port $webPort
                $controlledApiPeer = Get-I07ControlledApiPeerEvidence `
                    -PeersResponse $peers -PeerIPv6 $peerIPv6 `
                    -PeerTcpPort $peerTcpPort
                $apiPeer = [bool]$controlledApiPeer.matched
            } catch {
                $peers = $null
                $controlledApiPeer = $null
                $apiPeer = $false
            }
            $socket = Get-I07CandidateSocketEvidence `
                -ProcessId $process.Id -LocalIPv6 $localIPv6 `
                -PeerIPv6 $peerIPv6 -ExpectedInterfaceGuid $interfaceGuid `
                -PeerTcpPort $peerTcpPort -LocalTcpPort $tcpPort `
                -Role viewer
            $hls = Get-I07HlsEvidence -StreamKey $streamKey `
                -MinimumWriteTimeUtc $candidateStartedAt
            if ([bool]$socket.observed) {
                $socketSeen = $true
                $socketEvidence = $socket
            }
            if ($apiPeer) {
                $apiPeerSeen = $true
                $apiPeerEvidence = $controlledApiPeer
            }
            if ($viewing) { $viewingSeen = $true }
            if ([bool]$hls.playlist_seen) {
                $playlistSeen = $true
                $playlistEvidence = $hls
            }
            if ([bool]$hls.segment_seen) {
                $segmentSeen = $true
                $playlistEvidence = $hls
            }
            $sampleAt = [DateTimeOffset]::UtcNow
            if ($sessionStartedAt -eq [DateTimeOffset]::MinValue) {
                $sessionStartedAt = $sampleAt
                $deadline = $sessionStartedAt.AddSeconds($durationSeconds)
            }
            $samples.Add([ordered]@{
                at_utc = $sampleAt.ToString('o')
                process_alive = $true
                viewing = $viewing
                api_peer = $apiPeer
                peer_socket = [bool]$socket.observed
                playlist = [bool]$hls.playlist_seen
                segment = [bool]$hls.segment_seen
            })
            Write-I07Progress -CurrentPhase 'viewer_direct_session' `
                -Detail $samples[$samples.Count - 1]
            if ($sampleAt -ge $deadline) {
                break
            }
            Start-Sleep -Seconds 1
        } while ($true)

        if (-not $socketSeen) {
            Throw-I07Product `
                -Message 'Viewer PID never owned the exact direct IPv6 peer socket.' `
                -Code VIEWER_SESSION_INVARIANT -Reason 'SOCKET_NOT_OBSERVED' `
                -SessionObservation (New-I07SessionFailureEvidence `
                    -SampleCount $samples.Count `
                    -ObservationStartedAt $sessionStartedAt `
                    -DeadlineAt $deadline -SocketObserved $socketSeen `
                    -BroadcastingObserved $false `
                    -ApiPeerObserved $apiPeerSeen -ViewingObserved $viewingSeen `
                    -PlaylistObserved $playlistSeen `
                    -SegmentObserved $segmentSeen)
        }
        if (-not $apiPeerSeen) {
            Throw-I07Product `
                -Message 'The endpoint was not identified as the exact eSE peer by the candidate API.' `
                -Code VIEWER_SESSION_INVARIANT `
                -Reason 'API_PEER_NOT_OBSERVED' `
                -SessionObservation (New-I07SessionFailureEvidence `
                    -SampleCount $samples.Count `
                    -ObservationStartedAt $sessionStartedAt `
                    -DeadlineAt $deadline -SocketObserved $socketSeen `
                    -BroadcastingObserved $false `
                    -ApiPeerObserved $apiPeerSeen -ViewingObserved $viewingSeen `
                    -PlaylistObserved $playlistSeen `
                    -SegmentObserved $segmentSeen)
        }
        if (-not $viewingSeen -or -not $playlistSeen -or -not $segmentSeen) {
            Throw-I07Product `
                -Message 'The direct eSE session did not deliver valid LiveTV data.' `
                -Code VIEWER_SESSION_INVARIANT `
                -Reason 'LIVETV_NOT_OBSERVED' `
                -SessionObservation (New-I07SessionFailureEvidence `
                    -SampleCount $samples.Count `
                    -ObservationStartedAt $sessionStartedAt `
                    -DeadlineAt $deadline -SocketObserved $socketSeen `
                    -BroadcastingObserved $false `
                    -ApiPeerObserved $apiPeerSeen -ViewingObserved $viewingSeen `
                    -PlaylistObserved $playlistSeen `
                    -SegmentObserved $segmentSeen)
        }
        Write-I07ControlMessage -StreamWriter $writer -Message ([ordered]@{
            schema = 'ese.v91.i07-viewer-complete/v1'
            nonce = $nonce
            status = 'PASS'
        })
    }

    $phase = 'route_revalidation'
    $routeFinal = Get-I07NativeRouteEvidence -RemoteIPv6 $peerIPv6 `
        -ExpectedInterfaceIndex $interfaceIndex `
        -ExpectedSourceIPv6 $localIPv6 `
        -ExpectedInterfaceGuid $interfaceGuid
    if (-not [bool]$routeFinal.valid) {
        Throw-I07Lab "Native route changed during I07: $($routeFinal.reason)."
    }
    try {
        $apiStatusFinal = Invoke-RestMethod -Uri (
            "http://127.0.0.1:$webPort/api/status") -TimeoutSec 5
        $apiStatusFinalAt = [DateTimeOffset]::UtcNow
    } catch {
        Throw-I07Product `
            -Message 'Candidate API was not responsive at final sample.' `
            -Code API_FINAL_UNRESPONSIVE `
            -Reason 'API_STATUS_UNRESPONSIVE' `
            -ApiOperation (New-I07ApiOperationFailureEvidence `
                -Operation 'api_status_final' -Available $false `
                -ContractValid $false -Success $false -Ready $false)
    }
    $null = Assert-I07ApiIsolationStatus -Value $apiStatusFinal `
        -CapturedAt $apiStatusFinalAt -Sample final
    $status = 'PASS'
    Write-I07Progress -CurrentPhase 'pass'
} catch {
    $message = [string]$_.Exception.Message
    if ($message.StartsWith('I07_PRODUCT::',
            [StringComparison]::Ordinal)) {
        $productPayload = $message.Substring('I07_PRODUCT::'.Length)
        $productParts = $productPayload.Split(
            [string[]]@('::'), 2, [StringSplitOptions]::None)
        $allowedProductCodes = @(
            'SOURCE_START_INVARIANT', 'VIEWER_START_INVARIANT',
            'SOURCE_SESSION_INVARIANT', 'VIEWER_SESSION_INVARIANT',
            'API_INITIAL_UNRESPONSIVE',
            'API_INITIAL_ISOLATION_CONTRADICTION',
            'API_FINAL_UNRESPONSIVE',
            'API_FINAL_ISOLATION_CONTRADICTION')
        if ($productParts.Count -eq 2 -and
            [string]$productParts[0] -cin $allowedProductCodes) {
            $status = 'FAIL'
            $failureCategory = 'PRODUCT_INVARIANT'
            $failureCode = [string]$productParts[0]
        } else {
            $status = 'LAB_BLOCKED'
            $failureCategory = 'LAB_TOPOLOGY_OR_FIXTURE'
            $failureCode = 'UNEXPECTED_LAB_ERROR'
            $script:I07ProductFailureEvidence = $null
        }
    } else {
        $status = 'LAB_BLOCKED'
        $failureCategory = 'LAB_TOPOLOGY_OR_FIXTURE'
        if ($message.StartsWith('I07_LAB::',
                [StringComparison]::Ordinal)) {
            $failureCode = 'LAB_PRECONDITION_OR_RUNTIME'
        } else { $failureCode = 'UNEXPECTED_LAB_ERROR' }
    }
    try {
        Write-I07Progress -CurrentPhase 'failed' -Detail ([ordered]@{
            status = $status
            category = $failureCategory
            code = $failureCode
        })
    } catch {}
} finally {
    $roleForCleanup = if ($null -ne $request.PSObject.Properties['role']) {
        [string]$request.role
    } else { '' }
    if ($null -ne $process) {
        try {
            $process.Refresh()
            if (-not $process.HasExited -and $roleForCleanup -ceq 'source') {
                $stopBroadcast = Invoke-RestMethod -Uri (
                    "http://127.0.0.1:$($request.web_port)" +
                    '/api/live/broadcast/stop') -TimeoutSec 10
                $cleanup.broadcast_stopped =
                    (Test-I07StrictBoolean -Value $stopBroadcast.success) -and
                    [bool]$stopBroadcast.success -and
                    (Test-I07StrictBoolean `
                        -Value $stopBroadcast.was_broadcasting) -and
                    [bool]$stopBroadcast.was_broadcasting
            } elseif (-not $process.HasExited -and
                $roleForCleanup -ceq 'viewer' -and
                -not [string]::IsNullOrWhiteSpace($streamKey)) {
                $null = Invoke-RestMethod -Uri (
                    "http://127.0.0.1:$($request.web_port)/api/live/leave" +
                    "?key=$streamKey") -TimeoutSec 10
            }
        } catch {
            if ($roleForCleanup -ceq 'source') {
                $cleanup.broadcast_stopped = $false
            }
        }
    }
    if ($null -ne $writer) {
        try { $writer.Dispose() } catch { $cleanup.control_closed = $false }
    }
    if ($null -ne $reader) {
        try { $reader.Dispose() } catch { $cleanup.control_closed = $false }
    }
    if ($null -ne $controlClient) {
        try { $controlClient.Dispose() } catch { $cleanup.control_closed = $false }
    }
    if ($null -ne $controlListener) {
        try { $controlListener.Stop() } catch { $cleanup.control_closed = $false }
    }
    try {
        $nodeFfmpegPath = Join-Path $nodePath 'ffmpeg.exe'
        $ffmpegContracts = @($packageFiles | Where-Object {
                [string]$_.path -ceq 'ffmpeg.exe'
            })
        if ($null -ne $process -and $ffmpegContracts.Count -ne 1) {
            throw 'The FFmpeg package identity is not singular.'
        }
        $processCleanupEvidence = Stop-I07Candidate -Process $process `
            -ExpectedIdentity $processIdentity `
            -ExpectedFfmpegPath $nodeFfmpegPath `
            -ExpectedFfmpegSha256 $(if ($ffmpegContracts.Count -eq 1) {
                [string]$ffmpegContracts[0].sha256
            } else { '' }) `
            -ExpectedUserSidSha256 $(if ($null -ne
                    $request.PSObject.Properties[
                        'expected_lab_user_sid_sha256']) {
                [string]$request.expected_lab_user_sid_sha256
            } else { '' }) `
            -WebPort $(if ($null -ne
                    $request.PSObject.Properties['web_port']) {
                [int]$request.web_port
            } else { 0 })
        $cleanup.process_stopped =
            [bool]$processCleanupEvidence.stopped -and
            [bool]$processCleanupEvidence.root_identity_matched
        $cleanup.ffmpeg_children_gone =
            [bool]$processCleanupEvidence.descendants_collector_ok -and
            [bool]$processCleanupEvidence.descendants_stopped
        $postCandidateFfmpeg = @(Get-I07ExactNodeFfmpegProcesses `
            -ExpectedPath $nodeFfmpegPath)
        $cleanup.ffmpeg_children_gone =
            [bool]$cleanup.ffmpeg_children_gone -and
            $postCandidateFfmpeg.Count -eq 0
    } catch {
        $cleanup.process_stopped = $false
        $cleanup.ffmpeg_children_gone = $false
    }
    foreach ($binding in $ruleBindings) {
        try {
            $snapshot = $binding.snapshot
            if ($null -eq $snapshot) {
                $snapshot = Get-I07BoundFirewallRuleSnapshot `
                    -Name ([string]$binding.name) `
                    -ExpectedAction ([string]$binding.tuple.action) `
                    -ExpectedDirection ([string]$binding.tuple.direction) `
                    -ExpectedProtocol ([string]$binding.tuple.protocol) `
                    -ExpectedLocalPort ([string]$binding.tuple.local_port) `
                    -ExpectedLocalAddress @($binding.tuple.local_address) `
                    -ExpectedRemoteAddress @($binding.tuple.remote_address) `
                    -ExpectedProgram ([string]$binding.tuple.program) `
                    -ExpectedInterfaceAlias @($binding.tuple.interface_alias)
            }
            $null = Remove-I07BoundFirewallRule `
                -Name ([string]$binding.name) `
                -ExpectedSnapshot $snapshot -ExpectedTuple $binding.tuple
        } catch { $cleanup.firewall_removed = $false }
    }
    try {
        $retainedTopology = [ordered]@{
            local_ipv6 = if ($null -ne
                $request.PSObject.Properties['local_ipv6']) {
                [string]$request.local_ipv6
            } else { '' }
            peer_ipv6 = if ($null -ne
                $request.PSObject.Properties['peer_ipv6']) {
                [string]$request.peer_ipv6
            } else { '' }
            interface_index = if ($null -ne
                $request.PSObject.Properties['interface_index']) {
                [int]$request.interface_index
            } else { 0 }
            interface_guid = if ($null -ne
                $request.PSObject.Properties['interface_guid']) {
                [string]$request.interface_guid
            } else { '' }
            ports = [ordered]@{
                tcp = if ($null -ne $request.PSObject.Properties['tcp_port']) {
                    [int]$request.tcp_port
                } else { 0 }
                udp = if ($null -ne $request.PSObject.Properties['udp_port']) {
                    [int]$request.udp_port
                } else { 0 }
                web = if ($null -ne $request.PSObject.Properties['web_port']) {
                    [int]$request.web_port
                } else { 0 }
                peer_tcp = if ($null -ne
                    $request.PSObject.Properties['peer_tcp_port']) {
                    [int]$request.peer_tcp_port
                } else { 0 }
                control = if ($null -ne
                    $request.PSObject.Properties['control_port']) {
                    [int]$request.control_port
                } else { 0 }
            }
            initial_route = $routeInitial
            final_route = $routeFinal
            control = $controlEvidence
            socket = $socketEvidence
            r01_hotspot_profile = $profileEvidence
        }
        $expectedBuildForEvidence = if ($null -ne
            $request.PSObject.Properties['candidate_build_info_sha256']) {
            [string]$request.candidate_build_info_sha256
        } else { '' }
        $retainedEvidence = Write-I07RetainedNodeEvidence `
            -EvidencePath $evidencePath -NodePath $nodePath `
            -ExpectedBuildInfoSha256 $expectedBuildForEvidence `
            -ApiStatusInitial $apiStatusInitial `
            -ApiStatusFinal $apiStatusFinal `
            -ApiInitialAtUtc $apiStatusInitialAt `
            -ApiFinalAtUtc $apiStatusFinalAt `
            -Role $roleForCleanup `
            -CandidatePid $(if ($null -eq $process) { 0 } else {
                [int]$process.Id
            }) -TopologyPorts $retainedTopology `
            -Secrets @($nonce, $password, $streamKey)
        $cleanup.evidence_retained = [bool]$retainedEvidence.complete
    } catch { $cleanup.evidence_retained = $false }
    try {
        $cleanup.node_removed = Remove-I07TreeNoReparse -Path $nodePath `
            -ExpectedParent $jobRoot
    } catch { $cleanup.node_removed = $false }
    if (-not [string]::IsNullOrWhiteSpace($streamKey)) {
        try {
            $hlsRoot = [IO.Path]::GetFullPath((
                Join-Path $env:TEMP 'eMule_RTMP'))
            $ownedHls = [IO.Path]::GetFullPath((
                Join-Path $hlsRoot $streamKey))
            if (-not $ownedHls.StartsWith(
                    ($hlsRoot.TrimEnd('\') + '\'),
                    [StringComparison]::OrdinalIgnoreCase)) {
                throw 'HLS cleanup path escaped its root.'
            }
            $cleanup.hls_removed = Remove-I07TreeNoReparse `
                -Path $ownedHls -ExpectedParent $hlsRoot
        } catch { $cleanup.hls_removed = $false }
    }
    try {
        $allFirewallRules = @(Get-NetFirewallRule -PolicyStore ActiveStore `
            -ErrorAction Stop)
        foreach ($ruleName in $ruleNames) {
            if (@($allFirewallRules | Where-Object {
                        [string]$_.Name -ceq [string]$ruleName
                    }).Count -ne 0) {
                $cleanup.firewall_removed = $false
            }
        }
    } catch { $cleanup.firewall_removed = $false }
    if ($null -ne $systemMutationTransaction) {
        $systemMutationPostcheck = Complete-I07SystemMutationTransaction `
            -Transaction $systemMutationTransaction
        $cleanup.system_state_restored =
            [bool]$systemMutationPostcheck.collector_ok -and
            [bool]$systemMutationPostcheck.complete
    }
}

if ($status -ceq 'PASS' -and
    (-not [bool]$cleanup.process_stopped -or
     -not [bool]$cleanup.firewall_removed -or
     -not [bool]$cleanup.control_closed -or
     -not [bool]$cleanup.broadcast_stopped -or
     -not [bool]$cleanup.ffmpeg_children_gone -or
     -not [bool]$cleanup.hls_removed -or
     -not [bool]$cleanup.node_removed -or
     -not [bool]$cleanup.evidence_retained -or
     -not [bool]$cleanup.system_state_restored)) {
    $status = 'LAB_BLOCKED'
    $failureCategory = 'CLEANUP'
    $failureCode = 'CLEANUP_INCOMPLETE'
}
$result = [ordered]@{
    schema = 'ese.v91.i07-node-result/v1'
    case_id = 'V91-I07'
    status = $status
    role = if ($null -ne $request.PSObject.Properties['role']) {
        [string]$request.role
    } else { '' }
    nonce = if ($null -ne $request.PSObject.Properties['nonce']) {
        [string]$request.nonce
    } else { '' }
    completed_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
    phase = $phase
    failure = if ([string]::IsNullOrWhiteSpace($failureCategory)) {
        $null
    } else { [ordered]@{
        category = $failureCategory
        code = $failureCode
    }}
    candidate = if ($null -eq $candidate) { [ordered]@{
        requested_sha256 = if (
            $null -ne $request.PSObject.Properties['candidate_sha256']) {
            [string]$request.candidate_sha256
        } else { '' }
        verified = $false
    }} else { [ordered]@{
        requested_sha256 = [string]$request.candidate_sha256
        sha256 = [string]$candidate.sha256
        bytes = [Int64]$candidate.bytes
        verified = [string]$candidate.sha256 -ceq
            [string]$request.candidate_sha256 -and
            $null -ne $zipEvidence -and [bool]$zipEvidence.verified
        pid = if ($null -eq $process) { $null } else { [int]$process.Id }
        started_at_utc = if ($null -eq $candidateStartedAt) { $null } else {
            $candidateStartedAt.ToString('o')
        }
        commit = [string]$request.candidate_commit
        build_info_sha256 = [string]$request.candidate_build_info_sha256
        zip_sha256 = [string]$zipEvidence.zip_sha256
        zip_bytes = [Int64]$zipEvidence.zip_bytes
        zip_verified = [bool]$zipEvidence.verified
        zip_binding = $zipEvidence
        package_files = $candidate.package_files
        process_identity = $processIdentity
        launch_binding = $launchBinding
    }}
    topology = [ordered]@{
        topology_id = 'T3'
        native_path_proven_before_candidate = $topologyProven
        local_ipv6 = if ($null -ne $request.PSObject.Properties['local_ipv6']) {
            [string]$request.local_ipv6
        } else { '' }
        peer_ipv6 = if ($null -ne $request.PSObject.Properties['peer_ipv6']) {
            [string]$request.peer_ipv6
        } else { '' }
        interface_index = if ($null -ne
            $request.PSObject.Properties['interface_index']) {
            [int]$request.interface_index
        } else { 0 }
        interface_guid = if ($null -ne
            $request.PSObject.Properties['interface_guid']) {
            [string]$request.interface_guid
        } else { '' }
        ports = [ordered]@{
            tcp = if ($null -ne $request.PSObject.Properties['tcp_port']) {
                [int]$request.tcp_port
            } else { 0 }
            udp = if ($null -ne $request.PSObject.Properties['udp_port']) {
                [int]$request.udp_port
            } else { 0 }
            web = if ($null -ne $request.PSObject.Properties['web_port']) {
                [int]$request.web_port
            } else { 0 }
            peer_tcp = if ($null -ne
                $request.PSObject.Properties['peer_tcp_port']) {
                [int]$request.peer_tcp_port
            } else { 0 }
            control = if ($null -ne
                $request.PSObject.Properties['control_port']) {
                [int]$request.control_port
            } else { 0 }
        }
        initial_route = $routeInitial
        final_route = $routeFinal
        control = $controlEvidence
        r01_hotspot_profile = $profileEvidence
        web_api_containment = $webContainmentEvidence
    }
    product = [ordered]@{
        broadcast = $broadcastEvidence
        direct_join = $joinEvidence
        socket = $socketEvidence
        api_peer = $apiPeerEvidence
        hls = $playlistEvidence
        api_status_initial = Get-I07ApiEvidenceSummary `
            -Value $apiStatusInitial -CapturedAt $apiStatusInitialAt
        api_status_final = Get-I07ApiEvidenceSummary `
            -Value $apiStatusFinal -CapturedAt $apiStatusFinalAt
        samples = $samples
        failure_evidence = if ($status -ceq 'FAIL') {
            $script:I07ProductFailureEvidence
        } else { $null }
    }
    cleanup = $cleanup
    evidence = $retainedEvidence
    system_state = $systemMutationPostcheck
    process_cleanup = $processCleanupEvidence
}
Write-I07JsonAtomic -Value $result -Path $resultPath -Depth 20
if ($status -ceq 'PASS') { exit 0 }
if ($status -ceq 'FAIL') { exit 1 }
exit 2
