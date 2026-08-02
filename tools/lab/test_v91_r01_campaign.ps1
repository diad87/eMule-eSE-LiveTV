[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

function Assert-R01 {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Message
    )
    if (-not $Condition) { throw $Message }
}

function Import-R01Function {
    param(
        [Parameter(Mandatory = $true)]$Ast,
        [Parameter(Mandatory = $true)][string]$Name
    )
    $definitions = @($Ast.FindAll({
                param($node)
                $node -is
                    [Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -ceq $Name
            }, $true))
    if ($definitions.Count -ne 1) {
        throw "Expected exactly one $Name definition."
    }
    $bodyText = $definitions[0].Body.Extent.Text
    $body = [scriptblock]::Create(
        $bodyText.Substring(1, $bodyText.Length - 2))
    Set-Item -Path ("Function:\script:$Name") -Value $body
}

function New-R01TestFrame {
    param(
        [byte]$Protocol,
        [byte]$Opcode,
        [byte[]]$Payload
    )
    $buffer = New-Object byte[] (6 + $Payload.Length)
    $buffer[0] = $Protocol
    [Array]::Copy([BitConverter]::GetBytes(
            [uint32]($Payload.Length + 1)), 0, $buffer, 1, 4)
    $buffer[5] = $Opcode
    [Array]::Copy($Payload, 0, $buffer, 6, $Payload.Length)
    return $buffer
}

$paths = @(
    (Join-Path $PSScriptRoot 'run_v91_r01_remote.ps1'),
    (Join-Path $PSScriptRoot 'run_v91_r01_server.ps1'),
    (Join-Path $PSScriptRoot 'run_v91_r01_wifi_watchdog.ps1'),
    (Join-Path $PSScriptRoot 'invoke_v91_r01_campaign.ps1'),
    (Join-Path $PSScriptRoot 'run_ese_lab_smallframe_agent.ps1'),
    (Join-Path $PSScriptRoot 'control_ese_lab_smallframe_agent.ps1'),
    (Join-Path $PSScriptRoot 'test_v91_r01_remote.ps1')
)
$asts = @{}
foreach ($path in $paths) {
    $tokens = $null
    $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile(
        $path, [ref]$tokens, [ref]$errors)
    if ($errors.Count -ne 0) {
        throw "$path has $($errors.Count) PowerShell parser error(s)."
    }
    $asts[$path] = $ast
}

$controllerPath = $paths[3]
$controllerAst = $asts[$controllerPath]
foreach ($name in @(
    'Get-R01TextSha256', 'Get-R01StreamSha256',
    'Assert-R01NoReparsePath', 'Test-R01SafeRelativePath',
    'Get-R01PackageFileCensus', 'Get-R01PackageManifestCanonical',
    'Get-R01ZipPackageEvidence', 'Get-R01IPv4Class',
    'Test-R01OverlayAdapter', 'Assert-R01PublicResultPrivacy',
    'Add-R01OwnedUpnpMapping', 'Test-R01TransitionEvidence',
    'Test-R01EvidenceBinding',
    'Test-R01AggregatePass', 'Test-R01ProductFailureProven',
    'Get-R01AggregateStatus'
)) { Import-R01Function -Ast $controllerAst -Name $name }

$addressCases = [ordered]@{
    '8.8.8.8' = 'global'; '223.255.255.254' = 'global'
    '0.0.0.0' = 'special'; '0.255.255.255' = 'special'
    '10.0.0.1' = 'private'; '172.16.0.0' = 'private'
    '172.31.255.255' = 'private'; '192.168.1.1' = 'private'
    '100.64.0.0' = 'shared-cgnat'; '100.127.255.255' = 'shared-cgnat'
    '127.0.0.1' = 'loopback'; '169.254.1.1' = 'link-local'
    '192.0.0.1' = 'special'; '192.0.2.1' = 'special'
    '192.31.196.1' = 'special'; '192.52.193.1' = 'special'
    '192.88.99.1' = 'special'; '192.175.48.1' = 'special'
    '198.18.0.0' = 'special'; '198.19.255.255' = 'special'
    '198.51.100.1' = 'special'; '203.0.113.1' = 'special'
    '224.0.0.1' = 'special'; '239.255.255.255' = 'special'
    '240.0.0.1' = 'special'; '255.255.255.255' = 'special'
    'not-an-ip' = 'invalid'; '::ffff:8.8.8.8' = 'invalid'
}
foreach ($entry in $addressCases.GetEnumerator()) {
    Assert-R01 -Condition (
        (Get-R01IPv4Class -Address $entry.Key) -ceq $entry.Value) `
        -Message "Controller IPv4 class mismatch for $($entry.Key)."
}
Import-R01Function -Ast $asts[$paths[0]] -Name 'Get-R01IPv4Class'
foreach ($entry in $addressCases.GetEnumerator()) {
    Assert-R01 -Condition (
        (Get-R01IPv4Class -Address $entry.Key) -ceq $entry.Value) `
        -Message "Remote IPv4 class mismatch for $($entry.Key)."
}

$nonce = '0123456789abcdef0123456789abcdef'
$shaA = 'a' * 64; $shaB = 'b' * 64; $shaC = 'c' * 64
$shaD = 'd' * 64; $manifestSha = 'e' * 64
$candidate = [pscustomobject]@{
    version = '9.1.0-rc.test'; commit = '1' * 40; dirty = $false
    emule_sha256 = $shaA; ese_server_sha256 = $shaB
    build_info_sha256 = $shaC; zip_sha256 = $shaD
    zip_bytes = [Int64]1234; package_manifest_sha256 = $manifestSha
    package_manifest_file_count = 4
    h3_sid_sha256 = '6' * 64
}
$remote = [pscustomobject]@{
    schema = 'ese.v91.r01-remote/v4'; case_id = 'V91-R01'
    nonce = $nonce; status = 'REMOTE_PASS'
    failure_category = 'NONE'; product_failure_proven = $false
    process_preflight = [pscustomobject]@{ baseline_zero = $true }
    port_preflight = @(
        [pscustomobject]@{ protocol = 'TCP'; port = 51662; available = $true },
        [pscustomobject]@{ protocol = 'TCP'; port = 51711; available = $true },
        [pscustomobject]@{ protocol = 'UDP'; port = 51672; available = $true })
    account_registry_preflight = [pscustomobject]@{
        sid_sha256 = '6' * 64; disposable_account_confirmed = $true
        emule_autostart_absent = $true
    }
    candidate = [pscustomobject]@{
        version = $candidate.version; commit = $candidate.commit
        dirty = $false; emule_sha256 = $shaA; ese_server_sha256 = $shaB
        build_info_sha256 = $shaC; zip_sha256 = $shaD
        zip_bytes = [Int64]1234; package_manifest_sha256 = $manifestSha
        package_manifest_file_count = 4; same_pid_before_after = $true
        remote_package_binding = [pscustomobject]@{
            schema = 'ese.v91.r01-remote-package-binding/v2'
            remote_zip_sha256 = $shaD; remote_zip_bytes = [Int64]1234
            manifest_sha256 = $manifestSha; manifest_file_count = 4
            extracted_file_set_exact = $true
            extracted_bytes_and_sha256_exact = $true
            locked_zip_snapshot = $true; reparse_free = $true
            post_extract_file_count = 4
        }
        process_id = 4242
        process_identity = [pscustomobject]@{
            schema = 'ese.v91.r01-process-identity/v1'; pid = 4242
            start_time_utc = '2026-08-01T10:00:00.0000000Z'
            executable_path_sha256 = '7' * 64; executable_sha256 = $shaA
        }
    }
    topology = [pscustomobject]@{
        mobile_topology_validated = $true
        initial = [pscustomobject]@{
            interface_guid = '11111111-1111-1111-1111-111111111111'
            profile_matches_expected = $true; status = 'Up'
            hardware_interface = $true; virtual = $false
            overlay = $false
            wlan_profile_sha256 = 'f' * 64
            connection_profile = [pscustomobject]@{ name_sha256 = '0' * 64 }
            addresses = @([pscustomobject]@{
                family = 'IPv4'; address = '192.168.1.20'
                skip_as_source = $false
            })
        }
        mobile = [pscustomobject]@{
            interface_guid = '11111111-1111-1111-1111-111111111111'
            profile_matches_expected = $true; status = 'Up'
            hardware_interface = $true; virtual = $false
            overlay = $false
            wlan_profile_sha256 = '8' * 64
            connection_profile = [pscustomobject]@{ name_sha256 = '9' * 64 }
            addresses = @([pscustomobject]@{
                family = 'IPv4'; address = '10.20.30.40'
                skip_as_source = $false
            })
        }
        mobile_public_probe = [pscustomobject]@{
            status = 'PASS'; remote_port = 51902
            local_address = '10.20.30.40'
            interface_guid = '11111111-1111-1111-1111-111111111111'
            physical_nonvirtual = $true
            selected_route = [pscustomobject]@{ valid = $true; overlay = $false }
        }
        initial_selected_route = [pscustomobject]@{ valid = $true; overlay = $false }
        mobile_selected_route = [pscustomobject]@{ valid = $true; overlay = $false }
    }
    session = [pscustomobject]@{
        old_endpoint_expired = $true; server_port = 51901
        candidate_tcp_port = 51662
        initial_socket = [pscustomobject]@{
            local_address = '192.168.1.20'; owning_process = 4242
            process_start_time_utc = '2026-08-01T10:00:00.0000000Z'
            executable_path_sha256 = '7' * 64; executable_sha256 = $shaA
        }
        reconnected_socket = [pscustomobject]@{
            local_address = '10.20.30.40'; owning_process = 4242
            process_start_time_utc = '2026-08-01T10:00:00.0000000Z'
            executable_path_sha256 = '7' * 64; executable_sha256 = $shaA
        }
    }
    cleanup = [pscustomobject]@{
        home_restored = $true; final_profile_mode = 'home_restored'
        node_removed = $true; wifi_watchdog_safe = $true
        account_registry_unchanged = $true; cleanup_incident = $false
    }
}
$server = [pscustomobject]@{
    schema = 'ese.v91.r01-controlled-server/v1'; case_id = 'V91-R01'
    nonce = $nonce; status = 'SERVER_PASS'; server_port = 51901
    probe_port = 51902; same_client_identity = $true
    different_observed_remote = $true
    fixture_valid_for_product_adjudication = $true
    initial = [pscustomobject]@{
        advertised_tcp_port = 51662; remote_address = '192.168.1.20'
    }
    mobile = [pscustomobject]@{ remote_address = '8.8.4.4' }
    topology_probe = [pscustomobject]@{
        status = 'PASS'; remote_address = '8.8.4.4'
    }
}
$adjudication = @{
    Remote = $remote; Server = $server; ExpectedCandidate = $candidate
    ExpectedNonce = $nonce; ExpectedServerPort = 51901
    ExpectedProbePort = 51902; ExpectedCandidateTcpPort = 51662
    CleanupComplete = $true; ControllerFailure = ''
}
Assert-R01 -Condition (
    (Get-R01AggregateStatus @adjudication) -ceq 'PASS') `
    -Message 'Exact cross-bound R01 evidence did not adjudicate PASS.'
$remote.topology.mobile.wlan_profile_sha256 =
    $remote.topology.initial.wlan_profile_sha256
Assert-R01 -Condition (
    (Get-R01AggregateStatus @adjudication) -ceq 'BLOCKED') `
    -Message 'Unchanged WLAN identity was accepted as roaming.'
$remote.topology.mobile.wlan_profile_sha256 = '8' * 64
$remote.topology.mobile.connection_profile.name_sha256 =
    $remote.topology.initial.connection_profile.name_sha256
Assert-R01 -Condition (
    (Get-R01AggregateStatus @adjudication) -ceq 'BLOCKED') `
    -Message 'Unchanged NLA identity was accepted as roaming.'
$remote.topology.mobile.connection_profile.name_sha256 = '9' * 64
$remote.topology.mobile_public_probe.local_address = '192.168.1.20'
Assert-R01 -Condition (
    (Get-R01AggregateStatus @adjudication) -ceq 'BLOCKED') `
    -Message 'Unchanged physical IPv4 was accepted as roaming.'
$remote.topology.mobile_public_probe.local_address = '10.20.30.40'
$remote.topology.mobile.interface_guid =
    '22222222-2222-2222-2222-222222222222'
Assert-R01 -Condition (
    (Get-R01AggregateStatus @adjudication) -ceq 'BLOCKED') `
    -Message 'A different physical Wi-Fi interface was accepted as roaming.'
$remote.topology.mobile.interface_guid =
    '11111111-1111-1111-1111-111111111111'
$server.topology_probe.remote_address = $server.initial.remote_address
Assert-R01 -Condition (
    (Get-R01AggregateStatus @adjudication) -ceq 'BLOCKED') `
    -Message 'Server probe from the initial endpoint was accepted.'
$server.topology_probe.remote_address = '8.8.4.4'
$server.topology_probe.remote_address = '198.18.0.20'
Assert-R01 -Condition (
    (Get-R01AggregateStatus @adjudication) -ceq 'BLOCKED') `
    -Message 'Benchmark source address was accepted as public roaming.'
$server.topology_probe.remote_address = '8.8.4.4'
$remote.nonce = 'stale'
Assert-R01 -Condition (
    (Get-R01AggregateStatus @adjudication) -ceq 'BLOCKED') `
    -Message 'Stale nonce evidence was accepted.'
$remote.nonce = $nonce
$remote.account_registry_preflight.sid_sha256 = '5' * 64
Assert-R01 -Condition (
    (Get-R01AggregateStatus @adjudication) -ceq 'BLOCKED') `
    -Message 'A different disposable-account SID was accepted.'
$remote.account_registry_preflight.sid_sha256 = '6' * 64
$remote.port_preflight[0].available = $false
Assert-R01 -Condition (
    (Get-R01AggregateStatus @adjudication) -ceq 'BLOCKED') `
    -Message 'A busy or unproven candidate port was accepted.'
$remote.port_preflight[0].available = $true
$remote.candidate.process_identity.start_time_utc =
    '2026-08-01T10:00:01.0000000Z'
Assert-R01 -Condition (
    (Get-R01AggregateStatus @adjudication) -ceq 'BLOCKED') `
    -Message 'A changed process start-time tuple was accepted.'
$remote.candidate.process_identity.start_time_utc =
    '2026-08-01T10:00:00.0000000Z'
$remote.topology.mobile_selected_route.overlay = $true
Assert-R01 -Condition (
    (Get-R01AggregateStatus @adjudication) -ceq 'BLOCKED') `
    -Message 'An overlay-selected candidate route was accepted.'
$remote.topology.mobile_selected_route.overlay = $false
$remote.candidate.remote_package_binding.locked_zip_snapshot = $false
Assert-R01 -Condition (
    (Get-R01AggregateStatus @adjudication) -ceq 'BLOCKED') `
    -Message 'An unlocked remote ZIP snapshot was accepted.'
$remote.candidate.remote_package_binding.locked_zip_snapshot = $true
$server.mobile.remote_address = '1.1.1.1'
Assert-R01 -Condition (
    (Get-R01AggregateStatus @adjudication) -ceq 'BLOCKED') `
    -Message 'A mobile login not bound to the topology-probe public IP was accepted.'
$server.mobile.remote_address = '8.8.4.4'
$remote.status = 'REMOTE_FAIL'; $remote.failure_category = 'PRODUCT'
$remote.product_failure_proven = $true; $server.status = 'SERVER_BLOCKED'
$remote.cleanup.account_registry_unchanged = $false
$remote.cleanup.cleanup_incident = $true
$adjudication.CleanupComplete = $false
$adjudication.ControllerFailure = 'post-product cleanup incident'
Assert-R01 -Condition (
    (Get-R01AggregateStatus @adjudication) -ceq 'FAIL') `
    -Message 'Cross-proven product FAIL was masked by cleanup.'
$remote.product_failure_proven = $false
Assert-R01 -Condition (
    (Get-R01AggregateStatus @adjudication) -ceq 'BLOCKED') `
    -Message 'Untyped remote error was misclassified FAIL.'

$publicFixture = [pscustomobject][ordered]@{
    schema = 'ese.v91.r01-public-result/v1'; case_id = 'V91-R01'
    status = 'BLOCKED'; completed_at_utc = '2026-08-01T10:30:00Z'
    candidate = [pscustomobject][ordered]@{
        version = '9.1.0-rc.test'; commit = '1' * 40
        emule_sha256 = $shaA; build_info_sha256 = $shaC
        zip_sha256 = $shaD; zip_bytes = [Int64]1234
    }
    checks = [pscustomobject][ordered]@{
        product_failure_proven = $false; cleanup_complete = $false
        cleanup_incident = $true
    }
    private_aggregate = [pscustomobject][ordered]@{
        bytes = [Int64]100; sha256 = '2' * 64
    }
}
$null = Assert-R01PublicResultPrivacy -Value $publicFixture `
    -SensitiveValues @('HomeSSID', '203.0.113.8')
$publicFixture.candidate.version = 'HomeSSID'
$privacyRejected = $false
try {
    $null = Assert-R01PublicResultPrivacy -Value $publicFixture `
        -SensitiveValues @('HomeSSID')
} catch { $privacyRejected = $true }
Assert-R01 $privacyRejected 'Public projection accepted a sensitive value.'
$publicFixture.candidate.version = '9.1.0-rc.test'

$remotePath = $paths[0]
$remoteAst = $asts[$remotePath]
foreach ($name in @('Get-Hash', 'Assert-R01RunActive',
        'ConvertTo-R01NetworkProfileEvidence')) {
    Import-R01Function -Ast $remoteAst -Name $name
}
$cancelRoot = Join-Path ([IO.Path]::GetTempPath()) (
    'ese-r01-control-' + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($cancelRoot) | Out-Null
try {
    $script:cancelPath = Join-Path $cancelRoot 'cancel-request.json'
    $script:runnerDeadline = [DateTimeOffset]::UtcNow.AddMinutes(1)
    Assert-R01RunActive
    [IO.File]::WriteAllText($script:cancelPath, '{}')
    $cancelObserved = $false
    try { Assert-R01RunActive } catch [OperationCanceledException] {
        $cancelObserved = $true
    }
    Assert-R01 $cancelObserved 'Cooperative cancel was not observed.'
    Remove-Item -LiteralPath $script:cancelPath -Force
    $script:runnerDeadline = [DateTimeOffset]::UtcNow.AddSeconds(-1)
    $deadlineObserved = $false
    try { Assert-R01RunActive } catch [TimeoutException] {
        $deadlineObserved = $true
    }
    Assert-R01 $deadlineObserved 'Autonomous runner deadline was not observed.'
} finally {
    Remove-Item -LiteralPath $cancelRoot -Recurse -Force
}
$profileA = ConvertTo-R01NetworkProfileEvidence -Profile (
    [pscustomobject]@{ Name = 'HomeNla'; NetworkCategory = 'Private'
        IPv4Connectivity = 'Internet'; IPv6Connectivity = 'NoTraffic' })
$profileB = ConvertTo-R01NetworkProfileEvidence -Profile (
    [pscustomobject]@{ Name = 'HotspotNla'; NetworkCategory = 'Public'
        IPv4Connectivity = 'Internet'; IPv6Connectivity = 'Internet' })
Assert-R01 -Condition ($profileA.schema -ceq
    'ese.lab.windows-network-profile/v1' -and
    $profileA.name_sha256 -cne $profileB.name_sha256) `
    -Message 'Windows connection-profile evidence is ambiguous.'

$serverPath = $paths[1]
$serverAst = $asts[$serverPath]
foreach ($name in @('Read-R01ExactBytes', 'Read-R01WireFrame',
        'Send-R01IdChange')) {
    Import-R01Function -Ast $serverAst -Name $name
}
[byte[]]$loginPayload = New-Object byte[] 22
[Array]::Copy([BitConverter]::GetBytes([uint16]51662), 0,
    $loginPayload, 20, 2)
[byte[]]$extraPayload = @(1, 2, 3)
$firstLogin = New-R01TestFrame 0xE3 0x01 $loginPayload
$extraFrame = New-R01TestFrame 0xE3 0x34 $extraPayload
$firstStream = New-Object IO.MemoryStream
$firstStream.Write($firstLogin, 0, $firstLogin.Length)
$firstStream.Write($extraFrame, 0, $extraFrame.Length)
$firstStream.Position = 0
$parsedLogin = Read-R01WireFrame -Stream $firstStream
$parsedExtra = Read-R01WireFrame -Stream $firstStream
Assert-R01 -Condition ($parsedLogin.opcode -eq 1 -and
    $parsedExtra.opcode -eq 0x34 -and
    $firstStream.Position -eq $firstStream.Length) `
    -Message 'Server did not drain login + post-login frame to EOF.'
$firstStream.Dispose()
$secondStream = New-Object IO.MemoryStream (,$firstLogin)
$secondLogin = Read-R01WireFrame -Stream $secondStream
Assert-R01 -Condition ($secondLogin.opcode -eq 1) `
    -Message 'Server did not accept the second-session login frame.'
$secondStream.Dispose()
$idChangeStream = New-Object IO.MemoryStream
Send-R01IdChange -Stream $idChangeStream
$idChange = $idChangeStream.ToArray(); $idChangeStream.Dispose()
Assert-R01 -Condition ($idChange.Length -eq 10 -and
    $idChange[0] -eq 0xE3 -and $idChange[5] -eq 0x40) `
    -Message 'Controlled server IDCHANGE frame is malformed.'

$zipRoot = Join-Path ([IO.Path]::GetTempPath()) (
    'ese-r01-zip-' + [Guid]::NewGuid().ToString('N'))
$packageRoot = Join-Path $zipRoot 'package'
$nested = Join-Path $packageRoot 'config'
[IO.Directory]::CreateDirectory($nested) | Out-Null
try {
    [IO.File]::WriteAllBytes((Join-Path $packageRoot 'emule.exe'),
        [byte[]]@(1, 2, 3))
    [IO.File]::WriteAllBytes((Join-Path $packageRoot 'ese-server.exe'),
        [byte[]]@(4, 5, 6))
    [IO.File]::WriteAllText((Join-Path $packageRoot 'BUILD_INFO.txt'),
        "version: test`ncommit: $('1' * 40)`ndirty: false")
    [IO.File]::WriteAllText((Join-Path $nested 'preferences.ini'), '[eMule]')
    $zipPath = Join-Path $zipRoot 'candidate.zip'
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [IO.Compression.ZipFile]::CreateFromDirectory($packageRoot, $zipPath,
        [IO.Compression.CompressionLevel]::Optimal, $true)
    $zipCandidate = [pscustomobject]@{
        package_path = $packageRoot
        emule_sha256 = (Get-FileHash (Join-Path $packageRoot 'emule.exe') `
                -Algorithm SHA256).Hash.ToLowerInvariant()
        ese_server_sha256 = (Get-FileHash (
                Join-Path $packageRoot 'ese-server.exe') `
                -Algorithm SHA256).Hash.ToLowerInvariant()
        build_info_sha256 = (Get-FileHash (
                Join-Path $packageRoot 'BUILD_INFO.txt') `
                -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    $zipEvidence = Get-R01ZipPackageEvidence -ZipPath $zipPath `
        -Candidate $zipCandidate
    Assert-R01 -Condition ($zipEvidence.exact_file_set -and
        $zipEvidence.exact_bytes_and_sha256 -and
        $zipEvidence.file_count -eq 4 -and
        $zipEvidence.schema -ceq 'ese.v91.package-zip-binding/v3' -and
        $zipEvidence.locked_snapshot -and $zipEvidence.reparse_free -and
        $zipEvidence.zip_sha256 -match '^[0-9a-f]{64}$') `
        -Message 'Complete ZIP/package manifest did not bind.'

    $caseZip = Join-Path $zipRoot 'case-collision.zip'
    [IO.File]::Copy($zipPath, $caseZip)
    $caseArchive = [IO.Compression.ZipFile]::Open(
        $caseZip, [IO.Compression.ZipArchiveMode]::Update)
    try {
        $entry = $caseArchive.CreateEntry('package/EMULE.EXE')
        $stream = $entry.Open()
        try { $stream.WriteByte(9) } finally { $stream.Dispose() }
    } finally { $caseArchive.Dispose() }
    $caseRejected = $false
    try {
        $null = Get-R01ZipPackageEvidence -ZipPath $caseZip `
            -Candidate $zipCandidate
    } catch { $caseRejected = $_.Exception.Message -match 'case-colliding' }
    Assert-R01 $caseRejected 'ZIP case collision was not explicitly rejected.'

    $traversalZip = Join-Path $zipRoot 'traversal.zip'
    [IO.File]::Copy($zipPath, $traversalZip)
    $traversalArchive = [IO.Compression.ZipFile]::Open(
        $traversalZip, [IO.Compression.ZipArchiveMode]::Update)
    try {
        $entry = $traversalArchive.CreateEntry('package/../escape.txt')
        $stream = $entry.Open()
        try { $stream.WriteByte(9) } finally { $stream.Dispose() }
    } finally { $traversalArchive.Dispose() }
    $traversalRejected = $false
    try {
        $null = Get-R01ZipPackageEvidence -ZipPath $traversalZip `
            -Candidate $zipCandidate
    } catch { $traversalRejected = $_.Exception.Message -match 'Unsafe ZIP' }
    Assert-R01 $traversalRejected 'ZIP traversal entry was not explicitly rejected.'

    $symlinkZip = Join-Path $zipRoot 'symlink.zip'
    [IO.File]::Copy($zipPath, $symlinkZip)
    $symlinkArchive = [IO.Compression.ZipFile]::Open(
        $symlinkZip, [IO.Compression.ZipArchiveMode]::Update)
    try {
        $entry = $symlinkArchive.CreateEntry('package/link-to-outside')
        $entry.ExternalAttributes = -1577123840 # 0xA1FF0000, Unix symlink
        $stream = $entry.Open()
        try {
            $bytes = [Text.Encoding]::UTF8.GetBytes('../outside')
            $stream.Write($bytes, 0, $bytes.Length)
        } finally { $stream.Dispose() }
    } finally { $symlinkArchive.Dispose() }
    $symlinkRejected = $false
    try {
        $null = Get-R01ZipPackageEvidence -ZipPath $symlinkZip `
            -Candidate $zipCandidate
    } catch { $symlinkRejected = $_.Exception.Message -match 'Unsafe ZIP' }
    Assert-R01 $symlinkRejected 'ZIP symlink metadata was not rejected.'

    $outside = Join-Path $zipRoot 'outside'
    [IO.Directory]::CreateDirectory($outside) | Out-Null
    [IO.File]::WriteAllText((Join-Path $outside 'foreign.txt'), 'foreign')
    $junction = Join-Path $packageRoot 'junction'
    $null = New-Item -ItemType Junction -Path $junction -Target $outside `
        -ErrorAction Stop
    $reparseRejected = $false
    try {
        $null = Get-R01ZipPackageEvidence -ZipPath $zipPath `
            -Candidate $zipCandidate
    } catch { $reparseRejected = $_.Exception.Message -match 'reparse' }
    Assert-R01 $reparseRejected 'Package reparse point was not explicitly rejected.'
    [IO.Directory]::Delete($junction)

    [IO.File]::AppendAllText((Join-Path $nested 'preferences.ini'), 'changed')
    $mismatchRejected = $false
    try {
        $null = Get-R01ZipPackageEvidence -ZipPath $zipPath `
            -Candidate $zipCandidate
    } catch { $mismatchRejected = $true }
    Assert-R01 $mismatchRejected 'ZIP/package mismatch was accepted.'
} finally {
    Remove-Item -LiteralPath $zipRoot -Recurse -Force
}

$script:mappingLifecycleEvidence =
    [Collections.Generic.List[object]]::new()
$fakeMappings = [pscustomobject]@{ slots = @{} }
$fakeMappings | Add-Member ScriptMethod Item {
    param($port, $protocol)
    return $this.slots["$port/$protocol"]
}
$fakeMappings | Add-Member ScriptMethod Add {
    param($external, $protocol, $internal, $client, $enabled, $description)
    $this.slots["$external/$protocol"] = [pscustomobject]@{
        Description = $description; InternalClient = $client
        InternalPort = $internal; ExternalIPAddress = '198.18.0.1'
    }
    return $null
}
$fakeMappings | Add-Member ScriptMethod Remove {
    param($external, $protocol)
    $this.slots.Remove("$external/$protocol")
}
$rollbackRaised = $false
try {
    $null = Add-R01OwnedUpnpMapping -Mappings $fakeMappings `
        -ExternalPort 51901 -InternalPort 51901 `
        -InternalClient '192.168.1.2' -Description 'owned'
} catch { $rollbackRaised = $true }
Assert-R01 -Condition ($rollbackRaised -and
    $fakeMappings.slots.Count -eq 0 -and
    [bool]$script:mappingLifecycleEvidence[0].rollback_complete) `
    -Message 'UPnP Add validation rollback window is unsafe.'

$remoteText = Get-Content -LiteralPath $remotePath -Raw
$controllerText = Get-Content -LiteralPath $controllerPath -Raw
$agentText = Get-Content -LiteralPath $paths[4] -Raw
$watchdogText = Get-Content -LiteralPath $paths[2] -Raw
foreach ($pattern in @('EseNetLabEnabled\s*=\s*''0''',
        'Kad6BetaExitOptIn\s*=\s*''0''', 'home_restored',
        'timestamped_log_line_count', 'Get-NetFirewallApplicationFilter',
        'AutoStart\s*=\s*''0''', 'AutoTakeED2KLinks\s*=\s*''0''',
        'WatchClipboard4ED2kFilelinks\s*=\s*''0''',
        'OpenPortsOnStartUp\s*=\s*''0''',
        'Get-R01AccountRegistrySnapshot', 'expected_account_sid_sha256',
        'Assert-R01PackageManifestContract', 'FileShare\]::Read',
        'Start-R01IdentityBoundCandidate', 'Stop-R01IdentityBoundCandidate',
        'Remove-R01TreeNoReparse', 'Find-NetRoute',
        'Test-R01OverlayAdapter', 'Get-R01PortBaseline')) {
    Assert-R01 -Condition ($remoteText -match $pattern) `
        -Message "Remote R01 invariant missing: $pattern"
}
Assert-R01 -Condition ($agentText -match 'protocol\s*=\s*2' -and
    $agentText -match 'utc_now' -and
    $agentText -match 'cooperative_cancel') `
    -Message 'Agent ping v2 capability/clock contract is absent.'
$pingIndex = $controllerText.IndexOf('-Command ping')
$mutationIndex = $controllerText.IndexOf('HNetCfg.NATUPnP')
Assert-R01 -Condition ($pingIndex -ge 0 -and $mutationIndex -gt $pingIndex -and
    $controllerText -match 'clockBoundMs\s*-gt\s*1000') `
    -Message 'Clock/agent preflight is not before H1 mutation.'
Assert-R01 -Condition ($watchdogText -match 'home_restored' -and
    $remoteText -match 'Start-R01WifiWatchdog' -and
    $remoteText -match 'Complete-R01WifiWatchdog') `
    -Message 'Independent Home restore watchdog contract is absent.'
foreach ($name in @('package_zip_binding', 'upnp_mapping_lifecycle',
        'cooperative_remote_recovery',
        'requested_home_wlan_profile_sha256',
        'requested_hotspot_wlan_profile_sha256')) {
    Assert-R01 -Condition $controllerText.Contains($name) `
        -Message "Aggregate/manifest does not publish $name."
}
Assert-R01 -Condition ($controllerText.Contains(
        'HomeProfile and HotspotProfile must identify two non-empty, different saved WLAN profiles.')) `
    -Message 'Controller does not reject identical Home/hotspot profiles.'
Assert-R01 -Condition ($remoteText.Contains(
        'Home and hotspot must be different saved WLAN profiles.')) `
    -Message 'Remote runner does not reject identical Home/hotspot profiles.'
Assert-R01 -Condition ($remoteText.Contains(
        "if (`$failure -like 'R01_PRODUCT::*' -and `$mobileTopologyValidated)")) `
    -Message 'Product FAIL is not gated by proven roaming topology.'
Assert-R01 -Condition ($remoteText -notmatch
        'Get-Process\s+-Name\s+emule\s+`?\s*-ErrorAction\s+SilentlyContinue') `
    -Message 'Remote process preflight still treats collector failure as empty.'
Assert-R01 -Condition ($remoteText.Contains(
        'Get-R01FirewallRulesByNameFailClosed') -and
    $controllerText.Contains('Get-R01FirewallRulesByNameFailClosed') -and
    $remoteText.Contains('$LASTEXITCODE -ne 0')) `
    -Message 'Firewall/WLAN collectors are not fail-closed.'
Assert-R01 -Condition ($controllerText -match
        'Assert-R01PublicResultPrivacy' -and
    $controllerText -match 'ese\.v91\.r01-public-result/v1') `
    -Message 'R01 has no exact public privacy projection.'

[pscustomobject][ordered]@{
    schema = 'ese.v91.r01-offline-selftest/v2'
    case_id = 'V91-R01'
    status = 'PASS'
    formal_case_status = 'BLOCKED'
    physical_execution_performed = $false
    parsed_scripts = $paths.Count
    address_cases = $addressCases.Count
    address_implementations = 2
    address_assertions = $addressCases.Count * 2
    adjudication_cases = 16
    zip_manifest_cases = 6
    server_frame_sequence = 'login+post-login+EOF+second-login'
    cancellation_and_deadline = $true
    upnp_add_rollback = $true
    clock_preflight_before_mutation = $true
    independent_wifi_watchdog = $true
    account_registry_contract = $true
    process_identity_contract = $true
    route_overlay_contract = $true
    fail_closed_port_collectors = $true
    public_privacy_projection = $true
} | ConvertTo-Json -Depth 4
