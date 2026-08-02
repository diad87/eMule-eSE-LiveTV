[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('start', 'status', 'finalize')]
    [string]$Command,
    [string]$ManifestPath = '',
    [string]$OutputRoot = '',
    [ValidateSet('none', 'i01', 'i02', 'i08', 'k01', 'o01')]
    [string]$PostMode = 'none',
    [ValidateRange(60, 86400)][int]$DurationSeconds = 7200,
    [string]$CandidateExePath = '',
    [string]$H1AgentIPv4 = '',
    [string]$H3AgentIPv4 = '',
    [ValidateRange(1024, 65535)][int]$H1AgentPort = 8016,
    [ValidateRange(1024, 65535)][int]$H3AgentPort = 8015,
    [string]$H1TokenDpapiPath = (
        "$env:LOCALAPPDATA\eSE-Lab-Controller\h1-smallframe-token.dpapi"),
    [string]$H3TokenDpapiPath = (
        "$env:LOCALAPPDATA\eSE-Lab-Controller\smallframe-token.dpapi"),
    [string]$H1BaseNodePath = '',
    [string]$H3BaseNodeRelative = '',
    [ValidateRange(1, 2147483647)][int]$H1InterfaceIndex = 1,
    [ValidateRange(1, 2147483647)][int]$H3InterfaceIndex = 1,
    [string]$H1InterfaceAlias = 'Ethernet',
    [string]$H3InterfaceAlias = 'Wi-Fi',
    [string]$H1LocalIPv6 = '',
    [string]$H3LocalIPv6 = '',
    [string]$K01SecondaryIPv6 = '',
    [string]$K01GuardIPv6 = '',
    [string]$FixturePath = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
if ([string]::IsNullOrWhiteSpace($OutputRoot)) {
    $OutputRoot = Join-Path $PSScriptRoot '..\..\lab-runs\v91-k04'
}
$controller = Join-Path $PSScriptRoot (
    'control_ese_lab_smallframe_agent.ps1')
$runner = Join-Path $PSScriptRoot 'run_v91_k04_node.ps1'
$ipv4Probe = Join-Path $PSScriptRoot 'probe_physical_ipv4_remote.ps1'

function Invoke-K04Agent {
    param(
        [Parameter(Mandatory = $true)][string]$HostRole,
        [Parameter(Mandatory = $true)][string]$AgentCommand,
        [Parameter(Mandatory = $true)]$Manifest,
        [hashtable]$Extra = @{}
    )
    $isH1 = $HostRole -ceq 'h1'
    $node = if ($isH1) { $Manifest.h1 } else { $Manifest.h3 }
    $arguments = @{
        Command = $AgentCommand
        AgentIPv4 = [string]$node.agent_ipv4
        Port = [int]$node.agent_port
        TokenDpapiPath = if ($isH1) {
            $H1TokenDpapiPath
        } else {
            $H3TokenDpapiPath
        }
    }
    foreach ($key in $Extra.Keys) {
        $arguments[$key] = $Extra[$key]
    }
    & $controller @arguments
}

function Get-O01PhysicalIPv4 {
    param(
        [Parameter(Mandatory = $true)][string]$HostRole,
        [Parameter(Mandatory = $true)][int]$InterfaceIndex,
        [Parameter(Mandatory = $true)]$Manifest,
        [Parameter(Mandatory = $true)][string]$RunRoot
    )
    $probeJob = [Guid]::NewGuid().ToString('N')
    $requestPath = Join-Path $RunRoot "$HostRole-ipv4-probe-request.json"
    @{ interface_index = $InterfaceIndex } | ConvertTo-Json |
        Set-Content -LiteralPath $requestPath -Encoding UTF8
    $remote = "injected/$probeJob/probe_physical_ipv4_remote.ps1"
    Invoke-K04Agent -HostRole $HostRole -AgentCommand upload `
        -Manifest $Manifest -Extra @{
            SourcePath = $ipv4Probe
            RemotePath = $remote
        } | Out-Null
    Invoke-K04Agent -HostRole $HostRole -AgentCommand run `
        -Manifest $Manifest -Extra @{
            JobId = $probeJob
            RemotePath = $remote
            JobRequestPath = $requestPath
        } | Out-Null
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds(30)
    do {
        Start-Sleep -Milliseconds 500
        $state = Invoke-K04Agent -HostRole $HostRole -AgentCommand job `
            -Manifest $Manifest -Extra @{ JobId = $probeJob }
        if ([string]$state.state -ceq 'COMPLETE') { break }
        if ([string]$state.state -in @('ERROR', 'STOPPED')) {
            throw "Physical IPv4 probe failed on $HostRole."
        }
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    if ([string]$state.state -cne 'COMPLETE' -or [int]$state.exit_code -ne 0) {
        throw "Physical IPv4 probe timed out on $HostRole."
    }
    $resultPath = Join-Path $RunRoot "$HostRole-ipv4-probe-result.json"
    Invoke-K04Agent -HostRole $HostRole -AgentCommand download `
        -Manifest $Manifest -Extra @{
            RemotePath = "jobs/$probeJob/ipv4-probe.json"
            OutputPath = $resultPath
        } | Out-Null
    $result = Get-Content -LiteralPath $resultPath -Raw | ConvertFrom-Json
    if ([string]$result.status -cne 'PASS' -or
        [string]$result.address -notmatch '^\d{1,3}(?:\.\d{1,3}){3}$') {
        throw "Physical IPv4 probe returned invalid evidence on $HostRole."
    }
    return [string]$result.address
}

if ($Command -ceq 'start') {
    foreach ($required in @{
            CandidateExePath = $CandidateExePath
            H1AgentIPv4 = $H1AgentIPv4
            H3AgentIPv4 = $H3AgentIPv4
            H1BaseNodePath = $H1BaseNodePath
            H3BaseNodeRelative = $H3BaseNodeRelative
            H1LocalIPv6 = $H1LocalIPv6
            H3LocalIPv6 = $H3LocalIPv6
        }.GetEnumerator()) {
        if ([string]::IsNullOrWhiteSpace([string]$required.Value)) {
            throw "$($required.Key) is required for start."
        }
    }
    if ($PostMode -in @('i01', 'o01') -and
        [string]::IsNullOrWhiteSpace($FixturePath)) {
        throw 'FixturePath is required for i01 and o01.'
    }
    if ($PostMode -ceq 'k01' -and
        ([string]::IsNullOrWhiteSpace($K01SecondaryIPv6) -or
         [string]::IsNullOrWhiteSpace($K01GuardIPv6))) {
        throw 'K01SecondaryIPv6 and K01GuardIPv6 are required for k01.'
    }
    $candidateFullPath = [IO.Path]::GetFullPath($CandidateExePath)
    if (-not (Test-Path -LiteralPath $candidateFullPath -PathType Leaf)) {
        throw "CandidateExePath is missing: $candidateFullPath"
    }
    $candidateHash = (Get-FileHash -LiteralPath $candidateFullPath `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    $runId = [Guid]::NewGuid().ToString('N')
    $runRoot = Join-Path ([IO.Path]::GetFullPath($OutputRoot)) $runId
    New-Item -ItemType Directory -Path $runRoot -Force | Out-Null
    $h1Job = [Guid]::NewGuid().ToString('N')
    $h3Job = [Guid]::NewGuid().ToString('N')
    $manifest = [ordered]@{
        schema = 'ese.v91.k04-manifest/v1'
        run_id = $runId
        created_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
        run_root = $runRoot
        candidate_sha256 = $candidateHash
        h1 = [ordered]@{
            job_id = $h1Job
            agent_ipv4 = $H1AgentIPv4
            agent_port = $H1AgentPort
            request = Join-Path $runRoot 'h1-request.json'
        }
        h3 = [ordered]@{
            job_id = $h3Job
            agent_ipv4 = $H3AgentIPv4
            agent_port = $H3AgentPort
            request = Join-Path $runRoot 'h3-request.json'
        }
    }
    $ManifestPath = Join-Path $runRoot 'manifest.json'
    $manifest | ConvertTo-Json -Depth 8 |
        Set-Content -LiteralPath $ManifestPath -Encoding UTF8

    $h1Request = [ordered]@{
        base_node_path = [IO.Path]::GetFullPath($H1BaseNodePath)
        candidate_exe_path = $candidateFullPath
        local_ipv6 = $H1LocalIPv6
        peer_ipv6 = $H3LocalIPv6
        interface_index = $H1InterfaceIndex
        interface_alias = $H1InterfaceAlias
        tcp_port = 48062
        udp_port = 48072
        web_port = 48111
        peer_udp_port = 48272
        role = 'bootstrap'
        capture_enabled = $true
        exe_sha256 = $manifest.candidate_sha256
    }
    $h3Request = [ordered]@{
        base_node_relative = $H3BaseNodeRelative
        candidate_exe_relative = "candidates/$candidateHash/emule.exe"
        local_ipv6 = $H3LocalIPv6
        peer_ipv6 = $H1LocalIPv6
        interface_index = $H3InterfaceIndex
        interface_alias = $H3InterfaceAlias
        tcp_port = 48262
        udp_port = 48272
        web_port = 48311
        peer_udp_port = 48072
        role = 'listener'
        capture_enabled = $false
        exe_sha256 = $manifest.candidate_sha256
    }
    if ($PostMode -ceq 'i01') {
        $fixture = [ordered]@{
            name = 'v91-i05-canonical-4294967296.bin'
            bytes = 4294967296L
            sha256 =
                '1016d6f63ae1649a879a7c0de30865ed132deb37b1c3b2bc9ca004c88feee26c'
            ed2k = '796A95E75DF8E78D54A57CDEA1FEDE84'
        }
        $h1Request.post_action = 'i01-source'
        $h1Request.duration_seconds = $DurationSeconds
        $h1Request.peer_tcp_port = 48262
        $h1Request.control_port = 48904
        $h1Request.fixture_path = [IO.Path]::GetFullPath($FixturePath)
        $h3Request.post_action = 'i01-downloader'
        $h3Request.duration_seconds = $DurationSeconds
        $h3Request.peer_tcp_port = 48062
        $h3Request.control_port = 48904
        foreach ($requestObject in @($h1Request, $h3Request)) {
            $requestObject.fixture_name = $fixture.name
            $requestObject.fixture_bytes = $fixture.bytes
            $requestObject.fixture_sha256 = $fixture.sha256
            $requestObject.fixture_ed2k = $fixture.ed2k
        }
        $manifest | Add-Member -NotePropertyName post_mode `
            -NotePropertyValue 'i01'
        $manifest | Add-Member -NotePropertyName duration_seconds `
            -NotePropertyValue $DurationSeconds
        $manifest | Add-Member -NotePropertyName fixture `
            -NotePropertyValue $fixture
        $manifest | ConvertTo-Json -Depth 8 |
            Set-Content -LiteralPath $ManifestPath -Encoding UTF8
    }
    if ($PostMode -ceq 'i02') {
        $h1Request.post_action = 'i02-source'
        $h1Request.duration_seconds = $DurationSeconds
        $h1Request.peer_tcp_port = 48262
        $h1Request.control_port = 48902
        $h3Request.post_action = 'i02-viewer'
        $h3Request.duration_seconds = $DurationSeconds
        $h3Request.peer_tcp_port = 48062
        $h3Request.control_port = 48902
        $manifest | Add-Member -NotePropertyName post_mode `
            -NotePropertyValue 'i02'
        $manifest | Add-Member -NotePropertyName duration_seconds `
            -NotePropertyValue $DurationSeconds
        $manifest | ConvertTo-Json -Depth 8 |
            Set-Content -LiteralPath $ManifestPath -Encoding UTF8
    }
    if ($PostMode -ceq 'o01') {
        $h1IPv4 = Get-O01PhysicalIPv4 -HostRole h1 `
            -InterfaceIndex $H1InterfaceIndex `
            -Manifest $manifest -RunRoot $runRoot
        $h3IPv4 = Get-O01PhysicalIPv4 -HostRole h3 `
            -InterfaceIndex $H3InterfaceIndex `
            -Manifest $manifest -RunRoot $runRoot
        $fixture = [ordered]@{
            name = 'v91-i05-canonical-4294967296.bin'
            bytes = 4294967296L
            sha256 =
                '1016d6f63ae1649a879a7c0de30865ed132deb37b1c3b2bc9ca004c88feee26c'
            ed2k = '796A95E75DF8E78D54A57CDEA1FEDE84'
        }
        $h1Request.post_action = 'o01-source'
        $h1Request.duration_seconds = $DurationSeconds
        $h1Request.peer_tcp_port = 48262
        $h1Request.control_port = 48905
        $h1Request.local_ipv4 = $h1IPv4
        $h1Request.peer_ipv4 = $h3IPv4
        $h1Request.capture_enabled = $false
        $h1Request.fixture_path = [IO.Path]::GetFullPath($FixturePath)
        $h3Request.post_action = 'o01-viewer'
        $h3Request.duration_seconds = $DurationSeconds
        $h3Request.peer_tcp_port = 48062
        $h3Request.control_port = 48905
        $h3Request.local_ipv4 = $h3IPv4
        $h3Request.peer_ipv4 = $h1IPv4
        $h3Request.capture_enabled = $false
        foreach ($requestObject in @($h1Request, $h3Request)) {
            $requestObject.fixture_name = $fixture.name
            $requestObject.fixture_bytes = $fixture.bytes
            $requestObject.fixture_sha256 = $fixture.sha256
            $requestObject.fixture_ed2k = $fixture.ed2k
        }
        $manifest | Add-Member -NotePropertyName post_mode `
            -NotePropertyValue 'o01'
        $manifest | Add-Member -NotePropertyName duration_seconds `
            -NotePropertyValue $DurationSeconds
        $manifest | Add-Member -NotePropertyName fixture `
            -NotePropertyValue $fixture
        $manifest | ConvertTo-Json -Depth 8 |
            Set-Content -LiteralPath $ManifestPath -Encoding UTF8
    }
    if ($PostMode -ceq 'k01') {
        $h1Request.post_action = 'k01-source'
        $h1Request.peer_tcp_port = 48262
        $h1Request.control_port = 48901
        $h1Request.secondary_ipv6 = $K01SecondaryIPv6
        $h1Request.secondary_tcp_port = 48462
        $h1Request.secondary_udp_port = 48472
        $h1Request.secondary_web_port = 48511
        $h1Request.guard_ipv6 = $K01GuardIPv6
        $h1Request.guard_tcp_port = 48662
        $h1Request.guard_udp_port = 48672
        $h1Request.guard_web_port = 48711
        $h3Request.post_action = 'k01-requester'
        $h3Request.peer_tcp_port = 48062
        $h3Request.control_port = 48901
        $h3Request.secondary_ipv6 = $K01SecondaryIPv6
        $h3Request.secondary_tcp_port = 48462
        $h3Request.secondary_udp_port = 48472
        $h3Request.secondary_web_port = 48511
        $h3Request.guard_ipv6 = $K01GuardIPv6
        $h3Request.guard_udp_port = 48672
        $manifest | Add-Member -NotePropertyName post_mode `
            -NotePropertyValue 'k01'
        $manifest | ConvertTo-Json -Depth 8 |
            Set-Content -LiteralPath $ManifestPath -Encoding UTF8
    }
    if ($PostMode -ceq 'i08') {
        $nonce = [Guid]::NewGuid().ToString('N')
        $h1Request.post_action = 'i08-server'
        $h1Request.control_port = 48903
        $h1Request.echo_tcp_port = 48808
        $h1Request.echo_udp_port = 48809
        $h1Request.nonce = $nonce
        $h3Request.post_action = 'i08-client'
        $h3Request.control_port = 48903
        $h3Request.echo_tcp_port = 48808
        $h3Request.echo_udp_port = 48809
        $h3Request.nonce = $nonce
        $manifest | Add-Member -NotePropertyName post_mode `
            -NotePropertyValue 'i08'
        $manifest | Add-Member -NotePropertyName nonce `
            -NotePropertyValue $nonce
        $manifest | ConvertTo-Json -Depth 8 |
            Set-Content -LiteralPath $ManifestPath -Encoding UTF8
    }
    $h1Request | ConvertTo-Json | Set-Content -LiteralPath $manifest.h1.request `
        -Encoding UTF8
    $h3Request | ConvertTo-Json | Set-Content -LiteralPath $manifest.h3.request `
        -Encoding UTF8

    $h1Entrypoint = "injected/$h1Job/run_v91_k04_node.ps1"
    $h3Entrypoint = "injected/$h3Job/run_v91_k04_node.ps1"
    Invoke-K04Agent -HostRole h1 -AgentCommand upload -Manifest $manifest `
        -Extra @{
            SourcePath = $runner
            RemotePath = $h1Entrypoint
        } | Out-Null
    Invoke-K04Agent -HostRole h3 -AgentCommand upload -Manifest $manifest `
        -Extra @{
            SourcePath = $runner
            RemotePath = $h3Entrypoint
        } | Out-Null
    Invoke-K04Agent -HostRole h3 -AgentCommand run -Manifest $manifest `
        -Extra @{
            JobId = $h3Job
            RemotePath = $h3Entrypoint
            JobRequestPath = $manifest.h3.request
        } | Out-Null
    Start-Sleep -Seconds 1
    Invoke-K04Agent -HostRole h1 -AgentCommand run -Manifest $manifest `
        -Extra @{
            JobId = $h1Job
            RemotePath = $h1Entrypoint
            JobRequestPath = $manifest.h1.request
        } | Out-Null
    [pscustomobject]@{
        state = 'STARTED'
        run_id = $runId
        manifest = $ManifestPath
        h1_job = $h1Job
        h3_job = $h3Job
    }
    exit 0
}

if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) {
    throw 'status/finalize require a valid ManifestPath.'
}
$manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json

if ($Command -ceq 'status') {
    $h1 = Invoke-K04Agent -HostRole h1 -AgentCommand job `
        -Manifest $manifest -Extra @{ JobId = [string]$manifest.h1.job_id }
    $h3 = Invoke-K04Agent -HostRole h3 -AgentCommand job `
        -Manifest $manifest -Extra @{ JobId = [string]$manifest.h3.job_id }
    [pscustomobject]@{
        run_id = [string]$manifest.run_id
        h1_state = [string]$h1.state
        h1_exit_code = if (
            $null -ne $h1.PSObject.Properties['exit_code']
        ) { $h1.exit_code } else { $null }
        h3_state = [string]$h3.state
        h3_exit_code = if (
            $null -ne $h3.PSObject.Properties['exit_code']
        ) { $h3.exit_code } else { $null }
    }
    exit 0
}

$runRoot = [string]$manifest.run_root
$h1ResultPath = Join-Path $runRoot 'h1-result.json'
$h3ResultPath = Join-Path $runRoot 'h3-result.json'
Invoke-K04Agent -HostRole h1 -AgentCommand download -Manifest $manifest `
    -Extra @{
        RemotePath = "jobs/$($manifest.h1.job_id)/k04-result.json"
        OutputPath = $h1ResultPath
    } | Out-Null
Invoke-K04Agent -HostRole h3 -AgentCommand download -Manifest $manifest `
    -Extra @{
        RemotePath = "jobs/$($manifest.h3.job_id)/k04-result.json"
        OutputPath = $h3ResultPath
    } | Out-Null
$h1Result = Get-Content -LiteralPath $h1ResultPath -Raw | ConvertFrom-Json
$h3Result = Get-Content -LiteralPath $h3ResultPath -Raw | ConvertFrom-Json
$automatedPass = (
    [string]$h1Result.status -ceq 'PASS' -and
    [string]$h3Result.status -ceq 'PASS' -and
    [int]$h1Result.before_restart.verified -gt 0 -and
    [int]$h3Result.before_restart.verified -gt 0 -and
    [int]$h1Result.after_restart_blocked.verified -eq 0 -and
    [int]$h3Result.after_restart_blocked.verified -eq 0 -and
    [int]$h1Result.after_fresh_reverification.verified -gt 0 -and
    [int]$h3Result.after_fresh_reverification.verified -gt 0 -and
    [string]$h1Result.candidate.exe_sha256 -ceq
        [string]$manifest.candidate_sha256 -and
    [string]$h3Result.candidate.exe_sha256 -ceq
        [string]$manifest.candidate_sha256
)
$isK01 = (
    $null -ne $manifest.PSObject.Properties['post_mode'] -and
    [string]$manifest.post_mode -ceq 'k01')
$isI01 = (
    $null -ne $manifest.PSObject.Properties['post_mode'] -and
    [string]$manifest.post_mode -ceq 'i01')
$isI08 = (
    $null -ne $manifest.PSObject.Properties['post_mode'] -and
    [string]$manifest.post_mode -ceq 'i08')
$isO01 = (
    $null -ne $manifest.PSObject.Properties['post_mode'] -and
    [string]$manifest.post_mode -ceq 'o01')
if ($isI01) {
    $automatedPass = (
        $automatedPass -and
        [string]$h1Result.post_action.case_id -ceq 'V91-I01' -and
        [string]$h3Result.post_action.case_id -ceq 'V91-I01' -and
        [string]$h1Result.post_action.status -ceq 'PASS' -and
        [string]$h3Result.post_action.status -ceq 'PASS' -and
        [string]$h1Result.post_action.role -ceq 'source' -and
        [string]$h3Result.post_action.role -ceq 'downloader' -and
        [string]$h1Result.post_action.candidate_sha256 -ceq
            [string]$manifest.candidate_sha256 -and
        [string]$h3Result.post_action.candidate_sha256 -ceq
            [string]$manifest.candidate_sha256 -and
        [Int64]$h1Result.post_action.fixture.bytes -eq
            [Int64]$manifest.fixture.bytes -and
        [Int64]$h3Result.post_action.fixture.bytes -eq
            [Int64]$manifest.fixture.bytes -and
        [string]$h1Result.post_action.fixture.sha256 -ceq
            [string]$manifest.fixture.sha256 -and
        [string]$h3Result.post_action.fixture.sha256 -ceq
            [string]$manifest.fixture.sha256 -and
        [string]$h1Result.post_action.fixture.ed2k -ceq
            [string]$manifest.fixture.ed2k -and
        [string]$h1Result.post_action.fixture.local_ed2k -ceq
            [string]$manifest.fixture.ed2k -and
        [string]$h3Result.post_action.fixture.ed2k -ceq
            [string]$manifest.fixture.ed2k -and
        [string]$h1Result.post_action.transport.family -ceq 'IPv6' -and
        [string]$h3Result.post_action.transport.family -ceq 'IPv6' -and
        [string]$h1Result.post_action.transport.source_ipv6 -ceq
            [string]$h1Result.candidate.ipv6 -and
        [string]$h3Result.post_action.transport.source_ipv6 -ceq
            [string]$h1Result.candidate.ipv6 -and
        [bool]$h3Result.post_action.transport.ipv6_peer_observed -and
        -not [bool]$h3Result.post_action.transport.ipv4_peer_observed -and
        [bool]$h1Result.post_action.transport.ipv4_blocked_by_owned_firewall -and
        [bool]$h3Result.post_action.transport.ipv4_blocked_by_owned_firewall -and
        [bool]$h3Result.post_action.api_responsive
    )
}
if ($isK01) {
    $automatedPass = (
        $automatedPass -and
        [string]$h1Result.post_action.case_id -ceq 'V91-K01' -and
        [string]$h3Result.post_action.case_id -ceq 'V91-K01' -and
        [string]$h1Result.post_action.status -ceq 'PASS' -and
        [string]$h3Result.post_action.status -ceq 'PASS' -and
        [string]$h1Result.post_action.role -ceq 'source' -and
        [string]$h3Result.post_action.role -ceq 'requester' -and
        [int]$h1Result.post_action.circuit.active.hop_count -ge 2 -and
        [int]$h3Result.post_action.circuit.active.hop_count -ge 2 -and
        [bool]$h1Result.post_action.circuit.active.auth_ok -and
        [bool]$h3Result.post_action.circuit.active.auth_ok -and
        [Int64]$h1Result.post_action.hardening_after.source_pipeline.advertised `
            -gt [Int64]$h1Result.post_action.hardening_before.source_pipeline.advertised -and
        [Int64]$h3Result.post_action.hardening_after.source_pipeline.recovered `
            -gt [Int64]$h3Result.post_action.hardening_before.source_pipeline.recovered
    )
}
if ($isI08) {
    $target = [Net.IPAddress]::Parse(
        [string]$h1Result.candidate.ipv6)
    $peer = [Net.IPAddress]::Parse(
        [string]$h3Result.candidate.ipv6)
    $targetHex = (
        [BitConverter]::ToString($target.GetAddressBytes())
    ).Replace('-', '').ToLowerInvariant()
    $peerHex = (
        [BitConverter]::ToString($peer.GetAddressBytes())
    ).Replace('-', '').ToLowerInvariant()
    $tcpRemoteHex = (
        [BitConverter]::ToString(
            [Net.IPAddress]::Parse(
                [string]$h1Result.post_action.fixture.tcp.remote_address
            ).GetAddressBytes())
    ).Replace('-', '').ToLowerInvariant()
    $udpRemoteHex = (
        [BitConverter]::ToString(
            [Net.IPAddress]::Parse(
                [string]$h1Result.post_action.fixture.udp.remote_address
            ).GetAddressBytes())
    ).Replace('-', '').ToLowerInvariant()
    $clientTargetHex = (
        [BitConverter]::ToString(
            [Net.IPAddress]::Parse(
                [string]$h3Result.post_action.client_action.target
            ).GetAddressBytes())
    ).Replace('-', '').ToLowerInvariant()
    $fixturePayload = [string](
        $h1Result.post_action.fixture.expected_payload)
    $payloadMatch = [regex]::Match(
        $fixturePayload,
        '^ese-v91-i08-v1:([0-9a-f]{32})\|target=([0-9a-fA-F:]+)$')
    $payloadTargetHex = ''
    if ($payloadMatch.Success) {
        $payloadTargetHex = (
            [BitConverter]::ToString(
                [Net.IPAddress]::Parse(
                    $payloadMatch.Groups[2].Value).GetAddressBytes())
        ).Replace('-', '').ToLowerInvariant()
    }
    $automatedPass = (
        $automatedPass -and
        [string]$h1Result.post_action.case_id -ceq 'V91-I08' -and
        [string]$h3Result.post_action.case_id -ceq 'V91-I08' -and
        [string]$h1Result.post_action.status -ceq 'PASS' -and
        [string]$h3Result.post_action.status -ceq 'PASS' -and
        [string]$h1Result.post_action.role -ceq 'echo_fixture' -and
        [string]$h3Result.post_action.role -ceq 'client' -and
        [string]$h1Result.post_action.fixture.nonce -ceq
            [string]$manifest.nonce -and
        [string]$h3Result.post_action.client_action.nonce -ceq
            [string]$manifest.nonce -and
        $payloadMatch.Success -and
        $payloadMatch.Groups[1].Value -ceq [string]$manifest.nonce -and
        $payloadTargetHex -ceq $targetHex -and
        [string]$h1Result.post_action.fixture.tcp.local_address_hex -ceq
            $targetHex -and
        [string]$h1Result.post_action.fixture.udp.local_address_hex -ceq
            $targetHex -and
        $tcpRemoteHex -ceq $peerHex -and
        $udpRemoteHex -ceq $peerHex -and
        $clientTargetHex -ceq $targetHex -and
        [string]$h1Result.post_action.fixture.tcp.sha256 -ceq
            [string]$h1Result.post_action.fixture.udp.sha256 -and
        [int]$h1Result.post_action.fixture.tcp.bytes -eq
            [int]$h3Result.post_action.client_action.tcp.bytes -and
        [int]$h1Result.post_action.fixture.udp.bytes -eq
            [int]$h3Result.post_action.client_action.udp.bytes -and
        [bool]$h3Result.post_action.client_action.success -and
        [int]$h3Result.post_action.client_action.tcp.error -eq 0 -and
        [int]$h3Result.post_action.client_action.udp.error -eq 0
    )
}
$o01Preflight = $false
if ($isO01) {
    $o01Preflight = [int]$manifest.duration_seconds -lt 43200
    $expectedNodeStatus = if ($o01Preflight) {
        'PREFLIGHT_PASS'
    } else { 'PASS' }
    $automatedPass = (
        [string]$h1Result.status -ceq 'PASS' -and
        [string]$h3Result.status -ceq 'PASS' -and
        [string]$h1Result.candidate.exe_sha256 -ceq
            [string]$manifest.candidate_sha256 -and
        [string]$h3Result.candidate.exe_sha256 -ceq
            [string]$manifest.candidate_sha256 -and
        [string]$h1Result.post_action.case_id -ceq 'V91-O01' -and
        [string]$h3Result.post_action.case_id -ceq 'V91-O01' -and
        [string]$h1Result.post_action.status -ceq $expectedNodeStatus -and
        [string]$h3Result.post_action.status -ceq $expectedNodeStatus -and
        [string]$h1Result.post_action.role -ceq 'source' -and
        [string]$h3Result.post_action.role -ceq 'viewer' -and
        [int]$h1Result.post_action.requested_duration_seconds -eq
            [int]$manifest.duration_seconds -and
        [int]$h3Result.post_action.requested_duration_seconds -eq
            [int]$manifest.duration_seconds -and
        [bool]$h1Result.post_action.peer_route_seen -and
        [bool]$h3Result.post_action.peer_route_seen -and
        [bool]$h1Result.post_action.ipv4_peer_seen -and
        [bool]$h3Result.post_action.ipv4_peer_seen -and
        [bool]$h1Result.post_action.playlist_seen -and
        [bool]$h3Result.post_action.playlist_seen -and
        [bool]$h1Result.post_action.segment_seen -and
        [bool]$h3Result.post_action.segment_seen -and
        [Int64]$h3Result.post_action.final_chunks -gt
            [Int64]$h3Result.post_action.initial_chunks -and
        [Int64]$h1Result.post_action.resource_growth.working_set_bytes -le
            268435456L -and
        [Int64]$h3Result.post_action.resource_growth.working_set_bytes -le
            268435456L -and
        [int]$h1Result.post_action.resource_growth.handles -le 1024 -and
        [int]$h3Result.post_action.resource_growth.handles -le 1024 -and
        [double]$h3Result.post_action.duplicate_delta_ratio -le 0.25 -and
        [double]$h3Result.post_action.cumulative_ratio_drift -le 0.05 -and
        [Int64]$h1Result.post_action.fixture.bytes -eq
            [Int64]$manifest.fixture.bytes -and
        [Int64]$h3Result.post_action.fixture.bytes -eq
            [Int64]$manifest.fixture.bytes -and
        [string]$h1Result.post_action.fixture.local_sha256 -ceq
            [string]$manifest.fixture.sha256 -and
        [string]$h3Result.post_action.fixture.local_sha256 -ceq
            [string]$manifest.fixture.sha256 -and
        [string]$h1Result.post_action.fixture.local_ed2k -ceq
            [string]$manifest.fixture.ed2k -and
        [string]$h3Result.post_action.fixture.local_ed2k -ceq
            [string]$manifest.fixture.ed2k -and
        [string]$h1Result.post_action.fixture.transport_family -ceq 'IPv4' -and
        [string]$h3Result.post_action.fixture.transport_family -ceq 'IPv4' -and
        [string]$h1Result.post_action.live_transport.family -ceq 'IPv6' -and
        [string]$h3Result.post_action.live_transport.family -ceq 'IPv6'
    )
}
$aggregate = [ordered]@{
    schema = if ($isI01) {
        'ese.v91.i01-aggregate/v1'
    } elseif ($isK01) {
        'ese.v91.k01-aggregate/v1'
    } elseif ($isI08) {
        'ese.v91.i08-aggregate/v1'
    } elseif ($isO01) {
        'ese.v91.o01-aggregate/v1'
    } else { 'ese.v91.k04-aggregate/v1' }
    case_id = if ($isI01) {
        'V91-I01'
    } elseif ($isK01) {
        'V91-K01'
    } elseif ($isI08) {
        'V91-I08'
    } elseif ($isO01) {
        'V91-O01'
    } else { 'V91-K04' }
    status = if (-not $automatedPass) {
        'REVIEW_REQUIRED'
    } elseif ($isO01 -and $o01Preflight) {
        'PREFLIGHT_PASS'
    } else { 'PASS' }
    completed_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
    manifest = $ManifestPath
    candidate_sha256 = [string]$manifest.candidate_sha256
    h1 = $h1Result
    h3 = $h3Result
}
$aggregatePath = Join-Path $runRoot 'aggregate-result.json'
$aggregate | ConvertTo-Json -Depth 14 |
    Set-Content -LiteralPath $aggregatePath -Encoding UTF8
$aggregate
