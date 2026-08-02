[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$runner = Join-Path $PSScriptRoot 'run_v91_i05_downloader_kit.ps1'
$cleanup = Join-Path $PSScriptRoot 'cleanup_v91_i05_downloader.ps1'
$preparer = Join-Path $PSScriptRoot 'prepare_v91_i05_downloader_kit.ps1'
$contract = Join-Path $PSScriptRoot 'v91_i05_t1_contract.ps1'
$common = Join-Path $PSScriptRoot 'common.ps1'
$fixtureVerifier = Join-Path $PSScriptRoot `
    'ensure_v91_i05_canonical_fixture.ps1'

foreach ($path in @(
    $runner, $cleanup, $preparer, $contract, $fixtureVerifier
)) {
    $tokens = $null
    $errors = $null
    $null = [Management.Automation.Language.Parser]::ParseFile(
        $path, [ref]$tokens, [ref]$errors)
    if ($errors.Count -ne 0) {
        throw "Parser error in $path`: $($errors[0].Message)"
    }
}

. $common
. $contract
$previousLibraryOnly = $env:ESE_V91_I05_LIBRARY_ONLY
try {
    $env:ESE_V91_I05_LIBRARY_ONLY = '1'
    . $runner
} finally {
    $env:ESE_V91_I05_LIBRARY_ONLY = $previousLibraryOnly
}
$mutationState = [ordered]@{
    peer_firewall = 'NOT_STARTED'
    control_firewall = 'NOT_STARTED'
    containment_firewall = 'NOT_STARTED'
    pktmon_filters = 'NOT_STARTED'
    pktmon_session = 'NOT_STARTED'
    candidate_process = 'NOT_STARTED'
}
$mutationCopy = Copy-I05MutationState -State $mutationState
$mutationState.peer_firewall = 'MUTATED'
if ($mutationCopy.Count -ne 6 -or
    [string]$mutationCopy.peer_firewall -cne 'NOT_STARTED' -or
    (Get-Content -LiteralPath $runner -Raw) -match '\.Clone\s*\(') {
    throw 'The PowerShell 5.1 mutation-state copy self-test failed.'
}
$filterRowsArmed = @(
    'Filtros de paquete:',
    '  1 ese-i05-test-v4-data TCP 192.168.222.60 7862',
    '  2 ese-i05-test-v6-src-tcp IPv6 TCP 7862'
)
$filterRowsBeforeReset = @(
    'Packet filters:',
    '  2   ese-i05-test-v6-src-tcp  IPv6 TCP  7862',
    '  1 ese-i05-test-v4-data   TCP 192.168.222.60 7862'
)
Assert-I05PktMonFilterRowsExact `
    -ExpectedLines $filterRowsArmed -ActualLines $filterRowsBeforeReset
foreach ($invalidFilterRows in @(
    @($filterRowsBeforeReset +
        '  3 foreign-filter IPv4 UDP 53'),
    @(
        '  1 ese-i05-test-v4-data TCP 192.168.222.60 9999',
        '  2 ese-i05-test-v6-src-tcp IPv6 TCP 7862'
    )
)) {
    try {
        Assert-I05PktMonFilterRowsExact `
            -ExpectedLines $filterRowsArmed -ActualLines $invalidFilterRows
        throw 'Expected semantic PktMon inventory rejection.'
    } catch {
        if ($_.Exception.Message -cne
            'El inventario PktMon cambio mientras la captura estaba activa.') {
            throw
        }
    }
}
$iniSelftestPath = Join-Path ([IO.Path]::GetTempPath()) (
    'v91-i05-ini-selftest-' + [Guid]::NewGuid().ToString('N') + '.ini')
try {
    [IO.File]::WriteAllText(
        $iniSelftestPath,
        "[eMule]`r`nIPv6Mode=0`r`nKadNetworkMask=0`r`n",
        (New-Object Text.UTF8Encoding($false)))
    if ((Get-I05IniValue -Path $iniSelftestPath -Section 'eMule' `
            -Key 'IPv6Mode') -cne '0') {
        throw 'The PowerShell 5.1 INI regex-state self-test failed.'
    }
} finally {
    Remove-Item -LiteralPath $iniSelftestPath -Force `
        -ErrorAction SilentlyContinue
}
$mutexNonce = [Guid]::NewGuid().ToString('N').ToLowerInvariant()
try {
    Enter-I05SingleInstance -RunNonce $mutexNonce
    $childMutexCommand = @'
$mutex = [Threading.Mutex]::new($false, '__MUTEX_NAME__')
try {
    if ($mutex.WaitOne(0, $false)) {
        $mutex.ReleaseMutex()
        exit 1
    }
    exit 0
} finally {
    $mutex.Dispose()
}
'@.Replace(
        '__MUTEX_NAME__', "Local\eSE-V91-I05-H3-$mutexNonce")
    & powershell.exe -NoProfile -Command $childMutexCommand
    if ($LASTEXITCODE -ne 0) {
        throw 'The second H3 instance was not rejected.'
    }
} finally {
    Exit-I05SingleInstance
}
$runnerTextForOperator = Get-Content -LiteralPath $runner -Raw
$startTextForOperator = Get-Content -LiteralPath (
    Join-Path $PSScriptRoot 'START-V91-I05-DOWNLOADER.cmd') -Raw
if ($runnerTextForOperator -notmatch 'LAST-ERROR-V91-I05-T1\.txt' -or
    $runnerTextForOperator -notmatch 'LAST-FAILURE-V91-I05-T1\.json' -or
    $startTextForOperator -notmatch
        'type "%~dp0LAST-ERROR-V91-I05-T1\.txt"') {
    throw 'The one-click operator failure report self-test failed.'
}
if ($runnerTextForOperator -notmatch
        '\$peerListenerDeadline\s*=\s*\[DateTime\]::UtcNow\.AddSeconds\(30\)' -or
    $runnerTextForOperator -notmatch
        "Category 'candidate_peer_listener_missing'") {
    throw 'The candidate peer-listener startup grace contract is missing.'
}
if ($runnerTextForOperator -notmatch
        '\$peerConnectTimeoutSeconds\s*=\s*300' -or
    $runnerTextForOperator -notmatch
        '\-not\s+\$sawExactIPv4[\s\S]{0,180}' +
            '\$peerConnectTimeoutSeconds' -or
    $runnerTextForOperator -notmatch
        "Category 'missing_exact_peer_socket'") {
    throw 'The exact peer-socket fail-fast deadline is missing.'
}
if ($runnerTextForOperator -notmatch
        'FAILURE-PENDING-V91-I05-T1\.json' -or
    $runnerTextForOperator -notmatch
        '\$failureDelivered\s*=\s*\$true' -or
    $runnerTextForOperator.IndexOf(
        'FAILURE-PENDING-V91-I05-T1.json') -gt
    $runnerTextForOperator.IndexOf(
        '$cleanupFallback = & $cleanupPath')) {
    throw 'The pre-cleanup FAILURE delivery contract is missing.'
}
if ($runnerTextForOperator -notmatch
        'function Assert-I05LanApiForbidden' -or
    $runnerTextForOperator -notmatch
        '\$statusCode\s*-eq\s*403' -or
    $runnerTextForOperator -notmatch
        "Category 'candidate_api_lan_access'" -or
    $runnerTextForOperator -notmatch
        '\$_\.Exception -is \[Net\.WebException\]' -or
    $runnerTextForOperator -notmatch
        'api_lan_access_denied') {
    throw 'The native API LAN HTTP 403 contract is missing.'
}
if (-not (Test-I05Ipv4SameSubnet `
        -Left '192.168.222.60' -Right '192.168.223.20' `
        -PrefixLength 22) -or
    (Test-I05Ipv4SameSubnet `
        -Left '192.168.222.60' -Right '192.168.224.20' `
        -PrefixLength 22)) {
    throw 'The /22 prefix self-test failed.'
}
if ((Get-I05HostIdSha256) -notmatch '^[0-9a-f]{64}$') {
    throw 'The canonical host-id self-test failed.'
}
$selftestNonce = '00112233445566778899aabbccddeeff'
$selftestH1 = '192.168.222.60'
$selftestBaseLink = 'ed2k://|file|{0}|{1}|{2}|/' -f `
    $fixtureName, $fixtureBytes, $fixtureEd2k
$selftestDirectLink = $selftestBaseLink +
    "|sources,$selftestH1`:$expectedSourceTcpPort|/"
$selftestConfig = [pscustomobject][ordered]@{
    candidate = [pscustomobject][ordered]@{
        version = $expectedVersion
        commit = $expectedCommit
        emule_sha256 = $expectedEmuleSha256
        ese_server_sha256 = $expectedEseServerSha256
        build_info_sha256 = $expectedBuildInfoSha256
        zip_sha256 = $expectedArchiveSha256
        zip_bytes = [string]$expectedArchiveBytes
    }
    source = [pscustomobject][ordered]@{
        ipv4_address = $selftestH1
        ipv4_sha256 = Get-LabStringSha256 -Value $selftestH1
        interface_id = 'selftest-interface'
        tcp_port = [string]$expectedSourceTcpPort
        udp_port = [string]$expectedSourceUdpPort
        web_port = [string]$expectedSourceWebPort
    }
}
$selftestCommand = [pscustomobject][ordered]@{
    schema = 'ese.v91.i05.t1-command/v1'
    case_id = 'V91-I05'
    topology = 'T1'
    status = 'START'
    nonce = $selftestNonce
    candidate = [pscustomobject][ordered]@{
        version = $expectedVersion
        commit = $expectedCommit
        dirty = $false
        emule_sha256 = $expectedEmuleSha256
        ese_server_sha256 = $expectedEseServerSha256
        build_info_sha256 = $expectedBuildInfoSha256
        zip_sha256 = $expectedArchiveSha256
        zip_bytes = $expectedArchiveBytes
    }
    source = $selftestConfig.source
    fixture = [pscustomobject][ordered]@{
        name = $fixtureName
        bytes = $fixtureBytes
        sha256 = $fixtureSha256
        ed2k = $fixtureEd2k
        direct_link = $selftestDirectLink
        direct_link_sha256 =
            Get-LabStringSha256 -Value $selftestDirectLink
    }
    injection = [pscustomobject][ordered]@{
        delivery_count = 1
        direct_only = $true
    }
    policy = [pscustomobject][ordered]@{
        data_family = 'IPv4'
        ipv6_mode = 0
        wire_capture_required = $true
        wire_capture_host = 'H3'
        classic_crypt_layers_disabled = $true
        kad2_enabled = $false
        kad6_enabled = $false
        third_party_peers_allowed = $false
        direct_link_only = $true
        third_party_sources_forbidden = $true
        kad_network_mask = 0
        discovery = 'direct-link-only'
    }
}
$selftestLinkContract = Assert-I05Command -Command $selftestCommand `
    -Config $selftestConfig -Nonce $selftestNonce
if ([string]$selftestLinkContract.direct_link -cne
        $selftestDirectLink -or
    $null -ne $selftestLinkContract.PSObject.Properties['base_link']) {
    throw 'The direct-only COMMAND positive self-test failed.'
}
foreach ($negativeCommandName in @('base-field', 'delivery-count', 'policy')) {
    $negativeCommand = ($selftestCommand | ConvertTo-Json -Depth 12) |
        ConvertFrom-Json
    switch ($negativeCommandName) {
        'base-field' {
            $negativeCommand.fixture | Add-Member `
                -NotePropertyName base_link -NotePropertyValue $selftestBaseLink
        }
        'delivery-count' { $negativeCommand.injection.delivery_count = 2 }
        'policy' {
            $negativeCommand.policy.third_party_sources_forbidden = $false
        }
    }
    $rejected = $false
    try {
        $null = Assert-I05Command -Command $negativeCommand `
            -Config $selftestConfig -Nonce $selftestNonce
    } catch {
        $rejected = $true
    }
    if (-not $rejected) {
        throw "The COMMAND negative '$negativeCommandName' was accepted."
    }
}
$firewallProfilesSelftest = @(
    [pscustomobject]@{ Name = 'Domain'; Enabled = $true },
    [pscustomobject]@{ Name = 'Private'; Enabled = $true },
    [pscustomobject]@{ Name = 'Public'; Enabled = $true }
)
$firewallSnapshot = Assert-I05FirewallEnforcementSnapshot `
    -ServiceStatus Running -Profiles $firewallProfilesSelftest
if (-not [bool]$firewallSnapshot.service_running -or
    @($firewallSnapshot.profiles_enabled).Count -ne 3) {
    throw 'The firewall enforcement positive self-test failed.'
}
foreach ($negativeFirewall in @(
    [pscustomobject]@{
        Status = 'Stopped'; Profiles = $firewallProfilesSelftest
    },
    [pscustomobject]@{
        Status = 'Running'; Profiles = @(
            [pscustomobject]@{ Name = 'Domain'; Enabled = $true },
            [pscustomobject]@{ Name = 'Private'; Enabled = $false },
            [pscustomobject]@{ Name = 'Public'; Enabled = $true }
        )
    },
    [pscustomobject]@{
        Status = 'Running'; Profiles = @(
            [pscustomobject]@{ Name = 'Domain'; Enabled = $true },
            [pscustomobject]@{ Name = 'Private'; Enabled = $true }
        )
    }
)) {
    $firewallRejected = $false
    try {
        $null = Assert-I05FirewallEnforcementSnapshot `
            -ServiceStatus ([string]$negativeFirewall.Status) `
            -Profiles @($negativeFirewall.Profiles)
    } catch {
        $firewallRejected =
            [string]$_.Exception.Data['i05_classification'] -ceq 'LAB_BLOCKED'
    }
    if (-not $firewallRejected) {
        throw 'A disabled/incomplete firewall engine was accepted.'
    }
}

$wirePositive = [pscustomobject][ordered]@{
    Valid = $true
    TruncatedIPv4PeerPackets = 0L
    IPv4PeerPackets = 1L
    RejectedPeerTuplePackets = 0L
    ThirdPartyPeerPackets = 0L
    IPv6PeerPackets = 0L
    RequestPartsI64 = 1L
    CompressedPart32 = 0L
    SendingPartI64 = 1L
    CompressedPartI64 = 0L
    InvalidFixtureI64Frames = 0L
}
$null = Assert-I05WireEvidence -Wire $wirePositive
$classicWire = ($wirePositive | ConvertTo-Json -Depth 4) |
    ConvertFrom-Json
$classicWire.CompressedPart32 = 1L
$classicWire.SendingPartI64 = 0L
$null = Assert-I05WireEvidence -Wire $classicWire
$snaplenWire = ($wirePositive | ConvertTo-Json -Depth 4) |
    ConvertFrom-Json
$snaplenWire.TruncatedIPv4PeerPackets = 1L
$null = Assert-I05WireEvidence -Wire $snaplenWire
foreach ($wireCase in @(
    [pscustomobject]@{
        Name = 'parser-invalid'; Property = 'Valid'; Value = $false
        Expected = 'LAB_BLOCKED'
    },
    [pscustomobject]@{
        Name = 'no-exact-flow'; Property = 'IPv4PeerPackets'; Value = 0L
        Expected = 'LAB_BLOCKED'
    },
    [pscustomobject]@{
        Name = 'unattributed-ipv6'; Property = 'IPv6PeerPackets'; Value = 1L
        Expected = 'LAB_BLOCKED'
    },
    [pscustomobject]@{
        Name = 'third-party-capture'; Property = 'ThirdPartyPeerPackets'
        Value = 1L; Expected = 'LAB_BLOCKED'
    },
    [pscustomobject]@{
        Name = 'missing-request-i64'; Property = 'RequestPartsI64'; Value = 0L
        Expected = 'PRODUCT_INVARIANT'
    },
    [pscustomobject]@{
        Name = 'missing-response'; Property = 'SendingPartI64'; Value = 0L
        Expected = 'PRODUCT_INVARIANT'
    },
    [pscustomobject]@{
        Name = 'invalid-fixture-frame'; Property = 'InvalidFixtureI64Frames'
        Value = 1L; Expected = 'PRODUCT_INVARIANT'
    }
)) {
    $negativeWire = ($wirePositive | ConvertTo-Json -Depth 4) |
        ConvertFrom-Json
    $negativeWire.([string]$wireCase.Property) = $wireCase.Value
    $wireClassification = $null
    try {
        Assert-I05WireEvidence -Wire $negativeWire
    } catch {
        $wireClassification =
            [string]$_.Exception.Data['i05_classification']
    }
    if ($wireClassification -cne [string]$wireCase.Expected) {
        throw (
            "Wire classification '$($wireCase.Name)' was " +
            "'$wireClassification', expected '$($wireCase.Expected)'."
        )
    }
}

$allowedApiV6Row = [pscustomobject]@{
    LocalAddress = '::1'; LocalPort = $webPort
    RemoteAddress = '::'; State = 'Listen'
}
if (-not (Test-I05TcpRowAllowedByIPv4Profile `
        -Connection $allowedApiV6Row)) {
    throw 'The IPv6 loopback API exception was rejected.'
}
$allowedNativeApiRow = [pscustomobject]@{
    LocalAddress = '0.0.0.0'; LocalPort = $webPort
    RemoteAddress = '0.0.0.0'; State = 'Listen'
}
if (-not (Test-I05ApiListenerAllowedByIPv4Profile `
        -Connection $allowedNativeApiRow)) {
    throw 'The native IPv4 WebServer listener was rejected.'
}
foreach ($forbiddenApiRow in @(
    [pscustomobject]@{
        LocalAddress = '::'; LocalPort = $webPort
        RemoteAddress = '::'; State = 'Listen'
    },
    [pscustomobject]@{
        LocalAddress = '192.168.222.64'; LocalPort = $webPort
        RemoteAddress = '0.0.0.0'; State = 'Listen'
    },
    [pscustomobject]@{
        LocalAddress = '0.0.0.0'; LocalPort = $tcpPort
        RemoteAddress = '0.0.0.0'; State = 'Listen'
    }
)) {
    if (Test-I05ApiListenerAllowedByIPv4Profile `
            -Connection $forbiddenApiRow) {
        throw 'A forbidden native API listener row was accepted.'
    }
}
foreach ($forbiddenV6Row in @(
    [pscustomobject]@{
        LocalAddress = '::'; LocalPort = $tcpPort
        RemoteAddress = '::'; State = 'Listen'
    },
    [pscustomobject]@{
        LocalAddress = '::1'; LocalPort = 9000
        RemoteAddress = '::'; State = 'Listen'
    },
    [pscustomobject]@{
        LocalAddress = '2001:db8::2'; LocalPort = 50000
        RemoteAddress = '2001:db8::1'; State = 'Established'
    }
)) {
    if (Test-I05TcpRowAllowedByIPv4Profile -Connection $forbiddenV6Row) {
        throw 'An IPv6 wildcard/extra-port socket was accepted.'
    }
}

$containmentSelftestRoot = Join-Path ([IO.Path]::GetTempPath()) (
    'v91-i05-containment-selftest-' + [Guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $containmentSelftestRoot
try {
    $containmentPlanSelftest = New-I05ContainmentPlan `
        -Nonce $selftestNonce -Program $runner -SourceIPv4 $selftestH1 `
        -Profile 'Any' -EvidenceRoot $containmentSelftestRoot
    if ([int]$containmentPlanSelftest.rule_count -ne 10 -or
        @($containmentPlanSelftest.rules).Count -ne 10 -or
        @($containmentPlanSelftest.canonical_rules |
            Where-Object profile -cne 'Any').Count -ne 0) {
        throw 'The ten-rule/Profile-Any containment plan self-test failed.'
    }
    $specMaterialSelftest = @(
        $containmentPlanSelftest.canonical_rules | Sort-Object role |
            ForEach-Object { Get-I05ContainmentRuleLine -Rule $_ }
    ) -join "`n"
    if ((Get-LabStringSha256 -Value $specMaterialSelftest) -cne
            [string]$containmentPlanSelftest.spec_sha256) {
        throw 'The reproducible containment spec SHA self-test failed.'
    }
    $udpRoleExpectations = [ordered]@{
        in_udp_v4_all = '0.0.0.0-255.255.255.255'
        in_udp_v6_all = '::/1,8000::/1'
        out_udp_v4_all = '0.0.0.0-255.255.255.255'
        out_udp_v6_all = '::/1,8000::/1'
    }
    foreach ($udpExpectation in $udpRoleExpectations.GetEnumerator()) {
        $udpRule = @($containmentPlanSelftest.rules | Where-Object {
            [string]$_.role -ceq [string]$udpExpectation.Key
        })
        if ($udpRule.Count -ne 1 -or
            (@($udpRule[0].local_ports) -join ',') -cne 'Any' -or
            (@($udpRule[0].remote_ports) -join ',') -cne 'Any' -or
            (@($udpRule[0].remote_addresses) -join ',') -cne
                [string]$udpExpectation.Value) {
            throw "UDP containment is not all-address/port: $($udpExpectation.Key)"
        }
    }
    $inTcpV6All = @($containmentPlanSelftest.rules | Where-Object {
        [string]$_.role -ceq 'in_tcp_v6_all'
    })
    if ($inTcpV6All.Count -ne 1 -or
        (@($inTcpV6All[0].local_ports) -join ',') -cne 'Any' -or
        (@($inTcpV6All[0].remote_addresses) -join ',') -cne
            '::/1,8000::/1') {
        throw 'Inbound IPv6 TCP containment leaves extra local ports open.'
    }
    $snapshotSpec = @($containmentPlanSelftest.rules | Where-Object {
        [string]$_.role -ceq 'out_udp_v4_all'
    })[0]
    $snapshotRule = [pscustomobject]@{
        Name = $snapshotSpec.name
        DisplayName = $snapshotSpec.display_name
        Direction = $snapshotSpec.direction
        Action = 'Block'
        Enabled = 'True'
        Profile = 'Any'
        EdgeTraversalPolicy = 'Block'
    }
    $snapshotPort = [pscustomobject]@{
        Protocol = 'UDP'; LocalPort = 'Any'; RemotePort = 'Any'
    }
    $snapshotApplication = [pscustomobject]@{ Program = $runner }
    $snapshotAddress = [pscustomobject]@{
        LocalAddress = 'Any'
        RemoteAddress = @($snapshotSpec.remote_addresses)
    }
    $snapshotInterface = [pscustomobject]@{ InterfaceAlias = 'Any' }
    $null = Assert-I05ContainmentRuleSnapshot `
        -Rule $snapshotRule -Spec $snapshotSpec `
        -Ports @($snapshotPort) -Applications @($snapshotApplication) `
        -Addresses @($snapshotAddress) -Interfaces @($snapshotInterface)
    $badSnapshotRejected = $false
    try {
        $badSnapshotPort = [pscustomobject]@{
            Protocol = 'UDP'; LocalPort = '7972'; RemotePort = 'Any'
        }
        $null = Assert-I05ContainmentRuleSnapshot `
            -Rule $snapshotRule -Spec $snapshotSpec `
            -Ports @($badSnapshotPort) `
            -Applications @($snapshotApplication) `
            -Addresses @($snapshotAddress) -Interfaces @($snapshotInterface)
    } catch {
        $badSnapshotRejected = $true
    }
    if (-not $badSnapshotRejected) {
        throw 'The exact-filter watchdog validator accepted a port mutation.'
    }
    function Test-I05SelftestPortToken {
        param([string[]]$Tokens, [int]$Port)
        foreach ($token in $Tokens) {
            if ([string]$token -ceq 'Any') { return $true }
            if ([string]$token -match '^(\d+)-(\d+)$' -and
                $Port -ge [int]$Matches[1] -and
                $Port -le [int]$Matches[2]) {
                return $true
            }
            if ([string]$token -match '^\d+$' -and
                $Port -eq [int]$token) {
                return $true
            }
        }
        return $false
    }
    function Test-I05SelftestV4RuleMatch {
        param(
            [object]$Rule, [string]$RemoteAddress, [int]$LocalPort,
            [int]$RemotePort
        )
        if (@($Rule.remote_addresses | Where-Object {
                [string]$_ -match ':'
            }).Count -ne 0) {
            return $false
        }
        if (-not (Test-I05IPv4InRangeSet -Address $RemoteAddress `
                -Ranges @($Rule.remote_addresses))) {
            return $false
        }
        return (Test-I05SelftestPortToken `
                -Tokens @($Rule.local_ports) -Port $LocalPort) -and
            (Test-I05SelftestPortToken `
                -Tokens @($Rule.remote_ports) -Port $RemotePort)
    }
    $outTcpRules = @($containmentPlanSelftest.rules | Where-Object {
        [string]$_.direction -ceq 'Outbound' -and
        [string]$_.protocol -ceq 'TCP'
    })
    $inTcpRules = @($containmentPlanSelftest.rules | Where-Object {
        [string]$_.direction -ceq 'Inbound' -and
        [string]$_.protocol -ceq 'TCP'
    })
    $outUdpRules = @($containmentPlanSelftest.rules | Where-Object {
        [string]$_.direction -ceq 'Outbound' -and
        [string]$_.protocol -ceq 'UDP'
    })
    $inUdpRules = @($containmentPlanSelftest.rules | Where-Object {
        [string]$_.direction -ceq 'Inbound' -and
        [string]$_.protocol -ceq 'UDP'
    })
    if (@($outTcpRules | Where-Object {
            Test-I05SelftestV4RuleMatch -Rule $_ `
                -RemoteAddress $selftestH1 -LocalPort 50000 `
                -RemotePort $expectedSourceTcpPort
        }).Count -ne 0 -or
        @($inTcpRules | Where-Object {
            Test-I05SelftestV4RuleMatch -Rule $_ `
                -RemoteAddress $selftestH1 -LocalPort $tcpPort `
                -RemotePort 50000
        }).Count -ne 0 -or
        @($outTcpRules | Where-Object {
            Test-I05SelftestV4RuleMatch -Rule $_ `
                -RemoteAddress '127.0.0.1' -LocalPort $webPort `
                -RemotePort 50000
        }).Count -ne 0) {
        throw 'A containment block overlaps H1:7862 or IPv4 loopback API.'
    }
    if (@($outTcpRules | Where-Object {
            Test-I05SelftestV4RuleMatch -Rule $_ `
                -RemoteAddress '127.0.0.1' -LocalPort 50000 `
                -RemotePort 4662
        }).Count -lt 1) {
        throw 'Containment leaves a loopback peer with ephemeral local port.'
    }
    if (@($outUdpRules | Where-Object {
            Test-I05SelftestV4RuleMatch -Rule $_ `
                -RemoteAddress '127.0.0.1' -LocalPort 55000 `
                -RemotePort 55001
        }).Count -lt 1 -or
        @($inUdpRules | Where-Object {
            Test-I05SelftestV4RuleMatch -Rule $_ `
                -RemoteAddress '127.0.0.1' -LocalPort 55000 `
                -RemotePort 55001
        }).Count -lt 1) {
        throw 'UDP loopback is not blocked in both directions/all ports.'
    }
    foreach ($thirdParty in @('192.168.222.99', '100.64.0.1')) {
        if (@($outTcpRules | Where-Object {
                Test-I05SelftestV4RuleMatch -Rule $_ `
                    -RemoteAddress $thirdParty -LocalPort 50000 `
                    -RemotePort 4662
            }).Count -lt 1 -or
            @($inTcpRules | Where-Object {
                Test-I05SelftestV4RuleMatch -Rule $_ `
                    -RemoteAddress $thirdParty -LocalPort $tcpPort `
                    -RemotePort 50000
            }).Count -lt 1) {
            throw "Containment does not block third party $thirdParty."
        }
    }
    $privateProfileRejected = $false
    try {
        $null = New-I05ContainmentPlan -Nonce $selftestNonce `
            -Program $runner -SourceIPv4 $selftestH1 `
            -Profile 'Private' -EvidenceRoot $containmentSelftestRoot
    } catch {
        $privateProfileRejected = $true
    }
    if (-not $privateProfileRejected) {
        throw 'A non-Any containment profile was accepted.'
    }
} finally {
    Remove-Item -LiteralPath $containmentSelftestRoot -Recurse -Force `
        -ErrorAction SilentlyContinue
}
$fixtureHashSelfTest = & $fixtureVerifier -Mode SelfTest |
    Select-Object -Last 1
if ([string]$fixtureHashSelfTest.status -cne 'PASS') {
    throw 'The local SHA-256/ED2K streaming hash self-test failed.'
}

# Keep the complete RFC 1320 set and the ED2K PARTSIZE edges as
# independent literal oracles. The edge values were generated by an
# independent OpenSSL MD4 implementation over sparse, all-zero files.
$rfc1320Vectors = @(
    [pscustomobject]@{
        Text = ''; Md4 = '31D6CFE0D16AE931B73C59D7E0C089C0'
    }
    [pscustomobject]@{
        Text = 'a'; Md4 = 'BDE52CB31DE33E46245E05FBDBD6FB24'
    }
    [pscustomobject]@{
        Text = 'abc'; Md4 = 'A448017AAF21D8525FC10AE87AA6729D'
    }
    [pscustomobject]@{
        Text = 'message digest'
        Md4 = 'D9130A8164549FE818874806E1C7014B'
    }
    [pscustomobject]@{
        Text = 'abcdefghijklmnopqrstuvwxyz'
        Md4 = 'D79E1C308AA5BBCDEEA8ED63DF412DA9'
    }
    [pscustomobject]@{
        Text = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
        Md4 = '043F8582F241DB351CE627E153E7F0E4'
    }
    [pscustomobject]@{
        Text = (
            '123456789012345678901234567890123456789012345678901234567890' +
                '12345678901234567890'
        )
        Md4 = 'E33B4DDC9C38F2199C3E7B164FCC0536'
    }
)
$ed2kZeroEdges = @(
    @{ Bytes = 9727999L; Ed2k = 'AC44B93FC9AFF773AB0005C911F8396F' },
    @{ Bytes = 9728000L; Ed2k = 'FC21D9AF828F92A8DF64BEAC3357425D' },
    @{ Bytes = 9728001L; Ed2k = '06329E9DBA1373512C06386FE29E3C65' },
    @{ Bytes = 19456000L; Ed2k = '114B21C63A74B6CA922291A11177DD5C' },
    @{ Bytes = 19456017L; Ed2k = '3E9508AF3569305A6B699C1A5D39EEE0' }
)
$hashOracleRoot = Join-Path ([IO.Path]::GetTempPath()) (
    'v91-i05-hash-oracle-' + [Guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $hashOracleRoot
try {
    for ($vectorIndex = 0; $vectorIndex -lt
            $rfc1320Vectors.Count; ++$vectorIndex) {
        $vectorPath = Join-Path $hashOracleRoot (
            'rfc1320-{0}.bin' -f $vectorIndex)
        [IO.File]::WriteAllBytes(
            $vectorPath,
            [Text.Encoding]::ASCII.GetBytes(
                [string]$rfc1320Vectors[$vectorIndex].Text))
        $vectorResult =
            [EseV91Lab.CanonicalFixture]::HashFile($vectorPath)
        if ([long]$vectorResult.Bytes -ne
                [Text.Encoding]::ASCII.GetByteCount(
                    [string]$rfc1320Vectors[$vectorIndex].Text) -or
            [string]$vectorResult.Ed2k -cne
                [string]$rfc1320Vectors[$vectorIndex].Md4) {
            throw "RFC 1320 vector $vectorIndex failed."
        }
    }

    $edgePath = Join-Path $hashOracleRoot 'ed2k-zero-edge.bin'
    foreach ($edge in $ed2kZeroEdges) {
        $edgeStream = [IO.File]::Open(
            $edgePath, [IO.FileMode]::Create,
            [IO.FileAccess]::Write, [IO.FileShare]::None)
        try {
            $edgeStream.SetLength([long]$edge.Bytes)
        } finally {
            $edgeStream.Dispose()
        }
        $edgeResult = [EseV91Lab.CanonicalFixture]::HashFile($edgePath)
        if ([long]$edgeResult.Bytes -ne [long]$edge.Bytes -or
            [string]$edgeResult.Ed2k -cne [string]$edge.Ed2k) {
            throw (
                "ED2K zero edge $($edge.Bytes) failed: " +
                "$($edgeResult.Ed2k)")
        }
    }
} finally {
    if (Test-Path -LiteralPath $hashOracleRoot -PathType Container) {
        Remove-Item -LiteralPath $hashOracleRoot -Recurse -Force `
            -ErrorAction SilentlyContinue
    }
}

$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    $runner, [ref]$tokens, [ref]$errors)
$runnerText = [IO.File]::ReadAllText($runner)
if ($runnerText -notmatch
        '\$commandWait\s*=\s*\$expires\s*-\s*\[DateTimeOffset\]::UtcNow' -or
    $runnerText -notmatch
        '\$commandWait\.TotalSeconds\s*-lt\s*300' -or
    $runnerText -notmatch
        '\$controlStream\.ReadTimeout\s*=\s*\$commandWaitMilliseconds' -or
    $runnerText -notmatch
        'Confirm-I05ReceivedDocument[\s\S]{0,240}' +
            '\$controlStream\.ReadTimeout\s*=\s*30000') {
    throw 'The READY-to-COMMAND timeout is not bound to CONFIG expiration.'
}
$cleanupText = [IO.File]::ReadAllText($cleanup)
$contractPatterns = @(
    'Save-I05OwnershipDocuments[\s\S]{0,1200}' +
        '-Resource peer_firewall[\s\S]{0,200}-State PENDING' +
        '[\s\S]{0,400}New-NetFirewallRule'
    '-Resource pktmon_filters[\s\S]{0,200}-State PENDING' +
        '[\s\S]{0,900}\$capture = Start-I05Capture'
    '-Resource containment_firewall[\s\S]{0,200}-State PENDING' +
        '[\s\S]{0,500}Install-I05ContainmentRules'
    '-Resource candidate_process[\s\S]{0,200}-State PENDING' +
        '[\s\S]{0,500}\$process = Start-Process'
    "ValidateSet\('READY', 'STARTED', 'COMPLETE', 'CLEANUP', 'FAILURE'\)"
    'FixtureVerifier -Mode Verify'
    "ed2k_source = 'local-streaming-calculation'"
)
foreach ($contractPattern in $contractPatterns) {
    if ($runnerText -notmatch $contractPattern) {
        throw "The fail-closed runner contract is missing: $contractPattern"
    }
}
if ($cleanupText -notmatch "processState -eq 'PENDING'" -or
    $cleanupText -notmatch 'process_not_before_utc' -or
    $cleanupText -notmatch 'active-h3/v2') {
    throw 'The partial ACTIVE cleanup contract is missing.'
}
$sendLinkCalls = @($ast.FindAll({
    param($node)
    $node -is [Management.Automation.Language.CommandAst] -and
    $node.GetCommandName() -ceq 'Send-I05Ed2kLink'
}, $true))
$getChildItemCommands = @($ast.FindAll({
    param($node)
    $node -is [Management.Automation.Language.CommandAst] -and
    $node.GetCommandName() -ceq 'Get-ChildItem'
}, $true))
foreach ($getChildItemCommand in $getChildItemCommands) {
    if ($getChildItemCommand.Extent.Text -match
            '(?i)-ErrorAction\s+SilentlyContinue') {
        throw 'A Get-ChildItem enumeration remains fail-open.'
    }
}
if ($sendLinkCalls.Count -ne 1 -or
    $runnerText -match 'fixture\.base_link' -or
    $runnerText -match 'base_injected|queue_owned_before_direct') {
    throw 'The runner does not enforce exactly one direct-link injection.'
}
$commandAssertOffset = $runnerText.IndexOf(
    "Context 'COMMAND.injection'", [StringComparison]::Ordinal)
$directSendOffset = $runnerText.IndexOf(
    '$directDelivery = Send-I05Ed2kLink',
    [StringComparison]::Ordinal)
$queueAfterOffset = $runnerText.IndexOf(
    '$queue = Wait-I05QueueOwnership',
    [StringComparison]::Ordinal)
if ($commandAssertOffset -lt 0 -or $directSendOffset -lt 0 -or
    $queueAfterOffset -le $directSendOffset -or
    $runnerText -notmatch
        'delivery_count\s*=\s*1[\s\S]{0,160}' +
            'direct_injected[\s\S]{0,160}' +
            'queue_owned_after_direct') {
    throw 'The direct-only runtime/order/STARTED contract is missing.'
}
$directInjectionEndOffset = $runnerText.IndexOf(
    '$startedAt = [DateTimeOffset]::UtcNow',
    $directSendOffset, [StringComparison]::Ordinal)
if ($directInjectionEndOffset -le $directSendOffset -or
    $runnerText.Substring(
        $directSendOffset,
        $directInjectionEndOffset - $directSendOffset
    ) -notmatch
        '\$_\.Exception\.Data\.Contains\(''i05_classification''\)' +
            '[\s\S]{0,80}throw') {
    throw 'Direct injection does not preserve an existing LAB classification.'
}
$initialKadOffset = $runnerText.IndexOf(
    "-Context 'API initial'", [StringComparison]::Ordinal)
$forceNetworkOffset = $runnerText.IndexOf(
    'api/network/connect?ed2k=0&kad=0',
    [StringComparison]::Ordinal)
if ($initialKadOffset -lt 0 -or $forceNetworkOffset -lt 0 -or
    $initialKadOffset -ge $forceNetworkOffset) {
    throw 'The first API status is not strict-Kad-false before network forcing.'
}
$runtimePreferenceStart = $runnerText.IndexOf(
    'function Assert-I05RuntimeIPv4Only',
    [StringComparison]::Ordinal)
$runtimePreferenceEnd = $runnerText.IndexOf(
    'function Wait-I05TransferComplete',
    $runtimePreferenceStart, [StringComparison]::Ordinal)
if ($runtimePreferenceStart -lt 0 -or
    $runtimePreferenceEnd -le $runtimePreferenceStart -or
    $runnerText.Substring(
        $runtimePreferenceStart,
        $runtimePreferenceEnd - $runtimePreferenceStart
    ) -notmatch
        "-Section 'eMule' -Key 'NetworkED2K'") {
    throw 'Runtime does not fail closed if NetworkED2K changes.'
}
$candidateApiStart = $runnerText.IndexOf(
    'function Invoke-I05CandidateApi',
    [StringComparison]::Ordinal)
$candidateApiEnd = $runnerText.IndexOf(
    'function Assert-I05FirewallEnforcementSnapshot',
    $candidateApiStart, [StringComparison]::Ordinal)
if ($candidateApiStart -lt 0 -or
    $candidateApiEnd -le $candidateApiStart) {
    throw 'The candidate API fail-closed helper is missing.'
}
$candidateApiText = $runnerText.Substring(
    $candidateApiStart, $candidateApiEnd - $candidateApiStart)
foreach ($requiredApiRetry in @(
    '[int]$MaxAttempts = 4',
    '$attempt -le $MaxAttempts',
    '$attempt -lt $MaxAttempts',
    "Category 'candidate_api_unavailable'"
)) {
    if ($candidateApiText.IndexOf(
            $requiredApiRetry, [StringComparison]::Ordinal) -lt 0) {
        throw "Candidate API retry contract is missing: $requiredApiRetry"
    }
}
if ($runnerText -match
        'Get-Net(?:TCPConnection|UDPEndpoint)[^\r\n]*SilentlyContinue' -or
    $runnerText -match 'Stop-I05(?:Capture|Process)OnFailure' -or
    $runnerText -match "Arguments\s+@\('stop'\)") {
    throw 'A socket/PktMon/cleanup fail-open fallback remains.'
}
$lossProofOffset = $runnerText.IndexOf(
    'if (-not [bool]$loss.proved_zero)',
    [StringComparison]::Ordinal)
$pktmonResetOffset = $runnerText.IndexOf(
    '$pktmonReset = @(& pktmon.exe stop',
    [StringComparison]::Ordinal)
$filterSnapshotOffset = $runnerText.IndexOf(
    'Set-Content -LiteralPath $State.filters_before_reset',
    [StringComparison]::Ordinal)
$filterAssertionOffset = $runnerText.IndexOf(
    'Assert-I05PktMonFilterRowsExact',
    $filterSnapshotOffset,
    [StringComparison]::Ordinal)
if ($lossProofOffset -lt 0 -or
    $filterSnapshotOffset -le $lossProofOffset -or
    $filterAssertionOffset -le $filterSnapshotOffset -or
    $pktmonResetOffset -le $filterAssertionOffset) {
    throw (
        'PktMon reset is not gated by loss proof and exact armed filters.'
    )
}
if ($runnerText -notmatch "Category 'fixture_io_unavailable'" -or
    $runnerText -notmatch
        '\$destinationExists\s*=\s*Test-Path[\s\S]{0,160}' +
            '-ErrorAction\s+Stop' -or
    $runnerText -notmatch
        'Get-ChildItem[\s\S]{0,160}-ErrorAction\s+Stop') {
    throw 'Fixture file enumeration/existence is not fail-closed.'
}
if ($runnerText -notmatch "FilterBadIPs\s*=\s*'0'" -or
    $runnerText -notmatch
        "-Section 'eMule' -Key 'FilterBadIPs'\)\s*-cne '0'") {
    throw 'Private-LAN direct source acceptance is not fail-closed.'
}
if (($runnerText + "`n" + $cleanupText) -match
        'Get-NetFirewallRule[\s\S]{0,160}ErrorAction\s+SilentlyContinue') {
    throw 'Firewall ownership enumeration is not fail-closed.'
}
if ($cleanupText -match
        'Get-Process[^\r\n]*ErrorAction\s+SilentlyContinue' -or
    $cleanupText -notmatch 'function Get-I05CleanupProcessExact' -or
    $cleanupText -notmatch
        'Get-CimInstance Win32_Process[\s\S]{0,160}-ErrorAction Stop' -or
    $cleanupText -notmatch
        '\$processAfterStop\s*=\s*Get-I05CleanupProcessExact') {
    throw 'Cleanup process discovery/absence proof is not fail-closed.'
}
$engineTickStart = $runnerText.IndexOf(
    'function Assert-I05ContainmentEngineTick',
    [StringComparison]::Ordinal)
$engineTickEnd = $runnerText.IndexOf(
    'function Get-I05IniValue',
    $engineTickStart, [StringComparison]::Ordinal)
if ($engineTickStart -lt 0 -or $engineTickEnd -le $engineTickStart) {
    throw 'The exact containment engine watchdog function is missing.'
}
$engineTickText = $runnerText.Substring(
    $engineTickStart, $engineTickEnd - $engineTickStart)
foreach ($filterCommand in @(
    'Get-NetFirewallPortFilter', 'Get-NetFirewallApplicationFilter',
    'Get-NetFirewallAddressFilter', 'Get-NetFirewallInterfaceFilter',
    'Assert-I05ContainmentRuleSnapshot'
)) {
    if ($engineTickText.IndexOf(
            $filterCommand, [StringComparison]::Ordinal) -lt 0) {
        throw "Engine tick omits exact filter validation: $filterCommand"
    }
}
$readyRemoveOffset = $cleanupText.IndexOf(
    'Remove-Item -LiteralPath $latestReadyPath',
    [StringComparison]::Ordinal)
$activeRemoveOffset = $cleanupText.IndexOf(
    'Remove-Item -LiteralPath $activePath',
    [StringComparison]::Ordinal)
if ($readyRemoveOffset -lt 0 -or $activeRemoveOffset -lt 0 -or
    $readyRemoveOffset -ge $activeRemoveOffset) {
    throw 'Cleanup does not remove READY before committing ACTIVE removal.'
}
foreach ($requiredStatic in @(
    'Profile ''Any''', 'Assert-I05WindowsFirewallEnforced',
    'Get-Service -Name MpsSvc', 'firewall_profile_count = 3',
    'engine_watchdog_samples', 'engine_watchdog_exact_filter_checks',
    'ControlTrace(EVENT_TRACE_CONTROL_STOP)-final',
    'session_before_stop', 'isolation_rules_absent',
    'inventory_verified_sha256', 'exact-ten-nonce-program-rules-only'
)) {
    if (($runnerText + "`n" + $cleanupText).IndexOf(
            $requiredStatic, [StringComparison]::Ordinal) -lt 0) {
        throw "The NO-GO static invariant is missing: $requiredStatic"
    }
}
$productException = $null
try {
    Throw-I05ClassifiedFailure -Classification PRODUCT_INVARIANT `
        -Category 'selftest-product' -Message 'selftest'
} catch {
    $productException = $_.Exception
}
try { throw 'cleanup-selftest' } catch {}
if ($null -eq $productException -or
    [string]$productException.Data['i05_classification'] -cne
        'PRODUCT_INVARIANT') {
    throw 'Product classification did not survive cleanup precedence.'
}
$csharp = $ast.FindAll({
    param($node)
    $node -is
        [Management.Automation.Language.StringConstantExpressionAst] -and
    $node.Value -like '*public static class V91I05PcapAnalyzer*'
}, $true)
if ($csharp.Count -ne 1) {
    throw 'The runner does not contain one PCAP analyzer.'
}
Add-Type -Language CSharp -TypeDefinition $csharp[0].Value
$etwCsharp = $ast.FindAll({
    param($node)
    $node -is
        [Management.Automation.Language.StringConstantExpressionAst] -and
    $node.Value -like '*public static class V91I05EtwTraceQuery*'
}, $true)
if ($etwCsharp.Count -ne 1 -or
    $etwCsharp[0].Value -notmatch
        'public static Result Stop\(string sessionName\)' -or
    $etwCsharp[0].Value -notmatch
        'logFileNameCapacityChars\s*=\s*32768' -or
    $etwCsharp[0].Value -notmatch
        'value\.LogFileNameOffset\s*=' -or
    $etwCsharp[0].Value -notmatch
        'size \+ loggerNameCapacityBytes \+ logFileNameCapacityBytes') {
    throw 'The final ETW STOP/loss proof implementation is missing.'
}
Add-Type -Language CSharp -TypeDefinition $etwCsharp[0].Value

$mappingGuid = '00112233-4455-6677-8899-aabbccddeeff'
$mappingMac = '00-11-22-33-44-55'
function New-I05MappingJson {
    param(
        [object]$Id = 17,
        [object]$SecondaryId = 23,
        [string]$Guid = $mappingGuid,
        [switch]$Duplicate,
        [switch]$Grouped
    )
    $component = [ordered]@{
        Id = $Id
        SecondaryId = $SecondaryId
        Name = 'Intel Physical'
        Type = 'Network'
        Properties = @(
            [ordered]@{ Name = 'Interface Guid'; Value = "{$Guid}" }
            [ordered]@{ Name = 'IfIndex'; Value = 7 }
            [ordered]@{ Name = 'Physical Address'; Value = $mappingMac }
        )
    }
    $components = @(
            $component
            if ($Duplicate) { $component }
    )
    if ($Grouped) {
        return (@(
            [ordered]@{
                Group = 'Physical'
                Components = $components
            }
        ) | ConvertTo-Json -Depth 8 -Compress)
    }
    return ([ordered]@{ Components = $components } |
        ConvertTo-Json -Depth 8 -Compress)
}

$uniqueMapping = Get-I05PktMonComponentMappingFromJson `
    -Json (New-I05MappingJson) -InterfaceGuid $mappingGuid `
    -InterfaceIndex 7 -MacAddress $mappingMac
if ([int]$uniqueMapping.primary_id -ne 17 -or
    [int]$uniqueMapping.secondary_id -ne 23 -or
    @($uniqueMapping.conversion_component_ids).Count -ne 2) {
    throw 'The unique PktMon component mapping self-test failed.'
}
$groupedMapping = Get-I05PktMonComponentMappingFromJson `
    -Json (New-I05MappingJson -Grouped) -InterfaceGuid $mappingGuid `
    -InterfaceIndex 7 -MacAddress $mappingMac
if ([int]$groupedMapping.primary_id -ne 17 -or
    [int]$groupedMapping.secondary_id -ne 23 -or
    @($groupedMapping.conversion_component_ids).Count -ne 2) {
    throw 'The grouped PktMon component mapping self-test failed.'
}
foreach ($negativeMapping in @(
    @{ Json = New-I05MappingJson `
            -Guid '11112233-4455-6677-8899-aabbccddeeff';
       Name = 'wrong-guid' },
    @{ Json = New-I05MappingJson -Duplicate; Name = 'duplicate-guid' },
    @{ Json = New-I05MappingJson -Id 0; Name = 'invalid-id' },
    @{ Json = '[{"Group":"Physical"}]'; Name = 'group-without-components' }
)) {
    $rejected = $false
    try {
        $null = Get-I05PktMonComponentMappingFromJson `
            -Json ([string]$negativeMapping.Json) `
            -InterfaceGuid $mappingGuid -InterfaceIndex 7 `
            -MacAddress $mappingMac
    } catch {
        $rejected = $true
    }
    if (-not $rejected) {
        throw (
            "The PktMon $($negativeMapping.Name) self-test was accepted."
        )
    }
}
$singleConversion = Select-I05UniqueComponentConversion -Results @(
    [pscustomobject]@{ component_id = 17; exact_peer_flow = $true }
    [pscustomobject]@{ component_id = 23; exact_peer_flow = $false }
)
if ([int]$singleConversion.component_id -ne 17) {
    throw 'The unique component conversion self-test failed.'
}
foreach ($hitCount in @(0, 2)) {
    $results = if ($hitCount -eq 0) {
        @(
            [pscustomobject]@{ exact_peer_flow = $false }
            [pscustomobject]@{ exact_peer_flow = $false }
        )
    } else {
        @(
            [pscustomobject]@{ exact_peer_flow = $true }
            [pscustomobject]@{ exact_peer_flow = $true }
        )
    }
    $rejected = $false
    try {
        $null = Select-I05UniqueComponentConversion -Results $results
    } catch {
        $rejected = $true
    }
    if (-not $rejected) {
        throw "The $hitCount-hit component conversion test was accepted."
    }
}

$bundleRoot = Join-Path ([IO.Path]::GetTempPath()) (
    'v91-i05-bundle-selftest-' + [Guid]::NewGuid().ToString('N'))
try {
    $bundleEvidence = Join-Path $bundleRoot 'evidence'
    $null = New-Item -ItemType Directory -Path $bundleEvidence
    $compactNames = @(
        'pcap-analysis.json', 'component-mapping.json',
        'component-inventory-pre.json',
        'component-inventory-armed.json',
        'component-inventory-post.json', 'pktmon-filter.json',
        'pktmon-loss.json', 'pktmon-status.json',
        'socket-proof.json', 'file-integrity.json'
    )
    foreach ($name in $compactNames) {
        [IO.File]::WriteAllText(
            (Join-Path $bundleEvidence $name),
            '{"selftest":true}',
            (New-Object Text.UTF8Encoding($false)))
    }
    $rawNames = @(
        'capture.etl', 'capture.pcapng', 'samples.jsonl', 'pktmon.log',
        'pktmon-filters-before-reset.txt',
        'components-pre.json', 'components-armed.json',
        'components-post.json', 'firewall-containment-spec.json',
        'firewall-containment-inventory-before.json',
        'firewall-containment-inventory-armed.json',
        'firewall-containment-inventory-verified.json'
    )
    foreach ($name in $rawNames) {
        [IO.File]::WriteAllText(
            (Join-Path $bundleEvidence $name), "raw-$name",
            (New-Object Text.UTF8Encoding($false)))
    }
    $bundleCapture = [pscustomobject]@{
        etl_path = Join-Path $bundleEvidence 'capture.etl'
        pcapng_path = Join-Path $bundleEvidence 'capture.pcapng'
        command_log = Join-Path $bundleEvidence 'pktmon.log'
        filters_before_reset =
            Join-Path $bundleEvidence 'pktmon-filters-before-reset.txt'
        component_mapping_path =
            Join-Path $bundleEvidence 'component-mapping.json'
        component_pre_compact_path =
            Join-Path $bundleEvidence 'component-inventory-pre.json'
        component_armed_compact_path =
            Join-Path $bundleEvidence 'component-inventory-armed.json'
        component_post_compact_path =
            Join-Path $bundleEvidence 'component-inventory-post.json'
        component_pre_raw_path =
            Join-Path $bundleEvidence 'components-pre.json'
        component_armed_raw_path =
            Join-Path $bundleEvidence 'components-armed.json'
        component_post_raw_path =
            Join-Path $bundleEvidence 'components-post.json'
        loss_path = Join-Path $bundleEvidence 'pktmon-loss.json'
    }
    $bundleCaptureResult = [pscustomobject]@{
        filter_summary_path =
            Join-Path $bundleEvidence 'pktmon-filter.json'
        status_summary_path =
            Join-Path $bundleEvidence 'pktmon-status.json'
    }
    $bundleContainment = [pscustomobject]@{
        spec_path = Join-Path $bundleEvidence `
            'firewall-containment-spec.json'
        inventory_before_path = Join-Path $bundleEvidence `
            'firewall-containment-inventory-before.json'
        inventory_armed_path = Join-Path $bundleEvidence `
            'firewall-containment-inventory-armed.json'
        inventory_verified_path = Join-Path $bundleEvidence `
            'firewall-containment-inventory-verified.json'
    }
    $bundle = New-I05CompactEvidenceBundle -RunRoot $bundleRoot `
        -EvidenceRoot $bundleEvidence `
        -Nonce '00112233445566778899aabbccddeeff' `
        -CaptureState $bundleCapture `
        -CaptureResult $bundleCaptureResult `
        -ContainmentPlan $bundleContainment `
        -SamplesPath (Join-Path $bundleEvidence 'samples.jsonl') `
        -SocketProofPath (Join-Path $bundleEvidence 'socket-proof.json') `
        -FileIntegrityPath (Join-Path $bundleEvidence 'file-integrity.json')
    if ([string]$bundle.schema -cne
            'ese.v91.i05.t1-evidence-bundle/v1' -or
        [int]$bundle.bytes -le 0 -or [int]$bundle.bytes -gt 524288) {
        throw 'The compact evidence bundle self-test failed.'
    }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $bundleArchive = [IO.Compression.ZipFile]::OpenRead(
        [string]$bundle.path)
    try {
        $entryNames = @($bundleArchive.Entries |
            ForEach-Object { $_.FullName } | Sort-Object)
        $expectedBundleNames = @('manifest.json') + $compactNames |
            Sort-Object
        if (($entryNames -join "`n") -cne
            ($expectedBundleNames -join "`n")) {
            throw 'The evidence bundle allowlist self-test failed.'
        }
        $manifestEntry = $bundleArchive.Entries |
            Where-Object FullName -ceq 'manifest.json'
        $reader = New-Object IO.StreamReader(
            $manifestEntry.Open(),
            (New-Object Text.UTF8Encoding($false)), $true)
        try {
            $bundleManifest = $reader.ReadToEnd() | ConvertFrom-Json
        } finally {
            $reader.Dispose()
        }
        if (@($bundleManifest.entries).Count -ne 10 -or
            @($bundleManifest.retained_raw).Count -ne 12) {
            throw 'The evidence manifest cardinality self-test failed.'
        }
    } finally {
        $bundleArchive.Dispose()
    }
} finally {
    if (Test-Path -LiteralPath $bundleRoot -PathType Container) {
        Remove-Item -LiteralPath $bundleRoot -Recurse -Force `
            -ErrorAction SilentlyContinue
    }
}

function New-I05SelfTestFrame {
    param(
        [Parameter(Mandatory = $true)][byte]$Opcode,
        [Parameter(Mandatory = $true)][uint32]$PacketLength
    )
    $bytes = New-Object byte[] (5 + $PacketLength)
    $bytes[0] = 0xC5
    [BitConverter]::GetBytes($PacketLength).CopyTo($bytes, 1)
    $bytes[5] = $Opcode
    $hash = New-Object byte[] 16
    $hex = '796A95E75DF8E78D54A57CDEA1FEDE84'
    for ($index = 0; $index -lt 16; $index++) {
        $hash[$index] = [Convert]::ToByte(
            $hex.Substring($index * 2, 2), 16)
    }
    $hash.CopyTo($bytes, 6)
    return $bytes
}

function New-I05SelfTestPacket {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination,
        [Parameter(Mandatory = $true)][int]$SourcePort,
        [Parameter(Mandatory = $true)][int]$DestinationPort,
        [Parameter(Mandatory = $true)][uint32]$Sequence,
        [Parameter(Mandatory = $true)][byte[]]$Payload
    )
    $packet = New-Object byte[] (54 + $Payload.Length)
    $packet[12] = 0x08
    $packet[13] = 0x00
    $packet[14] = 0x45
    $total = 40 + $Payload.Length
    $packet[16] = [byte]($total -shr 8)
    $packet[17] = [byte]($total -band 0xff)
    $packet[22] = 64
    $packet[23] = 6
    [Net.IPAddress]::Parse($Source).GetAddressBytes().CopyTo($packet, 26)
    [Net.IPAddress]::Parse($Destination).GetAddressBytes().CopyTo(
        $packet, 30)
    $packet[34] = [byte]($SourcePort -shr 8)
    $packet[35] = [byte]($SourcePort -band 0xff)
    $packet[36] = [byte]($DestinationPort -shr 8)
    $packet[37] = [byte]($DestinationPort -band 0xff)
    $packet[38] = [byte]($Sequence -shr 24)
    $packet[39] = [byte]($Sequence -shr 16)
    $packet[40] = [byte]($Sequence -shr 8)
    $packet[41] = [byte]($Sequence -band 0xff)
    $packet[46] = 0x50
    $packet[47] = 0x18
    $Payload.CopyTo($packet, 54)
    return $packet
}

function New-I05SelfTestWifiPacket {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination,
        [Parameter(Mandatory = $true)][int]$SourcePort,
        [Parameter(Mandatory = $true)][int]$DestinationPort,
        [Parameter(Mandatory = $true)][uint32]$Sequence,
        [Parameter(Mandatory = $true)][byte[]]$Payload,
        [switch]$Qos,
        [switch]$InvalidSnap
    )
    $ethernet = New-I05SelfTestPacket -Source $Source `
        -Destination $Destination -SourcePort $SourcePort `
        -DestinationPort $DestinationPort -Sequence $Sequence `
        -Payload $Payload
    $headerBytes = if ($Qos) { 26 } else { 24 }
    $packet = New-Object byte[] (
        $headerBytes + 8 + $ethernet.Length - 14)
    $packet[0] = if ($Qos) { 0x88 } else { 0x08 }
    $packet[1] = 0x01
    foreach ($index in 4..21) {
        $packet[$index] = [byte](0x20 + $index)
    }
    $packet[$headerBytes] = if ($InvalidSnap) { 0xab } else { 0xaa }
    $packet[$headerBytes + 1] = 0xaa
    $packet[$headerBytes + 2] = 0x03
    $packet[$headerBytes + 6] = 0x08
    $packet[$headerBytes + 7] = 0x00
    [Array]::Copy(
        $ethernet, 14, $packet, $headerBytes + 8,
        $ethernet.Length - 14)
    return $packet
}

function Write-I05SelfTestBlock {
    param(
        [Parameter(Mandatory = $true)][IO.BinaryWriter]$Writer,
        [Parameter(Mandatory = $true)][uint32]$Type,
        [Parameter(Mandatory = $true)][byte[]]$Body
    )
    $padding = (4 - ($Body.Length % 4)) % 4
    $length = [uint32](12 + $Body.Length + $padding)
    $Writer.Write($Type)
    $Writer.Write($length)
    $Writer.Write($Body)
    if ($padding -ne 0) {
        $Writer.Write((New-Object byte[] $padding))
    }
    $Writer.Write($length)
}

$temporary = [IO.Path]::GetTempFileName()
try {
    $file = [IO.File]::Open(
        $temporary, [IO.FileMode]::Create, [IO.FileAccess]::Write)
    $writer = New-Object IO.BinaryWriter($file)
    try {
        $section = New-Object IO.MemoryStream
        $sectionWriter = New-Object IO.BinaryWriter($section)
        $sectionWriter.Write([uint32]0x1A2B3C4D)
        $sectionWriter.Write([uint16]1)
        $sectionWriter.Write([uint16]0)
        $sectionWriter.Write([int64]-1)
        Write-I05SelfTestBlock -Writer $writer `
            -Type ([uint32]0x0A0D0D0A) -Body $section.ToArray()

        $interface = New-Object IO.MemoryStream
        $interfaceWriter = New-Object IO.BinaryWriter($interface)
        $interfaceWriter.Write([uint16]1)
        $interfaceWriter.Write([uint16]0)
        $interfaceWriter.Write([uint32]65535)
        $name = [Text.Encoding]::UTF8.GetBytes('Ethernet')
        $interfaceWriter.Write([uint16]2)
        $interfaceWriter.Write([uint16]$name.Length)
        $interfaceWriter.Write($name)
        $interfaceWriter.Write([uint16]0)
        $interfaceWriter.Write([uint16]0)
        Write-I05SelfTestBlock -Writer $writer -Type 1 `
            -Body $interface.ToArray()

        $request = New-I05SelfTestFrame -Opcode 0xA3 -PacketLength 65
        $response = New-I05SelfTestFrame -Opcode 0xA2 -PacketLength 37
        $packets = @(
            (New-I05SelfTestPacket -Source '192.168.222.61' `
                -Destination '192.168.222.60' -SourcePort 50000 `
                -DestinationPort 7862 -Sequence 1000 -Payload $request),
            (New-I05SelfTestPacket -Source '192.168.222.60' `
                -Destination '192.168.222.61' -SourcePort 7862 `
                -DestinationPort 50000 -Sequence 2000 -Payload $response),
            (New-I05SelfTestWifiPacket -Source '192.168.222.61' `
                -Destination '192.168.222.60' -SourcePort 50000 `
                -DestinationPort 7862 -Sequence 3000 -Payload $request),
            (New-I05SelfTestWifiPacket -Source '192.168.222.60' `
                -Destination '192.168.222.61' -SourcePort 7862 `
                -DestinationPort 50000 -Sequence 4000 -Payload $response `
                -Qos),
            (New-I05SelfTestWifiPacket -Source '192.168.222.61' `
                -Destination '192.168.222.60' -SourcePort 50000 `
                -DestinationPort 7862 -Sequence 5000 -Payload $request `
                -InvalidSnap)
        )
        foreach ($packet in $packets) {
            $enhanced = New-Object IO.MemoryStream
            $enhancedWriter = New-Object IO.BinaryWriter($enhanced)
            $enhancedWriter.Write([uint32]0)
            $enhancedWriter.Write([uint32]0)
            $enhancedWriter.Write([uint32]0)
            $enhancedWriter.Write([uint32]$packet.Length)
            $enhancedWriter.Write([uint32]$packet.Length)
            $enhancedWriter.Write([byte[]]$packet)
            Write-I05SelfTestBlock -Writer $writer -Type 6 `
                -Body $enhanced.ToArray()
            $enhancedWriter.Dispose()
            $enhanced.Dispose()
        }
    } finally {
        $writer.Dispose()
        $file.Dispose()
    }

    $result = [V91I05PcapAnalyzer]::Analyze(
        $temporary, '192.168.222.60', '192.168.222.61', [int[]]@(50000))
    if (-not $result.Valid -or $result.IPv4PeerPackets -ne 4 -or
        $result.IPv4PhysicalInterfacePackets -ne 4 -or
        $result.IEEE80211Packets -ne 2 -or
        $result.IPv6PeerPackets -ne 0 -or
        $result.RequestPartsI64 -ne 2 -or
        $result.SendingPartI64 -ne 2 -or
        $result.CompressedPartI64 -ne 0 -or
        $result.InvalidFixtureI64Frames -ne 0 -or
        $result.FixtureHashFrames -ne 4 -or
        ($result.FixtureHashFrameSignatures -join ',') -cne
            'A2:37=2,A3:65=2' -or
        $result.RejectedPeerTuplePackets -ne 0 -or
        $result.ThirdPartyPeerPackets -ne 0) {
        throw 'The synthetic PCAPNG positive self-test failed.'
    }
    $wrongTuple = [V91I05PcapAnalyzer]::Analyze(
        $temporary, '192.168.222.60', '192.168.222.61', [int[]]@(50001))
    if (-not $wrongTuple.Valid -or
        $wrongTuple.IPv4PeerPackets -ne 0 -or
        $wrongTuple.RejectedPeerTuplePackets -ne 4 -or
        $wrongTuple.IEEE80211Packets -ne 2) {
        throw 'The unrecorded ephemeral-port self-test failed.'
    }
    foreach ($fixedPort in $reservedI05Ports) {
        $fixedPortRejected = $false
        try {
            $null = [V91I05PcapAnalyzer]::Analyze(
                $temporary, '192.168.222.60', '192.168.222.61',
                [int[]]@([int]$fixedPort))
        } catch {
            $fixedPortRejected = $true
        }
        if (-not $fixedPortRejected) {
            throw "The fixed local port $fixedPort was accepted."
        }
    }

    $bytes = [IO.File]::ReadAllBytes($temporary)
    $bytes[$bytes.Length - 1] = $bytes[$bytes.Length - 1] -bxor 0xff
    [IO.File]::WriteAllBytes($temporary, $bytes)
    $negative = [V91I05PcapAnalyzer]::Analyze(
        $temporary, '192.168.222.60', '192.168.222.61', [int[]]@(50000))
    if ($negative.Valid) {
        throw 'The corrupt-PCAPNG negative self-test failed.'
    }
} finally {
    Remove-Item -LiteralPath $temporary -Force `
        -ErrorAction SilentlyContinue
}

[pscustomobject][ordered]@{
    status = 'PASS'
    powershell_parser = 'PASS'
    csharp_compile = 'PASS'
    prefix_22 = 'PASS'
    host_id = 'PASS'
    local_sha256_ed2k_streaming = 'PASS'
    md4_rfc1320_vectors_7 = 'PASS'
    ed2k_literal_partsize_edges_5 = 'PASS'
    command_wait_contract = 'PASS'
    command_direct_only_exact = 'PASS'
    command_direct_only_negative_3 = 'PASS'
    wm_copydata_delivery_count_one = 'PASS'
    started_injection_exact = 'PASS'
    active_pending_before_mutations = 'PASS'
    mutation_state_copy_ps51 = 'PASS'
    pktmon_semantic_inventory_exact_negative_2 = 'PASS'
    ini_regex_state_ps51 = 'PASS'
    single_instance_and_operator_error = 'PASS'
    candidate_peer_listener_startup_grace = 'PASS'
    exact_peer_socket_fail_fast = 'PASS'
    containment_pending_before_mutation = 'PASS'
    containment_rules_ten_profile_any = 'PASS'
    containment_non_any_profile_rejected = 'PASS'
    containment_h1_7862_not_blocked = 'PASS'
    containment_loopback_api_not_blocked = 'PASS'
    containment_loopback_peer_blocked = 'PASS'
    containment_udp_loopback_all_ports_blocked = 'PASS'
    containment_udp_v4_v6_all = 'PASS'
    containment_in_tcp_v6_all_ports = 'PASS'
    containment_third_party_lan_overlay_blocked = 'PASS'
    containment_spec_sha_reproducible = 'PASS'
    firewall_engine_watchdog_contract = 'PASS'
    firewall_engine_negative_3 = 'PASS'
    firewall_exact_filter_watchdog = 'PASS'
    firewall_filter_snapshot_negative = 'PASS'
    ipv6_wildcard_extra_port_rejected = 'PASS'
    native_api_ipv4_listener_profile = 'PASS'
    native_api_lan_http_403_contract = 'PASS'
    wire_capture_classification_negative_6 = 'PASS'
    wire_parser_invalid_is_lab = 'PASS'
    wire_snaplen_truncation_expected = 'PASS'
    wire_valid_semantic_contradiction_is_product = 'PASS'
    socket_udp_enumeration_fail_closed = 'PASS'
    fixture_io_fail_closed = 'PASS'
    cleanup_process_absence_fail_closed = 'PASS'
    first_api_kad_strict_false = 'PASS'
    runtime_network_ed2k_pref_strict = 'PASS'
    etw_final_stop_loss_proof = 'PASS'
    partial_active_cleanup = 'PASS'
    cleanup_ready_before_active = 'PASS'
    weak_cleanup_fallback_absent = 'PASS'
    classification_product_precedence = 'PASS'
    failure_frame_contract = 'PASS'
    pktmon_component_mapping_unique = 'PASS'
    pktmon_group_array_mapping_unique = 'PASS'
    pktmon_group_without_components_rejected = 'PASS'
    pktmon_component_mapping_wrong_rejected = 'PASS'
    pktmon_component_mapping_duplicate_rejected = 'PASS'
    pktmon_component_id_invalid_rejected = 'PASS'
    component_conversion_zero_two_hits_rejected = 'PASS'
    compact_evidence_bundle_allowlist = 'PASS'
    pcapng_positive = 'PASS'
    pcapng_ieee80211_llc_snap = 'PASS'
    pcapng_ieee80211_invalid_snap_ignored = 'PASS'
    pcapng_unrecorded_tuple_rejected = 'PASS'
    pcapng_fixed_local_ports_rejected = 'PASS'
    pcapng_corrupt_rejected = 'PASS'
}
