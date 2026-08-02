[CmdletBinding()]
param(
    [string]$CandidateZipPath = '',
    [string]$FixturePath = '',
    [string]$RunBase = 'D:\eSE-Lab',
    [string]$SourceIPv4 = '',
    [string]$H3IPv4 = '',
    [switch]$RunEnvironmentPreflight
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
. (Join-Path $PSScriptRoot 'v91_i05_t1_contract.ps1')

$constants = Get-I05T1Constants
$runnerPath = Join-Path $PSScriptRoot 'run_v91_i05_t1_source.ps1'
$cleanupPath =
    Join-Path $PSScriptRoot 'cleanup_v91_i05_t1_source.ps1'
$contractPath =
    Join-Path $PSScriptRoot 'v91_i05_t1_contract.ps1'
$testPath = $MyInvocation.MyCommand.Path
$failures = [Collections.Generic.List[string]]::new()
$checks = [Collections.Generic.List[object]]::new()

function Add-I05SourceSelfTest {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][bool]$Passed,
        [AllowEmptyString()][string]$Detail = ''
    )

    $checks.Add([pscustomobject][ordered]@{
        name = $Name
        passed = $Passed
        detail = $Detail
    })
    if (-not $Passed) { $failures.Add($Name) }
}

function Invoke-I05SourceExpectedFailure {
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Action,
        [Parameter(Mandatory = $true)][string]$Pattern
    )

    try {
        & $Action
        return $false
    } catch {
        return $_.Exception.Message -match $Pattern
    }
}

function Get-I05SourceFunctionScript {
    param(
        [Parameter(Mandatory = $true)]
        [Management.Automation.Language.ScriptBlockAst]$Ast,
        [Parameter(Mandatory = $true)][string[]]$Names
    )

    $definitions = @($Ast.FindAll({
        param($node)
        $node -is
            [Management.Automation.Language.FunctionDefinitionAst] -and
        $Names -contains $node.Name
    }, $true))
    if ($definitions.Count -ne $Names.Count) {
        throw 'Could not isolate every requested runner function.'
    }
    $ordered = foreach ($name in $Names) {
        $definitions | Where-Object Name -eq $name |
            Select-Object -First 1
    }
    return [ScriptBlock]::Create(
        (($ordered | ForEach-Object { $_.Extent.Text }) -join "`r`n"))
}

function ConvertTo-I05SourceSelfTestJsonBytes {
    param([Parameter(Mandatory = $true)][object]$Value)

    $utf8 = New-Object Text.UTF8Encoding($false, $true)
    return $utf8.GetBytes(
        ($Value | ConvertTo-Json -Depth 32 -Compress))
}

function New-I05SourceSelfTestZipBytes {
    param(
        [Parameter(Mandatory = $true)]
        [Collections.IDictionary]$Entries,
        [Collections.IDictionary]$Renames = @{},
        [AllowEmptyString()][string]$ReparseEntry = ''
    )

    Add-Type -AssemblyName System.IO.Compression
    $memory = New-Object IO.MemoryStream
    $archive = New-Object IO.Compression.ZipArchive(
        $memory, [IO.Compression.ZipArchiveMode]::Create, $true)
    try {
        foreach ($sourceName in $Entries.Keys) {
            $entryName = if ($Renames.Contains($sourceName)) {
                [string]$Renames[$sourceName]
            } else {
                [string]$sourceName
            }
            $entry = $archive.CreateEntry(
                $entryName, [IO.Compression.CompressionLevel]::Optimal)
            if ($sourceName -eq $ReparseEntry) {
                $entry.ExternalAttributes =
                    [int][IO.FileAttributes]::ReparsePoint
            }
            $stream = $entry.Open()
            try {
                $bytes = [byte[]]$Entries[$sourceName]
                $stream.Write($bytes, 0, $bytes.Length)
            } finally {
                $stream.Dispose()
            }
        }
    } finally {
        $archive.Dispose()
    }
    try {
        return $memory.ToArray()
    } finally {
        $memory.Dispose()
    }
}

function New-I05SourceSelfTestContainment {
    param(
        [Parameter(Mandatory = $true)][string]$SourceIPv4,
        [Parameter(Mandatory = $true)][string]$Nonce
    )

    $sourceValue = ConvertTo-I05SourceIPv4UInt64 `
        -Address $SourceIPv4 -Context 'Self-test containment source'
    $loopbackStart = ConvertTo-I05SourceIPv4UInt64 `
        -Address '127.0.0.0' -Context 'Self-test loopback start'
    $loopbackEnd = ConvertTo-I05SourceIPv4UInt64 `
        -Address '127.255.255.255' -Context 'Self-test loopback end'
    $sourceComplement = @(Get-I05SourceIPv4ComplementTokens `
        -AllowedIntervals @(
            [pscustomobject]@{ start = $sourceValue; end = $sourceValue }
        ))
    $sourceLoopbackComplement = @(
        Get-I05SourceIPv4ComplementTokens -AllowedIntervals @(
            [pscustomobject]@{ start = $sourceValue; end = $sourceValue },
            [pscustomobject]@{
                start = $loopbackStart
                end = $loopbackEnd
            }
        )
    )
    $addresses = [ordered]@{
        in_tcp_v4_not_h1 = $sourceComplement
        in_tcp_v6_all = @('::/1', '8000::/1')
        in_udp_v4_all = @('0.0.0.0-255.255.255.255')
        in_udp_v6_all = @('::/1', '8000::/1')
        out_tcp_v4_not_h1_loopback = $sourceLoopbackComplement
        out_tcp_v4_h1_wrong_ports = @($SourceIPv4)
        out_tcp_v4_loopback_non_api_local_ports = @(
            '127.0.0.0-127.255.255.255'
        )
        out_tcp_v6_all = @('::/1', '8000::/1')
        out_udp_v4_all = @('0.0.0.0-255.255.255.255')
        out_udp_v6_all = @('::/1', '8000::/1')
    }
    $roles = @($addresses.Keys)
    $rules = [Collections.Generic.List[object]]::new()
    $lines = [Collections.Generic.List[string]]::new()
    $names = [Collections.Generic.List[string]]::new()
    foreach ($role in $roles) {
        $direction = if ($role.StartsWith(
                'in_', [StringComparison]::Ordinal)) {
            'Inbound'
        } else {
            'Outbound'
        }
        $protocol = if ($role.Contains('_tcp_')) { 'TCP' } else { 'UDP' }
        [string[]]$localPorts = if ($role -ceq
            'out_tcp_v4_loopback_non_api_local_ports') {
            @(
                "1-$($constants.downloader_web_port - 1)",
                "$($constants.downloader_web_port + 1)-65535"
            )
        } elseif ($role -ceq 'in_tcp_v4_not_h1') {
            @([string]$constants.downloader_tcp_port)
        } else {
            @('Any')
        }
        [string[]]$remotePorts = if ($role -ceq
            'out_tcp_v4_h1_wrong_ports') {
            @(
                "1-$($constants.source_tcp_port - 1)",
                "$($constants.source_tcp_port + 1)-65535"
            )
        } else {
            @('Any')
        }
        [string[]]$addressTokens = @(
            $addresses[$role] | Sort-Object -Unique
        )
        [string[]]$localPorts = @($localPorts | Sort-Object -Unique)
        [string[]]$remotePorts = @($remotePorts | Sort-Object -Unique)
        $roleToken = $role.Replace('_', '-')
        $name = "eSE-V91-I05-H3-Isolation-$Nonce-$roleToken"
        $names.Add($name)
        $nameHash = Get-LabStringSha256 -Value $name
        $addressHash =
            Get-LabStringSha256 -Value ($addressTokens -join "`n")
        $rule = [pscustomobject][ordered]@{
            role = $role
            name_sha256 = $nameHash
            direction = $direction
            action = 'Block'
            enabled = $true
            profile = 'Any'
            protocol = $protocol
            local_ports = @($localPorts)
            remote_ports = @($remotePorts)
            remote_addresses_sha256 = $addressHash
            remote_address_count = $addressTokens.Count
            program_sha256 = $constants.candidate_emule_sha256
            all_interfaces = $true
        }
        $rules.Add($rule)
        $canonicalLine = (
            'role={0}|name_sha256={1}|direction={2}|' +
            'action=Block|enabled=true|profile=Any|protocol={3}|' +
            'local_ports={4}|remote_ports={5}|' +
            'remote_addresses_sha256={6}|remote_address_count={7}|' +
            'program_sha256={8}|all_interfaces=true'
        ) -f @(
            $role,
            $nameHash,
            $direction,
            $protocol,
            ($localPorts -join ','),
            ($remotePorts -join ','),
            $addressHash,
            [string]$addressTokens.Count,
            $constants.candidate_emule_sha256
        )
        $lines.Add($canonicalLine)
    }
    [string[]]$orderedLines = $lines.ToArray()
    [string[]]$orderedNames = $names.ToArray()
    [Array]::Sort($orderedLines, [StringComparer]::Ordinal)
    [Array]::Sort($orderedNames, [StringComparer]::Ordinal)
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.i05.t1-firewall-containment/v1'
        rule_count = 10
        rule_names_sha256 =
            Get-LabStringSha256 -Value ($orderedNames -join "`n")
        spec_sha256 =
            Get-LabStringSha256 -Value ($orderedLines -join "`n")
        spec_document_sha256 =
            Get-LabStringSha256 -Value 'self-test-containment-spec-document'
        inventory_before_sha256 =
            Get-LabStringSha256 -Value 'self-test-containment-before'
        inventory_armed_sha256 =
            Get-LabStringSha256 -Value 'self-test-containment-armed'
        inventory_verified_sha256 =
            Get-LabStringSha256 -Value 'self-test-containment-verified'
        state_before_sha256 =
            Get-LabStringSha256 -Value 'self-test-state-before'
        state_armed_sha256 =
            Get-LabStringSha256 -Value 'self-test-state-armed'
        state_verified_sha256 =
            Get-LabStringSha256 -Value 'self-test-state-armed'
        direct_link_only = $true
        third_party_sources_forbidden = $true
        exact_rules_armed = $true
        third_party_bytes_impossible = $true
        watchdog_interval_ms = 500
        watchdog_samples = 4
        watchdog_violations = 0
        verification_count = 2
        inventory_scope = 'exact-ten-nonce-program-rules-only'
        profile_scope = 'Any'
        firewall_service_running = $true
        firewall_profiles_enabled = $true
        firewall_profile_count = 3
        firewall_profiles_sha256 = Get-LabStringSha256 `
            -Value "Domain=true`nPrivate=true`nPublic=true"
        engine_watchdog_samples = 4
        engine_watchdog_exact_filter_checks = 4
        canonical_rules = @($rules.ToArray())
    }
}

foreach ($file in @(
    $contractPath, $runnerPath, $cleanupPath, $testPath
)) {
    $tokens = $null
    $parseErrors = $null
    [void][Management.Automation.Language.Parser]::ParseFile(
        $file, [ref]$tokens, [ref]$parseErrors)
    Add-I05SourceSelfTest -Name (
        'ps5-parse-' + [IO.Path]::GetFileNameWithoutExtension($file)
    ) -Passed ($parseErrors.Count -eq 0) `
        -Detail (($parseErrors | ForEach-Object {
            $_.Message
        }) -join '; ')
}

Add-I05SourceSelfTest -Name 'exact-server-hash-length' `
    -Passed (
        $constants.candidate_ese_server_sha256 -match
            '^[0-9a-f]{64}$' -and
        $constants.candidate_ese_server_sha256 -eq
            'c12e71a1602bb7b55077b82a72000a6980790fdf75d90bdbcba8d2843f7a0ba2'
    )
Add-I05SourceSelfTest -Name 'exact-rc3-candidate-contract' `
    -Passed (
        $constants.candidate_version -ceq '9.1.0-rc.3' -and
        $constants.candidate_commit -ceq
            '815b45ca7a1415bd3e06ff043d53794bc340b346' -and
        $constants.candidate_emule_sha256 -ceq
            '94620cf502c954cda29fa7f40f834ef1eebacb753f1fe277865d1d173e0b9b41' -and
        $constants.candidate_build_info_sha256 -ceq
            '48445ff0231908aa1edbb21970bcb38b91397c643c7012b65b62686bc8a63428'
    )
Add-I05SourceSelfTest -Name 'exact-zip-contract' `
    -Passed (
        $constants.candidate_zip_bytes -eq 212040831 -and
        $constants.candidate_zip_sha256 -eq
            '359272c764c532c32cfd97eeb92e2db4feaa620c5d3f6318a82a7453dbf1b56f'
    )
Add-I05SourceSelfTest -Name 'exact-fixture-contract' `
    -Passed (
        $constants.fixture_bytes -eq 4294967296 -and
        $constants.fixture_sha256 -eq
            '1016d6f63ae1649a879a7c0de30865ed132deb37b1c3b2bc9ca004c88feee26c' -and
        $constants.fixture_ed2k -eq
            '796A95E75DF8E78D54A57CDEA1FEDE84'
    )
Add-I05SourceSelfTest -Name 'fixed-port-contract' `
    -Passed (
        $constants.source_tcp_port -eq 7862 -and
        $constants.source_udp_port -eq 7872 -and
        $constants.source_web_port -eq 7911 -and
        $constants.source_probe_port -eq 7912 -and
        $constants.downloader_tcp_port -eq 7962 -and
        $constants.downloader_udp_port -eq 7972 -and
        $constants.downloader_web_port -eq 8011 -and
        $constants.downloader_control_port -eq 8012
    )

Add-I05SourceSelfTest -Name 'subnet-22-positive' -Passed (
    Test-I05Ipv4SameSubnet -Left '192.168.222.60' `
        -Right '192.168.223.254' -PrefixLength 22)
Add-I05SourceSelfTest -Name 'subnet-22-negative' -Passed (
    -not (Test-I05Ipv4SameSubnet -Left '192.168.222.60' `
        -Right '192.168.224.1' -PrefixLength 22))

$apiNetworksOff = [pscustomobject][ordered]@{
    kad_connected = $false
    kad6_running = $false
    kad6_connected = $false
}
$strictApiPositive = $true
try {
    Assert-I05ApiNetworksOff -Status $apiNetworksOff `
        -Context 'Self-test API'
} catch {
    $strictApiPositive = $false
}
Add-I05SourceSelfTest -Name 'api-network-flags-strict-positive' `
    -Passed $strictApiPositive
$missingApiField = [pscustomobject][ordered]@{
    kad_connected = $false
    kad6_running = $false
}
Add-I05SourceSelfTest -Name 'api-network-flags-reject-missing' `
    -Passed (Invoke-I05SourceExpectedFailure -Action {
        Assert-I05ApiNetworksOff -Status $missingApiField `
            -Context 'Missing API'
    } -Pattern 'kad6_connected')
$malformedApiField = [pscustomobject][ordered]@{
    kad_connected = 0
    kad6_running = $false
    kad6_connected = $false
}
Add-I05SourceSelfTest -Name 'api-network-flags-reject-nonboolean' `
    -Passed (Invoke-I05SourceExpectedFailure -Action {
        Assert-I05ApiNetworksOff -Status $malformedApiField `
            -Context 'Malformed API'
    } -Pattern 'JSON boolean false')

$candidate = [pscustomobject][ordered]@{
    version = $constants.candidate_version
    commit = $constants.candidate_commit
    dirty = $false
    emule_sha256 = $constants.candidate_emule_sha256
    ese_server_sha256 = $constants.candidate_ese_server_sha256
    build_info_sha256 = $constants.candidate_build_info_sha256
    zip_sha256 = $constants.candidate_zip_sha256
    zip_bytes = $constants.candidate_zip_bytes
}
$candidatePositive = $true
try {
    Assert-I05CandidateContract -Candidate $candidate `
        -Context 'Self-test candidate'
} catch {
    $candidatePositive = $false
}
Add-I05SourceSelfTest -Name 'candidate-positive' `
    -Passed $candidatePositive
$badCandidate = $candidate | ConvertTo-Json -Depth 4 |
    ConvertFrom-Json
$badCandidate.zip_bytes = 1
Add-I05SourceSelfTest -Name 'candidate-rejects-wrong-zip' `
    -Passed (Invoke-I05SourceExpectedFailure -Action {
        Assert-I05CandidateContract -Candidate $badCandidate `
            -Context 'Bad candidate'
    } -Pattern 'zip_bytes')

$hostIdOne = Get-I05HostIdSha256
$hostIdTwo = Get-I05HostIdSha256
Add-I05SourceSelfTest -Name 'canonical-host-id-stable' `
    -Passed (
        $hostIdOne -match '^[0-9a-f]{64}$' -and
        $hostIdOne -ceq $hostIdTwo
    )

$runnerText = [IO.File]::ReadAllText($runnerPath)
$cleanupText = [IO.File]::ReadAllText($cleanupPath)
$allText = $runnerText + "`n" + $cleanupText
$forbiddenPatterns = [ordered]@{
    'no-disable-ipv6-binding' =
        '(?i)\bDisable-NetAdapterBinding\b'
    'no-disabledcomponents-registry' =
        '(?i)DisabledComponents'
    'no-recursive-delete' =
        '(?i)\bRemove-Item\b[^\r\n]*-(?:Recurse|r)\b'
    'no-process-name-kill' =
        '(?i)\bStop-Process\b[^\r\n]*-(?:Name|ProcessName)\b'
    'no-firewall-display-removal' =
        '(?i)\bRemove-NetFirewallRule\b[^\r\n]*-DisplayName\b'
    'no-overlay-address-literal' =
        '(?i)fd7a:115c|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.'
    'no-hardcoded-private-lan' =
        '(?<![\d.])192\.168\.\d{1,3}\.\d{1,3}(?![\d.])'
}
foreach ($entry in $forbiddenPatterns.GetEnumerator()) {
    Add-I05SourceSelfTest -Name $entry.Key `
        -Passed ($allText -notmatch $entry.Value)
}

Add-I05SourceSelfTest -Name 'runner-requires-exact-zip' `
    -Passed (
        $runnerText -match '\$CandidateZipPath' -and
        $runnerText -match 'candidate_zip_bytes' -and
        $runnerText -match 'candidate_zip_sha256' -and
        $runnerText -notmatch '\$PackagePath'
    )
Add-I05SourceSelfTest -Name 'runner-single-direct-link-only-command' `
    -Passed (
        $runnerText -match
            '\$fileLinkPrefix = ''ed2k://\|file\|''' -and
        ([regex]::Matches(
            $runnerText, 'direct_link\s*=\s*\$directLink')).Count -eq 1 -and
        ([regex]::Matches(
            $runnerText, 'delivery_count\s*=\s*1')).Count -eq 1 -and
        $runnerText -match 'direct_only\s*=\s*\$true' -and
        $runnerText -match 'direct_link_only\s*=\s*\$true' -and
        $runnerText -match
            'third_party_sources_forbidden\s*=\s*\$true' -and
        $runnerText -notmatch (
            '(?i)base_link|base_injected|base_first|' +
            'queue_owned_before_direct|direct_after_queue_owned'
        )
    )
Add-I05SourceSelfTest -Name 'runner-source-ed2k-locally-proved' `
    -Passed (
        $runnerText -match
            'fresh-candidate-shared-list-local-calculation' -and
        $runnerText -match 'source_local_ed2k_verified' -and
        $runnerText -match 'source_shared_page_sha256'
    )
Add-I05SourceSelfTest -Name 'runner-private-lan-peer-acceptance' `
    -Passed (
        $runnerText -match "FilterBadIPs = '0'" -and
        $runnerText -match
            '\(\?im\)\^\\s\*FilterBadIPs\\s\*=\\s\*0\\s\*\$'
    )
Add-I05SourceSelfTest -Name 'runner-unattended-exit' `
    -Passed (
        $runnerText -match "ConfirmExit = '0'" -and
        $runnerText -match
            '\(\?im\)\^\\s\*ConfirmExit\\s\*=\\s\*0\\s\*\$'
    )
Add-I05SourceSelfTest -Name 'runner-all-kad-off-profile' `
    -Passed (
        $runnerText -match "NetworkKademlia = '0'" -and
        $runnerText -match "-Key 'KadNetworkMask' -Value '0'" -and
        $runnerText -match 'Assert-I05ApiNetworksOff' -and
        $runnerText -notmatch "NetworkKademlia = '1'" -and
        $runnerText -notmatch "-Key 'KadNetworkMask' -Value '1'"
    )
Add-I05SourceSelfTest -Name 'runner-first-api-is-strict-before-observation' `
    -Passed (
        $runnerText.IndexOf(
            '$sourceStatus = Wait-I05SourceApi',
            [StringComparison]::Ordinal) -ge 0 -and
        $runnerText.IndexOf(
            "Context 'H1 source first API response'",
            [StringComparison]::Ordinal) -gt
            $runnerText.IndexOf(
                '$sourceStatus = Wait-I05SourceApi',
                [StringComparison]::Ordinal) -and
        $runnerText.IndexOf(
            'Assert-I05SourceOwnedListeners `',
            [StringComparison]::Ordinal) -gt
            $runnerText.IndexOf(
                "Context 'H1 source first API response'",
                [StringComparison]::Ordinal) -and
        $runnerText -notmatch '(?i)/api/network/connect'
    )
Add-I05SourceSelfTest -Name 'runner-classic-crypto-off' `
    -Passed (
        $runnerText -match "CryptLayerRequested = '0'" -and
        $runnerText -match "CryptLayerRequired = '0'" -and
        $runnerText -match "CryptLayerSupported = '0'"
    )
Add-I05SourceSelfTest -Name 'runner-central-route-pair' `
    -Passed (
        $runnerText -match 'Get-I05EffectiveRouteEvidence' -and
        $runnerText -notmatch
            'Find-NetRoute[\s\S]{0,120}Select-Object -First 1'
    )
Add-I05SourceSelfTest -Name 'runner-lan-control-framing' `
    -Passed (
        $runnerText -match 'V91-I05-\$Type' -and
        $runnerText -match 'maximum_frame_bytes = 1048576' -and
        $runnerText -match "transport = 'lan-tcp-v1'" -and
        $runnerText -match 'downloader_control_port'
    )
Add-I05SourceSelfTest -Name 'runner-no-h1-pktmon' `
    -Passed (
        $runnerText -notmatch '(?i)&\s*pktmon|Start-Process[^\r\n]*pktmon'
    )
Add-I05SourceSelfTest -Name 'runner-no-obsolete-h1-capture-contract' `
    -Passed (
        $runnerText -notmatch 'Assert-I05SourceCapture' -and
        $runnerText -notmatch '\$sourceCapture\b' -and
        $runnerText -notmatch 'source-capture-(?:arm|complete)'
    )
Add-I05SourceSelfTest -Name 'runner-ipv6-binding-query-is-valid' `
    -Passed (
        $runnerText -match
            'Get-NetAdapterBinding\s+-Name\s+\$network\.interface_alias' -and
        $runnerText -notmatch
            'Get-NetAdapterBinding\s+-InterfaceIndex'
    )
Add-I05SourceSelfTest -Name 'runner-control-fail-fast-and-timeout-aligned' `
    -Passed (
        $runnerText -match
            '\[int\]\$TransferTimeoutSeconds\s*=\s*7200' -and
        $runnerText -match (
            '\$transferStarted\.AddSeconds\(\s*' +
            '\$TransferTimeoutSeconds\s*\+\s*' +
            '\$CompletionTimeoutSeconds\s*\)'
        ) -and
        $runnerText -match
            'SelectMode\]::SelectRead' -and
        $runnerText -match
            'H3 closed the physical control stream during transfer'
    )
Add-I05SourceSelfTest -Name 'runner-wire-gates-h3' `
    -Passed (
        $runnerText -match 'requestparts_i64' -and
        $runnerText -match 'sending_i64' -and
        $runnerText -match 'compressed_i64' -and
        $runnerText -match 'analysis_sha256' -and
        $runnerText -match 'ed2k_framing_valid' -and
        $runnerText -match 'socket-watchdog-context-only' -and
        $runnerText -match 'pcap_pid_attributed' -and
        $runnerText -match 'tuple_allowlist_pid_observed' -and
        $runnerText -match 'process_scoped_containment' -and
        $runnerText -notmatch 'candidate_pid_correlated' -and
        $runnerText -match 'filter_inventory_restored'
    )
Add-I05SourceSelfTest -Name 'runner-evidence-bundle-fail-closed' `
    -Passed (
        $runnerText -match 'evidence_bundle_max_bytes' -and
        $runnerText -match 'h3-evidence-bundle\.zip' -and
        $runnerText -match 'case-insensitive duplicate' -and
        $runnerText -match 'retained_raw' -and
        $runnerText -match 'component_mapping_sha256' -and
        $runnerText -match 'observed_ephemeral_ports'
    )
Add-I05SourceSelfTest -Name 'runner-validates-ten-rule-containment' `
    -Passed (
        $runnerText -match
            'ese\.v91\.i05\.t1-firewall-containment/v1' -and
        $runnerText -match 'rule_count must be the JSON integer 10' -and
        $runnerText -match 'out_tcp_v4_h1_wrong_ports' -and
        $runnerText -match
            'out_tcp_v4_loopback_non_api_local_ports' -and
        $runnerText -match 'in_udp_v4_all' -and
        $runnerText -match 'out_udp_v4_all' -and
        $runnerText -notmatch 'in_udp_v4_nonloopback' -and
        $runnerText -notmatch 'out_udp_v4_nonloopback' -and
        $runnerText -match '0\.0\.0\.0-255\.255\.255\.255' -and
        $runnerText -match 'out_udp_v6_all' -and
        $runnerText -match 'recomputed canonical spec' -and
        $runnerText -match 'third_party_bytes_impossible' -and
        $runnerText -match 'spec_document_sha256' -and
        $runnerText -match 'engine_watchdog_exact_filter_checks'
    )
Add-I05SourceSelfTest -Name 'runner-validates-containment-cleanup' `
    -Passed (
        $runnerText -match 'isolation_rule_count' -and
        $runnerText -match
            'isolation_rule_count is not the JSON integer 10' -and
        $runnerText -match 'isolation_rules_absent' -and
        $runnerText -match 'isolation_spec_document_sha256' -and
        $runnerText -match 'isolation_inventory_after_sha256' -and
        $runnerText -match 'isolation_state_before_sha256' -and
        $runnerText -match 'isolation_state_after_sha256' -and
        $runnerText -match 'inventory_restored'
    )
Add-I05SourceSelfTest -Name 'runner-evidence-path-safety-complete' `
    -Passed (
        $runnerText -match 'IsPathRooted\(\$name\)' -and
        $runnerText -match "\.Contains\(':'\)" -and
        $runnerText -match 'FileAttributes\]::ReparsePoint' -and
        $runnerText -match 'OrdinalIgnoreCase'
    )
Add-I05SourceSelfTest -Name 'runner-failure-classification-contract' `
    -Passed (
        $runnerText -match 'ese\.v91\.i05\.t1-failure/v1' -and
        $runnerText -match 'LAB_BLOCKED' -and
        $runnerText -match 'PRODUCT_INVARIANT' -and
        $runnerText -match 'remote-lab-blocked' -and
        $runnerText -match 'direct-injection-invariant' -and
        $runnerText -match (
            '\$formalStatus -ne ''FAIL''[\s\S]{0,100}' +
            '\$formalStatus = ''BLOCKED'''
        )
    )
Add-I05SourceSelfTest -Name 'runner-product-checkpoints-classified' `
    -Passed (
        $runnerText -match 'source-profile-network-state' -and
        $runnerText -match 'source-local-ed2k-proof' -and
        $runnerText -match 'source-api-unresponsive-at-complete' -and
        $runnerText -match 'physical-ipv6-binding-changed' -and
        $runnerText -match 'h3-file-integrity-complete' -and
        $runnerText -match 'h3-file-integrity-evidence' -and
        $runnerText -match 'h3-node-state-complete' -and
        $runnerText -match 'h3-wire-invariant-complete' -and
        $runnerText -match 'h3-wire-invariant-evidence' -and
        $runnerText -match 'h3-socket-invariant-evidence' -and
        $runnerText -match (
            '(?s)try\s*\{\s*' +
            '\$classicSession\s*=\s*Get-I05SourceClassicSession.*?' +
            '\$shared\s*=\s*Get-I05SourceSharedLink.*?' +
            '\}\s*catch\s*\{.*?source-local-ed2k-proof'
        )
    )
Add-I05SourceSelfTest -Name 'runner-firewall-pending-before-mutation' `
    -Passed (
        ($probePendingIndex = $runnerText.IndexOf(
            '$ownership.firewall.probe_pending = $true',
            [StringComparison]::Ordinal)) -ge 0 -and
        ($probeOwnershipWriteIndex = $runnerText.IndexOf(
            'Write-I05SourceOwnership', $probePendingIndex,
            [StringComparison]::Ordinal)) -gt $probePendingIndex -and
        ($probeRuleCreateIndex = $runnerText.IndexOf(
            'New-NetFirewallRule -Name $probeFirewallName',
            [StringComparison]::Ordinal)) -gt $probeOwnershipWriteIndex -and
        ($dataPendingIndex = $runnerText.IndexOf(
            '$ownership.firewall.data_pending = $true',
            [StringComparison]::Ordinal)) -ge 0 -and
        ($dataOwnershipWriteIndex = $runnerText.IndexOf(
            'Write-I05SourceOwnership', $dataPendingIndex,
            [StringComparison]::Ordinal)) -gt $dataPendingIndex -and
        ($dataRuleCreateIndex = $runnerText.IndexOf(
            'New-NetFirewallRule -Name $dataFirewallName',
            [StringComparison]::Ordinal)) -gt $dataOwnershipWriteIndex
    )
Add-I05SourceSelfTest -Name 'cleanup-full-nonce-firewall' `
    -Passed (
        $cleanupText -match
            '"eSE-V91-I05-PROBE-\$nonce"' -and
        $cleanupText -match
            '"eSE-V91-I05-DATA-\$nonce"'
    )
Add-I05SourceSelfTest -Name 'cleanup-pending-launch-safe' `
    -Passed (
        $cleanupText -match 'launch_pending' -and
        $cleanupText -match 'launch_not_before_utc' -and
        $cleanupText -match 'Pending launch maps to more than one'
    )
Add-I05SourceSelfTest -Name 'cleanup-exact-firewall-policy' `
    -Passed (
        $cleanupText -match 'EdgeTraversalPolicy' -and
        $cleanupText -match "Expected 'Block'" -and
        $cleanupText -match "Expected 'Any'"
    )
Add-I05SourceSelfTest -Name 'cleanup-handles-owned-pending-rules' `
    -Passed (
        $cleanupText -match
            "-Name 'probe_pending' -Context 'Ownership\.firewall'" -and
        $cleanupText -match
            "-Name 'data_pending' -Context 'Ownership\.firewall'" -and
        $cleanupText -match 'ownership_pending_before' -and
        $cleanupText -match 'Assert-I05CleanupFirewallRule'
    )

$runnerTokens = $null
$runnerErrors = $null
$runnerAst =
    [Management.Automation.Language.Parser]::ParseFile(
        $runnerPath, [ref]$runnerTokens, [ref]$runnerErrors)
$cleanupTokens = $null
$cleanupErrors = $null
$cleanupAst =
    [Management.Automation.Language.Parser]::ParseFile(
        $cleanupPath, [ref]$cleanupTokens, [ref]$cleanupErrors)
$runnerHttpCommands = @($runnerAst.FindAll({
    param($node)
    $node -is [Management.Automation.Language.CommandAst] -and
    $node.GetCommandName() -in @(
        'Invoke-RestMethod', 'Invoke-WebRequest'
    )
}, $true))
Add-I05SourceSelfTest -Name 'runner-local-http-errors-terminate' `
    -Passed (
        $runnerHttpCommands.Count -eq 6 -and
        @($runnerHttpCommands | Where-Object {
            $_.Extent.Text -notmatch '(?i)-ErrorAction\s+Stop'
        }).Count -eq 0
    )
$socketEnumerationCommands = @(
    @($runnerAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.CommandAst] -and
        $node.GetCommandName() -in @(
            'Get-NetTCPConnection', 'Get-NetUDPEndpoint'
        )
    }, $true))
    @($cleanupAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.CommandAst] -and
        $node.GetCommandName() -in @(
            'Get-NetTCPConnection', 'Get-NetUDPEndpoint'
        )
    }, $true))
)
Add-I05SourceSelfTest -Name 'socket-enumerations-are-unfiltered-fail-closed' `
    -Passed (
        $socketEnumerationCommands.Count -eq 4 -and
        @($socketEnumerationCommands | Where-Object {
            $_.Extent.Text -notmatch
                '(?i)-ErrorAction\s+Stop' -or
            $_.Extent.Text -match
                '(?i)-(?:OwningProcess|LocalPort|State)\b'
        }).Count -eq 0
    )
$cleanupProcessCommands = @($cleanupAst.FindAll({
    param($node)
    $node -is [Management.Automation.Language.CommandAst] -and
    $node.GetCommandName() -eq 'Get-Process'
}, $true))
Add-I05SourceSelfTest -Name 'cleanup-process-presence-never-silent' `
    -Passed (
        $cleanupProcessCommands.Count -eq 1 -and
        @($cleanupProcessCommands | Where-Object {
            $_.Extent.Text -notmatch '(?i)-ErrorAction\s+Stop' -or
            $_.Extent.Text -match '(?i)SilentlyContinue'
        }).Count -eq 0 -and
        $cleanupText -match
            'Get-CimInstance\s+-ClassName\s+Win32_Process' -and
        $cleanupText -match 'process-enumeration-failed'
    )
$socketSnapshotFunctionsLoaded = $true
try {
    $socketSnapshotScript = Get-I05SourceFunctionScript -Ast $runnerAst `
        -Names @(
            'New-I05SourceClassifiedException',
            'Throw-I05SourceLabBlocked',
            'Get-I05SourceTcpSnapshot',
            'Get-I05SourceUdpSnapshot'
        )
    . $socketSnapshotScript
} catch {
    $socketSnapshotFunctionsLoaded = $false
}
Add-I05SourceSelfTest -Name 'socket-snapshot-functions-load' `
    -Passed $socketSnapshotFunctionsLoaded
if ($socketSnapshotFunctionsLoaded) {
    $tcpEnumerationFailsClosed = & {
        function Get-NetTCPConnection {
            throw 'synthetic TCP enumeration failure'
        }
        try {
            $null = Get-I05SourceTcpSnapshot
            return $false
        } catch {
            return (
                [string]$_.Exception.Data['I05Classification'] -eq
                    'LAB_BLOCKED' -and
                [string]$_.Exception.Data['I05Category'] -eq
                    'tcp-enumeration-failed'
            )
        }
    }
    Add-I05SourceSelfTest -Name 'tcp-enumeration-error-is-blocked' `
        -Passed $tcpEnumerationFailsClosed

    $udpEnumerationFailsClosed = & {
        function Get-NetUDPEndpoint {
            throw 'synthetic UDP enumeration failure'
        }
        try {
            $null = Get-I05SourceUdpSnapshot
            return $false
        } catch {
            return (
                [string]$_.Exception.Data['I05Classification'] -eq
                    'LAB_BLOCKED' -and
                [string]$_.Exception.Data['I05Category'] -eq
                    'udp-enumeration-failed'
            )
        }
    }
    Add-I05SourceSelfTest -Name 'udp-enumeration-error-is-blocked' `
        -Passed $udpEnumerationFailsClosed

    $emptyEnumerationIsValid = & {
        function Get-NetTCPConnection { return @() }
        try {
            return @(Get-I05SourceTcpSnapshot).Count -eq 0
        } catch {
            return $false
        }
    }
    Add-I05SourceSelfTest -Name 'empty-tcp-snapshot-is-not-an-error' `
        -Passed $emptyEnumerationIsValid
}
$cleanupSnapshotFunctionsLoaded = $true
try {
    $cleanupSnapshotScript = Get-I05SourceFunctionScript -Ast $cleanupAst `
        -Names @(
            'Get-I05CleanupRule',
            'Get-I05CleanupDisplayRule',
            'Get-I05CleanupFirewallSnapshot',
            'Get-I05CleanupTcpSnapshot',
            'Get-I05CleanupUdpSnapshot',
            'Get-I05CleanupProcessById'
        )
    . $cleanupSnapshotScript
} catch {
    $cleanupSnapshotFunctionsLoaded = $false
}
Add-I05SourceSelfTest -Name 'cleanup-snapshot-functions-load' `
    -Passed $cleanupSnapshotFunctionsLoaded
if ($cleanupSnapshotFunctionsLoaded) {
    $cleanupMissingNameIsAbsent = & {
        function Get-NetFirewallRule {
            [CmdletBinding()]
            param(
                [string]$Name,
                [string]$DisplayName
            )
            $errorRecord = [Management.Automation.ErrorRecord]::new(
                [InvalidOperationException]::new(
                    'synthetic missing firewall rule'
                ),
                'CmdletizationQuery_NotFound_InstanceID',
                [Management.Automation.ErrorCategory]::NotSpecified,
                $Name
            )
            $PSCmdlet.ThrowTerminatingError($errorRecord)
        }
        try {
            return @(Get-I05CleanupRule -Name 'missing-rule').Count -eq 0
        } catch {
            return $false
        }
    }
    Add-I05SourceSelfTest -Name 'cleanup-missing-rule-name-is-absent' `
        -Passed $cleanupMissingNameIsAbsent

    $cleanupMissingDisplayIsAbsent = & {
        function Get-NetFirewallRule {
            [CmdletBinding()]
            param(
                [string]$Name,
                [string]$DisplayName
            )
            $errorRecord = [Management.Automation.ErrorRecord]::new(
                [InvalidOperationException]::new(
                    'synthetic missing firewall display name'
                ),
                'SyntheticObjectNotFound',
                [Management.Automation.ErrorCategory]::ObjectNotFound,
                $DisplayName
            )
            $PSCmdlet.ThrowTerminatingError($errorRecord)
        }
        try {
            return @(
                Get-I05CleanupDisplayRule -DisplayName 'missing-display'
            ).Count -eq 0
        } catch {
            return $false
        }
    }
    Add-I05SourceSelfTest -Name 'cleanup-missing-display-is-absent' `
        -Passed $cleanupMissingDisplayIsAbsent

    $cleanupFirewallFailsClosed = & {
        function Get-NetFirewallRule {
            throw 'synthetic firewall enumeration failure'
        }
        try {
            $null = Get-I05CleanupFirewallSnapshot
            return $false
        } catch {
            return (
                [string]$_.Exception.Data['I05Classification'] -eq
                    'LAB_BLOCKED' -and
                [string]$_.Exception.Data['I05Category'] -eq
                    'firewall-enumeration-failed'
            )
        }
    }
    Add-I05SourceSelfTest -Name 'cleanup-firewall-error-is-blocked' `
        -Passed $cleanupFirewallFailsClosed

    $cleanupTcpFailsClosed = & {
        function Get-NetTCPConnection {
            throw 'synthetic cleanup TCP enumeration failure'
        }
        try {
            $null = Get-I05CleanupTcpSnapshot
            return $false
        } catch {
            return (
                [string]$_.Exception.Data['I05Category'] -eq
                    'tcp-enumeration-failed'
            )
        }
    }
    Add-I05SourceSelfTest -Name 'cleanup-tcp-error-is-blocked' `
        -Passed $cleanupTcpFailsClosed

    $cleanupUdpFailsClosed = & {
        function Get-NetUDPEndpoint {
            throw 'synthetic cleanup UDP enumeration failure'
        }
        try {
            $null = Get-I05CleanupUdpSnapshot
            return $false
        } catch {
            return (
                [string]$_.Exception.Data['I05Category'] -eq
                    'udp-enumeration-failed'
            )
        }
    }
    Add-I05SourceSelfTest -Name 'cleanup-udp-error-is-blocked' `
        -Passed $cleanupUdpFailsClosed

    $cleanupProcessEnumerationFailsClosed = & {
        function Get-CimInstance {
            throw 'synthetic process enumeration failure'
        }
        function Get-Process {
            throw 'Get-Process must not run after failed enumeration'
        }
        try {
            $null = Get-I05CleanupProcessById -ProcessId 4242
            return $false
        } catch {
            return (
                [string]$_.Exception.Data['I05Classification'] -eq
                    'LAB_BLOCKED' -and
                [string]$_.Exception.Data['I05Category'] -eq
                    'process-enumeration-failed'
            )
        }
    }
    Add-I05SourceSelfTest -Name 'cleanup-process-enumeration-error-blocked' `
        -Passed $cleanupProcessEnumerationFailsClosed

    $cleanupEmptyProcessIsAbsent = & {
        function Get-CimInstance { return @() }
        function Get-Process {
            throw 'Get-Process must not run for an absent PID'
        }
        try {
            return $null -eq (
                Get-I05CleanupProcessById -ProcessId 4242
            )
        } catch {
            return $false
        }
    }
    Add-I05SourceSelfTest -Name 'cleanup-empty-process-is-absent' `
        -Passed $cleanupEmptyProcessIsAbsent

    $cleanupProcessAccessErrorNotAbsent = & {
        function Get-CimInstance {
            return [pscustomobject]@{ ProcessId = 4242 }
        }
        function Get-Process {
            throw 'synthetic process access failure'
        }
        try {
            $null = Get-I05CleanupProcessById -ProcessId 4242
            return $false
        } catch {
            return (
                [string]$_.Exception.Data['I05Classification'] -eq
                    'LAB_BLOCKED' -and
                [string]$_.Exception.Data['I05Category'] -eq
                    'process-handle-open-failed'
            )
        }
    }
    Add-I05SourceSelfTest -Name 'cleanup-process-access-error-not-absent' `
        -Passed $cleanupProcessAccessErrorNotAbsent
}
$directInjectionFunctionsLoaded = $true
try {
    $directInjectionScript = Get-I05SourceFunctionScript `
        -Ast $runnerAst -Names @('Assert-I05SourceDirectInjection')
    . $directInjectionScript
} catch {
    $directInjectionFunctionsLoaded = $false
}
Add-I05SourceSelfTest -Name 'direct-injection-validator-loads' `
    -Passed $directInjectionFunctionsLoaded
if ($directInjectionFunctionsLoaded) {
    $directHash = 'a' * 64
    $directInjection = [pscustomobject][ordered]@{
        delivery_count = 1
        direct_injected = $true
        queue_owned_after_direct = $true
        direct_link_sha256 = $directHash
        queue_observed_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
    }
    $directPositive = $true
    try {
        Assert-I05SourceDirectInjection -Injection $directInjection `
            -DirectLinkSha256 $directHash
    } catch {
        $directPositive = $false
    }
    Add-I05SourceSelfTest -Name 'direct-injection-positive' `
        -Passed $directPositive

    $wrongDelivery = $directInjection | ConvertTo-Json -Depth 4 |
        ConvertFrom-Json
    $wrongDelivery.delivery_count = 2
    Add-I05SourceSelfTest -Name 'direct-injection-rejects-second-delivery' `
        -Passed (Invoke-I05SourceExpectedFailure -Action {
            Assert-I05SourceDirectInjection -Injection $wrongDelivery `
                -DirectLinkSha256 $directHash
        } -Pattern 'JSON integer 1')

    $stringDelivery = $directInjection | ConvertTo-Json -Depth 4 |
        ConvertFrom-Json
    $stringDelivery.delivery_count = '1'
    Add-I05SourceSelfTest -Name 'direct-injection-rejects-string-count' `
        -Passed (Invoke-I05SourceExpectedFailure -Action {
            Assert-I05SourceDirectInjection -Injection $stringDelivery `
                -DirectLinkSha256 $directHash
        } -Pattern 'JSON integer 1')

    $legacyInjection = [pscustomobject][ordered]@{
        delivery_count = 1
        direct_injected = $true
        queue_owned_after_direct = $true
        direct_link_sha256 = $directHash
        queue_observed_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
        base_link_sha256 = 'b' * 64
    }
    Add-I05SourceSelfTest -Name 'direct-injection-rejects-legacy-base' `
        -Passed (Invoke-I05SourceExpectedFailure -Action {
            Assert-I05SourceDirectInjection -Injection $legacyInjection `
                -DirectLinkSha256 $directHash
        } -Pattern 'exactly the five direct-only')

    $badTimestamp = $directInjection | ConvertTo-Json -Depth 4 |
        ConvertFrom-Json
    $badTimestamp.queue_observed_at_utc = 'not-a-timestamp'
    Add-I05SourceSelfTest -Name 'direct-injection-rejects-bad-time' `
        -Passed (Invoke-I05SourceExpectedFailure -Action {
            Assert-I05SourceDirectInjection -Injection $badTimestamp `
                -DirectLinkSha256 $directHash
        } -Pattern 'valid timestamp')
}
$frameFunctionNames = @(
    'New-I05SourceClassifiedException',
    'Get-I05SourceBytesSha256',
    'Read-I05SourceControlLine',
    'Read-I05SourceControlFrame',
    'Assert-I05SourceExpectedFrame'
)
$frameFunctionsLoaded = $true
try {
    $functionScript = Get-I05SourceFunctionScript `
        -Ast $runnerAst -Names $frameFunctionNames
    . $functionScript
} catch {
    $frameFunctionsLoaded = $false
}
Add-I05SourceSelfTest -Name 'frame-functions-load' `
    -Passed $frameFunctionsLoaded
if ($frameFunctionsLoaded) {
    $nonce = '0123456789abcdef0123456789abcdef'
    $bodyText = '{"schema":"ese.v91.i05.t1-ready/v1"}'
    $utf8 = New-Object Text.UTF8Encoding($false, $true)
    $body = $utf8.GetBytes($bodyText)
    $bodyHash = Get-I05SourceBytesSha256 -Bytes $body
    $header = [Text.Encoding]::ASCII.GetBytes(
        "V91-I05-READY $nonce $($body.Length) $bodyHash`n")
    $wire = New-Object byte[] ($header.Length + $body.Length)
    [Array]::Copy($header, 0, $wire, 0, $header.Length)
    [Array]::Copy($body, 0, $wire, $header.Length, $body.Length)
    $stream = New-Object IO.MemoryStream(,$wire)
    try {
        $frame = Read-I05SourceControlFrame -Stream $stream `
            -Type READY -Nonce $nonce -TimeoutSeconds 1
        Add-I05SourceSelfTest -Name 'frame-positive' -Passed (
            $frame.sha256 -ceq $bodyHash -and
            [string]$frame.document.schema -ceq
                'ese.v91.i05.t1-ready/v1')
    } finally {
        $stream.Dispose()
    }

    $badHeader = [Text.Encoding]::ASCII.GetBytes(
        "V91-I05-READY $nonce $($body.Length) " +
        ('0' * 64) + "`n")
    $badWire = New-Object byte[] ($badHeader.Length + $body.Length)
    [Array]::Copy($badHeader, 0, $badWire, 0, $badHeader.Length)
    [Array]::Copy(
        $body, 0, $badWire, $badHeader.Length, $body.Length)
    $badStream = New-Object IO.MemoryStream(,$badWire)
    try {
        $badRejected = Invoke-I05SourceExpectedFailure -Action {
            $null = Read-I05SourceControlFrame -Stream $badStream `
                -Type READY -Nonce $nonce -TimeoutSeconds 1
        } -Pattern 'SHA-256'
        Add-I05SourceSelfTest -Name 'frame-rejects-bad-sha' `
            -Passed $badRejected
    } finally {
        $badStream.Dispose()
    }

    $failureDocument = [pscustomobject][ordered]@{
        schema = 'ese.v91.i05.t1-failure/v1'
        case_id = $constants.case_id
        status = 'LAB_BLOCKED'
        nonce = $nonce
        phase = 'capture-conversion'
        category = 'component-filter'
        message_sha256 = Get-LabStringSha256 -Value 'self-test'
        cleanup = [pscustomobject][ordered]@{
            attempted = $false
            complete = $false
            status = 'NOT_ATTEMPTED'
            error_sha256 = $null
        }
    }
    $failureFrame = [pscustomobject][ordered]@{
        type = 'FAILURE'
        document = $failureDocument
    }
    $labMapped = $false
    try {
        Assert-I05SourceExpectedFrame -Frame $failureFrame `
            -ExpectedType COMPLETE -Nonce $nonce
    } catch {
        $labMapped =
            [string]$_.Exception.Data['I05Classification'] -eq
                'LAB_BLOCKED'
    }
    Add-I05SourceSelfTest -Name 'failure-lab-maps-blocked' `
        -Passed $labMapped
    $failureDocument.status = 'PRODUCT_INVARIANT'
    $failureDocument.phase = 'transfer'
    $failureDocument.category = 'destination-hash'
    $productMapped = $false
    try {
        Assert-I05SourceExpectedFrame -Frame $failureFrame `
            -ExpectedType COMPLETE -Nonce $nonce
    } catch {
        $productMapped =
            [string]$_.Exception.Data['I05Classification'] -eq
                'PRODUCT_INVARIANT'
    }
    Add-I05SourceSelfTest -Name 'failure-product-maps-fail' `
        -Passed $productMapped
}

$bundleFunctionNames = @(
    'New-I05SourceClassifiedException',
    'Throw-I05SourceProductInvariant',
    'Get-I05SourceBytesSha256',
    'Get-I05SourceJsonDocumentFromBytes',
    'Get-I05SourceCanonicalPortArray',
    'Assert-I05SourceSamePorts',
    'Assert-I05SourceExactProperties',
    'Get-I05SourceCanonicalRuleTokens',
    'ConvertTo-I05SourceIPv4UInt64',
    'ConvertFrom-I05SourceIPv4UInt64',
    'Get-I05SourceIPv4ComplementTokens',
    'Assert-I05SourceFirewallContainment',
    'Import-I05SourceEvidenceBundle',
    'Assert-I05SourceCompleteFileProduct',
    'Assert-I05SourceCompleteNodeProduct',
    'Assert-I05SourceCompleteWireProduct'
)
$bundleFunctionsLoaded = $true
try {
    $bundleFunctionScript = Get-I05SourceFunctionScript `
        -Ast $runnerAst -Names $bundleFunctionNames
    . $bundleFunctionScript
} catch {
    $bundleFunctionsLoaded = $false
}
Add-I05SourceSelfTest -Name 'bundle-functions-load' `
    -Passed $bundleFunctionsLoaded
if ($bundleFunctionsLoaded) {
    $completeNetworksOff = [pscustomobject][ordered]@{
        kad_connected = $false
        kad2_connected = $false
        kad6_running = $false
        kad6_connected = $false
    }
    $remoteProductFactsPositive = $true
    try {
        Assert-I05SourceCompleteFileProduct `
            -DestinationBytes $constants.fixture_bytes `
            -DestinationSha256 $constants.fixture_sha256 `
            -Ed2k $constants.fixture_ed2k `
            -Ed2kSource 'local-streaming-calculation' `
            -CompleteFlag $true
        Assert-I05SourceCompleteNodeProduct `
            -ProcessId 4242 -ExpectedProcessId 4242 `
            -IPv6Mode 0 -KadNetworkMask 0 `
            -Networks $completeNetworksOff `
            -ApiResponsive $true -TcpListenerOwned $true
        Assert-I05SourceCompleteWireProduct `
            -SocketForbiddenTupleCount 0 `
            -RequestPartsI64 1 -Compressed32 1 `
            -SendingI64 0 -CompressedI64 0 `
            -Ed2kFramingValid $true -AllowedOpcodesOnly $true
    } catch {
        $remoteProductFactsPositive = $false
    }
    Add-I05SourceSelfTest -Name 'remote-product-facts-positive' `
        -Passed $remoteProductFactsPositive

    $badCompleteShaClassified = $false
    try {
        Assert-I05SourceCompleteFileProduct `
            -DestinationBytes $constants.fixture_bytes `
            -DestinationSha256 ('0' * 64) `
            -Ed2k $constants.fixture_ed2k `
            -Ed2kSource 'local-streaming-calculation' `
            -CompleteFlag $true
    } catch {
        $badCompleteShaClassified = (
            [string]$_.Exception.Data['I05Classification'] -ceq
                'PRODUCT_INVARIANT' -and
            [string]$_.Exception.Data['I05Category'] -ceq
                'h3-file-integrity-complete'
        )
    }
    Add-I05SourceSelfTest -Name 'remote-complete-hash-is-product' `
        -Passed $badCompleteShaClassified

    $badCompleteEd2kClassified = $false
    try {
        Assert-I05SourceCompleteFileProduct `
            -DestinationBytes $constants.fixture_bytes `
            -DestinationSha256 $constants.fixture_sha256 `
            -Ed2k ('0' * 32) `
            -Ed2kSource 'local-streaming-calculation' `
            -CompleteFlag $true
    } catch {
        $badCompleteEd2kClassified = (
            [string]$_.Exception.Data['I05Classification'] -ceq
                'PRODUCT_INVARIANT' -and
            [string]$_.Exception.Data['I05Category'] -ceq
                'h3-file-integrity-complete'
        )
    }
    Add-I05SourceSelfTest -Name 'remote-complete-ed2k-is-product' `
        -Passed $badCompleteEd2kClassified

    $badCompleteApiClassified = $false
    try {
        Assert-I05SourceCompleteNodeProduct `
            -ProcessId 4242 -ExpectedProcessId 4242 `
            -IPv6Mode 0 -KadNetworkMask 0 `
            -Networks $completeNetworksOff `
            -ApiResponsive $false -TcpListenerOwned $true
    } catch {
        $badCompleteApiClassified = (
            [string]$_.Exception.Data['I05Classification'] -ceq
                'PRODUCT_INVARIANT' -and
            [string]$_.Exception.Data['I05Category'] -ceq
                'h3-node-state-complete'
        )
    }
    Add-I05SourceSelfTest -Name 'remote-complete-api-is-product' `
        -Passed $badCompleteApiClassified

    $badCompleteWireClassified = $false
    try {
        Assert-I05SourceCompleteWireProduct `
            -SocketForbiddenTupleCount 0 `
            -RequestPartsI64 1 -Compressed32 1 `
            -SendingI64 0 -CompressedI64 0 `
            -Ed2kFramingValid $true -AllowedOpcodesOnly $false
    } catch {
        $badCompleteWireClassified = (
            [string]$_.Exception.Data['I05Classification'] -ceq
                'PRODUCT_INVARIANT' -and
            [string]$_.Exception.Data['I05Category'] -ceq
                'h3-wire-invariant-complete'
        )
    }
    Add-I05SourceSelfTest -Name 'remote-complete-wire-is-product' `
        -Passed $badCompleteWireClassified

    $bundleNonce = 'abcdef0123456789abcdef0123456789'
    $sourceAddress = '10.20.30.1'
    $downloaderAddress = '10.20.30.2'
    $sourceAddressHash = Get-LabStringSha256 -Value $sourceAddress
    $downloaderAddressHash =
        Get-LabStringSha256 -Value $downloaderAddress
    $interfaceGuidHash =
        Get-LabStringSha256 -Value '00112233-4455-6677-8899-aabbccddeeff'
    $mappingKeyHash =
        Get-LabStringSha256 -Value 'self-test-mapping-key'
    $preRawHash = Get-LabStringSha256 -Value 'pre-raw'
    $armedRawHash = Get-LabStringSha256 -Value 'armed-raw'
    $postRawHash = Get-LabStringSha256 -Value 'post-raw'
    $pcapHash = Get-LabStringSha256 -Value 'pcapng-raw'
    $etlHash = Get-LabStringSha256 -Value 'etl'
    $samplesHash = Get-LabStringSha256 -Value 'samples'
    $pktmonLogHash = Get-LabStringSha256 -Value 'pktmon-log'
    $containmentObject = New-I05SourceSelfTestContainment `
        -SourceIPv4 $sourceAddress -Nonce $bundleNonce
    $containmentPositive = $true
    try {
        $null = Assert-I05SourceFirewallContainment `
            -Containment $containmentObject `
            -Context 'Self-test containment' -SourceIPv4 $sourceAddress `
            -Nonce $bundleNonce
    } catch {
        $containmentPositive = $false
    }
    Add-I05SourceSelfTest -Name 'containment-canonical-positive' `
        -Passed $containmentPositive
    $missingLoopbackRule = $containmentObject |
        ConvertTo-Json -Depth 16 | ConvertFrom-Json
    $missingLoopbackRule.canonical_rules = @(
        $missingLoopbackRule.canonical_rules | Where-Object {
            $_.role -cne
                'out_tcp_v4_loopback_non_api_local_ports'
        }
    )
    Add-I05SourceSelfTest `
        -Name 'containment-rejects-missing-loopback-non-api-rule' `
        -Passed (Invoke-I05SourceExpectedFailure -Action {
            $null = Assert-I05SourceFirewallContainment `
                -Containment $missingLoopbackRule `
                -Context 'Missing loopback non-API containment' `
                -SourceIPv4 $sourceAddress -Nonce $bundleNonce
        } -Pattern 'exactly ten rules')

    $badLoopbackPorts = $containmentObject |
        ConvertTo-Json -Depth 16 | ConvertFrom-Json
    $loopbackPortRule = @(
        $badLoopbackPorts.canonical_rules | Where-Object {
            $_.role -ceq
                'out_tcp_v4_loopback_non_api_local_ports'
        }
    )
    $loopbackPortRule[0].local_ports = @('Any')
    Add-I05SourceSelfTest `
        -Name 'containment-rejects-forged-loopback-local-ports' `
        -Passed (Invoke-I05SourceExpectedFailure -Action {
            $null = Assert-I05SourceFirewallContainment `
                -Containment $badLoopbackPorts `
                -Context 'Forged loopback ports containment' `
                -SourceIPv4 $sourceAddress -Nonce $bundleNonce
        } -Pattern 'loopback_non_api_local_ports local ports')

    $badLoopbackAddress = $containmentObject |
        ConvertTo-Json -Depth 16 | ConvertFrom-Json
    $loopbackAddressRule = @(
        $badLoopbackAddress.canonical_rules | Where-Object {
            $_.role -ceq
                'out_tcp_v4_loopback_non_api_local_ports'
        }
    )
    $loopbackAddressRule[0].remote_addresses_sha256 =
        Get-LabStringSha256 -Value '127.0.0.1'
    Add-I05SourceSelfTest `
        -Name 'containment-rejects-forged-loopback-address-set' `
        -Passed (Invoke-I05SourceExpectedFailure -Action {
            $null = Assert-I05SourceFirewallContainment `
                -Containment $badLoopbackAddress `
                -Context 'Forged loopback address containment' `
                -SourceIPv4 $sourceAddress -Nonce $bundleNonce
        } -Pattern 'loopback_non_api_local_ports address-set hash')

    $badInboundTcpV6Ports = $containmentObject |
        ConvertTo-Json -Depth 16 | ConvertFrom-Json
    $inboundTcpV6Rule = @(
        $badInboundTcpV6Ports.canonical_rules | Where-Object {
            $_.role -ceq 'in_tcp_v6_all'
        }
    )
    $inboundTcpV6Rule[0].local_ports = @(
        [string]$constants.downloader_tcp_port
    )
    Add-I05SourceSelfTest `
        -Name 'containment-rejects-limited-inbound-tcp-v6' `
        -Passed (Invoke-I05SourceExpectedFailure -Action {
            $null = Assert-I05SourceFirewallContainment `
                -Containment $badInboundTcpV6Ports `
                -Context 'Limited inbound TCPv6 containment' `
                -SourceIPv4 $sourceAddress -Nonce $bundleNonce
        } -Pattern 'in_tcp_v6_all local ports')

    $badInboundUdpV4Ports = $containmentObject |
        ConvertTo-Json -Depth 16 | ConvertFrom-Json
    $inboundUdpV4Rule = @(
        $badInboundUdpV4Ports.canonical_rules | Where-Object {
            $_.role -ceq 'in_udp_v4_all'
        }
    )
    $inboundUdpV4Rule[0].local_ports = @(
        [string]$constants.downloader_udp_port
    )
    Add-I05SourceSelfTest `
        -Name 'containment-rejects-limited-inbound-udp-v4' `
        -Passed (Invoke-I05SourceExpectedFailure -Action {
            $null = Assert-I05SourceFirewallContainment `
                -Containment $badInboundUdpV4Ports `
                -Context 'Limited inbound UDPv4 containment' `
                -SourceIPv4 $sourceAddress -Nonce $bundleNonce
        } -Pattern 'in_udp_v4_all local ports')

    $badOutboundUdpV4Address = $containmentObject |
        ConvertTo-Json -Depth 16 | ConvertFrom-Json
    $outboundUdpV4Rule = @(
        $badOutboundUdpV4Address.canonical_rules | Where-Object {
            $_.role -ceq 'out_udp_v4_all'
        }
    )
    $outboundUdpV4Rule[0].remote_addresses_sha256 =
        Get-LabStringSha256 -Value (
            '0.0.0.0-126.255.255.255' + "`n" +
            '128.0.0.0-255.255.255.255'
        )
    Add-I05SourceSelfTest `
        -Name 'containment-rejects-udp-v4-loopback-hole' `
        -Passed (Invoke-I05SourceExpectedFailure -Action {
            $null = Assert-I05SourceFirewallContainment `
                -Containment $badOutboundUdpV4Address `
                -Context 'UDPv4 loopback hole containment' `
                -SourceIPv4 $sourceAddress -Nonce $bundleNonce
        } -Pattern 'out_udp_v4_all address-set hash')

    $badContainment = $containmentObject | ConvertTo-Json -Depth 16 |
        ConvertFrom-Json
    $badContainment.canonical_rules[8].remote_addresses_sha256 =
        Get-LabStringSha256 -Value 'forged-address-set'
    Add-I05SourceSelfTest -Name 'containment-rejects-forged-address-set' `
        -Passed (Invoke-I05SourceExpectedFailure -Action {
            $null = Assert-I05SourceFirewallContainment `
                -Containment $badContainment `
                -Context 'Forged containment' -SourceIPv4 $sourceAddress `
                -Nonce $bundleNonce
        } -Pattern 'address-set hash')
    $badRuleName = $containmentObject | ConvertTo-Json -Depth 16 |
        ConvertFrom-Json
    $badRuleName.canonical_rules[0].name_sha256 =
        Get-LabStringSha256 -Value 'forged-rule-name'
    Add-I05SourceSelfTest -Name 'containment-rejects-forged-rule-name' `
        -Passed (Invoke-I05SourceExpectedFailure -Action {
            $null = Assert-I05SourceFirewallContainment `
                -Containment $badRuleName `
                -Context 'Forged name containment' `
                -SourceIPv4 $sourceAddress -Nonce $bundleNonce
        } -Pattern 'deterministic rule-name hash')
    $badRuleNamesSet = $containmentObject | ConvertTo-Json -Depth 16 |
        ConvertFrom-Json
    $badRuleNamesSet.rule_names_sha256 =
        Get-LabStringSha256 -Value 'forged-rule-name-set'
    Add-I05SourceSelfTest -Name 'containment-rejects-forged-name-set' `
        -Passed (Invoke-I05SourceExpectedFailure -Action {
            $null = Assert-I05SourceFirewallContainment `
                -Containment $badRuleNamesSet `
                -Context 'Forged names containment' `
                -SourceIPv4 $sourceAddress -Nonce $bundleNonce
        } -Pattern 'deterministic rule-name set')

    $badProfile = $containmentObject | ConvertTo-Json -Depth 16 |
        ConvertFrom-Json
    $badProfile.canonical_rules[0].profile = 'Private'
    Add-I05SourceSelfTest -Name 'containment-rejects-non-any-profile' `
        -Passed (Invoke-I05SourceExpectedFailure -Action {
            $null = Assert-I05SourceFirewallContainment `
                -Containment $badProfile -Context 'Bad profile containment' `
                -SourceIPv4 $sourceAddress -Nonce $bundleNonce
        } -Pattern 'all-profile block')

    $badService = $containmentObject | ConvertTo-Json -Depth 16 |
        ConvertFrom-Json
    $badService.firewall_service_running = $false
    Add-I05SourceSelfTest -Name 'containment-rejects-stopped-mpssvc' `
        -Passed (Invoke-I05SourceExpectedFailure -Action {
            $null = Assert-I05SourceFirewallContainment `
                -Containment $badService -Context 'Stopped service containment' `
                -SourceIPv4 $sourceAddress -Nonce $bundleNonce
        } -Pattern 'JSON boolean true')

    $badProfilesFlag = $containmentObject | ConvertTo-Json -Depth 16 |
        ConvertFrom-Json
    $badProfilesFlag.firewall_profiles_enabled = $false
    Add-I05SourceSelfTest -Name 'containment-rejects-disabled-profile-flag' `
        -Passed (Invoke-I05SourceExpectedFailure -Action {
            $null = Assert-I05SourceFirewallContainment `
                -Containment $badProfilesFlag `
                -Context 'Disabled profiles containment' `
                -SourceIPv4 $sourceAddress -Nonce $bundleNonce
        } -Pattern 'JSON boolean true')

    $badProfileCount = $containmentObject | ConvertTo-Json -Depth 16 |
        ConvertFrom-Json
    $badProfileCount.firewall_profile_count = 2
    Add-I05SourceSelfTest -Name 'containment-rejects-profile-count' `
        -Passed (Invoke-I05SourceExpectedFailure -Action {
            $null = Assert-I05SourceFirewallContainment `
                -Containment $badProfileCount `
                -Context 'Bad profile count containment' `
                -SourceIPv4 $sourceAddress -Nonce $bundleNonce
        } -Pattern 'JSON integer 3')

    $badProfilesHash = $containmentObject | ConvertTo-Json -Depth 16 |
        ConvertFrom-Json
    $badProfilesHash.firewall_profiles_sha256 =
        Get-LabStringSha256 -Value 'Domain=true'
    Add-I05SourceSelfTest -Name 'containment-rejects-profile-hash' `
        -Passed (Invoke-I05SourceExpectedFailure -Action {
            $null = Assert-I05SourceFirewallContainment `
                -Containment $badProfilesHash `
                -Context 'Bad profile hash containment' `
                -SourceIPv4 $sourceAddress -Nonce $bundleNonce
        } -Pattern 'enabled firewall-profile set')

    $badEngineSamples = $containmentObject | ConvertTo-Json -Depth 16 |
        ConvertFrom-Json
    $badEngineSamples.engine_watchdog_samples = 3
    Add-I05SourceSelfTest -Name 'containment-rejects-engine-sample-gap' `
        -Passed (Invoke-I05SourceExpectedFailure -Action {
            $null = Assert-I05SourceFirewallContainment `
                -Containment $badEngineSamples `
                -Context 'Engine sample gap containment' `
                -SourceIPv4 $sourceAddress -Nonce $bundleNonce
        } -Pattern 'continuously prove exact rules')
    $badExactFilterChecks = $containmentObject |
        ConvertTo-Json -Depth 16 | ConvertFrom-Json
    $badExactFilterChecks.engine_watchdog_exact_filter_checks = 3
    Add-I05SourceSelfTest `
        -Name 'containment-rejects-exact-filter-watchdog-gap' `
        -Passed (Invoke-I05SourceExpectedFailure -Action {
            $null = Assert-I05SourceFirewallContainment `
                -Containment $badExactFilterChecks `
                -Context 'Exact-filter watchdog gap containment' `
                -SourceIPv4 $sourceAddress -Nonce $bundleNonce
        } -Pattern 'continuously prove exact rules')
    $stableTuple = [pscustomobject][ordered]@{
        protocol = 'TCP'
        local_address_sha256 = $downloaderAddressHash
        local_port = 55001
        remote_address_sha256 = $sourceAddressHash
        remote_port = $constants.source_tcp_port
        pid = 4242
        first_sample = 1
        last_sample = 4
        observations = 4
    }
    $socketProofObject = [pscustomobject][ordered]@{
        schema = 'ese.v91.i05.t1-socket-proof/v1'
        candidate_pid = 4242
        source_ipv4_sha256 = $sourceAddressHash
        downloader_ipv4_sha256 = $downloaderAddressHash
        remote_port = $constants.source_tcp_port
        observed_tuples = @($stableTuple)
        unique_tuple_count = 1
        stable_tuple = $stableTuple
        forbidden_established_count = 0
        sample_count = 4
    }
    $pcapAnalysisObject = [pscustomobject][ordered]@{
        schema = 'ese.v91.i05.t1-pcap-analysis/v1'
        case_id = $constants.case_id
        parser_valid = $true
        conversion_component_id = 321
        allowed_local_ports = @(55001)
        exact_peer_packets = 12
        rejected_peer_tuple_packets = 0
        third_party_peer_packets = 0
        ipv6_peer_packets = 0
        requestparts_i64 = 2
        compressedpart_32 = 4
        sendingpart_i64 = 3
        compressedpart_i64 = 0
        invalid_fixture_i64_frames = 0
        candidate_pid = 4242
        candidate_pid_role = 'socket-watchdog-context-only'
        pcap_pid_attributed = $false
        tuple_allowlist_pid_observed = $true
        attribution_guard = 'process-scoped-firewall-containment'
        physical_component_guid_match = $true
        component_mapping_sha256 = ''
    }
    $inventoryObjects = [ordered]@{}
    foreach ($inventory in @(
        [pscustomobject]@{
            stage = 'pre'; raw_bytes = 111; raw_sha256 = $preRawHash
        },
        [pscustomobject]@{
            stage = 'armed'; raw_bytes = 112; raw_sha256 = $armedRawHash
        },
        [pscustomobject]@{
            stage = 'post'; raw_bytes = 113; raw_sha256 = $postRawHash
        }
    )) {
        $inventoryObjects[$inventory.stage] =
            [pscustomobject][ordered]@{
                schema = 'ese.v91.i05.t1-component-inventory/v1'
                stage = $inventory.stage
                raw_bytes = $inventory.raw_bytes
                raw_sha256 = $inventory.raw_sha256
                mapping_key_sha256 = $mappingKeyHash
                primary_id = 321
                secondary_id = 0
                interface_guid_sha256 = $interfaceGuidHash
            }
    }
    $mappingObject = [pscustomobject][ordered]@{
        schema = 'ese.v91.i05.t1-component-mapping/v1'
        case_id = $constants.case_id
        source = 'pktmon-list-json'
        interface_guid = '00112233-4455-6677-8899-aabbccddeeff'
        interface_guid_sha256 = $interfaceGuidHash
        interface_index = 7
        mac_address_sha256 =
            Get-LabStringSha256 -Value '001122334455'
        primary_id = 321
        secondary_id = 0
        conversion_component_ids = @(321)
        mapping_key_sha256 = $mappingKeyHash
        unique_guid_component_match = $true
        optional_if_index_correlated = $true
        optional_mac_correlated = $true
        stable_pre_armed_post = $true
        inventories = [pscustomobject][ordered]@{
            pre_raw_sha256 = $preRawHash
            armed_raw_sha256 = $armedRawHash
            post_raw_sha256 = $postRawHash
        }
    }
    $filterObject = [pscustomobject][ordered]@{
        schema = 'ese.v91.i05.t1-pktmon-filter/v1'
        case_id = $constants.case_id
        filters = @([pscustomobject]@{ name = 'V91-I05'; id = 7 })
        before_bytes = 10
        before_sha256 = Get-LabStringSha256 -Value 'before'
        armed_bytes = 11
        armed_sha256 = Get-LabStringSha256 -Value 'armed'
        before_reset_bytes = 12
        before_reset_sha256 =
            Get-LabStringSha256 -Value 'before-reset'
        after_bytes = 10
        after_sha256 = Get-LabStringSha256 -Value 'after'
        restored_exactly = $true
        third_party_containment = $containmentObject
    }
    $lossObject = [pscustomobject][ordered]@{
        schema = 'ese.v91.i05.t1-pktmon-loss/v1'
        case_id = $constants.case_id
        available = $true
        error_code = 0
        events_lost = 0
        log_buffers_lost = 0
        realtime_buffers_lost = 0
        buffers_lost = 0
        buffers_written = 2
        proved_zero = $true
    }
    $statusObject = [pscustomobject][ordered]@{
        schema = 'ese.v91.i05.t1-pktmon-status/v1'
        case_id = $constants.case_id
        primary_component_id = 321
        secondary_component_id = 0
        converted_component_id = 321
        conversion_hit_count = 1
        conversion_results = @([pscustomobject][ordered]@{
            component_id = 321
            bytes = 400
            sha256 = $pcapHash
            parser_valid = $true
            exact_peer_flow = $true
            retained = $true
        })
        command_log_bytes = 200
        command_log_sha256 = $pktmonLogHash
        counters_bytes = 20
        counters_sha256 = Get-LabStringSha256 -Value 'counters'
        session_stopped = $true
        filters_restored = $true
        etl_bytes = 500
        etl_sha256 = $etlHash
        pcapng_bytes = 400
        pcapng_sha256 = $pcapHash
        transfer_samples_bytes = 300
        transfer_samples_sha256 = $samplesHash
        candidate_status_ready_sha256 =
            Get-LabStringSha256 -Value 'ready-status'
        candidate_status_final_sha256 =
            Get-LabStringSha256 -Value 'final-status'
        candidate_networks = [pscustomobject][ordered]@{
            kad_connected = $false
            kad2_connected = $false
            kad6_running = $false
            kad6_connected = $false
        }
    }
    $fileIntegrityObject = [pscustomobject][ordered]@{
        schema = 'ese.v91.i05.t1-file-integrity/v1'
        case_id = $constants.case_id
        name = $constants.fixture_name
        name_sha256 =
            Get-LabStringSha256 -Value $constants.fixture_name
        path_relative = 'Incoming\v91-i05-canonical-4294967296.bin'
        bytes = $constants.fixture_bytes
        sha256 = $constants.fixture_sha256
        ed2k = $constants.fixture_ed2k
        method = 'local-streaming-sha256-ed2k-md4'
        calculation_report_sha256 =
            Get-LabStringSha256 -Value 'local-calculation-report'
        calculated_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
    }
    $mappingBytes =
        ConvertTo-I05SourceSelfTestJsonBytes $mappingObject
    $pcapAnalysisObject.component_mapping_sha256 =
        Get-I05SourceBytesSha256 -Bytes $mappingBytes
    $payloadEntries = [ordered]@{
        'pcap-analysis.json' =
            ConvertTo-I05SourceSelfTestJsonBytes $pcapAnalysisObject
        'component-mapping.json' = $mappingBytes
        'component-inventory-pre.json' =
            ConvertTo-I05SourceSelfTestJsonBytes $inventoryObjects.pre
        'component-inventory-armed.json' =
            ConvertTo-I05SourceSelfTestJsonBytes $inventoryObjects.armed
        'component-inventory-post.json' =
            ConvertTo-I05SourceSelfTestJsonBytes $inventoryObjects.post
        'pktmon-filter.json' =
            ConvertTo-I05SourceSelfTestJsonBytes $filterObject
        'pktmon-loss.json' =
            ConvertTo-I05SourceSelfTestJsonBytes $lossObject
        'pktmon-status.json' =
            ConvertTo-I05SourceSelfTestJsonBytes $statusObject
        'socket-proof.json' =
            ConvertTo-I05SourceSelfTestJsonBytes $socketProofObject
        'file-integrity.json' =
            ConvertTo-I05SourceSelfTestJsonBytes $fileIntegrityObject
    }
    $manifestEntries = [Collections.Generic.List[object]]::new()
    foreach ($name in $payloadEntries.Keys) {
        $bytes = [byte[]]$payloadEntries[$name]
        $manifestEntries.Add([pscustomobject][ordered]@{
            path = $name
            bytes = $bytes.Length
            sha256 = Get-I05SourceBytesSha256 -Bytes $bytes
        })
    }
    $rawRecords = @(
        [pscustomobject]@{
            kind = 'etl'; path_relative = 'raw\capture.etl'; bytes = 500
            sha256 = $etlHash
        },
        [pscustomobject]@{
            kind = 'pcapng'; path_relative = 'raw\capture.pcapng'; bytes = 400
            sha256 = $pcapHash
        },
        [pscustomobject]@{
            kind = 'transfer_samples'; path_relative = 'raw\samples.jsonl'
            bytes = 300; sha256 = $samplesHash
        },
        [pscustomobject]@{
            kind = 'pktmon_log'; path_relative = 'raw\pktmon.txt'; bytes = 200
            sha256 = $pktmonLogHash
        },
        [pscustomobject]@{
            kind = 'pktmon_filters_before_reset'
            path_relative = 'raw\pktmon-filters-before-reset.txt'
            bytes = 201
            sha256 = $filterObject.before_reset_sha256
        },
        [pscustomobject]@{
            kind = 'component_inventory_pre_raw'
            path_relative = 'raw\component-pre.json'; bytes = 111
            sha256 = $preRawHash
        },
        [pscustomobject]@{
            kind = 'component_inventory_armed_raw'
            path_relative = 'raw\component-armed.json'; bytes = 112
            sha256 = $armedRawHash
        },
        [pscustomobject]@{
            kind = 'component_inventory_post_raw'
            path_relative = 'raw\component-post.json'; bytes = 113
            sha256 = $postRawHash
        },
        [pscustomobject]@{
            kind = 'firewall_containment_spec'
            path_relative = 'evidence/firewall-containment-spec.json'
            bytes = 901
            sha256 = $containmentObject.spec_document_sha256
        },
        [pscustomobject]@{
            kind = 'firewall_containment_inventory_before'
            path_relative =
                'evidence/firewall-containment-inventory-before.json'
            bytes = 902
            sha256 = $containmentObject.inventory_before_sha256
        },
        [pscustomobject]@{
            kind = 'firewall_containment_inventory_armed'
            path_relative =
                'evidence/firewall-containment-inventory-armed.json'
            bytes = 903
            sha256 = $containmentObject.inventory_armed_sha256
        },
        [pscustomobject]@{
            kind = 'firewall_containment_inventory_verified'
            path_relative =
                'evidence/firewall-containment-inventory-verified.json'
            bytes = 904
            sha256 = $containmentObject.inventory_verified_sha256
        }
    )
    $manifestObject = [pscustomobject][ordered]@{
        schema = 'ese.v91.i05.t1-evidence-manifest/v1'
        case_id = $constants.case_id
        nonce = $bundleNonce
        created_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
        entries = @($manifestEntries.ToArray())
        retained_raw = @($rawRecords)
    }
    $manifestBytes =
        ConvertTo-I05SourceSelfTestJsonBytes $manifestObject
    $zipEntries = [ordered]@{
        'manifest.json' = $manifestBytes
    }
    foreach ($name in $payloadEntries.Keys) {
        $zipEntries.Add($name, $payloadEntries[$name])
    }
    $socketProofHash = Get-I05SourceBytesSha256 `
        -Bytes $payloadEntries['socket-proof.json']
    $analysisHash = Get-I05SourceBytesSha256 `
        -Bytes $payloadEntries['pcap-analysis.json']
    $mappingHash = Get-I05SourceBytesSha256 `
        -Bytes $payloadEntries['component-mapping.json']
    $integrityHash = Get-I05SourceBytesSha256 `
        -Bytes $payloadEntries['file-integrity.json']
    $remoteEvidence = [pscustomobject][ordered]@{
        process_id = 4242
        ipv4_address_sha256 = $downloaderAddressHash
        component_guid_sha256 = $interfaceGuidHash
        primary_component_id = 321
        secondary_component_ids = @()
        mapping_key_sha256 = $mappingKeyHash
        inventory_pre_sha256 = $preRawHash
        inventory_armed_sha256 = $armedRawHash
    }
    $completeEvidence = [pscustomobject][ordered]@{
        containment = $containmentObject
        file = [pscustomobject][ordered]@{
            integrity_sha256 = $integrityHash
            calculation_report_sha256 =
                $fileIntegrityObject.calculation_report_sha256
        }
        socket_proof = [pscustomobject][ordered]@{
            sha256 = $socketProofHash
            candidate_pid = 4242
            unique_tuple_count = 1
            stable_tuple = $stableTuple
            forbidden_tuple_count = 0
            sample_count = 4
            observed_ephemeral_ports = @(55001)
        }
        capture = [pscustomobject][ordered]@{
            candidate_pid = 4242
            candidate_pid_role = 'socket-watchdog-context-only'
            pcap_pid_attributed = $false
            tuple_allowlist_pid_observed = $true
            process_scoped_containment = $true
            analysis_sha256 = $analysisHash
            component_mapping_sha256 = $mappingHash
            mapping_key_sha256 = $mappingKeyHash
            converted_component_id = 321
            ipv4_peer_packets = 12
            rejected_peer_tuple_packets = 0
            third_party_peer_packets = 0
            ipv6_peer_packets = 0
            pcap_sha256 = $pcapHash
            pcap_bytes = 400
            etl_bytes = 500
            requestparts_i64 = 2
            compressedpart_32 = 4
            sending_i64 = 3
            compressed_i64 = 0
        }
        evidence = [pscustomobject][ordered]@{
            samples_sha256 = $samplesHash
        }
    }
    $bundleTestRoot = Join-Path ([IO.Path]::GetTempPath()) (
        'v91-i05-h1-bundle-selftest-' + [Guid]::NewGuid().ToString('N'))
    $null = New-Item -ItemType Directory -Path $bundleTestRoot
    try {
        $goodZip = New-I05SourceSelfTestZipBytes -Entries $zipEntries
        $goodBundle = [pscustomobject][ordered]@{
            schema = 'ese.v91.i05.t1-evidence-bundle/v1'
            encoding = 'base64'
            bytes = $goodZip.Length
            sha256 = Get-I05SourceBytesSha256 -Bytes $goodZip
            manifest_sha256 =
                Get-I05SourceBytesSha256 -Bytes $manifestBytes
            content_base64 = [Convert]::ToBase64String($goodZip)
        }
        $goodRoot = Join-Path $bundleTestRoot 'good'
        $null = New-Item -ItemType Directory -Path $goodRoot
        $goodImport = $null
        $goodError = ''
        try {
            $goodImport = Import-I05SourceEvidenceBundle `
                -Bundle $goodBundle -Complete $completeEvidence `
                -Remote $remoteEvidence -SourceIPv4 $sourceAddress `
                -Nonce $bundleNonce -ObservedRemotePorts @(55001) `
                -EvidenceRoot $goodRoot
        } catch {
            $goodError = $_.Exception.Message
        }
        Add-I05SourceSelfTest -Name 'bundle-safe-positive' -Passed (
            $null -ne $goodImport -and
            [string]$goodImport.status -eq 'PASS' -and
            (Test-Path -LiteralPath $goodImport.bundle_path -PathType Leaf)
        ) -Detail $goodError

        $traversalZip = New-I05SourceSelfTestZipBytes `
            -Entries $zipEntries `
            -Renames @{ 'manifest.json' = '..\manifest.json' }
        $traversalBundle = [pscustomobject][ordered]@{
            schema = 'ese.v91.i05.t1-evidence-bundle/v1'
            encoding = 'base64'
            bytes = $traversalZip.Length
            sha256 = Get-I05SourceBytesSha256 -Bytes $traversalZip
            manifest_sha256 =
                Get-I05SourceBytesSha256 -Bytes $manifestBytes
            content_base64 = [Convert]::ToBase64String($traversalZip)
        }
        $traversalRoot = Join-Path $bundleTestRoot 'traversal'
        $null = New-Item -ItemType Directory -Path $traversalRoot
        Add-I05SourceSelfTest -Name 'bundle-rejects-traversal' `
            -Passed (Invoke-I05SourceExpectedFailure -Action {
                $null = Import-I05SourceEvidenceBundle `
                    -Bundle $traversalBundle -Complete $completeEvidence `
                    -Remote $remoteEvidence -SourceIPv4 $sourceAddress `
                    -Nonce $bundleNonce -ObservedRemotePorts @(55001) `
                    -EvidenceRoot $traversalRoot
            } -Pattern 'unsafe|duplicate|extra')

        $duplicateZip = New-I05SourceSelfTestZipBytes `
            -Entries $zipEntries `
            -Renames @{ 'pcap-analysis.json' = 'Manifest.json' }
        $duplicateBundle = [pscustomobject][ordered]@{
            schema = 'ese.v91.i05.t1-evidence-bundle/v1'
            encoding = 'base64'
            bytes = $duplicateZip.Length
            sha256 = Get-I05SourceBytesSha256 -Bytes $duplicateZip
            manifest_sha256 =
                Get-I05SourceBytesSha256 -Bytes $manifestBytes
            content_base64 = [Convert]::ToBase64String($duplicateZip)
        }
        $duplicateRoot = Join-Path $bundleTestRoot 'duplicate'
        $null = New-Item -ItemType Directory -Path $duplicateRoot
        Add-I05SourceSelfTest -Name 'bundle-rejects-case-duplicate' `
            -Passed (Invoke-I05SourceExpectedFailure -Action {
                $null = Import-I05SourceEvidenceBundle `
                    -Bundle $duplicateBundle -Complete $completeEvidence `
                    -Remote $remoteEvidence -SourceIPv4 $sourceAddress `
                    -Nonce $bundleNonce -ObservedRemotePorts @(55001) `
                    -EvidenceRoot $duplicateRoot
            } -Pattern 'unsafe|duplicate|extra')
    } finally {
        $resolvedBundleTestRoot =
            [IO.Path]::GetFullPath($bundleTestRoot)
        $resolvedTemp = [IO.Path]::GetFullPath(
            [IO.Path]::GetTempPath())
        if ($resolvedBundleTestRoot.StartsWith(
                $resolvedTemp, [StringComparison]::OrdinalIgnoreCase) -and
            (Test-Path -LiteralPath $resolvedBundleTestRoot)) {
            Remove-Item -LiteralPath $resolvedBundleTestRoot `
                -Recurse -Force
        }
    }
}

$missingZip = Join-Path ([IO.Path]::GetTempPath()) (
    'missing-v91-i05-' + [Guid]::NewGuid().ToString('N') + '.zip')
$missingFixture = Join-Path ([IO.Path]::GetTempPath()) (
    'missing-v91-i05-' + [Guid]::NewGuid().ToString('N') + '.bin')
$negativeRunner = Invoke-I05SourceExpectedFailure -Action {
    & $runnerPath -CandidateZipPath $missingZip `
        -FixturePath $missingFixture `
        -ExpectedFixtureSha256 $constants.fixture_sha256 `
        -H3IPv4 '10.0.0.2' -RunBase $RunBase -PreflightOnly
} -Pattern 'candidate ZIP does not exist'
Add-I05SourceSelfTest -Name 'runner-negative-before-mutation' `
    -Passed $negativeRunner
Add-I05SourceSelfTest -Name 'runner-negative-created-no-files' `
    -Passed (
        -not (Test-Path -LiteralPath $missingZip) -and
        -not (Test-Path -LiteralPath $missingFixture)
    )

if (-not $CandidateZipPath) {
    $repoDefault = Join-Path (
        Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    ) (
        'dist\v0.70b-eSE9.1.0-rc.3\' +
        'eSE-LiveTV-v0.70b-eSE9.1.0-rc.3-x64.zip'
    )
    if (Test-Path -LiteralPath $repoDefault -PathType Leaf) {
        $CandidateZipPath = $repoDefault
    }
}
if ($CandidateZipPath -and
    (Test-Path -LiteralPath $CandidateZipPath -PathType Leaf)) {
    $zip = Get-Item -LiteralPath $CandidateZipPath
    Add-I05SourceSelfTest -Name 'local-zip-bytes' -Passed (
        [Int64]$zip.Length -eq $constants.candidate_zip_bytes)
    Add-I05SourceSelfTest -Name 'local-zip-sha256' -Passed (
        (Get-LabSha256 -Path $zip.FullName) -eq
            $constants.candidate_zip_sha256)
}

if ($RunEnvironmentPreflight) {
    if (-not $CandidateZipPath -or -not $FixturePath -or
        -not $H3IPv4) {
        throw (
            '-RunEnvironmentPreflight requires CandidateZipPath, ' +
            'FixturePath and H3IPv4.'
        )
    }
    $preflightJson = & $runnerPath `
        -CandidateZipPath $CandidateZipPath `
        -FixturePath $FixturePath `
        -ExpectedFixtureSha256 $constants.fixture_sha256 `
        -RunBase $RunBase -SourceIPv4 $SourceIPv4 `
        -H3IPv4 $H3IPv4 -PreflightOnly
    $preflight = ($preflightJson -join "`n") | ConvertFrom-Json
    Add-I05SourceSelfTest -Name 'environment-preflight-pass' `
        -Passed (
            [string]$preflight.status -eq 'PASS' -and
            -not [bool]$preflight.mutation_performed
        )
}

$passed = $failures.Count -eq 0
$report = [ordered]@{
    schema = 'ese.v91.i05.t1-source-selftest/v1'
    captured_at_utc = Get-LabUtcTimestamp
    status = if ($passed) { 'PASS' } else { 'FAIL' }
    mutation_performed = $false
    check_count = $checks.Count
    passed_count = @($checks.ToArray() | Where-Object passed).Count
    failed_count = $failures.Count
    failures = $failures.ToArray()
    checks = $checks.ToArray()
}
$report | ConvertTo-Json -Depth 12
if (-not $passed) {
    throw 'V91-I05 T1 source self-test failed.'
}
