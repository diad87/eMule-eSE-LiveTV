[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$RunRoot
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')

$expectedSchema = 'ese.v91.i06-isolated-source/v1'
$expectedCaseId = 'V91-I06'
$expectedTitle = 'V91-I06-ULA-Isolated'
$expectedVersion = '9.1.0-rc.2'
$expectedCommit =
    '08aa6521f7d7907edb3584266abc3a9e31693161'
$expectedEmuleSha256 =
    '55c5aa0e968b25330720cfb7f622cbc28ea9875365145333cbcf9d9585c1c44a'
$expectedEseServerSha256 =
    'eeceef0f0dbe427f3667c033e2b653fc69e432abcc3e8afa996840a7315e568'
$expectedBuildInfoSha256 =
    '7c87f77268030c2b4da40c6da8c960f968b4e1a033c9987b64e45c49cf4b5915'
$expectedViewerTailscaleIPv6 = 'fd7a:115c:a1e0::8134:181e'
$expectedTcpPort = 6962
$expectedUdpPort = 6972
$expectedWebPort = 7011

function Assert-I06Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'V91-I06 cleanup requires an elevated administrator session.'
    }
}

function Get-I06RequiredProperty {
    param(
        [Parameter(Mandatory = $true)][object]$Object,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Context
    )

    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property -or $null -eq $property.Value) {
        throw "$Context is missing required property '$Name'."
    }
    return $property.Value
}

function Assert-I06ExactText {
    param(
        [AllowEmptyString()][string]$Actual,
        [Parameter(Mandatory = $true)][string]$Expected,
        [Parameter(Mandatory = $true)][string]$Context,
        [switch]$IgnoreCase
    )

    $comparison = if ($IgnoreCase) {
        [StringComparison]::OrdinalIgnoreCase
    } else {
        [StringComparison]::Ordinal
    }
    if (-not [string]::Equals($Actual, $Expected, $comparison)) {
        throw "$Context does not match the exact V91-I06 value."
    }
}

function Assert-I06FalseValue {
    param(
        [Parameter(Mandatory = $true)][object]$Value,
        [Parameter(Mandatory = $true)][string]$Context
    )

    if ($Value -is [bool]) {
        if ([bool]$Value) {
            throw "$Context must be false."
        }
        return
    }
    if (-not [string]::Equals(
            [string]$Value, 'false',
            [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Context must be false."
    }
}

function Test-I06SamePath {
    param(
        [Parameter(Mandatory = $true)][string]$Left,
        [Parameter(Mandatory = $true)][string]$Right
    )

    try {
        $leftFull = [IO.Path]::GetFullPath(
            [Environment]::ExpandEnvironmentVariables($Left))
        $rightFull = [IO.Path]::GetFullPath(
            [Environment]::ExpandEnvironmentVariables($Right))
        return [string]::Equals(
            $leftFull.TrimEnd('\'),
            $rightFull.TrimEnd('\'),
            [StringComparison]::OrdinalIgnoreCase)
    } catch {
        return $false
    }
}

function Get-I06SingleFilterText {
    param(
        [Parameter(Mandatory = $true)][object]$Value,
        [Parameter(Mandatory = $true)][string]$Context
    )

    $items = @($Value | ForEach-Object { [string]$_ })
    if ($items.Count -ne 1 -or
        [string]::IsNullOrWhiteSpace($items[0])) {
        throw "$Context is not a single exact value."
    }
    return $items[0]
}

function Test-I06SameIpAddress {
    param(
        [Parameter(Mandatory = $true)][string]$Left,
        [Parameter(Mandatory = $true)][string]$Right
    )

    try {
        $leftAddress = [Net.IPAddress]::Parse($Left)
        $rightAddress = [Net.IPAddress]::Parse($Right)
        return $leftAddress.Equals($rightAddress)
    } catch {
        return $false
    }
}

function Get-I06TcpListeners {
    return @(
        Get-NetTCPConnection -State Listen -LocalPort $expectedTcpPort `
            -ErrorAction SilentlyContinue
    )
}

function Get-I06Process {
    param([Parameter(Mandatory = $true)][int]$ProcessId)

    return Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
}

function Assert-I06OwnedProcess {
    param(
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][string]$ExpectedExe,
        [Parameter(Mandatory = $true)]
        [DateTimeOffset]$SessionStartedAt
    )

    $Process.Refresh()
    if ($Process.HasExited) {
        throw 'The recorded V91-I06 process has already exited.'
    }
    if (-not (Test-I06SamePath -Left ([string]$Process.Path) `
            -Right $ExpectedExe)) {
        throw 'Recorded PID does not use the isolated V91-I06 executable.'
    }
    Assert-I06ExactText `
        -Actual (Get-LabSha256 -Path $ExpectedExe) `
        -Expected $expectedEmuleSha256 `
        -Context 'Running V91-I06 executable hash' -IgnoreCase

    $processStartedAt =
        [DateTimeOffset]$Process.StartTime.ToUniversalTime()
    if ($processStartedAt -lt $SessionStartedAt.AddMinutes(-5) -or
        $processStartedAt -gt $SessionStartedAt.AddSeconds(10)) {
        throw 'Recorded PID creation time does not match the I06 session.'
    }

    $cim = Get-CimInstance -ClassName Win32_Process `
        -Filter "ProcessId = $($Process.Id)" -ErrorAction Stop
    if ($null -eq $cim -or
        -not (Test-I06SamePath -Left ([string]$cim.ExecutablePath) `
            -Right $ExpectedExe)) {
        throw 'Recorded PID executable identity changed during validation.'
    }
    $commandLine = [string]$cim.CommandLine
    $requiredArguments = @(
        '--portable',
        '--ignoreinstances',
        '--headless',
        "--metrics-port=$expectedWebPort",
        "--tcp-port=$expectedTcpPort",
        "--udp-port=$expectedUdpPort"
    )
    foreach ($argument in $requiredArguments) {
        $pattern = '(?i)(?:^|\s)' +
            [regex]::Escape($argument) + '(?:\s|$)'
        if ($commandLine -notmatch $pattern) {
            throw 'Recorded PID lacks the exact isolated I06 arguments.'
        }
    }
}

function Get-I06FirewallRulesByName {
    param([Parameter(Mandatory = $true)][string]$Name)

    return @(
        Get-NetFirewallRule -Name $Name -ErrorAction SilentlyContinue
    )
}

function Get-I06FirewallRulesByDisplay {
    param([Parameter(Mandatory = $true)][string]$DisplayName)

    return @(
        Get-NetFirewallRule -DisplayName $DisplayName `
            -ErrorAction SilentlyContinue
    )
}

function Assert-I06ExactFirewallRule {
    param(
        [Parameter(Mandatory = $true)][object]$Rule,
        [Parameter(Mandatory = $true)][string]$ExpectedName,
        [Parameter(Mandatory = $true)][string]$ExpectedDisplayName,
        [Parameter(Mandatory = $true)][string]$ExpectedExe
    )

    Assert-I06ExactText -Actual ([string]$Rule.Name) `
        -Expected $ExpectedName -Context 'Firewall rule Name'
    Assert-I06ExactText -Actual ([string]$Rule.DisplayName) `
        -Expected $ExpectedDisplayName -Context 'Firewall rule DisplayName'
    Assert-I06ExactText -Actual ([string]$Rule.Direction) `
        -Expected 'Inbound' -Context 'Firewall rule direction' -IgnoreCase
    Assert-I06ExactText -Actual ([string]$Rule.Action) `
        -Expected 'Allow' -Context 'Firewall rule action' -IgnoreCase
    Assert-I06ExactText -Actual ([string]$Rule.Enabled) `
        -Expected 'True' -Context 'Firewall rule enabled state' -IgnoreCase
    Assert-I06ExactText -Actual ([string]$Rule.Profile) `
        -Expected 'Any' -Context 'Firewall rule profile' -IgnoreCase

    $applicationFilters = @(
        Get-NetFirewallApplicationFilter `
            -AssociatedNetFirewallRule $Rule -ErrorAction Stop
    )
    $portFilters = @(
        Get-NetFirewallPortFilter `
            -AssociatedNetFirewallRule $Rule -ErrorAction Stop
    )
    $interfaceFilters = @(
        Get-NetFirewallInterfaceFilter `
            -AssociatedNetFirewallRule $Rule -ErrorAction Stop
    )
    $addressFilters = @(
        Get-NetFirewallAddressFilter `
            -AssociatedNetFirewallRule $Rule -ErrorAction Stop
    )
    if ($applicationFilters.Count -ne 1 -or
        $portFilters.Count -ne 1 -or
        $interfaceFilters.Count -ne 1 -or
        $addressFilters.Count -ne 1) {
        throw 'Firewall rule does not have one exact filter of each type.'
    }

    $program = Get-I06SingleFilterText `
        -Value $applicationFilters[0].Program `
        -Context 'Firewall application program'
    if (-not (Test-I06SamePath -Left $program -Right $ExpectedExe)) {
        throw 'Firewall rule program is not the isolated I06 executable.'
    }

    $protocol = Get-I06SingleFilterText `
        -Value $portFilters[0].Protocol `
        -Context 'Firewall protocol'
    if ($protocol -ne '6' -and
        -not [string]::Equals(
            $protocol, 'TCP', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Firewall rule protocol is not exactly TCP.'
    }
    Assert-I06ExactText `
        -Actual (Get-I06SingleFilterText `
            -Value $portFilters[0].LocalPort `
            -Context 'Firewall local port') `
        -Expected ([string]$expectedTcpPort) `
        -Context 'Firewall local port'
    Assert-I06ExactText `
        -Actual (Get-I06SingleFilterText `
            -Value $portFilters[0].RemotePort `
            -Context 'Firewall remote port') `
        -Expected 'Any' -Context 'Firewall remote port' -IgnoreCase

    Assert-I06ExactText `
        -Actual (Get-I06SingleFilterText `
            -Value $interfaceFilters[0].InterfaceAlias `
            -Context 'Firewall interface alias') `
        -Expected 'Tailscale' `
        -Context 'Firewall interface alias' -IgnoreCase

    Assert-I06ExactText `
        -Actual (Get-I06SingleFilterText `
            -Value $addressFilters[0].LocalAddress `
            -Context 'Firewall local address') `
        -Expected 'Any' -Context 'Firewall local address' -IgnoreCase
    $remoteAddress = Get-I06SingleFilterText `
        -Value $addressFilters[0].RemoteAddress `
        -Context 'Firewall remote address'
    if (-not (Test-I06SameIpAddress -Left $remoteAddress `
            -Right $expectedViewerTailscaleIPv6)) {
        throw 'Firewall remote address is not the controlled I06 viewer.'
    }
}

Assert-I06Administrator

if (-not (Test-Path -LiteralPath $RunRoot -PathType Container)) {
    throw 'RunRoot does not exist or is not a directory.'
}
$run = (Resolve-Path -LiteralPath $RunRoot).Path
$runItem = Get-Item -LiteralPath $run -Force
if (($runItem.Attributes -band
        [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'RunRoot cannot be a reparse point.'
}
$runLeaf = Split-Path -Leaf $run
if ($runLeaf -notmatch '^v91-i06-source-(\d{8}-\d{6})$') {
    throw 'RunRoot does not have the exact V91-I06 source run name.'
}
$runStamp = $Matches[1]
$expectedFirewallName = "eSE-V91-I06-$runStamp"
$expectedFirewallDisplayName = "eSE V91 I06 RC2 $runStamp"

$sessionPath = Resolve-LabContainedFile -Root $run `
    -RelativePath 'evidence\session.json'
$sourceExe = Resolve-LabContainedFile -Root $run `
    -RelativePath 'nodes\v91-i06-isolated-a\emule.exe'
$sourceServer = Resolve-LabContainedFile -Root $run `
    -RelativePath 'nodes\v91-i06-isolated-a\ese-server.exe'
$sourceBuildInfo = Resolve-LabContainedFile -Root $run `
    -RelativePath 'nodes\v91-i06-isolated-a\BUILD_INFO.txt'
$expectedNode = Split-Path -Parent $sourceExe

Assert-I06ExactText -Actual (Get-LabSha256 -Path $sourceExe) `
    -Expected $expectedEmuleSha256 -Context 'Node emule.exe hash' -IgnoreCase
Assert-I06ExactText -Actual (Get-LabSha256 -Path $sourceServer) `
    -Expected $expectedEseServerSha256 `
    -Context 'Node ese-server.exe hash' -IgnoreCase
Assert-I06ExactText -Actual (Get-LabSha256 -Path $sourceBuildInfo) `
    -Expected $expectedBuildInfoSha256 `
    -Context 'Node BUILD_INFO.txt hash' -IgnoreCase

$sessionFile = Get-Item -LiteralPath $sessionPath
if ($sessionFile.Length -le 2 -or $sessionFile.Length -gt 65536) {
    throw 'V91-I06 session.json has an invalid size.'
}
$sessionRaw = [IO.File]::ReadAllText($sessionPath)
$session = $sessionRaw | ConvertFrom-Json
if ($null -eq $session -or $session -is [Array]) {
    throw 'V91-I06 session.json is not a single JSON object.'
}

Assert-I06ExactText `
    -Actual ([string](Get-I06RequiredProperty $session 'schema' 'Session')) `
    -Expected $expectedSchema -Context 'Session schema'
Assert-I06ExactText `
    -Actual ([string](Get-I06RequiredProperty `
        $session 'candidate_version' 'Session')) `
    -Expected $expectedVersion -Context 'Candidate version'
Assert-I06ExactText `
    -Actual ([string](Get-I06RequiredProperty `
        $session 'candidate_commit' 'Session')) `
    -Expected $expectedCommit -Context 'Candidate commit' -IgnoreCase
Assert-I06FalseValue `
    -Value (Get-I06RequiredProperty $session 'candidate_dirty' 'Session') `
    -Context 'Candidate dirty state'
Assert-I06FalseValue `
    -Value (Get-I06RequiredProperty `
        $session 'development_override' 'Session') `
    -Context 'Development override'
Assert-I06ExactText `
    -Actual ([string](Get-I06RequiredProperty `
        $session 'candidate_binary_sha256' 'Session')) `
    -Expected $expectedEmuleSha256 `
    -Context 'Candidate binary hash' -IgnoreCase

$optionalServerHash =
    $session.PSObject.Properties['candidate_ese_server_sha256']
if ($null -ne $optionalServerHash) {
    Assert-I06ExactText -Actual ([string]$optionalServerHash.Value) `
        -Expected $expectedEseServerSha256 `
        -Context 'Candidate server hash' -IgnoreCase
}
$optionalBuildInfoHash =
    $session.PSObject.Properties['candidate_build_info_sha256']
if ($null -ne $optionalBuildInfoHash) {
    Assert-I06ExactText -Actual ([string]$optionalBuildInfoHash.Value) `
        -Expected $expectedBuildInfoSha256 `
        -Context 'Candidate BUILD_INFO hash' -IgnoreCase
}

Assert-I06ExactText `
    -Actual ([string](Get-I06RequiredProperty $session 'title' 'Session')) `
    -Expected $expectedTitle -Context 'Session case title'
$caseProperty = $session.PSObject.Properties['case_id']
$caseProof = 'case-specific-schema-title-run-and-node'
if ($null -ne $caseProperty) {
    Assert-I06ExactText -Actual ([string]$caseProperty.Value) `
        -Expected $expectedCaseId -Context 'Session case ID'
    $caseProof = 'explicit-case-id'
}

$sessionNode = [string](Get-I06RequiredProperty `
    $session 'node_path' 'Session')
if (-not (Test-I06SamePath -Left $sessionNode -Right $expectedNode)) {
    throw 'Session node is not the contained isolated V91-I06 node.'
}
if ([int](Get-I06RequiredProperty $session 'tcp_port' 'Session') -ne
        $expectedTcpPort -or
    [int](Get-I06RequiredProperty $session 'udp_port' 'Session') -ne
        $expectedUdpPort -or
    [int](Get-I06RequiredProperty $session 'web_port' 'Session') -ne
        $expectedWebPort) {
    throw 'Session ports do not match the isolated V91-I06 profile.'
}
Assert-I06FalseValue `
    -Value (Get-I06RequiredProperty $session 'kad_enabled' 'Session') `
    -Context 'Session Kad state'
Assert-I06FalseValue `
    -Value (Get-I06RequiredProperty $session 'auto_connect' 'Session') `
    -Context 'Session automatic-connect state'

$streamKey = [string](Get-I06RequiredProperty `
    $session 'stream_key' 'Session')
if ($streamKey -notmatch '^[0-9a-fA-F]{32}$') {
    throw 'Session stream identity is invalid.'
}
$processIdText = [string](Get-I06RequiredProperty `
    $session 'process_id' 'Session')
if ($processIdText -notmatch '^[1-9][0-9]{0,9}$') {
    throw 'Session process ID is invalid.'
}
$sourceProcessId = [int]$processIdText
$sessionStartedAt = [DateTimeOffset]::MinValue
if (-not [DateTimeOffset]::TryParse(
        [string](Get-I06RequiredProperty `
            $session 'started_at_utc' 'Session'),
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::AssumeUniversal,
        [ref]$sessionStartedAt)) {
    throw 'Session start timestamp is invalid.'
}

$registeredFirewall = $session.PSObject.Properties['firewall_rule']
$firewallIdentitySource = 'derived-from-exact-run-id'
if ($null -ne $registeredFirewall) {
    Assert-I06ExactText -Actual ([string]$registeredFirewall.Value) `
        -Expected $expectedFirewallName `
        -Context 'Session firewall rule name'
    $firewallIdentitySource = 'registered-and-derived'
}

$sourceProcess = Get-I06Process -ProcessId $sourceProcessId
$listenersBefore = Get-I06TcpListeners
$processStateBefore = 'already-absent'
$processIdentityExact = $false
if ($null -ne $sourceProcess) {
    Assert-I06OwnedProcess -Process $sourceProcess `
        -ExpectedExe $sourceExe -SessionStartedAt $sessionStartedAt
    $processStateBefore = 'running-exact'
    $processIdentityExact = $true
    if ($listenersBefore.Count -eq 0 -or
        @($listenersBefore | Where-Object {
            [int]$_.OwningProcess -ne $sourceProcessId
        }).Count -gt 0) {
        throw 'TCP/6962 listener ownership is not exclusive to the I06 Source.'
    }
} elseif ($listenersBefore.Count -gt 0) {
    throw 'TCP/6962 is owned by another process; cleanup refuses to touch it.'
}

$rulesByName = Get-I06FirewallRulesByName -Name $expectedFirewallName
$rulesByDisplay = Get-I06FirewallRulesByDisplay `
    -DisplayName $expectedFirewallDisplayName
$firewallStateBefore = 'already-absent'
$firewallIdentityExact = $false
if ($rulesByName.Count -gt 0) {
    if ($rulesByName.Count -ne 1 -or
        $rulesByDisplay.Count -ne 1 -or
        [string]$rulesByDisplay[0].Name -ne
            [string]$rulesByName[0].Name) {
        throw 'The expected I06 firewall rule identity is ambiguous.'
    }
    Assert-I06ExactFirewallRule -Rule $rulesByName[0] `
        -ExpectedName $expectedFirewallName `
        -ExpectedDisplayName $expectedFirewallDisplayName `
        -ExpectedExe $sourceExe
    $firewallStateBefore = 'present-exact'
    $firewallIdentityExact = $true
} elseif ($rulesByDisplay.Count -gt 0) {
    throw 'An unexpected rule reuses the I06 firewall display name.'
}

$failureCodes = New-Object 'Collections.Generic.List[string]'
$stopMethod = 'already-absent'
if ($processStateBefore -eq 'running-exact') {
    try {
        $current = Get-I06Process -ProcessId $sourceProcessId
        if ($null -ne $current) {
            Assert-I06OwnedProcess -Process $current `
                -ExpectedExe $sourceExe -SessionStartedAt $sessionStartedAt
            $closeRequested = $current.CloseMainWindow()
            if ($closeRequested -and $current.WaitForExit(10000)) {
                $stopMethod = 'close-main-window'
            } else {
                $current = Get-I06Process -ProcessId $sourceProcessId
                if ($null -ne $current) {
                    Assert-I06OwnedProcess -Process $current `
                        -ExpectedExe $sourceExe `
                        -SessionStartedAt $sessionStartedAt
                    Stop-Process -InputObject $current -Force `
                        -ErrorAction Stop
                    if (-not $current.WaitForExit(10000)) {
                        throw 'Exact V91-I06 process did not exit.'
                    }
                    $stopMethod = 'forced-exact-process'
                } else {
                    $stopMethod = 'exited-during-grace-period'
                }
            }
        } else {
            $stopMethod = 'exited-before-stop'
        }
    } catch {
        $failureCodes.Add('source-process-stop-failed')
    }
}

$firewallRemoval = 'already-absent'
if ($firewallStateBefore -eq 'present-exact') {
    try {
        $currentRules = Get-I06FirewallRulesByName `
            -Name $expectedFirewallName
        if ($currentRules.Count -eq 1) {
            Assert-I06ExactFirewallRule -Rule $currentRules[0] `
                -ExpectedName $expectedFirewallName `
                -ExpectedDisplayName $expectedFirewallDisplayName `
                -ExpectedExe $sourceExe
            Remove-NetFirewallRule -Name $expectedFirewallName `
                -ErrorAction Stop
            $firewallRemoval = 'removed-exact-rule'
        } elseif ($currentRules.Count -eq 0) {
            $firewallRemoval = 'removed-concurrently'
        } else {
            throw 'Firewall rule identity became ambiguous.'
        }
    } catch {
        $failureCodes.Add('firewall-rule-removal-failed')
    }
}

$listenerDeadline = [DateTime]::UtcNow.AddSeconds(15)
do {
    $listenersAfter = Get-I06TcpListeners
    if ($listenersAfter.Count -eq 0) { break }
    Start-Sleep -Milliseconds 250
} while ([DateTime]::UtcNow -lt $listenerDeadline)

$processAbsentAfter =
    $null -eq (Get-I06Process -ProcessId $sourceProcessId)
$listenerAbsentAfter = $listenersAfter.Count -eq 0
$remainingRulesByName = Get-I06FirewallRulesByName `
    -Name $expectedFirewallName
$remainingRulesByDisplay = Get-I06FirewallRulesByDisplay `
    -DisplayName $expectedFirewallDisplayName
$firewallAbsentAfter =
    $remainingRulesByName.Count -eq 0 -and
    $remainingRulesByDisplay.Count -eq 0

if (-not $processAbsentAfter) {
    $failureCodes.Add('source-process-remains')
}
if (-not $listenerAbsentAfter) {
    $failureCodes.Add('tcp-6962-listener-remains')
}
if (-not $firewallAbsentAfter) {
    $failureCodes.Add('firewall-rule-remains')
}

$cleanupComplete = $failureCodes.Count -eq 0
$cleanup = [ordered]@{
    schema = 'ese.v91.i06-source-cleanup/v1'
    case_id = $expectedCaseId
    status = if ($cleanupComplete) { 'PASS' } else { 'FAIL' }
    captured_at_utc = Get-LabUtcTimestamp
    run_id = $runLeaf
    session_sha256 = Get-LabStringSha256 -Value $sessionRaw
    candidate = [ordered]@{
        version = $expectedVersion
        commit = $expectedCommit
        dirty = $false
        emule_sha256 = $expectedEmuleSha256
        ese_server_sha256 = $expectedEseServerSha256
        build_info_sha256 = $expectedBuildInfoSha256
    }
    validated_identity = [ordered]@{
        session_schema_exact = $true
        case_exact = $true
        case_proof = $caseProof
        candidate_exact = $true
        contained_node_exact = $true
    }
    process_cleanup = [ordered]@{
        process_id = $sourceProcessId
        state_before = $processStateBefore
        identity_exact_when_present = $processIdentityExact
        stop_method = $stopMethod
        absent_after = $processAbsentAfter
    }
    firewall_cleanup = [ordered]@{
        identity_source = $firewallIdentitySource
        state_before = $firewallStateBefore
        identity_exact_when_present = $firewallIdentityExact
        action = $firewallRemoval
        absent_after = $firewallAbsentAfter
    }
    listener_cleanup = [ordered]@{
        protocol = 'TCP'
        local_port = $expectedTcpPort
        owned_by_source_before = (
            $processStateBefore -eq 'running-exact' -and
            $listenersBefore.Count -gt 0
        )
        absent_after = $listenerAbsentAfter
    }
    cleanup_complete = $cleanupComplete
    failure_codes = @($failureCodes)
    privacy = [ordered]@{
        stream_key_included = $false
        ip_address_included = $false
        hostname_included = $false
        user_path_included = $false
    }
}
$cleanupPath = Write-LabJson -Value $cleanup `
    -Path (Join-Path $run 'evidence\cleanup.json')

if (-not $cleanupComplete) {
    throw (
        'V91-I06 cleanup is incomplete. Review the sanitized cleanup.json ' +
        'failure_codes; no unrelated process or firewall rule was targeted.'
    )
}

$successPath = Join-Path $run 'CLEANUP-I06-OK.txt'
$successText = @(
    'V91-I06 SOURCE CLEANUP OK'
    "candidate_commit=$expectedCommit"
    "source_process=$stopMethod"
    "firewall_rule=$firewallRemoval"
    "tcp_$expectedTcpPort=not_listening"
    'evidence=evidence\cleanup.json'
    ''
    'Solo se valido y retiro el proceso y la regla exactos de esta ejecucion.'
    'El parte no contiene stream key, direcciones IP, host, usuario ni rutas.'
) -join "`r`n"
$null = Write-LabText -Value ($successText + "`r`n") `
    -Path $successPath

Write-Host 'V91-I06 SOURCE CLEANUP OK' -ForegroundColor Green
Write-Host "Evidence: $cleanupPath"
try {
    Start-Process -FilePath 'notepad.exe' `
        -ArgumentList @($successPath) | Out-Null
} catch {
    Write-Warning 'Cleanup succeeded, but the success TXT could not be opened.'
}
