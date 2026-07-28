[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$RunRoot,
    [switch]$NoOpen
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
. (Join-Path $PSScriptRoot 'v91_i05_t1_contract.ps1')

$constants = Get-I05T1Constants

function Assert-I05CleanupAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'V91-I05 T1 cleanup requires an elevated administrator session.'
    }
}

function Get-I05CleanupSingleText {
    param(
        [Parameter(Mandatory = $true)][object]$Value,
        [Parameter(Mandatory = $true)][string]$Context
    )

    $items = @($Value | ForEach-Object { [string]$_ })
    if ($items.Count -ne 1 -or
        [string]::IsNullOrWhiteSpace($items[0])) {
        throw "$Context is not one exact value."
    }
    return $items[0]
}

function Assert-I05CleanupSameAddress {
    param(
        [Parameter(Mandatory = $true)][string]$Actual,
        [Parameter(Mandatory = $true)][string]$Expected,
        [Parameter(Mandatory = $true)][string]$Context
    )

    $left = $null
    $right = $null
    $leftText = $Actual.Trim('[', ']').Split('%')[0]
    $rightText = $Expected.Trim('[', ']').Split('%')[0]
    if (-not [Net.IPAddress]::TryParse($leftText, [ref]$left) -or
        -not [Net.IPAddress]::TryParse($rightText, [ref]$right) -or
        -not $left.Equals($right)) {
        throw "$Context is not the registered address."
    }
}

function Get-I05CleanupRule {
    param([Parameter(Mandatory = $true)][string]$Name)

    foreach ($attempt in 1..5) {
        try {
            return @(Get-NetFirewallRule -Name $Name -ErrorAction Stop)
        } catch {
            if ($_.FullyQualifiedErrorId -like
                    'CmdletizationQuery_NotFound_*,Get-NetFirewallRule' -or
                [string]$_.CategoryInfo.Category -eq 'ObjectNotFound') {
                return @()
            }
            if ($attempt -lt 5) {
                Start-Sleep -Milliseconds 500
            } else {
                throw
            }
        }
    }
}

function Get-I05CleanupDisplayRule {
    param([Parameter(Mandatory = $true)][string]$DisplayName)

    foreach ($attempt in 1..5) {
        try {
            return @(Get-NetFirewallRule -DisplayName $DisplayName `
                -ErrorAction Stop)
        } catch {
            if ($_.FullyQualifiedErrorId -like
                    'CmdletizationQuery_NotFound_*,Get-NetFirewallRule' -or
                [string]$_.CategoryInfo.Category -eq 'ObjectNotFound') {
                return @()
            }
            if ($attempt -lt 5) {
                Start-Sleep -Milliseconds 500
            } else {
                throw
            }
        }
    }
}

function Get-I05CleanupFirewallSnapshot {
    $lastError = $null
    foreach ($attempt in 1..15) {
        try {
            return @(Get-NetFirewallRule -ErrorAction Stop)
        } catch {
            $lastError = $_
            if ($attempt -lt 15) {
                Start-Sleep -Seconds 1
            }
        }
    }
    $exception = New-Object InvalidOperationException(
        'Windows Firewall enumeration failed closed after retries: ' +
        $lastError.Exception.Message)
    $exception.Data['I05Classification'] = 'LAB_BLOCKED'
    $exception.Data['I05Category'] = 'firewall-enumeration-failed'
    throw $exception
}

function Get-I05CleanupTcpSnapshot {
    try {
        return @(Get-NetTCPConnection -ErrorAction Stop)
    } catch {
        $exception = New-Object InvalidOperationException(
            'Windows TCP endpoint enumeration failed closed: ' +
            $_.Exception.Message)
        $exception.Data['I05Classification'] = 'LAB_BLOCKED'
        $exception.Data['I05Category'] = 'tcp-enumeration-failed'
        throw $exception
    }
}

function Get-I05CleanupUdpSnapshot {
    try {
        return @(Get-NetUDPEndpoint -ErrorAction Stop)
    } catch {
        $exception = New-Object InvalidOperationException(
            'Windows UDP endpoint enumeration failed closed: ' +
            $_.Exception.Message)
        $exception.Data['I05Classification'] = 'LAB_BLOCKED'
        $exception.Data['I05Category'] = 'udp-enumeration-failed'
        throw $exception
    }
}

function Get-I05CleanupProcessById {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$ProcessId
    )

    try {
        $cimMatches = @(
            Get-CimInstance -ClassName Win32_Process `
                -Filter "ProcessId = $ProcessId" -ErrorAction Stop
        )
    } catch {
        $exception = New-Object InvalidOperationException(
            'Windows process enumeration failed closed: ' +
            $_.Exception.Message)
        $exception.Data['I05Classification'] = 'LAB_BLOCKED'
        $exception.Data['I05Category'] = 'process-enumeration-failed'
        throw $exception
    }
    if ($cimMatches.Count -eq 0) {
        return $null
    }
    if ($cimMatches.Count -ne 1 -or
        [int]$cimMatches[0].ProcessId -ne $ProcessId) {
        $exception = New-Object InvalidOperationException(
            'Windows process enumeration returned an ambiguous PID.')
        $exception.Data['I05Classification'] = 'LAB_BLOCKED'
        $exception.Data['I05Category'] = 'process-enumeration-ambiguous'
        throw $exception
    }

    try {
        return Get-Process -Id $ProcessId -ErrorAction Stop
    } catch {
        try {
            $stillPresent = @(
                Get-CimInstance -ClassName Win32_Process `
                    -Filter "ProcessId = $ProcessId" -ErrorAction Stop
            )
        } catch {
            $exception = New-Object InvalidOperationException(
                'Windows process re-enumeration failed closed: ' +
                $_.Exception.Message)
            $exception.Data['I05Classification'] = 'LAB_BLOCKED'
            $exception.Data['I05Category'] =
                'process-enumeration-failed'
            throw $exception
        }
        if ($stillPresent.Count -eq 0) {
            return $null
        }
        $exception = New-Object InvalidOperationException(
            'The registered PID exists but its process handle could not ' +
            'be opened safely.')
        $exception.Data['I05Classification'] = 'LAB_BLOCKED'
        $exception.Data['I05Category'] = 'process-handle-open-failed'
        throw $exception
    }
}

function Assert-I05CleanupFirewallRule {
    param(
        [Parameter(Mandatory = $true)][object]$Rule,
        [Parameter(Mandatory = $true)][string]$ExpectedName,
        [Parameter(Mandatory = $true)][string]$ExpectedDisplayName,
        [Parameter(Mandatory = $true)][string]$ExpectedProgram,
        [Parameter(Mandatory = $true)][string]$ExpectedInterfaceAlias,
        [Parameter(Mandatory = $true)][string]$ExpectedLocalAddress,
        [Parameter(Mandatory = $true)][string]$ExpectedRemoteAddress,
        [Parameter(Mandatory = $true)][int]$ExpectedLocalPort
    )

    Assert-I05ExactText -Actual ([string]$Rule.Name) `
        -Expected $ExpectedName -Context 'Firewall Name'
    Assert-I05ExactText -Actual ([string]$Rule.DisplayName) `
        -Expected $ExpectedDisplayName -Context 'Firewall DisplayName'
    Assert-I05ExactText -Actual ([string]$Rule.Direction) `
        -Expected 'Inbound' -Context 'Firewall direction' -IgnoreCase
    Assert-I05ExactText -Actual ([string]$Rule.Action) `
        -Expected 'Allow' -Context 'Firewall action' -IgnoreCase
    Assert-I05ExactText -Actual ([string]$Rule.Enabled) `
        -Expected 'True' -Context 'Firewall enabled state' -IgnoreCase
    Assert-I05ExactText -Actual ([string]$Rule.Profile) `
        -Expected 'Any' -Context 'Firewall profile' -IgnoreCase
    Assert-I05ExactText -Actual ([string]$Rule.EdgeTraversalPolicy) `
        -Expected 'Block' -Context 'Firewall edge traversal' -IgnoreCase

    $application = @(
        Get-NetFirewallApplicationFilter `
            -AssociatedNetFirewallRule $Rule -ErrorAction Stop
    )
    $ports = @(
        Get-NetFirewallPortFilter `
            -AssociatedNetFirewallRule $Rule -ErrorAction Stop
    )
    $interfaces = @(
        Get-NetFirewallInterfaceFilter `
            -AssociatedNetFirewallRule $Rule -ErrorAction Stop
    )
    $addresses = @(
        Get-NetFirewallAddressFilter `
            -AssociatedNetFirewallRule $Rule -ErrorAction Stop
    )
    if ($application.Count -ne 1 -or $ports.Count -ne 1 -or
        $interfaces.Count -ne 1 -or $addresses.Count -ne 1) {
        throw 'Firewall rule filters are not one exact set.'
    }

    $program = Get-I05CleanupSingleText -Value $application[0].Program `
        -Context 'Firewall program'
    if (-not (Test-I05SamePath -Left $program -Right $ExpectedProgram)) {
        throw 'Firewall program is not the registered executable.'
    }
    Assert-I05ExactText -Actual (
        Get-I05CleanupSingleText -Value $interfaces[0].InterfaceAlias `
            -Context 'Firewall interface'
    ) -Expected $ExpectedInterfaceAlias -Context 'Firewall interface' `
        -IgnoreCase

    $protocol = Get-I05CleanupSingleText -Value $ports[0].Protocol `
        -Context 'Firewall protocol'
    if ($protocol -ne '6' -and
        -not [string]::Equals(
            $protocol, 'TCP', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Firewall protocol is not TCP.'
    }
    Assert-I05ExactText -Actual (
        Get-I05CleanupSingleText -Value $ports[0].LocalPort `
            -Context 'Firewall local port'
    ) -Expected ([string]$ExpectedLocalPort) `
        -Context 'Firewall local port'
    Assert-I05ExactText -Actual (
        Get-I05CleanupSingleText -Value $ports[0].RemotePort `
            -Context 'Firewall remote port'
    ) -Expected 'Any' -Context 'Firewall remote port' -IgnoreCase

    $local = Get-I05CleanupSingleText -Value $addresses[0].LocalAddress `
        -Context 'Firewall local address'
    Assert-I05CleanupSameAddress -Actual $local `
        -Expected $ExpectedLocalAddress -Context 'Firewall local address'
    $remote = Get-I05CleanupSingleText -Value $addresses[0].RemoteAddress `
        -Context 'Firewall remote address'
    if ([string]::Equals(
            $ExpectedRemoteAddress, 'LocalSubnet',
            [StringComparison]::OrdinalIgnoreCase)) {
        Assert-I05ExactText -Actual $remote -Expected 'LocalSubnet' `
            -Context 'Firewall remote address' -IgnoreCase
    } else {
        Assert-I05CleanupSameAddress -Actual $remote `
            -Expected $ExpectedRemoteAddress `
            -Context 'Firewall remote address'
    }
}

function Assert-I05CleanupOwnedProcess {
    param(
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][string]$ExpectedExe,
        [Parameter(Mandatory = $true)]
        [DateTimeOffset]$ExpectedStart,
        [Parameter(Mandatory = $true)][string[]]$ExpectedArguments
    )

    $Process.Refresh()
    if ($Process.HasExited) {
        throw 'The registered source process has exited.'
    }
    if (-not (Test-I05SamePath -Left ([string]$Process.Path) `
            -Right $ExpectedExe)) {
        throw 'The registered PID no longer belongs to the isolated source.'
    }
    Assert-I05ExactText -Actual (Get-LabSha256 -Path $ExpectedExe) `
        -Expected $constants.candidate_emule_sha256 `
        -Context 'Running source executable hash' -IgnoreCase
    $actualStart =
        [DateTimeOffset]$Process.StartTime.ToUniversalTime()
    if ([Math]::Abs(($actualStart - $ExpectedStart).TotalSeconds) -gt 10) {
        throw 'The registered PID start time no longer matches ownership.'
    }

    $cim = Get-CimInstance -ClassName Win32_Process `
        -Filter "ProcessId = $($Process.Id)" -ErrorAction Stop
    if ($null -eq $cim -or
        -not (Test-I05SamePath -Left ([string]$cim.ExecutablePath) `
            -Right $ExpectedExe)) {
        throw 'The registered PID executable identity changed.'
    }
    $commandLine = [string]$cim.CommandLine
    foreach ($argument in $ExpectedArguments) {
        $pattern = '(?i)(?:^|\s)' +
            [regex]::Escape($argument) + '(?:\s|$)'
        if ($commandLine -notmatch $pattern) {
            throw 'The registered PID lacks an exact isolated-source argument.'
        }
    }
}

Assert-I05CleanupAdministrator

if (-not (Test-Path -LiteralPath $RunRoot -PathType Container)) {
    throw 'RunRoot does not exist or is not a directory.'
}
$run = (Resolve-Path -LiteralPath $RunRoot).Path
$runItem = Get-Item -LiteralPath $run -Force
if (($runItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'RunRoot cannot be a reparse point.'
}
$runLeaf = Split-Path -Leaf $run
if ($runLeaf -notmatch
    '^v91-i05-t1-source-(\d{8}-\d{6})-([0-9a-f]{8})$') {
    throw 'RunRoot does not have the exact V91-I05 T1 source run name.'
}
$noncePrefix = $Matches[2]

$ownershipPath = Resolve-LabContainedFile -Root $run `
    -RelativePath 'private\ownership.json'
$ownershipRecord = Read-I05JsonFile -Path $ownershipPath `
    -Context 'V91-I05 T1 ownership record' -MaximumBytes 262144
$ownership = $ownershipRecord.document
Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
    -Object $ownership -Name 'schema' -Context 'Ownership')) `
    -Expected 'ese.v91.i05.t1-source-ownership/v1' `
    -Context 'Ownership schema'
Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
    -Object $ownership -Name 'case_id' -Context 'Ownership')) `
    -Expected $constants.case_id -Context 'Ownership case'
Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
    -Object $ownership -Name 'topology' -Context 'Ownership')) `
    -Expected $constants.topology -Context 'Ownership topology'
$nonce = Assert-I05Nonce -Value (Get-I05RequiredProperty `
    -Object $ownership -Name 'nonce' -Context 'Ownership') `
    -Context 'Ownership nonce'
if ($nonce.Substring(0, 8) -ne $noncePrefix) {
    throw 'Ownership nonce does not match the run directory.'
}
Assert-I05ExactText -Actual ([string](Get-I05RequiredProperty `
    -Object $ownership -Name 'run_id' -Context 'Ownership')) `
    -Expected $runLeaf -Context 'Ownership run ID'
Assert-I05CandidateContract -Candidate (Get-I05RequiredProperty `
    -Object $ownership -Name 'candidate' -Context 'Ownership') `
    -Context 'Ownership.candidate'

$nodeRelative = [string](Get-I05RequiredProperty `
    -Object $ownership -Name 'node_relative_path' -Context 'Ownership')
if ($nodeRelative -ne 'nodes\v91-i05-t1-source-a') {
    throw 'Ownership node path is not the fixed isolated source node.'
}
$sourceExe = Resolve-LabContainedFile -Root $run `
    -RelativePath (Join-Path $nodeRelative 'emule.exe')
$sourceServer = Resolve-LabContainedFile -Root $run `
    -RelativePath (Join-Path $nodeRelative 'ese-server.exe')
$sourceBuildInfo = Resolve-LabContainedFile -Root $run `
    -RelativePath (Join-Path $nodeRelative 'BUILD_INFO.txt')
Assert-I05ExactText -Actual (Get-LabSha256 -Path $sourceExe) `
    -Expected $constants.candidate_emule_sha256 `
    -Context 'Contained emule.exe hash' -IgnoreCase
Assert-I05ExactText -Actual (Get-LabSha256 -Path $sourceServer) `
    -Expected $constants.candidate_ese_server_sha256 `
    -Context 'Contained ese-server.exe hash' -IgnoreCase
Assert-I05ExactText -Actual (Get-LabSha256 -Path $sourceBuildInfo) `
    -Expected $constants.candidate_build_info_sha256 `
    -Context 'Contained BUILD_INFO.txt hash' -IgnoreCase

$sourceInfo = Get-I05RequiredProperty -Object $ownership `
    -Name 'source' -Context 'Ownership'
$sourceIPv4 = ConvertTo-I05CanonicalIPv4 -Value (
    Get-I05RequiredProperty -Object $sourceInfo `
        -Name 'ipv4_address' -Context 'Ownership.source'
) -Context 'Ownership source IPv4'
$sourceIPv6 = ConvertTo-I05CanonicalIPv6 -Value (
    Get-I05RequiredProperty -Object $sourceInfo `
        -Name 'ipv6_address' -Context 'Ownership.source'
) -Context 'Ownership source IPv6'
$interfaceAlias = [string](Get-I05RequiredProperty `
    -Object $sourceInfo -Name 'interface_alias' `
    -Context 'Ownership.source')
if ($interfaceAlias -match $constants.forbidden_interface_pattern) {
    throw 'Ownership names a forbidden interface.'
}

$processInfo = Get-I05RequiredProperty -Object $ownership `
    -Name 'process' -Context 'Ownership'
$processIdText = [string](Get-I05RequiredProperty `
    -Object $processInfo -Name 'process_id' -Context 'Ownership.process')
if ($processIdText -notmatch '^[0-9]{1,10}$') {
    throw 'Ownership process ID is invalid.'
}
$sourceProcessId = [int]$processIdText
$launchPending = [bool](Get-I05RequiredProperty `
    -Object $processInfo -Name 'launch_pending' `
    -Context 'Ownership.process')
$processStarted = [bool](Get-I05RequiredProperty `
    -Object $processInfo -Name 'started' -Context 'Ownership.process')
$processStart = $null
if ($processStarted) {
    if ($sourceProcessId -le 0) {
        throw 'Ownership marks a started process without a positive PID.'
    }
    $processStart = ConvertTo-I05UtcTimestamp -Value (
        Get-I05RequiredProperty -Object $processInfo `
            -Name 'start_time_utc' -Context 'Ownership.process'
    ) -Context 'Ownership process start'
} elseif ($sourceProcessId -ne 0) {
    throw 'Ownership records a PID for a process not marked started.'
}

$expectedArguments = @(
    '--portable',
    '--ignoreinstances',
    '--headless',
    "--metrics-port=$($constants.source_web_port)",
    "--tcp-port=$($constants.source_tcp_port)",
    "--udp-port=$($constants.source_udp_port)"
)

if ($launchPending -and -not $processStarted) {
    $launchNotBefore = ConvertTo-I05UtcTimestamp -Value (
        Get-I05RequiredProperty -Object $processInfo `
            -Name 'launch_not_before_utc' -Context 'Ownership.process'
    ) -Context 'Ownership pending-launch boundary'
    $pendingMatches = [Collections.Generic.List[object]]::new()
    foreach ($cim in @(Get-CimInstance -ClassName Win32_Process `
            -Filter "Name = 'emule.exe'" -ErrorAction Stop)) {
        if (-not (Test-I05SamePath -Left ([string]$cim.ExecutablePath) `
                -Right $sourceExe)) {
            continue
        }
        $commandLine = [string]$cim.CommandLine
        $argumentsExact = $true
        foreach ($argument in $expectedArguments) {
            $pattern = '(?i)(?:^|\s)' +
                [regex]::Escape($argument) + '(?:\s|$)'
            if ($commandLine -notmatch $pattern) {
                $argumentsExact = $false
                break
            }
        }
        if (-not $argumentsExact) { continue }
        $candidateProcess = Get-I05CleanupProcessById `
            -ProcessId ([int]$cim.ProcessId)
        if ($null -eq $candidateProcess) { continue }
        $candidateStart =
            [DateTimeOffset]$candidateProcess.StartTime.ToUniversalTime()
        if ($candidateStart -lt $launchNotBefore.AddSeconds(-5)) {
            continue
        }
        $pendingMatches.Add([pscustomobject][ordered]@{
            process = $candidateProcess
            started_at = $candidateStart
        })
    }
    if ($pendingMatches.Count -gt 1) {
        throw 'Pending launch maps to more than one exact source process.'
    }
    if ($pendingMatches.Count -eq 1) {
        $sourceProcessId = [int]$pendingMatches[0].process.Id
        $processStart = $pendingMatches[0].started_at
        $processStarted = $true
    }
}

$process = if ($sourceProcessId -gt 0) {
    Get-I05CleanupProcessById -ProcessId $sourceProcessId
} else {
    $null
}
$listenersBefore = @(Get-I05CleanupTcpSnapshot | Where-Object {
    [string]$_.State -eq 'Listen' -and (
        [int]$_.LocalPort -eq $constants.source_tcp_port -or
        [int]$_.LocalPort -eq $constants.source_web_port
    )
})
$udpBefore = @(Get-I05CleanupUdpSnapshot | Where-Object {
    [int]$_.LocalPort -eq $constants.source_udp_port
})
$processStateBefore = 'not-started'
$processIdentityExact = $false
if ($null -ne $process) {
    Assert-I05CleanupOwnedProcess -Process $process `
        -ExpectedExe $sourceExe -ExpectedStart $processStart `
        -ExpectedArguments $expectedArguments
    $foreignListeners = @($listenersBefore | Where-Object {
        [int]$_.OwningProcess -ne $sourceProcessId
    })
    if ($foreignListeners.Count -gt 0) {
        throw 'A source port is also owned by an unrelated process.'
    }
    if (@($udpBefore | Where-Object {
            [int]$_.OwningProcess -ne $sourceProcessId
        }).Count -gt 0) {
        throw 'Source UDP port is also owned by an unrelated process.'
    }
    $processStateBefore = 'running-exact'
    $processIdentityExact = $true
} elseif (@($listenersBefore).Count -gt 0 -or $udpBefore.Count -gt 0) {
    throw 'A source TCP/UDP port is owned by another process; cleanup refuses it.'
} elseif ($processStarted) {
    $processStateBefore = 'already-exited'
}

$firewallInfo = Get-I05RequiredProperty -Object $ownership `
    -Name 'firewall' -Context 'Ownership'
$probeName = [string](Get-I05RequiredProperty `
    -Object $firewallInfo -Name 'probe_name' `
    -Context 'Ownership.firewall')
$probeDisplay = [string](Get-I05RequiredProperty `
    -Object $firewallInfo -Name 'probe_display_name' `
    -Context 'Ownership.firewall')
$dataName = [string](Get-I05RequiredProperty `
    -Object $firewallInfo -Name 'data_name' `
    -Context 'Ownership.firewall')
$dataDisplay = [string](Get-I05RequiredProperty `
    -Object $firewallInfo -Name 'data_display_name' `
    -Context 'Ownership.firewall')
$probePendingValue = Get-I05RequiredProperty -Object $firewallInfo `
    -Name 'probe_pending' -Context 'Ownership.firewall'
$probeCreatedValue = Get-I05RequiredProperty -Object $firewallInfo `
    -Name 'probe_created' -Context 'Ownership.firewall'
$dataPendingValue = Get-I05RequiredProperty -Object $firewallInfo `
    -Name 'data_pending' -Context 'Ownership.firewall'
$dataCreatedValue = Get-I05RequiredProperty -Object $firewallInfo `
    -Name 'data_created' -Context 'Ownership.firewall'
foreach ($ownedBoolean in @(
    [pscustomobject]@{
        value = $probePendingValue
        context = 'Ownership.firewall.probe_pending'
    },
    [pscustomobject]@{
        value = $probeCreatedValue
        context = 'Ownership.firewall.probe_created'
    },
    [pscustomobject]@{
        value = $dataPendingValue
        context = 'Ownership.firewall.data_pending'
    },
    [pscustomobject]@{
        value = $dataCreatedValue
        context = 'Ownership.firewall.data_created'
    }
)) {
    if ($ownedBoolean.value -isnot [bool]) {
        throw "$($ownedBoolean.context) must be a JSON boolean."
    }
}
$probePending = [bool]$probePendingValue
$probeCreated = [bool]$probeCreatedValue
$dataPending = [bool]$dataPendingValue
$dataCreated = [bool]$dataCreatedValue
if ($probePending -and $probeCreated) {
    throw 'Probe firewall ownership cannot be pending and created together.'
}
if ($dataPending -and $dataCreated) {
    throw 'Data firewall ownership cannot be pending and created together.'
}
if ($probePending) {
    $null = ConvertTo-I05UtcTimestamp -Value (
        Get-I05RequiredProperty -Object $firewallInfo `
            -Name 'probe_pending_at_utc' -Context 'Ownership.firewall'
    ) -Context 'Probe firewall pending boundary'
}
if ($dataPending) {
    $null = ConvertTo-I05UtcTimestamp -Value (
        Get-I05RequiredProperty -Object $firewallInfo `
            -Name 'data_pending_at_utc' -Context 'Ownership.firewall'
    ) -Context 'Data firewall pending boundary'
}
Assert-I05ExactText -Actual $probeName `
    -Expected "eSE-V91-I05-PROBE-$nonce" `
    -Context 'Probe firewall Name'
Assert-I05ExactText -Actual $probeDisplay `
    -Expected "eSE V91 I05 T1 probe $noncePrefix" `
    -Context 'Probe firewall DisplayName'
Assert-I05ExactText -Actual $dataName `
    -Expected "eSE-V91-I05-DATA-$nonce" `
    -Context 'Data firewall Name'
Assert-I05ExactText -Actual $dataDisplay `
    -Expected "eSE V91 I05 T1 data $noncePrefix" `
    -Context 'Data firewall DisplayName'

$remoteInfo = Get-I05RequiredProperty -Object $ownership `
    -Name 'remote' -Context 'Ownership'
$remotePresent = [bool](Get-I05RequiredProperty -Object $remoteInfo `
    -Name 'registered' -Context 'Ownership.remote')
$remoteIPv4 = ''
if ($remotePresent) {
    $remoteIPv4 = ConvertTo-I05CanonicalIPv4 -Value (
        Get-I05RequiredProperty -Object $remoteInfo `
            -Name 'ipv4_address' -Context 'Ownership.remote'
    ) -Context 'Ownership remote IPv4'
}

$shellExe = [string](Get-I05RequiredProperty `
    -Object $firewallInfo -Name 'probe_program' `
    -Context 'Ownership.firewall')
$rulePlans = [Collections.Generic.List[object]]::new()
$rulePlans.Add([pscustomobject][ordered]@{
    label = 'probe'
    name = $probeName
    display = $probeDisplay
    program = $shellExe
    local_address = $sourceIPv6
    remote_address = 'LocalSubnet'
    local_port = $constants.source_probe_port
    ownership_pending = $probePending
    ownership_created = $probeCreated
})
if ($remotePresent) {
    $rulePlans.Add([pscustomobject][ordered]@{
        label = 'data'
        name = $dataName
        display = $dataDisplay
        program = $sourceExe
        local_address = $sourceIPv4
        remote_address = $remoteIPv4
        local_port = $constants.source_tcp_port
        ownership_pending = $dataPending
        ownership_created = $dataCreated
    })
} elseif ($dataPending -or $dataCreated) {
    throw (
        'Data firewall ownership exists without an exact registered remote; ' +
        'cleanup refuses an under-specified rule.'
    )
}

$failureCodes = [Collections.Generic.List[string]]::new()
$ruleResults = [Collections.Generic.List[object]]::new()
$stopMethod = if ($processStarted) { 'already-exited' } else { 'not-started' }
if ($processStateBefore -eq 'running-exact') {
    try {
        $current = Get-I05CleanupProcessById `
            -ProcessId $sourceProcessId
        if ($null -ne $current) {
            Assert-I05CleanupOwnedProcess -Process $current `
                -ExpectedExe $sourceExe -ExpectedStart $processStart `
                -ExpectedArguments $expectedArguments
            $closeRequested = $current.CloseMainWindow()
            if ($closeRequested -and $current.WaitForExit(10000)) {
                $stopMethod = 'close-main-window'
            } else {
                $current = Get-I05CleanupProcessById `
                    -ProcessId $sourceProcessId
                if ($null -ne $current) {
                    Assert-I05CleanupOwnedProcess -Process $current `
                        -ExpectedExe $sourceExe `
                        -ExpectedStart $processStart `
                        -ExpectedArguments $expectedArguments
                    Stop-Process -InputObject $current -Force -ErrorAction Stop
                    if (-not $current.WaitForExit(10000)) {
                        throw 'Exact source process did not exit.'
                    }
                    $stopMethod = 'forced-exact-process'
                } else {
                    $stopMethod = 'exited-during-grace'
                }
            }
        }
    } catch {
        $failureCodes.Add('source-process-stop-failed')
    }
}

foreach ($plan in $rulePlans.ToArray()) {
    $state = 'already-absent'
    $identityExact = $false
    $action = 'none'
    try {
        $rules = @(Get-I05CleanupRule -Name $plan.name)
        $displayRules = @(Get-I05CleanupDisplayRule `
            -DisplayName $plan.display)
        if ($rules.Count -eq 0) {
            if ($displayRules.Count -gt 0) {
                throw 'An unexpected rule reuses the registered DisplayName.'
            }
        } elseif ($rules.Count -ne 1 -or $displayRules.Count -ne 1 -or
            [string]$rules[0].Name -ne [string]$displayRules[0].Name) {
            throw 'Firewall identity is ambiguous.'
        } else {
            $state = 'present-exact'
            Assert-I05CleanupFirewallRule -Rule $rules[0] `
                -ExpectedName $plan.name `
                -ExpectedDisplayName $plan.display `
                -ExpectedProgram $plan.program `
                -ExpectedInterfaceAlias $interfaceAlias `
                -ExpectedLocalAddress $plan.local_address `
                -ExpectedRemoteAddress $plan.remote_address `
                -ExpectedLocalPort $plan.local_port
            $identityExact = $true
            Remove-NetFirewallRule -Name $plan.name -ErrorAction Stop
            $action = 'removed-exact-rule'
        }
    } catch {
        $failureCodes.Add("$($plan.label)-firewall-removal-failed")
        $action = 'refused-or-failed'
    }
    try {
        $remaining = Get-I05CleanupRule -Name $plan.name
        $absent = $remaining.Count -eq 0
    } catch {
        $absent = $false
        if (-not $failureCodes.Contains(
                "$($plan.label)-firewall-enumeration-failed")) {
            $failureCodes.Add(
                "$($plan.label)-firewall-enumeration-failed")
        }
    }
    if (-not $absent) {
        $failureCodes.Add("$($plan.label)-firewall-remains")
    }
    $ruleResults.Add([pscustomobject][ordered]@{
        kind = $plan.label
        state_before = $state
        identity_exact_when_present = $identityExact
        action = $action
        absent_after = $absent
        ownership_pending_before = [bool]$plan.ownership_pending
        ownership_created_before = [bool]$plan.ownership_created
    })
}

$deadline = [DateTime]::UtcNow.AddSeconds(15)
do {
    $listenersAfter = @(Get-I05CleanupTcpSnapshot | Where-Object {
        [string]$_.State -eq 'Listen' -and (
            [int]$_.LocalPort -eq $constants.source_tcp_port -or
            [int]$_.LocalPort -eq $constants.source_web_port -or
            [int]$_.LocalPort -eq $constants.source_probe_port
        )
    })
    $udpAfter = @(Get-I05CleanupUdpSnapshot | Where-Object {
        [int]$_.LocalPort -eq $constants.source_udp_port
    })
    if ($listenersAfter.Count -eq 0 -and $udpAfter.Count -eq 0) {
        break
    }
    Start-Sleep -Milliseconds 250
} while ([DateTime]::UtcNow -lt $deadline)

$processAbsent = if ($sourceProcessId -gt 0) {
    $null -eq (Get-I05CleanupProcessById `
        -ProcessId $sourceProcessId)
} else {
    $true
}
$listenersAbsent =
    $listenersAfter.Count -eq 0 -and $udpAfter.Count -eq 0
if (-not $processAbsent) {
    $failureCodes.Add('source-process-remains')
}
if (-not $listenersAbsent) {
    $failureCodes.Add('source-listener-remains')
}

$cleanupComplete = $failureCodes.Count -eq 0
$cleanup = [ordered]@{
    schema = 'ese.v91.i05.t1-source-cleanup/v1'
    case_id = $constants.case_id
    topology = $constants.topology
    status = if ($cleanupComplete) { 'PASS' } else { 'FAIL' }
    captured_at_utc = Get-LabUtcTimestamp
    run_id = $runLeaf
    nonce_sha256 = Get-LabStringSha256 -Value $nonce
    ownership_sha256 =
        Get-LabStringSha256 -Value $ownershipRecord.raw
    candidate = [ordered]@{
        version = $constants.candidate_version
        commit = $constants.candidate_commit
        dirty = $false
        emule_sha256 = $constants.candidate_emule_sha256
        ese_server_sha256 =
            $constants.candidate_ese_server_sha256
        build_info_sha256 =
            $constants.candidate_build_info_sha256
        zip_sha256 = $constants.candidate_zip_sha256
        zip_bytes = $constants.candidate_zip_bytes
    }
    process = [ordered]@{
        state_before = $processStateBefore
        identity_exact_when_present = $processIdentityExact
        stop_method = $stopMethod
        absent_after = $processAbsent
    }
    firewall = $ruleResults.ToArray()
    listeners_absent_after = $listenersAbsent
    cleanup_complete = $cleanupComplete
    failure_codes = $failureCodes.ToArray()
    privacy = [ordered]@{
        ip_address_included = $false
        hostname_included = $false
        user_path_included = $false
        password_included = $false
    }
}
$cleanupPath = Write-LabJson -Value $cleanup `
    -Path (Join-Path $run 'evidence\cleanup.json')

$resultPath = Join-Path $run 'CLEANUP-V91-I05-T1.txt'
$resultText = @(
    "V91-I05 T1 SOURCE CLEANUP " +
        $(if ($cleanupComplete) { 'PASS' } else { 'FAIL' })
    "candidate_commit=$($constants.candidate_commit)"
    "source_process=$stopMethod"
    "listeners_absent=$listenersAbsent"
    "cleanup_evidence=evidence\cleanup.json"
) -join "`r`n"
$null = Write-LabText -Value ($resultText + "`r`n") `
    -Path $resultPath

if (-not $cleanupComplete) {
    throw (
        'V91-I05 T1 cleanup is incomplete. Review sanitized ' +
        'evidence\cleanup.json; no unrelated process or rule was targeted.'
    )
}

Write-Host 'V91-I05 T1 SOURCE CLEANUP PASS' -ForegroundColor Green
Write-Host "Evidence: $cleanupPath"
if (-not $NoOpen) {
    try {
        Start-Process -FilePath 'notepad.exe' `
            -ArgumentList @($resultPath) | Out-Null
    } catch {
        Write-Warning 'Cleanup passed, but the result text could not be opened.'
    }
}
