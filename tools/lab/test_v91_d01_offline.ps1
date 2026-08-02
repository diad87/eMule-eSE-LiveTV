[CmdletBinding()]
param(
    [string]$HarnessPath = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

if ([string]::IsNullOrWhiteSpace($HarnessPath)) {
    $HarnessPath = Join-Path $PSScriptRoot 'test_v91_d01_dual_dns.ps1'
}
$script:SelfPath = [IO.Path]::GetFullPath($MyInvocation.MyCommand.Path)
$script:HarnessPath = [IO.Path]::GetFullPath($HarnessPath)
$script:HarnessBytes = [IO.File]::ReadAllBytes($script:HarnessPath)
$script:HarnessSha = [Security.Cryptography.SHA256]::Create()
try {
    $script:HarnessInitialSha256 = ([BitConverter]::ToString(
        $script:HarnessSha.ComputeHash($script:HarnessBytes)
    )).Replace('-', '').ToLowerInvariant()
} finally { $script:HarnessSha.Dispose() }
$script:HarnessStream = [IO.MemoryStream]::new(
    $script:HarnessBytes, $false)
$script:HarnessReader = [IO.StreamReader]::new(
    $script:HarnessStream, [Text.Encoding]::UTF8, $true)
try {
    $script:HarnessText = $script:HarnessReader.ReadToEnd()
} finally {
    $script:HarnessReader.Dispose()
    $script:HarnessStream.Dispose()
}
$script:HarnessTokens = $null
$script:HarnessParserErrors = $null
$script:HarnessAst =
    [Management.Automation.Language.Parser]::ParseInput(
        $script:HarnessText,
        [ref]$script:HarnessTokens,
        [ref]$script:HarnessParserErrors)
$script:Results = [System.Collections.Generic.List[object]]::new()
$script:TempRoot = Join-Path ([IO.Path]::GetTempPath()) `
    ('ese-v91-d01-offline-' + [Guid]::NewGuid().ToString('N'))
$script:TempCleanupProven = $false
$script:ExtractedFunctionNames =
    [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal)
$script:PureFunctionAllowlist = @(
    'Assert-D01ExactPropertySet',
    'Assert-D01JsonBoolean',
    'Assert-D01JsonInteger',
    'Assert-D01JsonStringArray',
    'Assert-D01JsonStringValue',
    'Assert-D01PktmonAllCounterSnapshotContract',
    'Get-D01AtomicJsonSerializationFingerprint',
    'Get-D01PktmonAllCounterSnapshotEvidence',
    'Get-D01Sha256FromStream',
    'Test-D01ImmutableCounterEvidenceSnapshot'
)

function Get-D01OfflineStringSha256 {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value)

    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString(
            $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value))
        )).Replace('-', '').ToLowerInvariant()
    } finally { $sha.Dispose() }
}

function Get-D01OfflineBytesSha256 {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)

    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).
            Replace('-', '').ToLowerInvariant()
    } finally { $sha.Dispose() }
}

function Get-D01OfflineFileSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)

    $stream = [IO.File]::Open(
        [IO.Path]::GetFullPath($Path),
        [IO.FileMode]::Open, [IO.FileAccess]::Read,
        [IO.FileShare]::Read)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($stream))).
            Replace('-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
        $stream.Dispose()
    }
}

function Assert-D01Offline {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Code
    )

    if (-not $Condition) { throw $Code }
}

function Assert-D01OfflineEqual {
    param(
        [AllowNull()][object]$Actual,
        [AllowNull()][object]$Expected,
        [Parameter(Mandatory = $true)][string]$Code
    )

    if ([string]$Actual -cne [string]$Expected) { throw $Code }
}

function Assert-D01OfflineThrows {
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Body,
        [Parameter(Mandatory = $true)][string]$ExpectedMessage
    )

    $caught = ''
    try { $null = & $Body } catch { $caught = [string]$_.Exception.Message }
    Assert-D01Offline -Condition ($caught -ceq $ExpectedMessage) `
        -Code 'EXPECTED_EXACT_REJECTION_NOT_OBSERVED'
}

function Invoke-D01OfflineTest {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)][scriptblock]$Body
    )

    if (@($script:Results | Where-Object id -ceq $Id).Count -ne 0) {
        throw 'OFFLINE_TEST_ID_COLLISION'
    }
    try {
        $null = & $Body
        $script:Results.Add([pscustomobject][ordered]@{
            id = $Id
            category = $Category
            status = 'PASS'
            failure_type = ''
            failure_id = ''
            failure_sha256 = ''
        })
    } catch {
        $message = [string]$_.Exception.Message
        $repoRoot = [IO.Path]::GetDirectoryName(
            [IO.Path]::GetDirectoryName(
                [IO.Path]::GetDirectoryName($script:HarnessPath)))
        if (-not [string]::IsNullOrWhiteSpace($repoRoot)) {
            $message = $message.Replace($repoRoot, '<REPO>')
        }
        if (-not [string]::IsNullOrWhiteSpace($script:TempRoot)) {
            $message = $message.Replace($script:TempRoot, '<TEMP>')
        }
        $failureId = ([string]$_.FullyQualifiedErrorId).Split(',')[0]
        if ($failureId -ceq 'PropertyNotFoundStrict' -and
            $message -match "'([A-Za-z0-9_]+)'") {
            $failureId = 'PROPERTY_NOT_FOUND_' +
                $Matches[1].ToUpperInvariant()
        } elseif ($message -match '^[A-Z][A-Z0-9_]{2,95}$') {
            $failureId = $message
        }
        $script:Results.Add([pscustomobject][ordered]@{
            id = $Id
            category = $Category
            status = 'FAIL'
            failure_type = $_.Exception.GetType().Name
            failure_id = $failureId
            failure_sha256 = Get-D01OfflineStringSha256 -Value $message
        })
    }
}

function Assert-D01AstNoExternalSideEffects {
    param(
        [Parameter(Mandatory = $true)]
        [Management.Automation.Language.Ast]$Ast,
        [Parameter(Mandatory = $true)][string]$Code
    )

    $forbiddenCommands = @(
        'Add-Type', 'Connect-PSSession', 'Disable-NetAdapter',
        'Disable-NetAdapterBinding', 'Enable-NetAdapter',
        'Enable-NetAdapterBinding', 'Enter-PSSession', 'Find-NetRoute',
        'Get-CimInstance', 'Get-DnsClient', 'Get-DnsClientCache',
        'Get-DnsClientServerAddress', 'Get-NetAdapter',
        'Get-NetAdapterBinding', 'Get-NetFirewallAddressFilter',
        'Get-NetFirewallApplicationFilter', 'Get-NetFirewallInterfaceFilter',
        'Get-NetFirewallInterfaceTypeFilter', 'Get-NetFirewallPortFilter',
        'Get-NetFirewallProfile', 'Get-NetFirewallRule',
        'Get-NetFirewallSecurityFilter', 'Get-NetFirewallServiceFilter',
        'Get-NetIPAddress', 'Get-NetIPConfiguration', 'Get-NetIPInterface',
        'Get-NetRoute', 'Get-NetTCPConnection', 'Get-NetUDPEndpoint',
        'Get-Process', 'Invoke-Command', 'Invoke-D01EtwLossEvidence',
        'Invoke-D01Pktmon', 'Invoke-D01PktmonDriverStop',
        'Invoke-Expression', 'Invoke-RestMethod', 'Invoke-WebRequest',
        'New-NetFirewallRule', 'New-NetIPAddress', 'New-NetRoute',
        'New-PSSession', 'netsh', 'pktmon', 'pktmon.exe', 'logman',
        'logman.exe', 'powershell', 'powershell.exe', 'pwsh', 'pwsh.exe',
        'reg', 'reg.exe', 'Remove-NetFirewallRule', 'Remove-NetIPAddress',
        'Remove-NetRoute', 'Restart-NetAdapter', 'route', 'route.exe',
        'Set-DnsClientServerAddress', 'Set-NetAdapter',
        'Set-NetFirewallProfile', 'Set-NetFirewallRule',
        'Set-NetIPInterface', 'Set-NetRoute', 'Start-D01PacketCapture',
        'Start-Job', 'Start-Process', 'Stop-D01PacketCapture',
        'Stop-Process', 'Test-NetConnection'
    )
    $commands = @($Ast.FindAll({
        param($node)
        $node -is [Management.Automation.Language.CommandAst]
    }, $true) | ForEach-Object { $_.GetCommandName() } |
        Where-Object { $_ })
    Assert-D01Offline -Condition (@($commands | Where-Object {
                $forbiddenCommands -ccontains $_
            }).Count -eq 0) -Code $Code

    $forbiddenNewObject = @($Ast.FindAll({
        param($node)
        $node -is [Management.Automation.Language.CommandAst] -and
            $node.GetCommandName() -ceq 'New-Object' -and
            $node.Extent.Text -match
                '(?i)\bNet\.Sockets\.(TcpClient|TcpListener|UdpClient)\b'
    }, $true))
    Assert-D01Offline -Condition ($forbiddenNewObject.Count -eq 0) `
        -Code $Code
    $typeTexts = @($Ast.FindAll({
        param($node)
        $node -is [Management.Automation.Language.TypeExpressionAst]
    }, $true) | ForEach-Object { $_.TypeName.FullName })
    foreach ($pattern in @(
        '^Diagnostics\.Process$', '^Microsoft\.Win32\.Registry',
        '^Net\.Http\.',
        '^Net\.Sockets\.(TcpClient|TcpListener|UdpClient)$')) {
        Assert-D01Offline -Condition (@($typeTexts | Where-Object {
                    $_ -match $pattern
                }).Count -eq 0) -Code $Code
    }
}

function Get-D01HarnessFunctionAst {
    param([Parameter(Mandatory = $true)][string]$Name)

    Assert-D01Offline -Condition (
        $script:PureFunctionAllowlist -ccontains $Name) `
        -Code 'PURE_FUNCTION_NOT_ALLOWLISTED'
    $matches = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq $Name
    }, $true))
    Assert-D01Offline -Condition ($matches.Count -eq 1) `
        -Code 'PURE_FUNCTION_NOT_UNIQUE'
    Assert-D01AstNoExternalSideEffects -Ast $matches[0] `
        -Code 'PURE_FUNCTION_EXTERNAL_SIDE_EFFECT_FOUND_BEFORE_EXTRACTION'
    [void]$script:ExtractedFunctionNames.Add($Name)
    return $matches[0]
}

function Invoke-D01PureScope {
    param(
        [Parameter(Mandatory = $true)][string[]]$FunctionNames,
        [Parameter(Mandatory = $true)][scriptblock]$Body,
        [object[]]$ArgumentList = @()
    )

    $definitions = @($FunctionNames | ForEach-Object {
        (Get-D01HarnessFunctionAst -Name $_).Extent.Text
    }) -join "`r`n`r`n"
    $safeHelpers = @'
function Get-LabStringSha256 {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString(
            $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value))
        )).Replace('-', '').ToLowerInvariant()
    } finally { $sha.Dispose() }
}
function Get-LabSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)
    $stream = [IO.File]::Open(
        [IO.Path]::GetFullPath($Path), [IO.FileMode]::Open,
        [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($stream))).
            Replace('-', '').ToLowerInvariant()
    } finally { $sha.Dispose(); $stream.Dispose() }
}
'@
    return & {
        param($HelperText, $DefinitionText, $TestBody, $Arguments)
        . ([scriptblock]::Create($HelperText))
        . ([scriptblock]::Create($DefinitionText))
        & $TestBody @Arguments
    } $safeHelpers $definitions $Body $ArgumentList
}

function Copy-D01OfflineObject {
    param([Parameter(Mandatory = $true)][object]$Value)

    return $Value | ConvertTo-Json -Depth 24 | ConvertFrom-Json
}

function Get-D01OfflineAtomicFingerprint {
    param([Parameter(Mandatory = $true)][object]$Value)

    return Invoke-D01PureScope -FunctionNames @(
        'Get-D01Sha256FromStream',
        'Get-D01AtomicJsonSerializationFingerprint'
    ) -Body {
        param($fixture)
        Get-D01AtomicJsonSerializationFingerprint -Value $fixture
    } -ArgumentList @($Value)
}

function Test-D01OfflineImmutableSnapshot {
    param(
        [Parameter(Mandatory = $true)][object]$Snapshot,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][object]$ExpectedValue
    )

    return Invoke-D01PureScope -FunctionNames @(
        'Assert-D01ExactPropertySet',
        'Assert-D01JsonBoolean',
        'Assert-D01JsonInteger',
        'Assert-D01JsonStringValue',
        'Get-D01Sha256FromStream',
        'Get-D01AtomicJsonSerializationFingerprint',
        'Test-D01ImmutableCounterEvidenceSnapshot'
    ) -Body {
        param($metadata, $fixturePath, $expected)
        Test-D01ImmutableCounterEvidenceSnapshot `
            -Snapshot $metadata -Path $fixturePath -ExpectedValue $expected
    } -ArgumentList @($Snapshot, $Path, $ExpectedValue)
}

function New-D01OfflineAllCounterStdout {
    param(
        [string]$DropName = 'Ethernet',
        [string]$FlowName = 'Flujo independiente'
    )

    $dropInbound = [pscustomobject][ordered]@{
        DirectionTag = 'Entrada'
        Packets = 0
        Bytes = 0
        'Last Drop Reason' = 'No especificado'
    }
    $dropOutbound = [pscustomobject][ordered]@{
        DirectionTag = 'Salida'
        Packets = 0
        Bytes = 0
        'Last Drop Reason' = 'No especificado'
    }
    $flowInbound = [pscustomobject][ordered]@{
        DirectionTag = 'Entrada'
        Packets = 0
        Bytes = 0
    }
    $flowOutbound = [pscustomobject][ordered]@{
        DirectionTag = 'Salida'
        Packets = 0
        Bytes = 0
    }
    $root = @([pscustomobject][ordered]@{
        Group = 'Adaptadores'
        Components = @([pscustomobject][ordered]@{
            Name = 'Ethernet'
            Id = 7
            Counters = @(
                [pscustomobject][ordered]@{
                    Name = $DropName
                    Type = 'Descartes'
                    Inbound = $dropInbound
                    Outbound = $dropOutbound
                },
                [pscustomobject][ordered]@{
                    Name = $FlowName
                    Type = 'Flujos'
                    Inbound = $flowInbound
                    Outbound = $flowOutbound
                }
            )
        })
    })
    return ConvertTo-Json -InputObject $root -Depth 10
}

function Get-D01OfflineAllCounterEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$Stdout,
        [AllowNull()][object]$ExpectedBaseline = $null
    )

    return Invoke-D01PureScope -FunctionNames @(
        'Assert-D01ExactPropertySet',
        'Assert-D01JsonInteger',
        'Assert-D01JsonStringValue',
        'Get-D01PktmonAllCounterSnapshotEvidence'
    ) -Body {
        param($json, $baseline)
        Get-D01PktmonAllCounterSnapshotEvidence `
            -Stdout $json -ExitCode 0 -ProcessExited $true `
            -OutputComplete $true -ExpectedBaseline $baseline
    } -ArgumentList @($Stdout, $ExpectedBaseline)
}

function Assert-D01OfflineAllCounterEvidence {
    param(
        [Parameter(Mandatory = $true)][object]$Evidence,
        [AllowNull()][object]$ExpectedBaseline = $null,
        [switch]$RequireAllZero,
        [switch]$RequireRestored
    )

    return Invoke-D01PureScope -FunctionNames @(
        'Assert-D01ExactPropertySet',
        'Assert-D01JsonBoolean',
        'Assert-D01JsonInteger',
        'Assert-D01JsonStringArray',
        'Assert-D01JsonStringValue',
        'Assert-D01PktmonAllCounterSnapshotContract'
    ) -Body {
        param($value, $baseline, $allZero, $restored)
        Assert-D01PktmonAllCounterSnapshotContract `
            -Evidence $value -ExpectedBaseline $baseline `
            -RequireAllZero:$allZero -RequireRestored:$restored
    } -ArgumentList @(
        $Evidence, $ExpectedBaseline,
        [bool]$RequireAllZero, [bool]$RequireRestored)
}

function Get-D01OfflineFunctionAstFromAst {
    param(
        [Parameter(Mandatory = $true)]
        [Management.Automation.Language.Ast]$Ast,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $matches = @($Ast.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq $Name
    }, $true))
    if ($matches.Count -ne 1) { throw 'STATIC_FUNCTION_NOT_UNIQUE' }
    return $matches[0]
}

function Get-D01OfflineCleanupContract {
    param(
        [Parameter(Mandatory = $true)]
        [Management.Automation.Language.Ast]$Ast
    )

    $issues = [Collections.Generic.List[string]]::new()
    try {
        $start = Get-D01OfflineFunctionAstFromAst `
            -Ast $Ast -Name 'Start-D01PacketCapture'
        $stop = Get-D01OfflineFunctionAstFromAst `
            -Ast $Ast -Name 'Stop-D01PacketCapture'
        $coordinator = Get-D01OfflineFunctionAstFromAst `
            -Ast $Ast -Name 'Invoke-D01CoordinatorRole'
    } catch {
        $issues.Add('REQUIRED_FUNCTION_NOT_UNIQUE')
        return [pscustomobject][ordered]@{
            valid = $false
            issues = $issues.ToArray()
        }
    }

    $startText = $start.Extent.Text
    $pendingStateAt = $startText.IndexOf(
        '$script:d01PendingPktmonCleanupState = $state')
    $firstFilterMutationAt = $startText.IndexOf("'filter', 'add'")
    if ($pendingStateAt -lt 0 -or $firstFilterMutationAt -lt 0 -or
        $pendingStateAt -ge $firstFilterMutationAt) {
        $issues.Add('PENDING_STATE_NOT_REGISTERED_BEFORE_MUTATION')
    }

    $coordinatorText = $coordinator.Extent.Text
    $pendingFailuresAt = $coordinatorText.IndexOf(
        '$script:d01PendingPktmonCleanupFailures = $cleanupFailures')
    $startCallAt = $coordinatorText.IndexOf(
        '$capture = Start-D01PacketCapture')
    if ($pendingFailuresAt -lt 0 -or $startCallAt -lt 0 -or
        $pendingFailuresAt -ge $startCallAt) {
        $issues.Add('PENDING_FAILURE_LEDGER_NOT_BOUND_BEFORE_START')
    }

    $stopText = $stop.Extent.Text
    $entryGuardAt = $stopText.IndexOf(
        'if (-not (Test-D01TrustedCommandLedgerQuiescent -Terminate))')
    $firstCleanupProbeAt = $stopText.IndexOf('$pktmonCliAvailable = $false')
    $deferredFlagAt = $stopText.IndexOf(
        '$State.cleanup_deferred_for_active_lease = $true')
    $retainStateAt = $stopText.IndexOf(
        '$script:d01PendingPktmonCleanupState = $State')
    $retainFailuresAt = $stopText.IndexOf(
        '$script:d01PendingPktmonCleanupFailures = $CleanupFailures')
    $returnFalseAt = if ($entryGuardAt -ge 0) {
        $stopText.IndexOf('return $false', $entryGuardAt)
    } else { -1 }
    if ($entryGuardAt -lt 0 -or $firstCleanupProbeAt -lt 0 -or
        $entryGuardAt -ge $firstCleanupProbeAt -or
        $deferredFlagAt -le $entryGuardAt -or
        $retainStateAt -le $deferredFlagAt -or
        $retainFailuresAt -le $retainStateAt -or
        $returnFalseAt -le $retainFailuresAt -or
        $returnFalseAt -ge $firstCleanupProbeAt) {
        $issues.Add('ENTRY_QUIESCENCE_DEFER_BRANCH_NOT_EXACT')
    }

    $sequenceCompleteAt = $stopText.LastIndexOf(
        '$State.cleanup_sequence_completed = $true')
    $referenceEqualsAt = $stopText.LastIndexOf(
        '[object]::ReferenceEquals(')
    $clearStateAt = $stopText.LastIndexOf(
        '$script:d01PendingPktmonCleanupState = $null')
    $clearFailuresAt = $stopText.LastIndexOf(
        '$script:d01PendingPktmonCleanupFailures = $null')
    $returnTrueAt = $stopText.LastIndexOf('return $true')
    if ($sequenceCompleteAt -lt 0 -or
        $referenceEqualsAt -le $sequenceCompleteAt -or
        $clearStateAt -le $referenceEqualsAt -or
        $clearFailuresAt -le $clearStateAt -or
        $returnTrueAt -le $clearFailuresAt) {
        $issues.Add('PENDING_CLEAR_NOT_TERMINAL_AND_REFERENCE_BOUND')
    }

    $commitGuardAt = $coordinatorText.IndexOf(
        'if ($null -ne $script:d01PendingPktmonCleanupState)')
    $commitGuardMessageAt = $coordinatorText.IndexOf(
        "throw 'PktMon cleanup remains pending before adjudication commit'")
    $commitWriteAt = $coordinatorText.IndexOf(
        'Write-D01JsonAtomic -Value $commit -Path $commitPath')
    if ($commitGuardAt -lt 0 -or
        $commitGuardMessageAt -le $commitGuardAt -or
        $commitWriteAt -le $commitGuardMessageAt) {
        $issues.Add('COMMIT_PENDING_GUARD_NOT_BEFORE_COMMIT')
    }

    $topText = $Ast.Extent.Text
    $outerAt = $topText.IndexOf('$outerLedgerQuiescent =')
    $outerTerminateAt = if ($outerAt -ge 0) {
        $topText.IndexOf(
            'Test-D01TrustedCommandLedgerQuiescent -Terminate', $outerAt)
    } else { -1 }
    $outerPendingAt = if ($outerAt -ge 0) {
        $topText.IndexOf('if ($outerLedgerQuiescent -and', $outerAt)
    } else { -1 }
    $outerRetryAt = if ($outerPendingAt -ge 0) {
        $topText.IndexOf('Stop-D01PacketCapture `', $outerPendingAt)
    } else { -1 }
    $outerRecensusAt = if ($outerRetryAt -ge 0) {
        $topText.IndexOf('$outerLedgerQuiescent =', $outerRetryAt)
    } else { -1 }
    $outerIncompleteAt = if ($outerRecensusAt -ge 0) {
        $topText.IndexOf(
            "'V91-D01 BLOCKED: deferred PktMon cleanup remains incomplete'",
            $outerRecensusAt)
    } else { -1 }
    if ($outerAt -lt 0 -or $outerTerminateAt -lt $outerAt -or
        $outerPendingAt -le $outerTerminateAt -or
        $outerRetryAt -le $outerPendingAt -or
        $outerRecensusAt -le $outerRetryAt -or
        $outerIncompleteAt -le $outerRecensusAt) {
        $issues.Add('OUTER_RETRY_NOT_QUIESCENCE_GATED_AND_RECENSUSED')
    }

    if ([regex]::Matches(
            $topText, [regex]::Escape("Arguments @('reset')")).Count -ne 1) {
        $issues.Add('RESET_INVOCATION_CARDINALITY_NOT_ONE')
    }
    if ([regex]::Matches(
            $topText,
            [regex]::Escape("Arguments @('filter', 'remove')")).Count -ne 1) {
        $issues.Add('FILTER_REMOVE_INVOCATION_CARDINALITY_NOT_ONE')
    }
    $cleanupCalls = @($Ast.FindAll({
        param($node)
        $node -is [Management.Automation.Language.CommandAst] -and
            $node.GetCommandName() -ceq 'Stop-D01PacketCapture'
    }, $true))
    if ($cleanupCalls.Count -ne 2) {
        $issues.Add('CAPTURE_CLEANUP_CALL_CARDINALITY_NOT_TWO')
    }
    return [pscustomobject][ordered]@{
        valid = $issues.Count -eq 0
        issues = $issues.ToArray()
    }
}

function Get-D01OfflineMutatedHarnessAst {
    param(
        [Parameter(Mandatory = $true)][string]$Search,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Replacement
    )

    $count = [regex]::Matches(
        $script:HarnessText, [regex]::Escape($Search)).Count
    if ($count -ne 1) { throw 'MUTATION_ANCHOR_NOT_UNIQUE' }
    $mutated = $script:HarnessText.Replace($Search, $Replacement)
    $tokens = $null
    $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseInput(
        $mutated, [ref]$tokens, [ref]$errors)
    if (@($errors).Count -ne 0) { throw 'MUTATED_AST_NOT_PARSEABLE' }
    return $ast
}

function Assert-D01OfflineCleanupMutationRejected {
    param(
        [Parameter(Mandatory = $true)]
        [Management.Automation.Language.Ast]$Ast,
        [Parameter(Mandatory = $true)][string]$ExpectedIssue
    )

    $result = Get-D01OfflineCleanupContract -Ast $Ast
    Assert-D01Offline -Condition (
        -not [bool]$result.valid -and
        @($result.issues) -ccontains $ExpectedIssue) `
        -Code 'CLEANUP_MUTATION_WAS_NOT_REJECTED_EXACTLY'
}

try {
    New-Item -ItemType Directory -Path $script:TempRoot `
        -ErrorAction Stop | Out-Null

Invoke-D01OfflineTest -Id 'PARSER-HARNESS-SNAPSHOT-CLEAN' `
    -Category 'parser' -Body {
    Assert-D01Offline -Condition (
        @($script:HarnessParserErrors).Count -eq 0 -and
        $null -ne $script:HarnessAst) `
        -Code 'HARNESS_PARSER_ERROR'
}

Invoke-D01OfflineTest -Id 'PARSER-OFFLINE-SELF-CLEAN' `
    -Category 'parser' -Body {
    $tokens = $null
    $errors = $null
    [void][Management.Automation.Language.Parser]::ParseFile(
        $script:SelfPath, [ref]$tokens, [ref]$errors)
    Assert-D01Offline -Condition (@($errors).Count -eq 0) `
        -Code 'OFFLINE_SELF_PARSER_ERROR'
}

Invoke-D01OfflineTest -Id 'HARNESS-CASE-AND-EXCLUSIVE-SWITCH-STATIC' `
    -Category 'startup_contract' -Body {
    $parameters = @($script:HarnessAst.ParamBlock.Parameters)
    $names = @($parameters | ForEach-Object {
        $_.Name.VariablePath.UserPath
    })
    foreach ($required in @(
        'Role', 'PackagePath', 'PackageZipPath',
        'ExpectedPackageZipSha256', 'OutputRoot', 'Commit',
        'ExpectedEmuleSha256', 'Hostname',
        'SourcePublicIPv4', 'SourceLocalIPv4', 'SourceIPv6',
        'CoordinatorPublicIPv4', 'CoordinatorLocalIPv4',
        'CoordinatorIPv6', 'CoordinationRoot',
        'ExclusivePktmonDriverControlAcknowledged')) {
        Assert-D01Offline -Condition ($names -ccontains $required) `
            -Code 'HARNESS_REQUIRED_PARAMETER_MISSING'
    }
    $switch = @($parameters | Where-Object {
        $_.Name.VariablePath.UserPath -ceq
            'ExclusivePktmonDriverControlAcknowledged'
    })
    Assert-D01Offline -Condition (
        $switch.Count -eq 1 -and
        $switch[0].StaticType.FullName -ceq
            'System.Management.Automation.SwitchParameter') `
        -Code 'EXCLUSIVE_PKTMON_SWITCH_NOT_TYPED'
    $gateAt = $script:HarnessText.IndexOf(
        "if (`$Role -eq 'Coordinator' -and")
    $gateValueAt = $script:HarnessText.IndexOf(
        '-not $ExclusivePktmonDriverControlAcknowledged', $gateAt)
    $platformAt = $script:HarnessText.IndexOf(
        'if ([Environment]::OSVersion.Platform', $gateValueAt)
    Assert-D01Offline -Condition (
        $gateAt -ge 0 -and $gateValueAt -gt $gateAt -and
        $platformAt -gt $gateValueAt) `
        -Code 'EXCLUSIVE_PKTMON_COORDINATOR_GATE_NOT_PREPHYSICAL'
}

Invoke-D01OfflineTest -Id 'OFFLINE-NEVER-INVOKES-PHYSICAL-HARNESS' `
    -Category 'side_effect_guard' -Body {
    $tokens = $null
    $errors = $null
    $selfAst = [Management.Automation.Language.Parser]::ParseFile(
        $script:SelfPath, [ref]$tokens, [ref]$errors)
    $physicalCalls = @($selfAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.CommandAst] -and
        $node.GetCommandName() -cin @(
            'Invoke-D01CoordinatorRole', 'Invoke-D01SourceRole',
            'Start-D01PacketCapture', 'Stop-D01PacketCapture',
            'Invoke-D01Pktmon', 'Invoke-D01PktmonDriverStop',
            'Get-D01EtwLossEvidence', 'Add-Type', 'Start-Process',
            'powershell', 'powershell.exe', 'pwsh', 'pwsh.exe')
    }, $true))
    $harnessInvocations = @($selfAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.CommandAst] -and
        $node.InvocationOperator -ne
            [Management.Automation.Language.TokenKind]::Unknown -and
        $node.Extent.Text -match '(?i)Harness(Path|Text|Bytes)'
    }, $true))
    Assert-D01Offline -Condition (
        $physicalCalls.Count -eq 0 -and
        $harnessInvocations.Count -eq 0 -and
        $script:HarnessText.Length -gt 0) `
        -Code 'PHYSICAL_HARNESS_EXECUTION_PATH_FOUND'
}

Invoke-D01OfflineTest -Id 'HARNESS-SINGLE-BYTE-SNAPSHOT-STATIC' `
    -Category 'side_effect_guard' -Body {
    $selfText = [IO.File]::ReadAllText($script:SelfPath)
    Assert-D01Offline -Condition (
        ([regex]::Matches(
            $selfText, '\$script:HarnessBytes\s*=\s*' +
                '\[IO\.File\]::ReadAllBytes')).Count -eq 1 -and
        $selfText.Contains(
            '[Management.Automation.Language.Parser]::ParseInput') -and
        $selfText.Contains('HARNESS_BYTES_CHANGED_DURING_OFFLINE_RUN')) `
        -Code 'HARNESS_SINGLE_SNAPSHOT_OR_TOCTOU_GUARD_MISSING'
}

Invoke-D01OfflineTest -Id 'SNAPSHOT-WRITER-FINGERPRINT-CONTRACT-STATIC' `
    -Category 'immutable_counter_evidence' -Body {
    $writer = Get-D01OfflineFunctionAstFromAst `
        -Ast $script:HarnessAst -Name 'Write-D01JsonAtomic'
    $fingerprint = Get-D01OfflineFunctionAstFromAst `
        -Ast $script:HarnessAst `
        -Name 'Get-D01AtomicJsonSerializationFingerprint'
    $writerText = $writer.Extent.Text
    $fingerprintText = $fingerprint.Extent.Text
    Assert-D01Offline -Condition (
        $writerText.Contains(
            '[Text.UTF8Encoding]::new($false), 4096, $true') -and
        $writerText.Contains(
            '$writer.Write(($Value | ConvertTo-Json -Depth 48))') -and
        -not $writerText.Contains('$writer.WriteLine(') -and
        $fingerprintText.Contains(
            '$json = [string]($Value | ConvertTo-Json -Depth 48)') -and
        $fingerprintText.Contains(
            '$bytes = [Text.UTF8Encoding]::new($false).GetBytes($json)')) `
        -Code 'ATOMIC_WRITER_AND_FINGERPRINT_SERIALIZATION_DRIFT'
}

Invoke-D01OfflineTest -Id 'SNAPSHOT-FOUR-CALLS-BIND-EXPECTED-VALUE' `
    -Category 'immutable_counter_evidence' -Body {
    $calls = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.CommandAst] -and
            $node.GetCommandName() -ceq
                'Test-D01ImmutableCounterEvidenceSnapshot'
    }, $true))
    $texts = @($calls | ForEach-Object { $_.Extent.Text })
    Assert-D01Offline -Condition (
        $calls.Count -eq 4 -and
        @($texts | Where-Object {
            $_.Contains('-ExpectedValue $State.counter_loss')
        }).Count -eq 2 -and
        @($texts | Where-Object {
            $_.Contains('-ExpectedValue $State.counter_global_final')
        }).Count -eq 2 -and
        @($texts | Where-Object {
            -not $_.Contains('-ExpectedValue')
        }).Count -eq 0) `
        -Code 'IMMUTABLE_COUNTER_CALL_NOT_OBJECT_BOUND'
}

Invoke-D01OfflineTest -Id 'SNAPSHOT-CHAIN-RECHECKED-AT-PRECOMMIT' `
    -Category 'immutable_counter_evidence' -Body {
    $coordinator = Get-D01OfflineFunctionAstFromAst `
        -Ast $script:HarnessAst -Name 'Invoke-D01CoordinatorRole'
    $text = $coordinator.Extent.Text
    $chainAt = $text.LastIndexOf(
        'Test-D01PktmonGlobalCounterEvidenceChain -State $capture')
    $artifactAt = $text.LastIndexOf(
        "schema = 'ese.v91.d01-pktmon-precommit-state/v2'")
    $commitAt = $text.LastIndexOf(
        'Write-D01JsonAtomic -Value $commit -Path $commitPath')
    Assert-D01Offline -Condition (
        $chainAt -ge 0 -and $artifactAt -gt $chainAt -and
        $commitAt -gt $artifactAt -and
        $text.Contains(
            'drop_counter_final_snapshot = $capture.counter_loss_snapshot') -and
        $text.Contains(
            'global_counter_final_snapshot =') -and
        $text.Contains(
            'global_counter_chain_exact =') -and
        $text.Contains(
            '-ExpectedPktmonPrecommitSha256 $expectedPktmonPrecommitSha256')) `
        -Code 'PRECOMMIT_COUNTER_CHAIN_NOT_REBOUND'
}

$boundValue = [pscustomobject][ordered]@{
    schema = 'ese.v91.d01-offline-object/v1'
    counter = [pscustomobject][ordered]@{
        name = 'Ethernet'
        packets = [Int64]0
        exact = $true
    }
    rows = @('A', 'AAAA')
}
$boundJson = [string]($boundValue | ConvertTo-Json -Depth 48)
$boundBytes = [Text.UTF8Encoding]::new($false).GetBytes($boundJson)
$boundPath = Join-Path $script:TempRoot 'counter-object.json'
[IO.File]::WriteAllBytes($boundPath, $boundBytes)
$boundLock = [IO.File]::Open(
    $boundPath, [IO.FileMode]::Open, [IO.FileAccess]::Read,
    [IO.FileShare]::Read)
try {
    $boundFingerprint = Get-D01OfflineAtomicFingerprint -Value $boundValue
    $boundSnapshot = [pscustomobject][ordered]@{
        bytes = $null
        byte_count = [Int64]$boundBytes.Length
        sha256 = Get-D01OfflineBytesSha256 -Bytes $boundBytes
        immutable_read_lock_held = $true
    }

Invoke-D01OfflineTest -Id 'SNAPSHOT-OBJECT-BYTES-EXACT-POSITIVE' `
    -Category 'immutable_counter_evidence' -Body {
    Assert-D01Offline -Condition (
        $boundLock.CanRead -and
        [Int64]$boundFingerprint.byte_count -eq $boundBytes.Length -and
        [string]$boundFingerprint.sha256 -ceq
            [string]$boundSnapshot.sha256 -and
        (Test-D01OfflineImmutableSnapshot `
            -Snapshot $boundSnapshot -Path $boundPath `
            -ExpectedValue $boundValue)) `
        -Code 'EXACT_OBJECT_BYTES_BINDING_REJECTED'
}

Invoke-D01OfflineTest -Id 'SNAPSHOT-UTF8-NO-BOM-NO-TRAILING-NEWLINE' `
    -Category 'immutable_counter_evidence' -Body {
    $hasBom = $boundBytes.Length -ge 3 -and
        $boundBytes[0] -eq 0xef -and $boundBytes[1] -eq 0xbb -and
        $boundBytes[2] -eq 0xbf
    $last = $boundBytes[$boundBytes.Length - 1]
    Assert-D01Offline -Condition (
        -not $hasBom -and $last -ne 0x0a -and $last -ne 0x0d) `
        -Code 'ATOMIC_JSON_ENCODING_NOT_EXACT'
}

Invoke-D01OfflineTest -Id 'SNAPSHOT-MUTATED-OBJECT-REJECTED' `
    -Category 'immutable_counter_evidence' -Body {
    $mutated = Copy-D01OfflineObject -Value $boundValue
    $mutated.counter.packets = [Int64]1
    Assert-D01Offline -Condition (-not (
        Test-D01OfflineImmutableSnapshot `
            -Snapshot $boundSnapshot -Path $boundPath `
            -ExpectedValue $mutated)) `
        -Code 'MUTATED_OBJECT_ACCEPTED_FOR_FROZEN_BYTES'
}

$snapshotMutations = @(
    [pscustomobject]@{ id='BYTE-COUNT'; mutate={ param($v)
        $v.byte_count = [Int64]$v.byte_count + 1 } },
    [pscustomobject]@{ id='SHA256'; mutate={ param($v)
        $v.sha256 = '0' * 64 } },
    [pscustomobject]@{ id='LOCK'; mutate={ param($v)
        $v.immutable_read_lock_held = $false } },
    [pscustomobject]@{ id='BYTES-NONNULL'; mutate={ param($v)
        $v.bytes = [byte[]](1, 2, 3) } }
)
foreach ($mutation in $snapshotMutations) {
    $capturedMutation = $mutation
    Invoke-D01OfflineTest -Id (
        'SNAPSHOT-METADATA-' + $capturedMutation.id + '-REJECTED') `
        -Category 'immutable_counter_evidence' -Body {
        $value = Copy-D01OfflineObject -Value $boundSnapshot
        & $capturedMutation.mutate $value
        Assert-D01Offline -Condition (-not (
            Test-D01OfflineImmutableSnapshot `
                -Snapshot $value -Path $boundPath `
                -ExpectedValue $boundValue)) `
            -Code 'MUTATED_SNAPSHOT_METADATA_ACCEPTED'
    }
}
} finally { $boundLock.Dispose() }

$wrongPath = Join-Path $script:TempRoot 'wrong-counter-object.json'
[IO.File]::WriteAllBytes(
    $wrongPath, [Text.UTF8Encoding]::new($false).GetBytes('{}'))
Invoke-D01OfflineTest -Id 'SNAPSHOT-WRONG-FILE-BYTES-REJECTED' `
    -Category 'immutable_counter_evidence' -Body {
    Assert-D01Offline -Condition (-not (
        Test-D01OfflineImmutableSnapshot `
            -Snapshot $boundSnapshot -Path $wrongPath `
            -ExpectedValue $boundValue)) `
        -Code 'WRONG_FILE_BYTES_ACCEPTED'
}

Invoke-D01OfflineTest -Id 'ALL-COUNTER-DESCARTES-GUARDS-STATIC' `
    -Category 'counter_identity' -Body {
    $parser = Get-D01OfflineFunctionAstFromAst `
        -Ast $script:HarnessAst `
        -Name 'Get-D01PktmonAllCounterSnapshotEvidence'
    $assertion = Get-D01OfflineFunctionAstFromAst `
        -Ast $script:HarnessAst `
        -Name 'Assert-D01PktmonAllCounterSnapshotContract'
    Assert-D01Offline -Condition (
        $parser.Extent.Text.Contains(
            "if (`$counterType -ceq 'Descartes' -and") -and
        $parser.Extent.Text.Contains(
            '$counterName -cne $componentName') -and
        $assertion.Extent.Text.Contains(
            "([string]`$row.counter_type -ceq 'Descartes' -and") -and
        $assertion.Extent.Text.Contains(
            '[string]$row.counter_name -cne') -and
        $assertion.Extent.Text.Contains(
            '[string]$row.component_name')) `
        -Code 'DESCARTES_NAME_IDENTITY_GUARD_MISSING'
}

$validCounterStdout = New-D01OfflineAllCounterStdout
$validCounterEvidence = Get-D01OfflineAllCounterEvidence `
    -Stdout $validCounterStdout
Invoke-D01OfflineTest -Id 'ALL-COUNTER-VALID-DROP-AND-FLOW-POSITIVE' `
    -Category 'counter_identity' -Body {
    $dropRow = @($validCounterEvidence.snapshot_rows | Where-Object {
        [string]$_.counter_type -ceq 'Descartes'
    })
    $flowRow = @($validCounterEvidence.snapshot_rows | Where-Object {
        [string]$_.counter_type -ceq 'Flujos'
    })
    Assert-D01Offline -Condition (
        [bool]$validCounterEvidence.json_contract_valid -and
        [bool]$validCounterEvidence.proved_all_zero -and
        $dropRow.Count -eq 1 -and
        [string]$dropRow[0].counter_name -ceq
            [string]$dropRow[0].component_name -and
        $flowRow.Count -eq 1 -and
        [string]$flowRow[0].counter_name -cne
            [string]$flowRow[0].component_name -and
        (Assert-D01OfflineAllCounterEvidence `
            -Evidence $validCounterEvidence -RequireAllZero)) `
        -Code 'VALID_ALL_COUNTER_FIXTURE_REJECTED'
}

Invoke-D01OfflineTest -Id 'ALL-COUNTER-RESTORED-SELF-BASELINE' `
    -Category 'counter_identity' -Body {
    $restored = Get-D01OfflineAllCounterEvidence `
        -Stdout $validCounterStdout `
        -ExpectedBaseline $validCounterEvidence
    Assert-D01Offline -Condition (
        [bool]$restored.proved_restored -and
        [bool]$restored.snapshot_equal_to_baseline -and
        (Assert-D01OfflineAllCounterEvidence `
            -Evidence $restored -ExpectedBaseline $validCounterEvidence `
            -RequireAllZero -RequireRestored)) `
        -Code 'EXACT_COUNTER_RESTORATION_REJECTED'
}

foreach ($invalidDropName in @('Impossible', 'ethernet')) {
    $capturedDropName = $invalidDropName
    Invoke-D01OfflineTest -Id (
        'ALL-COUNTER-PARSER-DROP-NAME-' +
        $capturedDropName.ToUpperInvariant() + '-REJECTED') `
        -Category 'counter_identity' -Body {
        $value = Get-D01OfflineAllCounterEvidence -Stdout (
            New-D01OfflineAllCounterStdout -DropName $capturedDropName)
        $expectedError = Get-D01OfflineStringSha256 -Value (
            'PktMon all-counter drop counter name does not match its ' +
            'component name')
        Assert-D01Offline -Condition (
            -not [bool]$value.json_contract_valid -and
            [string]$value.error_sha256 -ceq $expectedError) `
            -Code 'IMPOSSIBLE_DROP_NAME_NOT_REJECTED_BY_PARSER'
    }
}

Invoke-D01OfflineTest -Id 'ALL-COUNTER-REVALIDATOR-DROP-NAME-REJECTED' `
    -Category 'counter_identity' -Body {
    $malicious = Copy-D01OfflineObject -Value $validCounterEvidence
    $row = @($malicious.snapshot_rows | Where-Object {
        [string]$_.counter_type -ceq 'Descartes'
    })[0]
    $row.counter_name = 'Impossible'
    $row.counter_key = '{0}\u001f{1}\u001f{2}\u001f{3}\u001f{4}' -f
        $row.group, $row.component_name, $row.component_id,
        $row.counter_name, $row.counter_type
    $malicious.counter_keys = @($malicious.snapshot_rows |
        ForEach-Object { [string]$_.counter_key } | Sort-Object -Unique)
    Assert-D01OfflineThrows -ExpectedMessage (
        'PktMon all-counter snapshot row identity is not exact') -Body {
        Assert-D01OfflineAllCounterEvidence `
            -Evidence $malicious -RequireAllZero
    }
}

Invoke-D01OfflineTest -Id 'CLEANUP-PENDING-RETRY-CONTRACT-POSITIVE' `
    -Category 'cleanup_contract' -Body {
    $result = Get-D01OfflineCleanupContract -Ast $script:HarnessAst
    Assert-D01Offline -Condition (
        [bool]$result.valid -and @($result.issues).Count -eq 0) `
        -Code 'CURRENT_CLEANUP_CONTRACT_NOT_EXACT'
}

$cleanupMutations = @(
    [pscustomobject]@{
        id = 'PENDING-STATE'
        search = '$script:d01PendingPktmonCleanupState = $state'
        replacement = '$null = $state'
        issue = 'PENDING_STATE_NOT_REGISTERED_BEFORE_MUTATION'
    },
    [pscustomobject]@{
        id = 'FAILURE-LEDGER'
        search = '$script:d01PendingPktmonCleanupFailures = $cleanupFailures'
        replacement = '$null = $cleanupFailures'
        issue = 'PENDING_FAILURE_LEDGER_NOT_BOUND_BEFORE_START'
    },
    [pscustomobject]@{
        id = 'OUTER-QUIESCENCE-GATE'
        search = 'if ($outerLedgerQuiescent -and'
        replacement = 'if ($true -and'
        issue = 'OUTER_RETRY_NOT_QUIESCENCE_GATED_AND_RECENSUSED'
    },
    [pscustomobject]@{
        id = 'COMMIT-GUARD'
        search = "throw 'PktMon cleanup remains pending before adjudication commit'"
        replacement = "throw 'mutated pending guard'"
        issue = 'COMMIT_PENDING_GUARD_NOT_BEFORE_COMMIT'
    },
    [pscustomobject]@{
        id = 'TERMINAL-REFERENCE-BINDING'
        search = '[object]::ReferenceEquals('
        replacement = '[object]::Equals('
        issue = 'PENDING_CLEAR_NOT_TERMINAL_AND_REFERENCE_BOUND'
    },
    [pscustomobject]@{
        id = 'RESET-CARDINALITY'
        search = "Arguments @('reset')"
        replacement = "Arguments @('counters')"
        issue = 'RESET_INVOCATION_CARDINALITY_NOT_ONE'
    }
)
foreach ($mutation in $cleanupMutations) {
    $capturedMutation = $mutation
    Invoke-D01OfflineTest -Id (
        'CLEANUP-MUTATION-' + $capturedMutation.id + '-REJECTED') `
        -Category 'cleanup_contract' -Body {
        $ast = Get-D01OfflineMutatedHarnessAst `
            -Search $capturedMutation.search `
            -Replacement $capturedMutation.replacement
        Assert-D01OfflineCleanupMutationRejected `
            -Ast $ast -ExpectedIssue $capturedMutation.issue
    }
}

Invoke-D01OfflineTest -Id 'CLEANUP-STATE-FIELDS-AND-CARDINALITY-STATIC' `
    -Category 'cleanup_contract' -Body {
    $start = Get-D01OfflineFunctionAstFromAst `
        -Ast $script:HarnessAst -Name 'Start-D01PacketCapture'
    $stop = Get-D01OfflineFunctionAstFromAst `
        -Ast $script:HarnessAst -Name 'Stop-D01PacketCapture'
    foreach ($needle in @(
        'cleanup_invocation_count = 0',
        'cleanup_entry_ledger_quiescent = $false',
        'cleanup_deferred_for_active_lease = $false',
        'cleanup_sequence_completed = $false')) {
        Assert-D01Offline -Condition ($start.Extent.Text.Contains($needle)) `
            -Code 'CLEANUP_STATE_FIELD_MISSING'
    }
    Assert-D01Offline -Condition (
        $stop.Extent.Text.Contains(
            '$State.cleanup_invocation_count =') -and
        $stop.Extent.Text.Contains(
            '$State.cleanup_entry_ledger_quiescent = $true') -and
        $stop.Extent.Text.Contains(
            '$State.cleanup_deferred_for_active_lease = $false')) `
        -Code 'CLEANUP_STATE_TRANSITION_MISSING'
}

Invoke-D01OfflineTest -Id 'AST-OFFLINE-SELF-SIDE-EFFECT-FREE' `
    -Category 'side_effect_guard' -Body {
    $tokens = $null
    $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile(
        $script:SelfPath, [ref]$tokens, [ref]$errors)
    Assert-D01Offline -Condition (@($errors).Count -eq 0) `
        -Code 'OFFLINE_SELF_PARSER_ERROR'
    Assert-D01AstNoExternalSideEffects -Ast $ast `
        -Code 'OFFLINE_SELF_EXTERNAL_SIDE_EFFECT_FOUND'
}

Invoke-D01OfflineTest -Id 'AST-PURE-ALLOWLIST-EXACT-AND-EXERCISED' `
    -Category 'side_effect_guard' -Body {
    foreach ($name in $script:PureFunctionAllowlist) {
        $matches = @($script:HarnessAst.FindAll({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] `
                -and $node.Name -ceq $name
        }, $true))
        Assert-D01Offline -Condition ($matches.Count -eq 1) `
            -Code 'PURE_ALLOWLIST_FUNCTION_NOT_EXACTLY_ONE'
        Assert-D01Offline -Condition (
            $script:ExtractedFunctionNames.Contains($name)) `
            -Code 'PURE_ALLOWLIST_FUNCTION_NOT_EXERCISED'
    }
    Assert-D01Offline -Condition (
        $script:ExtractedFunctionNames.Count -eq
            $script:PureFunctionAllowlist.Count) `
        -Code 'PURE_EXTRACTION_SET_NOT_EXACT'
}

Invoke-D01OfflineTest -Id 'AST-EXTRACTED-CLOSURE-SIDE-EFFECT-FREE' `
    -Category 'side_effect_guard' -Body {
    foreach ($name in @($script:ExtractedFunctionNames)) {
        $functionAst = Get-D01OfflineFunctionAstFromAst `
            -Ast $script:HarnessAst -Name $name
        Assert-D01AstNoExternalSideEffects -Ast $functionAst `
            -Code 'EXTRACTED_FUNCTION_EXTERNAL_SIDE_EFFECT_FOUND'
    }
}

} finally {
    if (Test-Path -LiteralPath $script:TempRoot) {
        Remove-Item -LiteralPath $script:TempRoot -Recurse -Force `
            -ErrorAction SilentlyContinue
    }
    $script:TempCleanupProven =
        -not (Test-Path -LiteralPath $script:TempRoot)
}

Invoke-D01OfflineTest -Id 'TEMP-FIXTURE-CLEANUP' `
    -Category 'side_effect_guard' -Body {
    Assert-D01Offline -Condition $script:TempCleanupProven `
        -Code 'TEMP_FIXTURE_CLEANUP_NOT_PROVEN'
}

Invoke-D01OfflineTest -Id 'HARNESS-BYTES-UNCHANGED-DURING-RUN' `
    -Category 'side_effect_guard' -Body {
    Assert-D01OfflineEqual `
        -Actual (Get-D01OfflineFileSha256 -Path $script:HarnessPath) `
        -Expected $script:HarnessInitialSha256 `
        -Code 'HARNESS_BYTES_CHANGED_DURING_OFFLINE_RUN'
}

$failed = @($script:Results | Where-Object status -ceq 'FAIL')
$canonicalLines = @($script:Results | Sort-Object id | ForEach-Object {
    '{0}|{1}|{2}|{3}|{4}|{5}' -f $_.id, $_.category, $_.status,
        $_.failure_type, $_.failure_id, $_.failure_sha256
}) -join "`n"
$summary = [pscustomobject][ordered]@{
    schema = 'ese.v91.d01-offline-selftest/v1'
    case_id = 'V91-D01'
    status = if ($failed.Count -eq 0) { 'PASS' } else { 'FAIL' }
    physical_execution_performed = $false
    formal_case_status = 'BLOCKED'
    test_count = $script:Results.Count
    pass_count = $script:Results.Count - $failed.Count
    fail_count = $failed.Count
    harness_sha256 = $script:HarnessInitialSha256
    result_sha256 = Get-D01OfflineStringSha256 -Value $canonicalLines
    tests = @($script:Results | Sort-Object id)
}
$summary | ConvertTo-Json -Depth 10
if ($failed.Count -ne 0) { exit 1 }
