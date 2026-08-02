[CmdletBinding()]
param(
    [string]$HarnessPath = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

if ([string]::IsNullOrWhiteSpace($HarnessPath)) {
    $HarnessPath = Join-Path $PSScriptRoot 'test_v91_i04_fallback.ps1'
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
    ('ese-v91-i04-offline-' + [Guid]::NewGuid().ToString('N'))
$script:TempCleanupProven = $false
$script:ExtractedFunctionNames =
    [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal)
$script:PureFunctionAllowlist = @(
    'Get-I04Sha256FromStream',
    'Get-I04StringSha256',
    'Assert-I04NoReparsePath',
    'Convert-I04SafeRelativePath',
    'Get-I04SafeTreeFiles',
    'Open-I04LockedFile',
    'Get-I04CandidateBinding',
    'Assert-I04CandidateBindingUnchanged',
    'Assert-I04DisjointOperationalPaths',
    'Assert-I04PreferenceContract',
    'Convert-I04RequiredAddress',
    'Get-I04StrictAddressClass',
    'Get-I04NormalizedIp',
    'Get-I04TupleKey',
    'Test-I04PktmonInventoryMetadataLine',
    'Get-I04PktmonInventoryCensus',
    'Test-I04PktmonArmedFilterContracts',
    'Get-I04SamplerClockValidation',
    'Get-I04SynPidCorrelation',
    'Read-I04UInt16LE',
    'Read-I04UInt16BE',
    'Read-I04UInt32LE',
    'Read-I04UInt32BE',
    'Convert-I04Packet',
    'Read-I04PcapNg',
    'Get-I04PartialVerdict',
    'Assert-I04ManagedTypeContract',
    'Assert-I04RestrictedJobAccountingContract',
    'Test-I04PeerTerminalContract',
    'Test-I04PacketFailureSourceContract',
    'Test-I04SocketFailureSourceContract',
    'Assert-I04ProductFailureContract',
    'Get-I04FailureDisposition',
    'Assert-I04ProjectionPropertySet',
    'Get-I04PublicSummaryProjection',
    'Get-I04SafeErrorToken',
    'Test-I04RegistrySubtreeSnapshotEqual',
    'ConvertTo-I04FirewallValueCanonical',
    'Get-I04FirewallCimCanonical',
    'Get-I04ProductLogCounts',
    'Convert-I04ValueSet',
    'Test-I04ValueSetEqual',
    'Get-I04RequiredJsonProperty',
    'Assert-I04ApiStatusContract',
    'Assert-I04ApiV9Contract',
    'Test-I04ApiIsolation'
)

function Get-I04OfflineStringSha256 {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value)

    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($Value)
        return ([BitConverter]::ToString($sha.ComputeHash($bytes))).
            Replace('-', '').ToLowerInvariant()
    } finally { $sha.Dispose() }
}

function Get-I04OfflineFileSha256 {
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

function Assert-I04Offline {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Code
    )

    if (-not $Condition) { throw $Code }
}

function Assert-I04OfflineEqual {
    param(
        [AllowNull()][object]$Actual,
        [AllowNull()][object]$Expected,
        [Parameter(Mandatory = $true)][string]$Code
    )

    if ([string]$Actual -cne [string]$Expected) { throw $Code }
}

function Assert-I04OfflineThrows {
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Body,
        [Parameter(Mandatory = $true)][string]$ExpectedCode
    )

    $caught = ''
    try { $null = & $Body } catch { $caught = [string]$_.Exception.Message }
    Assert-I04Offline -Condition ($caught.Contains($ExpectedCode)) `
        -Code 'EXPECTED_REJECTION_NOT_OBSERVED'
}

function Invoke-I04OfflineTest {
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
            failure_sha256 = Get-I04OfflineStringSha256 -Value $message
        })
    }
}

function Assert-I04AstNoExternalSideEffects {
    param(
        [Parameter(Mandatory = $true)]
        [Management.Automation.Language.Ast]$Ast,
        [Parameter(Mandatory = $true)][string]$Code
    )

    $forbiddenCommands = @(
        'Connect-PSSession', 'Disable-NetAdapter',
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
        'Get-Process', 'Invoke-Command', 'Invoke-Expression',
        'Invoke-RestMethod', 'Invoke-WebRequest', 'New-NetFirewallRule',
        'New-NetIPAddress', 'New-NetRoute', 'New-PSSession', 'netsh',
        'pktmon', 'pktmon.exe', 'logman', 'logman.exe', 'powershell',
        'powershell.exe', 'pwsh', 'pwsh.exe', 'reg', 'reg.exe',
        'Remove-NetFirewallRule', 'Remove-NetIPAddress', 'Remove-NetRoute',
        'Restart-NetAdapter', 'route', 'route.exe',
        'Set-DnsClientServerAddress', 'Set-NetAdapter',
        'Set-NetFirewallProfile', 'Set-NetFirewallRule',
        'Set-NetIPInterface', 'Set-NetRoute', 'Start-Job', 'Start-Process',
        'Stop-Process', 'Test-NetConnection'
    )
    $commands = @($Ast.FindAll({
        param($node)
        $node -is [Management.Automation.Language.CommandAst]
    }, $true) | ForEach-Object { $_.GetCommandName() } |
        Where-Object { $_ })
    Assert-I04Offline -Condition (@($commands | Where-Object {
                $forbiddenCommands -ccontains $_
            }).Count -eq 0) -Code $Code

    $forbiddenNewObject = @($Ast.FindAll({
        param($node)
        $node -is [Management.Automation.Language.CommandAst] -and
            $node.GetCommandName() -ceq 'New-Object' -and
            $node.Extent.Text -match
                '(?i)\bNet\.Sockets\.(TcpClient|TcpListener|UdpClient)\b'
    }, $true))
    Assert-I04Offline -Condition ($forbiddenNewObject.Count -eq 0) `
        -Code $Code
    $typeTexts = @($Ast.FindAll({
        param($node)
        $node -is [Management.Automation.Language.TypeExpressionAst]
    }, $true) | ForEach-Object { $_.TypeName.FullName })
    foreach ($pattern in @(
        '^Diagnostics\.Process$', '^Microsoft\.Win32\.Registry',
        '^Net\.Http\.',
        '^Net\.Sockets\.(TcpClient|TcpListener|UdpClient)$')) {
        Assert-I04Offline -Condition (@($typeTexts | Where-Object {
                    $_ -match $pattern
                }).Count -eq 0) -Code $Code
    }
}

function Get-I04HarnessFunctionAst {
    param([Parameter(Mandatory = $true)][string]$Name)

    Assert-I04Offline -Condition ($script:PureFunctionAllowlist -ccontains $Name) `
        -Code 'PURE_FUNCTION_NOT_ALLOWLISTED'
    $matches = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq $Name
    }, $true))
    Assert-I04Offline -Condition ($matches.Count -eq 1) `
        -Code 'PURE_FUNCTION_NOT_UNIQUE'
    Assert-I04AstNoExternalSideEffects -Ast $matches[0] `
        -Code 'PURE_FUNCTION_EXTERNAL_SIDE_EFFECT_FOUND_BEFORE_EXTRACTION'
    [void]$script:ExtractedFunctionNames.Add($Name)
    return $matches[0]
}

function Invoke-I04PureScope {
    param(
        [Parameter(Mandatory = $true)][string[]]$FunctionNames,
        [Parameter(Mandatory = $true)][scriptblock]$Body,
        [object[]]$ArgumentList = @()
    )

    $definitions = @($FunctionNames | ForEach-Object {
        (Get-I04HarnessFunctionAst -Name $_).Extent.Text
    }) -join "`r`n`r`n"
    $safeHelpers = @'
function Get-LabFullPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    return [IO.Path]::GetFullPath($Path)
}

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
function Open-I04ImmutableEvidenceSnapshot {
    param([Parameter(Mandatory = $true)][string]$Path)
    $bytes = [IO.File]::ReadAllBytes([IO.Path]::GetFullPath($Path))
    $memory = [IO.MemoryStream]::new($bytes, $false)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $digest = ([BitConverter]::ToString(
            $sha.ComputeHash($memory))).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
        $memory.Dispose()
    }
    return [pscustomobject][ordered]@{
        bytes = $bytes
        byte_count = [Int64]$bytes.Length
        sha256 = $digest
        immutable_read_lock_held = $true
    }
}
function Get-LabUtcTimestamp {
    return [DateTime]::UtcNow.ToString('o')
}
function Get-LabCandidateInfo {
    param(
        [Parameter(Mandatory = $true)][string]$PackagePath,
        [string]$ExpectedCommit = '',
        [switch]$AllowDirty
    )
    $package = (Resolve-Path -LiteralPath $PackagePath).Path
    $buildInfoPath = Join-Path $package 'BUILD_INFO.txt'
    $binaryPath = Join-Path $package 'emule.exe'
    if (-not (Test-Path -LiteralPath $buildInfoPath -PathType Leaf) -or
        -not (Test-Path -LiteralPath $binaryPath -PathType Leaf)) {
        throw 'OFFLINE_CANDIDATE_INFO_FILE_MISSING'
    }
    $values = @{}
    foreach ($line in Get-Content -LiteralPath $buildInfoPath) {
        if ($line -match '^\s*([^:]+):\s*(.*?)\s*$') {
            $values[$Matches[1].Trim().ToLowerInvariant()] =
                $Matches[2].Trim()
        }
    }
    $commit = [string]$values['commit']
    $release = [string]$values['release']
    $version = [string]$values['version']
    $dirty = [string]$values['dirty']
    if ($commit -notmatch '^[0-9a-fA-F]{40}$' -or
        [string]::IsNullOrWhiteSpace($version) -or
        ($dirty -ne 'false' -and -not $AllowDirty) -or
        ($ExpectedCommit -and $commit -ne $ExpectedCommit)) {
        throw 'OFFLINE_CANDIDATE_INFO_INVALID'
    }
    return [pscustomobject][ordered]@{
        package_path = $package
        release = $release
        version = $version
        commit = $commit.ToLowerInvariant()
        dirty = $dirty
        emule_sha256 = Get-LabSha256 -Path $binaryPath
        ese_server_sha256 = Get-LabSha256 -Path (
            Join-Path $package 'ese-server.exe')
        build_info_sha256 = Get-LabSha256 -Path $buildInfoPath
    }
}
'@
    return & {
        param($HelperText, $DefinitionText, $TestBody, $Arguments)
        . ([scriptblock]::Create($HelperText))
        . ([scriptblock]::Create($DefinitionText))
        & $TestBody @Arguments
    } $safeHelpers $definitions $Body $ArgumentList
}

function Get-I04HermeticPacketVerdictDefinition {
    $matches = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Get-I04PacketVerdict'
    }, $true))
    Assert-I04Offline -Condition ($matches.Count -eq 1) `
        -Code 'PACKET_VERDICT_FUNCTION_NOT_UNIQUE'
    $sourceAst = $matches[0]
    $netAdapterCalls = @($sourceAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.CommandAst] -and
            $node.GetCommandName() -ceq 'Get-NetAdapter'
    }, $true))
    $interfaceIdCalls = @($sourceAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.CommandAst] -and
            $node.GetCommandName() -ceq 'Get-LabInterfaceId'
    }, $true))
    Assert-I04Offline -Condition (
        $netAdapterCalls.Count -eq 1 -and
        $netAdapterCalls[0].Extent.Text -ceq
            'Get-NetAdapter -IncludeHidden -ErrorAction Stop' -and
        $interfaceIdCalls.Count -eq 1) `
        -Code 'PACKET_VERDICT_LIVE_ADAPTER_DEPENDENCY_NOT_EXACT'

    $definition = $sourceAst.Extent.Text
    $originalDeclaration = 'function Get-I04PacketVerdict {'
    Assert-I04Offline -Condition (
        ([regex]::Matches(
            $definition, [regex]::Escape($originalDeclaration))).Count -eq 1 -and
        ([regex]::Matches($definition, '\bGet-NetAdapter\b')).Count -eq 1 -and
        ([regex]::Matches($definition, '\bGet-LabInterfaceId\b')).Count -eq 1) `
        -Code 'PACKET_VERDICT_HERMETIC_REWRITE_COUNT_MISMATCH'
    $definition = $definition.Replace(
        $originalDeclaration, 'function Get-I04HermeticPacketVerdict {')
    $definition = $definition.Replace(
        'Get-NetAdapter', 'Get-I04OfflineAdapterInventory')
    $definition = $definition.Replace(
        'Get-LabInterfaceId', 'Get-I04OfflineLabInterfaceId')

    $tokens = $null
    $errors = $null
    $transformedAst = [Management.Automation.Language.Parser]::ParseInput(
        $definition, [ref]$tokens, [ref]$errors)
    Assert-I04Offline -Condition (@($errors).Count -eq 0) `
        -Code 'HERMETIC_PACKET_VERDICT_PARSER_ERROR'
    $transformedFunctions = @($transformedAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Get-I04HermeticPacketVerdict'
    }, $true))
    Assert-I04Offline -Condition (
        $transformedFunctions.Count -eq 1 -and
        -not $definition.Contains('Get-NetAdapter') -and
        -not $definition.Contains('Get-LabInterfaceId') -and
        $definition.Contains('Get-I04OfflineAdapterInventory') -and
        $definition.Contains('Get-I04OfflineLabInterfaceId')) `
        -Code 'PACKET_VERDICT_LIVE_DEPENDENCY_SURVIVED_REWRITE'
    Assert-I04AstNoExternalSideEffects -Ast $transformedFunctions[0] `
        -Code 'HERMETIC_PACKET_VERDICT_EXTERNAL_SIDE_EFFECT_FOUND'
    return $definition
}

function Invoke-I04HermeticPacketScope {
    param(
        [Parameter(Mandatory = $true)][string[]]$FunctionNames,
        [Parameter(Mandatory = $true)][object[]]$AdapterInventory,
        [Parameter(Mandatory = $true)][scriptblock]$Body,
        [object[]]$ArgumentList = @()
    )

    $definitions = @($FunctionNames | ForEach-Object {
        (Get-I04HarnessFunctionAst -Name $_).Extent.Text
    }) -join "`r`n`r`n"
    $packetDefinition = Get-I04HermeticPacketVerdictDefinition
    $mockDefinitions = @'
function Get-I04OfflineAdapterInventory {
    param(
        [switch]$IncludeHidden,
        [object]$ErrorAction
    )
    return @($script:i04OfflineAdapterInventory)
}
function Get-I04OfflineLabInterfaceId {
    param(
        [AllowEmptyString()][string]$Id = '',
        [AllowEmptyString()][string]$Name = '',
        [AllowEmptyString()][string]$Description = ''
    )
    return $Id
}
function Open-I04ImmutableEvidenceSnapshot {
    param([Parameter(Mandatory = $true)][string]$Path)
    $bytes = [IO.File]::ReadAllBytes([IO.Path]::GetFullPath($Path))
    $memory = [IO.MemoryStream]::new($bytes, $false)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $digest = ([BitConverter]::ToString(
            $sha.ComputeHash($memory))).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
        $memory.Dispose()
    }
    return [pscustomobject][ordered]@{
        bytes = $bytes
        byte_count = [Int64]$bytes.Length
        sha256 = $digest
        immutable_read_lock_held = $true
    }
}
'@
    return & {
        param(
            $DependencyText, $PacketText, $MockText,
            $Inventory, $TestBody, $Arguments)
        . ([scriptblock]::Create($DependencyText))
        . ([scriptblock]::Create($PacketText))
        . ([scriptblock]::Create($MockText))
        $script:i04OfflineAdapterInventory = @($Inventory)
        & $TestBody @Arguments
    } $definitions $packetDefinition $mockDefinitions `
        $AdapterInventory $Body $ArgumentList
}

function Assert-I04OfflineTempPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    $full = [IO.Path]::GetFullPath($Path)
    $prefix = [IO.Path]::GetFullPath($script:TempRoot).TrimEnd('\') + '\'
    Assert-I04Offline -Condition ($full.StartsWith(
            $prefix, [StringComparison]::OrdinalIgnoreCase)) `
        -Code 'OFFLINE_FIXTURE_OUTSIDE_TEMP_ROOT'
    return $full
}

function Convert-I04OfflineRequiredAddress {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)]
        [Net.Sockets.AddressFamily]$AddressFamily,
        [string]$Name = 'Address'
    )

    return Invoke-I04PureScope -FunctionNames @(
        'Convert-I04RequiredAddress') -Body {
        param($address, $family, $label)
        Convert-I04RequiredAddress -Value $address `
            -AddressFamily $family -Name $label
    } -ArgumentList @($Value, $AddressFamily, $Name)
}

function Get-I04OfflineStrictAddressClass {
    param([Parameter(Mandatory = $true)][string]$Address)

    return Invoke-I04PureScope -FunctionNames @(
        'Get-I04StrictAddressClass') -Body {
        param($value)
        Get-I04StrictAddressClass -Address $value
    } -ArgumentList @($Address)
}

function Convert-I04OfflineSafeRelativePath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [switch]$AllowTrailingSlash
    )

    return Invoke-I04PureScope -FunctionNames @(
        'Convert-I04SafeRelativePath') -Body {
        param($value, $allowDirectory)
        Convert-I04SafeRelativePath -Path $value `
            -AllowTrailingSlash:$allowDirectory
    } -ArgumentList @($Path, [bool]$AllowTrailingSlash)
}

function Get-I04OfflineSafeTreeFiles {
    param([Parameter(Mandatory = $true)][string]$Root)

    $safeRoot = Assert-I04OfflineTempPath -Path $Root
    return Invoke-I04PureScope -FunctionNames @(
        'Assert-I04NoReparsePath', 'Convert-I04SafeRelativePath',
        'Get-I04SafeTreeFiles') -Body {
        param($value)
        Get-I04SafeTreeFiles -Root $value
    } -ArgumentList @($safeRoot)
}

function Get-I04OfflineCandidateBinding {
    param(
        [Parameter(Mandatory = $true)][string]$DirectoryPath,
        [Parameter(Mandatory = $true)][string]$ZipPath,
        [Parameter(Mandatory = $true)][string]$ExpectedZipSha256,
        [Parameter(Mandatory = $true)][string]$ExpectedExeSha256,
        [string]$ExpectedCommit = ('a' * 40)
    )

    $safeDirectory = Assert-I04OfflineTempPath -Path $DirectoryPath
    $safeZip = Assert-I04OfflineTempPath -Path $ZipPath
    $context = [pscustomobject]@{
        directory = $safeDirectory
        zip = $safeZip
        zip_sha256 = $ExpectedZipSha256
        exe_sha256 = $ExpectedExeSha256
        commit = $ExpectedCommit
    }
    return Invoke-I04PureScope -FunctionNames @(
        'Get-I04Sha256FromStream', 'Get-I04StringSha256',
        'Assert-I04NoReparsePath', 'Convert-I04SafeRelativePath',
        'Get-I04SafeTreeFiles', 'Open-I04LockedFile',
        'Get-I04CandidateBinding') -Body {
        param($value)
        $script:i04CandidateLocks =
            [System.Collections.Generic.List[IO.Stream]]::new()
        try {
            Get-I04CandidateBinding -DirectoryPath $value.directory `
                -ZipPath $value.zip `
                -ExpectedZipSha256 $value.zip_sha256 `
                -ExpectedExeSha256 $value.exe_sha256 `
                -ExpectedCommit $value.commit
        } finally {
            foreach ($lock in @($script:i04CandidateLocks)) {
                if ($null -ne $lock) { $lock.Dispose() }
            }
            $script:i04CandidateLocks.Clear()
        }
    } -ArgumentList @($context)
}

function Test-I04OfflineCandidateBindingUnchanged {
    param([Parameter(Mandatory = $true)][object]$Binding)

    return Invoke-I04PureScope -FunctionNames @(
        'Get-I04Sha256FromStream', 'Get-I04StringSha256',
        'Assert-I04NoReparsePath', 'Convert-I04SafeRelativePath',
        'Get-I04SafeTreeFiles', 'Assert-I04CandidateBindingUnchanged') `
        -Body {
        param($value)
        Assert-I04CandidateBindingUnchanged -Binding $value
    } -ArgumentList @($Binding)
}

function Test-I04OfflineDisjointOperationalPaths {
    param(
        [Parameter(Mandatory = $true)][string]$RepositoryDirectory,
        [Parameter(Mandatory = $true)][string]$PackageDirectory,
        [Parameter(Mandatory = $true)][string]$PackageZip,
        [Parameter(Mandatory = $true)][string]$OutputDirectory,
        [Parameter(Mandatory = $true)][string]$CoordinationDirectory
    )

    return Invoke-I04PureScope -FunctionNames @(
        'Assert-I04DisjointOperationalPaths') -Body {
        param($repository, $package, $zip, $output, $coordination)
        Assert-I04DisjointOperationalPaths `
            -RepositoryDirectory $repository `
            -PackageDirectory $package -PackageZip $zip `
            -OutputDirectory $output `
            -CoordinationDirectory $coordination
    } -ArgumentList @(
        $RepositoryDirectory, $PackageDirectory, $PackageZip,
        $OutputDirectory, $CoordinationDirectory)
}

function Get-I04OfflinePreferenceContract {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][object[]]$Contract
    )

    $safePath = Assert-I04OfflineTempPath -Path $Path
    $context = [pscustomobject]@{
        path = $safePath
        contract = @($Contract)
    }
    return Invoke-I04PureScope -FunctionNames @(
        'Get-I04Sha256FromStream', 'Get-I04StringSha256',
        'Assert-I04PreferenceContract') -Body {
        param($value)
        Assert-I04PreferenceContract -Path $value.path `
            -Contract @($value.contract)
    } -ArgumentList @($context)
}

function Test-I04OfflineRegistrySubtreeSnapshotEqual {
    param(
        [Parameter(Mandatory = $true)][object]$Left,
        [Parameter(Mandatory = $true)][object]$Right
    )

    return Invoke-I04PureScope -FunctionNames @(
        'Test-I04RegistrySubtreeSnapshotEqual') -Body {
        param($before, $after)
        Test-I04RegistrySubtreeSnapshotEqual -Left $before -Right $after
    } -ArgumentList @($Left, $Right)
}

function Get-I04OfflinePreexistingEmuleGateDefinition {
    $inventoryAssignments = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.AssignmentStatementAst] -and
            $node.Left.Extent.Text -ceq '$preexistingEmuleProcesses'
    }, $true))
    $countAssignments = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.AssignmentStatementAst] -and
            $node.Left.Extent.Text -ceq '$preexistingEmuleProcessCount'
    }, $true))
    $candidateAssignments = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.AssignmentStatementAst] -and
            $node.Left.Extent.Text -ceq '$candidate'
    }, $true))
    $gates = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.IfStatementAst] -and
            $node.Extent.Text.Contains(
                '$preexistingEmuleProcesses.Count -ne 0') -and
            $node.Extent.Text.Contains(
                'I04 requires zero pre-existing eMule processes')
    }, $true))
    Assert-I04Offline -Condition (
        $inventoryAssignments.Count -eq 1 -and
        $countAssignments.Count -eq 1 -and $gates.Count -eq 1 -and
        $candidateAssignments.Count -eq 1) `
        -Code 'PREEXISTING_EMULE_GATE_NOT_UNIQUE'
    $inventoryAssignment = $inventoryAssignments[0]
    $countAssignment = $countAssignments[0]
    $gate = $gates[0]
    $candidateAssignment = $candidateAssignments[0]
    $processCalls = @($inventoryAssignment.FindAll({
        param($node)
        $node -is [Management.Automation.Language.CommandAst] -and
            $node.GetCommandName() -ceq 'Get-Process'
    }, $true))
    Assert-I04Offline -Condition (
        $processCalls.Count -eq 1 -and
        $processCalls[0].Extent.Text -ceq 'Get-Process -ErrorAction Stop' -and
        $inventoryAssignment.Extent.Text.Contains(
            "[string]`$_.ProcessName -ieq 'emule'") -and
        $countAssignment.Extent.Text -ceq
            '$preexistingEmuleProcessCount = 0' -and
        $inventoryAssignment.Extent.EndOffset -lt $gate.Extent.StartOffset -and
        $gate.Extent.EndOffset -lt $countAssignment.Extent.StartOffset -and
        $countAssignment.Extent.EndOffset -lt
            $candidateAssignment.Extent.StartOffset) `
        -Code 'PREEXISTING_EMULE_GATE_NOT_FAIL_CLOSED_OR_PRE_MUTATION'

    $fragment = @(
        $inventoryAssignment.Extent.Text,
        $gate.Extent.Text,
        $countAssignment.Extent.Text
    ) -join "`r`n"
    Assert-I04Offline -Condition (
        ([regex]::Matches($fragment, '\bGet-Process\b')).Count -eq 1) `
        -Code 'PREEXISTING_EMULE_HERMETIC_REWRITE_COUNT_MISMATCH'
    $fragment = $fragment.Replace(
        'Get-Process', 'Get-I04OfflineProcessInventory')
    $tokens = $null
    $errors = $null
    $fragmentAst = [Management.Automation.Language.Parser]::ParseInput(
        $fragment, [ref]$tokens, [ref]$errors)
    Assert-I04Offline -Condition (
        @($errors).Count -eq 0 -and
        -not $fragment.Contains('Get-Process') -and
        $fragment.Contains('Get-I04OfflineProcessInventory')) `
        -Code 'PREEXISTING_EMULE_HERMETIC_REWRITE_INVALID'
    Assert-I04AstNoExternalSideEffects -Ast $fragmentAst `
        -Code 'PREEXISTING_EMULE_HERMETIC_SIDE_EFFECT_FOUND'
    return $fragment
}

function Invoke-I04OfflinePreexistingEmuleGate {
    param(
        [AllowEmptyCollection()][object[]]$ProcessInventory = @(),
        [switch]$CollectorFailure
    )

    $fragment = Get-I04OfflinePreexistingEmuleGateDefinition
    $mock = @'
function Get-I04OfflineProcessInventory {
    param([object]$ErrorAction)
    if ($script:i04OfflineProcessCollectorFailure) {
        throw 'OFFLINE_PROCESS_COLLECTOR_FAILED'
    }
    return @($script:i04OfflineProcessInventory)
}
'@
    return & {
        param($FragmentText, $MockText, $Inventory, $FailCollector)
        . ([scriptblock]::Create($MockText))
        $script:i04OfflineProcessInventory = @($Inventory)
        $script:i04OfflineProcessCollectorFailure = [bool]$FailCollector
        . ([scriptblock]::Create($FragmentText))
        return [int]$preexistingEmuleProcessCount
    } $fragment $mock $ProcessInventory ([bool]$CollectorFailure)
}

function Get-I04HermeticRegistryTransactionDefinitions {
    $startMatches = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Start-I04AccountRegistryTransaction'
    }, $true))
    $postMatches = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Get-I04AccountRegistryPostcheckEvidence'
    }, $true))
    Assert-I04Offline -Condition (
        $startMatches.Count -eq 1 -and $postMatches.Count -eq 1) `
        -Code 'REGISTRY_TRANSACTION_FUNCTION_NOT_UNIQUE'
    $startText = $startMatches[0].Extent.Text
    $postText = $postMatches[0].Extent.Text
    Assert-I04Offline -Condition (
        $startText.Contains('-not [bool]$baseline.run_subtree.exists') -and
        $postText.Contains('[bool]$Transaction.baseline.run_subtree.exists') -and
        $postText.Contains('[bool]$after.run_subtree.exists') -and
        $postText.Contains(
            'run_subtree_existed_before =') -and
        $postText.Contains('run_subtree_exists_after =')) `
        -Code 'REGISTRY_RUN_EXISTENCE_GATE_MISSING'

    $startText = $startText.Replace(
        'function Start-I04AccountRegistryTransaction {',
        'function Start-I04HermeticAccountRegistryTransaction {').Replace(
        'Get-I04AccountRegistrySnapshot',
        'Get-I04OfflineAccountRegistrySnapshot').Replace(
        'Get-I04GlobalFirewallSnapshot',
        'Get-I04OfflineGlobalFirewallSnapshot')
    $postText = $postText.Replace(
        'function Get-I04AccountRegistryPostcheckEvidence {',
        'function Get-I04HermeticAccountRegistryPostcheckEvidence {').Replace(
        'Get-I04AccountRegistrySnapshot',
        'Get-I04OfflineAccountRegistrySnapshot').Replace(
        'Get-I04GlobalFirewallSnapshot',
        'Get-I04OfflineGlobalFirewallSnapshot')
    $definitions = $startText + "`r`n`r`n" + $postText
    Assert-I04Offline -Condition (
        -not $definitions.Contains('Get-I04AccountRegistrySnapshot') -and
        -not $definitions.Contains('Get-I04GlobalFirewallSnapshot') -and
        ([regex]::Matches(
            $definitions, '\bGet-I04OfflineAccountRegistrySnapshot\b')).Count `
            -eq 2 -and
        ([regex]::Matches(
            $definitions, '\bGet-I04OfflineGlobalFirewallSnapshot\b')).Count `
            -eq 2) -Code 'REGISTRY_HERMETIC_REWRITE_COUNT_MISMATCH'
    $tokens = $null
    $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseInput(
        $definitions, [ref]$tokens, [ref]$errors)
    Assert-I04Offline -Condition (@($errors).Count -eq 0) `
        -Code 'REGISTRY_HERMETIC_PARSER_ERROR'
    Assert-I04AstNoExternalSideEffects -Ast $ast `
        -Code 'REGISTRY_HERMETIC_SIDE_EFFECT_FOUND'
    return $definitions
}

function Invoke-I04HermeticRegistryTransactionScope {
    param(
        [Parameter(Mandatory = $true)]$RegistrySnapshot,
        [Parameter(Mandatory = $true)]$FirewallSnapshot,
        [Parameter(Mandatory = $true)][scriptblock]$Body,
        [object[]]$ArgumentList = @(),
        [switch]$RegistryCollectorFailure,
        [switch]$FirewallCollectorFailure
    )

    $dependencyDefinitions = @(
        (Get-I04HarnessFunctionAst -Name 'Get-I04StringSha256').Extent.Text,
        (Get-I04HarnessFunctionAst `
            -Name 'Test-I04RegistrySubtreeSnapshotEqual').Extent.Text,
        (Get-I04HarnessFunctionAst -Name 'Get-I04SafeErrorToken').Extent.Text
    ) -join "`r`n`r`n"
    $transactionDefinitions = Get-I04HermeticRegistryTransactionDefinitions
    $mockDefinitions = @'
function Get-I04OfflineAccountRegistrySnapshot {
    param([string]$ExpectedUserSidSha256)
    if ($script:i04OfflineRegistryCollectorFailure) {
        throw 'OFFLINE_REGISTRY_COLLECTOR_FAILED'
    }
    return $script:i04OfflineRegistrySnapshot
}
function Get-I04OfflineGlobalFirewallSnapshot {
    if ($script:i04OfflineFirewallCollectorFailure) {
        throw 'OFFLINE_FIREWALL_COLLECTOR_FAILED'
    }
    return $script:i04OfflineFirewallSnapshot
}
'@
    return & {
        param(
            $DependencyText, $TransactionText, $MockText,
            $RegistryState, $FirewallState, $RegistryFail,
            $FirewallFail, $TestBody, $Arguments)
        . ([scriptblock]::Create($DependencyText))
        . ([scriptblock]::Create($TransactionText))
        . ([scriptblock]::Create($MockText))
        $script:i04OfflineRegistrySnapshot = $RegistryState
        $script:i04OfflineFirewallSnapshot = $FirewallState
        $script:i04OfflineRegistryCollectorFailure = [bool]$RegistryFail
        $script:i04OfflineFirewallCollectorFailure = [bool]$FirewallFail
        & $TestBody @Arguments
    } $dependencyDefinitions $transactionDefinitions $mockDefinitions `
        $RegistrySnapshot $FirewallSnapshot `
        ([bool]$RegistryCollectorFailure) ([bool]$FirewallCollectorFailure) `
        $Body $ArgumentList
}

function Start-I04OfflineRegistryTransaction {
    param(
        [Parameter(Mandatory = $true)]$Baseline,
        [Parameter(Mandatory = $true)]$FirewallBaseline,
        [Parameter(Mandatory = $true)][string]$ExpectedUserSidSha256
    )
    return Invoke-I04HermeticRegistryTransactionScope `
        -RegistrySnapshot $Baseline -FirewallSnapshot $FirewallBaseline `
        -Body {
        param($sidHash)
        Start-I04HermeticAccountRegistryTransaction `
            -ExpectedUserSidSha256 $sidHash
    } -ArgumentList @($ExpectedUserSidSha256)
}

function Get-I04OfflineRegistryPostcheckEvidence {
    param(
        [Parameter(Mandatory = $true)]$Transaction,
        [Parameter(Mandatory = $true)]$After,
        [Parameter(Mandatory = $true)]$FirewallAfter
    )
    return Invoke-I04HermeticRegistryTransactionScope `
        -RegistrySnapshot $After -FirewallSnapshot $FirewallAfter `
        -Body {
        param($value)
        Get-I04HermeticAccountRegistryPostcheckEvidence -Transaction $value
    } -ArgumentList @($Transaction)
}

function New-I04OfflineAccountRegistrySnapshot {
    param(
        [Parameter(Mandatory = $true)][string]$UserSidSha256,
        [bool]$RunExists = $true,
        [bool]$EmuleAutoStartAbsent = $true,
        [bool]$Ed2kSubtreeAbsent = $true
    )
    $run = [pscustomobject][ordered]@{
        schema = 'ese.v91.i04-registry-subtree/v2'
        path_sha256 = '1' * 64
        exists = $RunExists
        node_count = if ($RunExists) { 1 } else { 0 }
        value_count = 0
        tracked_root_value_count = if ($EmuleAutoStartAbsent) { 0 } else { 1 }
        canonical_sha256 = '2' * 64
    }
    $ed2k = [pscustomobject][ordered]@{
        schema = 'ese.v91.i04-registry-subtree/v2'
        path_sha256 = '3' * 64
        exists = -not $Ed2kSubtreeAbsent
        node_count = if ($Ed2kSubtreeAbsent) { 0 } else { 1 }
        value_count = 0
        tracked_root_value_count = 0
        canonical_sha256 = '4' * 64
    }
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.i04-account-registry-snapshot/v2'
        captured_at_utc = '2026-08-01T00:00:00.0000000+00:00'
        user_sid_sha256 = $UserSidSha256
        run_subtree = $run
        ed2k_subtree = $ed2k
        emule_autostart_absent = $EmuleAutoStartAbsent
        ed2k_subtree_absent = $Ed2kSubtreeAbsent
    }
}

function Test-I04OfflineManagedTypeContract {
    param(
        [Parameter(Mandatory = $true)][string]$TypeName,
        [Parameter(Mandatory = $true)][string]$ExpectedContractId
    )
    return Invoke-I04PureScope -FunctionNames @(
        'Assert-I04ManagedTypeContract') -Body {
        param($name, $contract)
        Assert-I04ManagedTypeContract `
            -TypeName $name -ExpectedContractId $contract
    } -ArgumentList @($TypeName, $ExpectedContractId)
}

function New-I04OfflineHarnessBundle {
    param(
        [string]$Schema = 'ese.v91.i04-harness-bundle/v1',
        [string]$BundleSha256 = ('1' * 64),
        [string]$HarnessSha256 = ('2' * 64),
        [string]$CommonSha256 = ('3' * 64),
        [string]$PrepareNodeSha256 = ('4' * 64),
        [object]$ImmutableReadLocksHeld = $true
    )
    return [pscustomobject][ordered]@{
        schema = $Schema
        harness_sha256 = $HarnessSha256
        common_sha256 = $CommonSha256
        prepare_node_sha256 = $PrepareNodeSha256
        bundle_sha256 = $BundleSha256
        immutable_read_locks_held = $ImmutableReadLocksHeld
    }
}

function Test-I04OfflineHarnessBundleEqual {
    param(
        [Parameter(Mandatory = $true)]$Actual,
        [Parameter(Mandatory = $true)]$Expected
    )
    $required = @(
        'schema', 'harness_sha256', 'common_sha256',
        'prepare_node_sha256', 'bundle_sha256',
        'immutable_read_locks_held'
    )
    $actualNames = @($Actual.PSObject.Properties.Name)
    if ($actualNames.Count -ne $required.Count -or
        @($required | Where-Object { $actualNames -cnotcontains $_ }).Count `
            -ne 0) {
        return $false
    }
    if ([string]$Actual.schema -cne 'ese.v91.i04-harness-bundle/v1' -or
        $Actual.immutable_read_locks_held -isnot [bool] -or
        -not [bool]$Actual.immutable_read_locks_held) {
        return $false
    }
    foreach ($name in @(
        'harness_sha256', 'common_sha256',
        'prepare_node_sha256', 'bundle_sha256')) {
        if ([string]$Actual.$name -cnotmatch '^[0-9a-f]{64}$' -or
            [string]$Actual.$name -cne [string]$Expected.$name) {
            return $false
        }
    }
    return $true
}

function Test-I04OfflinePktmonArmedFilterContracts {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text,
        [Parameter(Mandatory = $true)][string]$FilterV4,
        [Parameter(Mandatory = $true)][string]$FilterV6,
        [Parameter(Mandatory = $true)][string]$FilterIcmpV6,
        [Parameter(Mandatory = $true)][string]$IPv4,
        [Parameter(Mandatory = $true)][string]$IPv6,
        [Parameter(Mandatory = $true)][int]$Port
    )
    return Invoke-I04PureScope -FunctionNames @(
        'Get-I04Sha256FromStream', 'Get-I04StringSha256',
        'Test-I04PktmonInventoryMetadataLine',
        'Get-I04PktmonInventoryCensus',
        'Test-I04PktmonArmedFilterContracts') -Body {
        param($text, $v4Name, $v6Name, $icmpName, $v4, $v6, $port)
        Test-I04PktmonArmedFilterContracts -Text $text `
            -FilterV4 $v4Name -FilterV6 $v6Name `
            -FilterIcmpV6 $icmpName -IPv4 $v4 -IPv6 $v6 -Port $port
    } -ArgumentList @(
        $Text, $FilterV4, $FilterV6, $FilterIcmpV6,
        $IPv4, $IPv6, $Port)
}

function Get-I04OfflinePktmonInventoryCensus {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()][string]$Text
    )
    return Invoke-I04PureScope -FunctionNames @(
        'Get-I04Sha256FromStream', 'Get-I04StringSha256',
        'Test-I04PktmonInventoryMetadataLine',
        'Get-I04PktmonInventoryCensus') -Body {
        param($value)
        Get-I04PktmonInventoryCensus -Text $value
    } -ArgumentList @($Text)
}

function Get-I04OfflineImmutableEvidenceSnapshot {
    param([Parameter(Mandatory = $true)][string]$Path)

    $safePath = Assert-I04OfflineTempPath -Path $Path
    $snapshotFunctions = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Open-I04ImmutableEvidenceSnapshot'
    }, $true))
    Assert-I04Offline -Condition ($snapshotFunctions.Count -eq 1) `
        -Code 'IMMUTABLE_EVIDENCE_SNAPSHOT_FUNCTION_NOT_UNIQUE'
    $snapshotText = $snapshotFunctions[0].Extent.Text
    foreach ($needle in @(
        'Assert-I04NoReparsePath -Path $Path -Kind File',
        '[IO.FileAccess]::Read', '[IO.FileShare]::Read',
        'Get-I04Sha256FromStream -Stream $memory',
        '$script:i04EvidenceLocks.Add($stream)',
        'byte_count = [Int64]$bytes.Length',
        'sha256 = $sha256', 'immutable_read_lock_held = $true')) {
        Assert-I04Offline -Condition ($snapshotText.Contains($needle)) `
            -Code 'IMMUTABLE_EVIDENCE_SNAPSHOT_CONTRACT_MISSING'
    }
    Assert-I04AstNoExternalSideEffects -Ast $snapshotFunctions[0] `
        -Code 'IMMUTABLE_EVIDENCE_SNAPSHOT_FORBIDDEN_COMMAND_FOUND'
    $dependencyText = @(
        (Get-I04HarnessFunctionAst -Name 'Get-I04Sha256FromStream').Extent.Text,
        (Get-I04HarnessFunctionAst -Name 'Assert-I04NoReparsePath').Extent.Text
    ) -join "`r`n`r`n"
    return & {
        param($Dependencies, $SnapshotDefinition, $SnapshotPath)
        . ([scriptblock]::Create($Dependencies))
        . ([scriptblock]::Create($SnapshotDefinition))
        $script:i04EvidenceLocks =
            [System.Collections.Generic.List[IDisposable]]::new()
        try {
            $snapshot = Open-I04ImmutableEvidenceSnapshot -Path $SnapshotPath
            $writeOpenBlocked = $false
            $writeProbe = $null
            try {
                $writeProbe = [IO.File]::Open(
                    $SnapshotPath, [IO.FileMode]::Open,
                    [IO.FileAccess]::Write, [IO.FileShare]::ReadWrite)
            } catch {
                $writeOpenBlocked = $true
            } finally {
                if ($null -ne $writeProbe) { $writeProbe.Dispose() }
            }
            return [pscustomobject][ordered]@{
                bytes = [byte[]]$snapshot.bytes
                byte_count = [Int64]$snapshot.byte_count
                sha256 = [string]$snapshot.sha256
                immutable_read_lock_held =
                    [bool]$snapshot.immutable_read_lock_held
                write_open_blocked_while_snapshot_live = $writeOpenBlocked
                retained_lock_count = $script:i04EvidenceLocks.Count
            }
        } finally {
            foreach ($lock in @($script:i04EvidenceLocks.ToArray())) {
                try { $lock.Dispose() } catch {}
            }
            $script:i04EvidenceLocks.Clear()
        }
    } $dependencyText $snapshotText $safePath
}

function New-I04OfflineGlobalFirewallScenarioSnapshot {
    param(
        [string]$Schema = 'ese.v91.i04-global-firewall-snapshot/v2',
        [object]$PrivacySafe = $true,
        [string]$CanonicalSha256 = ('a' * 64)
    )
    return [pscustomobject][ordered]@{
        schema = $Schema
        privacy_safe = $PrivacySafe
        canonical_sha256 = $CanonicalSha256
    }
}

function Test-I04OfflineFirewallScenarioSnapshotsEqual {
    param(
        [Parameter(Mandatory = $true)]$Before,
        [Parameter(Mandatory = $true)]$After
    )
    foreach ($snapshot in @($Before, $After)) {
        $names = @($snapshot.PSObject.Properties.Name)
        if ($names -cnotcontains 'schema' -or
            $names -cnotcontains 'privacy_safe' -or
            $names -cnotcontains 'canonical_sha256' -or
            [string]$snapshot.schema -cne
                'ese.v91.i04-global-firewall-snapshot/v2' -or
            $snapshot.privacy_safe -isnot [bool] -or
            -not [bool]$snapshot.privacy_safe -or
            [string]$snapshot.canonical_sha256 -cnotmatch
                '^[0-9a-f]{64}$') {
            return $false
        }
    }
    return [string]$Before.canonical_sha256 -ceq
        [string]$After.canonical_sha256
}

function Test-I04OfflineFiniteNumber {
    param(
        [AllowNull()][object]$Value,
        [switch]$Integer
    )
    if ($Value -isnot [ValueType] -or $Value -is [bool]) {
        return $false
    }
    try { $number = [double]$Value } catch { return $false }
    if ([double]::IsNaN($number) -or [double]::IsInfinity($number)) {
        return $false
    }
    return -not $Integer -or $number -eq [Math]::Truncate($number)
}

function Test-I04OfflineSnapshotFailureSourceContract {
    param(
        [ValidateSet('packet_verdict', 'socket_sampler')][string]$Kind,
        [Parameter(Mandatory = $true)]$Evidence,
        [int]$CandidateProcessId = 4242,
        [double]$BoundaryEpochMs = 1000000,
        [ValidateSet(
            'ipv6_syn_missing', 'fallback_window', 'ipv4_connectivity',
            'transport_attempt_count', 'observation_window',
            'socket_contract')]
        [string]$FailureType = 'fallback_window'
    )
    $expectedKind = if ($FailureType -ceq 'socket_contract') {
        'socket_sampler'
    } else { 'packet_verdict' }
    if ($Kind -cne $expectedKind) {
        return $false
    }
    if ($Kind -ceq 'packet_verdict') {
        return Invoke-I04PureScope -FunctionNames @(
            'Test-I04PacketFailureSourceContract') -Body {
            param($value, $expectedProcessId, $boundary)
            Test-I04PacketFailureSourceContract -Evidence $value `
                -ExpectedProcessId $expectedProcessId `
                -ExpectedBoundaryEpochMs $boundary
        } -ArgumentList @($Evidence, $CandidateProcessId, $BoundaryEpochMs)
    }
    return Invoke-I04PureScope -FunctionNames @(
        'Test-I04SocketFailureSourceContract') -Body {
        param($value, $expectedProcessId, $boundary)
        Test-I04SocketFailureSourceContract -Evidence $value `
            -ExpectedProcessId $expectedProcessId `
            -ExpectedBoundaryEpochMs $boundary
    } -ArgumentList @($Evidence, $CandidateProcessId, $BoundaryEpochMs)
}

function Test-I04OfflinePeerTerminalContract {
    param(
        [Parameter(Mandatory = $true)][object]$Terminal,
        [Parameter(Mandatory = $true)][string]$ExpectedCaseId,
        [Parameter(Mandatory = $true)][string]$ExpectedRunNonce,
        [Parameter(Mandatory = $true)][string]$ExpectedPeerResultSha256
    )

    return Invoke-I04PureScope -FunctionNames @(
        'Test-I04PeerTerminalContract') -Body {
        param($value, $caseId, $nonce, $resultSha256)
        Test-I04PeerTerminalContract -Terminal $value `
            -ExpectedCaseId $caseId -ExpectedRunNonce $nonce `
            -ExpectedPeerResultSha256 $resultSha256
    } -ArgumentList @(
        $Terminal, $ExpectedCaseId, $ExpectedRunNonce,
        $ExpectedPeerResultSha256
    )
}

function Test-I04OfflineCoordinatorTerminalPublicationOrder {
    param(
        [Parameter(Mandatory = $true)][string]$CoordinatorRoleText,
        [Parameter(Mandatory = $true)][string]$OuterFinallyText,
        [Parameter(Mandatory = $true)][string]$FinalizerText
    )

    $summaryWrite =
        'Write-LabJson -Value $publication.summary'
    $publicProjection =
        'Get-I04PublicSummaryProjection'
    $publicWrite =
        'Write-LabJson -Value $publicProjection'
    $receiptSchema =
        "schema = 'ese.v91.i04-coordinator-terminal/v1'"
    $receiptWrite =
        '}) -Path ([string]$publication.terminal_receipt_path)'
    $passWrite =
        '"V91-I04 PASS on exact candidate/$($publication.observed_topology): "'
    $summaryAt = $FinalizerText.IndexOf($summaryWrite)
    $projectionAt = $FinalizerText.IndexOf($publicProjection)
    $publicAt = $FinalizerText.IndexOf($publicWrite)
    $receiptSchemaAt = $FinalizerText.IndexOf($receiptSchema)
    $receiptAt = $FinalizerText.IndexOf($receiptWrite)
    $passAt = $FinalizerText.IndexOf($passWrite)
    return $CoordinatorRoleText.Contains(
            '$script:i04CoordinatorPublication =') -and
        -not $CoordinatorRoleText.Contains(
            'Write-LabJson -Value $summary -Path $summaryPath') -and
        -not $CoordinatorRoleText.Contains(
            'Write-LabJson -Value $publicProjection') -and
        $OuterFinallyText.Contains(
            '$script:i04CandidateLocks.ToArray()') -and
        $OuterFinallyText.Contains(
            '$script:i04EvidenceLocks.ToArray()') -and
        $OuterFinallyText.Contains(
            '$script:i04HarnessBundleLocks.ToArray()') -and
        $OuterFinallyText.Contains('throw $i04TerminalLockFailure') -and
        $FinalizerText.Contains(
            '$Role -eq ''Coordinator'' -and $script:i04RoleCompleted') -and
        $FinalizerText.Contains(
            'Coordinator terminal publication prerequisites were not exact') -and
        $FinalizerText.Contains(
            '$script:i04CandidateLocks.Count -ne 0') -and
        $FinalizerText.Contains(
            '$script:i04EvidenceLocks.Count -ne 0') -and
        $FinalizerText.Contains(
            '$script:i04HarnessBundleLocks.Count -ne 0') -and
        $FinalizerText.Contains(
            '$publication.summary.outer_terminal_cleanup =') -and
        $FinalizerText.Contains(
            'summary_sha256 = $summarySha256') -and
        $FinalizerText.Contains(
            'public_summary_sha256 = $publicSummarySha256') -and
        $summaryAt -ge 0 -and $projectionAt -gt $summaryAt -and
        $publicAt -gt $projectionAt -and
        $receiptSchemaAt -gt $publicAt -and
        $receiptAt -gt $receiptSchemaAt -and
        $passAt -gt $receiptAt
}

function Invoke-I04OfflineRestrictedLauncherProbe {
    param([Parameter(Mandatory = $true)][string]$WorkingDirectory)

    $safeWorkingDirectory = Assert-I04OfflineTempPath -Path $WorkingDirectory
    $functionNames = @(
        'Assert-I04ManagedTypeContract',
        'Initialize-I04RestrictedProcessLauncher',
        'Get-I04RestrictedJobAccounting',
        'Assert-I04RestrictedJobAccountingContract',
        'Start-I04RestrictedProcess'
    )
    $definitions = @($functionNames | ForEach-Object {
        $name = $_
        $matches = @($script:HarnessAst.FindAll({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] `
                -and $node.Name -ceq $name
        }, $true))
        Assert-I04Offline -Condition ($matches.Count -eq 1) `
            -Code 'RESTRICTED_LAUNCHER_FUNCTION_NOT_UNIQUE'
        $matches[0].Extent.Text
    }) -join "`r`n`r`n"
    $startFunction = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Start-I04RestrictedProcess'
    }, $true))[0]
    Assert-I04Offline -Condition (
        @($startFunction.FindAll({
            param($node)
            $node -is [Management.Automation.Language.CommandAst] -and
                $node.GetCommandName() -ceq 'Start-Process'
        }, $true)).Count -eq 0 -and
        $startFunction.Extent.Text.Contains(
            '[V91I04RestrictedProcessLauncher]::Start(') -and
        $startFunction.Extent.Text.Contains(
            'Get-I04RestrictedJobAccounting')) `
        -Code 'RESTRICTED_LAUNCHER_PROBE_NOT_EXACTLY_SCOPED'
    $pingPath = [IO.Path]::GetFullPath((
        Join-Path $env:SystemRoot 'System32\PING.EXE'))
    Assert-I04Offline -Condition (
        Test-Path -LiteralPath $pingPath -PathType Leaf) `
        -Code 'OFFLINE_PING_HELPER_UNAVAILABLE'
    return & {
        param($DefinitionText, $Executable, $WorkingRoot)
        . ([scriptblock]::Create($DefinitionText))
        $script:i04RestrictedJobPids =
            [System.Collections.Generic.HashSet[int]]::new()
        $process = $null
        $accounting = $null
        $released = $true
        $releaseCount = 0
        $exitedAfterRelease = $false
        $leaseUnavailableAfterRelease = $false
        try {
            $process = Start-I04RestrictedProcess -FilePath $Executable `
                -ArgumentList @('-t', '127.0.0.1') `
                -WorkingDirectory $WorkingRoot
            $accounting = Get-I04RestrictedJobAccounting `
                -ProcessId ([int]$process.Id)
        } finally {
            foreach ($processId in @($script:i04RestrictedJobPids)) {
                $releaseCount++
                try {
                    $released = [bool](
                        [V91I04RestrictedProcessLauncher]::Release(
                            [int]$processId)) -and $released
                } catch { $released = $false }
            }
            $script:i04RestrictedJobPids.Clear()
            if ($null -ne $process) {
                try { $null = $process.WaitForExit(5000) } catch {}
                try { $exitedAfterRelease = [bool]$process.HasExited } catch {}
                if (-not $exitedAfterRelease) {
                    try {
                        $process.Kill()
                        $null = $process.WaitForExit(5000)
                        $exitedAfterRelease = [bool]$process.HasExited
                    } catch {}
                }
                try {
                    $null = [V91I04RestrictedProcessLauncher]::Query(
                        [int]$process.Id)
                } catch {
                    $leaseUnavailableAfterRelease = $true
                }
            }
        }
        try {
            return [pscustomobject][ordered]@{
                process_id = if ($null -eq $process) {
                    0
                } else { [int]$process.Id }
                contract_id = if ($null -eq $process) {
                    ''
                } else { [string]$process.i04_job_contract_id }
                active_process_limit = if ($null -eq $accounting) {
                    0
                } else { [int]$accounting.active_process_limit }
                total_processes = if ($null -eq $accounting) {
                    0
                } else { [int]$accounting.total_processes }
                active_processes = if ($null -eq $accounting) {
                    0
                } else { [int]$accounting.active_processes }
                child_processes_structurally_forbidden =
                    $null -ne $accounting -and [bool]$accounting.
                        child_processes_structurally_forbidden
                assigned_before_resume =
                    $null -ne $process -and
                    [bool]$process.i04_job_assigned_before_resume
                released = $releaseCount -gt 0 -and $released
                exited_after_release = $exitedAfterRelease
                lease_unavailable_after_release =
                    $leaseUnavailableAfterRelease
                tracked_pid_count_after_release =
                    $script:i04RestrictedJobPids.Count
            }
        } finally {
            if ($null -ne $process) { $process.Dispose() }
        }
    } $definitions $pingPath $safeWorkingDirectory
}

function Get-I04OfflineFirewallCimCanonical {
    param([Parameter(Mandatory = $true)][object]$Instance)

    return Invoke-I04PureScope -FunctionNames @(
        'ConvertTo-I04FirewallValueCanonical',
        'Get-I04FirewallCimCanonical') -Body {
        param($value)
        Get-I04FirewallCimCanonical -Instance $value
    } -ArgumentList @($Instance)
}

function Get-I04OfflineProductLogCounts {
    param(
        [Parameter(Mandatory = $true)][string]$NodePath,
        [string]$PeerIPv4 = '1.1.1.1',
        [string]$PeerIPv6 = '2001:4860::20',
        [int]$PeerPort = 9462,
        [string]$FileAName = 'fixture-a.bin',
        [string]$FileBName = 'fixture-b.bin'
    )

    $safeNode = Assert-I04OfflineTempPath -Path $NodePath
    $context = [pscustomobject]@{
        node = $safeNode; v4 = $PeerIPv4; v6 = $PeerIPv6
        port = $PeerPort; file_a = $FileAName; file_b = $FileBName
    }
    return Invoke-I04PureScope -FunctionNames @(
        'Get-I04Sha256FromStream', 'Get-I04StringSha256',
        'Get-I04SafeErrorToken', 'Get-I04ProductLogCounts') -Body {
        param($value)
        Get-I04ProductLogCounts -NodePath $value.node `
            -PeerIPv4 $value.v4 -PeerIPv6 $value.v6 `
            -PeerPort $value.port -FileAName $value.file_a `
            -FileBName $value.file_b
    } -ArgumentList @($context)
}

function Get-I04OfflineNormalizedIp {
    param([Parameter(Mandatory = $true)][string]$Address)

    return Invoke-I04PureScope -FunctionNames @(
        'Get-I04NormalizedIp') -Body {
        param($value)
        Get-I04NormalizedIp -Address $value
    } -ArgumentList @($Address)
}

function Get-I04OfflineTupleKey {
    param(
        [Parameter(Mandatory = $true)][string]$Family,
        [Parameter(Mandatory = $true)][string]$LocalAddress,
        [Parameter(Mandatory = $true)][int]$LocalPort,
        [Parameter(Mandatory = $true)][string]$RemoteAddress,
        [Parameter(Mandatory = $true)][int]$RemotePort
    )

    return Invoke-I04PureScope -FunctionNames @(
        'Get-I04NormalizedIp', 'Get-I04TupleKey') -Body {
        param($familyName, $local, $localPort, $remote, $remotePort)
        Get-I04TupleKey -Family $familyName `
            -LocalAddress $local -LocalPort $localPort `
            -RemoteAddress $remote -RemotePort $remotePort
    } -ArgumentList @(
        $Family, $LocalAddress, $LocalPort, $RemoteAddress, $RemotePort)
}

function Get-I04OfflineClockValidation {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()]
        [object[]]$Samples,
        [Int64]$QpcFrequency = 1000000,
        [double]$CoherenceToleranceMs = 0.1,
        [double]$BoundaryEpochMs = 1000000.0,
        [Int64]$BoundaryQpc = 1000000000
    )

    $context = [pscustomobject]@{
        rows = @($Samples)
        frequency = $QpcFrequency
        tolerance = $CoherenceToleranceMs
        boundary_epoch = $BoundaryEpochMs
        boundary_qpc = $BoundaryQpc
    }
    return Invoke-I04PureScope -FunctionNames @(
        'Get-I04SamplerClockValidation') -Body {
        param($value)
        Get-I04SamplerClockValidation -Samples @($value.rows) `
            -QpcFrequency $value.frequency `
            -CoherenceToleranceMs $value.tolerance `
            -BoundaryEpochMs $value.boundary_epoch `
            -BoundaryQpc $value.boundary_qpc
    } -ArgumentList @($context)
}

function Get-I04OfflineSynPidCorrelation {
    param(
        [Parameter(Mandatory = $true)][object]$Packet,
        [int]$CandidateProcessId = 4242,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()]
        [object[]]$SamplerRows,
        [double]$ToleranceMs = 250
    )

    $context = [pscustomobject]@{
        packet = $Packet
        pid = $CandidateProcessId
        rows = @($SamplerRows)
        tolerance = $ToleranceMs
    }
    return Invoke-I04PureScope -FunctionNames @(
        'Get-I04NormalizedIp', 'Get-I04TupleKey',
        'Get-I04SynPidCorrelation') -Body {
        param($value)
        Get-I04SynPidCorrelation -Packet $value.packet `
            -CandidateProcessId $value.pid -SamplerRows @($value.rows) `
            -ToleranceMs $value.tolerance
    } -ArgumentList @($context)
}

function Read-I04OfflinePcapNg {
    param([Parameter(Mandatory = $true)][string]$Path)

    $safePath = Assert-I04OfflineTempPath -Path $Path
    return Invoke-I04PureScope -FunctionNames @(
        'Get-I04Sha256FromStream', 'Get-I04StringSha256',
        'Read-I04UInt16LE', 'Read-I04UInt16BE',
        'Read-I04UInt32LE', 'Read-I04UInt32BE',
        'Convert-I04Packet', 'Read-I04PcapNg') -Body {
        param($pcapPath)
        Read-I04PcapNg -Path $pcapPath
    } -ArgumentList @($safePath)
}

function Get-I04OfflinePacketVerdict {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [string]$IPv4 = '1.1.1.1',
        [string]$IPv6 = '2001:4860::20',
        [string]$CoordinatorIPv4 = '8.8.8.8',
        [string]$CoordinatorIPv6 = '2001:4860::10',
        [int]$Port = 9462,
        [double]$NotBeforeEpochMs = 999900,
        [double]$BoundaryEpochMs = 1000000,
        [double]$ObservationEndEpochMs = 1012000,
        [int]$LimitSeconds = 10,
        [int]$MinimumSilentWindowMs = 2750,
        [int]$CandidateProcessId = 4242,
        [Parameter(Mandatory = $true)][object]$SocketSamplerEvidence,
        [AllowNull()][object]$ExpectedAdapterEvidence = $null,
        [int]$SynCorrelationToleranceMs = 250,
        [string[]]$ExcludedTupleKeys = @()
    )

    $safePath = Assert-I04OfflineTempPath -Path $Path
    if ($null -eq $ExpectedAdapterEvidence) {
        $ExpectedAdapterEvidence = New-I04OfflineAdapterEvidence
    }
    $context = [pscustomobject]@{
        pcap = $safePath; v4 = $IPv4; v6 = $IPv6
        coordinator_v4 = $CoordinatorIPv4
        coordinator_v6 = $CoordinatorIPv6
        port = $Port; not_before = $NotBeforeEpochMs
        boundary = $BoundaryEpochMs
        observation_end = $ObservationEndEpochMs
        limit = $LimitSeconds; silent_window = $MinimumSilentWindowMs
        pid = $CandidateProcessId; sampler = $SocketSamplerEvidence
        adapter = $ExpectedAdapterEvidence
        tolerance = $SynCorrelationToleranceMs
        excluded = @($ExcludedTupleKeys)
    }
    $adapterInventory = @([pscustomobject][ordered]@{
        InterfaceGuid = [string]$ExpectedAdapterEvidence.interface_id
        Name = [string]$ExpectedAdapterEvidence.name
        InterfaceDescription =
            [string]$ExpectedAdapterEvidence.description
        InterfaceIndex = [int]$ExpectedAdapterEvidence.interface_index
        HardwareInterface =
            [bool]$ExpectedAdapterEvidence.hardware_interface
        Virtual = [bool]$ExpectedAdapterEvidence.virtual
        Status = [string]$ExpectedAdapterEvidence.status
    })
    return Invoke-I04HermeticPacketScope -FunctionNames @(
        'Get-I04Sha256FromStream', 'Get-I04StringSha256',
        'Get-I04NormalizedIp', 'Get-I04TupleKey',
        'Read-I04UInt16LE', 'Read-I04UInt16BE',
        'Read-I04UInt32LE', 'Read-I04UInt32BE',
        'Convert-I04Packet', 'Read-I04PcapNg',
        'Get-I04SynPidCorrelation') -AdapterInventory $adapterInventory `
        -Body {
        param($value)
        Get-I04HermeticPacketVerdict -PcapNgPath $value.pcap `
            -IPv4 $value.v4 -IPv6 $value.v6 `
            -CoordinatorIPv4 $value.coordinator_v4 `
            -CoordinatorIPv6 $value.coordinator_v6 -Port $value.port `
            -NotBeforeEpochMs $value.not_before `
            -ScenarioBoundaryEpochMs $value.boundary `
            -ObservationEndEpochMs $value.observation_end `
            -LimitSeconds $value.limit `
            -MinimumSilentWindowMs $value.silent_window `
            -CandidateProcessId $value.pid `
            -SocketSamplerEvidence $value.sampler `
            -ExpectedAdapterEvidence $value.adapter `
            -SynCorrelationToleranceMs $value.tolerance `
            -ExcludedTupleKeys @($value.excluded)
    } -ArgumentList @($context)
}

function Get-I04OfflinePartialVerdict {
    param(
        [bool]$FixtureProofComplete,
        [bool]$ProductFailureProved,
        [bool]$ProofContradicted,
        [int]$ProductFailureCount
    )

    return Invoke-I04PureScope -FunctionNames @(
        'Get-I04PartialVerdict') -Body {
        param($complete, $proved, $contradicted, $failures)
        Get-I04PartialVerdict -FixtureProofComplete $complete `
            -ProductFailureProved $proved `
            -ProofContradicted $contradicted `
            -ProductFailureCount $failures
    } -ArgumentList @(
        $FixtureProofComplete, $ProductFailureProved,
        $ProofContradicted, $ProductFailureCount)
}

function Get-I04OfflineFailureDisposition {
    param(
        [bool]$CaseArmed,
        [bool]$FormalBoundaryPublished,
        [AllowNull()][object]$CandidateFailure,
        [bool]$ProofContradicted,
        [string]$ExceptionMessage = ''
    )

    return Invoke-I04PureScope -FunctionNames @(
        'Get-I04Sha256FromStream', 'Get-I04StringSha256',
        'Assert-I04RestrictedJobAccountingContract',
        'Test-I04PacketFailureSourceContract',
        'Test-I04SocketFailureSourceContract',
        'Assert-I04ProductFailureContract',
        'Get-I04FailureDisposition') -Body {
        param($armed, $published, $failure, $contradicted, $message)
        $caseId = 'V91-I04'
        $RunNonce = 'a' * 32
        Get-I04FailureDisposition -CaseArmed $armed `
            -FormalBoundaryPublished $published `
            -CandidateFailure $failure `
            -ProofContradicted $contradicted `
            -ExceptionMessage $message
    } -ArgumentList @(
        $CaseArmed, $FormalBoundaryPublished, $CandidateFailure,
        $ProofContradicted, $ExceptionMessage)
}

function Get-I04OfflinePublicSummaryProjection {
    param(
        [Parameter(Mandatory = $true)][object]$Summary,
        [string]$SourceSummarySha256 = ('f' * 64)
    )

    $context = [pscustomobject]@{
        summary = $Summary
        sha256 = $SourceSummarySha256
    }
    return Invoke-I04PureScope -FunctionNames @(
        'Assert-I04ProjectionPropertySet',
        'Get-I04PublicSummaryProjection') -Body {
        param($value)
        Get-I04PublicSummaryProjection -Summary $value.summary `
            -SourceSummarySha256 $value.sha256
    } -ArgumentList @($context)
}

function Test-I04OfflineApiIsolation {
    param(
        [Parameter(Mandatory = $true)][object]$Data,
        [bool]$RequireEd2k = $false
    )

    return Invoke-I04PureScope -FunctionNames @(
        'Get-I04RequiredJsonProperty',
        'Assert-I04ApiStatusContract',
        'Assert-I04ApiV9Contract',
        'Test-I04ApiIsolation') -Body {
        param($value, $required)
        $null = Assert-I04ApiStatusContract -Status $value
        $null = Assert-I04ApiV9Contract -Value $value.v9
        Test-I04ApiIsolation -Data $value -RequireEd2k $required
    } -ArgumentList @($Data, $RequireEd2k)
}

function Test-I04OfflineValueSetEqual {
    param(
        [AllowNull()][object[]]$Actual,
        [AllowNull()][object[]]$Expected,
        [switch]$NormalizeIp,
        [switch]$NormalizePath
    )

    $context = [pscustomobject]@{
        actual = @($Actual); expected = @($Expected)
        normalize_ip = [bool]$NormalizeIp
        normalize_path = [bool]$NormalizePath
    }
    return Invoke-I04PureScope -FunctionNames @(
        'Get-I04NormalizedIp', 'Convert-I04ValueSet',
        'Test-I04ValueSetEqual') -Body {
        param($value)
        Test-I04ValueSetEqual -Actual @($value.actual) `
            -Expected @($value.expected) `
            -NormalizeIp:$value.normalize_ip `
            -NormalizePath:$value.normalize_path
    } -ArgumentList @($context)
}

function Set-I04OfflineUInt16BE {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][int]$Offset,
        [Parameter(Mandatory = $true)][UInt16]$Value
    )

    $Bytes[$Offset] = [byte](($Value -shr 8) -band 0xff)
    $Bytes[$Offset + 1] = [byte]($Value -band 0xff)
}

function Set-I04OfflineUInt32BE {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][int]$Offset,
        [Parameter(Mandatory = $true)][UInt32]$Value
    )

    $Bytes[$Offset] = [byte](($Value -shr 24) -band 0xff)
    $Bytes[$Offset + 1] = [byte](($Value -shr 16) -band 0xff)
    $Bytes[$Offset + 2] = [byte](($Value -shr 8) -band 0xff)
    $Bytes[$Offset + 3] = [byte]($Value -band 0xff)
}

function Set-I04OfflineUInt16LE {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][int]$Offset,
        [Parameter(Mandatory = $true)][UInt16]$Value
    )

    $Bytes[$Offset] = [byte]($Value -band 0xff)
    $Bytes[$Offset + 1] = [byte](($Value -shr 8) -band 0xff)
}

function Set-I04OfflineUInt32LE {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][int]$Offset,
        [Parameter(Mandatory = $true)][UInt32]$Value
    )

    $Bytes[$Offset] = [byte]($Value -band 0xff)
    $Bytes[$Offset + 1] = [byte](($Value -shr 8) -band 0xff)
    $Bytes[$Offset + 2] = [byte](($Value -shr 16) -band 0xff)
    $Bytes[$Offset + 3] = [byte](($Value -shr 24) -band 0xff)
}

function New-I04OfflineTcpPacket {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('IPv4', 'IPv6')][string]$Family,
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination,
        [Parameter(Mandatory = $true)][UInt16]$SourcePort,
        [Parameter(Mandatory = $true)][UInt16]$DestinationPort,
        [Parameter(Mandatory = $true)][UInt32]$SequenceNumber,
        [UInt32]$AcknowledgementNumber = 0,
        [Parameter(Mandatory = $true)][byte]$Flags
    )

    $sourceBytes = ([Net.IPAddress]::Parse($Source)).GetAddressBytes()
    $destinationBytes =
        ([Net.IPAddress]::Parse($Destination)).GetAddressBytes()
    $ipLength = if ($Family -ceq 'IPv4') { 20 } else { 40 }
    $packet = New-Object byte[] ($ipLength + 20)
    if ($Family -ceq 'IPv4') {
        Assert-I04Offline -Condition (
            $sourceBytes.Length -eq 4 -and $destinationBytes.Length -eq 4) `
            -Code 'PCAP_FIXTURE_ADDRESS_FAMILY_MISMATCH'
        $packet[0] = 0x45
        Set-I04OfflineUInt16BE -Bytes $packet -Offset 2 `
            -Value ([UInt16]$packet.Length)
        $packet[8] = 64
        $packet[9] = 6
        [Array]::Copy($sourceBytes, 0, $packet, 12, 4)
        [Array]::Copy($destinationBytes, 0, $packet, 16, 4)
    } else {
        Assert-I04Offline -Condition (
            $sourceBytes.Length -eq 16 -and $destinationBytes.Length -eq 16) `
            -Code 'PCAP_FIXTURE_ADDRESS_FAMILY_MISMATCH'
        $packet[0] = 0x60
        Set-I04OfflineUInt16BE -Bytes $packet -Offset 4 -Value 20
        $packet[6] = 6
        $packet[7] = 64
        [Array]::Copy($sourceBytes, 0, $packet, 8, 16)
        [Array]::Copy($destinationBytes, 0, $packet, 24, 16)
    }
    Set-I04OfflineUInt16BE -Bytes $packet -Offset $ipLength `
        -Value $SourcePort
    Set-I04OfflineUInt16BE -Bytes $packet -Offset ($ipLength + 2) `
        -Value $DestinationPort
    Set-I04OfflineUInt32BE -Bytes $packet -Offset ($ipLength + 4) `
        -Value $SequenceNumber
    Set-I04OfflineUInt32BE -Bytes $packet -Offset ($ipLength + 8) `
        -Value $AcknowledgementNumber
    $packet[$ipLength + 12] = 0x50
    $packet[$ipLength + 13] = $Flags
    return [byte[]]$packet
}

function New-I04OfflinePcapNg {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()]
        [object[]]$Packets,
        [AllowEmptyCollection()][object[]]$Interfaces = @()
    )

    $full = Assert-I04OfflineTempPath -Path $Path
    if (@($Interfaces).Count -eq 0) {
        $Interfaces = @([pscustomobject][ordered]@{
            link_type = 101
            name = 'Offline Physical NIC'
            description = 'Offline Physical NIC Fixture'
        })
    }
    $stream = [IO.MemoryStream]::new()
    $writer = [IO.BinaryWriter]::new($stream)
    try {
        $writer.Write([UInt32]0x0a0d0d0a)
        $writer.Write([UInt32]28)
        $writer.Write([UInt32]0x1a2b3c4d)
        $writer.Write([UInt16]1)
        $writer.Write([UInt16]0)
        $writer.Write([Int64]-1)
        $writer.Write([UInt32]28)
        foreach ($interface in @($Interfaces)) {
            [UInt16]$linkType = [UInt16]$interface.link_type
            [byte[]]$nameBytes = [Text.Encoding]::UTF8.GetBytes(
                [string]$interface.name)
            [byte[]]$descriptionBytes = [Text.Encoding]::UTF8.GetBytes(
                [string]$interface.description)
            $namePaddedLength = ($nameBytes.Length + 3) -band (-bnot 3)
            $descriptionPaddedLength =
                ($descriptionBytes.Length + 3) -band (-bnot 3)
            $blockLength = [UInt32](
                20 + 4 + $namePaddedLength +
                4 + $descriptionPaddedLength + 4)
            $writer.Write([UInt32]1)
            $writer.Write($blockLength)
            $writer.Write($linkType)
            $writer.Write([UInt16]0)
            $writer.Write([UInt32]65535)
            $writer.Write([UInt16]2)
            $writer.Write([UInt16]$nameBytes.Length)
            $writer.Write($nameBytes)
            for ($index = $nameBytes.Length; $index -lt $namePaddedLength;
                $index++) {
                $writer.Write([byte]0)
            }
            $writer.Write([UInt16]3)
            $writer.Write([UInt16]$descriptionBytes.Length)
            $writer.Write($descriptionBytes)
            for ($index = $descriptionBytes.Length;
                $index -lt $descriptionPaddedLength; $index++) {
                $writer.Write([byte]0)
            }
            $writer.Write([UInt16]0)
            $writer.Write([UInt16]0)
            $writer.Write($blockLength)
        }
        foreach ($spec in $Packets) {
            [byte[]]$packetBytes = @($spec.bytes)
            $capturedLength = if (
                $spec.PSObject.Properties.Name -contains 'captured_length') {
                [int]$spec.captured_length
            } else { $packetBytes.Length }
            $originalLength = if (
                $spec.PSObject.Properties.Name -contains 'original_length') {
                [int]$spec.original_length
            } else { $packetBytes.Length }
            Assert-I04Offline -Condition (
                $capturedLength -ge 0 -and
                $capturedLength -le $packetBytes.Length -and
                $originalLength -ge 0) -Code 'PCAP_FIXTURE_LENGTH_INVALID'
            $paddedLength = ($capturedLength + 3) -band (-bnot 3)
            $blockLength = [UInt32](32 + $paddedLength)
            [UInt64]$ticks = [UInt64][Math]::Round(
                [double]$spec.timestamp_ms * 1000.0)
            $interfaceId = if (
                $spec.PSObject.Properties.Name -contains 'interface_id') {
                [UInt32]$spec.interface_id
            } else { [UInt32]0 }
            $writer.Write([UInt32]6)
            $writer.Write($blockLength)
            $writer.Write($interfaceId)
            $writer.Write([UInt32]($ticks -shr 32))
            $writer.Write([UInt32]($ticks -band [UInt64]4294967295))
            $writer.Write([UInt32]$capturedLength)
            $writer.Write([UInt32]$originalLength)
            if ($capturedLength -gt 0) {
                $writer.Write($packetBytes, 0, $capturedLength)
            }
            for ($index = $capturedLength; $index -lt $paddedLength; $index++) {
                $writer.Write([byte]0)
            }
            $writer.Write($blockLength)
        }
        $writer.Flush()
        [IO.File]::WriteAllBytes($full, $stream.ToArray())
    } finally {
        $writer.Dispose()
        $stream.Dispose()
    }
    return $full
}

function New-I04OfflineSamplerRow {
    param(
        [Parameter(Mandatory = $true)][string]$Family,
        [Parameter(Mandatory = $true)][string]$LocalAddress,
        [Parameter(Mandatory = $true)][int]$LocalPort,
        [Parameter(Mandatory = $true)][string]$RemoteAddress,
        [Parameter(Mandatory = $true)][int]$RemotePort,
        [Parameter(Mandatory = $true)][double]$EpochMs,
        [int]$OwningProcess = 4242,
        [ValidateSet('SynSent', 'Established', 'TimeWait')]
        [string]$State = 'SynSent'
    )

    return [pscustomobject][ordered]@{
        tuple_key = Get-I04OfflineTupleKey -Family $Family `
            -LocalAddress $LocalAddress -LocalPort $LocalPort `
            -RemoteAddress $RemoteAddress -RemotePort $RemotePort
        family = $Family
        local_address = $LocalAddress
        local_port = $LocalPort
        remote_address = $RemoteAddress
        remote_port = $RemotePort
        epoch_ms = $EpochMs
        owning_process = $OwningProcess
        state = $State
    }
}

function New-I04OfflineSamplerEvidence {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()]
        [object[]]$TargetRows,
        [int]$CandidateProcessId = 4242,
        [double]$BoundaryEpochMs = 1000000,
        [double]$FirstSampleEpochMs = 999900,
        [double]$LastSampleEpochMs = 1012000,
        [double]$MaximumSampleGapMs = 100,
        [bool]$ClockCoherenceValid = $true,
        [bool]$SamplerCoverageValid = $true
    )

    $boundaryQpc = [Int64]1000000
    $qpcFrequency = [Int64][Diagnostics.Stopwatch]::Frequency
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.i04-pid-socket-sampler/v1'
        source_byte_count = [Int64]4096
        source_sha256 = '9' * 64
        source_immutable_read_lock_held = $true
        candidate_process_id = $CandidateProcessId
        boundary_epoch_ms = $BoundaryEpochMs
        boundary_qpc = $boundaryQpc
        clock_coherence_valid = $ClockCoherenceValid
        qpc_frequency = $qpcFrequency
        clock_validation = [pscustomobject][ordered]@{
            valid = $ClockCoherenceValid
            sample_count = [int]2
            boundary_epoch_ms = $BoundaryEpochMs
            boundary_qpc = $boundaryQpc
            qpc_frequency = $qpcFrequency
        }
        sample_count = [int]2
        parse_error_count = [int]0
        sampler_coverage_valid = $SamplerCoverageValid
        first_sample_epoch_ms = $FirstSampleEpochMs
        last_sample_epoch_ms = $LastSampleEpochMs
        maximum_sample_gap_ms = $MaximumSampleGapMs
        target_rows = @($TargetRows)
        candidate_target_rows = @($TargetRows | Where-Object {
                [int]$_.owning_process -eq $CandidateProcessId
            })
    }
}

function New-I04OfflineAdapterEvidence {
    param(
        [string]$InterfaceId = 'offline-physical-interface-01',
        [string]$Name = 'Offline Physical NIC',
        [string]$Description = 'Offline Physical NIC Fixture',
        [int]$InterfaceIndex = 7,
        [bool]$HardwareInterface = $true,
        [bool]$Virtual = $false,
        [bool]$OverlayOrVpnLike = $false,
        [string]$Status = 'Up'
    )

    return [pscustomobject][ordered]@{
        interface_id = $InterfaceId
        name = $Name
        description = $Description
        interface_index = $InterfaceIndex
        hardware_interface = $HardwareInterface
        virtual = $Virtual
        overlay_or_vpn_like = $OverlayOrVpnLike
        status = $Status
    }
}

function New-I04OfflineProductFailure {
    param(
        [string]$FailureType = 'fallback_window',
        [ValidateSet('packet_verdict', 'socket_sampler')]
        [string]$SourceKind = 'packet_verdict',
        [bool]$PostBoundary = $true,
        [bool]$BindingExact = $true,
        [bool]$CollectorOk = $true,
        [bool]$EvidenceContractValid = $true,
        [bool]$EndpointBound = $true,
        [bool]$SourceBound = $true,
        [bool]$Adjudicable = $true
    )

    $sourceEvidence = if ($SourceKind -ceq 'socket_sampler') {
        New-I04OfflineSamplerEvidence -TargetRows @()
    } else {
        [pscustomobject][ordered]@{
            schema = 'ese.v91.i04-packet-verdict/v2'
            offline_fixture = $true
            candidate_process_id = 4242
            coordinator_stop_a_boundary_epoch_ms = [double]1000000
            pcapng_source_byte_count = [Int64]8192
            pcapng_source_sha256 = '8' * 64
            pcapng_source_immutable_read_lock_held = $true
            pcapng_parser_complete = $true
            capture_interface_binding_exact = $true
            target_frames_on_expected_physical_nic = $true
            pid_packet_correlation_complete = $true
        }
    }
    $sourceEvidenceJson =
        $sourceEvidence | ConvertTo-Json -Compress -Depth 32
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.i04-product-failure/v1'
        failure_type = $FailureType
        display_message = 'offline typed failure fixture'
        observed_at_epoch_ms = if ($PostBoundary) {
            [double]1000100
        } else { [double]999900 }
        boundary_epoch_ms = [double]1000000
        post_boundary = $PostBoundary
        case_id = 'V91-I04'
        run_nonce = 'a' * 32
        candidate_binding = [pscustomobject][ordered]@{
            schema = 'ese.v91.i04-candidate-binding/v1'
            pid = [int]4242
            exact = $BindingExact
            exit_state_collector_ok = $true
            has_exited = $false
            current_live_binding_exact = $true
            ownership_id_sha256 = 'b' * 64
            executable_sha256 = 'c' * 64
            user_sid_sha256 = 'd' * 64
            restricted_job_contract_id =
                'ese.v91.i04-restricted-process-launcher/2026-08-01.v1'
            restricted_job_active_process_limit = [int]1
            restricted_job_assigned_before_resume = $true
            restricted_job_accounting = [pscustomobject][ordered]@{
                schema = 'ese.v91.i04-restricted-job-accounting/v1'
                contract_id =
                    'ese.v91.i04-restricted-process-launcher/2026-08-01.v1'
                process_id = [int]4242
                active_process_limit = [int]1
                total_processes = [int]1
                active_processes = [int]1
                total_terminated_processes = [int]0
                child_processes_structurally_forbidden = $true
            }
            restricted_job_accounting_exact = $true
        }
        source = [pscustomobject][ordered]@{
            kind = $SourceKind
            collector_ok = $CollectorOk
            evidence_contract_valid = $EvidenceContractValid
            evidence = $sourceEvidence
            endpoint = ''
            endpoint_owner_pid = $null
            endpoint_bound_to_candidate = $EndpointBound
            evidence_sha256 = Get-I04OfflineStringSha256 `
                -Value $sourceEvidenceJson
            error_fingerprint_sha256 = ''
        }
        source_bound = $SourceBound
        adjudicable = $Adjudicable
    }
}

function New-I04OfflineSummaryFixture {
    $failure = New-I04OfflineProductFailure
    $failure.display_message = 'private-error-sentinel'
    return [pscustomobject][ordered]@{
        case_id = 'V91-I04'
        formal_status = 'BLOCKED'
        partial_verdict = 'PASS'
        formal_v91_i04_eligible = $false
        candidate = [pscustomobject][ordered]@{
            commit = 'a' * 40
            version = 'offline-v91'
            expected_emule_sha256 = 'b' * 64
            package_zip_sha256 = 'c' * 64
            package_manifest_sha256 = 'd' * 64
            unchanged = $true
            raw_path = 'C:\private-path-sentinel\emule.exe'
            ownership_id_sha256 = 'e' * 64
        }
        adjudication = [pscustomobject][ordered]@{
            fixture_proof_complete = $true
            product_failure_proved = $false
            product_failures_typed_and_source_bound = $true
            proof_contradicted = $false
            cleanup_complete = $true
        }
        topology = [pscustomobject][ordered]@{
            required = 'three-machine-physical'
            observed_topology = 'offline-synthetic'
            proved = $false
            distinct_physical_hosts = $false
            native_global_ipv6 = $true
            physical_adapters_and_sockets = $true
            overlay_vpn_proxy_absent = $true
            coordinator_ipv4 = '203.0.113.55'
            coordinator_user_sid = 'stable-user-id-sentinel'
        }
        fixture = [pscustomobject][ordered]@{
            trigger_runtime_valid = $true
            packet_capture_zero_loss = $true
            packet_capture_below_circular_limit = $true
            socket_sampler = [pscustomobject]@{
                sampler_coverage_valid = $true
                candidate_process_id = 4242
            }
        }
        single_retry = [pscustomobject][ordered]@{
            fallback_log_delta = 1
            bounded_fallback_log_delta = 1
            hello_send_delta = 1
            hello_answer_receive_delta = 1
            a4af_swap_a_to_b_delta = 1
        }
        timing = [pscustomobject][ordered]@{
            packet_verdict = [pscustomobject][ordered]@{
                pcapng_parser_complete = $true
                capture_interface_binding_exact = $true
                target_frames_on_expected_physical_nic = $true
                ipv6_syn_count = 1
                ipv4_syn_count = 1
                syn6_to_syn4_ms = 3000.0
                syn6_to_ipv4_connected_ms = 3200.0
                adapter_name = 'private-adapter-sentinel'
            }
        }
        liveness = [pscustomobject][ordered]@{
            api_probe_count = 10
            api_failure_count = 0
            ui_probe_count = 10
            ui_unresponsive_count = 0
        }
        product_failures = @($failure)
        blocked_reasons = @('private-blocked-reason-sentinel')
        cleanup = [pscustomobject][ordered]@{
            failures = @('private-cleanup-error-sentinel')
        }
        evidence = [pscustomobject][ordered]@{
            raw_log = 'private-raw-log-sentinel'
            raw_path = 'C:\private-path-sentinel\evidence'
        }
    }
}

function New-I04OfflineApiFixture {
    param([bool]$RequireEd2k = $false)

    return [pscustomobject][ordered]@{
        available = $true
        user_hash = '0123456789abcdef0123456789abcdef'
        ed2k_connected = $RequireEd2k
        kad_running_mask = [Int64]0
        connecting_client_count = [Int64]0
        connecting_client_adds = [Int64]0
        connecting_client_high_water = [Int64]0
        connecting_client_duplicate_adds = [Int64]0
        kad2_running = $false
        kad6_running = $false
        netlab_consent = 'declined'
        netlab_advanced_consent = 'declined'
        netlab_contribution_consent = 'declined'
        netlab_enabled = $false
        utp_hole_punch_enabled = $false
        v9 = [pscustomobject][ordered]@{
            success = $true
            netlab = [pscustomobject][ordered]@{
                enabled = $false
                capability_advertised = $false
                staged = [pscustomobject][ordered]@{
                    selector = $false; port_predict = $false
                    ed2k_punch3 = $false; kad3_rendezvous = $false
                }
                independent = [pscustomobject][ordered]@{
                    relay_accept = $false; relay_egress = $false
                    krp = $false; kad6_beta_exit = $false
                    kad6_stable_public_exit = $false
                }
                keepalive_running = $false
            }
            v9 = [pscustomobject][ordered]@{
                experimental = $false; port_predict = $false
                ed2k_punch3 = $false; kad3_rendezvous = $false
                keepalive_running = $false; hole_punch_master = $false
            }
        }
    }
}

function Copy-I04OfflineObject {
    param([Parameter(Mandatory = $true)][object]$Value)

    return $Value | ConvertTo-Json -Depth 32 -Compress | ConvertFrom-Json
}

function New-I04OfflinePackageFixture {
    param([Parameter(Mandatory = $true)][string]$Name)

    $root = Assert-I04OfflineTempPath -Path (
        Join-Path $script:TempRoot $Name)
    Assert-I04Offline -Condition (-not (Test-Path -LiteralPath $root)) `
        -Code 'PACKAGE_FIXTURE_ALREADY_EXISTS'
    New-Item -ItemType Directory -Path $root -Force -ErrorAction Stop |
        Out-Null
    New-Item -ItemType Directory -Path (Join-Path $root 'config') `
        -Force -ErrorAction Stop | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $root 'bin') `
        -Force -ErrorAction Stop | Out-Null
    $files = [ordered]@{
        'emule.exe' = 'i04-offline-emule-candidate'
        'ese-server.exe' = 'i04-offline-controlled-server'
        'BUILD_INFO.txt' = @(
            'release: v0.70b-eSE-offline'
            'version: offline'
            'commit: ' + ('a' * 40)
            'dirty: false'
        ) -join "`r`n"
        'config\preferences.ini' =
            "[eMule]`r`nUncontrolledSentinel=preserve-me`r`n"
        'bin\support.dll' = 'i04-offline-support-library'
        'empty.dat' = ''
    }
    foreach ($entry in $files.GetEnumerator()) {
        [IO.File]::WriteAllText(
            (Join-Path $root $entry.Key), [string]$entry.Value,
            [Text.UTF8Encoding]::new($false))
    }
    return $root
}

function Get-I04OfflinePackageEntrySpecs {
    param([Parameter(Mandatory = $true)][string]$PackagePath)

    $root = [IO.Path]::GetFullPath($PackagePath).TrimEnd('\')
    return @(Get-ChildItem -LiteralPath $root -Recurse -File -Force `
        -ErrorAction Stop | Sort-Object FullName | ForEach-Object {
        $relative = $_.FullName.Substring($root.Length + 1).Replace('\', '/')
        [pscustomobject][ordered]@{
            name = $relative
            bytes = [IO.File]::ReadAllBytes($_.FullName)
        }
    })
}

function New-I04OfflineZip {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()]
        [object[]]$Entries
    )

    $full = Assert-I04OfflineTempPath -Path $Path
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $stream = [IO.File]::Open(
        $full, [IO.FileMode]::Create, [IO.FileAccess]::ReadWrite,
        [IO.FileShare]::None)
    $archive = [IO.Compression.ZipArchive]::new(
        $stream, [IO.Compression.ZipArchiveMode]::Create, $false)
    try {
        foreach ($spec in $Entries) {
            $entry = $archive.CreateEntry(
                [string]$spec.name,
                [IO.Compression.CompressionLevel]::NoCompression)
            $entry.LastWriteTime = [DateTimeOffset]::Parse(
                '2026-08-01T00:00:00Z')
            $attributes = $spec.PSObject.Properties['external_attributes']
            if ($null -ne $attributes) {
                $entry.ExternalAttributes = [int]$attributes.Value
            }
            if (-not [string]::IsNullOrEmpty([string]$entry.Name)) {
                [byte[]]$bytes = @($spec.bytes)
                $entryStream = $entry.Open()
                try { $entryStream.Write($bytes, 0, $bytes.Length) }
                finally { $entryStream.Dispose() }
            }
        }
    } finally {
        $archive.Dispose()
        $stream.Dispose()
    }
    return $full
}

function New-I04OfflineValidZip {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$PackagePath
    )

    return New-I04OfflineZip -Path (Join-Path $script:TempRoot $Name) `
        -Entries (Get-I04OfflinePackageEntrySpecs -PackagePath $PackagePath)
}

function New-I04OfflineBindingFixture {
    param([Parameter(Mandatory = $true)][string]$Name)

    $package = New-I04OfflinePackageFixture -Name ($Name + '-package')
    $zip = New-I04OfflineValidZip -Name ($Name + '.zip') `
        -PackagePath $package
    return [pscustomobject][ordered]@{
        package = $package
        zip = $zip
        zip_sha256 = Get-I04OfflineFileSha256 -Path $zip
        exe_sha256 = Get-I04OfflineFileSha256 -Path (
            Join-Path $package 'emule.exe')
        commit = ('a' * 40)
    }
}

function New-I04OfflinePreferenceFile {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text
    )

    $path = Assert-I04OfflineTempPath -Path (
        Join-Path $script:TempRoot ($Name + '.ini'))
    Assert-I04Offline -Condition (-not (Test-Path -LiteralPath $path)) `
        -Code 'PREFERENCE_FIXTURE_ALREADY_EXISTS'
    [IO.File]::WriteAllText(
        $path, $Text, [Text.UTF8Encoding]::new($false))
    return $path
}

function New-I04OfflineFallbackFixture {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [double]$FallbackDelayMs = 3000,
        [bool]$IncludeIPv4 = $true,
        [bool]$IncludeSynAck = $true,
        [bool]$IncludeFinalAck = $true,
        [switch]$SecondIPv4Attempt,
        [switch]$IPv6Response,
        [ValidateSet('Candidate', 'Foreign', 'Ambiguous', 'Unobserved')]
        [string]$Ownership = 'Candidate'
    )

    $coordinatorV6 = '2001:4860::10'
    $peerV6 = '2001:4860::20'
    $coordinatorV4 = '8.8.8.8'
    $peerV4 = '1.1.1.1'
    $peerPort = 9462
    $v6LocalPort = 50000
    $v4LocalPort = 50001
    $v6SynAt = 1000100.0
    $v4SynAt = $v6SynAt + $FallbackDelayMs
    $packets = [System.Collections.Generic.List[object]]::new()
    $rows = [System.Collections.Generic.List[object]]::new()
    $packets.Add([pscustomobject]@{
        timestamp_ms = $v6SynAt; family = 'IPv6'
        bytes = New-I04OfflineTcpPacket -Family IPv6 `
            -Source $coordinatorV6 -Destination $peerV6 `
            -SourcePort $v6LocalPort -DestinationPort $peerPort `
            -SequenceNumber 100 -Flags 0x02
    })
    if ($IPv6Response) {
        $packets.Add([pscustomobject]@{
            timestamp_ms = $v6SynAt + 1000; family = 'IPv6'
            bytes = New-I04OfflineTcpPacket -Family IPv6 `
                -Source $peerV6 -Destination $coordinatorV6 `
                -SourcePort $peerPort -DestinationPort $v6LocalPort `
                -SequenceNumber 900 -AcknowledgementNumber 101 `
                -Flags 0x14
        })
    }
    if ($IncludeIPv4) {
        $packets.Add([pscustomobject]@{
            timestamp_ms = $v4SynAt; family = 'IPv4'
            bytes = New-I04OfflineTcpPacket -Family IPv4 `
                -Source $coordinatorV4 -Destination $peerV4 `
                -SourcePort $v4LocalPort -DestinationPort $peerPort `
                -SequenceNumber 200 -Flags 0x02
        })
        if ($SecondIPv4Attempt) {
            $packets.Add([pscustomobject]@{
                timestamp_ms = $v4SynAt + 100; family = 'IPv4'
                bytes = New-I04OfflineTcpPacket -Family IPv4 `
                    -Source $coordinatorV4 -Destination $peerV4 `
                    -SourcePort ($v4LocalPort + 1) `
                    -DestinationPort $peerPort `
                    -SequenceNumber 201 -Flags 0x02
            })
        }
        if ($IncludeSynAck) {
            $packets.Add([pscustomobject]@{
                timestamp_ms = $v4SynAt + 100; family = 'IPv4'
                bytes = New-I04OfflineTcpPacket -Family IPv4 `
                    -Source $peerV4 -Destination $coordinatorV4 `
                    -SourcePort $peerPort -DestinationPort $v4LocalPort `
                    -SequenceNumber 300 -AcknowledgementNumber 201 `
                    -Flags 0x12
            })
        }
        if ($IncludeSynAck -and $IncludeFinalAck) {
            $packets.Add([pscustomobject]@{
                timestamp_ms = $v4SynAt + 200; family = 'IPv4'
                bytes = New-I04OfflineTcpPacket -Family IPv4 `
                    -Source $coordinatorV4 -Destination $peerV4 `
                    -SourcePort $v4LocalPort -DestinationPort $peerPort `
                    -SequenceNumber 201 -AcknowledgementNumber 301 `
                    -Flags 0x10
            })
        }
    }

    $ownerPids = switch ($Ownership) {
        'Candidate' { @(4242) }
        'Foreign' { @(9999) }
        'Ambiguous' { @(4242, 9999) }
        'Unobserved' { @() }
    }
    foreach ($ownerPid in $ownerPids) {
        $rows.Add((New-I04OfflineSamplerRow -Family IPv6 `
            -LocalAddress $coordinatorV6 -LocalPort $v6LocalPort `
            -RemoteAddress $peerV6 -RemotePort $peerPort `
            -EpochMs $v6SynAt -OwningProcess $ownerPid))
        if ($IncludeIPv4) {
            $rows.Add((New-I04OfflineSamplerRow -Family IPv4 `
                -LocalAddress $coordinatorV4 -LocalPort $v4LocalPort `
                -RemoteAddress $peerV4 -RemotePort $peerPort `
                -EpochMs $v4SynAt -OwningProcess $ownerPid))
            if ($SecondIPv4Attempt) {
                $rows.Add((New-I04OfflineSamplerRow -Family IPv4 `
                    -LocalAddress $coordinatorV4 `
                    -LocalPort ($v4LocalPort + 1) `
                    -RemoteAddress $peerV4 -RemotePort $peerPort `
                    -EpochMs ($v4SynAt + 100) -OwningProcess $ownerPid))
            }
        }
    }
    $path = New-I04OfflinePcapNg `
        -Path (Join-Path $script:TempRoot ($Name + '.pcapng')) `
        -Packets @($packets)
    $adapter = New-I04OfflineAdapterEvidence
    return [pscustomobject][ordered]@{
        path = $path
        packets = @($packets)
        adapter = $adapter
        sampler = New-I04OfflineSamplerEvidence -TargetRows @($rows)
        v6_tuple = Get-I04OfflineTupleKey -Family IPv6 `
            -LocalAddress $coordinatorV6 -LocalPort $v6LocalPort `
            -RemoteAddress $peerV6 -RemotePort $peerPort
        v4_tuple = Get-I04OfflineTupleKey -Family IPv4 `
            -LocalAddress $coordinatorV4 -LocalPort $v4LocalPort `
            -RemoteAddress $peerV4 -RemotePort $peerPort
    }
}

try {
    New-Item -ItemType Directory -Path $script:TempRoot `
        -ErrorAction Stop | Out-Null

Invoke-I04OfflineTest -Id 'PARSER-HARNESS-SNAPSHOT-CLEAN' `
    -Category 'parser' -Body {
    Assert-I04Offline -Condition (
        @($script:HarnessParserErrors).Count -eq 0 -and
        $null -ne $script:HarnessAst) `
        -Code 'HARNESS_PARSER_ERROR'
}

Invoke-I04OfflineTest -Id 'PARSER-OFFLINE-SELF-CLEAN' `
    -Category 'parser' -Body {
    $tokens = $null
    $errors = $null
    [void][Management.Automation.Language.Parser]::ParseFile(
        $script:SelfPath, [ref]$tokens, [ref]$errors)
    Assert-I04Offline -Condition (@($errors).Count -eq 0) `
        -Code 'OFFLINE_SELF_PARSER_ERROR'
}

Invoke-I04OfflineTest -Id 'HARNESS-PARAMETER-CONTRACT-STATIC' `
    -Category 'startup_contract' -Body {
    $parameters = @($script:HarnessAst.ParamBlock.Parameters)
    $names = @($parameters | ForEach-Object {
        $_.Name.VariablePath.UserPath
    })
    foreach ($required in @(
        'Role', 'PackagePath', 'PackageZipPath',
        'ExpectedPackageZipSha256', 'ExpectedHarnessSha256',
        'ExpectedCommonSha256', 'ExpectedPrepareNodeSha256',
        'OutputRoot', 'Commit',
        'ExpectedEmuleSha256', 'PeerIPv4', 'PeerLocalIPv4', 'PeerIPv6',
        'CoordinatorIPv4', 'CoordinatorIPv6', 'CoordinationRoot',
        'ControlledPeerAcknowledged',
        'DisposableLabAccountAcknowledged',
        'ExpectedCoordinatorMachineIdSha256',
        'ExpectedPeerMachineIdSha256',
        'ExpectedCoordinatorUserSidSha256',
        'ExpectedPeerUserSidSha256',
        'PeerTcpPort', 'PeerUdpPort', 'PeerWebPort',
        'ClientTcpPort', 'ClientUdpPort', 'ClientWebPort',
        'FallbackLimitSeconds', 'RunNonce')) {
        Assert-I04Offline -Condition ($names -ccontains $required) `
            -Code 'HARNESS_REQUIRED_PARAMETER_MISSING'
    }
    $text = $script:HarnessAst.ParamBlock.Extent.Text
    foreach ($needle in @(
        "[ValidateSet('Coordinator', 'Peer')]",
        "[ValidatePattern('^[0-9a-fA-F]{40}$')]",
        "[ValidatePattern('^[0-9a-fA-F]{64}$')]",
        '[ValidateRange(4, 10)][int]$FallbackLimitSeconds = 10',
        "[ValidatePattern('^[0-9a-fA-F]{32}$')]")) {
        Assert-I04Offline -Condition ($text.Contains($needle)) `
            -Code 'HARNESS_PARAMETER_VALIDATION_MISSING'
    }
}

Invoke-I04OfflineTest -Id 'HOST-AND-DISPOSABLE-SID-BINDING-STATIC' `
    -Category 'startup_contract' -Body {
    $identity = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Get-I04CurrentHostIdentity'
    }, $true))[0].Extent.Text
    foreach ($needle in @(
        "'HKLM:\SOFTWARE\Microsoft\Cryptography'",
        '-Name MachineGuid -ErrorAction Stop',
        '[Guid]::TryParse', '[Guid]::Empty',
        '[Security.Principal.WindowsIdentity]::GetCurrent()',
        "'S-1-5-18'", "'S-1-5-19'", "'S-1-5-20'", "'-500$'",
        'Assert-I04NoReparsePath -Path $env:USERPROFILE',
        '$machineGuid.ToString(''D'').ToLowerInvariant()',
        'user_sid_sha256 = Get-I04StringSha256 -Value $sid',
        'disposable_account_operator_attested = $true')) {
        Assert-I04Offline -Condition ($identity.Contains($needle)) `
            -Code 'HOST_OR_DISPOSABLE_ACCOUNT_BINDING_MISSING'
    }
    $projection = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Get-I04HostIdentityEvidence'
    }, $true))[0]
    $maps = @($projection.FindAll({
        param($node)
        $node -is [Management.Automation.Language.HashtableAst]
    }, $true))
    Assert-I04Offline -Condition ($maps.Count -eq 1) `
        -Code 'HOST_IDENTITY_PROJECTION_NOT_EXACT'
    $keys = @($maps[0].KeyValuePairs | ForEach-Object {
        $_.Item1.Extent.Text.Trim("'`"")
    })
    $expectedKeys = @(
        'machine_id_sha256', 'user_sid_sha256', 'account_name_sha256',
        'profile_path_sha256', 'builtin_or_service',
        'disposable_account_operator_attested'
    )
    Assert-I04Offline -Condition (
        $keys.Count -eq $expectedKeys.Count -and
        @($expectedKeys | Where-Object {
            $keys -cnotcontains $_
        }).Count -eq 0 -and $keys -cnotcontains 'user_sid' -and
        $script:HarnessText.Contains(
            '$script:i04HostIdentity.machine_id_sha256 -ne') -and
        $script:HarnessText.Contains(
            '$script:i04HostIdentity.user_sid_sha256 -ne $expectedLocalSid')) `
        -Code 'HOST_IDENTITY_RUNTIME_OR_PRIVACY_BINDING_MISSING'
}

Invoke-I04OfflineTest -Id 'MACHINE-IDENTITIES-DISTINCT-PRE-MUTATION-STATIC' `
    -Category 'startup_contract' -Body {
    $distinctAt = $script:HarnessText.IndexOf(
        'if ($ExpectedCoordinatorMachineIdSha256 -ieq ' +
        '$ExpectedPeerMachineIdSha256)')
    $pathGateAt = $script:HarnessText.IndexOf(
        '$null = Assert-I04DisjointOperationalPaths')
    $bindingAt = $script:HarnessText.IndexOf(
        '$candidate = Get-I04CandidateBinding')
    $registryAt = $script:HarnessText.IndexOf(
        '$script:i04AccountRegistryTransaction =', $bindingAt)
    Assert-I04Offline -Condition (
        $distinctAt -ge 0 -and $pathGateAt -gt $distinctAt -and
        $bindingAt -gt $pathGateAt -and $registryAt -gt $bindingAt -and
        $script:HarnessText.Contains(
            'I04 requires two distinct bound physical machine identities')) `
        -Code 'DISTINCT_MACHINE_IDENTITIES_NOT_GATED_BEFORE_MUTATION'
}

Invoke-I04OfflineTest -Id 'OPERATIONAL-ROOTS-DISJOINT-POSITIVE' `
    -Category 'startup_contract' -Body {
    $base = Join-Path $script:TempRoot 'root-contract-positive'
    Assert-I04Offline -Condition ([bool](
        Test-I04OfflineDisjointOperationalPaths `
            -RepositoryDirectory (Join-Path $base 'repository') `
            -PackageDirectory (Join-Path $base 'package') `
            -PackageZip (Join-Path $base 'archive\candidate.zip') `
            -OutputDirectory (Join-Path $base 'output') `
            -CoordinationDirectory (Join-Path $base 'coordination'))) `
        -Code 'DISJOINT_OPERATIONAL_ROOTS_REJECTED'
}

$overlappingRootCases = @(
    [pscustomobject]@{ id = 'PACKAGE-EQUALS-OUTPUT'; repository = 'repository'; package = 'same'; zip = 'zip\candidate.zip'; output = 'same'; coordination = 'coordination' },
    [pscustomobject]@{ id = 'OUTPUT-UNDER-PACKAGE'; repository = 'repository'; package = 'package'; zip = 'zip\candidate.zip'; output = 'package\output'; coordination = 'coordination' },
    [pscustomobject]@{ id = 'PACKAGE-UNDER-OUTPUT'; repository = 'repository'; package = 'output\package'; zip = 'zip\candidate.zip'; output = 'output'; coordination = 'coordination' },
    [pscustomobject]@{ id = 'ZIP-UNDER-PACKAGE'; repository = 'repository'; package = 'package'; zip = 'package\candidate.zip'; output = 'output'; coordination = 'coordination' },
    [pscustomobject]@{ id = 'COORDINATION-UNDER-OUTPUT'; repository = 'repository'; package = 'package'; zip = 'zip\candidate.zip'; output = 'output'; coordination = 'output\coordination' },
    [pscustomobject]@{ id = 'REPOSITORY-EQUALS-OUTPUT'; repository = 'same'; package = 'package'; zip = 'zip\candidate.zip'; output = 'same'; coordination = 'coordination' },
    [pscustomobject]@{ id = 'OUTPUT-UNDER-REPOSITORY'; repository = 'repository'; package = 'package'; zip = 'zip\candidate.zip'; output = 'repository\output'; coordination = 'coordination' },
    [pscustomobject]@{ id = 'REPOSITORY-UNDER-OUTPUT'; repository = 'output\repository'; package = 'package'; zip = 'zip\candidate.zip'; output = 'output'; coordination = 'coordination' },
    [pscustomobject]@{ id = 'REPOSITORY-EQUALS-COORDINATION'; repository = 'same'; package = 'package'; zip = 'zip\candidate.zip'; output = 'output'; coordination = 'same' },
    [pscustomobject]@{ id = 'COORDINATION-UNDER-REPOSITORY'; repository = 'repository'; package = 'package'; zip = 'zip\candidate.zip'; output = 'output'; coordination = 'repository\coordination' },
    [pscustomobject]@{ id = 'REPOSITORY-UNDER-COORDINATION'; repository = 'coordination\repository'; package = 'package'; zip = 'zip\candidate.zip'; output = 'output'; coordination = 'coordination' }
)
foreach ($case in $overlappingRootCases) {
    $capturedCase = $case
    Invoke-I04OfflineTest -Id (
        'OPERATIONAL-ROOTS-OVERLAP-' + $capturedCase.id) `
        -Category 'startup_contract' -Body {
        $base = Join-Path $script:TempRoot (
            'root-contract-' + $capturedCase.id.ToLowerInvariant())
        Assert-I04OfflineThrows -ExpectedCode 'operational roots overlap' `
            -Body {
            Test-I04OfflineDisjointOperationalPaths `
                -RepositoryDirectory (
                    Join-Path $base $capturedCase.repository) `
                -PackageDirectory (Join-Path $base $capturedCase.package) `
                -PackageZip (Join-Path $base $capturedCase.zip) `
                -OutputDirectory (Join-Path $base $capturedCase.output) `
                -CoordinationDirectory (
                    Join-Path $base $capturedCase.coordination)
        }
    }
}

Invoke-I04OfflineTest -Id 'PREEXISTING-EMULE-ZERO-POSITIVE' `
    -Category 'startup_contract' -Body {
    $count = Invoke-I04OfflinePreexistingEmuleGate -ProcessInventory @(
        [pscustomobject]@{ ProcessName = 'explorer' },
        [pscustomobject]@{ ProcessName = 'powershell' }
    )
    Assert-I04OfflineEqual -Actual $count -Expected 0 `
        -Code 'ZERO_PREEXISTING_EMULE_COUNT_REJECTED'
}

Invoke-I04OfflineTest -Id 'PREEXISTING-EMULE-NONZERO-REJECT' `
    -Category 'startup_contract' -Body {
    Assert-I04OfflineThrows `
        -ExpectedCode 'I04 requires zero pre-existing eMule processes' `
        -Body {
        Invoke-I04OfflinePreexistingEmuleGate -ProcessInventory @(
            [pscustomobject]@{ ProcessName = 'eMuLe' }
        )
    }
}

Invoke-I04OfflineTest -Id 'PREEXISTING-EMULE-COLLECTOR-FAIL-CLOSED' `
    -Category 'startup_contract' -Body {
    Assert-I04OfflineThrows -ExpectedCode 'OFFLINE_PROCESS_COLLECTOR_FAILED' `
        -Body {
        Invoke-I04OfflinePreexistingEmuleGate -CollectorFailure
    }
}

Invoke-I04OfflineTest -Id 'PREEXISTING-EMULE-ZERO-EVIDENCE-STATIC' `
    -Category 'startup_contract' -Body {
    Assert-I04Offline -Condition (
        $script:HarnessText.Contains(
            'preexisting_emule_process_count = $preexistingEmuleProcessCount') `
        -and $script:HarnessText.Contains(
            'preexisting_emule_process_absence_proved =') -and
        $script:HarnessText.Contains(
            '$preexistingEmuleProcessCount -eq 0')) `
        -Code 'PREEXISTING_EMULE_ZERO_EVIDENCE_NOT_WIRED'
}

$offlineExpectedHarnessBundle = New-I04OfflineHarnessBundle

Invoke-I04OfflineTest -Id 'HARNESS-BUNDLE-EQUALITY-POSITIVE' `
    -Category 'startup_contract' -Body {
    $copy = $offlineExpectedHarnessBundle | ConvertTo-Json -Depth 6 |
        ConvertFrom-Json
    Assert-I04Offline -Condition ([bool](
        Test-I04OfflineHarnessBundleEqual `
            -Actual $copy -Expected $offlineExpectedHarnessBundle)) `
        -Code 'IDENTICAL_HARNESS_BUNDLE_REJECTED'
}

$offlineHarnessBundleMutations = @(
    [pscustomobject]@{
        id = 'SCHEMA'; property = 'schema'; value = 'legacy'; remove = $false
    },
    [pscustomobject]@{
        id = 'BUNDLE-HASH'; property = 'bundle_sha256';
        value = ('5' * 64); remove = $false
    },
    [pscustomobject]@{
        id = 'HARNESS-HASH'; property = 'harness_sha256';
        value = ('5' * 64); remove = $false
    },
    [pscustomobject]@{
        id = 'COMMON-HASH'; property = 'common_sha256';
        value = ('5' * 64); remove = $false
    },
    [pscustomobject]@{
        id = 'PREPARE-HASH'; property = 'prepare_node_sha256';
        value = ('5' * 64); remove = $false
    },
    [pscustomobject]@{
        id = 'LOCK-FALSE'; property = 'immutable_read_locks_held';
        value = $false; remove = $false
    },
    [pscustomobject]@{
        id = 'LOCK-STRING'; property = 'immutable_read_locks_held';
        value = 'true'; remove = $false
    },
    [pscustomobject]@{
        id = 'COMMON-MISSING'; property = 'common_sha256';
        value = $null; remove = $true
    }
)
foreach ($mutation in $offlineHarnessBundleMutations) {
    $capturedMutation = $mutation
    Invoke-I04OfflineTest -Id (
        'HARNESS-BUNDLE-REJECT-' + $capturedMutation.id) `
        -Category 'startup_contract' -Body {
        $changed = $offlineExpectedHarnessBundle | ConvertTo-Json -Depth 6 |
            ConvertFrom-Json
        if ([bool]$capturedMutation.remove) {
            $changed.PSObject.Properties.Remove($capturedMutation.property)
        } else {
            $changed.PSObject.Properties[$capturedMutation.property].Value =
                $capturedMutation.value
        }
        Assert-I04Offline -Condition (-not [bool](
            Test-I04OfflineHarnessBundleEqual `
                -Actual $changed -Expected $offlineExpectedHarnessBundle)) `
            -Code 'MUTATED_HARNESS_BUNDLE_ACCEPTED'
    }
}

Invoke-I04OfflineTest -Id 'HARNESS-BUNDLE-BOOTSTRAP-LOCKS-STATIC' `
    -Category 'startup_contract' -Body {
    $requiredHashParameters = @(
        'ExpectedHarnessSha256', 'ExpectedCommonSha256',
        'ExpectedPrepareNodeSha256'
    )
    foreach ($name in $requiredHashParameters) {
        $parameter = @($script:HarnessAst.ParamBlock.Parameters |
            Where-Object { $_.Name.VariablePath.UserPath -ceq $name })
        Assert-I04Offline -Condition (
            $parameter.Count -eq 1 -and
            $parameter[0].Extent.Text.Contains(
                '[Parameter(Mandatory = $true)]') -and
            $parameter[0].Extent.Text.Contains(
                "[ValidatePattern('^[0-9a-fA-F]{64}$')]") -and
            $parameter[0].Extent.Text.Contains('[string]$' + $name)) `
            -Code 'HARNESS_BUNDLE_HASH_PARAMETER_NOT_MANDATORY'
    }
    $bootstrapAssignments = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.AssignmentStatementAst] -and
            $node.Left.Extent.Text -ceq '$bootstrapFiles'
    }, $true))
    $bundleAssignments = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.AssignmentStatementAst] -and
            $node.Left.Extent.Text -ceq '$script:i04HarnessBundle'
    }, $true))
    Assert-I04Offline -Condition (
        $bootstrapAssignments.Count -eq 1 -and
        $bundleAssignments.Count -eq 1) `
        -Code 'HARNESS_BUNDLE_BOOTSTRAP_NOT_UNIQUE'
    $bootstrapText = $script:HarnessText.Substring(
        $bootstrapAssignments[0].Extent.StartOffset,
        $bundleAssignments[0].Extent.EndOffset -
            $bootstrapAssignments[0].Extent.StartOffset)
    foreach ($needle in @(
        "path = [IO.Path]::GetFullPath(`$PSCommandPath)",
        "Join-Path `$PSScriptRoot 'common.ps1'",
        "Join-Path `$PSScriptRoot 'prepare_node.ps1'",
        'expected = $ExpectedHarnessSha256.ToLowerInvariant()',
        'expected = $ExpectedCommonSha256.ToLowerInvariant()',
        'expected = $ExpectedPrepareNodeSha256.ToLowerInvariant()',
        '[IO.File]::Open(', '[IO.FileShare]::Read',
        '$script:i04HarnessBundleLocks.Add($stream)',
        'Get-I04BootstrapSha256FromStream -Stream $stream',
        '$observed -cne [string]$entry.Value.expected',
        'I04 harness bundle hash mismatch:',
        "schema = 'ese.v91.i04-harness-bundle/v1'",
        'harness_sha256 = [string]$bootstrapObserved.harness',
        'common_sha256 = [string]$bootstrapObserved.common',
        'prepare_node_sha256 = [string]$bootstrapObserved.prepare_node',
        'bundle_sha256 = Get-I04BootstrapStringSha256',
        'immutable_read_locks_held = $true')) {
        Assert-I04Offline -Condition ($bootstrapText.Contains($needle)) `
            -Code 'HARNESS_BUNDLE_BOOTSTRAP_FIELD_MISSING'
    }
    $bundleEnd = $bundleAssignments[0].Extent.EndOffset
    $commonImport = $script:HarnessText.IndexOf(
        ". (Join-Path `$PSScriptRoot 'common.ps1')")
    Assert-I04Offline -Condition (
        $commonImport -gt $bundleEnd -and
        ([regex]::Matches(
            $script:HarnessText,
            '\$script:i04HarnessBundleLocks\.ToArray\(\)')).Count `
            -ge 2 -and
        ([regex]::Matches(
            $script:HarnessText,
            '\$script:i04HarnessBundleLocks\.Clear\(\)')).Count -ge 2) `
        -Code 'HARNESS_BUNDLE_LOCK_LIFETIME_NOT_OUTER_SCOPED'
}

Invoke-I04OfflineTest -Id 'HARNESS-BUNDLE-ARTIFACT-EQUALITY-STATIC' `
    -Category 'startup_contract' -Body {
    $peer = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Invoke-I04PeerRole'
    }, $true))
    $coordinator = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Invoke-I04CoordinatorRole'
    }, $true))
    Assert-I04Offline -Condition (
        $peer.Count -eq 1 -and $coordinator.Count -eq 1) `
        -Code 'HARNESS_BUNDLE_ROLE_NOT_UNIQUE'

    $runGates = @($peer[0].FindAll({
        param($node)
        $node -is [Management.Automation.Language.IfStatementAst] -and
            $node.Extent.Text.Contains(
                '$runManifest.harness_bundle.schema')
    }, $true))
    $readyAssignments = @($coordinator[0].FindAll({
        param($node)
        $node -is [Management.Automation.Language.AssignmentStatementAst] -and
            $node.Left.Extent.Text -ceq '$peerReadyExact' -and
            $node.Extent.Text.Contains('$peerReady.harness_bundle.schema')
    }, $true))
    $resultAssignments = @($coordinator[0].FindAll({
        param($node)
        $node -is [Management.Automation.Language.AssignmentStatementAst] -and
            $node.Left.Extent.Text -ceq '$peerRestorationExact' -and
            $node.Extent.Text.Contains('$peerResult.harness_bundle.schema')
    }, $true))
    Assert-I04Offline -Condition (
        $runGates.Count -eq 1 -and $readyAssignments.Count -eq 1 -and
        $resultAssignments.Count -eq 1) `
        -Code 'HARNESS_BUNDLE_CONSUMER_GATE_NOT_UNIQUE'
    $consumers = @(
        [pscustomobject]@{
            prefix = 'runManifest'; operator = 'ne';
            text = $runGates[0].Extent.Text; lock_prefix = '-not '
        },
        [pscustomobject]@{
            prefix = 'peerReady'; operator = 'eq';
            text = $readyAssignments[0].Extent.Text; lock_prefix = ''
        },
        [pscustomobject]@{
            prefix = 'peerResult'; operator = 'eq';
            text = $resultAssignments[0].Extent.Text; lock_prefix = ''
        }
    )
    foreach ($consumer in $consumers) {
        foreach ($field in @(
            'bundle_sha256', 'harness_sha256', 'common_sha256',
            'prepare_node_sha256')) {
            $pattern = '\[string\]\$' + $consumer.prefix +
                '\.harness_bundle\.' + $field + '\s*-' +
                $consumer.operator +
                '\s*\[string\]\$script:i04HarnessBundle\.' + $field
            Assert-I04Offline -Condition (
                [regex]::IsMatch($consumer.text, $pattern)) `
                -Code 'HARNESS_BUNDLE_HASH_EQUALITY_GATE_MISSING'
        }
        Assert-I04Offline -Condition (
            $consumer.text.Contains(
                '$' + $consumer.prefix + '.harness_bundle.schema') -and
            $consumer.text.Contains('ese.v91.i04-harness-bundle/v1') -and
            [regex]::IsMatch(
                $consumer.text,
                [regex]::Escape($consumer.lock_prefix) +
                '\[bool\]\$' + $consumer.prefix +
                '\.harness_bundle\.\s*immutable_read_locks_held')) `
            -Code 'HARNESS_BUNDLE_SCHEMA_OR_LOCK_GATE_MISSING'
    }

    $producerContracts = @(
        [pscustomobject]@{
            scope = $coordinator[0]; schema = 'ese.v91.i04-run/v1'
        },
        [pscustomobject]@{
            scope = $peer[0]; schema = 'ese.v91.i04-peer-ready/v1'
        },
        [pscustomobject]@{
            scope = $peer[0]; schema = 'ese.v91.i04-peer-result/v1'
        },
        [pscustomobject]@{
            scope = $coordinator[0]; schema = 'ese.v91.i04-fallback/v1'
        }
    )
    foreach ($contract in $producerContracts) {
        $maps = @($contract.scope.FindAll({
            param($node)
            $node -is [Management.Automation.Language.HashtableAst] -and
                $node.Extent.Text.Contains("schema = '$($contract.schema)'") -and
                $node.Extent.Text.Contains(
                    'harness_bundle = $script:i04HarnessBundle')
        }, $true))
        Assert-I04Offline -Condition ($maps.Count -eq 1) `
            -Code 'HARNESS_BUNDLE_ARTIFACT_PRODUCER_MISSING'
    }

    $remoteAssignments = @($coordinator[0].FindAll({
        param($node)
        $node -is [Management.Automation.Language.AssignmentStatementAst] -and
            $node.Left.Extent.Text -ceq '$remoteArguments'
    }, $true))
    $manualAssignments = @($coordinator[0].FindAll({
        param($node)
        $node -is [Management.Automation.Language.AssignmentStatementAst] -and
            $node.Left.Extent.Text -ceq '$manualCommand'
    }, $true))
    Assert-I04Offline -Condition (
        $remoteAssignments.Count -eq 1 -and $manualAssignments.Count -eq 1) `
        -Code 'HARNESS_BUNDLE_LAUNCH_ARGUMENTS_NOT_UNIQUE'
    $remoteText = $remoteAssignments[0].Extent.Text
    $manualText = $manualAssignments[0].Extent.Text
    $launchHashes = [ordered]@{
        ExpectedHarnessSha256 = 'harness_sha256'
        ExpectedCommonSha256 = 'common_sha256'
        ExpectedPrepareNodeSha256 = 'prepare_node_sha256'
    }
    foreach ($entry in $launchHashes.GetEnumerator()) {
        Assert-I04Offline -Condition (
            $remoteText.Contains([string]$entry.Key) -and
            $remoteText.Contains(
                '$script:i04HarnessBundle.' + [string]$entry.Value) -and
            $manualText.Contains('-' + [string]$entry.Key) -and
            $manualText.Contains(
                '$script:i04HarnessBundle.' + [string]$entry.Value)) `
            -Code 'HARNESS_BUNDLE_MANUAL_OR_REMOTING_HASH_MISSING'
    }
}

$managedHelperContracts = @(
    [pscustomobject]@{
        id = 'COPYDATA'; function_name = 'Initialize-I04CopyData';
        type_name = 'V91I04CopyData';
        contract_id = 'ese.v91.i04-copydata/2026-08-01.v1'
    },
    [pscustomobject]@{
        id = 'UI'; function_name = 'Initialize-I04UiProbe';
        type_name = 'V91I04UiProbe';
        contract_id = 'ese.v91.i04-ui-probe/2026-08-01.v1'
    },
    [pscustomobject]@{
        id = 'ETW'; function_name = 'Get-I04EtwLossEvidence';
        type_name = 'V91I04EtwTraceControlV2';
        contract_id = 'ese.v91.i04-etw-trace-control/2026-08-01.v1'
    },
    [pscustomobject]@{
        id = 'SAMPLER'; function_name = 'Initialize-I04SocketSampler';
        type_name = 'V91I04SocketSampler';
        contract_id = 'ese.v91.i04-socket-sampler/2026-08-01.v1'
    },
    [pscustomobject]@{
        id = 'RESTRICTED-LAUNCHER';
        function_name = 'Initialize-I04RestrictedProcessLauncher';
        type_name = 'V91I04RestrictedProcessLauncher';
        contract_id =
            'ese.v91.i04-restricted-process-launcher/2026-08-01.v1'
    }
)
foreach ($contract in $managedHelperContracts) {
    $capturedContract = $contract
    Invoke-I04OfflineTest -Id (
        'MANAGED-HELPER-CONTRACT-MISMATCH-' + $capturedContract.id +
        '-REJECT') -Category 'startup_contract' -Body {
        Assert-I04OfflineThrows `
            -ExpectedCode 'Managed helper contract mismatch' -Body {
            Test-I04OfflineManagedTypeContract `
                -TypeName 'System.String' `
                -ExpectedContractId $capturedContract.contract_id
        }
    }
}

Invoke-I04OfflineTest -Id 'MANAGED-HELPER-MISSING-TYPE-REJECT' `
    -Category 'startup_contract' -Body {
    Assert-I04OfflineThrows `
        -ExpectedCode 'Required managed helper type is unavailable' -Body {
        Test-I04OfflineManagedTypeContract `
            -TypeName 'V91I04OfflineDefinitelyMissingManagedType' `
            -ExpectedContractId 'ese.v91.i04-ui-probe/2026-08-01.v1'
    }
}

Invoke-I04OfflineTest -Id 'MANAGED-HELPER-CONTRACTS-WIRED-STATIC' `
    -Category 'startup_contract' -Body {
    foreach ($contract in $managedHelperContracts) {
        $functions = @($script:HarnessAst.FindAll({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] `
                -and $node.Name -ceq $contract.function_name
        }, $true))
        Assert-I04Offline -Condition ($functions.Count -eq 1) `
            -Code 'MANAGED_HELPER_INITIALIZER_NOT_UNIQUE'
        $function = $functions[0]
        $text = $function.Extent.Text
        $assertions = @($function.FindAll({
            param($node)
            $node -is [Management.Automation.Language.CommandAst] -and
                $node.GetCommandName() -ceq 'Assert-I04ManagedTypeContract'
        }, $true))
        $addTypes = @($function.FindAll({
            param($node)
            $node -is [Management.Automation.Language.CommandAst] -and
                $node.GetCommandName() -ceq 'Add-Type'
        }, $true))
        $existingTypeGates = @($function.FindAll({
            param($node)
            $node -is [Management.Automation.Language.IfStatementAst] -and
                $node.Extent.Text.Contains(
                    "'$($contract.type_name)' -as [type]") -and
                $node.Extent.Text.Contains('Assert-I04ManagedTypeContract')
        }, $true))
        Assert-I04Offline -Condition (
            $assertions.Count -eq 2 -and $addTypes.Count -eq 1 -and
            $existingTypeGates.Count -eq 1 -and
            $assertions[0].Extent.StartOffset -lt
                $addTypes[0].Extent.StartOffset -and
            $assertions[1].Extent.StartOffset -gt
                $addTypes[0].Extent.EndOffset -and
            $text.Contains("-TypeName '$($contract.type_name)'") -and
            $text.Contains('-ExpectedContractId $contractId') -and
            $text.Contains(
                "`$contractId = '$($contract.contract_id)'") -and
            $text.Contains(
                'public const string ContractId = "' +
                $contract.contract_id + '";')) `
            -Code 'MANAGED_HELPER_CONTRACT_GATE_NOT_BOTH_SIDES_OF_ADD_TYPE'
    }
    $uiConsumers = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Get-I04UiProbe'
    }, $true))
    $samplerConsumers = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Start-I04SocketSampler'
    }, $true))
    $copyDataConsumers = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Send-I04Ed2kLink'
    }, $true))
    Assert-I04Offline -Condition (
        $uiConsumers.Count -eq 1 -and $samplerConsumers.Count -eq 1 -and
        $copyDataConsumers.Count -eq 1 -and
        $uiConsumers[0].Extent.Text.Contains('Initialize-I04UiProbe') -and
        $samplerConsumers[0].Extent.Text.Contains(
            'Initialize-I04SocketSampler') -and
        $copyDataConsumers[0].Extent.Text.Contains(
            'Initialize-I04CopyData')) `
        -Code 'MANAGED_HELPER_INITIALIZER_NOT_CONSUMED'
}

Invoke-I04OfflineTest -Id 'OFFLINE-NEVER-INVOKES-PHYSICAL-HARNESS' `
    -Category 'side_effect_guard' -Body {
    $tokens = $null
    $errors = $null
    $selfAst = [Management.Automation.Language.Parser]::ParseFile(
        $script:SelfPath, [ref]$tokens, [ref]$errors)
    $physicalCalls = @($selfAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.CommandAst] -and
        $node.GetCommandName() -cin @(
            'Invoke-I04CoordinatorRole', 'Invoke-I04PeerRole',
            'Start-I04PacketCapture', 'Start-I04SocketSampler',
            'Start-Process', 'Invoke-I04Pktmon')
    }, $true))
    $harnessInvocations = @($selfAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.CommandAst] -and
        $node.InvocationOperator -ne
            [Management.Automation.Language.TokenKind]::Unknown -and
        $node.Extent.Text -match '(?i)Harness(Path|Text|Bytes)'
    }, $true))
    Assert-I04Offline -Condition (
        $physicalCalls.Count -eq 0 -and $harnessInvocations.Count -eq 0 -and
        $script:HarnessText.Length -gt 0) `
        -Code 'PHYSICAL_HARNESS_EXECUTION_PATH_FOUND'
}

Invoke-I04OfflineTest -Id 'HARNESS-SINGLE-BYTE-SNAPSHOT-STATIC' `
    -Category 'side_effect_guard' -Body {
    $selfText = [IO.File]::ReadAllText($script:SelfPath)
    Assert-I04Offline -Condition (
        ([regex]::Matches(
            $selfText, '\$script:HarnessBytes\s*=\s*' +
                '\[IO\.File\]::ReadAllBytes')).Count -eq 1 -and
        $selfText.Contains(
            '[Management.Automation.Language.Parser]::ParseInput') -and
        $selfText.Contains('HARNESS_BYTES_CHANGED_DURING_OFFLINE_RUN')) `
        -Code 'HARNESS_SINGLE_SNAPSHOT_OR_TOCTOU_GUARD_MISSING'
}

Invoke-I04OfflineTest -Id 'FALLBACK-TIMING-CONSTANTS-STATIC' `
    -Category 'fallback_contract' -Body {
    foreach ($needle in @(
        '$expectedFallbackDelayMs = 3000',
        '$captureTimingToleranceMs = 250',
        '$minimumSilentWindowMs = $expectedFallbackDelayMs -',
        '$planningUpperBoundMs = [Math]::Min($limitMs, 8000)',
        '$fallbackMs -ge $MinimumSilentWindowMs',
        '$fallbackMs -lt $planningUpperBoundMs')) {
        Assert-I04Offline -Condition ($script:HarnessText.Contains($needle)) `
            -Code 'FALLBACK_2750_TO_LT_8000_CONTRACT_MISSING'
    }
}

$requiredAddressCases = @(
    [pscustomobject]@{
        id = 'V4'; value = '8.8.8.8'
        family = [Net.Sockets.AddressFamily]::InterNetwork
        expected = '8.8.8.8'
    },
    [pscustomobject]@{
        id = 'V6'; value = '2001:4860:0:0:0:0:0:20%7'
        family = [Net.Sockets.AddressFamily]::InterNetworkV6
        expected = '2001:4860::20'
    }
)
foreach ($case in $requiredAddressCases) {
    $capturedCase = $case
    Invoke-I04OfflineTest -Id ('ADDRESS-REQUIRED-' + $capturedCase.id) `
        -Category 'address_parser' -Body {
        $actual = Convert-I04OfflineRequiredAddress `
            -Value $capturedCase.value `
            -AddressFamily $capturedCase.family
        Assert-I04OfflineEqual -Actual $actual.ToString() `
            -Expected $capturedCase.expected `
            -Code 'REQUIRED_ADDRESS_CANONICALIZATION_FAILED'
    }
}

$rejectedAddressCases = @(
    [pscustomobject]@{
        id = 'V4-AS-V6'; value = '8.8.8.8'
        family = [Net.Sockets.AddressFamily]::InterNetworkV6
    },
    [pscustomobject]@{
        id = 'V6-AS-V4'; value = '2001:4860::20'
        family = [Net.Sockets.AddressFamily]::InterNetwork
    },
    [pscustomobject]@{
        id = 'MAPPED-V6'; value = '::ffff:8.8.8.8'
        family = [Net.Sockets.AddressFamily]::InterNetworkV6
    },
    [pscustomobject]@{
        id = 'MALFORMED'; value = 'not-an-address'
        family = [Net.Sockets.AddressFamily]::InterNetwork
    }
)
foreach ($case in $rejectedAddressCases) {
    $capturedCase = $case
    Invoke-I04OfflineTest -Id ('ADDRESS-REJECT-' + $capturedCase.id) `
        -Category 'address_parser' -Body {
        Assert-I04OfflineThrows -ExpectedCode 'not an address' -Body {
            Convert-I04OfflineRequiredAddress `
                -Value $capturedCase.value `
                -AddressFamily $capturedCase.family
        }
    }
}

$normalizedAddressCases = @(
    [pscustomobject]@{ id = 'V4'; value = '8.8.8.8'; expected = '8.8.8.8' },
    [pscustomobject]@{ id = 'V6'; value = '2001:4860:0:0::20%9'; expected = '2001:4860::20' },
    [pscustomobject]@{ id = 'MAPPED'; value = '::ffff:8.8.4.4'; expected = '8.8.4.4' },
    [pscustomobject]@{ id = 'INVALID'; value = 'invalid-fixture'; expected = 'invalid-fixture' }
)
foreach ($case in $normalizedAddressCases) {
    $capturedCase = $case
    Invoke-I04OfflineTest -Id ('ADDRESS-NORMALIZE-' + $capturedCase.id) `
        -Category 'address_parser' -Body {
        Assert-I04OfflineEqual `
            -Actual (Get-I04OfflineNormalizedIp $capturedCase.value) `
            -Expected $capturedCase.expected `
            -Code 'ADDRESS_NORMALIZATION_MISMATCH'
    }
}

$strictAddressClassCases = @(
    [pscustomobject]@{ id='INVALID'; address='not-an-ip'; expected='invalid' },
    [pscustomobject]@{ id='V4-UNSPECIFIED'; address='0.1.2.3'; expected='unspecified-or-this-network-v4' },
    [pscustomobject]@{ id='V4-PRIVATE-10'; address='10.1.2.3'; expected='private-v4' },
    [pscustomobject]@{ id='V4-PRIVATE-172'; address='172.31.255.254'; expected='private-v4' },
    [pscustomobject]@{ id='V4-PRIVATE-192'; address='192.168.1.1'; expected='private-v4' },
    [pscustomobject]@{ id='V4-CGNAT'; address='100.64.0.1'; expected='shared-cgnat-v4' },
    [pscustomobject]@{ id='V4-LOOPBACK'; address='127.0.0.1'; expected='loopback-v4' },
    [pscustomobject]@{ id='V4-LINKLOCAL'; address='169.254.1.1'; expected='linklocal-v4' },
    [pscustomobject]@{ id='V4-DOCUMENTATION'; address='192.0.2.1'; expected='special-purpose-v4' },
    [pscustomobject]@{ id='V4-BENCHMARK'; address='198.18.0.1'; expected='special-purpose-v4' },
    [pscustomobject]@{ id='V4-MULTICAST'; address='239.1.2.3'; expected='multicast-or-reserved-v4' },
    [pscustomobject]@{ id='V4-PUBLIC'; address='8.8.8.8'; expected='public-unicast-v4' },
    [pscustomobject]@{ id='V6-MAPPED'; address='::ffff:8.8.8.8'; expected='non-native-v6' },
    [pscustomobject]@{ id='V6-UNSPECIFIED'; address='::'; expected='non-global-unicast-v6' },
    [pscustomobject]@{ id='V6-LOOPBACK'; address='::1'; expected='loopback-v6' },
    [pscustomobject]@{ id='V6-LINKLOCAL'; address='fe80::1'; expected='linklocal-v6' },
    [pscustomobject]@{ id='V6-MULTICAST'; address='ff02::1'; expected='multicast-v6' },
    [pscustomobject]@{ id='V6-ULA'; address='fd12:3456::1'; expected='ula-v6' },
    [pscustomobject]@{ id='V6-NON-GLOBAL'; address='64:ff9b::1'; expected='non-global-unicast-v6' },
    [pscustomobject]@{ id='V6-TEREDO'; address='2001:0:1234::1'; expected='transition-or-documentation-v6' },
    [pscustomobject]@{ id='V6-ORCHID'; address='2001:10::1'; expected='transition-or-documentation-v6' },
    [pscustomobject]@{ id='V6-DOCUMENTATION'; address='2001:db8::1'; expected='transition-or-documentation-v6' },
    [pscustomobject]@{ id='V6-6TO4'; address='2002:c000:0201::1'; expected='transition-or-documentation-v6' },
    [pscustomobject]@{ id='V6-DOC-3FFF'; address='3fff:000::1'; expected='transition-or-documentation-v6' },
    [pscustomobject]@{ id='V6-AS112-DIRECT-DELEGATION'; address='2620:4f:8000::1'; expected='transition-or-documentation-v6' },
    [pscustomobject]@{ id='V6-AS112-SERVICE'; address='2001:4:112::1'; expected='transition-or-documentation-v6' },
    [pscustomobject]@{ id='V6-NATIVE-GLOBAL'; address='2001:4860:4860::8888'; expected='native-global-v6' }
)
foreach ($case in $strictAddressClassCases) {
    $capturedCase = $case
    Invoke-I04OfflineTest `
        -Id ('ADDRESS-STRICT-CLASS-' + $capturedCase.id) `
        -Category 'address_classifier' -Body {
        Assert-I04OfflineEqual `
            -Actual (Get-I04OfflineStrictAddressClass `
                -Address $capturedCase.address) `
            -Expected $capturedCase.expected `
            -Code 'STRICT_ADDRESS_CLASS_MISMATCH'
    }
}

$safeArchivePathCases = @(
    [pscustomobject]@{ id='FILE'; path='config/preferences.ini'; directory=$false; expected='config/preferences.ini' },
    [pscustomobject]@{ id='UNICODE-NFC'; path="caf$([char]0x00e9).txt"; directory=$false; expected="caf$([char]0x00e9).txt" },
    [pscustomobject]@{ id='DIRECTORY'; path='config/'; directory=$true; expected='config' }
)
foreach ($case in $safeArchivePathCases) {
    $capturedCase = $case
    Invoke-I04OfflineTest -Id ('ARCHIVE-PATH-ACCEPT-' + $capturedCase.id) `
        -Category 'package_binding' -Body {
        $actual = Convert-I04OfflineSafeRelativePath `
            -Path $capturedCase.path `
            -AllowTrailingSlash:$capturedCase.directory
        Assert-I04OfflineEqual -Actual $actual `
            -Expected $capturedCase.expected `
            -Code 'SAFE_ARCHIVE_PATH_CHANGED'
    }
}

$unsafeArchivePathCases = @(
    [pscustomobject]@{ id='WHITESPACE'; path=' '; expected='Unsafe archive' },
    [pscustomobject]@{ id='ABSOLUTE'; path='/root/file'; expected='Unsafe archive' },
    [pscustomobject]@{ id='DRIVE'; path='C:/file'; expected='Unsafe archive' },
    [pscustomobject]@{ id='BACKSLASH'; path='a\b'; expected='Unsafe archive' },
    [pscustomobject]@{ id='TRAVERSAL'; path='../escape'; expected='path segment' },
    [pscustomobject]@{ id='NESTED-TRAVERSAL'; path='a/../escape'; expected='path segment' },
    [pscustomobject]@{ id='DOT'; path='./file'; expected='path segment' },
    [pscustomobject]@{ id='EMPTY-SEGMENT'; path='a//b'; expected='path segment' },
    [pscustomobject]@{ id='FILE-TRAILING-SLASH'; path='file/'; expected='Unsafe archive file path' },
    [pscustomobject]@{ id='TRAILING-DOT'; path='file.'; expected='path segment' },
    [pscustomobject]@{ id='TRAILING-SPACE'; path='file '; expected='path segment' },
    [pscustomobject]@{ id='INVALID-CHAR'; path='bad?.txt'; expected='path segment' },
    [pscustomobject]@{ id='DEVICE'; path='dir/CON.txt'; expected='Reserved Windows device' },
    [pscustomobject]@{ id='NON-NFC'; path="cafe$([char]0x0301).txt"; expected='canonical Unicode NFC' }
)
foreach ($case in $unsafeArchivePathCases) {
    $capturedCase = $case
    Invoke-I04OfflineTest -Id ('ARCHIVE-PATH-REJECT-' + $capturedCase.id) `
        -Category 'package_binding' -Body {
        Assert-I04OfflineThrows -ExpectedCode $capturedCase.expected -Body {
            Convert-I04OfflineSafeRelativePath -Path $capturedCase.path
        }
    }
}

Invoke-I04OfflineTest -Id 'PACKAGE-SAFE-TREE-CANONICAL' `
    -Category 'package_binding' -Body {
    $package = New-I04OfflinePackageFixture -Name 'safe-tree'
    $files = @(Get-I04OfflineSafeTreeFiles -Root $package)
    $names = @($files | ForEach-Object relative_path)
    Assert-I04Offline -Condition (
        $files.Count -eq 6 -and
        $names -ccontains 'emule.exe' -and
        $names -ccontains 'config/preferences.ini' -and
        $names -ccontains 'bin/support.dll' -and
        @($names | Where-Object { $_.Contains('\') }).Count -eq 0) `
        -Code 'SAFE_TREE_ENUMERATION_MISMATCH'
}

Invoke-I04OfflineTest -Id 'PACKAGE-ZIP-EXACT-BINDING' `
    -Category 'package_binding' -Body {
    $fixture = New-I04OfflineBindingFixture -Name 'binding-positive'
    $binding = Get-I04OfflineCandidateBinding `
        -DirectoryPath $fixture.package -ZipPath $fixture.zip `
        -ExpectedZipSha256 $fixture.zip_sha256 `
        -ExpectedExeSha256 $fixture.exe_sha256 `
        -ExpectedCommit $fixture.commit
    Assert-I04Offline -Condition (
        [string]$binding.package_zip_sha256 -ceq $fixture.zip_sha256 -and
        [string]$binding.emule_sha256 -ceq $fixture.exe_sha256 -and
        [string]$binding.commit -ceq $fixture.commit -and
        [int]$binding.package_file_count -eq 6 -and
        [bool]$binding.immutable_locks_held -and
        [string]$binding.package_manifest_sha256 -match '^[0-9a-f]{64}$') `
        -Code 'EXACT_PACKAGE_ZIP_BINDING_REJECTED'
}

Invoke-I04OfflineTest -Id 'PACKAGE-BINDING-UNCHANGED-POSITIVE' `
    -Category 'package_binding' -Body {
    $fixture = New-I04OfflineBindingFixture -Name 'binding-unchanged'
    $binding = Get-I04OfflineCandidateBinding `
        -DirectoryPath $fixture.package -ZipPath $fixture.zip `
        -ExpectedZipSha256 $fixture.zip_sha256 `
        -ExpectedExeSha256 $fixture.exe_sha256
    Assert-I04Offline -Condition ([bool](
        Test-I04OfflineCandidateBindingUnchanged -Binding $binding)) `
        -Code 'UNCHANGED_PACKAGE_BINDING_REJECTED'
}

Invoke-I04OfflineTest -Id 'PACKAGE-BINDING-DIRECTORY-TAMPER-REJECT' `
    -Category 'package_binding' -Body {
    $fixture = New-I04OfflineBindingFixture -Name 'binding-dir-tamper'
    $binding = Get-I04OfflineCandidateBinding `
        -DirectoryPath $fixture.package -ZipPath $fixture.zip `
        -ExpectedZipSha256 $fixture.zip_sha256 `
        -ExpectedExeSha256 $fixture.exe_sha256
    [IO.File]::AppendAllText(
        (Join-Path $fixture.package 'bin\support.dll'), 'tamper')
    Assert-I04OfflineThrows -ExpectedCode 'Candidate package file changed' `
        -Body {
        Test-I04OfflineCandidateBindingUnchanged -Binding $binding
    }
}

Invoke-I04OfflineTest -Id 'PACKAGE-BINDING-ZIP-TAMPER-REJECT' `
    -Category 'package_binding' -Body {
    $fixture = New-I04OfflineBindingFixture -Name 'binding-zip-tamper'
    $binding = Get-I04OfflineCandidateBinding `
        -DirectoryPath $fixture.package -ZipPath $fixture.zip `
        -ExpectedZipSha256 $fixture.zip_sha256 `
        -ExpectedExeSha256 $fixture.exe_sha256
    $append = [IO.File]::Open(
        $fixture.zip, [IO.FileMode]::Append, [IO.FileAccess]::Write,
        [IO.FileShare]::None)
    try { $append.WriteByte(0x5a) } finally { $append.Dispose() }
    Assert-I04OfflineThrows -ExpectedCode 'Locked package ZIP changed' -Body {
        Test-I04OfflineCandidateBindingUnchanged -Binding $binding
    }
}

Invoke-I04OfflineTest -Id 'PACKAGE-ZIP-HASH-MISMATCH-REJECT' `
    -Category 'package_binding' -Body {
    $fixture = New-I04OfflineBindingFixture -Name 'binding-hash-mismatch'
    Assert-I04OfflineThrows -ExpectedCode 'Package ZIP hash mismatch' -Body {
        Get-I04OfflineCandidateBinding `
            -DirectoryPath $fixture.package -ZipPath $fixture.zip `
            -ExpectedZipSha256 ('0' * 64) `
            -ExpectedExeSha256 $fixture.exe_sha256
    }
}

Invoke-I04OfflineTest -Id 'PACKAGE-ZIP-CONTENT-MISMATCH-REJECT' `
    -Category 'package_binding' -Body {
    $fixture = New-I04OfflineBindingFixture -Name 'binding-content-mismatch'
    [IO.File]::AppendAllText(
        (Join-Path $fixture.package 'bin\support.dll'), 'tamper')
    Assert-I04OfflineThrows -ExpectedCode 'ZIP/package content mismatch' `
        -Body {
        Get-I04OfflineCandidateBinding `
            -DirectoryPath $fixture.package -ZipPath $fixture.zip `
            -ExpectedZipSha256 $fixture.zip_sha256 `
            -ExpectedExeSha256 $fixture.exe_sha256
    }
}

Invoke-I04OfflineTest -Id 'PACKAGE-ZIP-TRAVERSAL-REJECT' `
    -Category 'package_binding' -Body {
    $package = New-I04OfflinePackageFixture -Name 'zip-traversal-package'
    $entries = @(Get-I04OfflinePackageEntrySpecs -PackagePath $package)
    $entries += [pscustomobject]@{
        name = '../escape.txt'
        bytes = [Text.Encoding]::UTF8.GetBytes('escape')
    }
    $zip = New-I04OfflineZip `
        -Path (Join-Path $script:TempRoot 'zip-traversal.zip') `
        -Entries $entries
    Assert-I04OfflineThrows -ExpectedCode 'Unsafe archive path segment' `
        -Body {
        Get-I04OfflineCandidateBinding -DirectoryPath $package `
            -ZipPath $zip `
            -ExpectedZipSha256 (Get-I04OfflineFileSha256 -Path $zip) `
            -ExpectedExeSha256 (Get-I04OfflineFileSha256 -Path (
                Join-Path $package 'emule.exe'))
    }
}

Invoke-I04OfflineTest -Id 'PACKAGE-ZIP-CASE-COLLISION-REJECT' `
    -Category 'package_binding' -Body {
    $package = New-I04OfflinePackageFixture -Name 'zip-case-package'
    $entries = @(Get-I04OfflinePackageEntrySpecs -PackagePath $package)
    $entries += [pscustomobject]@{
        name = 'Case.txt'; bytes = [byte[]]@(1)
    }, [pscustomobject]@{
        name = 'case.txt'; bytes = [byte[]]@(2)
    }
    $zip = New-I04OfflineZip `
        -Path (Join-Path $script:TempRoot 'zip-case.zip') -Entries $entries
    Assert-I04OfflineThrows -ExpectedCode 'case/Unicode path collision' `
        -Body {
        Get-I04OfflineCandidateBinding -DirectoryPath $package `
            -ZipPath $zip `
            -ExpectedZipSha256 (Get-I04OfflineFileSha256 -Path $zip) `
            -ExpectedExeSha256 (Get-I04OfflineFileSha256 -Path (
                Join-Path $package 'emule.exe'))
    }
}

Invoke-I04OfflineTest -Id 'PACKAGE-ZIP-NON-NFC-REJECT' `
    -Category 'package_binding' -Body {
    $package = New-I04OfflinePackageFixture -Name 'zip-nonnfc-package'
    $entries = @(Get-I04OfflinePackageEntrySpecs -PackagePath $package)
    $entries += [pscustomobject]@{
        name = "cafe$([char]0x0301).txt"; bytes = [byte[]]@(1)
    }
    $zip = New-I04OfflineZip `
        -Path (Join-Path $script:TempRoot 'zip-nonnfc.zip') -Entries $entries
    Assert-I04OfflineThrows -ExpectedCode 'canonical Unicode NFC' -Body {
        Get-I04OfflineCandidateBinding -DirectoryPath $package `
            -ZipPath $zip `
            -ExpectedZipSha256 (Get-I04OfflineFileSha256 -Path $zip) `
            -ExpectedExeSha256 (Get-I04OfflineFileSha256 -Path (
                Join-Path $package 'emule.exe'))
    }
}

Invoke-I04OfflineTest -Id 'PACKAGE-ZIP-SYMLINK-REJECT' `
    -Category 'package_binding' -Body {
    $package = New-I04OfflinePackageFixture -Name 'zip-symlink-package'
    $entries = @(Get-I04OfflinePackageEntrySpecs -PackagePath $package)
    $entries += [pscustomobject]@{
        name = 'symlink-entry'
        bytes = [Text.Encoding]::UTF8.GetBytes('outside-target')
        external_attributes = -1610612736
    }
    $zip = New-I04OfflineZip `
        -Path (Join-Path $script:TempRoot 'zip-symlink.zip') `
        -Entries $entries
    Assert-I04OfflineThrows -ExpectedCode 'symlink/reparse entry' -Body {
        Get-I04OfflineCandidateBinding -DirectoryPath $package `
            -ZipPath $zip `
            -ExpectedZipSha256 (Get-I04OfflineFileSha256 -Path $zip) `
            -ExpectedExeSha256 (Get-I04OfflineFileSha256 -Path (
                Join-Path $package 'emule.exe'))
    }
}

Invoke-I04OfflineTest -Id 'PACKAGE-ZIP-DUPLICATE-EMULE-REJECT' `
    -Category 'package_binding' -Body {
    $package = New-I04OfflinePackageFixture -Name 'zip-two-exe-package'
    $entries = @(Get-I04OfflinePackageEntrySpecs -PackagePath $package)
    $entries += [pscustomobject]@{
        name = 'nested/emule.exe'; bytes = [byte[]]@(1, 2, 3)
    }
    $zip = New-I04OfflineZip `
        -Path (Join-Path $script:TempRoot 'zip-two-exe.zip') `
        -Entries $entries
    Assert-I04OfflineThrows -ExpectedCode 'exactly one emule.exe' -Body {
        Get-I04OfflineCandidateBinding -DirectoryPath $package `
            -ZipPath $zip `
            -ExpectedZipSha256 (Get-I04OfflineFileSha256 -Path $zip) `
            -ExpectedExeSha256 (Get-I04OfflineFileSha256 -Path (
                Join-Path $package 'emule.exe'))
    }
}

Invoke-I04OfflineTest -Id 'PACKAGE-ZIP-LOGICAL-ROOT-ESCAPE-REJECT' `
    -Category 'package_binding' -Body {
    $package = New-I04OfflinePackageFixture -Name 'zip-root-package'
    $entries = @(Get-I04OfflinePackageEntrySpecs -PackagePath $package |
        ForEach-Object {
        [pscustomobject]@{
            name = 'candidate/' + [string]$_.name
            bytes = [byte[]]$_.bytes
        }
    })
    $entries += [pscustomobject]@{
        name = 'outside.txt'; bytes = [byte[]]@(1)
    }
    $zip = New-I04OfflineZip `
        -Path (Join-Path $script:TempRoot 'zip-root.zip') -Entries $entries
    Assert-I04OfflineThrows -ExpectedCode 'outside the candidate root' -Body {
        Get-I04OfflineCandidateBinding -DirectoryPath $package `
            -ZipPath $zip `
            -ExpectedZipSha256 (Get-I04OfflineFileSha256 -Path $zip) `
            -ExpectedExeSha256 (Get-I04OfflineFileSha256 -Path (
                Join-Path $package 'emule.exe'))
    }
}

Invoke-I04OfflineTest -Id 'PACKAGE-ZIP-MISSING-FILE-REJECT' `
    -Category 'package_binding' -Body {
    $package = New-I04OfflinePackageFixture -Name 'zip-missing-package'
    $entries = @(Get-I04OfflinePackageEntrySpecs -PackagePath $package |
        Where-Object name -cne 'empty.dat')
    $zip = New-I04OfflineZip `
        -Path (Join-Path $script:TempRoot 'zip-missing.zip') `
        -Entries $entries
    Assert-I04OfflineThrows -ExpectedCode 'file-count mismatch' -Body {
        Get-I04OfflineCandidateBinding -DirectoryPath $package `
            -ZipPath $zip `
            -ExpectedZipSha256 (Get-I04OfflineFileSha256 -Path $zip) `
            -ExpectedExeSha256 (Get-I04OfflineFileSha256 -Path (
                Join-Path $package 'emule.exe'))
    }
}

Invoke-I04OfflineTest -Id 'PACKAGE-ZIP-EXTRA-FILE-REJECT' `
    -Category 'package_binding' -Body {
    $package = New-I04OfflinePackageFixture -Name 'zip-extra-package'
    $entries = @(Get-I04OfflinePackageEntrySpecs -PackagePath $package)
    $entries += [pscustomobject]@{
        name = 'extra.txt'; bytes = [byte[]]@(1)
    }
    $zip = New-I04OfflineZip `
        -Path (Join-Path $script:TempRoot 'zip-extra.zip') -Entries $entries
    Assert-I04OfflineThrows -ExpectedCode 'file-count mismatch' -Body {
        Get-I04OfflineCandidateBinding -DirectoryPath $package `
            -ZipPath $zip `
            -ExpectedZipSha256 (Get-I04OfflineFileSha256 -Path $zip) `
            -ExpectedExeSha256 (Get-I04OfflineFileSha256 -Path (
                Join-Path $package 'emule.exe'))
    }
}

Invoke-I04OfflineTest -Id 'PACKAGE-OWNED-LAB-NODE-REJECT' `
    -Category 'package_binding' -Body {
    $package = New-I04OfflinePackageFixture -Name 'package-lab-node'
    [IO.File]::WriteAllText(
        (Join-Path $package 'LAB_NODE.json'), '{}',
        [Text.UTF8Encoding]::new($false))
    $zip = New-I04OfflineValidZip -Name 'package-lab-node.zip' `
        -PackagePath $package
    Assert-I04OfflineThrows `
        -ExpectedCode 'may not predefine the harness-owned LAB_NODE.json' `
        -Body {
        Get-I04OfflineCandidateBinding -DirectoryPath $package `
            -ZipPath $zip `
            -ExpectedZipSha256 (Get-I04OfflineFileSha256 -Path $zip) `
            -ExpectedExeSha256 (Get-I04OfflineFileSha256 -Path (
                Join-Path $package 'emule.exe'))
    }
}

Invoke-I04OfflineTest -Id 'PACKAGE-TREE-REPARSE-REJECT' `
    -Category 'package_binding' -Body {
    $package = New-I04OfflinePackageFixture -Name 'package-reparse'
    $target = Assert-I04OfflineTempPath -Path (
        Join-Path $script:TempRoot 'junction-target')
    New-Item -ItemType Directory -Path $target -ErrorAction Stop | Out-Null
    [IO.File]::WriteAllText((Join-Path $target 'outside.txt'), 'outside')
    New-Item -ItemType Junction -Path (Join-Path $package 'linked') `
        -Target $target -ErrorAction Stop | Out-Null
    Assert-I04OfflineThrows -ExpectedCode 'reparse point' -Body {
        Get-I04OfflineSafeTreeFiles -Root $package
    }
}

Invoke-I04OfflineTest -Id 'PACKAGE-BINDING-TOCTOU-STATIC' `
    -Category 'package_binding' -Body {
    $lockText = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Open-I04LockedFile'
    }, $true))[0].Extent.Text
    $bindingText = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Get-I04CandidateBinding'
    }, $true))[0].Extent.Text
    Assert-I04Offline -Condition (
        $lockText.Contains('[IO.FileShare]::None') -and
        $lockText.Contains('[IO.FileShare]::Read') -and
        $lockText.Contains('Get-I04Sha256FromStream') -and
        $lockText.Contains('$script:i04CandidateLocks.Add($locked)') -and
        $bindingText.Contains('ExpectedZipSha256') -and
        $bindingText.Contains('ExpectedExeSha256') -and
        ([regex]::Matches($script:HarnessText,
            'Assert-I04CandidateBindingUnchanged')).Count -ge 4) `
        -Code 'PACKAGE_BINDING_TOCTOU_GUARD_MISSING'
}

Invoke-I04OfflineTest -Id 'PACKAGE-BINDING-LOCK-FAILURE-RELEASES-ALL' `
    -Category 'package_binding' -Body {
    $fixture = New-I04OfflineBindingFixture -Name 'binding-lock-failure'
    $blockedPath = Join-Path $fixture.package 'emule.exe'
    $blocker = [IO.File]::Open(
        $blockedPath, [IO.FileMode]::Open, [IO.FileAccess]::Read,
        [IO.FileShare]::Read)
    $rejected = $false
    try {
        try {
            $null = Get-I04OfflineCandidateBinding `
                -DirectoryPath $fixture.package -ZipPath $fixture.zip `
                -ExpectedZipSha256 $fixture.zip_sha256 `
                -ExpectedExeSha256 $fixture.exe_sha256
        } catch { $rejected = $true }
    } finally { $blocker.Dispose() }
    Assert-I04Offline -Condition $rejected `
        -Code 'PREEXISTING_CANDIDATE_LOCK_NOT_REJECTED'

    $probePaths = @($fixture.zip) + @(
        Get-I04OfflinePackageEntrySpecs -PackagePath $fixture.package |
            ForEach-Object {
                Join-Path $fixture.package (
                    ([string]$_.name).Replace('/', '\'))
            })
    $exclusiveProbes = [Collections.Generic.List[IO.Stream]]::new()
    try {
        foreach ($probePath in $probePaths) {
            $exclusiveProbes.Add([IO.File]::Open(
                $probePath, [IO.FileMode]::Open, [IO.FileAccess]::Read,
                [IO.FileShare]::None))
        }
    } finally {
        foreach ($probe in @($exclusiveProbes)) { $probe.Dispose() }
    }
    Assert-I04Offline -Condition (
        $exclusiveProbes.Count -eq $probePaths.Count) `
        -Code 'FAILED_BINDING_LEFT_IMMUTABLE_LOCKS_HELD'
}

Invoke-I04OfflineTest -Id 'PACKAGE-BINDING-LOCKS-TERMINAL-FINALLY-STATIC' `
    -Category 'package_binding' -Body {
    $outerTries = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.TryStatementAst] -and
            $null -ne $node.Finally -and
            $node.Parent -is
                [Management.Automation.Language.NamedBlockAst] -and
            [object]::ReferenceEquals(
                $node.Parent.Parent, $script:HarnessAst)
    }, $true))
    Assert-I04Offline -Condition ($outerTries.Count -eq 1) `
        -Code 'TERMINAL_OUTER_FINALLY_NOT_EXACT'
    $tail = $outerTries[0].Finally.Extent.Text
    Assert-I04Offline -Condition (
        $tail.Contains(
            '$script:i04CandidateLocks.ToArray()') -and
        $tail.Contains('$lockedResource.Dispose()') -and
        $tail.Contains('$script:i04CandidateLocks.Clear()')) `
        -Code 'TERMINAL_IMMUTABLE_LOCK_RELEASE_MISSING'
}

Invoke-I04OfflineTest -Id 'TUPLE-KEY-CANONICAL' `
    -Category 'ownership_contract' -Body {
    $key = Get-I04OfflineTupleKey -Family 'IPv6' `
        -LocalAddress '2001:4860:0:0::10%3' -LocalPort 50000 `
        -RemoteAddress '2001:4860::20' -RemotePort 9462
    Assert-I04OfflineEqual -Actual $key `
        -Expected 'IPv6|2001:4860::10|50000|2001:4860::20|9462' `
        -Code 'TUPLE_KEY_NOT_CANONICAL'
}

Invoke-I04OfflineTest -Id 'CLOCK-DUAL-SOURCE-COHERENT' `
    -Category 'clock_contract' -Body {
    $samples = @(
        [pscustomobject]@{ epoch_ms = 999900.0; qpc = [Int64]999900000 },
        [pscustomobject]@{ epoch_ms = 1000000.0; qpc = [Int64]1000000000 },
        [pscustomobject]@{ epoch_ms = 1000100.0; qpc = [Int64]1000100000 }
    )
    $value = Get-I04OfflineClockValidation -Samples $samples
    Assert-I04Offline -Condition (
        [bool]$value.valid -and $value.sample_count -eq 3 -and
        [bool]$value.epoch_monotonic_non_decreasing -and
        [bool]$value.qpc_strictly_increasing -and
        [bool]$value.interval_deltas_coherent -and
        [bool]$value.boundary_projection_coherent -and
        $value.violation_count -eq 0) `
        -Code 'COHERENT_DUAL_CLOCK_REJECTED'
}

$clockNegativeCases = @(
    [pscustomobject]@{
        id = 'INVALID'; expected = 'invalid-clock-value'; samples = @(
            [pscustomobject]@{ epoch_ms = 0.0; qpc = [Int64]1 })
    },
    [pscustomobject]@{
        id = 'EPOCH-REGRESSION'; expected = 'epoch-regressed'; samples = @(
            [pscustomobject]@{ epoch_ms = 1000000.0; qpc = [Int64]1000000000 },
            [pscustomobject]@{ epoch_ms = 999999.0; qpc = [Int64]1000001000 })
    },
    [pscustomobject]@{
        id = 'QPC-REGRESSION'; expected = 'qpc-not-strictly-increasing'; samples = @(
            [pscustomobject]@{ epoch_ms = 1000000.0; qpc = [Int64]1000000000 },
            [pscustomobject]@{ epoch_ms = 1000001.0; qpc = [Int64]999999999 })
    },
    [pscustomobject]@{
        id = 'INTERVAL-INCOHERENT'; expected = 'interval-clock-incoherent'; samples = @(
            [pscustomobject]@{ epoch_ms = 1000000.0; qpc = [Int64]1000000000 },
            [pscustomobject]@{ epoch_ms = 1000010.0; qpc = [Int64]1000001000 })
    },
    [pscustomobject]@{
        id = 'BOUNDARY-INCOHERENT'; expected = 'boundary-clock-incoherent'; samples = @(
            [pscustomobject]@{ epoch_ms = 1000010.0; qpc = [Int64]1000000000 })
    }
)
foreach ($case in $clockNegativeCases) {
    $capturedCase = $case
    Invoke-I04OfflineTest -Id ('CLOCK-REJECT-' + $capturedCase.id) `
        -Category 'clock_contract' -Body {
        $value = Get-I04OfflineClockValidation `
            -Samples @($capturedCase.samples)
        Assert-I04Offline -Condition (
            -not [bool]$value.valid -and
            @($value.violations.code) -ccontains $capturedCase.expected) `
            -Code 'INVALID_DUAL_CLOCK_ACCEPTED'
    }
}

$correlationPacket = [pscustomobject][ordered]@{
    timestamp_ms = 1000100.0
    family = 'IPv6'
    source = '2001:4860::10'
    source_port = 50000
    destination = '2001:4860::20'
    destination_port = 9462
}
$correlationTuple = Get-I04OfflineTupleKey -Family 'IPv6' `
    -LocalAddress '2001:4860::10' -LocalPort 50000 `
    -RemoteAddress '2001:4860::20' -RemotePort 9462
$correlationCases = @(
    [pscustomobject]@{ id = 'CANDIDATE'; expected = 'candidate'; rows = @(
        [pscustomobject]@{ tuple_key=$correlationTuple; state='SynSent'; epoch_ms=1000100.0; owning_process=4242 }) },
    [pscustomobject]@{ id = 'FOREIGN'; expected = 'foreign-owner'; rows = @(
        [pscustomobject]@{ tuple_key=$correlationTuple; state='SynSent'; epoch_ms=1000100.0; owning_process=9999 }) },
    [pscustomobject]@{ id = 'AMBIGUOUS'; expected = 'ambiguous-owner'; rows = @(
        [pscustomobject]@{ tuple_key=$correlationTuple; state='SynSent'; epoch_ms=1000100.0; owning_process=4242 },
        [pscustomobject]@{ tuple_key=$correlationTuple; state='Established'; epoch_ms=1000101.0; owning_process=9999 }) },
    [pscustomobject]@{ id = 'UNOBSERVED'; expected = 'unobserved'; rows = @() },
    [pscustomobject]@{ id = 'OUTSIDE-TOLERANCE'; expected = 'unobserved'; rows = @(
        [pscustomobject]@{ tuple_key=$correlationTuple; state='SynSent'; epoch_ms=1000500.0; owning_process=4242 }) },
    [pscustomobject]@{ id = 'WRONG-STATE'; expected = 'unobserved'; rows = @(
        [pscustomobject]@{ tuple_key=$correlationTuple; state='TimeWait'; epoch_ms=1000100.0; owning_process=4242 }) }
)
foreach ($case in $correlationCases) {
    $capturedCase = $case
    Invoke-I04OfflineTest -Id ('PID-TUPLE-' + $capturedCase.id) `
        -Category 'ownership_contract' -Body {
        $value = Get-I04OfflineSynPidCorrelation `
            -Packet $correlationPacket `
            -SamplerRows @($capturedCase.rows)
        Assert-I04OfflineEqual -Actual $value.status `
            -Expected $capturedCase.expected `
            -Code 'PID_TUPLE_CORRELATION_STATUS_MISMATCH'
        Assert-I04Offline -Condition (
            ([string]$value.status -ceq 'candidate') -eq
                [bool]$value.candidate_correlated -and
            ([string]$value.status -ceq 'ambiguous-owner') -eq
                [bool]$value.correlation_ambiguous) `
            -Code 'PID_TUPLE_CORRELATION_FLAGS_INCOHERENT'
    }
}

Invoke-I04OfflineTest -Id 'PCAPNG-PARSER-SYN-SYNACK-ACK' `
    -Category 'pcap_contract' -Body {
    $fixture = New-I04OfflineFallbackFixture -Name 'pcap-parser-positive'
    $pcap = Read-I04OfflinePcapNg -Path $fixture.path
    $packets = @($pcap.packets)
    Assert-I04Offline -Condition (
        [string]$pcap.schema -ceq 'ese.v91.i04-pcapng-parse/v2' -and
        [bool]$pcap.parser_complete -and
        $pcap.section_count -eq 1 -and
        $pcap.interface_count -eq 1 -and
        $pcap.enhanced_packet_count -eq 4 -and
        $pcap.parsed_packet_count -eq 4 -and
        $pcap.trailing_byte_count -eq 0 -and
        $pcap.block_error_count -eq 0 -and
        $pcap.idb_option_error_count -eq 0 -and
        $pcap.truncated_frame_count -eq 0 -and
        $pcap.unknown_interface_frame_count -eq 0 -and
        $pcap.unsupported_linktype_frame_count -eq 0 -and
        $pcap.unsupported_packet_block_count -eq 0 -and
        $pcap.parse_null_frame_count -eq 0 -and
        $pcap.non_adjudicable_frame_count -eq 0 -and
        @($pcap.interfaces).Count -eq 1 -and
        [bool]$pcap.interfaces[0].supported_link_type -and
        [bool]$pcap.interfaces[0].options_valid -and
        [string]$pcap.interfaces[0].interface_name_sha256 -ceq
            (Get-I04OfflineStringSha256 -Value $fixture.adapter.name) -and
        $packets.Count -eq 4 -and
        @($packets | Where-Object {
            $_.family -ceq 'IPv6' -and $_.syn -and -not $_.ack -and
            $_.source -ceq '2001:4860::10' -and
            $_.destination -ceq '2001:4860::20' -and
            $_.source_port -eq 50000 -and $_.destination_port -eq 9462
        }).Count -eq 1 -and
        @($packets | Where-Object {
            $_.family -ceq 'IPv4' -and $_.syn -and $_.ack -and
            $_.source -ceq '1.1.1.1' -and
            $_.destination -ceq '8.8.8.8' -and
            $_.acknowledgement_number -eq 201
        }).Count -eq 1 -and
        @($packets | Where-Object {
            $_.family -ceq 'IPv4' -and -not $_.syn -and $_.ack -and
            $_.sequence_number -eq 201 -and
            $_.acknowledgement_number -eq 301
        }).Count -eq 1) `
        -Code 'PCAPNG_TCP_SEQUENCE_PARSE_MISMATCH'
}

Invoke-I04OfflineTest -Id 'PACKET-VERDICT-PLANNED-FALLBACK-POSITIVE' `
    -Category 'fallback_contract' -Body {
    $fixture = New-I04OfflineFallbackFixture -Name 'fallback-positive'
    $value = Get-I04OfflinePacketVerdict -Path $fixture.path `
        -SocketSamplerEvidence $fixture.sampler
    Assert-I04Offline -Condition (
        [string]$value.schema -ceq 'ese.v91.i04-packet-verdict/v2' -and
        [bool]$value.pcapng_parser_complete -and
        $value.pcapng_section_count -eq 1 -and
        $value.pcapng_interface_count -eq 1 -and
        $value.pcapng_trailing_byte_count -eq 0 -and
        $value.pcapng_block_error_count -eq 0 -and
        $value.pcapng_idb_option_error_count -eq 0 -and
        $value.pcapng_truncated_frame_count -eq 0 -and
        $value.pcapng_unknown_interface_frame_count -eq 0 -and
        $value.pcapng_unsupported_linktype_frame_count -eq 0 -and
        $value.pcapng_unsupported_packet_block_count -eq 0 -and
        $value.pcapng_parse_null_frame_count -eq 0 -and
        $value.pcapng_non_adjudicable_frame_count -eq 0 -and
        [string]$value.capture_interface_binding.schema -ceq
            'ese.v91.i04-capture-interface-binding/v1' -and
        [bool]$value.capture_interface_binding_exact -and
        [bool]$value.capture_interface_binding.exact -and
        $value.capture_interface_binding.matching_pcapng_interface_count -eq 1 -and
        $value.target_frame_count -eq 4 -and
        $value.foreign_interface_target_frame_count -eq 0 -and
        [bool]$value.target_frames_on_expected_physical_nic -and
        $value.ipv6_syn_count -eq 1 -and
        $value.distinct_ipv6_connection_attempts -eq 1 -and
        $value.ipv4_syn_count -eq 1 -and
        $value.distinct_ipv4_connection_attempts -eq 1 -and
        [bool]$value.ipv4_synack_observed -and
        [bool]$value.ipv4_final_ack_observed -and
        [double]$value.syn6_to_syn4_ms -eq 3000 -and
        [double]$value.syn6_to_ipv4_connected_ms -eq 3200 -and
        [bool]$value.silent_drop_proved -and
        [bool]$value.fallback_under_limit -and
        [bool]$value.fallback_in_planning_window -and
        [bool]$value.connection_under_limit -and
        [bool]$value.pid_sampler_temporal_coverage_valid -and
        [bool]$value.pid_packet_correlation_complete -and
        $value.uncorrelated_target_syn_count -eq 0 -and
        $value.ambiguous_owner_target_syn_count -eq 0) `
        -Code 'PLANNED_FALLBACK_PACKET_VERDICT_REJECTED'
}

$fallbackBoundaryCases = @(
    [pscustomobject]@{ id = 'LOWER-INCLUSIVE'; delay = 2750.0; expected = $true },
    [pscustomobject]@{ id = 'LOWER-BELOW'; delay = 2749.999; expected = $false },
    [pscustomobject]@{ id = 'UPPER-BELOW'; delay = 7999.999; expected = $true },
    [pscustomobject]@{ id = 'UPPER-EXCLUSIVE'; delay = 8000.0; expected = $false }
)
foreach ($case in $fallbackBoundaryCases) {
    $capturedCase = $case
    Invoke-I04OfflineTest -Id (
        'PACKET-VERDICT-PLANNING-BOUNDARY-' + $capturedCase.id) `
        -Category 'fallback_contract' -Body {
        $fixture = New-I04OfflineFallbackFixture `
            -Name ('fallback-boundary-' + $capturedCase.id.ToLowerInvariant()) `
            -FallbackDelayMs $capturedCase.delay
        $value = Get-I04OfflinePacketVerdict -Path $fixture.path `
            -SocketSamplerEvidence $fixture.sampler
        Assert-I04Offline -Condition (
            [bool]$value.fallback_in_planning_window -eq
                [bool]$capturedCase.expected -and
            [double]$value.syn6_to_syn4_ms -eq
                [double]$capturedCase.delay) `
            -Code 'FALLBACK_PLANNING_BOUNDARY_MISMATCH'
    }
}

Invoke-I04OfflineTest -Id 'PACKET-VERDICT-NO-IPV4-ATTEMPT' `
    -Category 'fallback_contract' -Body {
    $fixture = New-I04OfflineFallbackFixture -Name 'fallback-no-v4' `
        -IncludeIPv4 $false -IncludeSynAck $false -IncludeFinalAck $false
    $value = Get-I04OfflinePacketVerdict -Path $fixture.path `
        -SocketSamplerEvidence $fixture.sampler
    Assert-I04Offline -Condition (
        $value.ipv6_syn_count -eq 1 -and $value.ipv4_syn_count -eq 0 -and
        [bool]$value.ipv4_attempt_absent_proved -and
        -not [bool]$value.fallback_under_limit -and
        -not [bool]$value.fallback_in_planning_window -and
        -not [bool]$value.connection_under_limit) `
        -Code 'MISSING_IPV4_ATTEMPT_NOT_PROVED'
}

Invoke-I04OfflineTest -Id 'PACKET-VERDICT-DUPLICATE-IPV4-ATTEMPT' `
    -Category 'fallback_contract' -Body {
    $fixture = New-I04OfflineFallbackFixture -Name 'fallback-duplicate-v4' `
        -SecondIPv4Attempt
    $value = Get-I04OfflinePacketVerdict -Path $fixture.path `
        -SocketSamplerEvidence $fixture.sampler
    Assert-I04Offline -Condition (
        $value.ipv4_syn_count -eq 2 -and
        $value.distinct_ipv4_connection_attempts -eq 2 -and
        [bool]$value.pid_packet_correlation_complete) `
        -Code 'DUPLICATE_IPV4_ATTEMPT_NOT_EXPOSED'
}

$packetOwnershipCases = @(
    [pscustomobject]@{
        id = 'FOREIGN'; ownership = 'Foreign'
        uncorrelated = 2; ambiguous = 0
    },
    [pscustomobject]@{
        id = 'AMBIGUOUS'; ownership = 'Ambiguous'
        uncorrelated = 0; ambiguous = 2
    },
    [pscustomobject]@{
        id = 'UNOBSERVED'; ownership = 'Unobserved'
        uncorrelated = 2; ambiguous = 0
    }
)
foreach ($case in $packetOwnershipCases) {
    $capturedCase = $case
    Invoke-I04OfflineTest -Id (
        'PACKET-VERDICT-PID-OWNER-' + $capturedCase.id) `
        -Category 'ownership_contract' -Body {
        $fixture = New-I04OfflineFallbackFixture `
            -Name ('fallback-owner-' + $capturedCase.id.ToLowerInvariant()) `
            -Ownership $capturedCase.ownership
        $value = Get-I04OfflinePacketVerdict -Path $fixture.path `
            -SocketSamplerEvidence $fixture.sampler
        Assert-I04Offline -Condition (
            -not [bool]$value.pid_packet_correlation_complete -and
            $value.uncorrelated_target_syn_count -eq
                $capturedCase.uncorrelated -and
            $value.ambiguous_owner_target_syn_count -eq
                $capturedCase.ambiguous) `
            -Code 'FOREIGN_OR_AMBIGUOUS_PID_OWNER_ACCEPTED'
    }
}

Invoke-I04OfflineTest -Id 'PACKET-VERDICT-V6-RESPONSE-REJECTS-SILENCE' `
    -Category 'fallback_contract' -Body {
    $fixture = New-I04OfflineFallbackFixture `
        -Name 'fallback-v6-response' -IPv6Response
    $value = Get-I04OfflinePacketVerdict -Path $fixture.path `
        -SocketSamplerEvidence $fixture.sampler
    Assert-I04Offline -Condition (
        [bool]$value.environment_rejected_blackhole_in_fixed_window -and
        $value.ipv6_tcp_response_count_in_fixed_silent_window -eq 1 -and
        -not [bool]$value.silent_drop_proved) `
        -Code 'IPV6_RESPONSE_ACCEPTED_AS_SILENT_DROP'
}

$handshakeNegativeCases = @(
    [pscustomobject]@{
        id = 'NO-SYNACK'; synack = $false; final_ack = $false
        expected_synack = $false; expected_final = $false
    },
    [pscustomobject]@{
        id = 'NO-FINAL-ACK'; synack = $true; final_ack = $false
        expected_synack = $true; expected_final = $false
    }
)
foreach ($case in $handshakeNegativeCases) {
    $capturedCase = $case
    Invoke-I04OfflineTest -Id (
        'PACKET-VERDICT-HANDSHAKE-' + $capturedCase.id) `
        -Category 'pcap_contract' -Body {
        $fixture = New-I04OfflineFallbackFixture `
            -Name ('fallback-handshake-' + $capturedCase.id.ToLowerInvariant()) `
            -IncludeSynAck $capturedCase.synack `
            -IncludeFinalAck $capturedCase.final_ack
        $value = Get-I04OfflinePacketVerdict -Path $fixture.path `
            -SocketSamplerEvidence $fixture.sampler
        Assert-I04Offline -Condition (
            [bool]$value.ipv4_synack_observed -eq
                [bool]$capturedCase.expected_synack -and
            [bool]$value.ipv4_final_ack_observed -eq
                [bool]$capturedCase.expected_final -and
            -not [bool]$value.connection_under_limit) `
            -Code 'INCOMPLETE_IPV4_HANDSHAKE_ACCEPTED'
    }
}

Invoke-I04OfflineTest -Id 'PACKET-VERDICT-HISTORICAL-TUPLE-NOT-SUPPRESSED' `
    -Category 'ownership_contract' -Body {
    $fixture = New-I04OfflineFallbackFixture -Name 'fallback-reused-tuple'
    $value = Get-I04OfflinePacketVerdict -Path $fixture.path `
        -SocketSamplerEvidence $fixture.sampler `
        -ExcludedTupleKeys @($fixture.v6_tuple, $fixture.v4_tuple)
    Assert-I04Offline -Condition (
        $value.excluded_prewarm_tuple_count -eq 2 -and
        $value.excluded_prewarm_syn_packet_count -eq 2 -and
        $value.target_syn_count -eq 2 -and
        $value.pid_correlated_target_syn_count -eq 2 -and
        [bool]$value.fallback_in_planning_window) `
        -Code 'REUSED_HISTORICAL_TUPLE_SUPPRESSED_NEW_ATTEMPT'
}

$samplerBindingMutations = @(
    [pscustomobject]@{ id = 'PID'; property = 'candidate_process_id'; value = 4243 },
    [pscustomobject]@{ id = 'BOUNDARY'; property = 'boundary_epoch_ms'; value = 1000002.0 },
    [pscustomobject]@{ id = 'CLOCK'; property = 'clock_coherence_valid'; value = $false },
    [pscustomobject]@{ id = 'COVERAGE'; property = 'sampler_coverage_valid'; value = $false },
    [pscustomobject]@{ id = 'FREQUENCY'; property = 'qpc_frequency'; value = [Int64]1 }
)
foreach ($mutation in $samplerBindingMutations) {
    $capturedMutation = $mutation
    Invoke-I04OfflineTest -Id (
        'PACKET-VERDICT-SAMPLER-BINDING-' + $capturedMutation.id) `
        -Category 'clock_contract' -Body {
        $fixture = New-I04OfflineFallbackFixture `
            -Name ('fallback-sampler-' + $capturedMutation.id.ToLowerInvariant())
        $fixture.sampler.($capturedMutation.property) =
            $capturedMutation.value
        Assert-I04OfflineThrows `
            -ExpectedCode 'does not identify this exact scenario' -Body {
            Get-I04OfflinePacketVerdict -Path $fixture.path `
                -SocketSamplerEvidence $fixture.sampler
        }
    }
}

Invoke-I04OfflineTest -Id 'PCAPNG-MALFORMED-HEADER-REJECTED' `
    -Category 'pcap_contract' -Body {
    $path = Assert-I04OfflineTempPath -Path (
        Join-Path $script:TempRoot 'malformed-header.pcapng')
    [IO.File]::WriteAllBytes($path, [byte[]](0, 1, 2, 3, 4, 5))
    Assert-I04OfflineThrows `
        -ExpectedCode 'Only little-endian PCAPNG' -Body {
        Read-I04OfflinePcapNg -Path $path
    }
}

Invoke-I04OfflineTest -Id 'PCAPNG-CORRUPT-BLOCK-REJECTED' `
    -Category 'pcap_contract' -Body {
    $fixture = New-I04OfflineFallbackFixture -Name 'pcap-corrupt-block'
    [byte[]]$bytes = [IO.File]::ReadAllBytes($fixture.path)
    $bytes[24] = 0
    $bytes[25] = 0
    $bytes[26] = 0
    $bytes[27] = 0
    [IO.File]::WriteAllBytes($fixture.path, $bytes)
    $pcap = Read-I04OfflinePcapNg -Path $fixture.path
    Assert-I04Offline -Condition (
        -not [bool]$pcap.parser_complete -and
        $pcap.block_error_count -eq 1 -and
        $pcap.parsed_packet_count -eq 0 -and
        $pcap.trailing_byte_count -gt 0) `
        -Code 'CORRUPT_PCAPNG_BLOCK_WAS_ADJUDICABLE'
}

foreach ($trailingCount in 1..11) {
    $capturedTrailingCount = $trailingCount
    Invoke-I04OfflineTest -Id (
        'PCAPNG-TRAILING-BYTES-' + $capturedTrailingCount) `
        -Category 'pcap_contract' -Body {
        $fixture = New-I04OfflineFallbackFixture -Name (
            'pcap-trailing-' + $capturedTrailingCount)
        [byte[]]$base = [IO.File]::ReadAllBytes($fixture.path)
        [byte[]]$mutated = New-Object byte[] (
            $base.Length + $capturedTrailingCount)
        [Array]::Copy($base, 0, $mutated, 0, $base.Length)
        for ($index = $base.Length; $index -lt $mutated.Length; $index++) {
            $mutated[$index] = 0xa5
        }
        [IO.File]::WriteAllBytes($fixture.path, $mutated)
        $pcap = Read-I04OfflinePcapNg -Path $fixture.path
        Assert-I04Offline -Condition (
            -not [bool]$pcap.parser_complete -and
            $pcap.trailing_byte_count -eq $capturedTrailingCount -and
            $pcap.block_error_count -eq 0 -and
            $pcap.non_adjudicable_frame_count -eq 0) `
            -Code 'PCAPNG_TRAILING_BYTES_WERE_SILENCED'
    }
}

Invoke-I04OfflineTest -Id 'PCAPNG-SHORT-IDB-REJECTED' `
    -Category 'pcap_contract' -Body {
    $fixture = New-I04OfflineFallbackFixture -Name 'pcap-short-idb-source'
    [byte[]]$source = [IO.File]::ReadAllBytes($fixture.path)
    [byte[]]$mutated = New-Object byte[] 44
    [Array]::Copy($source, 0, $mutated, 0, 28)
    Set-I04OfflineUInt32LE -Bytes $mutated -Offset 28 -Value 1
    Set-I04OfflineUInt32LE -Bytes $mutated -Offset 32 -Value 16
    Set-I04OfflineUInt16LE -Bytes $mutated -Offset 36 -Value 101
    Set-I04OfflineUInt32LE -Bytes $mutated -Offset 40 -Value 16
    [IO.File]::WriteAllBytes($fixture.path, $mutated)
    $pcap = Read-I04OfflinePcapNg -Path $fixture.path
    Assert-I04Offline -Condition (
        -not [bool]$pcap.parser_complete -and
        $pcap.block_error_count -eq 1 -and
        $pcap.interface_count -eq 0 -and
        $pcap.trailing_byte_count -eq 0) `
        -Code 'SHORT_PCAPNG_IDB_WAS_ADJUDICABLE'
}

Invoke-I04OfflineTest -Id 'PCAPNG-IDB-OPTION-OVERFLOW-REJECTED' `
    -Category 'pcap_contract' -Body {
    $fixture = New-I04OfflineFallbackFixture -Name 'pcap-idb-option-overflow'
    [byte[]]$bytes = [IO.File]::ReadAllBytes($fixture.path)
    Set-I04OfflineUInt16LE -Bytes $bytes -Offset 46 -Value 65535
    [IO.File]::WriteAllBytes($fixture.path, $bytes)
    $pcap = Read-I04OfflinePcapNg -Path $fixture.path
    Assert-I04Offline -Condition (
        -not [bool]$pcap.parser_complete -and
        $pcap.idb_option_error_count -eq 1 -and
        -not [bool]$pcap.interfaces[0].options_valid) `
        -Code 'OVERFLOWING_PCAPNG_IDB_OPTION_WAS_ADJUDICABLE'
}

Invoke-I04OfflineTest -Id 'PCAPNG-SHORT-EPB-REJECTED' `
    -Category 'pcap_contract' -Body {
    $fixture = New-I04OfflineFallbackFixture -Name 'pcap-short-epb-source'
    [byte[]]$source = [IO.File]::ReadAllBytes($fixture.path)
    $idbLength = [BitConverter]::ToUInt32($source, 32)
    $prefixLength = 28 + [int]$idbLength
    [byte[]]$mutated = New-Object byte[] ($prefixLength + 28)
    [Array]::Copy($source, 0, $mutated, 0, $prefixLength)
    Set-I04OfflineUInt32LE -Bytes $mutated -Offset $prefixLength -Value 6
    Set-I04OfflineUInt32LE -Bytes $mutated -Offset ($prefixLength + 4) `
        -Value 28
    Set-I04OfflineUInt32LE -Bytes $mutated -Offset ($prefixLength + 24) `
        -Value 28
    [IO.File]::WriteAllBytes($fixture.path, $mutated)
    $pcap = Read-I04OfflinePcapNg -Path $fixture.path
    Assert-I04Offline -Condition (
        -not [bool]$pcap.parser_complete -and
        $pcap.block_error_count -eq 1 -and
        $pcap.enhanced_packet_count -eq 1 -and
        $pcap.parsed_packet_count -eq 0 -and
        $pcap.non_adjudicable_frame_count -eq 1 -and
        $pcap.trailing_byte_count -eq 0) `
        -Code 'SHORT_PCAPNG_EPB_WAS_ADJUDICABLE'
}

foreach ($packetBlockType in @(2, 3)) {
    $capturedPacketBlockType = $packetBlockType
    Invoke-I04OfflineTest -Id (
        'PCAPNG-UNSUPPORTED-PACKET-BLOCK-' + $capturedPacketBlockType) `
        -Category 'pcap_contract' -Body {
        $fixture = New-I04OfflineFallbackFixture -Name (
            'pcap-unsupported-block-' + $capturedPacketBlockType)
        [byte[]]$source = [IO.File]::ReadAllBytes($fixture.path)
        [byte[]]$mutated = New-Object byte[] ($source.Length + 12)
        [Array]::Copy($source, 0, $mutated, 0, $source.Length)
        Set-I04OfflineUInt32LE -Bytes $mutated -Offset $source.Length `
            -Value ([UInt32]$capturedPacketBlockType)
        Set-I04OfflineUInt32LE -Bytes $mutated `
            -Offset ($source.Length + 4) -Value 12
        Set-I04OfflineUInt32LE -Bytes $mutated `
            -Offset ($source.Length + 8) -Value 12
        [IO.File]::WriteAllBytes($fixture.path, $mutated)
        $pcap = Read-I04OfflinePcapNg -Path $fixture.path
        Assert-I04Offline -Condition (
            -not [bool]$pcap.parser_complete -and
            $pcap.unsupported_packet_block_count -eq 1 -and
            $pcap.non_adjudicable_frame_count -eq 1 -and
            $pcap.trailing_byte_count -eq 0) `
            -Code 'UNSUPPORTED_PCAPNG_PACKET_BLOCK_WAS_SILENCED'
    }
}

Invoke-I04OfflineTest -Id 'PCAPNG-MULTIPLE-SECTIONS-REJECTED' `
    -Category 'pcap_contract' -Body {
    $fixture = New-I04OfflineFallbackFixture -Name 'pcap-second-section'
    [byte[]]$source = [IO.File]::ReadAllBytes($fixture.path)
    [byte[]]$mutated = New-Object byte[] ($source.Length + 28)
    [Array]::Copy($source, 0, $mutated, 0, $source.Length)
    [Array]::Copy($source, 0, $mutated, $source.Length, 28)
    [IO.File]::WriteAllBytes($fixture.path, $mutated)
    $pcap = Read-I04OfflinePcapNg -Path $fixture.path
    Assert-I04Offline -Condition (
        -not [bool]$pcap.parser_complete -and
        $pcap.section_count -eq 2 -and
        $pcap.trailing_byte_count -eq 0 -and
        $pcap.block_error_count -eq 0) `
        -Code 'MULTI_SECTION_PCAPNG_WAS_ADJUDICABLE'
}

$pcapFrameNegativeCases = @(
    [pscustomobject]@{
        id = 'UNKNOWN-INTERFACE'; interface_id = 1; link_type = 101
        truncate = $false; malformed = $false
        expected_counter = 'unknown_interface_frame_count'
    },
    [pscustomobject]@{
        id = 'UNSUPPORTED-LINKTYPE'; interface_id = 0; link_type = 999
        truncate = $false; malformed = $false
        expected_counter = 'unsupported_linktype_frame_count'
    },
    [pscustomobject]@{
        id = 'CAPTURED-LT-ORIGINAL'; interface_id = 0; link_type = 101
        truncate = $true; malformed = $false
        expected_counter = 'truncated_frame_count'
    },
    [pscustomobject]@{
        id = 'MALFORMED-FRAME'; interface_id = 0; link_type = 101
        truncate = $false; malformed = $true
        expected_counter = 'parse_null_frame_count'
    }
)
foreach ($case in $pcapFrameNegativeCases) {
    $capturedCase = $case
    Invoke-I04OfflineTest -Id ('PCAPNG-FRAME-' + $capturedCase.id) `
        -Category 'pcap_contract' -Body {
        [byte[]]$frame = if ($capturedCase.malformed) {
            [byte[]](0x70, 0, 0, 0)
        } else {
            New-I04OfflineTcpPacket -Family IPv4 -Source '8.8.8.8' `
                -Destination '1.1.1.1' -SourcePort 50001 `
                -DestinationPort 9462 -SequenceNumber 1 -Flags 0x02
        }
        $spec = [pscustomobject]@{
            timestamp_ms = 1000100.0
            family = 'IPv4'
            interface_id = $capturedCase.interface_id
            bytes = $frame
        }
        if ($capturedCase.truncate) {
            $spec | Add-Member -NotePropertyName captured_length `
                -NotePropertyValue ($frame.Length - 1)
            $spec | Add-Member -NotePropertyName original_length `
                -NotePropertyValue $frame.Length
        }
        $path = New-I04OfflinePcapNg -Path (Join-Path $script:TempRoot (
            'pcap-frame-' + $capturedCase.id.ToLowerInvariant() + '.pcapng')) `
            -Packets @($spec) -Interfaces @([pscustomobject]@{
                link_type = $capturedCase.link_type
                name = 'Offline Physical NIC'
                description = 'Offline Physical NIC Fixture'
            })
        $pcap = Read-I04OfflinePcapNg -Path $path
        $expectedCount = [int]$pcap.($capturedCase.expected_counter)
        Assert-I04Offline -Condition (
            -not [bool]$pcap.parser_complete -and
            $pcap.enhanced_packet_count -eq 1 -and
            $pcap.parsed_packet_count -eq 0 -and
            $pcap.non_adjudicable_frame_count -eq 1 -and
            $expectedCount -eq 1) `
            -Code 'NON_ADJUDICABLE_PCAPNG_FRAME_WAS_SILENCED'
    }
}

Invoke-I04OfflineTest -Id 'PACKET-NIC-BINDING-FOREIGN-TARGET-FRAME' `
    -Category 'pcap_contract' -Body {
    $fixture = New-I04OfflineFallbackFixture -Name 'nic-foreign-source'
    $fixture.packets[1] | Add-Member -NotePropertyName interface_id `
        -NotePropertyValue 1 -Force
    $path = New-I04OfflinePcapNg -Path (Join-Path $script:TempRoot `
        'nic-foreign-target.pcapng') -Packets @($fixture.packets) `
        -Interfaces @(
            [pscustomobject]@{
                link_type = 101; name = $fixture.adapter.name
                description = $fixture.adapter.description
            },
            [pscustomobject]@{
                link_type = 101; name = 'Foreign Physical NIC'
                description = 'Foreign Physical NIC Fixture'
            })
    $value = Get-I04OfflinePacketVerdict -Path $path `
        -SocketSamplerEvidence $fixture.sampler `
        -ExpectedAdapterEvidence $fixture.adapter
    Assert-I04Offline -Condition (
        [bool]$value.pcapng_parser_complete -and
        [bool]$value.capture_interface_binding_exact -and
        $value.foreign_interface_target_frame_count -eq 1 -and
        -not [bool]$value.target_frames_on_expected_physical_nic) `
        -Code 'FOREIGN_INTERFACE_TARGET_FRAME_WAS_ADMISSIBLE'
}

$nicPhysicalMutations = @(
    [pscustomobject]@{ id = 'HARDWARE-FALSE'; property = 'hardware_interface'; value = $false },
    [pscustomobject]@{ id = 'VIRTUAL-TRUE'; property = 'virtual'; value = $true },
    [pscustomobject]@{ id = 'OVERLAY-TRUE'; property = 'overlay_or_vpn_like'; value = $true }
)
foreach ($mutation in $nicPhysicalMutations) {
    $capturedMutation = $mutation
    Invoke-I04OfflineTest -Id (
        'PACKET-NIC-BINDING-' + $capturedMutation.id) `
        -Category 'pcap_contract' -Body {
        $fixture = New-I04OfflineFallbackFixture -Name (
            'nic-' + $capturedMutation.id.ToLowerInvariant())
        $fixture.adapter.($capturedMutation.property) =
            $capturedMutation.value
        $value = Get-I04OfflinePacketVerdict -Path $fixture.path `
            -SocketSamplerEvidence $fixture.sampler `
            -ExpectedAdapterEvidence $fixture.adapter
        Assert-I04Offline -Condition (
            [bool]$value.pcapng_parser_complete -and
            -not [bool]$value.capture_interface_binding_exact -and
            -not [bool]$value.capture_interface_binding.exact -and
            -not [bool]$value.target_frames_on_expected_physical_nic -and
            $value.foreign_interface_target_frame_count -eq
                $value.target_frame_count) `
            -Code 'NON_PHYSICAL_NIC_BINDING_WAS_ADMISSIBLE'
    }
}

Invoke-I04OfflineTest -Id 'PACKET-NIC-BINDING-AMBIGUOUS-IDB' `
    -Category 'pcap_contract' -Body {
    $fixture = New-I04OfflineFallbackFixture -Name 'nic-ambiguous-source'
    $interfaces = @(
        [pscustomobject]@{
            link_type = 101; name = $fixture.adapter.name
            description = $fixture.adapter.description
        },
        [pscustomobject]@{
            link_type = 101; name = $fixture.adapter.name
            description = $fixture.adapter.description
        })
    $path = New-I04OfflinePcapNg -Path (Join-Path $script:TempRoot `
        'nic-ambiguous-idb.pcapng') -Packets @($fixture.packets) `
        -Interfaces $interfaces
    $value = Get-I04OfflinePacketVerdict -Path $path `
        -SocketSamplerEvidence $fixture.sampler `
        -ExpectedAdapterEvidence $fixture.adapter
    Assert-I04Offline -Condition (
        [bool]$value.pcapng_parser_complete -and
        $value.capture_interface_binding.matching_pcapng_interface_count -eq 2 -and
        -not [bool]$value.capture_interface_binding_exact -and
        -not [bool]$value.target_frames_on_expected_physical_nic -and
        $value.foreign_interface_target_frame_count -eq
            $value.target_frame_count) `
        -Code 'AMBIGUOUS_PCAPNG_INTERFACE_BINDING_WAS_ADMISSIBLE'
}

Invoke-I04OfflineTest -Id 'VALUE-SET-NORMALIZATION' `
    -Category 'cleanup_contract' -Body {
    Assert-I04Offline -Condition (
        [bool](Test-I04OfflineValueSetEqual `
            -Actual @('Beta,alpha', 'ALPHA') `
            -Expected @('alpha', 'beta')) -and
        [bool](Test-I04OfflineValueSetEqual `
            -Actual @('2001:4860:0:0::10%7', '::ffff:8.8.8.8') `
            -Expected @('2001:4860::10', '8.8.8.8') -NormalizeIp) -and
        -not [bool](Test-I04OfflineValueSetEqual `
            -Actual @('alpha') -Expected @('alpha', 'beta'))) `
        -Code 'VALUE_SET_NORMALIZATION_MISMATCH'
}

Invoke-I04OfflineTest -Id 'PROCESS-OWNERSHIP-REGISTER-STATIC' `
    -Category 'ownership_contract' -Body {
    $register = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Register-I04OwnedProcess'
    }, $true))
    Assert-I04Offline -Condition ($register.Count -eq 1) `
        -Code 'PROCESS_REGISTER_FUNCTION_NOT_EXACTLY_ONE'
    $text = $register[0].Extent.Text
    foreach ($needle in @(
        '[void]$Process.Handle', '$Process.Refresh()', '$Process.HasExited',
        'Assert-I04NoReparsePath -Path $Process.Path -Kind File',
        '[IO.Path]::GetFullPath($ExpectedPath)',
        '$Process.StartTime.ToUniversalTime().Ticks',
        'Get-I04CimProcessCreationUtcTicks',
        '$cimCreationTicks',
        'Get-I04ProcessOwnerSidHash -ProcessId $Process.Id',
        '$script:i04HostIdentity.user_sid_sha256',
        '$Nonce.ToLowerInvariant()', '$OwnerRole', '$Process.Id',
        '$pathHash, $exeHash', '$ownerSidHash',
        'i04_owner_nonce', 'i04_owner_role', 'i04_owner_pid',
        'i04_owner_creation_utc_ticks', 'i04_owner_path_sha256',
        'i04_owner_cim_creation_utc_ticks',
        'i04_owner_executable_sha256', 'i04_owner_sid_sha256',
        'i04_ownership_id_sha256',
        'i04_descendant_collector_failed = $false',
        'i04_descendant_root_identity_contradicted = $false',
        'i04_descendant_observed = $false')) {
        Assert-I04Offline -Condition ($text.Contains($needle)) `
            -Code 'PROCESS_REGISTRATION_IDENTITY_FIELD_MISSING'
    }
}

Invoke-I04OfflineTest -Id 'PROCESS-OWNERSHIP-BINDING-FAIL-CLOSED-STATIC' `
    -Category 'ownership_contract' -Body {
    $binding = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Test-I04OwnedProcessBinding'
    }, $true))
    Assert-I04Offline -Condition ($binding.Count -eq 1) `
        -Code 'PROCESS_BINDING_FUNCTION_NOT_EXACTLY_ONE'
    $text = $binding[0].Extent.Text
    foreach ($needle in @(
        '[void]$Process.Handle', '$Process.Refresh()', '$Process.HasExited',
        '$Process.i04_owner_pid', '$RunNonce.ToLowerInvariant()',
        '$Process.StartTime.ToUniversalTime().Ticks',
        '$Process.i04_owner_creation_utc_ticks',
        '$Process.i04_owner_cim_creation_utc_ticks',
        '$Process.i04_owner_path_sha256',
        '$Process.i04_owner_executable_sha256',
        '$Process.i04_owner_sid_sha256',
        '$Process.i04_ownership_id_sha256',
        "'i04_descendant_collector_failed'",
        "'i04_descendant_root_identity_contradicted'",
        "'i04_descendant_observed'",
        '$script:i04HostIdentity.user_sid_sha256',
        "'PeerSource'", "'CoordinatorClient'",
        'return Test-I04OwnedProcessDescendants -Process $Process')) {
        Assert-I04Offline -Condition ($text.Contains($needle)) `
            -Code 'PROCESS_BINDING_FAIL_CLOSED_GUARD_MISSING'
    }
    Assert-I04Offline -Condition (
        $text.IndexOf('[void]$Process.Handle') -lt
            $text.IndexOf('$Process.StartTime') -and
        $text.IndexOf('Test-I04OwnedProcessDescendants') -gt
            $text.IndexOf('$Process.i04_ownership_id_sha256')) `
        -Code 'PROCESS_HANDLE_OR_CHILD_CENSUS_ORDER_WRONG'
}

Invoke-I04OfflineTest -Id 'PROCESS-DESCENDANT-CENSUS-STICKY-STATIC' `
    -Category 'ownership_contract' -Body {
    $censusText = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Get-I04DescendantCensus'
    }, $true))[0].Extent.Text
    foreach ($needle in @(
        'Get-CimInstance -ClassName Win32_Process -ErrorAction Stop',
        '$rootRows.Count -gt 1', '$RootMayHaveExited',
        'Get-I04CimProcessCreationUtcTicks',
        '[Int64]$observedRootCreationTicks -eq',
        '$knownAncestors.Add($RootProcessId)',
        '$row.ParentProcessId',
        '$creationTicks -lt $RootCreationUtcTicks',
        '} while ($added)', 'descendant_count = $descendants.Count',
        'clear = $rootIdentityExact -and $descendants.Count -eq 0')) {
        Assert-I04Offline -Condition ($censusText.Contains($needle)) `
            -Code 'RECURSIVE_DESCENDANT_CENSUS_GUARD_MISSING'
    }
    $auditText = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Test-I04OwnedProcessDescendants'
    }, $true))[0].Extent.Text
    foreach ($needle in @(
        'Get-I04DescendantCensus',
        'i04_descendant_last_census',
        'i04_descendant_root_identity_contradicted = $true',
        'i04_descendant_observed = $true',
        'i04_descendant_observed_process_ids',
        'i04_descendant_collector_failed = $true',
        'i04_descendant_error_sha256',
        '-not [bool]$Process.i04_descendant_collector_failed',
        '-not [bool]$Process.i04_descendant_observed')) {
        Assert-I04Offline -Condition ($auditText.Contains($needle)) `
            -Code 'DESCENDANT_OBSERVATION_NOT_STICKY_FAIL_CLOSED'
    }
}

Invoke-I04OfflineTest -Id 'PROCESS-OWNERSHIP-STOP-HANDLE-BOUND-STATIC' `
    -Category 'ownership_contract' -Body {
    $stop = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Stop-I04OwnedProcess'
    }, $true))
    Assert-I04Offline -Condition ($stop.Count -eq 1) `
        -Code 'OWNED_PROCESS_STOP_FUNCTION_NOT_EXACTLY_ONE'
    $ast = $stop[0]
    $text = $ast.Extent.Text
    $bindingOffsets = @($ast.FindAll({
        param($node)
        $node -is [Management.Automation.Language.CommandAst] -and
            $node.GetCommandName() -ceq 'Test-I04OwnedProcessBinding'
    }, $true) | ForEach-Object { $_.Extent.StartOffset } | Sort-Object)
    $stopProcessCalls = @($ast.FindAll({
        param($node)
        $node -is [Management.Automation.Language.CommandAst] -and
            $node.GetCommandName() -ceq 'Stop-Process'
    }, $true))
    $killCalls = @($ast.FindAll({
        param($node)
        $node -is `
            [Management.Automation.Language.InvokeMemberExpressionAst] -and
            [string]$node.Member.Value -ceq 'Kill'
    }, $true))
    Assert-I04Offline -Condition (
        $bindingOffsets.Count -eq 2 -and
        $stopProcessCalls.Count -eq 0 -and $killCalls.Count -eq 1 -and
        $text.Contains('[void]$Process.Handle') -and
        $text.Contains('$Process.Kill()') -and
        $text.Contains('Test-I04OwnedProcessDescendants') -and
        $text.Contains('-RootMayHaveExited') -and
        $text.Contains('if ($RequireGraceful) { return $false }') -and
        $killCalls[0].Extent.StartOffset -gt $bindingOffsets[1] -and
        $bindingOffsets[0] -gt $ast.Extent.StartOffset) `
        -Code 'PROCESS_STOP_NOT_HANDLE_BOUND_OR_REVALIDATED'
}

Invoke-I04OfflineTest -Id 'PROCESS-OWNERSHIP-ALL-CALLS-BOUND-STATIC' `
    -Category 'ownership_contract' -Body {
    $starts = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.CommandAst] -and
            $node.GetCommandName() -ceq 'Start-I04RestrictedProcess'
    }, $true))
    $registers = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.CommandAst] -and
            $node.GetCommandName() -ceq 'Register-I04OwnedProcess'
    }, $true))
    $stops = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.CommandAst] -and
            $node.GetCommandName() -ceq 'Stop-I04OwnedProcess'
    }, $true))
    Assert-I04Offline -Condition (
        $starts.Count -eq 2 -and $registers.Count -eq 2 -and
        $stops.Count -gt 0) `
        -Code 'PROCESS_START_REGISTER_STOP_COUNT_MISMATCH'
    foreach ($call in $registers) {
        $parameters = @($call.CommandElements | Where-Object {
            $_ -is [Management.Automation.Language.CommandParameterAst]
        } | ForEach-Object ParameterName)
        Assert-I04Offline -Condition (
            $parameters -ccontains 'Process' -and
            $parameters -ccontains 'ExpectedPath' -and
            $parameters -ccontains 'OwnerRole' -and
            $parameters -ccontains 'Nonce') `
            -Code 'PROCESS_REGISTRATION_CALL_UNBOUND'
    }
    foreach ($call in $stops) {
        $parameters = @($call.CommandElements | Where-Object {
            $_ -is [Management.Automation.Language.CommandParameterAst]
        } | ForEach-Object ParameterName)
        Assert-I04Offline -Condition (
            $parameters -ccontains 'Process' -and
            $parameters -ccontains 'ExpectedPath') `
            -Code 'PROCESS_STOP_CALL_UNBOUND'
    }
}

Invoke-I04OfflineTest -Id 'CLEANUP-TERMINAL-OWNERSHIP-CENSUS-STATIC' `
    -Category 'cleanup_contract' -Body {
    $census = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Get-I04TerminalOwnershipCensus'
    }, $true))
    Assert-I04Offline -Condition ($census.Count -eq 1) `
        -Code 'TERMINAL_OWNERSHIP_CENSUS_NOT_EXACTLY_ONE'
    $text = $census[0].Extent.Text
    foreach ($needle in @(
        '[AllowEmptyCollection()][object[]]$OwnedProcesses',
        'Get-Process -ErrorAction Stop',
        'Get-NetTCPConnection -ErrorAction Stop',
        'Get-NetUDPEndpoint -ErrorAction Stop',
        '[int]$_.Id -in $ProcessIds',
        '[int]$_.OwningProcess -in $ProcessIds',
        '[int]$_.LocalPort -in $Ports',
        'Test-I04OwnedProcessDescendants',
        'i04_descendant_collector_failed',
        'i04_descendant_root_identity_contradicted',
        'i04_descendant_observed',
        'collector_ok = $descendantCollectorOk',
        'collector_ok = $false',
        'remaining_processes = $remainingProcesses',
        'remaining_tcp = $tcp', 'remaining_udp = $udp',
        'descendant_census = $descendantAudits.ToArray()',
        '$descendantCollectorOk -and $descendantsClear',
        'all_clear = $false')) {
        Assert-I04Offline -Condition ($text.Contains($needle)) `
            -Code 'TERMINAL_OWNERSHIP_CENSUS_FIELD_MISSING'
    }
    Assert-I04Offline -Condition (
        $text -notmatch 'ErrorAction\s+SilentlyContinue') `
        -Code 'TERMINAL_OWNERSHIP_CENSUS_COLLAPSES_FAILURE'
}

Invoke-I04OfflineTest -Id 'CLEANUP-TERMINAL-CENSUS-BOTH-ROLES-STATIC' `
    -Category 'cleanup_contract' -Body {
    $roleContracts = @(
        [pscustomobject]@{
            function_name = 'Invoke-I04PeerRole'
            ports = @('PeerTcpPort', 'PeerUdpPort', 'PeerWebPort')
            cleanup_property = 'terminal_ownership_census = $peerTerminalCensus'
        },
        [pscustomobject]@{
            function_name = 'Invoke-I04CoordinatorRole'
            ports = @('ClientTcpPort', 'ClientUdpPort', 'ClientWebPort')
            cleanup_property = 'terminal_ownership_census = $clientTerminalCensus'
        }
    )
    foreach ($contract in $roleContracts) {
        $role = @($script:HarnessAst.FindAll({
            param($node)
            $node -is `
                [Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -ceq $contract.function_name
        }, $true))[0]
        $terminalCalls = @($role.FindAll({
            param($node)
            $node -is [Management.Automation.Language.CommandAst] -and
                $node.GetCommandName() -ceq
                    'Get-I04TerminalOwnershipCensus'
        }, $true))
        $stopOffsets = @($role.FindAll({
            param($node)
            $node -is [Management.Automation.Language.CommandAst] -and
                $node.GetCommandName() -ceq 'Stop-I04OwnedProcess'
        }, $true) | ForEach-Object { $_.Extent.StartOffset })
        Assert-I04Offline -Condition (
            $terminalCalls.Count -eq 1 -and $stopOffsets.Count -gt 0 -and
            $terminalCalls[0].Extent.StartOffset -gt
                ($stopOffsets | Measure-Object -Maximum).Maximum) `
            -Code 'TERMINAL_CENSUS_NOT_AFTER_ALL_OWNED_STOPS'
        $callText = $terminalCalls[0].Extent.Text
        foreach ($port in $contract.ports) {
            Assert-I04Offline -Condition (
                $callText.Contains('$' + $port)) `
                -Code 'TERMINAL_CENSUS_PORT_SET_INCOMPLETE'
        }
        $roleText = $role.Extent.Text
        Assert-I04Offline -Condition (
            $callText.Contains('-OwnedProcesses') -and
            $roleText.Contains($contract.cleanup_property) -and
            $roleText.Contains('.collector_ok') -and
            $roleText.Contains('.all_clear') -and
            $roleText.Contains('cleanupFailures.Add')) `
            -Code 'TERMINAL_CENSUS_NOT_BOUND_TO_CLEANUP'
    }
}

$offlineRegistrySnapshot = [pscustomobject][ordered]@{
    schema = 'ese.v91.i04-registry-subtree/v2'
    path_sha256 = 'a' * 64
    exists = $true
    node_count = 2
    value_count = 3
    tracked_root_value_count = 0
    canonical_sha256 = 'b' * 64
}

Invoke-I04OfflineTest -Id 'REGISTRY-SUBTREE-EQUALITY-POSITIVE' `
    -Category 'registry_contract' -Body {
    $copy = $offlineRegistrySnapshot | ConvertTo-Json -Depth 8 |
        ConvertFrom-Json
    Assert-I04Offline -Condition ([bool](
        Test-I04OfflineRegistrySubtreeSnapshotEqual `
            -Left $offlineRegistrySnapshot -Right $copy)) `
        -Code 'IDENTICAL_REGISTRY_SUBTREE_REJECTED'
}

$registrySnapshotMutations = @(
    [pscustomobject]@{ id='SCHEMA'; property='schema'; value='legacy' },
    [pscustomobject]@{ id='PATH'; property='path_sha256'; value=('c' * 64) },
    [pscustomobject]@{ id='EXISTS'; property='exists'; value=$false },
    [pscustomobject]@{ id='NODE-COUNT'; property='node_count'; value=3 },
    [pscustomobject]@{ id='VALUE-COUNT'; property='value_count'; value=4 },
    [pscustomobject]@{
        id='TRACKED-VALUE'; property='tracked_root_value_count'; value=1
    },
    [pscustomobject]@{
        id='CANONICAL'; property='canonical_sha256'; value=('d' * 64)
    }
)
foreach ($mutation in $registrySnapshotMutations) {
    $capturedMutation = $mutation
    Invoke-I04OfflineTest -Id (
        'REGISTRY-SUBTREE-REJECT-' + $capturedMutation.id) `
        -Category 'registry_contract' -Body {
        $changed = $offlineRegistrySnapshot | ConvertTo-Json -Depth 8 |
            ConvertFrom-Json
        $changed.PSObject.Properties[$capturedMutation.property].Value =
            $capturedMutation.value
        Assert-I04Offline -Condition (-not [bool](
            Test-I04OfflineRegistrySubtreeSnapshotEqual `
                -Left $offlineRegistrySnapshot -Right $changed)) `
            -Code 'CHANGED_REGISTRY_SUBTREE_ACCEPTED'
    }
}

$offlineRegistrySidHash = 'a' * 64
$offlineFirewallSnapshot = [pscustomobject][ordered]@{
    schema = 'ese.v91.i04-global-firewall-snapshot/v2'
    canonical_sha256 = 'f' * 64
}

Invoke-I04OfflineTest -Id 'REGISTRY-HKCU-RUN-BASELINE-EXISTS-POSITIVE' `
    -Category 'registry_contract' -Body {
    $baseline = New-I04OfflineAccountRegistrySnapshot `
        -UserSidSha256 $offlineRegistrySidHash -RunExists $true
    $transaction = Start-I04OfflineRegistryTransaction `
        -Baseline $baseline -FirewallBaseline $offlineFirewallSnapshot `
        -ExpectedUserSidSha256 $offlineRegistrySidHash
    Assert-I04Offline -Condition (
        [bool]$transaction.initial_absence_proved -and
        [bool]$transaction.baseline.run_subtree.exists) `
        -Code 'EXISTING_HKCU_RUN_BASELINE_REJECTED'
}

Invoke-I04OfflineTest -Id 'REGISTRY-HKCU-RUN-BASELINE-MISSING-REJECT' `
    -Category 'registry_contract' -Body {
    $baseline = New-I04OfflineAccountRegistrySnapshot `
        -UserSidSha256 $offlineRegistrySidHash -RunExists $false
    Assert-I04OfflineThrows `
        -ExpectedCode 'I04 requires the HKCU Run key to exist' -Body {
        Start-I04OfflineRegistryTransaction `
            -Baseline $baseline -FirewallBaseline $offlineFirewallSnapshot `
            -ExpectedUserSidSha256 $offlineRegistrySidHash
    }
}

Invoke-I04OfflineTest -Id 'REGISTRY-HKCU-RUN-AFTER-EXISTS-POSITIVE' `
    -Category 'registry_contract' -Body {
    $baseline = New-I04OfflineAccountRegistrySnapshot `
        -UserSidSha256 $offlineRegistrySidHash -RunExists $true
    $transaction = Start-I04OfflineRegistryTransaction `
        -Baseline $baseline -FirewallBaseline $offlineFirewallSnapshot `
        -ExpectedUserSidSha256 $offlineRegistrySidHash
    $after = New-I04OfflineAccountRegistrySnapshot `
        -UserSidSha256 $offlineRegistrySidHash -RunExists $true
    $post = Get-I04OfflineRegistryPostcheckEvidence `
        -Transaction $transaction -After $after `
        -FirewallAfter $offlineFirewallSnapshot
    Assert-I04Offline -Condition (
        [bool]$post.collector_ok -and [bool]$post.safe_to_pass -and
        [bool]$post.run_subtree_existed_before -and
        [bool]$post.run_subtree_exists_after) `
        -Code 'EXISTING_HKCU_RUN_POST_STATE_REJECTED'
}

Invoke-I04OfflineTest -Id 'REGISTRY-HKCU-RUN-AFTER-MISSING-BLOCKS' `
    -Category 'registry_contract' -Body {
    $baseline = New-I04OfflineAccountRegistrySnapshot `
        -UserSidSha256 $offlineRegistrySidHash -RunExists $true
    $transaction = Start-I04OfflineRegistryTransaction `
        -Baseline $baseline -FirewallBaseline $offlineFirewallSnapshot `
        -ExpectedUserSidSha256 $offlineRegistrySidHash
    $after = New-I04OfflineAccountRegistrySnapshot `
        -UserSidSha256 $offlineRegistrySidHash -RunExists $false
    $post = Get-I04OfflineRegistryPostcheckEvidence `
        -Transaction $transaction -After $after `
        -FirewallAfter $offlineFirewallSnapshot
    Assert-I04Offline -Condition (
        [bool]$post.collector_ok -and -not [bool]$post.safe_to_pass -and
        [bool]$post.run_subtree_existed_before -and
        -not [bool]$post.run_subtree_exists_after) `
        -Code 'MISSING_HKCU_RUN_POST_STATE_ACCEPTED'
}

Invoke-I04OfflineTest -Id 'REGISTRY-HKCU-TRANSACTION-FAIL-CLOSED-STATIC' `
    -Category 'registry_contract' -Body {
    $once = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Get-I04RegistrySubtreeSnapshotOnce'
    }, $true))[0].Extent.Text
    $stable = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Get-I04RegistrySubtreeSnapshot'
    }, $true))[0].Extent.Text
    $account = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Get-I04AccountRegistrySnapshot'
    }, $true))[0].Extent.Text
    $start = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Start-I04AccountRegistryTransaction'
    }, $true))[0].Extent.Text
    $post = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Get-I04AccountRegistryPostcheckEvidence'
    }, $true))[0].Extent.Text
    foreach ($needle in @(
        '[Microsoft.Win32.Registry]::CurrentUser.OpenSubKey',
        'RegistryValueOptions]::DoNotExpandEnvironmentNames',
        'Registry value changed during fail-closed capture',
        'Registry subtree changed during fail-closed capture',
        'Registry subtree names changed during fail-closed capture',
        'canonical_sha256', 'tracked_root_value_count')) {
        Assert-I04Offline -Condition ($once.Contains($needle)) `
            -Code 'REGISTRY_CANONICAL_CAPTURE_GUARD_MISSING'
    }
    Assert-I04Offline -Condition (
        ([regex]::Matches(
            $stable, 'Get-I04RegistrySubtreeSnapshotOnce')).Count -eq 2 -and
        $stable.Contains('Test-I04RegistrySubtreeSnapshotEqual') -and
        $stable.Contains(
            'Registry subtree was not stable across the baseline capture')) `
        -Code 'REGISTRY_DOUBLE_SNAPSHOT_GUARD_MISSING'
    foreach ($needle in @(
        '[Security.Principal.WindowsIdentity]::GetCurrent()',
        'Software\Microsoft\Windows\CurrentVersion\Run',
        "-TrackedRootValueName 'eMuleAutoStart'",
        'Software\Classes\ed2k', 'user_sid_sha256',
        'emule_autostart_absent', 'ed2k_subtree_absent')) {
        Assert-I04Offline -Condition ($account.Contains($needle)) `
            -Code 'ACCOUNT_REGISTRY_BINDING_FIELD_MISSING'
    }
    foreach ($needle in @(
        '-not [bool]$baseline.run_subtree.exists',
        'emule_autostart_absent', 'ed2k_subtree_absent',
        'Get-I04GlobalFirewallSnapshot',
        'initial_absence_proved = $true',
        'destructive_restore_permitted = $false')) {
        Assert-I04Offline -Condition ($start.Contains($needle)) `
            -Code 'REGISTRY_INITIAL_ABSENCE_GATE_MISSING'
    }
    foreach ($needle in @(
        'Test-I04RegistrySubtreeSnapshotEqual',
        'Get-I04GlobalFirewallSnapshot',
        '[bool]$Transaction.baseline.run_subtree.exists',
        '[bool]$after.run_subtree.exists',
        'global_firewall_unchanged = $firewallUnchanged',
        'collector_ok = $false', 'safe_to_pass = $false',
        'destructive_restore_attempted = $false')) {
        Assert-I04Offline -Condition ($post.Contains($needle)) `
            -Code 'REGISTRY_POSTCHECK_NOT_FAIL_CLOSED'
    }
    Assert-I04Offline -Condition (
        $post -notmatch '(?m)^\s*global_firewall_unchanged\s*=\s*\$true') `
        -Code 'FIREWALL_UNCHANGED_HARDCODED_TRUE'
}

Invoke-I04OfflineTest -Id 'REGISTRY-TRANSACTION-WIRED-PRE-POST-STATIC' `
    -Category 'registry_contract' -Body {
    $starts = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.CommandAst] -and
            $node.GetCommandName() -ceq
                'Start-I04AccountRegistryTransaction'
    }, $true))
    Assert-I04Offline -Condition ($starts.Count -eq 1) `
        -Code 'ACCOUNT_REGISTRY_TRANSACTION_START_NOT_EXACTLY_ONE'
    foreach ($roleName in @(
        'Invoke-I04PeerRole', 'Invoke-I04CoordinatorRole')) {
        $role = @($script:HarnessAst.FindAll({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] `
                -and $node.Name -ceq $roleName
        }, $true))[0]
        $preferenceWrites = @($role.FindAll({
            param($node)
            $node -is [Management.Automation.Language.CommandAst] -and
                $node.GetCommandName() -ceq 'Set-I04IsolatedPreferences'
        }, $true))
        $postchecks = @($role.FindAll({
            param($node)
            $node -is [Management.Automation.Language.CommandAst] -and
                $node.GetCommandName() -ceq
                    'Get-I04AccountRegistryPostcheckEvidence'
        }, $true))
        $roleText = $role.Extent.Text
        Assert-I04Offline -Condition (
            $preferenceWrites.Count -eq 1 -and $postchecks.Count -eq 1 -and
            $starts[0].Extent.StartOffset -lt
                $preferenceWrites[0].Extent.StartOffset -and
            $roleText.Contains('.collector_ok') -and
            $roleText.Contains('.safe_to_pass')) `
            -Code 'ACCOUNT_REGISTRY_TRANSACTION_NOT_BOUND_TO_ROLE'
    }
    Assert-I04Offline -Condition (
        $script:HarnessText -match
            '\$peerResult\.cleanup\s*\.\s*account_registry_transaction' -and
        $script:HarnessText.Contains('.global_firewall_unchanged') -and
        $script:HarnessText -match '\.\s*destructive_restore_attempted') `
        -Code 'PEER_REGISTRY_POSTCHECK_NOT_BOUND_TO_COORDINATOR'
}

Invoke-I04OfflineTest -Id 'FIREWALL-CANONICAL-PROJECTION-DETERMINISTIC' `
    -Category 'firewall_contract' -Body {
    $first = [pscustomobject]@{ CimInstanceProperties = @(
        [pscustomobject]@{ Name='Zeta'; CimType='String'; Value='tail' },
        [pscustomobject]@{ Name='Enabled'; CimType='Boolean'; Value=$true },
        [pscustomobject]@{
            Name='Addresses'; CimType='StringArray'; Value=@('z', 'a')
        }
    ) }
    $second = [pscustomobject]@{ CimInstanceProperties = @(
        [pscustomobject]@{
            Name='Addresses'; CimType='StringArray'; Value=@('a', 'z')
        },
        [pscustomobject]@{ Name='Enabled'; CimType='Boolean'; Value=$true },
        [pscustomobject]@{ Name='Zeta'; CimType='String'; Value='tail' }
    ) }
    $canonicalA = Get-I04OfflineFirewallCimCanonical -Instance $first
    $canonicalB = Get-I04OfflineFirewallCimCanonical -Instance $second
    Assert-I04Offline -Condition (
        [string]$canonicalA -ceq [string]$canonicalB -and
        $canonicalA.Contains('addresses|StringArray|array:[') -and
        $canonicalA.IndexOf('addresses|') -lt
            $canonicalA.IndexOf('enabled|') -and
        $canonicalA.IndexOf('enabled|') -lt $canonicalA.IndexOf('zeta|')) `
        -Code 'FIREWALL_CANONICAL_PROJECTION_NONDETERMINISTIC'
}

Invoke-I04OfflineTest -Id 'FIREWALL-GLOBAL-SNAPSHOT-COMPLETE-STATIC' `
    -Category 'firewall_contract' -Body {
    $once = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Get-I04GlobalFirewallSnapshotOnce'
    }, $true))[0].Extent.Text
    $stable = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Get-I04GlobalFirewallSnapshot'
    }, $true))[0].Extent.Text
    foreach ($collector in @(
        'Get-NetFirewallRule', 'Get-NetFirewallPortFilter',
        'Get-NetFirewallApplicationFilter', 'Get-NetFirewallAddressFilter',
        'Get-NetFirewallInterfaceFilter',
        'Get-NetFirewallInterfaceTypeFilter',
        'Get-NetFirewallServiceFilter', 'Get-NetFirewallSecurityFilter')) {
        Assert-I04Offline -Condition ($once.Contains($collector)) `
            -Code 'GLOBAL_FIREWALL_COLLECTOR_MISSING'
    }
    Assert-I04Offline -Condition (
        $once.Contains('-PolicyStore ActiveStore -ErrorAction Stop') -and
        $once.Contains('Global firewall collector returned no') -and
        $once.Contains('Get-I04FirewallCimCanonical') -and
        $once.Contains('canonical_sha256') -and
        $once.Contains("privacy_safe = `$true") -and
        ([regex]::Matches(
            $stable, 'Get-I04GlobalFirewallSnapshotOnce')).Count -eq 2 -and
        $stable.Contains('Global firewall inventory was not stable')) `
        -Code 'GLOBAL_FIREWALL_SNAPSHOT_NOT_COMPLETE_FAIL_CLOSED'
}

Invoke-I04OfflineTest -Id 'PRODUCT-LOG-COLLECTOR-POSITIVE' `
    -Category 'log_contract' -Body {
    $node = Join-Path $script:TempRoot 'logs-positive'
    [IO.Directory]::CreateDirectory($node) | Out-Null
    $logPath = Join-Path $node 'emule.log'
    $lines = @(
        'IPv6 connect failed (2001:4860::20 bounded blackhole timeout; retrying target over IPv4)',
        '>>> OP_Hello to 1.1.1.1',
        '<<< OP_HelloAnswer from 1.1.1.1',
        'ooo Swapped source fixture-a.bin to fixture-b.bin for 1.1.1.1'
    )
    [IO.File]::WriteAllLines(
        $logPath, $lines, [Text.UTF8Encoding]::new($false))
    $value = Get-I04OfflineProductLogCounts -NodePath $node
    Assert-I04Offline -Condition (
        [string]$value.schema -ceq
            'ese.v91.i04-product-log-counts/v2' -and
        [bool]$value.collector_ok -and [bool]$value.adjudicable -and
        [int]$value.log_file_count -eq 1 -and
        [int]$value.fallback_count -eq 1 -and
        [int]$value.bounded_fallback_count -eq 1 -and
        [int]$value.hello_send_count -eq 1 -and
        [int]$value.hello_answer_receive_count -eq 1 -and
        [int]$value.a4af_swap_a_to_b_count -eq 1 -and
        [int]$value.ambiguous_target_marker_count -eq 0) `
        -Code 'PRODUCT_LOG_COUNTS_OR_ADJUDICABILITY_WRONG'
}

Invoke-I04OfflineTest -Id 'PRODUCT-LOG-MISSING-NOT-ADJUDICABLE' `
    -Category 'log_contract' -Body {
    $node = Join-Path $script:TempRoot 'logs-empty'
    [IO.Directory]::CreateDirectory($node) | Out-Null
    $value = Get-I04OfflineProductLogCounts -NodePath $node
    Assert-I04Offline -Condition (
        [bool]$value.collector_ok -and -not [bool]$value.adjudicable -and
        [int]$value.log_file_count -eq 0) `
        -Code 'MISSING_LOG_SNAPSHOT_COLLAPSED_TO_VALID_ZERO'
}

Invoke-I04OfflineTest -Id 'PRODUCT-LOG-ENUMERATION-FAIL-CLOSED' `
    -Category 'log_contract' -Body {
    $missing = Join-Path $script:TempRoot 'logs-do-not-exist'
    $value = Get-I04OfflineProductLogCounts -NodePath $missing
    Assert-I04Offline -Condition (
        -not [bool]$value.collector_ok -and
        -not [bool]$value.adjudicable -and
        @($value.collector_errors).Count -gt 0) `
        -Code 'LOG_ENUMERATION_ERROR_COLLAPSED_TO_VALID_ZERO'
}

Invoke-I04OfflineTest -Id 'PRODUCT-LOG-READ-FAIL-CLOSED' `
    -Category 'log_contract' -Body {
    $node = Join-Path $script:TempRoot 'logs-locked'
    [IO.Directory]::CreateDirectory($node) | Out-Null
    $logPath = Join-Path $node 'locked.log'
    [IO.File]::WriteAllText($logPath, 'private fixture')
    $lock = [IO.File]::Open(
        $logPath, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite,
        [IO.FileShare]::None)
    try {
        $value = Get-I04OfflineProductLogCounts -NodePath $node
    } finally { $lock.Dispose() }
    Assert-I04Offline -Condition (
        -not [bool]$value.collector_ok -and
        -not [bool]$value.adjudicable -and
        @($value.collector_errors).Count -gt 0) `
        -Code 'LOG_READ_ERROR_COLLAPSED_TO_VALID_ZERO'
}

Invoke-I04OfflineTest -Id 'PRODUCT-LOG-ADJUDICATION-WIRING-STATIC' `
    -Category 'log_contract' -Body {
    $roleText = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Invoke-I04CoordinatorRole'
    }, $true))[0].Extent.Text
    foreach ($needle in @(
        '$logBefore.collector_ok', '$logBefore.adjudicable',
        '$liveLog.collector_ok', '$liveLog.adjudicable',
        '$logAfter.collector_ok', '$logAfter.adjudicable',
        '$null -ne $logBefore', '$null -ne $logAfter',
        '$logsAdjudicable', 'I04_LOG_COLLECTOR_BLOCKED')) {
        Assert-I04Offline -Condition ($roleText.Contains($needle)) `
            -Code 'PRODUCT_LOG_FAILURE_NOT_BOUND_TO_BLOCKED'
    }
    Assert-I04Offline -Condition (
        $roleText.IndexOf('$logsAdjudicable') -lt
            $roleText.IndexOf('$fallbackDelta =') -and
        $roleText.Contains('if (-not $logsAdjudicable') -and
        $roleText.Contains('blockedReasons.Add')) `
        -Code 'MISSING_LOGS_COULD_ADJUDICATE_ZERO_DELTAS'
}

Invoke-I04OfflineTest -Id 'API-ISOLATION-POSITIVE' `
    -Category 'api_contract' -Body {
    Assert-I04Offline -Condition (
        [bool](Test-I04OfflineApiIsolation `
            -Data (New-I04OfflineApiFixture)) -and
        [bool](Test-I04OfflineApiIsolation `
            -Data (New-I04OfflineApiFixture -RequireEd2k $true) `
            -RequireEd2k $true)) `
        -Code 'SAFE_API_ISOLATION_REJECTED'
}

$apiIsolationMutations = @(
    [pscustomobject]@{ id = 'UNAVAILABLE'; path = 'available'; value = $false },
    [pscustomobject]@{ id = 'USERHASH'; path = 'user_hash'; value = 'raw-invalid' },
    [pscustomobject]@{ id = 'ED2K'; path = 'ed2k_connected'; value = $true },
    [pscustomobject]@{ id = 'KAD'; path = 'kad_running_mask'; value = [Int64]1 },
    [pscustomobject]@{ id = 'NETLAB'; path = 'netlab_enabled'; value = $true },
    [pscustomobject]@{ id = 'UTP'; path = 'utp_hole_punch_enabled'; value = $true },
    [pscustomobject]@{ id = 'V9-MISSING'; path = 'v9'; value = $null },
    [pscustomobject]@{ id = 'V9-EXPERIMENTAL'; path = 'v9.v9.experimental'; value = $true },
    [pscustomobject]@{ id = 'RELAY'; path = 'v9.netlab.independent.relay_accept'; value = $true }
)
foreach ($mutation in $apiIsolationMutations) {
    $capturedMutation = $mutation
    Invoke-I04OfflineTest -Id ('API-ISOLATION-REJECT-' + $capturedMutation.id) `
        -Category 'api_contract' -Body {
        $value = New-I04OfflineApiFixture
        switch ([string]$capturedMutation.path) {
            'v9.v9.experimental' {
                $value.v9.v9.experimental = $capturedMutation.value
            }
            'v9.netlab.independent.relay_accept' {
                $value.v9.netlab.independent.relay_accept =
                    $capturedMutation.value
            }
            default { $value.($capturedMutation.path) = $capturedMutation.value }
        }
        $accepted = $false
        try {
            $accepted = [bool](Test-I04OfflineApiIsolation -Data $value)
        } catch { $accepted = $false }
        Assert-I04Offline -Condition (-not $accepted) `
            -Code 'UNSAFE_API_ISOLATION_ACCEPTED'
    }
}

$apiTypeMutations = @(
    [pscustomobject]@{
        id = 'BOOL-STRING'; mutation = {
            param($value) $value.ed2k_connected = 'False'
        }
    },
    [pscustomobject]@{
        id = 'INTEGER-STRING'; mutation = {
            param($value) $value.kad_running_mask = '0'
        }
    },
    [pscustomobject]@{
        id = 'INTEGER-FRACTION'; mutation = {
            param($value) $value.kad_running_mask = [double]0.5
        }
    },
    [pscustomobject]@{
        id = 'NESTED-BOOL-STRING'; mutation = {
            param($value) $value.v9.netlab.staged.selector = 'False'
        }
    },
    [pscustomobject]@{
        id = 'NULL-STRING'; mutation = {
            param($value) $value.user_hash = $null
        }
    },
    [pscustomobject]@{
        id = 'NULL-NESTED-OBJECT'; mutation = {
            param($value) $value.v9.netlab.staged = $null
        }
    },
    [pscustomobject]@{
        id = 'MISSING-PROPERTY'; mutation = {
            param($value) $value.PSObject.Properties.Remove('kad2_running')
        }
    }
)
foreach ($mutation in $apiTypeMutations) {
    $capturedMutation = $mutation
    Invoke-I04OfflineTest -Id ('API-CONTRACT-TYPE-' + $capturedMutation.id) `
        -Category 'api_contract' -Body {
        $value = New-I04OfflineApiFixture
        & $capturedMutation.mutation $value
        Assert-I04OfflineThrows -ExpectedCode 'JSON' -Body {
            Test-I04OfflineApiIsolation -Data $value
        }
    }
}

Invoke-I04OfflineTest -Id 'API-CONTRACT-RUNTIME-WIRING-STATIC' `
    -Category 'api_contract' -Body {
    $probeText = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Get-I04ApiProbe'
    }, $true))[0].Extent.Text
    Assert-I04Offline -Condition (
        $probeText.Contains('Assert-I04ApiStatusContract -Status $status') -and
        $probeText.Contains('Assert-I04ApiV9Contract -Value $v9') -and
        $probeText.IndexOf('Assert-I04ApiStatusContract') -lt
            $probeText.IndexOf('$statusAvailable = $true') -and
        $probeText.IndexOf('Assert-I04ApiV9Contract') -lt
            $probeText.IndexOf('$v9Available = $true')) `
        -Code 'API_TYPES_NOT_ASSERTED_BEFORE_AVAILABILITY'
}

$partialVerdictCases = @(
    [pscustomobject]@{ id='PASS'; complete=$true; proved=$false; contradicted=$false; count=0; expected='PASS' },
    [pscustomobject]@{ id='FIXTURE-INCOMPLETE'; complete=$false; proved=$false; contradicted=$false; count=0; expected='BLOCKED' },
    [pscustomobject]@{ id='UNPROVED-LISTED-FAILURE'; complete=$true; proved=$false; contradicted=$false; count=1; expected='BLOCKED' },
    [pscustomobject]@{ id='PROVED-WITHOUT-COUNT'; complete=$true; proved=$true; contradicted=$false; count=0; expected='BLOCKED' },
    [pscustomobject]@{ id='PROVED-FAIL'; complete=$true; proved=$true; contradicted=$false; count=1; expected='FAIL' },
    [pscustomobject]@{ id='PROVED-FAIL-LATER-LAB-INCIDENT'; complete=$false; proved=$true; contradicted=$false; count=1; expected='FAIL' },
    [pscustomobject]@{ id='PROOF-CONTRADICTED'; complete=$true; proved=$true; contradicted=$true; count=1; expected='BLOCKED' },
    [pscustomobject]@{ id='CONTRADICTION-NO-FAILURE'; complete=$true; proved=$false; contradicted=$true; count=0; expected='BLOCKED' }
)
foreach ($case in $partialVerdictCases) {
    $capturedCase = $case
    Invoke-I04OfflineTest -Id ('ADJUDICATION-PARTIAL-' + $capturedCase.id) `
        -Category 'adjudication' -Body {
        $actual = Get-I04OfflinePartialVerdict `
            -FixtureProofComplete $capturedCase.complete `
            -ProductFailureProved $capturedCase.proved `
            -ProofContradicted $capturedCase.contradicted `
            -ProductFailureCount $capturedCase.count
        Assert-I04OfflineEqual -Actual $actual -Expected $capturedCase.expected `
            -Code 'PARTIAL_VERDICT_PRECEDENCE_MISMATCH'
    }
}

$failureDispositionCases = @(
    [pscustomobject]@{ id='PRE-ARM'; armed=$false; boundary=$false; failure=(New-I04OfflineProductFailure); contradicted=$false; expected='BLOCKED' },
    [pscustomobject]@{ id='ARMED-NO-BOUNDARY'; armed=$true; boundary=$false; failure=(New-I04OfflineProductFailure); contradicted=$false; expected='BLOCKED' },
    [pscustomobject]@{ id='NO-TYPED-FAILURE'; armed=$true; boundary=$true; failure=$null; contradicted=$false; expected='BLOCKED' },
    [pscustomobject]@{ id='PROOF-CONTRADICTED'; armed=$true; boundary=$true; failure=(New-I04OfflineProductFailure); contradicted=$true; expected='BLOCKED' },
    [pscustomobject]@{ id='PROVED-POST-BOUNDARY'; armed=$true; boundary=$true; failure=(New-I04OfflineProductFailure); contradicted=$false; expected='FAIL' },
    [pscustomobject]@{ id='PROVED-SOCKET-CONTRACT'; armed=$true; boundary=$true; failure=(New-I04OfflineProductFailure -FailureType socket_contract -SourceKind socket_sampler); contradicted=$false; expected='FAIL' }
)
foreach ($case in $failureDispositionCases) {
    $capturedCase = $case
    Invoke-I04OfflineTest -Id ('FAILURE-DISPOSITION-' + $capturedCase.id) `
        -Category 'adjudication' -Body {
        $value = Get-I04OfflineFailureDisposition `
            -CaseArmed $capturedCase.armed `
            -FormalBoundaryPublished $capturedCase.boundary `
            -CandidateFailure $capturedCase.failure `
            -ProofContradicted $capturedCase.contradicted `
            -ExceptionMessage 'private-exception-sentinel'
        $expectedPostBoundary =
            [string]$capturedCase.expected -ceq 'FAIL'
        Assert-I04Offline -Condition (
            [string]$value.classification -ceq $capturedCase.expected -and
            [bool]$value.candidate_post_boundary -eq
                $expectedPostBoundary -and
            [bool]$value.candidate_failure_proved -eq
                $expectedPostBoundary -and
            [bool]$value.candidate_failure_contract_valid -eq
                ($null -ne $capturedCase.failure)) `
            -Code 'FAILURE_DISPOSITION_BOUNDARY_MISMATCH'
    }
}

$failureNegativeCases = @(
    [pscustomobject]@{
        id = 'LEGACY-STRING'; expected_contract = $false
        failure = 'legacy raw failure string'
    },
    [pscustomobject]@{
        id = 'COLLECTOR-FALSE'; expected_contract = $true
        failure = New-I04OfflineProductFailure -CollectorOk $false `
            -Adjudicable $false
    },
    [pscustomobject]@{
        id = 'EVIDENCE-CONTRACT-FALSE'; expected_contract = $false
        failure = New-I04OfflineProductFailure `
            -EvidenceContractValid $false -SourceBound $false `
            -Adjudicable $false
    },
    [pscustomobject]@{
        id = 'NO-SOURCE-OWNER'; expected_contract = $false
        failure = New-I04OfflineProductFailure -BindingExact $false `
            -SourceBound $false -Adjudicable $false
    },
    [pscustomobject]@{
        id = 'PRE-BOUNDARY'; expected_contract = $true
        failure = New-I04OfflineProductFailure -PostBoundary $false `
            -Adjudicable $false
    }
)
$boolStringFailure = New-I04OfflineProductFailure
$boolStringFailure.post_boundary = 'True'
$failureNegativeCases += [pscustomobject]@{
    id = 'BOOL-STRING'; expected_contract = $false
    failure = $boolStringFailure
}
$boolTimestampFailure = New-I04OfflineProductFailure
$boolTimestampFailure.observed_at_epoch_ms = $true
$failureNegativeCases += [pscustomobject]@{
    id = 'BOOL-TIMESTAMP'; expected_contract = $false
    failure = $boolTimestampFailure
}
$nanTimestampFailure = New-I04OfflineProductFailure
$nanTimestampFailure.observed_at_epoch_ms = [double]::NaN
$failureNegativeCases += [pscustomobject]@{
    id = 'NAN-TIMESTAMP'; expected_contract = $false
    failure = $nanTimestampFailure
}
$evidenceHashTamper = New-I04OfflineProductFailure
$evidenceHashTamper.source.evidence.offline_fixture = $false
$failureNegativeCases += [pscustomobject]@{
    id = 'EVIDENCE-HASH-TAMPER'; expected_contract = $false
    failure = $evidenceHashTamper
}
$snapshotLockStringFailure = New-I04OfflineProductFailure
$snapshotLockStringFailure.source.evidence.
    pcapng_source_immutable_read_lock_held = 'false'
$snapshotLockStringFailure.source.evidence_sha256 =
    Get-I04OfflineStringSha256 -Value (
        $snapshotLockStringFailure.source.evidence |
            ConvertTo-Json -Compress -Depth 32)
$failureNegativeCases += [pscustomobject]@{
    id = 'SOURCE-LOCK-STRING-REHASHED'; expected_contract = $false
    failure = $snapshotLockStringFailure
}
$snapshotBytesStringFailure = New-I04OfflineProductFailure
$snapshotBytesStringFailure.source.evidence.pcapng_source_byte_count = '8192'
$snapshotBytesStringFailure.source.evidence_sha256 =
    Get-I04OfflineStringSha256 -Value (
        $snapshotBytesStringFailure.source.evidence |
            ConvertTo-Json -Compress -Depth 32)
$failureNegativeCases += [pscustomobject]@{
    id = 'SOURCE-BYTES-STRING-REHASHED'; expected_contract = $false
    failure = $snapshotBytesStringFailure
}
$snapshotBoundaryFailure = New-I04OfflineProductFailure
$snapshotBoundaryFailure.source.evidence.
    coordinator_stop_a_boundary_epoch_ms = [double]1000001
$snapshotBoundaryFailure.source.evidence_sha256 =
    Get-I04OfflineStringSha256 -Value (
        $snapshotBoundaryFailure.source.evidence |
            ConvertTo-Json -Compress -Depth 32)
$failureNegativeCases += [pscustomobject]@{
    id = 'SOURCE-BOUNDARY-REHASHED'; expected_contract = $false
    failure = $snapshotBoundaryFailure
}
$packetKindMismatchFailure = New-I04OfflineProductFailure `
    -FailureType socket_contract -SourceKind packet_verdict
$failureNegativeCases += [pscustomobject]@{
    id = 'SOURCE-KIND-PACKET-MISMATCH'; expected_contract = $false
    failure = $packetKindMismatchFailure
}
$socketKindMismatchFailure = New-I04OfflineProductFailure `
    -FailureType fallback_window -SourceKind socket_sampler
$failureNegativeCases += [pscustomobject]@{
    id = 'SOURCE-KIND-SOCKET-MISMATCH'; expected_contract = $false
    failure = $socketKindMismatchFailure
}
$restrictedJobMutations = @(
    [pscustomobject]@{ id='CONTRACT-ID'; mutation={
        param($value) $value.candidate_binding.restricted_job_contract_id =
            'legacy'
    } },
    [pscustomobject]@{ id='LIMIT'; mutation={
        param($value)
        $value.candidate_binding.restricted_job_active_process_limit = 2
    } },
    [pscustomobject]@{ id='LIMIT-STRING'; mutation={
        param($value)
        $value.candidate_binding.restricted_job_active_process_limit = '1'
    } },
    [pscustomobject]@{ id='ASSIGNED'; mutation={
        param($value)
        $value.candidate_binding.restricted_job_assigned_before_resume = $false
    } },
    [pscustomobject]@{ id='ASSIGNED-STRING'; mutation={
        param($value)
        $value.candidate_binding.restricted_job_assigned_before_resume = 'true'
    } },
    [pscustomobject]@{ id='ACCOUNTING-MISSING'; mutation={
        param($value)
        $value.candidate_binding.restricted_job_accounting = $null
    } },
    [pscustomobject]@{ id='ACCOUNTING-EXACT'; mutation={
        param($value)
        $value.candidate_binding.restricted_job_accounting_exact = $false
    } },
    [pscustomobject]@{ id='ACCOUNTING-EXACT-STRING'; mutation={
        param($value)
        $value.candidate_binding.restricted_job_accounting_exact = 'true'
    } },
    [pscustomobject]@{ id='ACCOUNTING-SCHEMA'; mutation={
        param($value)
        $value.candidate_binding.restricted_job_accounting.schema = 'legacy'
    } },
    [pscustomobject]@{ id='ACCOUNTING-CONTRACT'; mutation={
        param($value)
        $value.candidate_binding.restricted_job_accounting.contract_id =
            'legacy'
    } },
    [pscustomobject]@{ id='ACCOUNTING-PID'; mutation={
        param($value)
        $value.candidate_binding.restricted_job_accounting.process_id = 4243
    } },
    [pscustomobject]@{ id='ACCOUNTING-LIMIT'; mutation={
        param($value)
        $value.candidate_binding.restricted_job_accounting.active_process_limit =
            2
    } },
    [pscustomobject]@{ id='TOTAL-PROCESSES'; mutation={
        param($value)
        $value.candidate_binding.restricted_job_accounting.total_processes = 2
    } },
    [pscustomobject]@{ id='TOTAL-PROCESSES-STRING'; mutation={
        param($value)
        $value.candidate_binding.restricted_job_accounting.total_processes =
            '1'
    } },
    [pscustomobject]@{ id='ACTIVE-PROCESSES'; mutation={
        param($value)
        $value.candidate_binding.restricted_job_accounting.active_processes = 2
    } },
    [pscustomobject]@{ id='TOTAL-TERMINATED'; mutation={
        param($value)
        $value.candidate_binding.restricted_job_accounting.
            total_terminated_processes = 1
    } },
    [pscustomobject]@{ id='CHILDREN'; mutation={
        param($value)
        $value.candidate_binding.restricted_job_accounting.
            child_processes_structurally_forbidden = $false
    } },
    [pscustomobject]@{ id='CHILDREN-STRING'; mutation={
        param($value)
        $value.candidate_binding.restricted_job_accounting.
            child_processes_structurally_forbidden = 'true'
    } }
)
foreach ($restrictedMutation in $restrictedJobMutations) {
    $failure = New-I04OfflineProductFailure
    & $restrictedMutation.mutation $failure
    $failureNegativeCases += [pscustomobject]@{
        id = 'RESTRICTED-' + [string]$restrictedMutation.id
        expected_contract = $false
        failure = $failure
    }
}
foreach ($case in $failureNegativeCases) {
    $capturedCase = $case
    Invoke-I04OfflineTest -Id (
        'FAILURE-DISPOSITION-REJECT-' + $capturedCase.id) `
        -Category 'adjudication' -Body {
        $value = Get-I04OfflineFailureDisposition -CaseArmed $true `
            -FormalBoundaryPublished $true `
            -CandidateFailure $capturedCase.failure `
            -ProofContradicted $false
        Assert-I04Offline -Condition (
            [string]$value.classification -ceq 'BLOCKED' -and
            -not [bool]$value.candidate_post_boundary -and
            -not [bool]$value.candidate_failure_proved -and
            [bool]$value.candidate_failure_contract_valid -eq
                [bool]$capturedCase.expected_contract) `
            -Code 'UNTYPED_OR_UNBOUND_FAILURE_WAS_PROMOTED'
    }
}

Invoke-I04OfflineTest -Id 'FAILURE-DISPOSITION-BINDING-MISMATCH-BLOCKED' `
    -Category 'adjudication' -Body {
    $failure = New-I04OfflineProductFailure -BindingExact $false `
        -SourceBound $true -Adjudicable $true
    $value = Get-I04OfflineFailureDisposition -CaseArmed $true `
        -FormalBoundaryPublished $true -CandidateFailure $failure `
        -ProofContradicted $false
    Assert-I04Offline -Condition (
        [string]$value.classification -ceq 'BLOCKED' -and
        -not [bool]$value.candidate_failure_proved) `
        -Code 'CONTRADICTORY_CANDIDATE_BINDING_WAS_PROMOTED'
}

Invoke-I04OfflineTest -Id 'FAILURE-DISPOSITION-PRE-BOUNDARY-TIMESTAMP-BLOCKED' `
    -Category 'adjudication' -Body {
    $failure = New-I04OfflineProductFailure
    $failure.observed_at_epoch_ms = [double]999900
    $failure.boundary_epoch_ms = [double]1000000
    $failure.post_boundary = $true
    $value = Get-I04OfflineFailureDisposition -CaseArmed $true `
        -FormalBoundaryPublished $true -CandidateFailure $failure `
        -ProofContradicted $false
    Assert-I04Offline -Condition (
        [string]$value.classification -ceq 'BLOCKED' -and
        -not [bool]$value.candidate_failure_proved) `
        -Code 'PRE_BOUNDARY_FAILURE_TIMESTAMP_WAS_PROMOTED'
}

Invoke-I04OfflineTest -Id 'FAILURE-DISPOSITION-NO-RAW-ERROR' `
    -Category 'privacy_contract' -Body {
    $sentinel = 'private-exception-sentinel'
    $failure = New-I04OfflineProductFailure
    $value = Get-I04OfflineFailureDisposition -CaseArmed $true `
        -FormalBoundaryPublished $true -CandidateFailure $failure `
        -ProofContradicted $false -ExceptionMessage $sentinel
    $json = $value | ConvertTo-Json -Depth 8 -Compress
    $properties = @($value.PSObject.Properties.Name)
    $expectedProperties = @(
        'classification', 'candidate_post_boundary', 'case_armed',
        'formal_boundary_published', 'candidate_failure_contract_valid',
        'candidate_failure_proved',
        'proof_contradicted', 'exception_present',
        'exception_fingerprint_sha256'
    )
    Assert-I04Offline -Condition (
        -not $json.Contains($sentinel) -and
        $json -notmatch '(?i)exception_message|raw_error|message' -and
        $properties.Count -eq $expectedProperties.Count -and
        @($expectedProperties | Where-Object {
            $properties -cnotcontains $_
        }).Count -eq 0 -and
        [bool]$value.exception_present -and
        [string]$value.exception_fingerprint_sha256 -ceq
            (Get-I04OfflineStringSha256 -Value $sentinel)) `
        -Code 'FAILURE_DISPOSITION_LEAKS_RAW_ERROR'
}

Invoke-I04OfflineTest -Id 'PUBLIC-PROJECTION-ALLOWLIST-PRIVACY' `
    -Category 'privacy_contract' -Body {
    $summaryFixture = New-I04OfflineSummaryFixture
    $projection = Get-I04OfflinePublicSummaryProjection `
        -Summary $summaryFixture
    $json = $projection | ConvertTo-Json -Depth 32 -Compress
    foreach ($sentinel in @(
        'private-error-sentinel', 'private-path-sentinel',
        '203.0.113.55', 'stable-user-id-sentinel',
        'private-adapter-sentinel', 'private-blocked-reason-sentinel',
        'private-cleanup-error-sentinel', 'private-raw-log-sentinel')) {
        Assert-I04Offline -Condition (-not $json.Contains($sentinel)) `
            -Code 'PUBLIC_PROJECTION_LEAKED_PRIVATE_SENTINEL'
    }
    Assert-I04Offline -Condition (
        [string]$projection.schema -ceq
            'ese.v91.i04-public-summary/v1' -and
        [string]$projection.projection_policy -ceq
            'explicit-allowlist-v1' -and
        [string]$projection.source_summary_sha256 -ceq ('f' * 64) -and
        $projection.product_failures.Count -eq 1 -and
        [string]$projection.product_failures[0].failure_type -ceq
            'fallback_window' -and
        $projection.counts.product_failure_count -eq 1 -and
        $projection.counts.blocked_reason_count -eq 1 -and
        $projection.counts.cleanup_failure_count -eq 1 -and
        -not [bool]$projection.privacy.direct_identifiers_included -and
        -not [bool]$projection.privacy.raw_paths_included -and
        -not [bool]$projection.privacy.raw_network_endpoints_included -and
        -not [bool]$projection.privacy.raw_logs_or_errors_included -and
        -not [bool]$projection.privacy.stable_host_or_user_ids_included) `
        -Code 'PUBLIC_PROJECTION_CONTRACT_MISMATCH'
}

Invoke-I04OfflineTest -Id 'PUBLIC-PROJECTION-RUNTIME-WIRING-STATIC' `
    -Category 'privacy_contract' -Body {
    $roleText = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Invoke-I04CoordinatorRole'
    }, $true))[0].Extent.Text
    $finalizers = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.IfStatementAst] -and
            $node.Parent -is
                [Management.Automation.Language.NamedBlockAst] -and
            [object]::ReferenceEquals(
                $node.Parent.Parent, $script:HarnessAst) -and
            $node.Extent.Text.Contains(
                '$Role -eq ''Coordinator'' -and $script:i04RoleCompleted')
    }, $true))
    Assert-I04Offline -Condition ($finalizers.Count -eq 1) `
        -Code 'COORDINATOR_TERMINAL_FINALIZER_NOT_EXACT'
    $finalizerText = $finalizers[0].Extent.Text
    Assert-I04Offline -Condition (
        $roleText.Contains('$script:i04CoordinatorPublication =') -and
        $finalizerText.Contains(
            'Get-I04PublicSummaryProjection') -and
        $finalizerText.Contains(
            '-SourceSummarySha256 $summarySha256') -and
        $finalizerText.Contains(
            'Write-LabJson -Value $publicProjection') -and
        $finalizerText.Contains(
            '-Path ([string]$publication.public_summary_path)') -and
        $roleText.Contains(
            "public_summary = 'evidence\public-summary.json'")) `
        -Code 'PUBLIC_PROJECTION_NOT_WRITTEN_FROM_FINAL_SUMMARY'
}

Invoke-I04OfflineTest -Id 'OFFLINE-OUTPUT-PRIVACY-STATIC' `
    -Category 'privacy_contract' -Body {
    $selfText = [IO.File]::ReadAllText($script:SelfPath)
    $testFunctionStart = $selfText.IndexOf(
        'function Invoke-I04OfflineTest')
    $testFunctionEnd = $selfText.IndexOf(
        'function Assert-I04AstNoExternalSideEffects')
    $testFunctionText = $selfText.Substring(
        $testFunctionStart, $testFunctionEnd - $testFunctionStart)
    Assert-I04Offline -Condition (
        $testFunctionText.Contains('failure_sha256') -and
        $testFunctionText.Contains('failure_id') -and
        -not $testFunctionText.Contains('failure_message =') -and
        -not $testFunctionText.Contains('raw_error =') -and
        $selfText.Contains("schema = 'ese.v91.i04-offline-selftest/v1'") -and
        $selfText.Contains("case_id = 'V91-I04'") -and
        $selfText.Contains('physical_execution_performed = $false') -and
        $selfText.Contains("formal_case_status = 'BLOCKED'") -and
        -not $selfText.Contains(
            ('harness_' + 'path = $script:HarnessPath'))) `
        -Code 'OFFLINE_PUBLIC_OUTPUT_PRIVACY_CONTRACT_MISSING'
}

$offlinePreferenceContract = @(
    [pscustomobject]@{
        section = 'eMule'; key = 'NetworkKademlia'; value = '0'
    },
    [pscustomobject]@{
        section = 'Connection'; key = 'IPv6Mode'; value = '2'
    },
    [pscustomobject]@{
        section = 'Connection'; key = 'IPv6BindAddr'
        value = '2001:4860::10'
    }
)
$validOfflinePreferences = @'
[eMule]
NetworkKademlia=0
UncontrolledSentinel=preserved
[Connection]
IPv6Mode=2
IPv6BindAddr=2001:4860::10
[Ignored]
Arbitrary=allowed
'@

Invoke-I04OfflineTest -Id 'PREFERENCES-EXACT-CONTRACT-POSITIVE' `
    -Category 'preference_contract' -Body {
    $path = New-I04OfflinePreferenceFile -Name 'prefs-positive' `
        -Text $validOfflinePreferences
    $evidence = Get-I04OfflinePreferenceContract -Path $path `
        -Contract $offlinePreferenceContract
    Assert-I04Offline -Condition (
        [bool]$evidence.exact -and
        [int]$evidence.target_section_count -eq 2 -and
        [int]$evidence.target_key_count -eq 3 -and
        [bool]$evidence.duplicate_sections_rejected -and
        [bool]$evidence.duplicate_keys_rejected -and
        [string]$evidence.contract_sha256 -match '^[0-9a-f]{64}$') `
        -Code 'EXACT_PREFERENCE_CONTRACT_REJECTED'
}

$preferenceMutationCases = @(
    [pscustomobject]@{
        id = 'DUPLICATE-SECTION'
        expected = 'must occur exactly once'
        text = $validOfflinePreferences + "`n[eMule]`nOther=1`n"
    },
    [pscustomobject]@{
        id = 'DUPLICATE-KEY'
        expected = 'must occur once with its exact value'
        text = $validOfflinePreferences.Replace(
            'NetworkKademlia=0',
            "NetworkKademlia=0`nNetworkKademlia=0")
    },
    [pscustomobject]@{
        id = 'DUPLICATE-KEY-CASE'
        expected = 'must occur once with its exact value'
        text = $validOfflinePreferences.Replace(
            'NetworkKademlia=0',
            "NetworkKademlia=0`nnetworkkademlia=0")
    },
    [pscustomobject]@{
        id = 'MISSING-KEY'
        expected = 'must occur once with its exact value'
        text = $validOfflinePreferences.Replace('IPv6Mode=2', '')
    },
    [pscustomobject]@{
        id = 'WRONG-VALUE'
        expected = 'must occur once with its exact value'
        text = $validOfflinePreferences.Replace('IPv6Mode=2', 'IPv6Mode=1')
    },
    [pscustomobject]@{
        id = 'WRONG-VALUE-CASE'
        expected = 'must occur once with its exact value'
        text = $validOfflinePreferences.Replace(
            'IPv6BindAddr=2001:4860::10',
            'IPv6BindAddr=2001:4860::A')
    },
    [pscustomobject]@{
        id = 'KEY-IN-WRONG-SECTION'
        expected = 'must occur once with its exact value'
        text = $validOfflinePreferences.Replace(
            'IPv6Mode=2', "[IgnoredTwo]`nIPv6Mode=2")
    },
    [pscustomobject]@{
        id = 'COMMENTED-ONLY'
        expected = 'must occur once with its exact value'
        text = $validOfflinePreferences.Replace(
            'NetworkKademlia=0', ';NetworkKademlia=0')
    }
)
foreach ($case in $preferenceMutationCases) {
    $capturedCase = $case
    Invoke-I04OfflineTest `
        -Id ('PREFERENCES-EXACT-REJECT-' + $capturedCase.id) `
        -Category 'preference_contract' -Body {
        $path = New-I04OfflinePreferenceFile `
            -Name ('prefs-' + $capturedCase.id.ToLowerInvariant()) `
            -Text $capturedCase.text
        Assert-I04OfflineThrows -ExpectedCode $capturedCase.expected -Body {
            Get-I04OfflinePreferenceContract -Path $path `
                -Contract $offlinePreferenceContract
        }
    }
}

Invoke-I04OfflineTest -Id 'PREFERENCES-CONTRACT-DUPLICATE-REJECT' `
    -Category 'preference_contract' -Body {
    $path = New-I04OfflinePreferenceFile -Name 'prefs-contract-duplicate' `
        -Text $validOfflinePreferences
    $contract = @($offlinePreferenceContract) + [pscustomobject]@{
        section = 'emule'; key = 'networkkademlia'; value = '0'
    }
    Assert-I04OfflineThrows -ExpectedCode 'contract itself duplicates' -Body {
        Get-I04OfflinePreferenceContract -Path $path -Contract $contract
    }
}

Invoke-I04OfflineTest -Id 'PREFERENCES-CONTRACT-EMPTY-REJECT' `
    -Category 'preference_contract' -Body {
    $path = New-I04OfflinePreferenceFile -Name 'prefs-contract-empty' `
        -Text $validOfflinePreferences
    $contract = @([pscustomobject]@{
        section = ' '; key = 'NetworkKademlia'; value = '0'
    })
    Assert-I04OfflineThrows -ExpectedCode 'empty section/key' -Body {
        Get-I04OfflinePreferenceContract -Path $path -Contract $contract
    }
}

Invoke-I04OfflineTest -Id 'PREFERENCES-ISOLATION-STATIC' `
    -Category 'preference_contract' -Body {
    $function = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Set-I04IsolatedPreferences'
    }, $true))[0]
    $text = $function.Extent.Text
    foreach ($needle in @(
        "'preferences.dat', 'cryptkey.dat', 'clients.met'",
        "Autoconnect = '0'", "NetworkKademlia = '0'",
        "AutoStart = '0'", "AutoTakeED2KLinks = '0'",
        "WatchClipboard4ED2kFilelinks = '0'",
        "OpenPortsOnStartUp = '0'",
        "Serverlist = '0'", "AddServersFromServer = '0'",
        "AddServersFromClient = '0'", "IPv6Mode = [string]`$IPv6Mode",
        'IPv6BindAddr = $IPv6BindAddress', "KadNetworkMask = '0'",
        "NetworkED2K = '0'", "CryptLayerRequested = '0'",
        "CryptLayerRequired = '0'", "CryptLayerSupported = '0'",
        "EseNetLabEnabled = '0'", "EseV9Experimental = '0'",
        "EnableUtpHolePunch = '0'", "EseAutoKeepalive = '0'",
        "EseKad3Rendezvous = '0'", "EseReachSelector = '0'",
        "EseHolePunchPortPredict = '0'", "EseEd2kPunch3 = '0'",
        "EseRelayAccept = '0'", "EseRelayEgress = '0'",
        "Kad6BetaExitOptIn = '0'", "Kad6PublicExitOptIn = '0'",
        "-Key 'ProxyEnableProxy' -Value '0'",
        "-Key 'EnableUPnP' -Value '0'", "AllowedIPs = '127.0.0.1'",
        "WebUseUPnP = '0'", "-Key 'KrpRelayEnabled' -Value '0'",
        "-Key 'KrpRelayKillSwitch' -Value '1'")) {
        Assert-I04Offline -Condition ($text.Contains($needle)) `
            -Code 'ISOLATED_PREFERENCE_WRITE_MISSING'
    }
    Assert-I04Offline -Condition (-not $text.Contains("-Key 'ProxyEnable'")) `
        -Code 'OBSOLETE_PROXY_KEY_PRESENT'
}

Invoke-I04OfflineTest -Id 'PREFERENCES-EXACT-READBACK-STATIC' `
    -Category 'preference_contract' -Body {
    $setText = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Set-I04IsolatedPreferences'
    }, $true))[0].Extent.Text
    $enableText = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Enable-I04ControlledEd2kProfile'
    }, $true))[0].Extent.Text
    $assertText = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Assert-I04PreferenceContract'
    }, $true))[0].Extent.Text
    Assert-I04Offline -Condition (
        $setText.Contains('Set-I04StoredPreferenceContract') -and
        $enableText.Contains('Set-I04StoredPreferenceContract') -and
        $enableText.Contains('-Merge') -and
        $assertText.Contains('$sectionCounts[$targetSection] -ne 1') -and
        $assertText.Contains('$observed[$id].Count -ne 1') -and
        $assertText.Contains('[StringComparer]::Ordinal.Equals') -and
        $assertText.Contains('contract_sha256')) `
        -Code 'PREFERENCE_EXACT_READBACK_GATE_MISSING'

    $starts = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.CommandAst] -and
            $node.GetCommandName() -ceq 'Start-I04RestrictedProcess'
    }, $true))
    Assert-I04Offline -Condition ($starts.Count -eq 2) `
        -Code 'PREFERENCE_RESTRICTED_START_COUNT_CHANGED'
    foreach ($start in $starts) {
        $owner = $start.Parent
        while ($null -ne $owner -and
            $owner -isnot `
                [Management.Automation.Language.FunctionDefinitionAst]) {
            $owner = $owner.Parent
        }
        Assert-I04Offline -Condition ($null -ne $owner) `
            -Code 'PREFERENCE_START_OWNER_FUNCTION_MISSING'
        $assertCalls = @($owner.FindAll({
            param($node)
            $node -is [Management.Automation.Language.CommandAst] -and
                $node.GetCommandName() -ceq
                    'Assert-I04StoredPreferenceContract'
        }, $true))
        $evidenceBound = $owner.Extent.Text.Contains(
            'preference_contract = $preferenceProof') -or
            $owner.Extent.Text.Contains(
                '-NotePropertyValue $preferenceProof.contract_sha256')
        Assert-I04Offline -Condition (
            $assertCalls.Count -eq 1 -and
            $assertCalls[0].Extent.StartOffset -lt $start.Extent.StartOffset -and
            $evidenceBound) `
            -Code 'PREFERENCE_NOT_REVALIDATED_BEFORE_EACH_START'
    }
}

Invoke-I04OfflineTest -Id 'OVERLAY-DENYLIST-STATIC' `
    -Category 'address_classifier' -Body {
    $assignments = @($script:HarnessAst.FindAll({
        param($node)
        $node -is `
            [Management.Automation.Language.AssignmentStatementAst] -and
        $node.Left.Extent.Text -ceq '$overlayPattern'
    }, $true))
    Assert-I04Offline -Condition ($assignments.Count -eq 1) `
        -Code 'OVERLAY_DENYLIST_ASSIGNMENT_NOT_UNIQUE'
    $lower = $assignments[0].Extent.Text.ToLowerInvariant()
    foreach ($needle in @(
        'tailscale', 'wireguard', 'cloudflare', 'warp', 'zerotier',
        'openvpn', 'hyper-v', 'vethernet', 'loopback', 'tunnel',
        'tap', 'vpn', 'hamachi', 'teredo', '6to4', 'isatap')) {
        Assert-I04Offline -Condition ($lower.Contains($needle)) `
            -Code 'OVERLAY_DENYLIST_TERM_MISSING'
    }
    Assert-I04Offline -Condition (
        $lower -match 'ip.*https' -and
        $script:HarnessText.Contains('strict_isolation_valid')) `
        -Code 'IPHTTPS_OR_STRICT_ISOLATION_GUARD_MISSING'
}

Invoke-I04OfflineTest -Id 'VIRTUAL-ADAPTER-UNKNOWN-FAILS-CLOSED-STATIC' `
    -Category 'address_classifier' -Body {
    foreach ($functionName in @(
        'Get-I04RouteEvidence', 'Get-I04IsolationEvidence')) {
        $text = @($script:HarnessAst.FindAll({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -ceq $functionName
        }, $true))[0].Extent.Text
        Assert-I04Offline -Condition (
            $text.Contains("Properties.Name -contains 'Virtual'") -and
            $text.Contains('$_.Virtual -is [bool]') -or
            $text.Contains('$adapter.Virtual -is [bool]')) `
            -Code 'VIRTUAL_ADAPTER_TYPE_NOT_EXACT'
        Assert-I04Offline -Condition (
            $text.Contains('else { $true }') -or
            $text.Contains('$isVirtual = $true')) `
            -Code 'UNKNOWN_VIRTUAL_STATUS_NOT_FAIL_CLOSED'
    }
    Assert-I04Offline -Condition (
        $script:HarnessText.Contains(
            '-not $coordinatorAdapterVirtual -and') -and
        $script:HarnessText.Contains(
            '-not $adapterVirtual -and -not $adapterOverlayLike') -and
        $script:HarnessText.Contains(
            '[bool]$routeV4.physical_nonvirtual') -and
        $script:HarnessText.Contains(
            '[bool]$routeV6.physical_nonvirtual')) `
        -Code 'VIRTUAL_OR_UNKNOWN_ADAPTER_COULD_PROVE_TOPOLOGY'
}

Invoke-I04OfflineTest -Id 'ADDRESS-CLASSIFIER-RUNTIME-WIRING-STATIC' `
    -Category 'address_classifier' -Body {
    foreach ($needle in @(
        '(Get-I04StrictAddressClass -Address $peerV4Text) -ne',
        "'public-unicast-v4'",
        '(Get-I04StrictAddressClass -Address $peerV6Text) -ne',
        "'native-global-v6'",
        '(Get-I04StrictAddressClass -Address $coordinatorV6Text) -ne')) {
        Assert-I04Offline -Condition ($script:HarnessText.Contains($needle)) `
            -Code 'STRICT_ADDRESS_CLASSIFIER_NOT_WIRED'
    }
    $isolationText = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Get-I04IsolationEvidence'
    }, $true))[0].Extent.Text
    Assert-I04Offline -Condition (
        $isolationText.Contains('$overlayPattern') -and
        $isolationText.Contains('strict_isolation_valid')) `
        -Code 'OVERLAY_CLASSIFIER_NOT_BOUND_TO_ISOLATION_PROOF'
}

Invoke-I04OfflineTest -Id 'ZIP-BINDING-RUNTIME-WIRING-STATIC' `
    -Category 'package_binding' -Body {
    $bindingCalls = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.CommandAst] -and
            $node.GetCommandName() -ceq 'Get-I04CandidateBinding'
    }, $true))
    Assert-I04Offline -Condition ($bindingCalls.Count -eq 1) `
        -Code 'CANDIDATE_BINDING_CALL_NOT_EXACTLY_ONE'
    $callText = $bindingCalls[0].Extent.Text
    foreach ($needle in @(
        '-DirectoryPath $PackagePath', '-ZipPath $PackageZipPath',
        '-ExpectedZipSha256 $expectedZipHash',
        '-ExpectedExeSha256 $expectedHash',
        '-ExpectedCommit $Commit')) {
        Assert-I04Offline -Condition ($callText.Contains($needle)) `
            -Code 'CANDIDATE_BINDING_INPUT_NOT_EXACT'
    }
    foreach ($needle in @(
        'PackageZipPath = $RemotePackageZipPath',
        'ExpectedPackageZipSha256 = $expectedZipHash',
        "-PackageZipPath '<exact-package-zip-on-peer>'",
        '-ExpectedPackageZipSha256 ''$expectedZipHash''')) {
        Assert-I04Offline -Condition ($script:HarnessText.Contains($needle)) `
            -Code 'REMOTE_OR_MANUAL_ZIP_BINDING_NOT_PROPAGATED'
    }
}

Invoke-I04OfflineTest -Id 'ADJUDICATION-RUNTIME-WIRING-STATIC' `
    -Category 'adjudication' -Body {
    $coordinatorText = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Invoke-I04CoordinatorRole'
    }, $true))[0].Extent.Text
    foreach ($needle in @(
        '-CandidateFailure $candidatePostTriggerFailure',
        '[bool]$failureDisposition.candidate_failure_contract_valid',
        '$candidatePostTriggerFailure.source_bound',
        '$candidatePostTriggerFailure.adjudicable',
        'Assert-I04ProductFailureContract -Failure $_',
        '$productFailuresTypedAndSourceBound',
        '$proofContradicted = $caseArmed -and',
        '-not $candidateUnchanged',
        '$fixtureProofComplete = $triggerFixtureRuntimeValid',
        '$productFailureProved = $fixtureProofComplete -and',
        '-ProductFailureProved $productFailureProved',
        '-ProofContradicted $proofContradicted',
        'if ($partialVerdict -eq ''FAIL'')',
        'elseif ($partialVerdict -eq ''PASS'' -and $adjudicationClean)')) {
        Assert-I04Offline -Condition ($coordinatorText.Contains($needle)) `
            -Code 'FORMAL_ADJUDICATION_WIRING_MISSING'
    }
}

Invoke-I04OfflineTest -Id 'PRODUCT-FAILURE-TYPED-WIRING-STATIC' `
    -Category 'adjudication' -Body {
    $newText = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'New-I04ProductFailure'
    }, $true))[0].Extent.Text
    $addText = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Add-I04TypedProductFailure'
    }, $true))[0].Extent.Text
    $roleText = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Invoke-I04CoordinatorRole'
    }, $true))[0].Extent.Text
    foreach ($needle in @(
        "schema = 'ese.v91.i04-product-failure/v1'",
        '$sourceEvidenceContractValid',
        'source_bound = [bool]$sourceBound',
        'adjudicable = [bool]$collectorOk -and [bool]$sourceBound -and')) {
        Assert-I04Offline -Condition ($newText.Contains($needle)) `
            -Code 'PRODUCT_FAILURE_CREATION_NOT_TYPED_AND_SOURCE_BOUND'
    }
    foreach ($needle in @(
        'New-I04ProductFailure -FailureType $FailureType',
        'Assert-I04ProductFailureContract -Failure $failure',
        '-not [bool]$failure.source_bound',
        '-not [bool]$failure.adjudicable',
        '$Failures.Add($failure)')) {
        Assert-I04Offline -Condition ($addText.Contains($needle)) `
            -Code 'PRODUCT_FAILURE_ADD_HELPER_NOT_FAIL_CLOSED'
    }
    $directAdds = @([regex]::Matches(
        $roleText, '\$productFailures\.Add\(([^\r\n]+)\)'))
    Assert-I04Offline -Condition (
        $directAdds.Count -eq 1 -and
        $directAdds[0].Groups[1].Value.Trim() -ceq
            '$candidatePostTriggerFailure' -and
        $roleText.Contains(
            'Assert-I04ProductFailureContract') -and
        $roleText.Contains('Add-I04TypedProductFailure -Failures') -and
        $roleText.Contains(
            '-CandidateFailure $candidatePostTriggerFailure')) `
        -Code 'RAW_OR_UNASSERTED_PRODUCT_FAILURE_ADDED'
}

Invoke-I04OfflineTest -Id 'PACKET-ADJUDICATION-SINGLE-FALLBACK-STATIC' `
    -Category 'fallback_contract' -Body {
    $text = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Invoke-I04CoordinatorRole'
    }, $true))[0].Extent.Text
    foreach ($needle in @(
        '[bool]$packetVerdict.pid_packet_correlation_complete',
        '[bool]$packetVerdict.silent_drop_proved',
        '[bool]$packetVerdict.environment_rejected_blackhole_in_fixed_window',
        '$packetVerdict.fallback_in_planning_window',
        '$packetVerdict.connection_under_limit',
        '$packetVerdict.ipv4_final_ack_observed',
        '$packetVerdict.distinct_ipv4_connection_attempts -ne 1',
        '$packetVerdict.distinct_ipv6_connection_attempts -ne 1',
        '$fallbackDelta -ne 1', '$boundedFallbackDelta -ne 1',
        '$helloDelta -ne 1', '$helloAnswerDelta -ne 1')) {
        Assert-I04Offline -Condition ($text.Contains($needle)) `
            -Code 'SINGLE_FALLBACK_ADJUDICATION_GATE_MISSING'
    }
}

Invoke-I04OfflineTest -Id 'CAPTURE-ZERO-LOSS-NO-WRAP-STATIC' `
    -Category 'pcap_contract' -Body {
    $text = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Invoke-I04CoordinatorRole'
    }, $true))[0].Extent.Text
    Assert-I04Offline -Condition (
        $text.Contains('[bool]$capture.etw_loss_proved_zero') -and
        $text.Contains('[bool]$capture.etl_below_circular_limit') -and
        $script:HarnessText.Contains('EventsLost') -and
        $script:HarnessText.Contains('LogBuffersLost') -and
        $script:HarnessText.Contains('RealTimeBuffersLost')) `
        -Code 'ETW_ZERO_LOSS_OR_NO_WRAP_GATE_MISSING'
}

Invoke-I04OfflineTest -Id 'ETW-FINAL-FLUSH-ORDER-STATIC' `
    -Category 'pcap_contract' -Body {
    $stopText = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Stop-I04PacketCapture'
    }, $true))[0].Extent.Text
    $flushAt = $stopText.IndexOf(
        '$flush = Invoke-I04EtwFinalFlush -SessionName ''PktMon''')
    $queryAt = $stopText.IndexOf(
        '$loss = Get-I04EtwLossEvidence -SessionName ''PktMon''')
    $stopAt = $stopText.IndexOf(
        '$stopResult = Invoke-I04Pktmon -LogPath $State.command_log')
    Assert-I04Offline -Condition (
        $flushAt -ge 0 -and $queryAt -gt $flushAt -and
        $stopAt -gt $queryAt -and
        $stopText.Contains(
            "`$State.etw_loss_sample_phase = 'post-final-flush-pre-stop'") -and
        $stopText.Contains(
            '[bool]$flush.succeeded -and [bool]$loss.available -and') -and
        $stopText.Contains('[UInt32]$loss.error_code -eq 0') -and
        $stopText.Contains('[bool]$loss.proved_zero')) `
        -Code 'ETW_FINAL_FLUSH_QUERY_STOP_ORDER_NOT_EXACT'
}

Invoke-I04OfflineTest -Id 'ETW-LOSS-NEGATIVE-GATES-STATIC' `
    -Category 'pcap_contract' -Body {
    $stopText = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Stop-I04PacketCapture'
    }, $true))[0].Extent.Text
    $roleText = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Invoke-I04CoordinatorRole'
    }, $true))[0].Extent.Text
    foreach ($needle in @(
        '[bool]$State.etw_final_flush_succeeded -and',
        '[bool]$State.etw_post_flush_query_ok -and',
        'if (-not [bool]$State.etw_loss_proved_zero)',
        "'ese.v91.i04-etw-loss/v2'",
        "'post-final-flush-pre-stop'",
        '-not [bool]$capture.etw_final_flush_succeeded',
        '-not [bool]$capture.etw_post_flush_query_ok',
        '-not [bool]$capture.etw_loss_proved_zero',
        '[bool]$capture.etw_final_flush_succeeded -and',
        '[bool]$capture.etw_post_flush_query_ok -and',
        '[bool]$capture.etw_loss_proved_zero -and')) {
        Assert-I04Offline -Condition (
            $stopText.Contains($needle) -or $roleText.Contains($needle)) `
            -Code 'ETW_LOSS_FAILURE_COULD_REMAIN_ADMISSIBLE'
    }
}

Invoke-I04OfflineTest -Id 'PCAPNG-NEGATIVE-COUNTERS-WIRED-STATIC' `
    -Category 'pcap_contract' -Body {
    $roleText = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Invoke-I04CoordinatorRole'
    }, $true))[0].Extent.Text
    foreach ($field in @(
        'pcapng_trailing_byte_count', 'pcapng_block_error_count',
        'pcapng_idb_option_error_count', 'pcapng_truncated_frame_count',
        'pcapng_unknown_interface_frame_count',
        'pcapng_unsupported_linktype_frame_count',
        'pcapng_unsupported_packet_block_count',
        'pcapng_parse_null_frame_count',
        'pcapng_non_adjudicable_frame_count')) {
        Assert-I04Offline -Condition (
            $roleText.Contains('[int]$packetVerdict.' + $field + ' -ne 0') -and
            $roleText.Contains('[int]$packetVerdict.' + $field + ' -eq 0')) `
            -Code 'PCAPNG_NEGATIVE_COUNTER_NOT_ADJUDICATION_BOUND'
    }
}

$offlinePktmonFilterV4 = 'i04-offline-filter-v4'
$offlinePktmonFilterV6 = 'i04-offline-filter-v6'
$offlinePktmonFilterIcmp = 'i04-offline-filter-icmp6'
$offlinePktmonIPv4 = '1.1.1.1'
$offlinePktmonIPv6 = '2001:4860::20'
$offlinePktmonPort = 9462
$offlinePktmonValidText = @"
Name: $offlinePktmonFilterV4
Address: $offlinePktmonIPv4
Protocol: TCP
Port: $offlinePktmonPort
Name: $offlinePktmonFilterV6
Address: $offlinePktmonIPv6
Protocol: TCP
Port: $offlinePktmonPort
Name: $offlinePktmonFilterIcmp
Protocol: ICMPV6
"@
$offlinePktmonNumberedValidText = @"
1 $offlinePktmonFilterV4 $offlinePktmonIPv4 TCP $offlinePktmonPort
2 $offlinePktmonFilterV6 $offlinePktmonIPv6 TCP $offlinePktmonPort
3 $offlinePktmonFilterIcmp ICMPV6
"@

Invoke-I04OfflineTest -Id 'PKTMON-FILTER-CONTRACTS-POSITIVE' `
    -Category 'pcap_contract' -Body {
    $result = Test-I04OfflinePktmonArmedFilterContracts `
        -Text $offlinePktmonValidText `
        -FilterV4 $offlinePktmonFilterV4 `
        -FilterV6 $offlinePktmonFilterV6 `
        -FilterIcmpV6 $offlinePktmonFilterIcmp `
        -IPv4 $offlinePktmonIPv4 -IPv6 $offlinePktmonIPv6 `
        -Port $offlinePktmonPort
    Assert-I04Offline -Condition (
        [bool]$result.exact -and @($result.contracts).Count -eq 3 -and
        @($result.contracts | Where-Object { -not [bool]$_.exact }).Count `
            -eq 0 -and
        @($result.contracts | Where-Object {
            [string]$_.protocol -ceq 'ICMPV6' -and
            [bool]$_.port_contract_exact
        }).Count -eq 1) -Code 'EXACT_PKTMON_FILTER_CONTRACTS_REJECTED'
}

Invoke-I04OfflineTest -Id 'PKTMON-FILTER-CONTRACTS-NUMBERED-POSITIVE' `
    -Category 'pcap_contract' -Body {
    $result = Test-I04OfflinePktmonArmedFilterContracts `
        -Text $offlinePktmonNumberedValidText `
        -FilterV4 $offlinePktmonFilterV4 `
        -FilterV6 $offlinePktmonFilterV6 `
        -FilterIcmpV6 $offlinePktmonFilterIcmp `
        -IPv4 $offlinePktmonIPv4 -IPv6 $offlinePktmonIPv6 `
        -Port $offlinePktmonPort
    Assert-I04Offline -Condition (
        [bool]$result.exact -and
        [string]$result.inventory_mode -ceq 'numbered-rows' -and
        @($result.contracts).Count -eq 3) `
        -Code 'EXACT_NUMBERED_PKTMON_FILTER_CONTRACTS_REJECTED'
}

Invoke-I04OfflineTest -Id 'PKTMON-FILTER-CENSUS-NUMBERED-HEADER-POSITIVE' `
    -Category 'pcap_contract' -Body {
    $text = "Packet Filters:`nId Name IP Address Protocol Port`n" +
        "-- ---- ---------- -------- ----`n" +
        $offlinePktmonNumberedValidText
    $result = Test-I04OfflinePktmonArmedFilterContracts -Text $text `
        -FilterV4 $offlinePktmonFilterV4 `
        -FilterV6 $offlinePktmonFilterV6 `
        -FilterIcmpV6 $offlinePktmonFilterIcmp `
        -IPv4 $offlinePktmonIPv4 -IPv6 $offlinePktmonIPv6 `
        -Port $offlinePktmonPort
    Assert-I04Offline -Condition ([bool]$result.exact) `
        -Code 'NUMBERED_PKTMON_METADATA_HEADER_REJECTED'
}

$pktmonCensusAttackFixtures = @(
    [pscustomobject]@{
        id = 'DUPLICATE-ID'
        text = $offlinePktmonNumberedValidText.Replace(
            "2 $offlinePktmonFilterV6", "1 $offlinePktmonFilterV6")
    },
    [pscustomobject]@{
        id = 'UNRECOGNIZED-LINE'
        text = $offlinePktmonNumberedValidText + "`nDirection: Inbound`n"
    },
    [pscustomobject]@{
        id = 'MIXED-NAMED-FOREIGN'
        text = $offlinePktmonNumberedValidText + "`nName: foreign`n"
    }
)
foreach ($fixture in $pktmonCensusAttackFixtures) {
    $capturedFixture = $fixture
    Invoke-I04OfflineTest -Id (
        'PKTMON-FILTER-CENSUS-REJECT-' + $capturedFixture.id) `
        -Category 'pcap_contract' -Body {
        $result = Test-I04OfflinePktmonArmedFilterContracts `
            -Text $capturedFixture.text `
            -FilterV4 $offlinePktmonFilterV4 `
            -FilterV6 $offlinePktmonFilterV6 `
            -FilterIcmpV6 $offlinePktmonFilterIcmp `
            -IPv4 $offlinePktmonIPv4 -IPv6 $offlinePktmonIPv6 `
            -Port $offlinePktmonPort
        Assert-I04Offline -Condition (-not [bool]$result.exact) `
            -Code 'PKTMON_FULL_CENSUS_ATTACK_ACCEPTED'
    }
}

Invoke-I04OfflineTest -Id 'PKTMON-FILTER-CENSUS-EMPTY-EXACT' `
    -Category 'pcap_contract' -Body {
    $census = Get-I04OfflinePktmonInventoryCensus `
        -Text "Packet Filters:`nNone`n"
    Assert-I04Offline -Condition (
        [bool]$census.exact -and [bool]$census.empty -and
        [int]$census.entry_count -eq 0) `
        -Code 'EXACT_EMPTY_PKTMON_INVENTORY_REJECTED'
}

Invoke-I04OfflineTest -Id 'PKTMON-FILTER-CENSUS-EMPTY-WITH-FOREIGN-REJECT' `
    -Category 'pcap_contract' -Body {
    $census = Get-I04OfflinePktmonInventoryCensus `
        -Text "Packet Filters:`nNone`nName: foreign`n"
    Assert-I04Offline -Condition (-not [bool]$census.exact) `
        -Code 'EMPTY_MARKER_WITH_FOREIGN_PKTMON_FILTER_ACCEPTED'
}

$pktmonNumberedMutations = @(
    [pscustomobject]@{
        id = 'ROW-EXTRA'
        text = $offlinePktmonNumberedValidText +
            "`n4 i04-offline-unowned UDP 5353`n"
    },
    [pscustomobject]@{
        id = 'V4-EXTRA-ADDRESS'
        text = $offlinePktmonNumberedValidText.Replace(
            "$offlinePktmonIPv4 TCP", "$offlinePktmonIPv4 9.9.9.9 TCP")
    },
    [pscustomobject]@{
        id = 'V6-EXTRA-PORT'
        text = $offlinePktmonNumberedValidText.Replace(
            "$offlinePktmonIPv6 TCP $offlinePktmonPort",
            "$offlinePktmonIPv6 TCP $offlinePktmonPort 9463")
    },
    [pscustomobject]@{
        id = 'V6-EXTRA-PROTOCOL'
        text = $offlinePktmonNumberedValidText.Replace(
            "$offlinePktmonIPv6 TCP", "$offlinePktmonIPv6 TCP UDP")
    },
    [pscustomobject]@{
        id = 'ICMPV6-HAS-ADDRESS'
        text = $offlinePktmonNumberedValidText.Replace(
            "$offlinePktmonFilterIcmp ICMPV6",
            "$offlinePktmonFilterIcmp 2001:4860::99 ICMPV6")
    }
)
foreach ($mutation in $pktmonNumberedMutations) {
    $capturedNumberedMutation = $mutation
    Invoke-I04OfflineTest -Id (
        'PKTMON-FILTER-CONTRACTS-NUMBERED-REJECT-' +
        $capturedNumberedMutation.id) -Category 'pcap_contract' -Body {
        $result = Test-I04OfflinePktmonArmedFilterContracts `
            -Text $capturedNumberedMutation.text `
            -FilterV4 $offlinePktmonFilterV4 `
            -FilterV6 $offlinePktmonFilterV6 `
            -FilterIcmpV6 $offlinePktmonFilterIcmp `
            -IPv4 $offlinePktmonIPv4 -IPv6 $offlinePktmonIPv6 `
            -Port $offlinePktmonPort
        Assert-I04Offline -Condition (-not [bool]$result.exact) `
            -Code 'MUTATED_NUMBERED_PKTMON_FILTER_CONTRACT_ACCEPTED'
    }
}

$pktmonFilterMutations = @(
    [pscustomobject]@{
        id = 'NAME-MISSING'; expected_reason = 'filter-name-census'
        text = $offlinePktmonValidText.Replace(
            $offlinePktmonFilterV6, 'i04-offline-filter-other6')
    },
    [pscustomobject]@{
        id = 'NAME-DUPLICATE'; expected_reason = 'filter-name-census'
        text = $offlinePktmonValidText +
            "`nName: $offlinePktmonFilterV4`n"
    },
    [pscustomobject]@{
        id = 'V4-ADDRESS'; expected_reason = ''
        text = $offlinePktmonValidText.Replace(
            "Address: $offlinePktmonIPv4`nProtocol: TCP`nPort: $offlinePktmonPort",
            "Address: 9.9.9.9`nProtocol: TCP`nPort: $offlinePktmonPort")
    },
    [pscustomobject]@{
        id = 'V4-OTHER-ADDRESS'; expected_reason = ''
        text = $offlinePktmonValidText.Replace(
            "Address: $offlinePktmonIPv4`nProtocol: TCP",
            "Address: $offlinePktmonIPv4`nOther: $offlinePktmonIPv6`nProtocol: TCP")
    },
    [pscustomobject]@{
        id = 'V4-EXTRA-ADDRESS'; expected_reason = ''
        text = $offlinePktmonValidText.Replace(
            "Address: $offlinePktmonIPv4`nProtocol: TCP",
            "Address: $offlinePktmonIPv4`nAddress: 9.9.9.9`nProtocol: TCP")
    },
    [pscustomobject]@{
        id = 'V4-PROTOCOL'; expected_reason = ''
        text = $offlinePktmonValidText.Replace(
            "Address: $offlinePktmonIPv4`nProtocol: TCP",
            "Address: $offlinePktmonIPv4`nProtocol: UDP")
    },
    [pscustomobject]@{
        id = 'V4-PORT'; expected_reason = ''
        text = $offlinePktmonValidText.Replace(
            "Address: $offlinePktmonIPv4`nProtocol: TCP`nPort: $offlinePktmonPort",
            "Address: $offlinePktmonIPv4`nProtocol: TCP`nPort: 9463")
    },
    [pscustomobject]@{
        id = 'V4-EXTRA-PORT'; expected_reason = ''
        text = $offlinePktmonValidText.Replace(
            "Port: $offlinePktmonPort`nName: $offlinePktmonFilterV6",
            "Port: $offlinePktmonPort`nPort: 9463`nName: $offlinePktmonFilterV6")
    },
    [pscustomobject]@{
        id = 'V6-ADDRESS'; expected_reason = ''
        text = $offlinePktmonValidText.Replace(
            "Address: $offlinePktmonIPv6`nProtocol: TCP`nPort: $offlinePktmonPort",
            "Address: 2001:4860::99`nProtocol: TCP`nPort: $offlinePktmonPort")
    },
    [pscustomobject]@{
        id = 'V6-OTHER-ADDRESS'; expected_reason = ''
        text = $offlinePktmonValidText.Replace(
            "Address: $offlinePktmonIPv6`nProtocol: TCP",
            "Address: $offlinePktmonIPv6`nOther: $offlinePktmonIPv4`nProtocol: TCP")
    },
    [pscustomobject]@{
        id = 'V6-EXTRA-ADDRESS'; expected_reason = ''
        text = $offlinePktmonValidText.Replace(
            "Address: $offlinePktmonIPv6`nProtocol: TCP",
            "Address: $offlinePktmonIPv6`nAddress: 2001:4860::99`nProtocol: TCP")
    },
    [pscustomobject]@{
        id = 'V6-PROTOCOL'; expected_reason = ''
        text = $offlinePktmonValidText.Replace(
            "Address: $offlinePktmonIPv6`nProtocol: TCP",
            "Address: $offlinePktmonIPv6`nProtocol: UDP")
    },
    [pscustomobject]@{
        id = 'V6-PORT'; expected_reason = ''
        text = $offlinePktmonValidText.Replace(
            "Address: $offlinePktmonIPv6`nProtocol: TCP`nPort: $offlinePktmonPort",
            "Address: $offlinePktmonIPv6`nProtocol: TCP`nPort: 9463")
    },
    [pscustomobject]@{
        id = 'V6-EXTRA-PORT'; expected_reason = ''
        text = $offlinePktmonValidText.Replace(
            "Port: $offlinePktmonPort`nName: $offlinePktmonFilterIcmp",
            "Port: $offlinePktmonPort`nPort: 9463`nName: $offlinePktmonFilterIcmp")
    },
    [pscustomobject]@{
        id = 'ICMPV6-PROTOCOL'; expected_reason = ''
        text = $offlinePktmonValidText.Replace(
            'Protocol: ICMPV6', 'Protocol: ICMP')
    },
    [pscustomobject]@{
        id = 'ICMPV6-HAS-PORT'; expected_reason = ''
        text = $offlinePktmonValidText.Replace(
            'Protocol: ICMPV6',
            "Protocol: ICMPV6`nPort: $offlinePktmonPort")
    },
    [pscustomobject]@{
        id = 'ICMPV6-HAS-ADDRESS'; expected_reason = ''
        text = $offlinePktmonValidText.Replace(
            'Protocol: ICMPV6',
            "Address: 2001:4860::99`nProtocol: ICMPV6")
    }
)
foreach ($mutation in $pktmonFilterMutations) {
    $capturedMutation = $mutation
    Invoke-I04OfflineTest -Id (
        'PKTMON-FILTER-CONTRACTS-REJECT-' + $capturedMutation.id) `
        -Category 'pcap_contract' -Body {
        $result = Test-I04OfflinePktmonArmedFilterContracts `
            -Text $capturedMutation.text `
            -FilterV4 $offlinePktmonFilterV4 `
            -FilterV6 $offlinePktmonFilterV6 `
            -FilterIcmpV6 $offlinePktmonFilterIcmp `
            -IPv4 $offlinePktmonIPv4 -IPv6 $offlinePktmonIPv6 `
            -Port $offlinePktmonPort
        Assert-I04Offline -Condition (
            -not [bool]$result.exact -and
            ([string]$capturedMutation.expected_reason -ceq '' -or
             [string]$result.reason -ceq
                [string]$capturedMutation.expected_reason)) `
            -Code 'MUTATED_PKTMON_FILTER_CONTRACT_ACCEPTED'
    }
}

Invoke-I04OfflineTest -Id 'PKTMON-FILTER-CONTRACTS-WIRED-STATIC' `
    -Category 'pcap_contract' -Body {
    $captureFunctions = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Start-I04PacketCapture'
    }, $true))
    Assert-I04Offline -Condition ($captureFunctions.Count -eq 1) `
        -Code 'PKTMON_CAPTURE_FUNCTION_NOT_UNIQUE'
    $capture = $captureFunctions[0]
    $filterAdds = @($capture.FindAll({
        param($node)
        $node -is [Management.Automation.Language.CommandAst] -and
            $node.GetCommandName() -ceq 'Invoke-I04Pktmon' -and
            $node.Extent.Text.Contains("'filter', 'add'")
    }, $true))
    Assert-I04Offline -Condition ($filterAdds.Count -eq 3) `
        -Code 'PKTMON_FILTER_ADD_CENSUS_NOT_EXACT'
    $v4Calls = @($filterAdds | Where-Object {
        $_.Extent.Text.Contains('$filterV4')
    })
    $v6Calls = @($filterAdds | Where-Object {
        $_.Extent.Text.Contains('$filterV6')
    })
    $icmpCalls = @($filterAdds | Where-Object {
        $_.Extent.Text.Contains('$filterIcmp')
    })
    Assert-I04Offline -Condition (
        $v4Calls.Count -eq 1 -and $v6Calls.Count -eq 1 -and
        $icmpCalls.Count -eq 1 -and
        $v4Calls[0].Extent.Text.Contains("'-i', `$IPv4") -and
        $v4Calls[0].Extent.Text.Contains("'-p', ([string]`$Port)") -and
        $v4Calls[0].Extent.Text.Contains("'-t', 'TCP'") -and
        $v6Calls[0].Extent.Text.Contains("'-i', `$IPv6") -and
        $v6Calls[0].Extent.Text.Contains("'-p', ([string]`$Port)") -and
        $v6Calls[0].Extent.Text.Contains("'-t', 'TCP'") -and
        $icmpCalls[0].Extent.Text.Contains("'-t', 'ICMPV6'") -and
        -not $icmpCalls[0].Extent.Text.Contains("'-p'") -and
        -not $icmpCalls[0].Extent.Text.Contains("'-i'")) `
        -Code 'PKTMON_FILTER_ADD_ARGUMENT_CONTRACT_WRONG'
    $filterValidatorCalls = @($capture.FindAll({
        param($node)
        $node -is [Management.Automation.Language.CommandAst] -and
            $node.GetCommandName() -ceq
                'Test-I04PktmonArmedFilterContracts'
    }, $true))
    $startCalls = @($capture.FindAll({
        param($node)
        $node -is [Management.Automation.Language.CommandAst] -and
            $node.GetCommandName() -ceq 'Invoke-I04Pktmon' -and
            $node.Extent.Text.Contains("'start', '--capture'")
    }, $true))
    Assert-I04Offline -Condition (
        $filterValidatorCalls.Count -eq 1 -and $startCalls.Count -eq 1 -and
        $filterValidatorCalls[0].Extent.StartOffset -lt
            $startCalls[0].Extent.StartOffset -and
        $capture.Extent.Text.Contains(
            '$state.filters = @($filterV4, $filterV6, $filterIcmp)') -and
        $capture.Extent.Text.Contains('[bool]$filterContracts.exact') -and
        $capture.Extent.Text.Contains(
            'PktMon did not prove the exact IPv4/IPv6/ICMPv6 filter contracts')) `
        -Code 'PKTMON_ARMED_FILTER_CONTRACT_NOT_PRE_CAPTURE_GATED'
}

Invoke-I04OfflineTest -Id 'PKTMON-FILTER-CENSUS-UNIFIED-WIRING-STATIC' `
    -Category 'pcap_contract' -Body {
    $functions = @{}
    foreach ($name in @(
        'Get-I04PktmonInventoryCensus',
        'Test-I04PktmonArmedFilterContracts',
        'Start-I04PacketCapture', 'Stop-I04PacketCapture')) {
        $matches = @($script:HarnessAst.FindAll({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] `
                -and $node.Name -ceq $name
        }, $true))
        Assert-I04Offline -Condition ($matches.Count -eq 1) `
            -Code 'PKTMON_UNIFIED_CENSUS_FUNCTION_NOT_UNIQUE'
        $functions[$name] = $matches[0].Extent.Text
    }
    Assert-I04Offline -Condition (
        $functions['Test-I04PktmonArmedFilterContracts'].Contains(
            'Get-I04PktmonInventoryCensus -Text $Text') -and
        $functions['Start-I04PacketCapture'].Contains(
            'Get-I04PktmonInventoryCensus -Text $filtersBeforeText') -and
        $functions['Start-I04PacketCapture'].Contains(
            '[bool]$filtersBeforeCensus.empty') -and
        $functions['Stop-I04PacketCapture'].Contains(
            'Get-I04PktmonInventoryCensus -Text $filterInventoryText') -and
        $functions['Stop-I04PacketCapture'].Contains(
            '-not [bool]$filterInventoryCensus.exact')) `
        -Code 'PKTMON_UNIFIED_CENSUS_NOT_USED_BY_ALL_MUTATION_GATES'
}

Invoke-I04OfflineTest -Id 'PKTMON-FILTER-SCENARIO-HASHES-WIRED-STATIC' `
    -Category 'pcap_contract' -Body {
    $startText = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Start-I04PacketCapture'
    }, $true))[0].Extent.Text
    $stopText = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Stop-I04PacketCapture'
    }, $true))[0].Extent.Text
    $coordinator = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Invoke-I04CoordinatorRole'
    }, $true))[0]
    $coordinatorText = $coordinator.Extent.Text
    foreach ($needle in @(
        'filter_inventory_armed_sha256 = $null',
        'filter_inventory_pre_stop_sha256 = $null',
        'filter_inventory_scenario_unchanged = $false',
        '$state.filter_inventory_armed_sha256 =',
        '[string]$filterContracts.canonical_sha256')) {
        Assert-I04Offline -Condition ($startText.Contains($needle)) `
            -Code 'PKTMON_ARMED_FILTER_HASH_NOT_CAPTURED'
    }
    $boundaryAt = $stopText.IndexOf('$State.capture_ended_epoch_ms =')
    $preStopAt = $stopText.IndexOf("-Arguments @('filter', 'list')")
    $flushAt = $stopText.IndexOf(
        '$flush = Invoke-I04EtwFinalFlush -SessionName ''PktMon''')
    Assert-I04Offline -Condition (
        $boundaryAt -ge 0 -and $preStopAt -gt $boundaryAt -and
        $flushAt -gt $preStopAt -and
        $stopText.Contains(
            '$State.filter_inventory_pre_stop_sha256 =') -and
        $stopText.Contains('[bool]$preStopContracts.exact -and') -and
        $stopText.Contains(
            '[string]$State.filter_inventory_armed_sha256 -match') -and
        $stopText.Contains(
            '[string]$State.filter_inventory_pre_stop_sha256 -ceq') -and
        $stopText.Contains(
            '$State.filter_inventory_scenario_unchanged = $false')) `
        -Code 'PKTMON_PRE_STOP_FILTER_HASH_NOT_BOUND_TO_CAPTURE_BOUNDARY'
    $proofAssignments = @($coordinator.FindAll({
        param($node)
        $node -is [Management.Automation.Language.AssignmentStatementAst] -and
            $node.Left.Extent.Text -ceq '$proofContradicted'
    }, $true))
    Assert-I04Offline -Condition (
        $coordinatorText.Contains(
            '$pktmonFilterScenarioContradiction = $caseArmed') -and
        $proofAssignments.Count -eq 1 -and
        $proofAssignments[0].Extent.Text.Contains(
            '$pktmonFilterScenarioContradiction') -and
        $coordinatorText.Contains(
            'pktmon_filter_scenario_contradiction =') -and
        $coordinatorText.Contains(
            'pktmon_filter_inventory_armed_sha256 =') -and
        $coordinatorText.Contains(
            'pktmon_filter_inventory_pre_stop_sha256 =')) `
        -Code 'PKTMON_FILTER_DRIFT_NOT_PROOF_CONTRADICTED_OR_PUBLISHED'
}

Invoke-I04OfflineTest -Id 'IMMUTABLE-EVIDENCE-SNAPSHOT-BYTES-SHA-LOCK' `
    -Category 'evidence_snapshot_contract' -Body {
    $path = Join-Path $script:TempRoot 'immutable-evidence.bin'
    $expectedBytes = [byte[]](0, 1, 2, 3, 7, 11, 127, 128, 254, 255)
    [IO.File]::WriteAllBytes($path, $expectedBytes)
    $expectedSha = Get-I04OfflineFileSha256 -Path $path
    $snapshot = Get-I04OfflineImmutableEvidenceSnapshot -Path $path
    Assert-I04Offline -Condition (
        [Int64]$snapshot.byte_count -eq $expectedBytes.Length -and
        [string]$snapshot.sha256 -ceq $expectedSha -and
        [bool]$snapshot.immutable_read_lock_held -and
        [bool]$snapshot.write_open_blocked_while_snapshot_live -and
        [int]$snapshot.retained_lock_count -eq 1 -and
        [BitConverter]::ToString([byte[]]$snapshot.bytes) -ceq
            [BitConverter]::ToString($expectedBytes)) `
        -Code 'IMMUTABLE_EVIDENCE_SNAPSHOT_BYTES_HASH_OR_LOCK_WRONG'
}

$offlinePacketSnapshotEvidence = [pscustomobject][ordered]@{
    schema = 'ese.v91.i04-packet-verdict/v2'
    candidate_process_id = 4242
    coordinator_stop_a_boundary_epoch_ms = [double]1000000
    pcapng_source_byte_count = [Int64]8192
    pcapng_source_sha256 = '8' * 64
    pcapng_source_immutable_read_lock_held = $true
    pcapng_parser_complete = $true
    capture_interface_binding_exact = $true
    target_frames_on_expected_physical_nic = $true
}
$offlineSocketSnapshotEvidence = [pscustomobject][ordered]@{
    schema = 'ese.v91.i04-pid-socket-sampler/v1'
    candidate_process_id = 4242
    boundary_epoch_ms = [double]1000000
    boundary_qpc = [Int64]1000000
    qpc_frequency = [Int64][Diagnostics.Stopwatch]::Frequency
    clock_coherence_valid = $true
    clock_validation = [pscustomobject][ordered]@{
        valid = $true
        sample_count = [int]2
        boundary_epoch_ms = [double]1000000
        boundary_qpc = [Int64]1000000
        qpc_frequency = [Int64][Diagnostics.Stopwatch]::Frequency
    }
    sample_count = [int]2
    parse_error_count = [int]0
    sampler_coverage_valid = $true
    source_byte_count = [Int64]4096
    source_sha256 = '9' * 64
    source_immutable_read_lock_held = $true
}

Invoke-I04OfflineTest -Id 'SNAPSHOT-FAILURE-SOURCE-BINDING-POSITIVE' `
    -Category 'evidence_snapshot_contract' -Body {
    Assert-I04Offline -Condition (
        [bool](Test-I04OfflineSnapshotFailureSourceContract `
            -Kind packet_verdict `
            -Evidence $offlinePacketSnapshotEvidence) -and
        [bool](Test-I04OfflineSnapshotFailureSourceContract `
            -Kind socket_sampler `
            -Evidence $offlineSocketSnapshotEvidence `
            -FailureType socket_contract)) `
        -Code 'VALID_SNAPSHOT_FAILURE_SOURCE_REJECTED'
}

$snapshotFailureMutations = @(
    [pscustomobject]@{ id='PACKET-BYTES'; kind='packet_verdict'; property='pcapng_source_byte_count'; value=[Int64]0; remove=$false },
    [pscustomobject]@{ id='PACKET-BYTES-STRING'; kind='packet_verdict'; property='pcapng_source_byte_count'; value='8192'; remove=$false },
    [pscustomobject]@{ id='PACKET-BYTES-DOUBLE'; kind='packet_verdict'; property='pcapng_source_byte_count'; value=[double]8192; remove=$false },
    [pscustomobject]@{ id='PACKET-SHA'; kind='packet_verdict'; property='pcapng_source_sha256'; value=('x' * 64); remove=$false },
    [pscustomobject]@{ id='PACKET-LOCK'; kind='packet_verdict'; property='pcapng_source_immutable_read_lock_held'; value=$false; remove=$false },
    [pscustomobject]@{ id='PACKET-LOCK-STRING'; kind='packet_verdict'; property='pcapng_source_immutable_read_lock_held'; value='true'; remove=$false },
    [pscustomobject]@{ id='PACKET-LOCK-MISSING'; kind='packet_verdict'; property='pcapng_source_immutable_read_lock_held'; value=$null; remove=$true },
    [pscustomobject]@{ id='PACKET-PID-STRING'; kind='packet_verdict'; property='candidate_process_id'; value='4242'; remove=$false },
    [pscustomobject]@{ id='PACKET-PID-DOUBLE'; kind='packet_verdict'; property='candidate_process_id'; value=[double]4242; remove=$false },
    [pscustomobject]@{ id='PACKET-BOUNDARY'; kind='packet_verdict'; property='coordinator_stop_a_boundary_epoch_ms'; value=[double]1000001; remove=$false },
    [pscustomobject]@{ id='PACKET-BOUNDARY-TOLERANCE'; kind='packet_verdict'; property='coordinator_stop_a_boundary_epoch_ms'; value=[double]1000000.0009; remove=$false },
    [pscustomobject]@{ id='PACKET-BOUNDARY-STRING'; kind='packet_verdict'; property='coordinator_stop_a_boundary_epoch_ms'; value='1000000'; remove=$false },
    [pscustomobject]@{ id='PACKET-BOUNDARY-MISSING'; kind='packet_verdict'; property='coordinator_stop_a_boundary_epoch_ms'; value=$null; remove=$true },
    [pscustomobject]@{ id='SOCKET-BYTES'; kind='socket_sampler'; property='source_byte_count'; value=[Int64]0; remove=$false },
    [pscustomobject]@{ id='SOCKET-BYTES-STRING'; kind='socket_sampler'; property='source_byte_count'; value='4096'; remove=$false },
    [pscustomobject]@{ id='SOCKET-BYTES-DOUBLE'; kind='socket_sampler'; property='source_byte_count'; value=[double]4096; remove=$false },
    [pscustomobject]@{ id='SOCKET-SHA'; kind='socket_sampler'; property='source_sha256'; value=('x' * 64); remove=$false },
    [pscustomobject]@{ id='SOCKET-LOCK'; kind='socket_sampler'; property='source_immutable_read_lock_held'; value=$false; remove=$false },
    [pscustomobject]@{ id='SOCKET-LOCK-STRING'; kind='socket_sampler'; property='source_immutable_read_lock_held'; value='true'; remove=$false },
    [pscustomobject]@{ id='SOCKET-PID-STRING'; kind='socket_sampler'; property='candidate_process_id'; value='4242'; remove=$false },
    [pscustomobject]@{ id='SOCKET-PID-DOUBLE'; kind='socket_sampler'; property='candidate_process_id'; value=[double]4242; remove=$false },
    [pscustomobject]@{ id='SOCKET-BOUNDARY'; kind='socket_sampler'; property='boundary_epoch_ms'; value=[double]1000001; remove=$false },
    [pscustomobject]@{ id='SOCKET-BOUNDARY-TOLERANCE'; kind='socket_sampler'; property='boundary_epoch_ms'; value=[double]1000000.0009; remove=$false },
    [pscustomobject]@{ id='SOCKET-BOUNDARY-STRING'; kind='socket_sampler'; property='boundary_epoch_ms'; value='1000000'; remove=$false },
    [pscustomobject]@{ id='SOCKET-BOUNDARY-MISSING'; kind='socket_sampler'; property='boundary_epoch_ms'; value=$null; remove=$true },
    [pscustomobject]@{ id='SOCKET-LOCK-MISSING'; kind='socket_sampler'; property='source_immutable_read_lock_held'; value=$null; remove=$true },
    [pscustomobject]@{ id='SOCKET-BOUNDARY-QPC-DOUBLE'; kind='socket_sampler'; property='boundary_qpc'; value=[double]1000000; remove=$false },
    [pscustomobject]@{ id='SOCKET-QPC-FREQUENCY-INT32'; kind='socket_sampler'; property='qpc_frequency'; value=[int]1; remove=$false },
    [pscustomobject]@{ id='SOCKET-CLOCK-COHERENCE'; kind='socket_sampler'; property='clock_coherence_valid'; value=$false; remove=$false },
    [pscustomobject]@{ id='SOCKET-SAMPLER-COVERAGE'; kind='socket_sampler'; property='sampler_coverage_valid'; value=$false; remove=$false },
    [pscustomobject]@{ id='SOCKET-PARSE-ERROR'; kind='socket_sampler'; property='parse_error_count'; value=[int]1; remove=$false }
)
foreach ($mutation in $snapshotFailureMutations) {
    $capturedMutation = $mutation
    Invoke-I04OfflineTest -Id (
        'SNAPSHOT-FAILURE-SOURCE-REJECT-' + $capturedMutation.id) `
        -Category 'evidence_snapshot_contract' -Body {
        $source = if ($capturedMutation.kind -ceq 'packet_verdict') {
            $offlinePacketSnapshotEvidence
        } else { $offlineSocketSnapshotEvidence }
        $changed = $source | ConvertTo-Json -Depth 8 | ConvertFrom-Json
        if ([bool]$capturedMutation.remove) {
            $changed.PSObject.Properties.Remove($capturedMutation.property)
        } else {
            $changed.PSObject.Properties[$capturedMutation.property].Value =
                $capturedMutation.value
        }
        Assert-I04Offline -Condition (-not [bool](
            Test-I04OfflineSnapshotFailureSourceContract `
                -Kind $capturedMutation.kind -Evidence $changed `
                -FailureType $(if ($capturedMutation.kind -ceq
                    'socket_sampler') { 'socket_contract' } else {
                    'fallback_window'
                }))) `
            -Code 'MUTATED_SNAPSHOT_FAILURE_SOURCE_ACCEPTED'
    }
}

$socketClockMutations = @(
    [pscustomobject]@{ id='VALID-FALSE'; property='valid'; value=$false; remove=$false },
    [pscustomobject]@{ id='BOUNDARY-EPOCH'; property='boundary_epoch_ms'; value=[double]1000001; remove=$false },
    [pscustomobject]@{ id='BOUNDARY-QPC'; property='boundary_qpc'; value=[Int64]1000001; remove=$false },
    [pscustomobject]@{ id='QPC-FREQUENCY'; property='qpc_frequency'; value=[Int64]1; remove=$false },
    [pscustomobject]@{ id='MISSING'; property='valid'; value=$null; remove=$true }
)
foreach ($mutation in $socketClockMutations) {
    $capturedMutation = $mutation
    Invoke-I04OfflineTest -Id (
        'SNAPSHOT-FAILURE-SOURCE-REJECT-SOCKET-CLOCK-' +
        $capturedMutation.id) -Category 'evidence_snapshot_contract' -Body {
        $changed = New-I04OfflineSamplerEvidence -TargetRows @()
        if ([bool]$capturedMutation.remove) {
            $changed.clock_validation.PSObject.Properties.Remove(
                $capturedMutation.property)
        } else {
            $changed.clock_validation.PSObject.Properties[
                $capturedMutation.property].Value = $capturedMutation.value
        }
        Assert-I04Offline -Condition (-not [bool](
            Test-I04OfflineSnapshotFailureSourceContract `
                -Kind socket_sampler -Evidence $changed `
                -FailureType socket_contract)) `
            -Code 'MUTATED_SOCKET_CLOCK_CONTRACT_ACCEPTED'
    }
}

Invoke-I04OfflineTest -Id 'SNAPSHOT-FAILURE-SOURCE-KIND-MAPPING-REJECT' `
    -Category 'evidence_snapshot_contract' -Body {
    Assert-I04Offline -Condition (
        -not [bool](Test-I04OfflineSnapshotFailureSourceContract `
            -Kind packet_verdict -Evidence $offlinePacketSnapshotEvidence `
            -FailureType socket_contract) -and
        -not [bool](Test-I04OfflineSnapshotFailureSourceContract `
            -Kind socket_sampler -Evidence $offlineSocketSnapshotEvidence `
            -FailureType fallback_window)) `
        -Code 'FAILURE_TYPE_SOURCE_KIND_MISMATCH_ACCEPTED'
}

Invoke-I04OfflineTest -Id 'PCAP-SOCKET-SNAPSHOT-WIRING-STATIC' `
    -Category 'evidence_snapshot_contract' -Body {
    foreach ($contract in @(
        [pscustomobject]@{
            function_name = 'Read-I04PcapNg'; byte_field = 'bytes'
            count_field = 'source_byte_count = [Int64]$snapshot.byte_count'
            sha_field = 'source_sha256 = [string]$snapshot.sha256'
            lock_field = 'source_immutable_read_lock_held ='
        },
        [pscustomobject]@{
            function_name = 'Get-I04SocketSamplerEvidence';
            byte_field = 'snapshotText';
            count_field = 'source_byte_count = [Int64]$snapshot.byte_count'
            sha_field = 'source_sha256 = [string]$snapshot.sha256'
            lock_field = 'source_immutable_read_lock_held ='
        }
    )) {
        $functions = @($script:HarnessAst.FindAll({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] `
                -and $node.Name -ceq $contract.function_name
        }, $true))
        Assert-I04Offline -Condition ($functions.Count -eq 1) `
            -Code 'SNAPSHOT_CONSUMER_FUNCTION_NOT_UNIQUE'
        $function = $functions[0]
        $openCalls = @($function.FindAll({
            param($node)
            $node -is [Management.Automation.Language.CommandAst] -and
                $node.GetCommandName() -ceq
                    'Open-I04ImmutableEvidenceSnapshot'
        }, $true))
        $text = $function.Extent.Text
        Assert-I04Offline -Condition (
            $openCalls.Count -eq 1 -and
            $text.Contains('$snapshot.bytes') -and
            $text.Contains($contract.count_field) -and
            $text.Contains($contract.sha_field) -and
            $text.Contains($contract.lock_field) -and
            $text.Contains('[bool]$snapshot.immutable_read_lock_held')) `
            -Code 'PCAP_OR_SOCKET_SNAPSHOT_BINDING_MISSING'
    }
    $packetVerdict = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Get-I04PacketVerdict'
    }, $true))[0].Extent.Text
    $failure = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'New-I04ProductFailure'
        }, $true))[0].Extent.Text
    $packetFailureContract = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Test-I04PacketFailureSourceContract'
    }, $true))[0].Extent.Text
    $socketFailureContract = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Test-I04SocketFailureSourceContract'
    }, $true))[0].Extent.Text
    Assert-I04Offline -Condition (
        $failure.Contains('Test-I04PacketFailureSourceContract') -and
        $failure.Contains('Test-I04SocketFailureSourceContract')) `
        -Code 'SNAPSHOT_FAILURE_VALIDATORS_NOT_WIRED'
    $snapshotFailureContractText = @(
        $packetVerdict, $failure, $packetFailureContract,
        $socketFailureContract) -join "`n"
    foreach ($needle in @(
        'pcapng_source_byte_count = [Int64]$pcap.source_byte_count',
        'pcapng_source_sha256 = [string]$pcap.source_sha256',
        'pcapng_source_immutable_read_lock_held =',
        '[Int64]$Evidence.pcapng_source_byte_count -gt 0',
        '[string]$Evidence.pcapng_source_sha256 -cmatch',
        'pcapng_source_immutable_read_lock_held',
        '[Int64]$Evidence.source_byte_count -gt 0',
        '[string]$Evidence.source_sha256 -cmatch',
        '[bool]$Evidence.source_immutable_read_lock_held')) {
        Assert-I04Offline -Condition (
            $snapshotFailureContractText.Contains($needle)) `
            -Code 'SNAPSHOT_FAILURE_CONTRACT_BINDING_MISSING'
    }
}

$offlineFirewallScenarioBefore =
    New-I04OfflineGlobalFirewallScenarioSnapshot

Invoke-I04OfflineTest -Id 'FIREWALL-SCENARIO-SNAPSHOT-EQUALITY-POSITIVE' `
    -Category 'firewall_contract' -Body {
    $after = $offlineFirewallScenarioBefore | ConvertTo-Json -Depth 5 |
        ConvertFrom-Json
    Assert-I04Offline -Condition ([bool](
        Test-I04OfflineFirewallScenarioSnapshotsEqual `
            -Before $offlineFirewallScenarioBefore -After $after)) `
        -Code 'IDENTICAL_FIREWALL_SCENARIO_SNAPSHOTS_REJECTED'
}

$firewallScenarioMutations = @(
    [pscustomobject]@{ id='DRIFT'; property='canonical_sha256'; value=('b' * 64); remove=$false },
    [pscustomobject]@{ id='SCHEMA'; property='schema'; value='legacy'; remove=$false },
    [pscustomobject]@{ id='PRIVACY-FALSE'; property='privacy_safe'; value=$false; remove=$false },
    [pscustomobject]@{ id='PRIVACY-STRING'; property='privacy_safe'; value='true'; remove=$false },
    [pscustomobject]@{ id='HASH-INVALID'; property='canonical_sha256'; value='bad'; remove=$false },
    [pscustomobject]@{ id='HASH-MISSING'; property='canonical_sha256'; value=$null; remove=$true }
)
foreach ($mutation in $firewallScenarioMutations) {
    $capturedMutation = $mutation
    Invoke-I04OfflineTest -Id (
        'FIREWALL-SCENARIO-SNAPSHOT-REJECT-' + $capturedMutation.id) `
        -Category 'firewall_contract' -Body {
        $after = $offlineFirewallScenarioBefore | ConvertTo-Json -Depth 5 |
            ConvertFrom-Json
        if ([bool]$capturedMutation.remove) {
            $after.PSObject.Properties.Remove($capturedMutation.property)
        } else {
            $after.PSObject.Properties[$capturedMutation.property].Value =
                $capturedMutation.value
        }
        Assert-I04Offline -Condition (-not [bool](
            Test-I04OfflineFirewallScenarioSnapshotsEqual `
                -Before $offlineFirewallScenarioBefore -After $after)) `
            -Code 'MUTATED_FIREWALL_SCENARIO_SNAPSHOT_ACCEPTED'
    }
}

Invoke-I04OfflineTest -Id 'FIREWALL-SCENARIO-SNAPSHOTS-WIRED-STATIC' `
    -Category 'firewall_contract' -Body {
    $peer = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Invoke-I04PeerRole'
    }, $true))[0].Extent.Text
    $coordinatorAst = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Invoke-I04CoordinatorRole'
    }, $true))[0]
    $coordinator = $coordinatorAst.Extent.Text
    foreach ($needle in @(
        '$peerFirewallArmedSnapshot = $null',
        '$peerFirewallPreRemovalSnapshot = $null',
        '$peerFirewallScenarioUnchanged = $false',
        '$peerFirewallArmedSnapshot = Get-I04GlobalFirewallSnapshot',
        '$peerFirewallPreRemovalSnapshot =',
        '$peerFirewallPreRemovalSnapshot.canonical_sha256 -ceq',
        '$peerFirewallArmedSnapshot.canonical_sha256',
        'global firewall inventory drifted while the peer scenario was armed',
        'global_firewall_armed = $peerFirewallArmedSnapshot',
        'global_firewall_pre_removal = $peerFirewallPreRemovalSnapshot',
        'global_firewall_scenario_unchanged = $peerFirewallScenarioUnchanged')) {
        Assert-I04Offline -Condition ($peer.Contains($needle)) `
            -Code 'PEER_FIREWALL_SCENARIO_SNAPSHOT_WIRING_MISSING'
    }
    foreach ($needle in @(
        '$coordinatorFirewallBeforeBoundary = $null',
        '$coordinatorFirewallAfterObservation = $null',
        '$coordinatorFirewallScenarioUnchanged = $false',
        '$coordinatorFirewallBeforeBoundary =',
        '$coordinatorFirewallAfterObservation =',
        '$coordinatorFirewallAfterObservation.',
        '$coordinatorFirewallBeforeBoundary.canonical_sha256',
        'Coordinator global firewall drifted during the formal scenario',
        '-not $coordinatorFirewallScenarioUnchanged')) {
        Assert-I04Offline -Condition ($coordinator.Contains($needle)) `
            -Code 'COORDINATOR_FIREWALL_SCENARIO_SNAPSHOT_WIRING_MISSING'
    }
    $proofAssignments = @($coordinatorAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.AssignmentStatementAst] -and
            $node.Left.Extent.Text -ceq '$proofContradicted'
    }, $true))
    Assert-I04Offline -Condition (
        $proofAssignments.Count -eq 1 -and
        $proofAssignments[0].Extent.Text.Contains(
            '$coordinatorFirewallScenarioUnchanged') -and
        $proofAssignments[0].Extent.Text.ToLowerInvariant().Contains(
            'peer') -and
        $proofAssignments[0].Extent.Text.ToLowerInvariant().Contains(
            'firewall') -and
        $coordinator.Contains(
            "if (`$partialVerdict -eq 'PASS' -and `$adjudicationClean)")) `
        -Code 'FIREWALL_SCENARIO_DRIFT_NOT_PROOF_CONTRADICTED_BLOCKED'
    foreach ($needle in @(
        '[bool]$peerResult.cleanup.global_firewall_scenario_unchanged',
        '$peerResult.cleanup.global_firewall_armed.',
        '$peerResult.cleanup.global_firewall_pre_removal.',
        '$peerArmed.global_firewall_armed.')) {
        Assert-I04Offline -Condition ($coordinator.Contains($needle)) `
            -Code 'PEER_FIREWALL_SNAPSHOT_NOT_CROSS_ARTIFACT_BOUND'
    }
}

Invoke-I04OfflineTest -Id 'RESTRICTED-LAUNCHER-PING-ISOLATED' `
    -Category 'ownership_contract' -Body {
    $working = Join-Path $script:TempRoot 'restricted-launcher-ping'
    [IO.Directory]::CreateDirectory($working) | Out-Null
    $probe = Invoke-I04OfflineRestrictedLauncherProbe `
        -WorkingDirectory $working
    Assert-I04Offline -Condition (
        [int]$probe.process_id -gt 0 -and
        [string]$probe.contract_id -ceq
            'ese.v91.i04-restricted-process-launcher/2026-08-01.v1' -and
        [int]$probe.active_process_limit -eq 1 -and
        [int]$probe.total_processes -eq 1 -and
        [int]$probe.active_processes -eq 1 -and
        [bool]$probe.child_processes_structurally_forbidden -and
        [bool]$probe.assigned_before_resume -and [bool]$probe.released -and
        [bool]$probe.exited_after_release -and
        [bool]$probe.lease_unavailable_after_release -and
        [int]$probe.tracked_pid_count_after_release -eq 0) `
        -Code 'RESTRICTED_LAUNCHER_PING_CONTRACT_NOT_PROVED'
}

Invoke-I04OfflineTest -Id 'RESTRICTED-LAUNCHER-ORDER-ACCOUNTING-STATIC' `
    -Category 'ownership_contract' -Body {
    $initializer = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Initialize-I04RestrictedProcessLauncher'
    }, $true))[0].Extent.Text
    $startAt = $initializer.IndexOf('public static LaunchResult Start(')
    $queryAt = $initializer.IndexOf('public static AccountingResult Query(')
    Assert-I04Offline -Condition ($startAt -ge 0 -and $queryAt -gt $startAt) `
        -Code 'RESTRICTED_LAUNCHER_MANAGED_START_NOT_UNIQUE'
    $managedStart = $initializer.Substring($startAt, $queryAt - $startAt)
    $createAt = $managedStart.IndexOf('if (!CreateProcessW(')
    $limitAt = $managedStart.IndexOf(
        'limits.BasicLimitInformation.ActiveProcessLimit = 1;')
    $setLimitAt = $managedStart.IndexOf('SetInformationJobObject(')
    $assignAt = $managedStart.IndexOf('AssignProcessToJobObject(')
    $resumeAt = $managedStart.IndexOf('ResumeThread(pi.hThread)')
    Assert-I04Offline -Condition (
        $createAt -ge 0 -and $limitAt -gt $createAt -and
        $setLimitAt -gt $limitAt -and $assignAt -gt $setLimitAt -and
        $resumeAt -gt $assignAt -and
        $managedStart.Contains('CREATE_SUSPENDED') -and
        $initializer.Contains('JOB_OBJECT_LIMIT_ACTIVE_PROCESS') -and
        $initializer.Contains('JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE') -and
        $initializer.Contains('ActiveProcessLimit = 1') -and
        $initializer.Contains('StartedSuspended = true') -and
        $initializer.Contains('AssignedBeforeResume = true')) `
        -Code 'RESTRICTED_LAUNCHER_ASSIGN_BEFORE_RESUME_ORDER_WRONG'
    $startWrapper = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Start-I04RestrictedProcess'
    }, $true))[0].Extent.Text
    foreach ($needle in @(
        "'ese.v91.i04-restricted-process-launcher/2026-08-01.v1'",
        '-not ($launch.ActiveProcessLimit -is [UInt32])',
        '[UInt32]$launch.ActiveProcessLimit -ne 1',
        '-not [bool]$launch.StartedSuspended',
        '-not [bool]$launch.AssignedBeforeResume',
        'Assert-I04RestrictedJobAccountingContract',
        '-ExpectedActiveProcesses 1',
        'i04_job_contract_id', 'i04_job_active_process_limit',
        'i04_job_assigned_before_resume', 'i04_job_last_accounting')) {
        Assert-I04Offline -Condition ($startWrapper.Contains($needle)) `
            -Code 'RESTRICTED_LAUNCHER_WRAPPER_GATE_MISSING'
    }
}

Invoke-I04OfflineTest -Id 'RESTRICTED-LAUNCHER-BINDING-TERMINAL-STATIC' `
    -Category 'ownership_contract' -Body {
    $launchCalls = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.CommandAst] -and
            $node.GetCommandName() -ceq 'Start-I04RestrictedProcess'
    }, $true))
    $legacyStarts = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.CommandAst] -and
            $node.GetCommandName() -ceq 'Start-Process'
    }, $true))
    Assert-I04Offline -Condition (
        $launchCalls.Count -eq 2 -and $legacyStarts.Count -eq 0) `
        -Code 'CANDIDATE_PROCESS_NOT_EXCLUSIVELY_RESTRICTED_LAUNCHED'
    foreach ($name in @(
        'Register-I04OwnedProcess', 'Test-I04OwnedProcessBinding',
        'Test-I04OwnedProcessDescendants',
        'Get-I04TerminalOwnershipCensus')) {
        $functions = @($script:HarnessAst.FindAll({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] `
                -and $node.Name -ceq $name
        }, $true))
        Assert-I04Offline -Condition ($functions.Count -eq 1) `
            -Code 'RESTRICTED_JOB_BINDING_FUNCTION_NOT_UNIQUE'
        $text = $functions[0].Extent.Text
        $requiredJobFields = if ($name -ceq
                'Test-I04OwnedProcessDescendants') {
            @('i04_job_last_accounting')
        } else {
            @(
                'i04_job_contract_id', 'i04_job_active_process_limit',
                'i04_job_assigned_before_resume',
                'i04_job_last_accounting'
            )
        }
        foreach ($needle in $requiredJobFields) {
            Assert-I04Offline -Condition ($text.Contains($needle)) `
                -Code 'RESTRICTED_JOB_NOT_BOUND_TO_OWNERSHIP_OR_TERMINAL_CENSUS'
        }
    }
    $descendants = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Test-I04OwnedProcessDescendants'
    }, $true))[0].Extent.Text
    foreach ($needle in @(
        'Get-I04RestrictedJobAccounting',
        '$expectedActive = if ($RootMayHaveExited -or $Process.HasExited)',
        'Assert-I04RestrictedJobAccountingContract',
        '-ExpectedActiveProcesses $expectedActive')) {
        Assert-I04Offline -Condition ($descendants.Contains($needle)) `
            -Code 'RESTRICTED_JOB_ACTIVE_ONE_TO_ZERO_NOT_TERMINALLY_GATED'
    }
    $accountingContract = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Assert-I04RestrictedJobAccountingContract'
    }, $true))[0].Extent.Text
    foreach ($needle in @(
        "'ese.v91.i04-restricted-job-accounting/v1'",
        '-not ($Accounting.process_id -is [int])',
        '-not ($Accounting.active_process_limit -is [int])',
        '-not ($Accounting.total_processes -is [int])',
        '-not ($Accounting.active_processes -is [int])',
        '-not ($Accounting.total_terminated_processes -is [int])',
        '[int]$Accounting.total_terminated_processes -ne 0',
        '-not ($Accounting.child_processes_structurally_forbidden -is [bool])'
    )) {
        Assert-I04Offline -Condition ($accountingContract.Contains($needle)) `
            -Code 'RESTRICTED_JOB_TYPED_ACCOUNTING_GATE_MISSING'
    }
    Assert-I04Offline -Condition (
        $script:HarnessText.Contains(
            '$script:i04RestrictedJobPids.Add([int]$launch.ProcessId)') -and
        $script:HarnessText.Contains(
            '[V91I04RestrictedProcessLauncher]::Release(') -and
        $script:HarnessText.Contains(
            '$script:i04RestrictedJobPids.Remove(') -and
        $script:HarnessText.Contains(
            'Complete-I04RestrictedJobLeaseCleanup -Context OuterFinally')) `
        -Code 'RESTRICTED_JOB_LEASE_NOT_RELEASED_IN_OUTER_FINALLY'
}

Invoke-I04OfflineTest `
    -Id 'RESTRICTED-LEASE-CLEANUP-BEFORE-PUBLICATION-STATIC' `
    -Category 'ownership_contract' -Body {
    $peer = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Invoke-I04PeerRole'
    }, $true))[0].Extent.Text
    $coordinator = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Invoke-I04CoordinatorRole'
    }, $true))[0].Extent.Text
    $peerCleanupAt = $peer.IndexOf(
        'Complete-I04RestrictedJobLeaseCleanup -Context Peer')
    $peerResultAt = $peer.IndexOf('$peerResult = [ordered]@{')
    $coordinatorCleanupAt = $coordinator.IndexOf(
        'Complete-I04RestrictedJobLeaseCleanup -Context Coordinator')
    $coordinatorSummaryAt = $coordinator.IndexOf('$summary = [ordered]@{')
    Assert-I04Offline -Condition (
        $peerCleanupAt -ge 0 -and $peerResultAt -gt $peerCleanupAt -and
        $peer.Contains('[bool]$restrictedJobLeaseCleanup.complete') -and
        $peer.Contains('restricted_job_lease_cleanup =') -and
        $coordinatorCleanupAt -ge 0 -and
        $coordinatorSummaryAt -gt $coordinatorCleanupAt -and
        $coordinator.Contains(
            '[bool]$cleanup.restricted_job_lease_cleanup.complete') -and
        $script:HarnessText.Contains(
            'lease_unavailable_after_release_count') -and
        $script:HarnessText.Contains(
            'remaining_registered_process_count')) `
        -Code 'RESTRICTED_LEASE_RELEASE_NOT_TERMINALLY_GATED'
}

Invoke-I04OfflineTest `
    -Id 'PEER-TERMINAL-RECEIPT-AND-REMOTE-EXIT-STATIC' `
    -Category 'ownership_contract' -Body {
    $coordinator = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Invoke-I04CoordinatorRole'
    }, $true))[0].Extent.Text
    $outerFinallyAt = $script:HarnessText.LastIndexOf('} finally {')
    $terminalSchemaAt = $script:HarnessText.IndexOf(
        "schema = 'ese.v91.i04-peer-terminal/v1'", $outerFinallyAt)
    $terminalWriteAt = $script:HarnessText.IndexOf(
        '}) -Path $script:i04PeerTerminalReceiptPath', $terminalSchemaAt)
    Assert-I04Offline -Condition (
        $outerFinallyAt -ge 0 -and $terminalSchemaAt -gt $outerFinallyAt -and
        $terminalWriteAt -gt $terminalSchemaAt -and
        $coordinator.Contains("'peer-terminal.json'") -and
        $coordinator.Contains('Wait-I04File -Path $peerTerminalPath') -and
        $coordinator.Contains('Test-I04PeerTerminalContract') -and
        $coordinator.Contains('Get-LabSha256 -Path $peerResultPath') -and
        $coordinator.Contains('Wait-Job -Job $remoteJob') -and
        $coordinator.Contains(
            '[string]$remoteJob.State -cne ''Completed''') -and
        $coordinator.Contains(
            'Receive-Job -Job $remoteJob -Wait -ErrorAction Stop') -and
        -not $coordinator.Contains(
            'Receive-Job -Job $remoteJob -Wait -ErrorAction Continue') -and
        $coordinator.Contains('$remoteJob.ChildJobs') -and
        $coordinator.Contains('@($remoteJob.Error).Count -ne 0') -and
        $coordinator.Contains(
            '$peerTerminalExact -and $remoteJobTerminalExact')) `
        -Code 'PEER_TERMINAL_OR_REMOTE_JOB_EXIT_GATE_MISSING'
}

$coordinatorRoleText = @($script:HarnessAst.FindAll({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Invoke-I04CoordinatorRole'
}, $true))[0].Extent.Text
$outerTerminalTries = @($script:HarnessAst.FindAll({
    param($node)
    $node -is [Management.Automation.Language.TryStatementAst] -and
        $null -ne $node.Finally -and
        $node.Parent -is [Management.Automation.Language.NamedBlockAst] -and
        [object]::ReferenceEquals($node.Parent.Parent, $script:HarnessAst)
}, $true))
$coordinatorFinalizers = @($script:HarnessAst.FindAll({
    param($node)
    $node -is [Management.Automation.Language.IfStatementAst] -and
        $node.Parent -is [Management.Automation.Language.NamedBlockAst] -and
        [object]::ReferenceEquals($node.Parent.Parent, $script:HarnessAst) -and
        $node.Extent.Text.Contains(
            '$Role -eq ''Coordinator'' -and $script:i04RoleCompleted')
}, $true))
Invoke-I04OfflineTest `
    -Id 'COORDINATOR-PASS-AFTER-OUTER-CLEANUP-STATIC' `
    -Category 'ownership_contract' -Body {
    Assert-I04Offline -Condition (
        $outerTerminalTries.Count -eq 1 -and
        $coordinatorFinalizers.Count -eq 1 -and
        $coordinatorFinalizers[0].Extent.StartOffset -gt
            $outerTerminalTries[0].Extent.EndOffset -and
        (Test-I04OfflineCoordinatorTerminalPublicationOrder `
            -CoordinatorRoleText $coordinatorRoleText `
            -OuterFinallyText $outerTerminalTries[0].Finally.Extent.Text `
            -FinalizerText $coordinatorFinalizers[0].Extent.Text)) `
        -Code 'COORDINATOR_PASS_PRECEDES_OUTER_CLEANUP'
}

$coordinatorPublicationMutations = @(
    [pscustomobject]@{
        id = 'EARLY-SUMMARY'; scope = 'role'; target = ''
        replacement = 'Write-LabJson -Value $summary -Path $summaryPath'
    },
    [pscustomobject]@{
        id = 'NO-TERMINAL-LOCK-THROW'; scope = 'finally'
        target = 'throw $i04TerminalLockFailure'
        replacement = 'Write-Output $i04TerminalLockFailure'
    },
    [pscustomobject]@{
        id = 'NO-CANDIDATE-LOCK-RELEASE'; scope = 'finally'
        target = '$script:i04CandidateLocks.ToArray()'
        replacement = '$script:i04CandidateLocksMissing.ToArray()'
    },
    [pscustomobject]@{
        id = 'NO-EVIDENCE-LOCK-RELEASE'; scope = 'finally'
        target = '$script:i04EvidenceLocks.ToArray()'
        replacement = '$script:i04EvidenceLocksMissing.ToArray()'
    },
    [pscustomobject]@{
        id = 'NO-HARNESS-LOCK-RELEASE'; scope = 'finally'
        target = '$script:i04HarnessBundleLocks.ToArray()'
        replacement = '$script:i04HarnessBundleLocksMissing.ToArray()'
    },
    [pscustomobject]@{
        id = 'NO-SUMMARY-HASH-BINDING'; scope = 'finalizer'
        target = 'summary_sha256 = $summarySha256'
        replacement = 'summary_sha256 = (''0'' * 64)'
    },
    [pscustomobject]@{
        id = 'NO-PUBLIC-HASH-BINDING'; scope = 'finalizer'
        target = 'public_summary_sha256 = $publicSummarySha256'
        replacement = 'public_summary_sha256 = (''0'' * 64)'
    },
    [pscustomobject]@{
        id = 'NO-TERMINAL-RECEIPT'; scope = 'finalizer'
        target = "schema = 'ese.v91.i04-coordinator-terminal/v1'"
        replacement = "schema = 'ese.v91.i04-coordinator-terminal/removed'"
    }
)
foreach ($publicationMutation in $coordinatorPublicationMutations) {
    $capturedPublicationMutation = $publicationMutation
    Invoke-I04OfflineTest -Id (
        'COORDINATOR-TERMINAL-REJECT-' +
            $capturedPublicationMutation.id) `
        -Category 'ownership_contract' -Body {
        $role = $coordinatorRoleText
        $outerFinally = $outerTerminalTries[0].Finally.Extent.Text
        $finalizer = $coordinatorFinalizers[0].Extent.Text
        switch ([string]$capturedPublicationMutation.scope) {
            'role' {
                $role += "`r`n" +
                    [string]$capturedPublicationMutation.replacement
            }
            'finally' {
                $outerFinally = $outerFinally.Replace(
                    [string]$capturedPublicationMutation.target,
                    [string]$capturedPublicationMutation.replacement)
            }
            'finalizer' {
                $finalizer = $finalizer.Replace(
                    [string]$capturedPublicationMutation.target,
                    [string]$capturedPublicationMutation.replacement)
            }
            default { throw 'Unknown coordinator publication mutation scope' }
        }
        Assert-I04Offline -Condition (-not (
            Test-I04OfflineCoordinatorTerminalPublicationOrder `
                -CoordinatorRoleText $role `
                -OuterFinallyText $outerFinally `
                -FinalizerText $finalizer)) `
            -Code 'MUTATED_COORDINATOR_TERMINAL_PUBLICATION_ACCEPTED'
    }
}

Invoke-I04OfflineTest -Id 'PKTMON-GLOBAL-MUTEX-WIRING-STATIC' `
    -Category 'pcap_contract' -Body {
    $coordinator = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Invoke-I04CoordinatorRole'
    }, $true))[0].Extent.Text
    foreach ($name in @(
        'Enter-I04PktmonGlobalMutex',
        'Assert-I04PktmonGlobalMutexOwnership',
        'Exit-I04PktmonGlobalMutex')) {
        $matches = @($script:HarnessAst.FindAll({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] `
                -and $node.Name -ceq $name
        }, $true))
        Assert-I04Offline -Condition ($matches.Count -eq 1) `
            -Code 'PKTMON_GLOBAL_MUTEX_FUNCTION_NOT_UNIQUE'
    }
    $acquireAt = $coordinator.IndexOf('Enter-I04PktmonGlobalMutex')
    $censusAt = $coordinator.IndexOf(
        "Get-I04EtwLossEvidence -SessionName 'PktMon'")
    $startAt = $coordinator.IndexOf('Start-I04PacketCapture')
    $stopAt = $coordinator.IndexOf('Stop-I04PacketCapture')
    $releaseAt = $coordinator.IndexOf(
        'Exit-I04PktmonGlobalMutex', $stopAt)
    $startFunction = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Start-I04PacketCapture'
    }, $true))[0].Extent.Text
    $stopFunction = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Stop-I04PacketCapture'
    }, $true))[0].Extent.Text
    Assert-I04Offline -Condition (
        $acquireAt -ge 0 -and $censusAt -gt $acquireAt -and
        $startAt -gt $censusAt -and $stopAt -gt $startAt -and
        $releaseAt -gt $stopAt -and
        $startFunction.Contains(
            'Assert-I04PktmonGlobalMutexOwnership') -and
        $stopFunction.Contains(
            'Assert-I04PktmonGlobalMutexOwnership') -and
        $coordinator.Contains('pktmon_global_mutex =') -and
        $coordinator.Contains(
            '[bool]$cleanup.pktmon_global_mutex.release_exact') -and
        $script:HarnessText.Contains(
            "'Global\eSE-V91-I04-PktMon-v1'")) `
        -Code 'PKTMON_GLOBAL_MUTEX_SCOPE_OR_RELEASE_GATE_MISSING'
}

$validPeerTerminal = [pscustomobject][ordered]@{
    schema = 'ese.v91.i04-peer-terminal/v1'
    case_id = 'V91-I04'
    run_nonce = '1' * 32
    status = 'COMPLETE'
    peer_result_sha256 = 'a' * 64
    restricted_job_lease_cleanup = [pscustomobject][ordered]@{
        schema = 'ese.v91.i04-restricted-job-lease-cleanup/v1'
        context = 'Peer'
        completed_at_utc = '2026-08-01T00:00:00.0000000Z'
        requested_process_count = 2
        terminal_accounting_exact_count = 2
        released_count = 2
        lease_unavailable_after_release_count = 2
        remaining_registered_process_count = 0
        failures = @()
        complete = $true
    }
    candidate_locks_released = $true
    evidence_locks_released = $true
    harness_bundle_locks_released = $true
    account_registry_postcheck_complete = $true
    account_registry_safe_to_pass = $true
    outer_cleanup_complete = $true
    completed_at_utc = '2026-08-01T00:00:01.0000000Z'
}
Invoke-I04OfflineTest -Id 'PEER-TERMINAL-CONTRACT-POSITIVE' `
    -Category 'ownership_contract' -Body {
    Assert-I04Offline -Condition (
        Test-I04OfflinePeerTerminalContract -Terminal $validPeerTerminal `
            -ExpectedCaseId 'V91-I04' -ExpectedRunNonce ('1' * 32) `
            -ExpectedPeerResultSha256 ('a' * 64)) `
        -Code 'EXACT_PEER_TERMINAL_RECEIPT_REJECTED'
}
$peerTerminalMutations = @(
    [pscustomobject]@{ id='RESULT-HASH'; mutate={ param($v)
        $v.peer_result_sha256 = 'b' * 64 } },
    [pscustomobject]@{ id='LEASE-CONTEXT'; mutate={ param($v)
        $v.restricted_job_lease_cleanup.context = 'Coordinator' } },
    [pscustomobject]@{ id='LEASE-COUNT'; mutate={ param($v)
        $v.restricted_job_lease_cleanup.released_count = 1 } },
    [pscustomobject]@{ id='LEASE-REMAINS'; mutate={ param($v)
        $v.restricted_job_lease_cleanup.remaining_registered_process_count = 1 } },
    [pscustomobject]@{ id='LEASE-FAILURES-NULL'; mutate={ param($v)
        $v.restricted_job_lease_cleanup.failures = $null } },
    [pscustomobject]@{ id='OUTER-INCOMPLETE'; mutate={ param($v)
        $v.outer_cleanup_complete = $false } },
    [pscustomobject]@{ id='LOCK-BOOLEAN-TYPE'; mutate={ param($v)
        $v.candidate_locks_released = 'true' } },
    [pscustomobject]@{ id='EXTRA-PROPERTY'; mutate={ param($v)
        $v | Add-Member -NotePropertyName unexpected -NotePropertyValue $true } }
)
foreach ($mutation in $peerTerminalMutations) {
    $capturedMutation = $mutation
    Invoke-I04OfflineTest -Id (
        'PEER-TERMINAL-CONTRACT-REJECT-' + $capturedMutation.id) `
        -Category 'ownership_contract' -Body {
        $value = $validPeerTerminal | ConvertTo-Json -Depth 12 |
            ConvertFrom-Json
        & $capturedMutation.mutate $value
        Assert-I04Offline -Condition (-not (
            Test-I04OfflinePeerTerminalContract -Terminal $value `
                -ExpectedCaseId 'V91-I04' `
                -ExpectedRunNonce ('1' * 32) `
                -ExpectedPeerResultSha256 ('a' * 64))) `
            -Code 'MUTATED_PEER_TERMINAL_RECEIPT_ACCEPTED'
    }
}

Invoke-I04OfflineTest -Id 'AST-OFFLINE-SELF-SIDE-EFFECT-FREE' `
    -Category 'side_effect_guard' -Body {
    $tokens = $null
    $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile(
        $script:SelfPath, [ref]$tokens, [ref]$errors)
    Assert-I04Offline -Condition (@($errors).Count -eq 0) `
        -Code 'OFFLINE_SELF_PARSER_ERROR'
    Assert-I04AstNoExternalSideEffects -Ast $ast `
        -Code 'OFFLINE_SELF_EXTERNAL_SIDE_EFFECT_FOUND'
}

Invoke-I04OfflineTest -Id 'AST-PURE-ALLOWLIST-EXACT-AND-EXERCISED' `
    -Category 'side_effect_guard' -Body {
    foreach ($name in $script:PureFunctionAllowlist) {
        $matches = @($script:HarnessAst.FindAll({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] `
                -and $node.Name -ceq $name
        }, $true))
        Assert-I04Offline -Condition ($matches.Count -eq 1) `
            -Code 'PURE_ALLOWLIST_FUNCTION_NOT_EXACTLY_ONE'
        Assert-I04Offline -Condition (
            $script:ExtractedFunctionNames.Contains($name)) `
            -Code 'PURE_ALLOWLIST_FUNCTION_NOT_EXERCISED'
    }
    Assert-I04Offline -Condition (
        $script:ExtractedFunctionNames.Count -eq
            $script:PureFunctionAllowlist.Count) `
        -Code 'PURE_EXTRACTION_SET_NOT_EXACT'
}

Invoke-I04OfflineTest -Id 'AST-EXTRACTED-CLOSURE-SIDE-EFFECT-FREE' `
    -Category 'side_effect_guard' -Body {
    foreach ($name in @($script:ExtractedFunctionNames)) {
        $functionAst = @($script:HarnessAst.FindAll({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] `
                -and $node.Name -ceq $name
        }, $true))[0]
        Assert-I04AstNoExternalSideEffects -Ast $functionAst `
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

Invoke-I04OfflineTest -Id 'TEMP-FIXTURE-CLEANUP' `
    -Category 'side_effect_guard' -Body {
    Assert-I04Offline -Condition $script:TempCleanupProven `
        -Code 'TEMP_FIXTURE_CLEANUP_NOT_PROVEN'
}

Invoke-I04OfflineTest -Id 'HARNESS-BYTES-UNCHANGED-DURING-RUN' `
    -Category 'side_effect_guard' -Body {
    Assert-I04OfflineEqual `
        -Actual (Get-I04OfflineFileSha256 -Path $script:HarnessPath) `
        -Expected $script:HarnessInitialSha256 `
        -Code 'HARNESS_BYTES_CHANGED_DURING_OFFLINE_RUN'
}

$failed = @($script:Results | Where-Object status -ceq 'FAIL')
$canonicalLines = @($script:Results | Sort-Object id | ForEach-Object {
    '{0}|{1}|{2}|{3}|{4}|{5}' -f $_.id, $_.category, $_.status,
        $_.failure_type, $_.failure_id, $_.failure_sha256
}) -join "`n"
$summary = [pscustomobject][ordered]@{
    schema = 'ese.v91.i04-offline-selftest/v1'
    case_id = 'V91-I04'
    status = if ($failed.Count -eq 0) { 'PASS' } else { 'FAIL' }
    physical_execution_performed = $false
    formal_case_status = 'BLOCKED'
    test_count = $script:Results.Count
    pass_count = $script:Results.Count - $failed.Count
    fail_count = $failed.Count
    harness_sha256 = $script:HarnessInitialSha256
    result_sha256 = Get-I04OfflineStringSha256 -Value $canonicalLines
    tests = @($script:Results | Sort-Object id)
}
$summary | ConvertTo-Json -Depth 10
if ($failed.Count -ne 0) { exit 1 }
