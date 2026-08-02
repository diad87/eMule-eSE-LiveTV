[CmdletBinding()]
param(
    [string]$HarnessPath = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

if ([string]::IsNullOrWhiteSpace($HarnessPath)) {
    $HarnessPath = Join-Path $PSScriptRoot `
        'test_v91_i03_route_selection.ps1'
}
$script:SelfPath = [IO.Path]::GetFullPath($MyInvocation.MyCommand.Path)

$script:HarnessPath = [IO.Path]::GetFullPath($HarnessPath)
$script:HarnessBytes = [IO.File]::ReadAllBytes($script:HarnessPath)
$script:HarnessByteSha = [Security.Cryptography.SHA256]::Create()
try {
    $script:HarnessInitialSha256 = ([BitConverter]::ToString(
        $script:HarnessByteSha.ComputeHash($script:HarnessBytes)
    )).Replace('-', '').ToLowerInvariant()
} finally {
    $script:HarnessByteSha.Dispose()
}
$script:HarnessMemoryStream = [IO.MemoryStream]::new(
    $script:HarnessBytes, $false)
$script:HarnessReader = [IO.StreamReader]::new(
    $script:HarnessMemoryStream, [Text.Encoding]::UTF8, $true)
try {
    $script:HarnessText = $script:HarnessReader.ReadToEnd()
} finally {
    $script:HarnessReader.Dispose()
    $script:HarnessMemoryStream.Dispose()
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
    ('ese-v91-i03-offline-' + [Guid]::NewGuid().ToString('N'))
$script:TempCleanupProven = $false
$script:PackagePath = ''
$script:PackageIdentity = $null
$script:ValidZipPath = ''
$script:NodePackagePath = ''
$script:NodePackageIdentity = $null
$script:ExtractedFunctionNames =
    [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal)
$script:PureFunctionAllowlist = @(
    'Convert-I03Address',
    'Get-I03NormalizedIp',
    'Test-I03PathContainedBy',
    'Assert-I03PrivateRoot',
    'Test-I03PublicEvidenceText',
    'Test-I03PublicEvidenceObject',
    'Test-I03IpPrefix',
    'Get-I03NativeAddressClass',
    'Get-I03PackageIdentity',
    'Get-I03PackageManifestSha256',
    'Test-I03PreparedNodeBinding',
    'Get-I03ZipPackageBinding',
    'Test-I03FailurePhase',
    'New-I03ProofProjection',
    'New-I03FailureRecord',
    'Test-I03FailureRecord',
    'Get-I03FormalAdjudication',
    'Get-I03ClockEvidence',
    'Get-I03TopologyDecision',
    'Get-I03RouteSelectionDecision',
    'Get-I03HelloEvidenceDecision',
    'Test-I03StrictJsonInteger',
    'Test-I03ApiIsolation',
    'Get-I03ApiEvidenceProjection',
    'Test-I03SamePhysicalPrefix',
    'Get-I03TupleKey',
    'Get-I03CandidateSocketCensusDecision',
    'New-I03Ed2kFrame',
    'New-I03Ed2kIdChangeFrame',
    'Test-I03Ed2kLoginRequestFrame',
    'Test-I03ProcessIdentityMatch',
    'Get-I03ProcessLineageDecision',
    'ConvertTo-I03RegistryDataProjection',
    'Get-I03ObjectSha256',
    'Get-I03RegistryTreeWithoutValueProjection',
    'Get-I03RegistryCleanupPlan',
    'Get-I03FirewallProjection',
    'Test-I03SystemStateSnapshot',
    'Get-I03IniExactValueEvidence',
    'Assert-I03PreferenceContract'
)

function Get-OfflineStringSha256 {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value)

    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($Value)
        return ([BitConverter]::ToString($sha.ComputeHash($bytes))).
            Replace('-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function Get-OfflineFileSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)

    $stream = [IO.File]::Open(
        [IO.Path]::GetFullPath($Path),
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
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

function Assert-I03Offline {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Code
    )

    if (-not $Condition) { throw $Code }
}

function Assert-I03OfflineEqual {
    param(
        [AllowNull()][object]$Actual,
        [AllowNull()][object]$Expected,
        [Parameter(Mandatory = $true)][string]$Code
    )

    if ([string]$Actual -cne [string]$Expected) { throw $Code }
}

function Invoke-I03OfflineTest {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)][scriptblock]$Body
    )

    if (@($script:Results | Where-Object { $_.id -ceq $Id }).Count -ne 0) {
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
        $safeMessage = [string]$_.Exception.Message
        $safeMessage = $safeMessage.Replace(
            [IO.Path]::GetDirectoryName($script:HarnessPath), '<REPO>')
        $failureId = ([string]$_.FullyQualifiedErrorId).Split(',')[0]
        if ($failureId -ceq 'PropertyNotFoundStrict' -and
            $safeMessage -match "'([A-Za-z0-9_]+)'") {
            $failureId = 'PROPERTY_NOT_FOUND_' +
                $Matches[1].ToUpperInvariant()
        } elseif ($safeMessage -match '^[A-Z][A-Z0-9_]{2,95}$') {
            $failureId = $safeMessage
        }
        $script:Results.Add([pscustomobject][ordered]@{
            id = $Id
            category = $Category
            status = 'FAIL'
            failure_type = $_.Exception.GetType().Name
            failure_id = $failureId
            failure_sha256 = Get-OfflineStringSha256 -Value $safeMessage
        })
    }
}

function Get-I03HarnessFunctionAst {
    param([Parameter(Mandatory = $true)][string]$Name)

    Assert-I03Offline -Condition ($script:PureFunctionAllowlist -ccontains $Name) `
        -Code 'PURE_FUNCTION_NOT_ALLOWLISTED'
    $matches = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq $Name
    }, $true))
    Assert-I03Offline -Condition ($matches.Count -eq 1) `
        -Code 'PURE_FUNCTION_NOT_UNIQUE'
    Assert-I03AstNoExternalSideEffects -Ast $matches[0] `
        -Code 'PURE_FUNCTION_EXTERNAL_SIDE_EFFECT_FOUND_BEFORE_EXTRACTION'
    [void]$script:ExtractedFunctionNames.Add($Name)
    return $matches[0]
}

function Invoke-I03PureScope {
    param(
        [Parameter(Mandatory = $true)][string[]]$FunctionNames,
        [Parameter(Mandatory = $true)][scriptblock]$Body,
        [object[]]$ArgumentList = @()
    )

    $definitions = @($FunctionNames | ForEach-Object {
        (Get-I03HarnessFunctionAst -Name $_).Extent.Text
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
    } finally {
        $sha.Dispose()
        $stream.Dispose()
    }
}
function Get-LabUtcTimestamp {
    return '2026-01-02T03:04:05.0000000Z'
}
'@
    return & {
        param($HelperText, $DefinitionText, $TestBody, $Arguments)
        . ([scriptblock]::Create($HelperText))
        . ([scriptblock]::Create($DefinitionText))
        & $TestBody @Arguments
    } $safeHelpers $definitions $Body $ArgumentList
}

function Test-I03HarnessStaticNoMutation {
    $commands = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.CommandAst]
    }, $true) | ForEach-Object { $_.GetCommandName() } |
        Where-Object { $_ } | Sort-Object -Unique)
    $forbidden = @(
        'Add-NetRoute', 'Disable-NetAdapter', 'Disable-NetAdapterBinding',
        'Enable-NetAdapter', 'Enable-NetAdapterBinding', 'netsh',
        'New-NetFirewallRule', 'New-NetIPAddress', 'New-NetRoute',
        'Remove-NetFirewallRule', 'Remove-NetIPAddress', 'Remove-NetRoute',
        'Restart-NetAdapter', 'route', 'Set-DnsClientServerAddress',
        'Set-NetAdapter', 'Set-NetFirewallProfile', 'Set-NetFirewallRule',
        'Set-NetIPInterface', 'Set-NetRoute'
    )
    $hits = @($commands | Where-Object { $forbidden -ccontains $_ })
    Assert-I03Offline -Condition ($hits.Count -eq 0) `
        -Code 'PHYSICAL_HARNESS_MUTATION_COMMAND_FOUND'
}

function Assert-I03AstNoExternalSideEffects {
    param(
        [Parameter(Mandatory = $true)]
        [Management.Automation.Language.Ast]$Ast,
        [Parameter(Mandatory = $true)][string]$Code
    )

    $forbiddenCommands = @(
        'Connect-PSSession', 'Disable-NetAdapter',
        'Disable-NetAdapterBinding', 'Enable-NetAdapter',
        'Enable-NetAdapterBinding', 'Enter-PSSession', 'Get-CimInstance',
        'Get-DnsClient', 'Get-DnsClientCache', 'Get-DnsClientServerAddress',
        'Get-NetAdapter', 'Get-NetAdapterBinding', 'Get-NetFirewallAddressFilter',
        'Get-NetFirewallApplicationFilter', 'Get-NetFirewallInterfaceFilter',
        'Get-NetFirewallInterfaceTypeFilter',
        'Get-NetFirewallPortFilter', 'Get-NetFirewallProfile',
        'Get-NetFirewallRule', 'Get-NetFirewallSecurityFilter',
        'Get-NetFirewallServiceFilter',
        'Get-NetIPAddress', 'Get-NetIPConfiguration',
        'Get-NetIPInterface', 'Get-NetRoute', 'Find-NetRoute',
        'Get-NetTCPConnection', 'Get-NetUDPEndpoint',
        'Get-Process', 'Invoke-Command', 'Invoke-Expression',
        'Invoke-RestMethod', 'Invoke-WebRequest', 'New-NetFirewallRule',
        'New-NetIPAddress', 'New-NetRoute', 'New-PSSession', 'netsh',
        'pktmon', 'powershell', 'powershell.exe', 'pwsh', 'pwsh.exe',
        'reg', 'reg.exe', 'Remove-NetFirewallRule', 'Remove-NetIPAddress',
        'Remove-NetRoute', 'Restart-NetAdapter', 'route', 'route.exe',
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
    Assert-I03Offline -Condition (@($commands | Where-Object {
                $forbiddenCommands -ccontains $_
            }).Count -eq 0) -Code $Code
    $forbiddenNewObject = @($Ast.FindAll({
        param($node)
        $node -is [Management.Automation.Language.CommandAst] -and
            $node.GetCommandName() -ceq 'New-Object' -and
            $node.Extent.Text -match
                '(?i)\bNet\.Sockets\.(TcpClient|TcpListener|UdpClient)\b'
    }, $true))
    Assert-I03Offline -Condition ($forbiddenNewObject.Count -eq 0) `
        -Code $Code
    $typeTexts = @($Ast.FindAll({
        param($node)
        $node -is [Management.Automation.Language.TypeExpressionAst]
    }, $true) | ForEach-Object { $_.TypeName.FullName })
    foreach ($pattern in @(
        '^Diagnostics\.Process$', '^Microsoft\.Win32\.Registry',
        '^Net\.Http\.', '^Net\.Sockets\.(TcpClient|TcpListener|UdpClient)$')) {
        Assert-I03Offline -Condition (@($typeTexts | Where-Object {
                    $_ -match $pattern
                }).Count -eq 0) -Code $Code
    }
}

function New-I03OfflineZip {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][object[]]$Entries
    )

    $full = [IO.Path]::GetFullPath($Path)
    Assert-I03Offline -Condition ($full.StartsWith(
        $script:TempRoot.TrimEnd('\') + '\',
        [StringComparison]::OrdinalIgnoreCase)) `
        -Code 'ZIP_FIXTURE_OUTSIDE_TEMP_ROOT'
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $stream = [IO.File]::Open(
        $full, [IO.FileMode]::Create, [IO.FileAccess]::ReadWrite,
        [IO.FileShare]::None)
    $archive = New-Object IO.Compression.ZipArchive(
        $stream, [IO.Compression.ZipArchiveMode]::Create, $false)
    try {
        foreach ($spec in $Entries) {
            $entry = $archive.CreateEntry(
                [string]$spec.name,
                [IO.Compression.CompressionLevel]::NoCompression)
            $entry.LastWriteTime = [DateTimeOffset]::Parse(
                '2026-01-02T03:04:06Z')
            $externalProperty = $spec.PSObject.Properties[
                'external_attributes']
            if ($null -ne $externalProperty) {
                $entry.ExternalAttributes = [int]$externalProperty.Value
            }
            if (-not [string]::IsNullOrEmpty([string]$entry.Name)) {
                $entryStream = $entry.Open()
                try {
                    $bytesProperty = $spec.PSObject.Properties['bytes']
                    [byte[]]$bytes = @()
                    if ($null -ne $bytesProperty) {
                        $bytes = [byte[]]@($bytesProperty.Value)
                    } else {
                        $textProperty = $spec.PSObject.Properties['text']
                        Assert-I03Offline -Condition ($null -ne $textProperty) `
                            -Code 'ZIP_FIXTURE_ENTRY_CONTENT_MISSING'
                        $bytes = [Text.Encoding]::UTF8.GetBytes(
                            [string]$textProperty.Value)
                    }
                    $entryStream.Write($bytes, 0, $bytes.Count)
                } finally { $entryStream.Dispose() }
            }
        }
    } finally {
        $archive.Dispose()
        $stream.Dispose()
    }
    return $full
}

function Get-I03OfflinePackageIdentity {
    param([Parameter(Mandatory = $true)][string]$Path)

    return Invoke-I03PureScope -FunctionNames @(
        'Get-I03PackageManifestSha256', 'Get-I03PackageIdentity') -Body {
        param($fixturePath)
        Get-I03PackageIdentity -PackagePath $fixturePath
    } -ArgumentList @($Path)
}

function Get-I03OfflineZipBinding {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256,
        [Parameter(Mandatory = $true)][object]$Identity
    )

    return Invoke-I03PureScope -FunctionNames @(
        'Get-I03PackageManifestSha256', 'Get-I03ZipPackageBinding') -Body {
        param($zipPath, $sha256, $packageIdentity)
        Get-I03ZipPackageBinding -ZipPath $zipPath `
            -ExpectedZipSha256 $sha256 -PackageIdentity $packageIdentity
    } -ArgumentList @($Path, $ExpectedSha256, $Identity)
}

function Test-I03OfflinePreparedNodeBinding {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][object]$Identity,
        [ValidateSet('Initial', 'Terminal')][string]$Phase,
        [string]$ExpectedPreparedPreferencesSha256 = '',
        [Int64]$ExpectedPreparedPreferencesBytes = -1
    )

    return Invoke-I03PureScope -FunctionNames @(
        'Get-I03PackageManifestSha256',
        'Test-I03PreparedNodeBinding') -Body {
        param(
            $nodePath, $packageIdentity, $bindingPhase,
            $preferencesSha256, $preferencesBytes)
        Test-I03PreparedNodeBinding -NodePath $nodePath `
            -PackageIdentity $packageIdentity -Phase $bindingPhase `
            -ExpectedPreparedPreferencesSha256 $preferencesSha256 `
            -ExpectedPreparedPreferencesBytes $preferencesBytes
    } -ArgumentList @(
        $Path, $Identity, $Phase,
        $ExpectedPreparedPreferencesSha256,
        $ExpectedPreparedPreferencesBytes)
}

function New-I03OfflinePreparedNodeFixture {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$PackagePath
    )

    $node = Join-Path $script:TempRoot $Name
    Assert-I03Offline -Condition (-not (Test-Path -LiteralPath $node)) `
        -Code 'NODE_FIXTURE_ALREADY_EXISTS'
    New-Item -ItemType Directory -Path $node -ErrorAction Stop | Out-Null
    Get-ChildItem -LiteralPath $PackagePath -Force -ErrorAction Stop |
        Copy-Item -Destination $node -Recurse -Force -ErrorAction Stop
    [IO.File]::WriteAllText(
        (Join-Path $node 'LAB_NODE.json'),
        ([pscustomobject][ordered]@{
            schema = 'ese.lab.node/v1'
            launch_performed = $false
        } | ConvertTo-Json -Compress),
        [Text.UTF8Encoding]::new($false))
    return $node
}

function Get-I03OfflinePreparedPreferencesExpectation {
    param([Parameter(Mandatory = $true)][string]$NodePath)

    $path = Join-Path $NodePath 'config\preferences.ini'
    return [pscustomobject][ordered]@{
        sha256 = Get-OfflineFileSha256 -Path $path
        bytes = [Int64](Get-Item -LiteralPath $path `
            -Force -ErrorAction Stop).Length
    }
}

function Assert-I03OfflineThrows {
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Body,
        [Parameter(Mandatory = $true)][string]$ExpectedCode
    )

    $caught = ''
    try { $null = & $Body } catch { $caught = [string]$_.Exception.Message }
    Assert-I03Offline -Condition ($caught.Contains($ExpectedCode)) `
        -Code 'EXPECTED_REJECTION_NOT_OBSERVED'
}

function Copy-I03OfflineObject {
    param([Parameter(Mandatory = $true)][object]$Value)

    return $Value | ConvertTo-Json -Depth 12 -Compress | ConvertFrom-Json
}

function New-I03OfflineApiFixture {
    param([bool]$Ed2kConnected = $false)

    return [pscustomobject][ordered]@{
        upnp_critical_error = $false
        utp_hole_punch_enabled = $false
        web_upnp_active = $false
        upnp_ports_forwarded = 'false'
        kad_connected = $false
        kad_configured_mask = [int]0
        netlab_enabled = $false
        netlab_consent = 'declined'
        netlab_advanced_consent = 'declined'
        netlab_contribution_consent = 'declined'
        kad_running_mask = [int]0
        kad2_running = $false
        kad2_connected = $false
        kad6_running = $false
        kad6_connected = $false
        ed2k_connected = $Ed2kConnected
        keepalive_running = $false
        user_hash = 'raw-user-hash-sentinel'
        token = 'raw-token-sentinel'
        public_ip = '203.0.113.123'
        raw_exception = 'raw-exception-sentinel'
    }
}

function Get-I03OfflineValidPreferencesText {
    return @'
[eMule]
OpenPortsOnStartUp=0
AutoTakeED2KLinks=0
WatchClipboard4ED2kFilelinks=0
AutoStart=0
NetworkKademlia=0
Serverlist=0
AddServersFromServer=0
AddServersFromClient=0
[Connection]
IPv6Mode=1
IPv6BindAddr=2001:4860:4860::10
KadNetworkMask=0
NetworkED2K=0
CryptLayerRequested=0
CryptLayerRequired=0
CryptLayerSupported=0
[eSE]
EseNetLabConsent=1
EseNetLabAdvancedConsent=1
EseNetLabContributionConsent=1
EseNetLabEnabled=0
EseV9Experimental=0
EnableUtpHolePunch=0
EseAutoKeepalive=0
EseKad3Rendezvous=0
EseReachSelector=0
EseHolePunchPortPredict=0
EseEd2kPunch3=0
EseRelayAccept=0
EseRelayEgress=0
Kad6BetaExitOptIn=0
[Proxy]
ProxyEnableProxy=0
[UPnP]
EnableUPnP=0
[WebServer]
Enabled=1
Port=9611
AllowedIPs=127.0.0.1
WebUseUPnP=0
'@
}

function Test-I03OfflinePreferenceFile {
    param([Parameter(Mandatory = $true)][string]$Path)

    return Invoke-I03PureScope -FunctionNames @(
        'Get-I03IniExactValueEvidence', 'Assert-I03PreferenceContract') `
        -Body {
        param($preferencesPath)
        try {
            $null = Assert-I03PreferenceContract `
                -PreferencesPath $preferencesPath -IPv6Mode 1 `
                -IPv6BindAddress '2001:4860:4860::10' `
                -WebPort 9611 -NetworkEd2k 0
            return $true
        } catch { return $false }
    } -ArgumentList @($Path)
}

function Get-I03OfflineObjectSha256 {
    param([AllowNull()][object]$Value)

    return Get-OfflineStringSha256 -Value (
        $Value | ConvertTo-Json -Depth 32 -Compress)
}

function New-I03OfflineRegistryValueState {
    param(
        [bool]$KeyExists,
        [bool]$ValueExists,
        [string]$Kind = '',
        [AllowNull()][object]$Data = $null
    )

    $state = [pscustomobject][ordered]@{
        schema = 'ese.v91.i03-registry-value-state/v1'
        subkey_sha256 = '1' * 64
        value_name_sha256 = '2' * 64
        key_exists = $KeyExists
        value_exists = $ValueExists
        kind = $Kind
        data = $Data
    }
    $state | Add-Member -NotePropertyName state_sha256 `
        -NotePropertyValue (Get-I03OfflineObjectSha256 -Value $state)
    return $state
}

function New-I03OfflineRegistryTreeState {
    param(
        [bool]$Exists,
        [object[]]$Values = @(),
        [object[]]$AdditionalEntries = @()
    )

    $entries = @()
    if ($Exists) {
        $entries = @([pscustomobject][ordered]@{
            relative_path = ''
            values = @($Values)
        }) + @($AdditionalEntries)
    }
    $state = [pscustomobject][ordered]@{
        schema = 'ese.v91.i03-registry-tree-state/v1'
        subkey_sha256 = '3' * 64
        exists = $Exists
        entries = @($entries)
    }
    $state | Add-Member -NotePropertyName state_sha256 `
        -NotePropertyValue (Get-I03OfflineObjectSha256 -Value $state)
    return $state
}

function New-I03OfflineMutationBaseline {
    param(
        [Parameter(Mandatory = $true)][object]$RunKey,
        [string[]]$AllowedAutostartValueSha256 = @(
            (Get-OfflineStringSha256 -Value 'owned-candidate'))
    )

    return [pscustomobject][ordered]@{
        schema = 'ese.v91.i03-mutation-baseline/v2'
        lab_user_sid_sha256 = '4' * 64
        allowed_autostart_value_sha256 = @($AllowedAutostartValueSha256)
        forbidden_state = $null
        autostart = New-I03OfflineRegistryValueState `
            -KeyExists ([bool]$RunKey.exists) -ValueExists $false
        run_key = $RunKey
        ed2k_association = New-I03OfflineRegistryTreeState -Exists $false
    }
}

function Get-I03OfflineRegistryCleanupPlan {
    param(
        [Parameter(Mandatory = $true)][object]$Baseline,
        [Parameter(Mandatory = $true)][object]$CurrentAutostart,
        [Parameter(Mandatory = $true)][object]$CurrentRunKey,
        [Parameter(Mandatory = $true)][object]$CurrentEd2k
    )

    return Invoke-I03PureScope -FunctionNames @(
        'Get-I03ObjectSha256',
        'Get-I03RegistryTreeWithoutValueProjection',
        'Get-I03RegistryCleanupPlan') -Body {
        param($baselineState, $autostartState, $runState, $ed2kState)
        Get-I03RegistryCleanupPlan -Baseline $baselineState `
            -CurrentAutostart $autostartState `
            -CurrentRunKey $runState `
            -CurrentEd2kAssociation $ed2kState
    } -ArgumentList @(
        $Baseline, $CurrentAutostart, $CurrentRunKey, $CurrentEd2k)
}

function New-I03OfflineSystemState {
    param([string]$Seed = 'a')

    return [pscustomobject][ordered]@{
        schema = 'ese.v91.i03-forbidden-state-digests/v1'
        adapters_sha256 = $Seed * 64
        adapter_bindings_sha256 = $Seed * 64
        ip_addresses_sha256 = $Seed * 64
        ip_interfaces_sha256 = $Seed * 64
        routes_sha256 = $Seed * 64
        dns_sha256 = $Seed * 64
        firewall_rules_sha256 = $Seed * 64
        firewall_ports_sha256 = $Seed * 64
        firewall_apps_sha256 = $Seed * 64
        firewall_addresses_sha256 = $Seed * 64
        firewall_interfaces_sha256 = $Seed * 64
        firewall_interface_types_sha256 = $Seed * 64
        firewall_services_sha256 = $Seed * 64
        firewall_security_sha256 = $Seed * 64
        firewall_profiles_sha256 = $Seed * 64
        hosts_sha256 = $Seed * 64
    }
}

function Test-I03OfflineProcessIdentityFixture {
    param(
        [AllowNull()][object]$Expected,
        [AllowNull()][object]$Actual
    )

    return Invoke-I03PureScope `
        -FunctionNames @('Test-I03ProcessIdentityMatch') -Body {
        param($expectedIdentity, $actualIdentity)
        Test-I03ProcessIdentityMatch -Expected $expectedIdentity `
            -Actual $actualIdentity
    } -ArgumentList @($Expected, $Actual)
}

function Get-I03OfflineProcessLineageDecision {
    param(
        [Parameter(Mandatory = $true)][int]$ExpectedProcessId,
        [Parameter(Mandatory = $true)][int]$ExpectedParentProcessId,
        [Parameter(Mandatory = $true)][string]$ParentStartTimeUtc,
        [Parameter(Mandatory = $true)][int]$CimProcessId,
        [Parameter(Mandatory = $true)][int]$CimParentProcessId,
        [Parameter(Mandatory = $true)][string]$CimCreationTimeUtc,
        [Parameter(Mandatory = $true)][object]$Identity
    )

    return Invoke-I03PureScope -FunctionNames @(
        'Test-I03ProcessIdentityMatch',
        'Get-I03ProcessLineageDecision') -Body {
        param(
            $expectedPid, $expectedParentPid, $parentStart,
            $cimPid, $cimParentPid, $cimStart, $processIdentity)
        Get-I03ProcessLineageDecision `
            -ExpectedProcessId $expectedPid `
            -ExpectedParentProcessId $expectedParentPid `
            -ParentStartTimeUtc $parentStart `
            -CimProcessId $cimPid `
            -CimParentProcessId $cimParentPid `
            -CimCreationTimeUtc $cimStart `
            -Identity $processIdentity
    } -ArgumentList @(
        $ExpectedProcessId, $ExpectedParentProcessId,
        $ParentStartTimeUtc, $CimProcessId, $CimParentProcessId,
        $CimCreationTimeUtc, $Identity)
}

function New-I03OfflineProcessIdentity {
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.i03-process-identity/v1'
        process_id = [int]4242
        start_time_utc = '2026-01-02T03:04:05.0000000Z'
        executable_path_sha256 = 'a' * 64
        executable_sha256 = 'b' * 64
    }
}

function Get-I03OfflineClockEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$T0,
        [Parameter(Mandatory = $true)][string]$T0Echo,
        [Parameter(Mandatory = $true)][string]$T1,
        [Parameter(Mandatory = $true)][string]$T2,
        [Parameter(Mandatory = $true)][string]$T3
    )

    return Invoke-I03PureScope -FunctionNames @('Get-I03ClockEvidence') `
        -Body {
        param($a, $b, $c, $d, $e)
        Get-I03ClockEvidence -T0CoordinatorSendUtc $a `
            -T0CoordinatorEchoUtc $b -T1PeerReceiveUtc $c `
            -T2PeerSendUtc $d -T3CoordinatorReceiveUtc $e
    } -ArgumentList @($T0, $T0Echo, $T1, $T2, $T3)
}

function Get-I03OfflineTopologyDecision {
    param(
        [bool]$DifferentMachineIdentities = $true,
        [bool]$SameIPv4PhysicalPrefix = $true,
        [bool]$SameIPv6PhysicalPrefix = $true,
        [bool]$IPv6OnLink = $true,
        [bool]$NativeIPv4 = $true,
        [bool]$NativeIPv6 = $true,
        [bool]$PhysicalSingleAdapter = $true,
        [bool]$OverlayDetected = $false,
        [bool]$RoutedNativeIPv6 = $false
    )

    $context = [pscustomobject]@{
        different = $DifferentMachineIdentities
        same_v4 = $SameIPv4PhysicalPrefix
        same_v6 = $SameIPv6PhysicalPrefix
        on_link = $IPv6OnLink
        native_v4 = $NativeIPv4
        native_v6 = $NativeIPv6
        physical = $PhysicalSingleAdapter
        overlay = $OverlayDetected
        routed = $RoutedNativeIPv6
    }
    return Invoke-I03PureScope `
        -FunctionNames @('Get-I03TopologyDecision') -Body {
        param($value)
        Get-I03TopologyDecision `
            -DifferentMachineIdentities ([bool]$value.different) `
            -SameIPv4PhysicalPrefix ([bool]$value.same_v4) `
            -SameIPv6PhysicalPrefix ([bool]$value.same_v6) `
            -IPv6OnLink ([bool]$value.on_link) `
            -NativeIPv4 ([bool]$value.native_v4) `
            -NativeIPv6 ([bool]$value.native_v6) `
            -PhysicalSingleAdapter ([bool]$value.physical) `
            -OverlayDetected ([bool]$value.overlay) `
            -RoutedNativeIPv6 ([bool]$value.routed)
    } -ArgumentList @($context)
}

function Get-I03OfflineRouteDecision {
    param(
        [ValidateSet('auto', 'preferred')][string]$Policy,
        [bool]$CollectorOk = $true,
        [bool]$FixtureCertified = $true,
        [AllowEmptyCollection()][object[]]$Rows = @(),
        [AllowNull()][AllowEmptyCollection()][object[]]$SocketProofs = @(),
        [double]$StableSeconds = 5,
        [bool]$Contamination = $false,
        [bool]$AmbiguousSelection = $false,
        [bool]$WrongFamilyObserved = $false,
        [double]$RequiredStableSeconds = 5
    )

    $context = [pscustomobject]@{
        policy = $Policy
        collector = $CollectorOk
        fixture = $FixtureCertified
        rows = @($Rows)
        sockets = @($SocketProofs)
        stable = $StableSeconds
        contamination = $Contamination
        ambiguous = $AmbiguousSelection
        wrong_family = $WrongFamilyObserved
        required = $RequiredStableSeconds
    }
    return Invoke-I03PureScope `
        -FunctionNames @('Get-I03RouteSelectionDecision') -Body {
        param($value)
        Get-I03RouteSelectionDecision -Policy ([string]$value.policy) `
            -CollectorOk ([bool]$value.collector) `
            -FixtureCertified ([bool]$value.fixture) `
            -Rows @($value.rows) -SocketProofs @($value.sockets) `
            -StableSeconds ([double]$value.stable) `
            -Contamination ([bool]$value.contamination) `
            -AmbiguousSelection ([bool]$value.ambiguous) `
            -WrongFamilyObserved ([bool]$value.wrong_family) `
            -RequiredStableSeconds ([double]$value.required)
    } -ArgumentList @($context)
}

function Get-I03OfflineHelloEvidenceDecision {
    param([AllowNull()][object]$Evidence)

    return Invoke-I03PureScope `
        -FunctionNames @('Get-I03HelloEvidenceDecision') -Body {
        param($value)
        Get-I03HelloEvidenceDecision -Evidence $value
    } -ArgumentList @($Evidence)
}

function New-I03OfflineSocketProof {
    return [pscustomobject][ordered]@{
        collector_ok = $true
        pid_matches = $true
        tuple_current_exact = $true
        local_address_assigned = $true
        physical_nonvirtual = $true
        attribution_exact = $true
    }
}

function New-I03OfflineSocketCensus {
    param(
        [int]$ProcessId = 4242,
        [bool]$CollectorOk = $true,
        [object[]]$TcpRows = @(),
        [object[]]$UdpRows = @()
    )

    return [pscustomobject][ordered]@{
        schema = 'ese.v91.i03-process-socket-census/v1'
        collector_ok = $CollectorOk
        collector_error_code = if ($CollectorOk) {
            'NONE'
        } else { 'PROCESS_SOCKET_QUERY_FAILED' }
        process_id = $ProcessId
        tcp_rows = @($TcpRows)
        udp_rows = @($UdpRows)
        socket_count = @($TcpRows).Count + @($UdpRows).Count
    }
}

function Get-I03OfflineSocketCensusDecision {
    param(
        [Parameter(Mandatory = $true)][object]$Census,
        [int]$ProcessId = 4242
    )

    return Invoke-I03PureScope -FunctionNames @(
        'Test-I03StrictJsonInteger',
        'Get-I03NormalizedIp',
        'Get-I03CandidateSocketCensusDecision') -Body {
        param($value, $pidValue)
        Get-I03CandidateSocketCensusDecision -Census $value `
            -ProcessId $pidValue -TcpPort 4662 -UdpPort 4672 `
            -WebPort 4711 `
            -TargetAddresses @('198.51.100.10', '2001:4860::20') `
            -TargetPort 4662 -ControlAddress '198.51.100.5' `
            -ControlPort 5000
    } -ArgumentList @($Census, $ProcessId)
}

function New-I03OfflineEd2kFrame {
    param(
        [Parameter(Mandatory = $true)][byte]$Opcode,
        [AllowEmptyCollection()][byte[]]$Payload = @()
    )

    $arguments = [object[]]::new(2)
    $arguments[0] = $Opcode
    $arguments[1] = [byte[]]$Payload
    return Invoke-I03PureScope -FunctionNames @('New-I03Ed2kFrame') `
        -Body {
        param($opcodeValue, $payloadValue)
        New-I03Ed2kFrame -Opcode $opcodeValue -Payload $payloadValue
    } -ArgumentList $arguments
}

function New-I03OfflineEd2kIdChangeFrame {
    param([uint32]$ClientId = [uint32]0x01000001)

    return Invoke-I03PureScope -FunctionNames @(
        'New-I03Ed2kFrame', 'New-I03Ed2kIdChangeFrame') -Body {
        param($clientIdValue)
        New-I03Ed2kIdChangeFrame -ClientId $clientIdValue
    } -ArgumentList @($ClientId)
}

function Test-I03OfflineEd2kLoginRequestFrame {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()][byte[]]$Frame
    )

    $arguments = [object[]]::new(1)
    $arguments[0] = [byte[]]$Frame
    return Invoke-I03PureScope `
        -FunctionNames @('Test-I03Ed2kLoginRequestFrame') -Body {
        param($frameValue)
        Test-I03Ed2kLoginRequestFrame -Frame $frameValue
    } -ArgumentList $arguments
}

function Test-I03OfflinePublicEvidenceObject {
    param([Parameter(Mandatory = $true)][object]$Value)

    return Invoke-I03PureScope -FunctionNames @(
        'Test-I03PublicEvidenceText',
        'Test-I03PublicEvidenceObject') -Body {
        param($publicValue)
        Test-I03PublicEvidenceObject -Value $publicValue
    } -ArgumentList @($Value)
}

function Test-I03OfflinePublicEvidenceText {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()][string]$Text
    )

    return Invoke-I03PureScope `
        -FunctionNames @('Test-I03PublicEvidenceText') -Body {
        param($publicText)
        Test-I03PublicEvidenceText -Text $publicText
    } -ArgumentList @($Text)
}

function New-I03OfflinePublicCoordinatorSummary {
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.i03-public-summary/v1'
        case_id = 'V91-I03'
        formal_status = 'BLOCKED'
        candidate = [pscustomobject][ordered]@{
            commit = 'a' * 40
            emule_sha256 = 'b' * 64
            zip_sha256 = 'c' * 64
            package_manifest_sha256 = 'd' * 64
            package_unchanged = $true
        }
        topology = [pscustomobject][ordered]@{
            class = ''
            proved = $false
            t1_proved = $false
            t2_proved = $false
        }
        policies = @(
            [pscustomobject][ordered]@{
                policy = 'auto'; ipv6_mode = [int]1
                expected_family = 'IPv4'; fixture_valid = $false
                product_match = $false
            },
            [pscustomobject][ordered]@{
                policy = 'preferred'; ipv6_mode = [int]2
                expected_family = 'IPv6'; fixture_valid = $false
                product_match = $false
            }
        )
        adjudication = [pscustomobject][ordered]@{
            formal_status = 'BLOCKED'
            proven_product_failure_count = [int]0
            untrusted_product_failure_count = [int]0
            lab_incident_count = [int]1
            malformed_or_stale_failure_count = [int]0
        }
        failures = @([pscustomobject][ordered]@{
            role = 'Coordinator'; policy = 'none'; phase = 'preflight'
            status = 'LAB_BLOCKED'; category = 'LAB_CLOCK'; code = 'CLOCK'
            fixture_certified = $false; cleanup_complete = $false
            cleanup_incident_codes = @()
        })
        cleanup = [pscustomobject][ordered]@{
            complete = $false
            candidate_package_unchanged = $true
            package_manifest_unchanged = $true
            package_zip_binding_unchanged = $true
            process_cleanup_complete = $true
            peer_cleanup_complete = $false
            registry_and_system_state_exact = $true
        }
        retention = [pscustomobject][ordered]@{
            private_artifacts_retained = $true
            private_file_count = [int]4
            private_total_bytes = [Int64]4096
            private_artifact_manifest_sha256 = 'e' * 64
            public_allowlist = @('summary.json', 'evidence-manifest.json')
        }
    }
}

function New-I03OfflinePublicPeerSummary {
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.i03-peer-public-summary/v1'
        case_id = 'V91-I03'
        role = 'Peer'
        status = 'LAB_BLOCKED'
        candidate = [pscustomobject][ordered]@{
            commit = 'a' * 40
            emule_sha256 = 'b' * 64
            zip_sha256 = 'c' * 64
            package_unchanged = $true
        }
        barriers_completed = [int]0
        expected_barriers = [int]2
        failures = @([pscustomobject][ordered]@{
            policy = 'none'; phase = 'preflight'; status = 'LAB_BLOCKED'
            category = 'LAB_CLOCK'; code = 'CLOCK'
            fixture_certified = $false; cleanup_complete = $false
        })
        cleanup = [pscustomobject][ordered]@{
            complete = $false
            source_process_stopped = $true
            candidate_package_unchanged = $true
            registry_and_system_state_exact = $true
        }
        retention = [pscustomobject][ordered]@{
            private_artifacts_retained = $true
            coordination_private_artifacts_retained = $true
            private_file_count = [int]4
            private_artifact_manifest_sha256 = 'e' * 64
        }
    }
}

function New-I03OfflinePublicCoordinatorPass {
    $value = New-I03OfflinePublicCoordinatorSummary
    $value.formal_status = 'PASS'
    $value.topology.class = 'T1'
    $value.topology.proved = $true
    $value.topology.t1_proved = $true
    $value.topology.t2_proved = $false
    foreach ($policy in @($value.policies)) {
        $policy.fixture_valid = $true
        $policy.product_match = $true
    }
    $value.adjudication.formal_status = 'PASS'
    $value.adjudication.proven_product_failure_count = [int]0
    $value.adjudication.untrusted_product_failure_count = [int]0
    $value.adjudication.lab_incident_count = [int]0
    $value.adjudication.malformed_or_stale_failure_count = [int]0
    $value.failures = [object[]]@()
    foreach ($property in $value.cleanup.PSObject.Properties) {
        $property.Value = $true
    }
    return $value
}

function New-I03OfflinePublicCoordinatorFail {
    $value = New-I03OfflinePublicCoordinatorSummary
    $value.formal_status = 'FAIL'
    $value.adjudication.formal_status = 'FAIL'
    $value.adjudication.proven_product_failure_count = [int]1
    $value.adjudication.lab_incident_count = [int]0
    $value.policies = [object[]]@($value.policies[0])
    $value.policies[0].fixture_valid = $true
    $value.failures = [object[]]@([pscustomobject][ordered]@{
        role = 'Coordinator'
        policy = 'auto'
        phase = 'post_restart_route'
        status = 'PRODUCT_INVARIANT'
        category = 'PRODUCT_ROUTE'
        code = 'WRONG_FAMILY'
        fixture_certified = $true
        cleanup_complete = $false
        cleanup_incident_codes = @()
    })
    return $value
}

function New-I03OfflinePublicPeerComplete {
    $value = New-I03OfflinePublicPeerSummary
    $value.status = 'COMPLETE'
    $value.barriers_completed = [int]2
    $value.failures = [object[]]@()
    foreach ($property in $value.cleanup.PSObject.Properties) {
        $property.Value = $true
    }
    return $value
}

function New-I03OfflinePublicManifest {
    param([switch]$Peer)

    $value = [ordered]@{
        schema = 'ese.v91.i03-public-evidence-manifest/v1'
        case_id = 'V91-I03'
    }
    if ($Peer) { $value['role'] = 'Peer' }
    $value['files'] = @([pscustomobject][ordered]@{
        name = 'summary.json'; bytes = [Int64]1024; sha256 = 'f' * 64
    })
    $value['private_artifacts_retained'] = $true
    $value['private_artifact_manifest_sha256'] = 'e' * 64
    $value['public_scan_passed'] = $true
    return [pscustomobject]$value
}

function Assert-I03OfflinePrivateRoot {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [Parameter(Mandatory = $true)][string]$CandidatePackageRoot
    )

    return Invoke-I03PureScope -FunctionNames @(
        'Test-I03PathContainedBy', 'Assert-I03PrivateRoot') -Body {
        param($valuePath, $valueLabel, $repoRoot, $packageRoot)
        Assert-I03PrivateRoot -Path $valuePath -Label $valueLabel `
            -RepositoryRoot $repoRoot `
            -CandidatePackageRoot $packageRoot
    } -ArgumentList @(
        $Path, $Label, $RepositoryRoot, $CandidatePackageRoot)
}

function New-I03OfflineFailureFixture {
    param(
        [ValidateSet('LAB_BLOCKED', 'PRODUCT_INVARIANT')]
        [string]$Status = 'PRODUCT_INVARIANT',
        [string]$Category = 'PRODUCT_ROUTE',
        [string]$Code = 'WRONG_FAMILY',
        [ValidateSet('Coordinator', 'Peer')][string]$Role = 'Coordinator',
        [ValidateSet('none', 'auto', 'preferred')]
        [string]$Policy = 'auto',
        [bool]$FixtureCertified = $true,
        [string]$Phase = 'post_restart_route'
    )

    return Invoke-I03PureScope -FunctionNames @(
        'Test-I03FailurePhase', 'New-I03ProofProjection',
        'New-I03FailureRecord') -Body {
        param(
            $fixtureStatus, $fixtureCategory, $fixtureCode,
            $fixtureRole, $fixturePolicy, $certified, $fixturePhase)
        $proofs = @()
        if ($fixtureStatus -ceq 'PRODUCT_INVARIANT') {
            $proofs = @(New-I03ProofProjection `
                -Kind (([string]$fixtureCode).ToLowerInvariant()) `
                -CaseId 'V91-I03' `
                -RunNonce ('1' * 32) -Role $fixtureRole `
                -Policy $fixturePolicy -Phase $fixturePhase `
                -SourceEvidenceSha256 ('5' * 64))
        }
        New-I03FailureRecord -CaseId 'V91-I03' `
            -RunNonce ('1' * 32) -Role $fixtureRole `
            -Policy $fixturePolicy -Phase $fixturePhase `
            -Status $fixtureStatus -Category $fixtureCategory `
            -Code $fixtureCode -Message 'private failure detail' `
            -CandidateCommit ('a' * 40) `
            -CandidateEmuleSha256 ('b' * 64) `
            -CandidateZipSha256 ('c' * 64) `
            -PackageManifestSha256 ('d' * 64) `
            -FixtureCertified $certified -Proofs $proofs
    } -ArgumentList @(
        $Status, $Category, $Code, $Role, $Policy, $FixtureCertified, $Phase)
}

function Test-I03OfflineFailureFixture {
    param(
        [AllowNull()][object]$Record,
        [string]$ExpectedRole = 'Coordinator',
        [string]$ExpectedPolicy = 'auto'
    )

    return Invoke-I03PureScope -FunctionNames @(
        'Test-I03FailurePhase', 'Test-I03FailureRecord') -Body {
        param($value, $role, $policy)
        $arguments = @{
            Record = $value
            ExpectedCaseId = 'V91-I03'
            ExpectedRunNonce = ('1' * 32)
            ExpectedRole = $role
            ExpectedPolicy = $policy
            ExpectedCommit = ('a' * 40)
            ExpectedEmuleSha256 = ('b' * 64)
            ExpectedZipSha256 = ('c' * 64)
            ExpectedManifestSha256 = ('d' * 64)
        }
        $command = Get-Command Test-I03FailureRecord
        foreach ($parameterName in @($command.Parameters.Keys | Where-Object {
                    $_ -match '^Expected.*Proof.*Sha256'
                })) {
            $arguments[$parameterName] = @('5' * 64)
        }
        Test-I03FailureRecord @arguments
    } -ArgumentList @($Record, $ExpectedRole, $ExpectedPolicy)
}

function Get-I03OfflineAdjudication {
    param(
        [object[]]$FailureRecords = @(),
        [string[]]$AllowedRolePolicyTuples = @(
            'Coordinator|none', 'Coordinator|auto',
            'Coordinator|preferred', 'Peer|none', 'Peer|auto',
            'Peer|preferred'),
        [string[]]$TrustedProofBindings = @('0' * 64),
        [bool]$FixtureComplete = $false,
        [bool]$BothPoliciesPass = $false,
        [bool]$EvidenceComplete = $false,
        [bool]$CleanupComplete = $false
    )

    $context = [pscustomobject]@{
        records = @($FailureRecords)
        allowed_tuples = @($AllowedRolePolicyTuples)
        trusted_bindings = @($TrustedProofBindings)
        fixture = $FixtureComplete
        policies = $BothPoliciesPass
        evidence = $EvidenceComplete
        cleanup = $CleanupComplete
    }
    return Invoke-I03PureScope -FunctionNames @(
        'Test-I03FailurePhase', 'Test-I03FailureRecord',
        'Get-I03FormalAdjudication') -Body {
        param($value)
        $arguments = @{
            FailureRecords = @($value.records)
            AllowedRolePolicyTuples = @($value.allowed_tuples)
            TrustedProofBindings = @($value.trusted_bindings)
            FixtureComplete = [bool]$value.fixture
            BothPoliciesPass = [bool]$value.policies
            EvidenceComplete = [bool]$value.evidence
            CleanupComplete = [bool]$value.cleanup
            ExpectedCaseId = 'V91-I03'
            ExpectedRunNonce = ('1' * 32)
            ExpectedCommit = ('a' * 40)
            ExpectedEmuleSha256 = ('b' * 64)
            ExpectedZipSha256 = ('c' * 64)
            ExpectedManifestSha256 = ('d' * 64)
        }
        Get-I03FormalAdjudication @arguments
    } -ArgumentList @($context)
}

$script:SelfPreflightTokens = $null
$script:SelfPreflightErrors = $null
$script:SelfPreflightAst =
    [Management.Automation.Language.Parser]::ParseFile(
        $script:SelfPath,
        [ref]$script:SelfPreflightTokens,
        [ref]$script:SelfPreflightErrors)
Assert-I03Offline -Condition ($script:SelfPreflightErrors.Count -eq 0) `
    -Code 'OFFLINE_SELF_PREFLIGHT_PARSER_ERROR'
Assert-I03AstNoExternalSideEffects -Ast $script:SelfPreflightAst `
    -Code 'OFFLINE_SELF_PREFLIGHT_EXTERNAL_SIDE_EFFECT_FOUND'

New-Item -ItemType Directory -Path $script:TempRoot -ErrorAction Stop |
    Out-Null
try {

Invoke-I03OfflineTest -Id 'AST-HARNESS-PARSER' -Category 'parser' -Body {
    Assert-I03Offline -Condition ($script:HarnessParserErrors.Count -eq 0) `
        -Code 'HARNESS_PARSER_ERROR'
}

Invoke-I03OfflineTest -Id 'AST-REQUIRED-PARAMETERS' -Category 'parser' -Body {
    $paramNames = @($script:HarnessAst.ParamBlock.Parameters | ForEach-Object {
        $_.Name.VariablePath.UserPath
    })
    foreach ($required in @(
        'PackagePath', 'CandidateZipPath', 'ExpectedCandidateZipSha256',
        'OutputRoot', 'Commit', 'ExpectedEmuleSha256', 'PeerIPv4',
        'PeerLocalIPv4', 'PeerIPv6', 'CoordinationRoot',
        'ControlledPeerAcknowledged', 'DisposableLabAccountAcknowledged',
        'ExpectedLabUserSidSha256')) {
        Assert-I03Offline -Condition ($paramNames -ccontains $required) `
            -Code 'REQUIRED_PARAMETER_MISSING'
    }
}

Invoke-I03OfflineTest -Id 'AST-NO-PHYSICAL-MUTATION' `
    -Category 'side_effect_guard' -Body {
    Test-I03HarnessStaticNoMutation
}

Invoke-I03OfflineTest -Id 'AST-SIDE-EFFECT-GUARD-SELFTEST' `
    -Category 'side_effect_guard' -Body {
    $tokens = $null
    $errors = $null
    $safeAst = [Management.Automation.Language.Parser]::ParseInput(
        'param([string]$Value) return $Value.ToLowerInvariant()',
        [ref]$tokens, [ref]$errors)
    Assert-I03Offline -Condition ($errors.Count -eq 0) `
        -Code 'SIDE_EFFECT_GUARD_SAFE_FIXTURE_PARSE_ERROR'
    Assert-I03AstNoExternalSideEffects -Ast $safeAst `
        -Code 'SIDE_EFFECT_GUARD_SAFE_FIXTURE_REJECTED'
    foreach ($unsafeText in @(
        'Start-Process -FilePath calc.exe',
        'Get-NetIPInterface -ErrorAction Stop',
        'Find-NetRoute -RemoteIPAddress 198.51.100.1',
        'New-Object Net.Sockets.TcpClient',
        'New-Object -TypeName Net.Sockets.UdpClient',
        '[Microsoft.Win32.Registry]::CurrentUser')) {
        $unsafeTokens = $null
        $unsafeErrors = $null
        $unsafeAst = [Management.Automation.Language.Parser]::ParseInput(
            $unsafeText, [ref]$unsafeTokens, [ref]$unsafeErrors)
        Assert-I03OfflineThrows -ExpectedCode 'GUARD_EXPECTED_REJECTION' `
            -Body {
            Assert-I03AstNoExternalSideEffects -Ast $unsafeAst `
                -Code 'GUARD_EXPECTED_REJECTION'
        }
    }
}

Invoke-I03OfflineTest -Id 'AST-OFFLINE-DOES-NOT-INVOKE-HARNESS' `
    -Category 'side_effect_guard' -Body {
    $selfErrors = $null
    $selfTokens = $null
    $selfAst = [Management.Automation.Language.Parser]::ParseFile(
        $script:SelfPath, [ref]$selfTokens, [ref]$selfErrors)
    Assert-I03Offline -Condition ($selfErrors.Count -eq 0) `
        -Code 'OFFLINE_SELF_PARSER_ERROR'
    $commands = @($selfAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.CommandAst]
    }, $true))
    foreach ($command in $commands) {
        $text = $command.Extent.Text
        $name = [string]$command.GetCommandName()
        Assert-I03Offline -Condition ($name -notin @(
            'Invoke-Expression', 'Start-Process', 'powershell',
            'powershell.exe', 'pwsh', 'pwsh.exe')) `
            -Code 'OFFLINE_DYNAMIC_OR_CHILD_EXECUTION'
        if ($command.InvocationOperator -ne
            [Management.Automation.Language.TokenKind]::Unknown) {
            Assert-I03Offline -Condition (
                -not $text.Contains('$HarnessPath') -and
                -not $text.Contains('$script:HarnessPath')) `
                -Code 'OFFLINE_HARNESS_INVOCATION_OPERATOR'
        }
    }
    Assert-I03Offline -Condition (
        $script:HarnessText -cnotmatch '(?im)^\s*param\s*\(\s*\)\s*$') `
        -Code 'HARNESS_PARAM_CONTRACT_COLLAPSED'
}

Invoke-I03OfflineTest -Id 'PRIVATE-ROOT-CONTAINMENT-BOUNDARIES' `
    -Category 'privacy_contract' -Body {
    $root = Join-Path $script:TempRoot 'root-boundary'
    $cases = @(
        [pscustomobject]@{ path = $root; root = $root; expected = $true },
        [pscustomobject]@{
            path = Join-Path $root 'child'; root = $root; expected = $true
        },
        [pscustomobject]@{
            path = $root.ToUpperInvariant()
            root = $root.ToLowerInvariant()
            expected = $true
        },
        [pscustomobject]@{
            path = $root + '-sibling'; root = $root; expected = $false
        }
    )
    foreach ($case in $cases) {
        $actual = Invoke-I03PureScope `
            -FunctionNames @('Test-I03PathContainedBy') -Body {
            param($child, $parent)
            Test-I03PathContainedBy -Path $child -Root $parent
        } -ArgumentList @([string]$case.path, [string]$case.root)
        Assert-I03Offline -Condition (
            [bool]$actual -eq [bool]$case.expected) `
            -Code 'PRIVATE_ROOT_CONTAINMENT_BOUNDARY_WRONG'
    }
}

Invoke-I03OfflineTest -Id 'PRIVATE-ROOT-VALID-TEMP-POSITIVE' `
    -Category 'privacy_contract' -Body {
    $repo = Join-Path $script:TempRoot 'private-root-repo'
    $package = Join-Path $script:TempRoot 'private-root-package'
    $private = Join-Path $script:TempRoot 'private-root-output'
    New-Item -ItemType Directory -Path $repo, $package -Force | Out-Null
    $value = Assert-I03OfflinePrivateRoot -Path $private -Label OUTPUT `
        -RepositoryRoot $repo -CandidatePackageRoot $package
    Assert-I03OfflineEqual -Actual $value `
        -Expected ([IO.Path]::GetFullPath($private)) `
        -Code 'VALID_PRIVATE_ROOT_REJECTED'
}

Invoke-I03OfflineTest -Id 'PRIVATE-ROOT-REPO-REJECTED' `
    -Category 'privacy_contract' -Body {
    $repo = Join-Path $script:TempRoot 'repo-reject'
    $package = Join-Path $script:TempRoot 'package-reject'
    New-Item -ItemType Directory -Path $repo, $package -Force | Out-Null
    Assert-I03OfflineThrows `
        -ExpectedCode 'I03_PRIVATE_ROOT::OUTPUT_INSIDE_REPOSITORY' -Body {
        Assert-I03OfflinePrivateRoot -Path (Join-Path $repo 'out') `
            -Label OUTPUT -RepositoryRoot $repo `
            -CandidatePackageRoot $package
    }
}

Invoke-I03OfflineTest -Id 'PRIVATE-ROOT-PACKAGE-REJECTED' `
    -Category 'privacy_contract' -Body {
    $repo = Join-Path $script:TempRoot 'repo-package-case'
    $package = Join-Path $script:TempRoot 'candidate-package-case'
    New-Item -ItemType Directory -Path $repo, $package -Force | Out-Null
    Assert-I03OfflineThrows `
        -ExpectedCode 'I03_PRIVATE_ROOT::OUTPUT_INSIDE_PACKAGE' -Body {
        Assert-I03OfflinePrivateRoot -Path (Join-Path $package 'out') `
            -Label OUTPUT -RepositoryRoot $repo `
            -CandidatePackageRoot $package
    }
}

Invoke-I03OfflineTest -Id 'PRIVATE-ROOT-REPARSE-ANCESTOR-REJECTED' `
    -Category 'privacy_contract' -Body {
    $repo = Join-Path $script:TempRoot 'repo-reparse-case'
    $package = Join-Path $script:TempRoot 'package-reparse-case'
    $target = Join-Path $script:TempRoot 'junction-target-root'
    $link = Join-Path $script:TempRoot 'junction-private-root'
    New-Item -ItemType Directory -Path $repo, $package, $target `
        -Force | Out-Null
    New-Item -ItemType Junction -Path $link -Target $target `
        -ErrorAction Stop | Out-Null
    try {
        Assert-I03OfflineThrows `
            -ExpectedCode 'I03_PRIVATE_ROOT::OUTPUT_REPARSE_ANCESTOR' `
            -Body {
            Assert-I03OfflinePrivateRoot -Path (Join-Path $link 'child') `
                -Label OUTPUT -RepositoryRoot $repo `
                -CandidatePackageRoot $package
        }
    } finally {
        if (Test-Path -LiteralPath $link) {
            [IO.Directory]::Delete($link)
        }
    }
}

Invoke-I03OfflineTest -Id 'PRIVATE-ROOT-BOTH-ROLES-BEFORE-WRITE' `
    -Category 'privacy_contract' -Body {
    foreach ($role in @('Invoke-I03PeerRole', 'Invoke-I03CoordinatorRole')) {
        $text = @($script:HarnessAst.FindAll({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] `
                -and $node.Name -ceq $role
        }, $true))[0].Extent.Text
        $outputGuard = $text.IndexOf(
            'Assert-I03PrivateRoot -Path $OutputRoot')
        $coordinationGuard = $text.IndexOf(
            '-Path $CoordinationRoot -Label')
        $overlapGuard = $text.IndexOf(
            'I03_PRIVATE_ROOT::OUTPUT_COORDINATION_OVERLAP')
        $firstDirectoryWrite = $text.IndexOf('New-LabDirectory')
        Assert-I03Offline -Condition (
            $outputGuard -ge 0 -and $coordinationGuard -ge 0 -and
            $overlapGuard -ge 0 -and $firstDirectoryWrite -ge 0 -and
            $outputGuard -lt $firstDirectoryWrite -and
            $coordinationGuard -lt $firstDirectoryWrite -and
            $overlapGuard -lt $firstDirectoryWrite) `
            -Code 'PRIVATE_ROOT_GUARD_AFTER_FIRST_WRITE_OR_MISSING'
    }
}

Invoke-I03OfflineTest -Id 'PRIVACY-PUBLIC-ALLOWLIST-POSITIVES' `
    -Category 'privacy_contract' -Body {
    foreach ($value in @(
        (New-I03OfflinePublicCoordinatorSummary),
        (New-I03OfflinePublicCoordinatorPass),
        (New-I03OfflinePublicPeerSummary),
        (New-I03OfflinePublicPeerComplete),
        (New-I03OfflinePublicManifest),
        (New-I03OfflinePublicManifest -Peer))) {
        Assert-I03Offline -Condition ([bool](
            Test-I03OfflinePublicEvidenceObject -Value $value)) `
            -Code 'SAFE_PUBLIC_ALLOWLIST_OBJECT_REJECTED'
        $roundTrip = $value | ConvertTo-Json -Depth 32 -Compress |
            ConvertFrom-Json -ErrorAction Stop
        Assert-I03Offline -Condition ([bool](
            Test-I03OfflinePublicEvidenceObject -Value $roundTrip)) `
            -Code 'SAFE_PUBLIC_JSON_ROUNDTRIP_REJECTED'
    }
}

Invoke-I03OfflineTest -Id 'PRIVACY-PUBLIC-EARLY-VERDICT-POSITIVES' `
    -Category 'privacy_contract' -Body {
    $blocked = New-I03OfflinePublicCoordinatorSummary
    $blocked.policies = [object[]]@()
    $failed = New-I03OfflinePublicCoordinatorFail
    foreach ($value in @($blocked, $failed)) {
        Assert-I03Offline -Condition ([bool](
            Test-I03OfflinePublicEvidenceObject -Value $value)) `
            -Code 'EARLY_PUBLIC_VERDICT_OBJECT_REJECTED'
        $roundTrip = $value | ConvertTo-Json -Depth 32 -Compress |
            ConvertFrom-Json -ErrorAction Stop
        Assert-I03Offline -Condition ([bool](
            Test-I03OfflinePublicEvidenceObject -Value $roundTrip)) `
            -Code 'EARLY_PUBLIC_VERDICT_ROUNDTRIP_REJECTED'
    }
}

$publicSmugglingCases = @(
    [pscustomobject]@{
        id = 'EXTRA-FIELD'; kind = 'coordinator'
        mutate = {
            param($value)
            $value | Add-Member -NotePropertyName notes `
                -NotePropertyValue 'apparently-safe'
        }
    },
    [pscustomobject]@{
        id = 'NESTED-EXTRA-FIELD'; kind = 'coordinator'
        mutate = {
            param($value)
            $value.candidate | Add-Member -NotePropertyName notes `
                -NotePropertyValue 'apparently-safe'
        }
    },
    [pscustomobject]@{
        id = 'FAILURE-CODE-SECRET'; kind = 'coordinator'
        mutate = { param($value) $value.failures[0].code = 'raw-secret-sentinel' }
    },
    [pscustomobject]@{
        id = 'FAILURE-PHASE-UNKNOWN'; kind = 'coordinator'
        mutate = { param($value) $value.failures[0].phase = 'unknown_phase' }
    },
    [pscustomobject]@{
        id = 'CLEANUP-INCIDENT-UNKNOWN'; kind = 'coordinator'
        mutate = {
            param($value)
            $value.failures[0].cleanup_incident_codes = @('NOT_A_CODE')
        }
    },
    [pscustomobject]@{
        id = 'CLEANUP-INCIDENT-NONSTRING'; kind = 'coordinator'
        mutate = {
            param($value)
            $value.failures[0].cleanup_incident_codes = @([int]7)
        }
    },
    [pscustomobject]@{
        id = 'ADJUDICATION-COUNT-STRING'; kind = 'coordinator'
        mutate = {
            param($value)
            $value.adjudication.proven_product_failure_count = 'secret'
        }
    },
    [pscustomobject]@{
        id = 'CLEANUP-BOOL-STRING'; kind = 'coordinator'
        mutate = { param($value) $value.cleanup.complete = 'false' }
    },
    [pscustomobject]@{
        id = 'RETENTION-COUNT-STRING'; kind = 'coordinator'
        mutate = { param($value) $value.retention.private_file_count = 'secret' }
    },
    [pscustomobject]@{
        id = 'PEER-BARRIER-STRING'; kind = 'peer'
        mutate = { param($value) $value.barriers_completed = 'secret' }
    },
    [pscustomobject]@{
        id = 'PEER-FAILURE-CATEGORY-SECRET'; kind = 'peer'
        mutate = {
            param($value)
            $value.failures[0].category = 'raw-secret-sentinel'
        }
    },
    [pscustomobject]@{
        id = 'PEER-FAILURE-PHASE-UNKNOWN'; kind = 'peer'
        mutate = { param($value) $value.failures[0].phase = 'unknown_phase' }
    },
    [pscustomobject]@{
        id = 'POLICY-DUPLICATE'; kind = 'coordinator'
        mutate = {
            param($value)
            $value.policies[1].policy = 'auto'
        }
    },
    [pscustomobject]@{
        id = 'PASS-MISSING-PREFERRED'; kind = 'pass'
        mutate = {
            param($value)
            $value.policies = [object[]]@($value.policies[0])
        }
    },
    [pscustomobject]@{
        id = 'PASS-TOPOLOGY-NOT-PROVED'; kind = 'pass'
        mutate = { param($value) $value.topology.proved = $false }
    },
    [pscustomobject]@{
        id = 'PASS-TOPOLOGY-FLAGS-INCOHERENT'; kind = 'pass'
        mutate = { param($value) $value.topology.t2_proved = $true }
    },
    [pscustomobject]@{
        id = 'PASS-CANDIDATE-CHANGED'; kind = 'pass'
        mutate = { param($value) $value.candidate.package_unchanged = $false }
    },
    [pscustomobject]@{
        id = 'PASS-CLEANUP-INCOMPLETE'; kind = 'pass'
        mutate = { param($value) $value.cleanup.complete = $false }
    },
    [pscustomobject]@{
        id = 'PASS-POLICY-NOT-MATCH'; kind = 'pass'
        mutate = { param($value) $value.policies[0].product_match = $false }
    },
    [pscustomobject]@{
        id = 'PASS-FAILURE-PRESENT'; kind = 'pass'
        mutate = {
            param($value)
            $value.failures = [object[]]@(
                (New-I03OfflinePublicCoordinatorSummary).failures[0])
        }
    },
    [pscustomobject]@{
        id = 'PASS-INCIDENT-COUNT'; kind = 'pass'
        mutate = { param($value) $value.adjudication.lab_incident_count = 1 }
    },
    [pscustomobject]@{
        id = 'FAIL-ZERO-PROVEN'; kind = 'fail'
        mutate = {
            param($value)
            $value.adjudication.proven_product_failure_count = [int]0
        }
    },
    [pscustomobject]@{
        id = 'FAIL-NO-PRODUCT-FAILURE'; kind = 'fail'
        mutate = {
            param($value)
            $value.failures[0].policy = 'none'
            $value.failures[0].status = 'LAB_BLOCKED'
            $value.failures[0].category = 'LAB_CLOCK'
            $value.failures[0].code = 'CLOCK'
            $value.failures[0].fixture_certified = $false
        }
    },
    [pscustomobject]@{
        id = 'BLOCKED-PROVEN-NONZERO'; kind = 'coordinator'
        mutate = {
            param($value)
            $value.adjudication.proven_product_failure_count = [int]1
        }
    },
    [pscustomobject]@{
        id = 'BLOCKED-WITH-NO-INCOMPLETENESS'; kind = 'pass'
        mutate = {
            param($value)
            $value.formal_status = 'BLOCKED'
            $value.adjudication.formal_status = 'BLOCKED'
        }
    },
    [pscustomobject]@{
        id = 'PEER-COMPLETE-CLEANUP-FALSE'; kind = 'peer_complete'
        mutate = { param($value) $value.cleanup.complete = $false }
    },
    [pscustomobject]@{
        id = 'PEER-COMPLETE-CANDIDATE-FALSE'; kind = 'peer_complete'
        mutate = { param($value) $value.candidate.package_unchanged = $false }
    },
    [pscustomobject]@{
        id = 'PEER-COMPLETE-WITH-FAILURE'; kind = 'peer_complete'
        mutate = {
            param($value)
            $value.failures = [object[]]@(
                (New-I03OfflinePublicPeerSummary).failures[0])
        }
    },
    [pscustomobject]@{
        id = 'PEER-PRODUCT-STATUS-WITH-LAB-FAILURE'; kind = 'peer'
        mutate = { param($value) $value.status = 'PRODUCT_INVARIANT' }
    },
    [pscustomobject]@{
        id = 'PEER-LAB-STATUS-WITH-PRODUCT-FAILURE'; kind = 'peer'
        mutate = {
            param($value)
            $value.failures[0].policy = 'auto'
            $value.failures[0].phase = 'post_restart_route'
            $value.failures[0].status = 'PRODUCT_INVARIANT'
            $value.failures[0].category = 'PRODUCT_ROUTE'
            $value.failures[0].code = 'WRONG_FAMILY'
            $value.failures[0].fixture_certified = $true
        }
    },
    [pscustomobject]@{
        id = 'MANIFEST-BYTES-STRING'; kind = 'manifest'
        mutate = { param($value) $value.files[0].bytes = 'secret' }
    }
)
foreach ($smugglingCase in $publicSmugglingCases) {
    $capturedSmuggling = $smugglingCase
    Invoke-I03OfflineTest -Id (
        'PRIVACY-PUBLIC-SMUGGLING-' + $capturedSmuggling.id) `
        -Category 'privacy_contract' -Body {
        $value = switch ([string]$capturedSmuggling.kind) {
            'peer' { New-I03OfflinePublicPeerSummary }
            'peer_complete' { New-I03OfflinePublicPeerComplete }
            'pass' { New-I03OfflinePublicCoordinatorPass }
            'fail' { New-I03OfflinePublicCoordinatorFail }
            'manifest' { New-I03OfflinePublicManifest }
            default { New-I03OfflinePublicCoordinatorSummary }
        }
        & $capturedSmuggling.mutate $value
        Assert-I03Offline -Condition (-not [bool](
            Test-I03OfflinePublicEvidenceObject -Value $value)) `
            -Code 'PUBLIC_ALLOWLIST_VALUE_SMUGGLING_ACCEPTED'
    }
}

Invoke-I03OfflineTest -Id 'PRIVACY-PUBLIC-TEXT-SAFE-POSITIVE' `
    -Category 'privacy_contract' -Body {
    $safe = '{"schema":"safe/v1","status":"BLOCKED",' +
        '"count":2,"digest_sha256":"' + ('a' * 64) + '"}'
    Assert-I03Offline -Condition ([bool](
        Test-I03OfflinePublicEvidenceText -Text $safe)) `
        -Code 'SAFE_PUBLIC_TEXT_REJECTED'
}

$privateTextSentinels = @(
    [pscustomobject]@{ id = 'USER-HASH'; text = '{"user_hash":"raw"}' },
    [pscustomobject]@{ id = 'IPV4'; text = '{"value":"203.0.113.123"}' },
    [pscustomobject]@{ id = 'IPV6'; text = '{"value":"2001:db8::123"}' },
    [pscustomobject]@{ id = 'DRIVE-PATH'; text = '{"value":"C:\\Users\\lab\\x"}' },
    [pscustomobject]@{ id = 'UNC-PATH'; text = '{"value":"\\\\server\\share\\x"}' },
    [pscustomobject]@{ id = 'AUTH'; text = '{"auth":"raw-auth"}' },
    [pscustomobject]@{ id = 'BEARER'; text = '{"value":"Bearer abcdefghijklmnop"}' },
    [pscustomobject]@{ id = 'TOKEN'; text = '{"token":"raw-token"}' },
    [pscustomobject]@{ id = 'COOKIE'; text = '{"cookie":"raw-cookie"}' },
    [pscustomobject]@{ id = 'SECRET'; text = '{"secret":"raw-secret"}' },
    [pscustomobject]@{ id = 'PRIVATE-KEY'; text =
        '{"value":"-----BEGIN PRIVATE KEY-----"}' },
    [pscustomobject]@{ id = 'EXCEPTION-KEY'; text =
        '{"exception":"private detail"}' },
    [pscustomobject]@{ id = 'EXCEPTION-VALUE'; text =
        '{"value":"System.InvalidOperationException: private"}' },
    [pscustomobject]@{ id = 'API-TOKEN-VALUE'; text =
        '{"value":"sk-abcdefghijklmnop"}' }
)
foreach ($sentinel in $privateTextSentinels) {
    $capturedSentinel = $sentinel
    Invoke-I03OfflineTest -Id (
        'PRIVACY-PUBLIC-TEXT-' + $capturedSentinel.id + '-REJECTED') `
        -Category 'privacy_contract' -Body {
        Assert-I03Offline -Condition (-not [bool](
            Test-I03OfflinePublicEvidenceText `
                -Text ([string]$capturedSentinel.text))) `
            -Code 'PRIVATE_PUBLIC_TEXT_SENTINEL_ACCEPTED'
    }
}

Invoke-I03OfflineTest -Id 'PRIVACY-PUBLIC-PRIVATE-PARTITION-STATIC' `
    -Category 'privacy_contract' -Body {
    foreach ($role in @('Invoke-I03PeerRole', 'Invoke-I03CoordinatorRole')) {
        $text = @($script:HarnessAst.FindAll({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] `
                -and $node.Name -ceq $role
        }, $true))[0].Extent.Text
        Assert-I03Offline -Condition (
            $text.Contains('Join-Path $output ''private''') -and
            $text.Contains('Join-Path $output ''evidence''') -and
            $text.Contains('Test-I03PublicEvidenceObject') -and
            $text.Contains('Test-I03PublicEvidenceText') -and
            $text.Contains("'evidence-manifest.json'") -and
            $text.Contains("name = 'summary.json'")) `
            -Code 'PUBLIC_PRIVATE_EVIDENCE_PARTITION_MISSING'
    }
}

Invoke-I03OfflineTest -Id 'PRIVACY-PUBLIC-DIRECTORY-EXACT-STATIC' `
    -Category 'privacy_contract' -Body {
    $matches = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Test-I03PublicEvidenceDirectory'
    }, $true))
    Assert-I03Offline -Condition ($matches.Count -eq 1) `
        -Code 'PUBLIC_DIRECTORY_VALIDATOR_NOT_UNIQUE'
    $text = $matches[0].Extent.Text
    foreach ($needle in @(
        '[IO.Path]::GetFullPath($Root)',
        'Get-Item -LiteralPath $rootPath -Force',
        '[IO.FileAttributes]::ReparsePoint',
        'Get-ChildItem -LiteralPath $rootPath -Force',
        '-Recurse -ErrorAction Stop', '$_.PSIsContainer',
        '$actualNames.Count -ne $expectedNames.Count',
        "(`$actualNames -join '|') -cne (`$expectedNames -join '|')",
        'Get-Content -LiteralPath $item.FullName -Raw',
        'ConvertFrom-Json -ErrorAction Stop',
        'Test-I03PublicEvidenceText -Text $text',
        'Test-I03PublicEvidenceObject -Value $object')) {
        Assert-I03Offline -Condition ($text.Contains($needle)) `
            -Code 'PUBLIC_DIRECTORY_VALIDATOR_CONTRACT_MISSING'
    }
    Assert-I03Offline -Condition (
        $script:PureFunctionAllowlist -cnotcontains
            'Test-I03PublicEvidenceDirectory') `
        -Code 'FILESYSTEM_DIRECTORY_VALIDATOR_MUST_NOT_BE_EXTRACTED'
    foreach ($role in @('Invoke-I03PeerRole', 'Invoke-I03CoordinatorRole')) {
        $roleText = @($script:HarnessAst.FindAll({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] `
                -and $node.Name -ceq $role
        }, $true))[0].Extent.Text
        Assert-I03Offline -Condition (
            $roleText.Contains('Test-I03PublicEvidenceDirectory') -and
            $roleText.Contains('-Root $publicEvidence') -and
            $roleText.Contains(
                "-ExpectedFiles @('summary.json', 'evidence-manifest.json')")) `
            -Code 'PUBLIC_DIRECTORY_VALIDATOR_NOT_WIRED_BOTH_ROLES'
    }
}

$ipv4Corpus = @(
    @('invalid', 'invalid'),
    @('0.0.0.0', 'special-v4'),
    @('0.255.255.255', 'special-v4'),
    @('1.1.1.1', 'global-public-v4'),
    @('9.255.255.255', 'global-public-v4'),
    @('10.0.0.0', 'private-v4'),
    @('10.255.255.255', 'private-v4'),
    @('11.0.0.0', 'global-public-v4'),
    @('100.63.255.255', 'global-public-v4'),
    @('100.64.0.0', 'cgnat-v4'),
    @('100.127.255.255', 'cgnat-v4'),
    @('100.128.0.0', 'global-public-v4'),
    @('126.255.255.255', 'global-public-v4'),
    @('127.0.0.0', 'loopback-v4'),
    @('127.255.255.255', 'loopback-v4'),
    @('128.0.0.0', 'global-public-v4'),
    @('169.253.255.255', 'global-public-v4'),
    @('169.254.0.0', 'linklocal-v4'),
    @('169.254.255.255', 'linklocal-v4'),
    @('169.255.0.0', 'global-public-v4'),
    @('172.15.255.255', 'global-public-v4'),
    @('172.16.0.0', 'private-v4'),
    @('172.31.255.255', 'private-v4'),
    @('172.32.0.0', 'global-public-v4'),
    @('192.0.0.0', 'special-v4'),
    @('192.0.0.255', 'special-v4'),
    @('192.0.2.1', 'special-v4'),
    @('192.31.196.1', 'special-v4'),
    @('192.52.193.1', 'special-v4'),
    @('192.88.99.1', 'special-v4'),
    @('192.168.0.0', 'private-v4'),
    @('192.168.255.255', 'private-v4'),
    @('192.169.0.0', 'global-public-v4'),
    @('192.175.48.1', 'special-v4'),
    @('198.17.255.255', 'global-public-v4'),
    @('198.18.0.0', 'special-v4'),
    @('198.19.255.255', 'special-v4'),
    @('198.20.0.0', 'global-public-v4'),
    @('198.51.100.1', 'special-v4'),
    @('203.0.113.1', 'special-v4'),
    @('223.255.255.255', 'global-public-v4'),
    @('224.0.0.0', 'special-v4'),
    @('255.255.255.255', 'special-v4')
)
$ipv4Index = 0
foreach ($case in $ipv4Corpus) {
    $ipv4Index++
    $capturedCase = $case
    Invoke-I03OfflineTest -Id ('IPV4-CLASS-{0:D3}' -f $ipv4Index) `
        -Category 'address_classifier' -Body {
        $actual = Invoke-I03PureScope `
            -FunctionNames @('Test-I03IpPrefix', 'Get-I03NativeAddressClass') `
            -Body { param($address) Get-I03NativeAddressClass -Address $address } `
            -ArgumentList @([string]$capturedCase[0])
        Assert-I03OfflineEqual -Actual $actual -Expected $capturedCase[1] `
            -Code 'IPV4_CLASS_MISMATCH'
    }
}

$ipv6Corpus = @(
    @('not-an-ipv6', 'invalid'),
    @('::', 'unspecified-v6'),
    @('::1', 'loopback-v6'),
    @('::ffff:8.8.8.8', 'ipv4-mapped'),
    @('ff00::', 'multicast-v6'),
    @('ffff::1', 'multicast-v6'),
    @('fe80::', 'linklocal-v6'),
    @('febf:ffff::1', 'linklocal-v6'),
    @('fc00::', 'ula-v6'),
    @('fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff', 'ula-v6'),
    @('64:ff9b::', 'translation-v6'),
    @('64:ff9b::ffff:ffff', 'translation-v6'),
    @('64:ff9b:1::', 'translation-v6'),
    @('64:ff9b:1:ffff:ffff:ffff:ffff:ffff', 'translation-v6'),
    @('2001::1', 'special-v6'),
    @('2001:0:ffff:ffff:ffff:ffff:ffff:ffff', 'special-v6'),
    @('2001:10::1', 'special-v6'),
    @('2001:20::1', 'special-v6'),
    @('2001:1ff:ffff:ffff:ffff:ffff:ffff:ffff', 'special-v6'),
    @('2001:200::1', 'global-native-v6'),
    @('2001:db8::', 'documentation-v6'),
    @('2001:db8:ffff:ffff:ffff:ffff:ffff:ffff', 'documentation-v6'),
    @('2002::', 'transition-v6'),
    @('2002:ffff:ffff:ffff:ffff:ffff:ffff:ffff', 'transition-v6'),
    @('3ffe::1', 'former-6bone-v6'),
    @('3fff::1', 'documentation-v6'),
    @('3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff', 'documentation-v6'),
    @('2620:4f:8000::1', 'special-v6'),
    @('1fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff', 'non-global-v6'),
    @('4000::', 'non-global-v6'),
    @('2001:4860:4860::8888', 'global-native-v6'),
    @('2606:4700:4700::1111', 'global-native-v6'),
    @('2a02:26f7:abcd::10', 'global-native-v6')
)
$ipv6Index = 0
foreach ($case in $ipv6Corpus) {
    $ipv6Index++
    $capturedCase = $case
    Invoke-I03OfflineTest -Id ('IPV6-CLASS-{0:D3}' -f $ipv6Index) `
        -Category 'address_classifier' -Body {
        $actual = Invoke-I03PureScope `
            -FunctionNames @('Test-I03IpPrefix', 'Get-I03NativeAddressClass') `
            -Body { param($address) Get-I03NativeAddressClass -Address $address } `
            -ArgumentList @([string]$capturedCase[0])
        Assert-I03OfflineEqual -Actual $actual -Expected $capturedCase[1] `
            -Code 'IPV6_CLASS_MISMATCH'
    }
}

Invoke-I03OfflineTest -Id 'IP-NORMALIZE-MAPPED' `
    -Category 'address_parser' -Body {
    $actual = Invoke-I03PureScope -FunctionNames @('Get-I03NormalizedIp') `
        -Body { Get-I03NormalizedIp -Address '[::ffff:192.0.2.1]' }
    Assert-I03OfflineEqual -Actual $actual -Expected '192.0.2.1' `
        -Code 'MAPPED_NORMALIZATION_MISMATCH'
}

Invoke-I03OfflineTest -Id 'IP-PARSER-REJECTS-MAPPED-AS-NATIVE' `
    -Category 'address_parser' -Body {
    $rejected = Invoke-I03PureScope -FunctionNames @('Convert-I03Address') `
        -Body {
            try {
                $null = Convert-I03Address -Value '::ffff:8.8.8.8' `
                    -Family ([Net.Sockets.AddressFamily]::InterNetworkV6) `
                    -Name 'fixture'
                return $false
            } catch { return $true }
        }
    Assert-I03Offline -Condition ([bool]$rejected) `
        -Code 'MAPPED_NATIVE_ACCEPTED'
}

$prefixCorpus = @(
    @('192.0.2.1', 24, '192.0.2.254', 24, $true),
    @('192.0.2.1', 24, '192.0.3.1', 24, $false),
    @('10.0.127.1', 17, '10.0.127.254', 17, $true),
    @('10.0.127.1', 17, '10.0.128.1', 17, $false),
    @('10.10.2.1', 23, '10.10.3.254', 23, $true),
    @('10.10.2.1', 23, '10.10.4.1', 23, $false),
    @('2001:4860:abcd::1', 64, '2001:4860:abcd::ffff', 64, $true),
    @('2001:4860:abcd::1', 64, '2001:4860:abce::1', 64, $false),
    @('2001:4860:abcd:0:7fff::1', 65,
        '2001:4860:abcd:0:7fff::2', 65, $true),
    @('2001:4860:abcd:0:7fff::1', 65,
        '2001:4860:abcd:0:8000::1', 65, $false),
    @('192.0.2.1', 24, '2001:4860::1', 24, $false),
    @('192.0.2.1', 24, '192.0.2.2', 25, $false),
    @('invalid', 24, '192.0.2.2', 24, $false),
    @('192.0.2.1', 0, '192.0.2.2', 0, $false),
    @('192.0.2.1', 33, '192.0.2.2', 33, $false)
)
$prefixIndex = 0
foreach ($prefixCase in $prefixCorpus) {
    $prefixIndex++
    $capturedPrefix = $prefixCase
    Invoke-I03OfflineTest -Id ('PREFIX-CORPUS-{0:D2}' -f $prefixIndex) `
        -Category 'topology_contract' -Body {
        $actual = Invoke-I03PureScope `
            -FunctionNames @('Test-I03SamePhysicalPrefix') -Body {
            param($value)
            Test-I03SamePhysicalPrefix `
                -LeftAddress ([string]$value[0]) `
                -LeftPrefixLength ([int]$value[1]) `
                -RightAddress ([string]$value[2]) `
                -RightPrefixLength ([int]$value[3])
        } -ArgumentList @(,$capturedPrefix)
        Assert-I03Offline -Condition (
            [bool]$actual -eq [bool]$capturedPrefix[4]) `
            -Code 'PHYSICAL_PREFIX_CLASSIFICATION_MISMATCH'
    }
}

Invoke-I03OfflineTest -Id 'TOPOLOGY-T1-EXACT' `
    -Category 'topology_contract' -Body {
    $value = Get-I03OfflineTopologyDecision
    Assert-I03Offline -Condition (
        [string]$value.status -ceq 'PASS' -and
        [string]$value.code -ceq 'NONE' -and
        [string]$value.topology_class -ceq 'T1' -and
        [bool]$value.t1_proved -and -not [bool]$value.t2_proved) `
        -Code 'VALID_T1_TOPOLOGY_REJECTED'
}

Invoke-I03OfflineTest -Id 'TOPOLOGY-T2-EXACT' `
    -Category 'topology_contract' -Body {
    $value = Get-I03OfflineTopologyDecision `
        -SameIPv4PhysicalPrefix $false `
        -SameIPv6PhysicalPrefix $false -IPv6OnLink $false `
        -RoutedNativeIPv6 $true
    Assert-I03Offline -Condition (
        [string]$value.status -ceq 'PASS' -and
        [string]$value.code -ceq 'NONE' -and
        [string]$value.topology_class -ceq 'T2' -and
        -not [bool]$value.t1_proved -and [bool]$value.t2_proved) `
        -Code 'VALID_T2_TOPOLOGY_REJECTED'
}

$blockedTopologyCases = @(
    [pscustomobject]@{ id = 'SAME-MACHINE'; parameter = 'DifferentMachineIdentities' },
    [pscustomobject]@{ id = 'NONNATIVE-IPV4'; parameter = 'NativeIPv4' },
    [pscustomobject]@{ id = 'NONNATIVE-IPV6'; parameter = 'NativeIPv6' },
    [pscustomobject]@{ id = 'NONPHYSICAL-OR-MULTI-ADAPTER'
        parameter = 'PhysicalSingleAdapter' },
    [pscustomobject]@{ id = 'OVERLAY'; parameter = 'OverlayDetected'; value = $true },
    [pscustomobject]@{ id = 'T1-NOT-ONLINK'; parameter = 'IPv6OnLink' }
)
foreach ($topologyCase in $blockedTopologyCases) {
    $capturedTopology = $topologyCase
    Invoke-I03OfflineTest -Id (
        'TOPOLOGY-' + $capturedTopology.id + '-BLOCKED') `
        -Category 'topology_contract' -Body {
        $arguments = @{}
        $property = $capturedTopology.PSObject.Properties['value']
        $arguments[$capturedTopology.parameter] = if ($null -eq $property) {
            $false
        } else { [bool]$property.Value }
        $value = Get-I03OfflineTopologyDecision @arguments
        Assert-I03Offline -Condition (
            [string]$value.status -ceq 'LAB_BLOCKED' -and
            [string]$value.code -ceq 'TOPOLOGY' -and
            [string]::IsNullOrEmpty([string]$value.topology_class) -and
            -not [bool]$value.t1_proved -and
            -not [bool]$value.t2_proved) `
            -Code 'INVALID_TOPOLOGY_NOT_BLOCKED'
    }
}

Invoke-I03OfflineTest -Id 'CLOCK-FOUR-TIMESTAMP-VALID' `
    -Category 'clock_contract' -Body {
    $t0 = '2026-01-02T03:04:05.0000000Z'
    $value = Get-I03OfflineClockEvidence -T0 $t0 -T0Echo $t0 `
        -T1 '2026-01-02T03:04:05.1000000Z' `
        -T2 '2026-01-02T03:04:05.2000000Z' `
        -T3 '2026-01-02T03:04:05.3000000Z'
    Assert-I03Offline -Condition (
        [string]$value.schema -ceq 'ese.v91.i03-clock-evidence/v1' -and
        [bool]$value.collector_ok -and
        [string]$value.collector_error_code -ceq 'NONE' -and
        [bool]$value.certified_within_1000_ms) `
        -Code 'VALID_FOUR_TIMESTAMP_CLOCK_REJECTED'
}

Invoke-I03OfflineTest -Id 'CLOCK-BOUNDARY-INCLUSIVE-1000MS' `
    -Category 'clock_contract' -Body {
    $t0 = '2026-01-02T03:04:05.0000000Z'
    $value = Get-I03OfflineClockEvidence -T0 $t0 -T0Echo $t0 `
        -T1 '2026-01-02T03:04:06.0000000Z' `
        -T2 '2026-01-02T03:04:06.0000000Z' `
        -T3 '2026-01-02T03:04:05.2000000Z'
    Assert-I03Offline -Condition (
        [bool]$value.collector_ok -and
        [double]$value.estimated_offset_ms -eq 900.0 -and
        [double]$value.uncertainty_ms -eq 100.0 -and
        [bool]$value.certified_within_1000_ms) `
        -Code 'CLOCK_1000MS_BOUNDARY_NOT_INCLUSIVE'
}

Invoke-I03OfflineTest -Id 'CLOCK-BOUNDARY-ABOVE-1000MS' `
    -Category 'clock_contract' -Body {
    $t0 = '2026-01-02T03:04:05.0000000Z'
    $value = Get-I03OfflineClockEvidence -T0 $t0 -T0Echo $t0 `
        -T1 '2026-01-02T03:04:06.0010000Z' `
        -T2 '2026-01-02T03:04:06.0010000Z' `
        -T3 '2026-01-02T03:04:05.2000000Z'
    Assert-I03Offline -Condition (
        [bool]$value.collector_ok -and
        -not [bool]$value.certified_within_1000_ms) `
        -Code 'CLOCK_ABOVE_1000MS_CERTIFIED'
}

$invalidClockCases = @(
    [pscustomobject]@{
        id = 'REVERSED'; t0 = '2026-01-02T03:04:05.0000000Z'
        echo = '2026-01-02T03:04:05.0000000Z'
        t1 = '2026-01-02T03:04:05.3000000Z'
        t2 = '2026-01-02T03:04:05.2000000Z'
        t3 = '2026-01-02T03:04:05.4000000Z'
        code = 'CLOCK_ORDER_OR_ECHO_INVALID'
    },
    [pscustomobject]@{
        id = 'MALFORMED'; t0 = '2026-01-02T03:04:05Z'
        echo = '2026-01-02T03:04:05Z'
        t1 = '2026-01-02T03:04:05.1000000Z'
        t2 = '2026-01-02T03:04:05.2000000Z'
        t3 = '2026-01-02T03:04:05.3000000Z'
        code = 'CLOCK_TIMESTAMP_INVALID'
    },
    [pscustomobject]@{
        id = 'NEGATIVE-DELAY'; t0 = '2026-01-02T03:04:05.0000000Z'
        echo = '2026-01-02T03:04:05.0000000Z'
        t1 = '2026-01-02T03:04:05.0000000Z'
        t2 = '2026-01-02T03:04:05.2000000Z'
        t3 = '2026-01-02T03:04:05.1000000Z'
        code = 'CLOCK_NEGATIVE_DELAY'
    },
    [pscustomobject]@{
        id = 'ECHO-MISMATCH'; t0 = '2026-01-02T03:04:05.0000000Z'
        echo = '2026-01-02T03:04:05.0000001Z'
        t1 = '2026-01-02T03:04:05.1000000Z'
        t2 = '2026-01-02T03:04:05.2000000Z'
        t3 = '2026-01-02T03:04:05.3000000Z'
        code = 'CLOCK_ORDER_OR_ECHO_INVALID'
    }
)
foreach ($clockCase in $invalidClockCases) {
    $capturedClock = $clockCase
    Invoke-I03OfflineTest -Id ('CLOCK-' + $capturedClock.id + '-REJECTED') `
        -Category 'clock_contract' -Body {
        $value = Get-I03OfflineClockEvidence `
            -T0 $capturedClock.t0 -T0Echo $capturedClock.echo `
            -T1 $capturedClock.t1 -T2 $capturedClock.t2 `
            -T3 $capturedClock.t3
        Assert-I03Offline -Condition (
            -not [bool]$value.collector_ok -and
            [string]$value.collector_error_code -ceq
                [string]$capturedClock.code -and
            -not [bool]$value.certified_within_1000_ms) `
            -Code 'INVALID_CLOCK_EVIDENCE_ACCEPTED'
    }
}

Invoke-I03OfflineTest -Id 'CLOCK-RUNTIME-WIRING-STATIC' `
    -Category 'clock_contract' -Body {
    $text = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Invoke-I03CoordinatorRole'
    }, $true))[0].Extent.Text
    $clockOffset = $text.IndexOf('Get-I03ClockEvidence')
    $policyOffset = $text.IndexOf("name = 'auto'")
    Assert-I03Offline -Condition (
        $clockOffset -ge 0 -and $policyOffset -gt $clockOffset -and
        $text.Contains('-T0CoordinatorSendUtc') -and
        $text.Contains('-T0CoordinatorEchoUtc') -and
        $text.Contains('-T1PeerReceiveUtc') -and
        $text.Contains('-T2PeerSendUtc') -and
        $text.Contains('-T3CoordinatorReceiveUtc') -and
        $text.Contains('$clockEvidence.collector_ok') -and
        $text.Contains('$clockEvidence.certified_within_1000_ms') -and
        $text.Contains('Stop-I03Fixture -Code ''CLOCK''')) `
        -Code 'CLOCK_RUNTIME_NOT_BOUND_TO_PURE_DECISION'
}

Invoke-I03OfflineTest -Id 'TUPLE-KEY-CANONICAL' `
    -Category 'collector_contract' -Body {
    $value = Invoke-I03PureScope -FunctionNames @(
        'Get-I03NormalizedIp', 'Get-I03TupleKey') -Body {
        Get-I03TupleKey -Family IPv6 `
            -LocalAddress '[2001:4860:0:0::1%12]' -LocalPort 45678 `
            -RemoteAddress '::ffff:192.0.2.10' -RemotePort 9462
    }
    Assert-I03OfflineEqual -Actual $value `
        -Expected 'IPv6|2001:4860::1|45678|192.0.2.10|9462' `
        -Code 'TUPLE_KEY_NOT_CANONICAL'
}

Invoke-I03OfflineTest -Id 'PROCESS-IDENTITY-SCHEMA-STATIC' `
    -Category 'ownership_contract' -Body {
    $ast = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Get-I03ProcessIdentity'
    }, $true))
    Assert-I03Offline -Condition ($ast.Count -eq 1) `
        -Code 'PROCESS_IDENTITY_FUNCTION_NOT_UNIQUE'
    $maps = @($ast[0].FindAll({
        param($node)
        $node -is [Management.Automation.Language.HashtableAst]
    }, $true))
    Assert-I03Offline -Condition ($maps.Count -eq 1) `
        -Code 'PROCESS_IDENTITY_SCHEMA_MAP_NOT_EXACT'
    $keys = @($maps[0].KeyValuePairs | ForEach-Object {
        $_.Item1.Extent.Text.Trim("'`"")
    })
    $expected = @(
        'schema', 'process_id', 'start_time_utc',
        'executable_path_sha256', 'executable_sha256')
    Assert-I03Offline -Condition (
        $keys.Count -eq $expected.Count -and
        @($expected | Where-Object { $keys -cnotcontains $_ }).Count -eq 0 -and
        $ast[0].Extent.Text.Contains('ToUniversalTime()') -and
        $ast[0].Extent.Text.Contains('Get-LabStringSha256') -and
        $ast[0].Extent.Text.Contains('Get-LabSha256')) `
        -Code 'PROCESS_IDENTITY_PID_TIME_PATH_EXE_CONTRACT_MISSING'
}

Invoke-I03OfflineTest -Id 'PROCESS-IDENTITY-TYPED-FAILURE-WIRING' `
    -Category 'ownership_contract' -Body {
    $identityText = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Get-I03ProcessIdentity'
    }, $true))[0].Extent.Text
    foreach ($needle in @(
        '$Process.Refresh()', '$Process.HasExited',
        'I03_PRODUCT_RUNTIME::PROCESS_EXITED_BEFORE_IDENTITY',
        'I03_COLLECTOR::PROCESS_IDENTITY_QUERY_FAILED')) {
        Assert-I03Offline -Condition ($identityText.Contains($needle)) `
            -Code 'PROCESS_IDENTITY_TYPED_FAILURE_CONTRACT_MISSING'
    }
    $peerText = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Invoke-I03PeerRole'
    }, $true))[0].Extent.Text
    Assert-I03Offline -Condition (
        $peerText.Contains("'^I03_COLLECTOR::'") -and
        $peerText.Contains('Peer restart collector failed') -and
        $peerText.Contains(
            "Stop-I03PeerLab -Code 'COLLECTOR_UNAVAILABLE'")) `
        -Code 'PEER_IDENTITY_COLLECTOR_NOT_CLASSIFIED_AS_LAB'
    $coordinatorText = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Invoke-I03CoordinatorRole'
    }, $true))[0].Extent.Text
    Assert-I03Offline -Condition (
        $coordinatorText.Contains("'^I03_COLLECTOR::'") -and
        $coordinatorText.Contains('Identity bootstrap collector failed') -and
        $coordinatorText.Contains(
            "Stop-I03Fixture -Code 'COLLECTOR_UNAVAILABLE'")) `
        -Code 'COORDINATOR_IDENTITY_COLLECTOR_NOT_CLASSIFIED_AS_LAB'
}

Invoke-I03OfflineTest -Id 'PROCESS-IDENTITY-EXACT-POSITIVE' `
    -Category 'ownership_contract' -Body {
    $expected = New-I03OfflineProcessIdentity
    $actual = Copy-I03OfflineObject $expected
    Assert-I03Offline -Condition (
        [bool](Test-I03OfflineProcessIdentityFixture `
            -Expected $expected -Actual $actual)) `
        -Code 'EXACT_PROCESS_IDENTITY_REJECTED'
}

$processIdentityMutations = @(
    [pscustomobject]@{ id = 'PID'; property = 'process_id'; value = [int]4243 },
    [pscustomobject]@{
        id = 'STARTTIME'; property = 'start_time_utc'
        value = '2026-01-02T03:04:05.0000001Z'
    },
    [pscustomobject]@{
        id = 'PATHHASH'; property = 'executable_path_sha256'; value = 'c' * 64
    },
    [pscustomobject]@{
        id = 'EXEHASH'; property = 'executable_sha256'; value = 'd' * 64
    }
)
foreach ($mutation in $processIdentityMutations) {
    $capturedMutation = $mutation
    Invoke-I03OfflineTest -Id (
        'PROCESS-IDENTITY-MISMATCH-' + $capturedMutation.id) `
        -Category 'ownership_contract' -Body {
        $expected = New-I03OfflineProcessIdentity
        $actual = Copy-I03OfflineObject $expected
        $actual.($capturedMutation.property) = $capturedMutation.value
        Assert-I03Offline -Condition (-not [bool](
            Test-I03OfflineProcessIdentityFixture `
                -Expected $expected -Actual $actual)) `
            -Code 'PROCESS_IDENTITY_MISMATCH_ACCEPTED'
    }
}

$malformedProcessIdentities = @(
    [pscustomobject]@{ id = 'NULL-EXPECTED'; expected = $null
        actual = (New-I03OfflineProcessIdentity) },
    [pscustomobject]@{ id = 'NULL-ACTUAL'
        expected = (New-I03OfflineProcessIdentity); actual = $null },
    [pscustomobject]@{ id = 'EMPTY-EXPECTED'; expected = [pscustomobject]@{}
        actual = (New-I03OfflineProcessIdentity) },
    [pscustomobject]@{ id = 'PID-WRONG-TYPE'
        expected = (New-I03OfflineProcessIdentity)
        actual = (New-I03OfflineProcessIdentity) },
    [pscustomobject]@{ id = 'HASH-WRONG-TYPE'
        expected = (New-I03OfflineProcessIdentity)
        actual = (New-I03OfflineProcessIdentity) }
)
$malformedProcessIdentities[3].actual.process_id = '4242'
$malformedProcessIdentities[4].actual.executable_sha256 = @('b' * 64)
foreach ($malformed in $malformedProcessIdentities) {
    $capturedMalformed = $malformed
    Invoke-I03OfflineTest -Id (
        'PROCESS-IDENTITY-MALFORMED-' + $capturedMalformed.id) `
        -Category 'ownership_contract' -Body {
        Assert-I03Offline -Condition (-not [bool](
            Test-I03OfflineProcessIdentityFixture `
                -Expected $capturedMalformed.expected `
                -Actual $capturedMalformed.actual)) `
            -Code 'MALFORMED_PROCESS_IDENTITY_ACCEPTED_OR_THROWN'
    }
}

Invoke-I03OfflineTest -Id 'PROCESS-LINEAGE-EXACT-POSITIVE' `
    -Category 'ownership_contract' -Body {
    $decision = Get-I03OfflineProcessLineageDecision `
        -ExpectedProcessId 4242 -ExpectedParentProcessId 3131 `
        -ParentStartTimeUtc '2026-01-02T03:04:04.0000000Z' `
        -CimProcessId 4242 -CimParentProcessId 3131 `
        -CimCreationTimeUtc '2026-01-02T03:04:05.0000000Z' `
        -Identity (New-I03OfflineProcessIdentity)
    Assert-I03Offline -Condition (
        [string]$decision.schema -ceq
            'ese.v91.i03-process-lineage-decision/v1' -and
        [bool]$decision.collector_ok -and
        [bool]$decision.safe_to_control -and
        -not [bool]$decision.historical_pid_row -and
        [string]$decision.error_code -ceq 'NONE') `
        -Code 'EXACT_PROCESS_LINEAGE_REJECTED'
}

Invoke-I03OfflineTest -Id 'PROCESS-LINEAGE-HISTORICAL-ORPHAN-IGNORED' `
    -Category 'ownership_contract' -Body {
    $decision = Get-I03OfflineProcessLineageDecision `
        -ExpectedProcessId 4242 -ExpectedParentProcessId 3131 `
        -ParentStartTimeUtc '2026-01-02T03:04:06.0000000Z' `
        -CimProcessId 4242 -CimParentProcessId 3131 `
        -CimCreationTimeUtc '2026-01-02T03:04:05.0000000Z' `
        -Identity (New-I03OfflineProcessIdentity)
    Assert-I03Offline -Condition (
        [bool]$decision.collector_ok -and
        -not [bool]$decision.safe_to_control -and
        [bool]$decision.historical_pid_row -and
        [string]$decision.error_code -ceq 'HISTORICAL_PID_ROW') `
        -Code 'HISTORICAL_ORPHAN_NOT_IGNORED'
}

$lineageBindingMismatches = @(
    [pscustomobject]@{
        id = 'CIM-PID'; expected_pid = 4242; expected_parent = 3131
        cim_pid = 4243; cim_parent = 3131
        cim_start = '2026-01-02T03:04:05.0000000Z'; identity_pid = 4242
    },
    [pscustomobject]@{
        id = 'CIM-PPID'; expected_pid = 4242; expected_parent = 3131
        cim_pid = 4242; cim_parent = 3132
        cim_start = '2026-01-02T03:04:05.0000000Z'; identity_pid = 4242
    },
    [pscustomobject]@{
        id = 'CIM-CREATION'; expected_pid = 4242; expected_parent = 3131
        cim_pid = 4242; cim_parent = 3131
        cim_start = '2026-01-02T03:04:05.0000001Z'; identity_pid = 4242
    },
    [pscustomobject]@{
        id = 'IDENTITY-PID'; expected_pid = 4242; expected_parent = 3131
        cim_pid = 4242; cim_parent = 3131
        cim_start = '2026-01-02T03:04:05.0000000Z'; identity_pid = 4243
    }
)
foreach ($mismatch in $lineageBindingMismatches) {
    $capturedMismatch = $mismatch
    Invoke-I03OfflineTest -Id (
        'PROCESS-LINEAGE-MISMATCH-' + $capturedMismatch.id) `
        -Category 'ownership_contract' -Body {
        $identity = New-I03OfflineProcessIdentity
        $identity.process_id = [int]$capturedMismatch.identity_pid
        $decision = Get-I03OfflineProcessLineageDecision `
            -ExpectedProcessId ([int]$capturedMismatch.expected_pid) `
            -ExpectedParentProcessId ([int]$capturedMismatch.expected_parent) `
            -ParentStartTimeUtc '2026-01-02T03:04:04.0000000Z' `
            -CimProcessId ([int]$capturedMismatch.cim_pid) `
            -CimParentProcessId ([int]$capturedMismatch.cim_parent) `
            -CimCreationTimeUtc ([string]$capturedMismatch.cim_start) `
            -Identity $identity
        Assert-I03Offline -Condition (
            -not [bool]$decision.collector_ok -and
            -not [bool]$decision.safe_to_control -and
            -not [bool]$decision.historical_pid_row -and
            [string]$decision.error_code -ceq 'IDENTITY_CIM_MISMATCH') `
            -Code 'PROCESS_LINEAGE_MISMATCH_ACCEPTED'
    }
}

$lineageMalformedTimes = @('PARENT', 'CIM', 'IDENTITY')
foreach ($malformedTime in $lineageMalformedTimes) {
    $capturedMalformedTime = $malformedTime
    Invoke-I03OfflineTest -Id (
        'PROCESS-LINEAGE-MALFORMED-' + $capturedMalformedTime) `
        -Category 'ownership_contract' -Body {
        $parentStart = '2026-01-02T03:04:04.0000000Z'
        $cimStart = '2026-01-02T03:04:05.0000000Z'
        $identity = New-I03OfflineProcessIdentity
        switch ($capturedMalformedTime) {
            'PARENT' { $parentStart = 'not-a-time' }
            'CIM' { $cimStart = 'not-a-time' }
            'IDENTITY' { $identity.start_time_utc = 'not-a-time' }
        }
        $decision = Get-I03OfflineProcessLineageDecision `
            -ExpectedProcessId 4242 -ExpectedParentProcessId 3131 `
            -ParentStartTimeUtc $parentStart `
            -CimProcessId 4242 -CimParentProcessId 3131 `
            -CimCreationTimeUtc $cimStart -Identity $identity
        Assert-I03Offline -Condition (
            -not [bool]$decision.collector_ok -and
            -not [bool]$decision.safe_to_control -and
            -not [bool]$decision.historical_pid_row -and
            [string]$decision.error_code -ceq 'LINEAGE_INVALID') `
            -Code 'MALFORMED_PROCESS_LINEAGE_ACCEPTED'
    }
}

Invoke-I03OfflineTest -Id 'PROCESS-DESCENDANT-CIM-BINDING-STATIC' `
    -Category 'ownership_contract' -Body {
    $ast = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Get-I03DescendantProcessSnapshot'
    }, $true))[0]
    $text = $ast.Extent.Text
    $commands = @($ast.FindAll({
        param($node)
        $node -is [Management.Automation.Language.CommandAst]
    }, $true) | ForEach-Object { $_.GetCommandName() })
    foreach ($command in @(
        'Get-CimInstance', 'Get-Process', 'Get-I03ProcessIdentity',
        'Convert-I03ProcessCreationTimeUtc',
        'Get-I03ProcessLineageDecision')) {
        Assert-I03Offline -Condition ($commands -ccontains $command) `
            -Code 'DESCENDANT_CIM_IDENTITY_BINDING_COMMAND_MISSING'
    }
    foreach ($needle in @(
        '[Parameter(Mandatory = $true)][string]$RootStartTimeUtc',
        '$row.CreationDate', '$row.ParentProcessId',
        '$lineage.collector_ok', '$lineage.historical_pid_row',
        '$lineage.safe_to_control', 'cim_binding =',
        'creation_time_utc = $cimCreationTimeUtc',
        "error_code = 'DESCENDANT_QUERY_FAILED'")) {
        Assert-I03Offline -Condition ($text.Contains($needle)) `
            -Code 'DESCENDANT_CIM_IDENTITY_BINDING_CONTRACT_MISSING'
    }
    $lineageOffset = $text.IndexOf('Get-I03ProcessLineageDecision')
    $addOffset = $text.IndexOf('$descendants.Add')
    $historicalOffset = $text.IndexOf('historical_pid_row')
    Assert-I03Offline -Condition (
        $lineageOffset -ge 0 -and $addOffset -gt $lineageOffset -and
        $historicalOffset -gt $lineageOffset -and
        $historicalOffset -lt $addOffset) `
        -Code 'DESCENDANT_CAPTURE_PRECEDES_LINEAGE_GUARD'
}

Invoke-I03OfflineTest -Id 'PROCESS-OWNERSHIP-STOP-STATIC' `
    -Category 'ownership_contract' -Body {
    $ast = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Stop-I03OwnedProcess'
    }, $true))[0]
    $text = $ast.Extent.Text
    $identityOffsets = @($ast.FindAll({
        param($node)
        $node -is [Management.Automation.Language.CommandAst] -and
            $node.GetCommandName() -ceq 'Test-I03ProcessIdentityMatch'
    }, $true) | ForEach-Object { $_.Extent.StartOffset } | Sort-Object)
    $stopProcessCalls = @($ast.FindAll({
        param($node)
        $node -is [Management.Automation.Language.CommandAst] -and
            $node.GetCommandName() -ceq 'Stop-Process'
    }, $true))
    $killOffsets = @($ast.FindAll({
        param($node)
        $node -is [Management.Automation.Language.InvokeMemberExpressionAst] `
            -and [string]$node.Member.Value -ceq 'Kill'
    }, $true) | ForEach-Object { $_.Extent.StartOffset } | Sort-Object)
    $descendantOffset = $text.IndexOf('Get-I03DescendantProcessSnapshot')
    $rootRevalidationOffset = $text.IndexOf(
        '$preStopRootState = Get-I03OwnedRootProcessState')
    $rootHandleOffset = $text.IndexOf(
        '[void]$preStopRootState.process.Handle')
    $rootIdentityOffset = $text.IndexOf(
        '$preStopRootIdentity = Get-I03ProcessIdentity')
    $rootIdentityMatchOffset = $text.IndexOf(
        'Test-I03ProcessIdentityMatch', $rootIdentityOffset)
    $descendantCimOffset = $text.IndexOf('$currentCim = @(Get-CimInstance')
    $descendantHandleOffset = $text.IndexOf('[void]$current.Handle')
    $descendantIdentityOffset = $text.IndexOf(
        '$currentIdentity = Get-I03ProcessIdentity',
        $descendantHandleOffset)
    $descendantLineageOffset = $text.IndexOf(
        'Get-I03ProcessLineageDecision', $descendantIdentityOffset)
    $descendantIdentityMatchOffset = $text.IndexOf(
        'Test-I03ProcessIdentityMatch', $descendantLineageOffset)
    $verifiedAddOffset = $text.IndexOf(
        '$verifiedDescendantProcesses.Add($current)')
    $closeOffset = $text.IndexOf('CloseMainWindow()')
    Assert-I03Offline -Condition (
        $text.Contains('[AllowNull()][object]$ExpectedIdentity') -and
        $identityOffsets.Count -ge 4 -and $stopProcessCalls.Count -eq 0 -and
        $killOffsets.Count -eq 2 -and
        $descendantOffset -ge 0 -and
        $rootRevalidationOffset -gt $descendantOffset -and
        $rootHandleOffset -gt $rootRevalidationOffset -and
        $rootIdentityOffset -gt $rootHandleOffset -and
        $rootIdentityMatchOffset -gt $rootIdentityOffset -and
        $descendantCimOffset -gt $rootIdentityMatchOffset -and
        $descendantHandleOffset -gt $descendantCimOffset -and
        $descendantIdentityOffset -gt $descendantHandleOffset -and
        $descendantLineageOffset -gt $descendantIdentityOffset -and
        $descendantIdentityMatchOffset -gt $descendantLineageOffset -and
        $verifiedAddOffset -gt $descendantIdentityMatchOffset -and
        $closeOffset -gt $verifiedAddOffset -and
        $killOffsets[0] -gt $verifiedAddOffset -and
        $killOffsets[1] -gt $killOffsets[0] -and
        $text.Contains('-not $RequireGraceful') -and
        $text.Contains('PROCESS_IDENTITY_MISMATCH') -and
        $text.Contains('EXPECTED_PROCESS_IDENTITY_MISSING') -and
        $text.Contains('ROOT_IDENTITY_CHANGED_BEFORE_STOP') -and
        $text.Contains('DESCENDANT_REVALIDATION_FAILED')) `
        -Code 'OWNED_PROCESS_IDENTITY_OR_DESCENDANT_GUARD_MISSING'
}

Invoke-I03OfflineTest -Id 'PROCESS-OWNERSHIP-HANDLE-BOUND-FAIL-CLOSED' `
    -Category 'ownership_contract' -Body {
    $ast = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Stop-I03OwnedProcess'
    }, $true))[0]
    $text = $ast.Extent.Text
    foreach ($needle in @(
        '$preStopRootState.collector_ok',
        '$preStopRootState.present',
        '$preStopRootIdentity = Get-I03ProcessIdentity',
        '-Expected $ExpectedIdentity',
        '-Actual $preStopRootIdentity',
        '[void]$preStopRootState.process.Handle',
        '$currentCim.Count -ne 1',
        '$currentCim[0].ParentProcessId',
        '$currentCim[0].CreationDate',
        '[void]$current.Handle',
        '$verifiedDescendantProcesses.Add($current)',
        '$actual.Kill()', '$current.Kill()',
        "error_code = 'ROOT_REVALIDATION_QUERY_FAILED'",
        "error_code = 'ROOT_REVALIDATION_IDENTITY_FAILED'",
        "error_code = 'ROOT_IDENTITY_CHANGED_BEFORE_STOP'",
        "error_code = 'DESCENDANT_REVALIDATION_FAILED'")) {
        Assert-I03Offline -Condition ($text.Contains($needle)) `
            -Code 'HANDLE_BOUND_FAIL_CLOSED_CONTRACT_MISSING'
    }
    Assert-I03Offline -Condition (
        -not $text.Contains('Stop-Process -Id') -and
        $text.Contains('$alreadyExited = $true') -and
        $text.Contains('$actual = $null') -and
        $text.Contains('if ($alreadyExited) {') -and
        $text.Contains(
            '$descendantsStopped = @($descendantSnapshot.rows).Count -eq 0')) `
        -Code 'PID_REUSE_OR_ROOT_EXIT_ZERO_KILL_GUARD_MISSING'
}

Invoke-I03OfflineTest -Id 'PROCESS-OWNERSHIP-ALL-CALLS-BOUND' `
    -Category 'ownership_contract' -Body {
    $calls = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.CommandAst] -and
            $node.GetCommandName() -ceq 'Stop-I03OwnedProcess'
    }, $true))
    Assert-I03Offline -Condition ($calls.Count -gt 0) `
        -Code 'OWNED_PROCESS_STOP_CALLS_MISSING'
    foreach ($call in $calls) {
        $parameters = @($call.CommandElements | Where-Object {
            $_ -is [Management.Automation.Language.CommandParameterAst]
        } | ForEach-Object { $_.ParameterName })
        Assert-I03Offline -Condition (
            $parameters -ccontains 'ExpectedIdentity') `
            -Code 'OWNED_PROCESS_STOP_CALL_UNBOUND'
    }
}

Invoke-I03OfflineTest -Id 'COLLECTOR-TARGET-SNAPSHOT-TYPED-STATIC' `
    -Category 'collector_contract' -Body {
    $snapshot = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Get-I03TargetConnectionSnapshot'
    }, $true))[0].Extent.Text
    $wrapper = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Get-I03TargetConnections'
    }, $true))[0].Extent.Text
    foreach ($needle in @(
        "schema = 'ese.v91.i03-target-connection-collector/v1'",
        'ok = $true', 'ok = $false', "error_code = 'NONE'",
        "error_code = 'TARGET_TCP_QUERY_FAILED'",
        'captured_at_utc = $capturedAt', 'rows = $rows', 'rows = @()')) {
        Assert-I03Offline -Condition ($snapshot.Contains($needle)) `
            -Code 'TARGET_COLLECTOR_TYPED_BRANCH_MISSING'
    }
    Assert-I03Offline -Condition (
        $wrapper.Contains('if (-not [bool]$snapshot.ok)') -and
        $wrapper.Contains('throw "I03_COLLECTOR::$($snapshot.error_code)"') -and
        $wrapper.Contains('return @($snapshot.rows)')) `
        -Code 'TARGET_COLLECTOR_FAILURE_COLLAPSED_TO_EMPTY'
}

Invoke-I03OfflineTest -Id 'COLLECTOR-AMBIGUITY-BLOCKS-STATIC' `
    -Category 'collector_contract' -Body {
    $socket = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Get-I03SocketEvidence'
    }, $true))[0].Extent.Text
    foreach ($needle in @(
        'collector_ok = $collectorOk',
        'collector_error_code = $collectorErrorCode',
        "'LOCAL_ADDRESS_ADAPTER_AMBIGUOUS'",
        "'CURRENT_TUPLE_AMBIGUOUS'", "'SOCKET_QUERY_FAILED'")) {
        Assert-I03Offline -Condition ($socket.Contains($needle)) `
            -Code 'SOCKET_COLLECTOR_AMBIGUITY_CONTRACT_MISSING'
    }
    $coordinator = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Invoke-I03CoordinatorRole'
    }, $true))[0].Extent.Text
    $collectorGuard = $coordinator.IndexOf(
        '-not [bool]$_.collector_ok')
    $fixtureStop = $coordinator.IndexOf(
        'Stop-I03Fixture', $collectorGuard)
    $productFailure = $coordinator.IndexOf(
        'Add-I03ProductFailure', $collectorGuard)
    Assert-I03Offline -Condition (
        $collectorGuard -ge 0 -and $fixtureStop -gt $collectorGuard -and
        ($productFailure -lt 0 -or $fixtureStop -lt $productFailure)) `
        -Code 'COLLECTOR_AMBIGUITY_NOT_BLOCKED_BEFORE_PRODUCT_CLASSIFICATION'
}

Invoke-I03OfflineTest -Id 'CENSUS-PROCESS-SOCKET-COLLECTOR-STATIC' `
    -Category 'collector_contract' -Body {
    $text = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Get-I03ProcessSocketCensus'
    }, $true))[0].Extent.Text
    foreach ($needle in @(
        'Get-NetTCPConnection -ErrorAction Stop',
        'Get-NetUDPEndpoint -ErrorAction Stop',
        '[int]$_.OwningProcess -eq $ProcessId',
        "schema = 'ese.v91.i03-process-socket-census/v1'",
        'collector_ok = $true', 'collector_ok = $false',
        "collector_error_code = 'PROCESS_SOCKET_QUERY_FAILED'",
        'tcp_rows = $tcp', 'udp_rows = $udp',
        'socket_count = $tcp.Count + $udp.Count')) {
        Assert-I03Offline -Condition ($text.Contains($needle)) `
            -Code 'PROCESS_SOCKET_CENSUS_TYPED_CONTRACT_MISSING'
    }
}

Invoke-I03OfflineTest -Id 'CENSUS-EMULE-PROCESS-GATES-STATIC' `
    -Category 'collector_contract' -Body {
    $collector = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Get-I03EmuleProcessCensus'
    }, $true))
    Assert-I03Offline -Condition ($collector.Count -eq 1) `
        -Code 'EMULE_PROCESS_CENSUS_NOT_UNIQUE'
    $collectorText = $collector[0].Extent.Text
    foreach ($needle in @(
        'Get-CimInstance -ClassName Win32_Process',
        '"Name = ''emule.exe''"', '-ErrorAction Stop',
        "schema = 'ese.v91.i03-emule-process-census/v1'",
        'collector_ok = $true', 'collector_ok = $false',
        "collector_error_code = 'NONE'",
        "collector_error_code = 'EMULE_PROCESS_QUERY_FAILED'",
        'process_id = [int]$_.ProcessId',
        'executable_path = $path', 'Get-LabSha256 -Path $path',
        'process_count = $rows.Count', 'rows = $rows', 'rows = @()')) {
        Assert-I03Offline -Condition ($collectorText.Contains($needle)) `
            -Code 'EMULE_PROCESS_CENSUS_TYPED_CONTRACT_MISSING'
    }
    Assert-I03Offline -Condition (
        $script:PureFunctionAllowlist -cnotcontains
            'Get-I03EmuleProcessCensus') `
        -Code 'EXTERNAL_PROCESS_CENSUS_MUST_NOT_BE_EXTRACTED'

    foreach ($role in @('Invoke-I03PeerRole', 'Invoke-I03CoordinatorRole')) {
        $text = @($script:HarnessAst.FindAll({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] `
                -and $node.Name -ceq $role
        }, $true))[0].Extent.Text
        Assert-I03Offline -Condition (
            ([regex]::Matches(
                $text, 'Get-I03EmuleProcessCensus')).Count -ge 2 -and
            $text.Contains('preexisting-emule-process-census.json') -and
            $text.Contains('terminal-emule-process-census.json') -and
            $text.Contains('$preexistingProcesses.collector_ok') -and
            $text.Contains('$preexistingProcesses.process_count -ne 0') -and
            $text -match '(?i)terminal[a-z]*process' -and
            $text.Contains('.process_count -ne 0') -and
            $text.Contains('cleanupFailures.Add')) `
            -Code 'EMULE_PROCESS_PREFLIGHT_OR_TERMINAL_GATE_MISSING'
    }
}

Invoke-I03OfflineTest -Id 'CONTROLLED-SERVER-REVERSE-TUPLE-ATTRIBUTION-STATIC' `
    -Category 'ownership_contract' -Body {
    $serverAst = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Start-I03ControlledEd2kServer'
    }, $true))[0]
    $serverText = $serverAst.Extent.Text
    foreach ($needle in @(
        "`$State.ContainsKey('expected_client_process_id')",
        'Get-NetTCPConnection -ErrorAction Stop',
        '$reverseRows.Count -ne 1',
        '$expectedPidRows.Count -ne 1',
        "I03_EXTERNAL_CONTAMINATION::REVERSE_TUPLE_NOT_OWNED",
        "`$State['candidate_attributed'] = `$true",
        "`$State['attributed_process_id'] = `$expectedPid")) {
        Assert-I03Offline -Condition ($serverText.Contains($needle)) `
            -Code 'CONTROLLED_SERVER_REVERSE_TUPLE_ATTRIBUTION_MISSING'
    }
    $whereCommands = @($serverAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.CommandAst] -and
            $node.GetCommandName() -ceq 'Where-Object'
    }, $true))
    $tupleFilters = @($whereCommands | Where-Object {
        $_.Extent.Text.Contains("[string]`$_.State -eq 'Established'") -and
        $_.Extent.Text.Contains('$_.LocalAddress') -and
        $_.Extent.Text.Contains('$_.RemoteAddress') -and
        $_.Extent.Text.Contains('$_.LocalPort') -and
        $_.Extent.Text.Contains('$_.RemotePort')
    })
    $ownerFilters = @($whereCommands | Where-Object {
        $_.Extent.Text.Contains('$_.OwningProcess') -and
        $_.Extent.Text.Contains('$expectedPid')
    })
    Assert-I03Offline -Condition (
        $tupleFilters.Count -eq 1 -and $ownerFilters.Count -eq 1) `
        -Code 'CONTROLLED_SERVER_REVERSE_TUPLE_FILTER_NOT_EXACT'
    $tupleFilterText = $tupleFilters[0].Extent.Text
    $ownerFilterText = $ownerFilters[0].Extent.Text
    Assert-I03Offline -Condition (
        -not $tupleFilterText.Contains('OwningProcess') -and
        $tupleFilterText -match (
            '(?s)\$_.LocalAddress.*?\.ToString\(\)\s+-eq\s+' +
            '\$AllowedClientAddress') -and
        $tupleFilterText -match (
            '(?s)\$_.RemoteAddress.*?\.ToString\(\)\s+-eq\s+' +
            '\[string\]\$State\[''listen_address''\]') -and
        $tupleFilterText -match (
            '(?s)\[int\]\$_.LocalPort\s+-eq\s+' +
            '\[int\]\$remote\.Port') -and
        $tupleFilterText -match (
            '(?s)\[int\]\$_\.RemotePort\s+-eq\s+' +
            '\[int\]\$State\[''listen_port''\]') -and
        $ownerFilterText -match (
            '(?s)\[int\]\$_.OwningProcess\s+-eq\s+\$expectedPid') -and
        $serverText -match (
            '(?s)\$reverseRows\.Count\s+-ne\s+1\s+-or\s+' +
            '\$expectedPidRows\.Count\s+-ne\s+1')) `
        -Code 'CONTROLLED_SERVER_REVERSE_TUPLE_ATTRIBUTION_MISSING'
    $waitText = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Wait-I03ControlledEd2kLogin'
    }, $true))[0].Extent.Text
    Assert-I03Offline -Condition (
        $waitText.Contains(
            '[int]$Server.state[''attributed_process_id''] -ne $Process.Id')) `
        -Code 'CONTROLLED_SERVER_ATTRIBUTION_NOT_REVALIDATED'
}

Invoke-I03OfflineTest -Id `
    'CONTROLLED-SERVER-REVERSE-TUPLE-BOUNDED-POLLING-STATIC' `
    -Category 'ownership_contract' -Body {
    $text = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Start-I03ControlledEd2kServer'
    }, $true))[0].Extent.Text
    $deadlineOffset = $text.IndexOf(
        '$reverseDeadline = [DateTime]::UtcNow.AddSeconds(')
    $loopOffset = $text.IndexOf('do {', $deadlineOffset)
    $queryOffset = $text.IndexOf(
        'Get-NetTCPConnection -ErrorAction Stop', $loopOffset)
    $ambiguousOffset = $text.IndexOf(
        '$reverseRows.Count -gt 1', $queryOffset)
    $sleepOffset = $text.IndexOf(
        'Start-Sleep -Milliseconds', $ambiguousOffset)
    $deadlineCheckOffset = $text.IndexOf(
        '[DateTime]::UtcNow -lt $reverseDeadline', $sleepOffset)
    $terminalOffset = $text.IndexOf(
        '$reverseRows.Count -ne 1', $deadlineCheckOffset)
    Assert-I03Offline -Condition (
        $deadlineOffset -ge 0 -and $loopOffset -gt $deadlineOffset -and
        $queryOffset -gt $loopOffset -and
        $ambiguousOffset -gt $queryOffset -and
        $text.IndexOf(
            'REVERSE_TUPLE_AMBIGUOUS', $ambiguousOffset) -gt
                $ambiguousOffset -and
        $sleepOffset -gt $ambiguousOffset -and
        $deadlineCheckOffset -gt $sleepOffset -and
        $terminalOffset -gt $deadlineCheckOffset -and
        $text.IndexOf(
            'REVERSE_TUPLE_NOT_OWNED', $terminalOffset) -gt
                $terminalOffset) `
        -Code 'REVERSE_TUPLE_ATTRIBUTION_NOT_BOUNDED_POLLING'
}

Invoke-I03OfflineTest -Id `
    'PEER-COMPLETION-MISMATCH-PRODUCT-WIRING-STATIC' `
    -Category 'ownership_contract' -Body {
    $peerMatches = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Invoke-I03PeerRole'
    }, $true))
    Assert-I03Offline -Condition ($peerMatches.Count -eq 1) `
        -Code 'PEER_ROLE_NOT_UNIQUE'
    $text = $peerMatches[0].Extent.Text
    $phaseOffset = $text.IndexOf("`$peerFailurePhase = 'peer_completion'")
    $snapshotOffset = $text.IndexOf(
        'Get-I03PeerInboundConnectionSnapshot', $phaseOffset + 1)
    $correlationReasonOffset = $text.IndexOf(
        "-Reason 'Peer final inbound socket did not correlate'",
        $snapshotOffset + 1)
    $unreportedReasonOffset = $text.IndexOf(
        "-Reason 'Peer saw an unreported final connection'",
        $snapshotOffset + 1)
    Assert-I03Offline -Condition (
        $phaseOffset -ge 0 -and $snapshotOffset -gt $phaseOffset -and
        $correlationReasonOffset -gt $snapshotOffset -and
        $unreportedReasonOffset -gt $correlationReasonOffset) `
        -Code 'PEER_COMPLETION_FINAL_INBOUND_BRANCH_MISSING'

    foreach ($reasonOffset in @(
        $correlationReasonOffset, $unreportedReasonOffset)) {
        $branchStart = [Math]::Max($snapshotOffset,
            $text.LastIndexOf('if (', $reasonOffset))
        $branchText = $text.Substring(
            $branchStart, $reasonOffset - $branchStart)
        Assert-I03Offline -Condition (
            $branchText.Contains('Stop-I03PeerProduct') -and
            $branchText.Contains("-Code 'WRONG_OR_NONPHYSICAL_SOCKET'") -and
            $branchText.Contains('done = $done') -and
            $branchText.Contains('final_inbound = $finalInbound') -and
            -not $branchText.Contains('throw ')) `
            -Code 'PEER_COMPLETION_MISMATCH_NOT_PRODUCT_ATTRIBUTED'
    }
}

Invoke-I03OfflineTest -Id 'CENSUS-ALLOWLIST-EXACT-POSITIVE' `
    -Category 'collector_contract' -Body {
    $tcp = @(
        [pscustomobject]@{
            transport = 'TCP'; state = 'Listen'; local_address = '::'
            local_port = 4662; remote_address = '::'; remote_port = 0
            owning_process = 4242
        },
        [pscustomobject]@{
            transport = 'TCP'; state = 'Listen'; local_address = '127.0.0.1'
            local_port = 4711; remote_address = '0.0.0.0'; remote_port = 0
            owning_process = 4242
        },
        [pscustomobject]@{
            transport = 'TCP'; state = 'Established'; local_address = '10.0.0.2'
            local_port = 55001; remote_address = '198.51.100.10'
            remote_port = 4662; owning_process = 4242
        },
        [pscustomobject]@{
            transport = 'TCP'; state = 'Established'
            local_address = '2001:4860::10'; local_port = 55002
            remote_address = '2001:4860::20'; remote_port = 4662
            owning_process = 4242
        },
        [pscustomobject]@{
            transport = 'TCP'; state = 'Established'; local_address = '10.0.0.2'
            local_port = 55003; remote_address = '198.51.100.5'
            remote_port = 5000; owning_process = 4242
        },
        [pscustomobject]@{
            transport = 'TCP'; state = 'Established'
            local_address = '127.0.0.1'; local_port = 4711
            remote_address = '127.0.0.1'; remote_port = 55004
            owning_process = 4242
        }
    )
    $udp = @([pscustomobject]@{
        transport = 'UDP'; state = 'Bound'; local_address = '::'
        local_port = 4672; remote_address = ''; remote_port = 0
        owning_process = 4242
    })
    $decision = Get-I03OfflineSocketCensusDecision `
        -Census (New-I03OfflineSocketCensus -TcpRows $tcp -UdpRows $udp)
    Assert-I03Offline -Condition (
        [string]$decision.schema -ceq
            'ese.v91.i03-candidate-socket-decision/v1' -and
        [bool]$decision.collector_ok -and
        [string]$decision.collector_error_code -ceq 'NONE' -and
        [int]$decision.allowed_row_count -eq 7 -and
        [int]$decision.unexpected_row_count -eq 0 -and
        [bool]$decision.complete) `
        -Code 'EXACT_CANDIDATE_SOCKET_ALLOWLIST_REJECTED'
}

$unexpectedCensusCases = @(
    [pscustomobject]@{
        id = 'THIRD-PARTY-TCP'; transport = 'TCP'; state = 'Established'
        local_address = '10.0.0.2'; local_port = 55000
        remote_address = '8.8.8.8'; remote_port = 443
        owning_process = 4242; classification = 'tcp_not_allowlisted'
    },
    [pscustomobject]@{
        id = 'WRONG-PID'; transport = 'TCP'; state = 'Listen'
        local_address = '::'; local_port = 4662
        remote_address = '::'; remote_port = 0
        owning_process = 4243; classification = 'wrong_process'
    },
    [pscustomobject]@{
        id = 'WRONG-UDP'; transport = 'UDP'; state = 'Bound'
        local_address = '::'; local_port = 9999
        remote_address = ''; remote_port = 0
        owning_process = 4242; classification = 'udp_not_allowlisted'
    }
)
foreach ($censusCase in $unexpectedCensusCases) {
    $capturedCensus = $censusCase
    Invoke-I03OfflineTest -Id ('CENSUS-' + $capturedCensus.id + '-REJECTED') `
        -Category 'collector_contract' -Body {
        $row = [pscustomobject][ordered]@{
            transport = [string]$capturedCensus.transport
            state = [string]$capturedCensus.state
            local_address = [string]$capturedCensus.local_address
            local_port = [int]$capturedCensus.local_port
            remote_address = [string]$capturedCensus.remote_address
            remote_port = [int]$capturedCensus.remote_port
            owning_process = [int]$capturedCensus.owning_process
        }
        $census = if ([string]$capturedCensus.transport -ceq 'UDP') {
            New-I03OfflineSocketCensus -UdpRows @($row)
        } else { New-I03OfflineSocketCensus -TcpRows @($row) }
        $decision = Get-I03OfflineSocketCensusDecision -Census $census
        Assert-I03Offline -Condition (
            [bool]$decision.collector_ok -and
            [int]$decision.unexpected_row_count -eq 1 -and
            [string]$decision.unexpected_rows[0].classification -ceq
                [string]$capturedCensus.classification -and
            -not [bool]$decision.complete) `
            -Code 'NON_ALLOWLISTED_CANDIDATE_SOCKET_ACCEPTED'
    }
}

Invoke-I03OfflineTest -Id 'CENSUS-COLLECTOR-FAILURE-BLOCKED' `
    -Category 'collector_contract' -Body {
    $decision = Get-I03OfflineSocketCensusDecision -Census (
        New-I03OfflineSocketCensus -CollectorOk $false)
    Assert-I03Offline -Condition (
        -not [bool]$decision.collector_ok -and
        [string]$decision.collector_error_code -ceq
            'PROCESS_SOCKET_QUERY_FAILED' -and
        -not [bool]$decision.complete) `
        -Code 'CENSUS_COLLECTOR_FAILURE_NOT_BLOCKED'
}

Invoke-I03OfflineTest -Id 'CENSUS-PROCESS-BINDING-MISMATCH-BLOCKED' `
    -Category 'collector_contract' -Body {
    $decision = Get-I03OfflineSocketCensusDecision `
        -Census (New-I03OfflineSocketCensus -ProcessId 4243) `
        -ProcessId 4242
    Assert-I03Offline -Condition (
        -not [bool]$decision.collector_ok -and
        -not [bool]$decision.complete) `
        -Code 'CENSUS_PROCESS_ID_BINDING_MISMATCH_ACCEPTED'
}

Invoke-I03OfflineTest -Id 'CENSUS-RUNTIME-WIRING-STATIC' `
    -Category 'collector_contract' -Body {
    foreach ($functionName in @(
        'Wait-I03Prewarm', 'Wait-I03PostRestartRoute')) {
        $text = @($script:HarnessAst.FindAll({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] `
                -and $node.Name -ceq $functionName
        }, $true))[0].Extent.Text
        Assert-I03Offline -Condition (
            $text.Contains('Get-I03ProcessSocketCensus') -and
            $text.Contains('Get-I03CandidateSocketCensusDecision') -and
            $text.Contains('collector_ok') -and
            ($text.Contains('unexpected_rows') -or
                $text.Contains('unexpected_socket'))) `
            -Code 'CANDIDATE_CENSUS_NOT_WIRED_IN_ROUTE_PHASE'
    }
    $coordinator = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Invoke-I03CoordinatorRole'
    }, $true))[0].Extent.Text
    Assert-I03Offline -Condition (
        $coordinator.Contains('startupCensus') -and
        $coordinator.Contains('startupSocketDecision') -and
        $coordinator.Contains('CANDIDATE_THIRD_PARTY_SOCKET') -and
        $coordinator.Contains('unexpected_socket_observation_count')) `
        -Code 'CANDIDATE_CENSUS_NOT_CLASSIFIED_BY_COORDINATOR'
}

Invoke-I03OfflineTest -Id 'CLEANUP-TERMINAL-SOCKET-COLLECTOR-STATIC' `
    -Category 'cleanup_contract' -Body {
    $text = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Get-I03TerminalSocketCleanupEvidence'
    }, $true))[0].Extent.Text
    foreach ($needle in @(
        "schema = 'ese.v91.i03-terminal-socket-cleanup/v1'",
        'Get-NetTCPConnection -ErrorAction Stop',
        'Get-NetUDPEndpoint -ErrorAction Stop',
        'checked_ports = $portSet', 'checked_process_ids = $ownedPids',
        'tcp_port_row_count = $tcpAtPorts.Count',
        'udp_port_row_count = $udpAtPorts.Count',
        'owned_tcp_row_count = $ownedTcp.Count',
        'owned_udp_row_count = $ownedUdp.Count',
        "collector_error_code = 'TERMINAL_SOCKET_QUERY_FAILED'",
        'ports_free = $false',
        'owned_process_sockets_free = $false', 'complete = $false')) {
        Assert-I03Offline -Condition ($text.Contains($needle)) `
            -Code 'TERMINAL_SOCKET_CLEANUP_CONTRACT_MISSING'
    }
    Assert-I03Offline -Condition (
        $text -notmatch 'ErrorAction\s+SilentlyContinue') `
        -Code 'TERMINAL_SOCKET_COLLECTOR_COLLAPSES_ERRORS'
}

Invoke-I03OfflineTest -Id 'CLEANUP-TERMINAL-NINE-PORTS-BOTH-ROLES' `
    -Category 'cleanup_contract' -Body {
    foreach ($role in @('Invoke-I03PeerRole', 'Invoke-I03CoordinatorRole')) {
        $roleAst = @($script:HarnessAst.FindAll({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] `
                -and $node.Name -ceq $role
        }, $true))[0]
        $text = $roleAst.Extent.Text
        $terminalCalls = @($roleAst.FindAll({
            param($node)
            $node -is [Management.Automation.Language.CommandAst] -and
                $node.GetCommandName() -ceq
                    'Get-I03TerminalSocketCleanupEvidence'
        }, $true))
        Assert-I03Offline -Condition ($terminalCalls.Count -eq 1) `
            -Code 'TERMINAL_NETWORK_CALL_NOT_EXACTLY_ONE'
        $terminalCallText = $terminalCalls[0].Extent.Text
        $terminalOffset = $terminalCalls[0].Extent.StartOffset
        $stopOffsets = @($roleAst.FindAll({
            param($node)
            $node -is [Management.Automation.Language.CommandAst] -and
                $node.GetCommandName() -ceq 'Stop-I03OwnedProcess'
        }, $true) | ForEach-Object { $_.Extent.StartOffset })
        Assert-I03Offline -Condition (
            $stopOffsets.Count -gt 0 -and
            $terminalOffset -gt ($stopOffsets | Measure-Object -Maximum).Maximum `
            -and $text.Contains('terminal-network-cleanup.json')) `
            -Code 'TERMINAL_NETWORK_PROOF_NOT_AFTER_PROCESS_CLEANUP'
        foreach ($portName in @(
            'PeerTcpPort', 'PeerUdpPort', 'PeerWebPort',
            'AutoTcpPort', 'AutoUdpPort', 'AutoWebPort',
            'PreferredTcpPort', 'PreferredUdpPort', 'PreferredWebPort')) {
            Assert-I03Offline -Condition (
                $terminalCallText.Contains('$' + $portName)) `
                -Code 'TERMINAL_NETWORK_NINE_PORT_SET_INCOMPLETE'
        }
        Assert-I03Offline -Condition (
            $text.Contains('.complete') -and
            $text.Contains('cleanupFailures.Add')) `
            -Code 'TERMINAL_NETWORK_RESULT_NOT_BOUND_TO_CLEANUP'
    }
}

Invoke-I03OfflineTest -Id 'CODEC-ED2K-FRAME-STATIC' `
    -Category 'codec_contract' -Body {
    $read = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Read-ExactBytes'
    }, $true))
    Assert-I03Offline -Condition ($read.Count -eq 1) `
        -Code 'CONTROLLED_ED2K_CODEC_NOT_UNIQUE'
    $readText = $read[0].Extent.Text
    Assert-I03Offline -Condition (
        $readText.Contains('[Net.Sockets.NetworkStream]$Stream') -and
        $readText.Contains('while ($offset -lt $Count)') -and
        $readText.Contains('$Count - $offset') -and
        $readText.Contains('if ($read -le 0)')) `
        -Code 'CONTROLLED_ED2K_EXACT_READ_CONTRACT_MISSING'
    foreach ($name in @(
        'New-I03Ed2kFrame', 'New-I03Ed2kIdChangeFrame',
        'Test-I03Ed2kLoginRequestFrame')) {
        $matches = @($script:HarnessAst.FindAll({
            param($node)
            $node -is `
                [Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -ceq $name
        }, $true))
        Assert-I03Offline -Condition ($matches.Count -eq 1) `
            -Code 'PURE_ED2K_CODEC_FUNCTION_NOT_UNIQUE'
    }
}

Invoke-I03OfflineTest -Id 'CODEC-ED2K-REFERENCE-BYTES' `
    -Category 'codec_contract' -Body {
    [byte[]]$idChange = New-I03OfflineEd2kIdChangeFrame
    Assert-I03OfflineEqual -Actual ([BitConverter]::ToString($idChange)) `
        -Expected 'E3-05-00-00-00-40-01-00-00-01' `
        -Code 'ED2K_IDCHANGE_REFERENCE_BYTES_WRONG'
    [byte[]]$otherId = New-I03OfflineEd2kIdChangeFrame `
        -ClientId ([uint32]0x11223344)
    Assert-I03OfflineEqual -Actual ([BitConverter]::ToString($otherId)) `
        -Expected 'E3-05-00-00-00-40-44-33-22-11' `
        -Code 'ED2K_IDCHANGE_CLIENT_ID_ENDIAN_WRONG'
    [byte[]]$statusFrame = New-I03OfflineEd2kFrame -Opcode 0x34 `
        -Payload (New-Object byte[] 8)
    Assert-I03OfflineEqual -Actual ([BitConverter]::ToString($statusFrame)) `
        -Expected 'E3-09-00-00-00-34-00-00-00-00-00-00-00-00' `
        -Code 'ED2K_STATUS_REFERENCE_BYTES_WRONG'
}

Invoke-I03OfflineTest -Id 'CODEC-LOGIN-VALID-PORT-LITTLE-ENDIAN' `
    -Category 'codec_contract' -Body {
    [byte[]]$payload = New-Object byte[] 22
    $payload[20] = 0x36
    $payload[21] = 0x12
    [byte[]]$frame = New-I03OfflineEd2kFrame `
        -Opcode 0x01 -Payload $payload
    Assert-I03OfflineEqual -Actual ([BitConverter]::ToString(
            [byte[]]($frame[0..5]))) -Expected 'E3-17-00-00-00-01' `
        -Code 'ED2K_LOGIN_FRAME_HEADER_WRONG'
    $result = Test-I03OfflineEd2kLoginRequestFrame -Frame $frame
    Assert-I03Offline -Condition (
        [string]$result.schema -ceq
            'ese.v91.i03-ed2k-loginrequest-codec/v1' -and
        [bool]$result.valid -and
        [string]$result.error_code -ceq 'NONE' -and
        [int]$result.protocol -eq 0xE3 -and
        [int]$result.opcode -eq 0x01 -and
        [Int64]$result.packet_length -eq 23 -and
        [int]$result.payload_length -eq 22 -and
        [string]$result.payload_sha256 -ceq
            'b383c3191c3e9df98bfc8f4516c7ca3b1e3000216507dcf5f6cdba7958ac3f4b' `
        -and [int]$result.advertised_tcp_port -eq 4662) `
        -Code 'VALID_ED2K_LOGIN_FRAME_REJECTED_OR_MISPARSED'

    $payload[20] = 0x12
    $payload[21] = 0x36
    [byte[]]$reversedFrame = New-I03OfflineEd2kFrame `
        -Opcode 0x01 -Payload $payload
    $reversed = Test-I03OfflineEd2kLoginRequestFrame `
        -Frame $reversedFrame
    Assert-I03Offline -Condition (
        [bool]$reversed.valid -and
        [int]$reversed.advertised_tcp_port -eq 13842 -and
        [int]$reversed.advertised_tcp_port -ne 4662) `
        -Code 'ED2K_LOGIN_PORT_NOT_PARSED_LITTLE_ENDIAN'
}

$shortLoginFrame = New-Object byte[] 27
$shortLoginFrame[0] = 0xE3
$shortLoginFrame[1] = 0x16
$shortLoginFrame[5] = 0x01
$validLoginFrame = New-Object byte[] 28
$validLoginFrame[0] = 0xE3
$validLoginFrame[1] = 0x17
$validLoginFrame[5] = 0x01
[byte[]]$trailingLoginFrame = New-Object byte[] ($validLoginFrame.Length + 1)
[Array]::Copy(
    $validLoginFrame, 0, $trailingLoginFrame, 0, $validLoginFrame.Length)
$trailingLoginFrame[$trailingLoginFrame.Length - 1] = 0x7F
$codecInvalidCases = @(
    [pscustomobject]@{
        id = 'ZERO-BYTES'; frame = [byte[]]@(); code = 'TRUNCATED_HEADER'
    },
    [pscustomobject]@{
        id = 'FIVE-BYTES'; frame = [byte[]](0xE3, 1, 0, 0, 0)
        code = 'TRUNCATED_HEADER'
    },
    [pscustomobject]@{
        id = 'WRONG-PROTOCOL'
        frame = [byte[]](0xD4, 1, 0, 0, 0, 1)
        code = 'WRONG_PROTOCOL'
    },
    [pscustomobject]@{
        id = 'WRONG-OPCODE'
        frame = [byte[]](0xE3, 1, 0, 0, 0, 2)
        code = 'WRONG_OPCODE'
    },
    [pscustomobject]@{
        id = 'ZERO-PACKET-LENGTH'
        frame = [byte[]](0xE3, 0, 0, 0, 0, 1)
        code = 'INVALID_PACKET_LENGTH'
    },
    [pscustomobject]@{
        id = 'OVERSIZED-PACKET'
        frame = [byte[]](0xE3, 1, 0, 0x10, 0, 1)
        code = 'OVERSIZED_PACKET'
    },
    [pscustomobject]@{
        id = 'TRUNCATED-PAYLOAD'
        frame = [byte[]](0xE3, 0x17, 0, 0, 0, 1)
        code = 'TRUNCATED_PAYLOAD'
    },
    [pscustomobject]@{
        id = 'LOGIN-PAYLOAD-TOO-SHORT'; frame = $shortLoginFrame
        code = 'LOGIN_PAYLOAD_TOO_SHORT'
    },
    [pscustomobject]@{
        id = 'TRAILING-BYTES'; frame = $trailingLoginFrame
        code = 'TRAILING_BYTES'
    },
    [pscustomobject]@{
        id = 'BIG-ENDIAN-LENGTH'
        frame = [byte[]](0xE3, 0, 0, 0, 0x17, 1)
        code = 'OVERSIZED_PACKET'
    }
)
foreach ($codecInvalidCase in $codecInvalidCases) {
    $capturedCodecInvalid = $codecInvalidCase
    Invoke-I03OfflineTest -Id (
        'CODEC-LOGIN-' + $capturedCodecInvalid.id + '-REJECTED') `
        -Category 'codec_contract' -Body {
        $result = Test-I03OfflineEd2kLoginRequestFrame `
            -Frame ([byte[]]$capturedCodecInvalid.frame)
        Assert-I03Offline -Condition (
            -not [bool]$result.valid -and
            [string]$result.error_code -ceq
                [string]$capturedCodecInvalid.code) `
            -Code 'INVALID_ED2K_LOGIN_FRAME_NOT_REJECTED_EXACTLY'
    }
}

Invoke-I03OfflineTest -Id 'CODEC-RUNSPACE-PURE-SOURCE-WIRING-STATIC' `
    -Category 'codec_contract' -Body {
    $text = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Start-I03ControlledEd2kServer'
    }, $true))[0].Extent.Text
    foreach ($needle in @(
        '$LoginCodecSource', '$FrameCodecSource', '$IdChangeCodecSource',
        'Function:\Test-I03Ed2kLoginRequestFrame',
        'Function:\New-I03Ed2kFrame',
        'Function:\New-I03Ed2kIdChangeFrame',
        '${function:Test-I03Ed2kLoginRequestFrame}.ToString()',
        '${function:New-I03Ed2kFrame}.ToString()',
        '${function:New-I03Ed2kIdChangeFrame}.ToString()',
        'Test-I03Ed2kLoginRequestFrame -Frame $header',
        'Test-I03Ed2kLoginRequestFrame -Frame $frame',
        'New-I03Ed2kIdChangeFrame',
        'New-I03Ed2kFrame -Opcode 0x34')) {
        Assert-I03Offline -Condition ($text.Contains($needle)) `
            -Code 'CONTROLLED_ED2K_PURE_CODEC_NOT_WIRED_IN_RUNSPACE'
    }
}

Invoke-I03OfflineTest -Id 'COORDINATION-COMMAND-SCHEMAS-STATIC' `
    -Category 'codec_contract' -Body {
    foreach ($schema in @(
        'ese.v91.i03-run/v1',
        'ese.v91.i03-baseline-command/v1',
        'ese.v91.i03-peer-baseline-ack/v1',
        'ese.v91.i03-rearm-command/v1',
        'ese.v91.i03-peer-rearm-ack/v1',
        'ese.v91.i03-prewarm-command/v1',
        'ese.v91.i03-peer-prewarm-ack/v1',
        'ese.v91.i03-restart-command/v1',
        'ese.v91.i03-peer-restarted/v1',
        'ese.v91.i03-done-command/v1',
        'ese.v91.i03-peer-complete/v1',
        'ese.v91.i03-stop-command/v1',
        'ese.v91.i03-peer-result/v1')) {
        Assert-I03Offline -Condition (
            ([regex]::Matches(
                $script:HarnessText, [regex]::Escape($schema))).Count -ge 2) `
            -Code 'COORDINATION_SCHEMA_NOT_WRITTEN_AND_VALIDATED'
    }
    foreach ($binding in @(
        'case_id', 'run_nonce', 'candidate_commit',
        'candidate_emule_sha256', 'source_process_id')) {
        Assert-I03Offline -Condition ($script:HarnessText.Contains($binding)) `
            -Code 'COORDINATION_CONTEXT_BINDING_MISSING'
    }
}

$helloDecisionCases = @(
    [pscustomobject]@{
        id = 'COLLECTOR-PASS'; collector_ok = $true
        error_code = 'NONE'; status = 'PASS'; code = 'NONE'
    },
    [pscustomobject]@{
        id = 'EXPECTED-LOG-NOT-FOUND'; collector_ok = $false
        error_code = 'EXPECTED_LOG_NOT_FOUND'
        status = 'PRODUCT_INVARIANT'; code = 'IPV4_PREWARM_INVARIANT'
    },
    [pscustomobject]@{
        id = 'LOG-ENUMERATION-FAILED'; collector_ok = $false
        error_code = 'LOG_ENUMERATION_FAILED'
        status = 'LAB_BLOCKED'; code = 'COLLECTOR_UNAVAILABLE'
    },
    [pscustomobject]@{
        id = 'LOG-READ-FAILED'; collector_ok = $false
        error_code = 'LOG_READ_FAILED'
        status = 'LAB_BLOCKED'; code = 'COLLECTOR_UNAVAILABLE'
    }
)
foreach ($helloDecisionCase in $helloDecisionCases) {
    $capturedHelloDecision = $helloDecisionCase
    Invoke-I03OfflineTest -Id (
        'HELLO-DECISION-' + $capturedHelloDecision.id) `
        -Category 'route_policy' -Body {
        $evidence = [pscustomobject][ordered]@{
            schema = 'ese.v91.i03-hello-log-collector/v2'
            collector_ok = [bool]$capturedHelloDecision.collector_ok
            collector_error_code =
                [string]$capturedHelloDecision.error_code
        }
        $value = Get-I03OfflineHelloEvidenceDecision -Evidence $evidence
        Assert-I03Offline -Condition (
            [string]$value.schema -ceq
                'ese.v91.i03-hello-evidence-decision/v1' -and
            [string]$value.status -ceq
                [string]$capturedHelloDecision.status -and
            [string]$value.code -ceq
                [string]$capturedHelloDecision.code) `
            -Code 'HELLO_EVIDENCE_DECISION_MISMATCH'
    }
}

Invoke-I03OfflineTest -Id 'HELLO-DECISION-MALFORMED-BLOCKED' `
    -Category 'route_policy' -Body {
    foreach ($evidence in @(
        $null,
        [pscustomobject]@{},
        [pscustomobject]@{
            schema = 'ese.v91.i03-hello-log-collector/v2'
            collector_ok = 'false'
            collector_error_code = 'EXPECTED_LOG_NOT_FOUND'
        })) {
        $value = Get-I03OfflineHelloEvidenceDecision -Evidence $evidence
        Assert-I03Offline -Condition (
            [string]$value.status -ceq 'LAB_BLOCKED' -and
            [string]$value.code -ceq 'COLLECTOR_UNAVAILABLE') `
            -Code 'MALFORMED_HELLO_EVIDENCE_NOT_BLOCKED'
    }
}

Invoke-I03OfflineTest -Id 'HELLO-DECISION-RUNTIME-WIRING-STATIC' `
    -Category 'route_policy' -Body {
    $text = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Invoke-I03CoordinatorRole'
    }, $true))[0].Extent.Text
    $decisionOffset = $text.IndexOf('Get-I03HelloEvidenceDecision')
    $productOffset = $text.IndexOf("'PRODUCT_INVARIANT'", $decisionOffset)
    $productStopOffset = $text.IndexOf(
        'Stop-I03ProductFailure', $productOffset)
    $labOffset = $text.IndexOf("'LAB_BLOCKED'", $productStopOffset)
    $labStopOffset = $text.IndexOf('Stop-I03Fixture', $labOffset)
    Assert-I03Offline -Condition (
        $decisionOffset -ge 0 -and $productOffset -gt $decisionOffset -and
        $productStopOffset -gt $productOffset -and
        $text.IndexOf('$prewarm.hello', $productStopOffset) -gt
            $productStopOffset -and
        $labOffset -gt $productStopOffset -and
        $labStopOffset -gt $labOffset) `
        -Code 'HELLO_DECISION_NOT_WIRED_TO_TYPED_ADJUDICATION'
}

$routePositiveCases = @(
    [pscustomobject]@{ policy = 'auto'; family = 'IPv4' },
    [pscustomobject]@{ policy = 'preferred'; family = 'IPv6' }
)
foreach ($routePositive in $routePositiveCases) {
    $capturedRoutePositive = $routePositive
    Invoke-I03OfflineTest -Id (
        'ROUTE-' + $capturedRoutePositive.policy.ToUpperInvariant() +
        '-EXACT-ONE-' + $capturedRoutePositive.family.ToUpperInvariant()) `
        -Category 'route_policy' -Body {
        $value = Get-I03OfflineRouteDecision `
            -Policy $capturedRoutePositive.policy `
            -Rows @([pscustomobject]@{
                family = $capturedRoutePositive.family
            }) -SocketProofs @(New-I03OfflineSocketProof) `
            -StableSeconds 5 -RequiredStableSeconds 5
        Assert-I03Offline -Condition (
            [string]$value.status -ceq 'PASS' -and
            [string]$value.code -ceq 'NONE' -and
            [string]$value.expected_family -ceq
                [string]$capturedRoutePositive.family -and
            [bool]$value.product_match) `
            -Code 'EXACT_ROUTE_POLICY_MATCH_REJECTED'
    }
}

Invoke-I03OfflineTest -Id `
    'ROUTE-HISTORICAL-WRONG-FAMILY-NOT-DUPLICATE' `
    -Category 'route_policy' -Body {
    $value = Get-I03OfflineRouteDecision -Policy auto `
        -Rows @([pscustomobject]@{ family = 'IPv4' }) `
        -SocketProofs @(New-I03OfflineSocketProof) `
        -StableSeconds 5 -RequiredStableSeconds 5 `
        -AmbiguousSelection $false -WrongFamilyObserved $true
    Assert-I03Offline -Condition (
        [string]$value.status -ceq 'PRODUCT_INVARIANT' -and
        [string]$value.code -ceq 'WRONG_FAMILY' -and
        -not [bool]$value.product_match) `
        -Code 'SINGLE_WRONG_FAMILY_MISCLASSIFIED_AS_DUPLICATE'
}

Invoke-I03OfflineTest -Id `
    'ROUTE-DUPLICATE-PRECEDES-WRONG-FAMILY-HISTORY' `
    -Category 'route_policy' -Body {
    $value = Get-I03OfflineRouteDecision -Policy auto `
        -Rows @([pscustomobject]@{ family = 'IPv4' }) `
        -SocketProofs @(New-I03OfflineSocketProof) `
        -StableSeconds 5 -RequiredStableSeconds 5 `
        -AmbiguousSelection $true -WrongFamilyObserved $true
    Assert-I03Offline -Condition (
        [string]$value.status -ceq 'PRODUCT_INVARIANT' -and
        [string]$value.code -ceq 'DUPLICATE_ROUTE' -and
        -not [bool]$value.product_match) `
        -Code 'DUPLICATE_ROUTE_DID_NOT_PRECEDE_WRONG_FAMILY_HISTORY'
}

Invoke-I03OfflineTest -Id `
    'ROUTE-ACTIVE-ESTABLISHED-PLUS-SYNSENT-DUPLICATE' `
    -Category 'route_policy' -Body {
    $rows = @(
        [pscustomobject]@{ family = 'IPv4'; state = 'Established' },
        [pscustomobject]@{ family = 'IPv4'; state = 'SynSent' }
    )
    $value = Get-I03OfflineRouteDecision -Policy auto -Rows $rows `
        -SocketProofs @(
            (New-I03OfflineSocketProof),
            (New-I03OfflineSocketProof)) `
        -StableSeconds 5 -RequiredStableSeconds 5
    Assert-I03Offline -Condition (
        [string]$value.status -ceq 'PRODUCT_INVARIANT' -and
        [string]$value.code -ceq 'DUPLICATE_ROUTE' -and
        -not [bool]$value.product_match) `
        -Code 'ESTABLISHED_PLUS_SYNSENT_NOT_DUPLICATE_ROUTE'
}

$routeDecisionCases = @(
    [pscustomobject]@{ id = 'COLLECTOR-FAIL'; policy = 'auto'
        collector = $false; fixture = $true; families = @('IPv4')
        socket = 'good'; stable = 5.0; contamination = $false
        ambiguous = $false; status = 'LAB_BLOCKED'
        code = 'COLLECTOR_UNAVAILABLE' },
    [pscustomobject]@{ id = 'UNCERTIFIED'; policy = 'auto'
        collector = $true; fixture = $false; families = @('IPv4')
        socket = 'good'; stable = 5.0; contamination = $false
        ambiguous = $false; status = 'LAB_BLOCKED'
        code = 'EVIDENCE_INCOMPLETE' },
    [pscustomobject]@{ id = 'CONTAMINATION'; policy = 'auto'
        collector = $true; fixture = $true; families = @('IPv4')
        socket = 'good'; stable = 5.0; contamination = $true
        ambiguous = $false; status = 'LAB_BLOCKED'
        code = 'EXTERNAL_CONTAMINATION' },
    [pscustomobject]@{ id = 'AMBIGUOUS-SELECTION'; policy = 'auto'
        collector = $true; fixture = $true; families = @('IPv4')
        socket = 'good'; stable = 5.0; contamination = $false
        ambiguous = $true; status = 'PRODUCT_INVARIANT'
        code = 'DUPLICATE_ROUTE' },
    [pscustomobject]@{ id = 'NO-ROUTE'; policy = 'auto'
        collector = $true; fixture = $true; families = @()
        socket = 'good'; stable = 5.0; contamination = $false
        ambiguous = $false; status = 'PRODUCT_INVARIANT'
        code = 'NO_ROUTE' },
    [pscustomobject]@{ id = 'DUPLICATE'; policy = 'auto'
        collector = $true; fixture = $true
        families = @('IPv4', 'IPv4'); socket = 'good'; stable = 5.0
        contamination = $false; ambiguous = $false
        status = 'PRODUCT_INVARIANT'; code = 'DUPLICATE_ROUTE' },
    [pscustomobject]@{ id = 'AUTO-WRONG-FAMILY'; policy = 'auto'
        collector = $true; fixture = $true; families = @('IPv6')
        socket = 'good'; stable = 5.0; contamination = $false
        ambiguous = $false; status = 'PRODUCT_INVARIANT'
        code = 'WRONG_FAMILY' },
    [pscustomobject]@{ id = 'PREFERRED-WRONG-FAMILY'; policy = 'preferred'
        collector = $true; fixture = $true; families = @('IPv4')
        socket = 'good'; stable = 5.0; contamination = $false
        ambiguous = $false; status = 'PRODUCT_INVARIANT'
        code = 'WRONG_FAMILY' },
    [pscustomobject]@{ id = 'SOCKET-COLLECTOR-AMBIGUOUS'; policy = 'auto'
        collector = $true; fixture = $true; families = @('IPv4')
        socket = 'collector-bad'; stable = 5.0; contamination = $false
        ambiguous = $false; status = 'LAB_BLOCKED'
        code = 'COLLECTOR_AMBIGUOUS' },
    [pscustomobject]@{ id = 'SOCKET-NULL'; policy = 'auto'
        collector = $true; fixture = $true; families = @('IPv4')
        socket = 'null'; stable = 5.0; contamination = $false
        ambiguous = $false; status = 'LAB_BLOCKED'
        code = 'COLLECTOR_AMBIGUOUS' },
    [pscustomobject]@{ id = 'STALE-TUPLE'; policy = 'auto'
        collector = $true; fixture = $true; families = @('IPv4')
        socket = 'stale'; stable = 5.0; contamination = $false
        ambiguous = $false; status = 'PRODUCT_INVARIANT'
        code = 'WRONG_OR_NONPHYSICAL_SOCKET' },
    [pscustomobject]@{ id = 'WRONG-PID'; policy = 'auto'
        collector = $true; fixture = $true; families = @('IPv4')
        socket = 'wrong-pid'; stable = 5.0; contamination = $false
        ambiguous = $false; status = 'PRODUCT_INVARIANT'
        code = 'WRONG_OR_NONPHYSICAL_SOCKET' },
    [pscustomobject]@{ id = 'MISSING-SOCKET-PROOF'; policy = 'auto'
        collector = $true; fixture = $true; families = @('IPv4')
        socket = 'none'; stable = 5.0; contamination = $false
        ambiguous = $false; status = 'PRODUCT_INVARIANT'
        code = 'WRONG_OR_NONPHYSICAL_SOCKET' },
    [pscustomobject]@{ id = 'SHORT-STABLE'; policy = 'auto'
        collector = $true; fixture = $true; families = @('IPv4')
        socket = 'good'; stable = 4.999; contamination = $false
        ambiguous = $false; status = 'PRODUCT_INVARIANT'
        code = 'NO_ROUTE' }
)
foreach ($routeDecisionCase in $routeDecisionCases) {
    $capturedRoute = $routeDecisionCase
    Invoke-I03OfflineTest -Id ('ROUTE-' + $capturedRoute.id) `
        -Category 'route_policy' -Body {
        $rows = @($capturedRoute.families | ForEach-Object {
            [pscustomobject]@{ family = [string]$_ }
        })
        [object[]]$sockets = @()
        switch ([string]$capturedRoute.socket) {
            'none' { $sockets = [object[]]@() }
            'null' { $sockets = [object[]](,$null) }
            'collector-bad' {
                $proof = New-I03OfflineSocketProof
                $proof.collector_ok = $false
                $sockets = [object[]](,$proof)
            }
            'stale' {
                $proof = New-I03OfflineSocketProof
                $proof.tuple_current_exact = $false
                $sockets = [object[]](,$proof)
            }
            'wrong-pid' {
                $proof = New-I03OfflineSocketProof
                $proof.pid_matches = $false
                $sockets = [object[]](,$proof)
            }
            default {
                $sockets = [object[]](,(New-I03OfflineSocketProof))
            }
        }
        $value = Get-I03OfflineRouteDecision `
            -Policy ([string]$capturedRoute.policy) `
            -CollectorOk ([bool]$capturedRoute.collector) `
            -FixtureCertified ([bool]$capturedRoute.fixture) `
            -Rows $rows -SocketProofs $sockets `
            -StableSeconds ([double]$capturedRoute.stable) `
            -Contamination ([bool]$capturedRoute.contamination) `
            -AmbiguousSelection ([bool]$capturedRoute.ambiguous) `
            -RequiredStableSeconds 5
        Assert-I03Offline -Condition (
            [string]$value.status -ceq [string]$capturedRoute.status -and
            [string]$value.code -ceq [string]$capturedRoute.code -and
            -not [bool]$value.product_match) `
            -Code 'ROUTE_DECISION_MATRIX_MISMATCH'
    }
}

Invoke-I03OfflineTest -Id 'ROUTE-POLICY-RUNTIME-WIRING-STATIC' `
    -Category 'route_policy' -Body {
    $text = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Invoke-I03CoordinatorRole'
    }, $true))[0].Extent.Text
    $autoOffset = $text.IndexOf("name = 'auto'")
    $preferredOffset = $text.IndexOf("name = 'preferred'")
    $decisionOffset = $text.IndexOf('Get-I03RouteSelectionDecision')
    Assert-I03Offline -Condition (
        $autoOffset -ge 0 -and $preferredOffset -gt $autoOffset -and
        $text.IndexOf('mode = 1', $autoOffset) -gt $autoOffset -and
        $text.IndexOf("expected_family = 'IPv4'", $autoOffset) -gt
            $autoOffset -and
        $text.IndexOf('mode = 2', $preferredOffset) -gt $preferredOffset -and
        $text.IndexOf("expected_family = 'IPv6'", $preferredOffset) -gt
            $preferredOffset -and
        $decisionOffset -gt $preferredOffset -and
        $text.Contains('-Rows $observedConnections') -and
        $text.Contains('-SocketProofs @($decisionSocketProofs)') -and
        $text.Contains('$routeDecision.status -ceq ''LAB_BLOCKED''') -and
        $text.Contains('$routeDecision.status -ceq') -and
        $text.Contains("'PRODUCT_INVARIANT'") -and
        $text.Contains('$routeDecision.product_match')) `
        -Code 'ROUTE_POLICY_RUNTIME_NOT_BOUND_TO_PURE_DECISION'
}

Invoke-I03OfflineTest -Id `
    'ROUTE-WRONG-HISTORY-NOT-AMBIGUITY-WIRING-STATIC' `
    -Category 'route_policy' -Body {
    $coordinatorAst = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Invoke-I03CoordinatorRole'
    }, $true))[0]
    $decisionCalls = @($coordinatorAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.CommandAst] -and
            $node.GetCommandName() -ceq 'Get-I03RouteSelectionDecision'
    }, $true))
    Assert-I03Offline -Condition ($decisionCalls.Count -eq 1) `
        -Code 'ROUTE_DECISION_CALL_NOT_UNIQUE'
    $callText = $decisionCalls[0].Extent.Text
    $ambiguousOffset = $callText.IndexOf('-AmbiguousSelection')
    $wrongFamilyOffset = $callText.IndexOf(
        '-WrongFamilyObserved', $ambiguousOffset + 1)
    $ambiguousText = if ($ambiguousOffset -ge 0 -and
        $wrongFamilyOffset -gt $ambiguousOffset) {
        $callText.Substring(
            $ambiguousOffset, $wrongFamilyOffset - $ambiguousOffset)
    } else { '' }
    $wrongFamilyText = if ($wrongFamilyOffset -ge 0) {
        $callText.Substring($wrongFamilyOffset)
    } else { '' }
    Assert-I03Offline -Condition (
        $ambiguousOffset -ge 0 -and $wrongFamilyOffset -gt $ambiguousOffset -and
        $ambiguousText.Contains('ambiguous_family_selection') -and
        $ambiguousText.Contains('duplicate_target_observation_count') -and
        -not $ambiguousText.Contains('wrong_family_observation_count') -and
        $wrongFamilyText.Contains('wrong_family_observation_count')) `
        -Code 'WRONG_FAMILY_HISTORY_COLLAPSED_TO_DUPLICATE_ROUTE'
}

Invoke-I03OfflineTest -Id 'ROUTE-ACTIVE-UNIQUENESS-WIRING-STATIC' `
    -Category 'route_policy' -Body {
    foreach ($functionName in @(
        'Wait-I03Prewarm', 'Wait-I03PostRestartRoute')) {
        $text = @($script:HarnessAst.FindAll({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] `
                -and $node.Name -ceq $functionName
        }, $true))[0].Extent.Text
        $activePattern = '(?s)\[int\]\$_\.owning_process\s+-eq\s+' +
            '\$Process\.Id.{0,280}\[string\]\$_\.state\s+-in\s+' +
            "@\('SynSent',\s*'Established'\)"
        $activeFilters = @([regex]::Matches($text, $activePattern))
        $finalOffset = $text.IndexOf('$finalConnections')
        Assert-I03Offline -Condition (
            $activeFilters.Count -ge 2 -and $finalOffset -ge 0 -and
            [regex]::IsMatch(
                $text.Substring($finalOffset), $activePattern) -and
            $text -match '(?i)(ambiguous|duplicate)' -and
            $text -match '\.Count\s+-(gt|ne)\s+1') `
            -Code 'ACTIVE_CANDIDATE_UNIQUENESS_NOT_ENFORCED'
    }
}

Invoke-I03OfflineTest -Id 'TOPOLOGY-RUNTIME-WIRING-STATIC' `
    -Category 'topology_contract' -Body {
    $text = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Invoke-I03CoordinatorRole'
    }, $true))[0].Extent.Text
    Assert-I03Offline -Condition (
        $text.Contains('Get-I03TopologyDecision') -and
        $text.Contains('-DifferentMachineIdentities') -and
        $text.Contains('-SameIPv4PhysicalPrefix') -and
        $text.Contains('-SameIPv6PhysicalPrefix') -and
        $text.Contains('-IPv6OnLink') -and
        $text.Contains('-NativeIPv4') -and
        $text.Contains('-NativeIPv6') -and
        $text.Contains('-PhysicalSingleAdapter') -and
        $text.Contains('-OverlayDetected') -and
        $text.Contains('-RoutedNativeIPv6') -and
        $text.Contains('$topologyDecision.status -ceq ''PASS''') -and
        $text.Contains('Stop-I03Fixture -Code ''TOPOLOGY''')) `
        -Code 'TOPOLOGY_RUNTIME_NOT_BOUND_TO_PURE_DECISION'
}

Invoke-I03OfflineTest -Id 'MACHINE-IDENTITY-FAIL-CLOSED-STATIC' `
    -Category 'topology_contract' -Body {
    $identityMatches = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Get-I03MachineIdentityEvidence'
    }, $true))
    Assert-I03Offline -Condition ($identityMatches.Count -eq 1) `
        -Code 'MACHINE_IDENTITY_COLLECTOR_NOT_UNIQUE'
    $identityText = $identityMatches[0].Extent.Text
    foreach ($needle in @(
        "'HKLM:\SOFTWARE\Microsoft\Cryptography'",
        '-Name MachineGuid', '-ErrorAction Stop',
        '[string]::IsNullOrWhiteSpace($machineGuid)',
        'Get-CimInstance -ClassName Win32_ComputerSystem',
        '[string]::IsNullOrWhiteSpace',
        'machine_id_sha256 = Get-LabStringSha256 -Value $machineGuid',
        "source = 'HKLM_MACHINEGUID_AND_WIN32_COMPUTERSYSTEM'",
        "throw 'I03_COLLECTOR::MACHINE_ID_QUERY_FAILED'")) {
        Assert-I03Offline -Condition ($identityText.Contains($needle)) `
            -Code 'MACHINE_IDENTITY_FAIL_CLOSED_CONTRACT_MISSING'
    }
    Assert-I03Offline -Condition (
        -not $identityText.Contains('$env:COMPUTERNAME') -and
        -not $identityText.Contains('OSVersion') -and
        -not $identityText.Contains('machine_guid =')) `
        -Code 'MACHINE_IDENTITY_FALLBACK_OR_RAW_GUID_FOUND'
}

Invoke-I03OfflineTest -Id 'PHYSICAL-HOST-VM-DENYLIST-STATIC' `
    -Category 'topology_contract' -Body {
    $identityText = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Get-I03MachineIdentityEvidence'
    }, $true))[0].Extent.Text.ToLowerInvariant()
    foreach ($needle in @(
        'vmware', 'virtualbox', 'vbox', 'parallels', 'qemu', 'virtio',
        'xen', 'hyper-v', 'virtual machine')) {
        Assert-I03Offline -Condition ($identityText.Contains($needle)) `
            -Code 'PHYSICAL_HOST_VM_SIGNATURE_MISSING'
    }
    Assert-I03Offline -Condition (
        $identityText.Contains('virtual_signature_detected') -and
        $identityText.Contains('physical_host_claim = -not $virtualsignature')) `
        -Code 'PHYSICAL_HOST_CLAIM_NOT_FAIL_CLOSED'

    foreach ($roleName in @(
        'Invoke-I03CoordinatorRole', 'Invoke-I03PeerRole')) {
        $roleText = @($script:HarnessAst.FindAll({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] `
                -and $node.Name -ceq $roleName
        }, $true))[0].Extent.Text
        Assert-I03Offline -Condition (
            $roleText.Contains('Get-I03MachineIdentityEvidence') -and
            $roleText.Contains('physical_host_claim') -and
            $roleText.Contains('virtual_signature_detected') -and
            $roleText.Contains("StartsWith('I03_COLLECTOR::')") -and
            $roleText.Contains("Code 'COLLECTOR_UNAVAILABLE'")) `
            -Code 'ROLE_MACHINE_IDENTITY_NOT_TYPED_OR_NOT_GATED'
    }
}

Invoke-I03OfflineTest -Id 'PORTS-NINE-UNIQUE-STATIC' `
    -Category 'startup_contract' -Body {
    foreach ($portName in @(
        'PeerTcpPort', 'PeerUdpPort', 'PeerWebPort', 'AutoTcpPort',
        'AutoUdpPort', 'AutoWebPort', 'PreferredTcpPort',
        'PreferredUdpPort', 'PreferredWebPort')) {
        Assert-I03Offline -Condition (
            $script:HarnessText -match ('\$' + $portName + '\b')) `
            -Code 'PORT_PARAMETER_MISSING'
    }
    Assert-I03Offline -Condition (
        $script:HarnessText -match
            '\$allPorts\s*=\s*@\(' -and
        $script:HarnessText -match
            'Sort-Object\s+-Unique\)\.Count\s+-ne\s+\$allPorts\.Count') `
        -Code 'NINE_PORT_UNIQUENESS_GUARD_MISSING'
}

Invoke-I03OfflineTest -Id 'PORT-CENSUS-ANY-TCP-STATE-STATIC' `
    -Category 'startup_contract' -Body {
    $matches = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Test-I03PortSetFree'
    }, $true))
    Assert-I03Offline -Condition ($matches.Count -eq 1) `
        -Code 'PORT_CENSUS_FUNCTION_NOT_UNIQUE'
    $text = $matches[0].Extent.Text
    Assert-I03Offline -Condition (
        $text.Contains('Get-NetTCPConnection -ErrorAction Stop') -and
        $text.Contains('Get-NetUDPEndpoint -ErrorAction Stop') -and
        $text.Contains('[int]$_.LocalPort -eq $port') -and
        -not $text.Contains('[string]$_.State') -and
        -not $text.Contains("State -eq 'Listen'")) `
        -Code 'PORT_CENSUS_IGNORES_NON_LISTEN_TCP_STATE'
}

Invoke-I03OfflineTest -Id 'CONTROL-SERVER-DYNAMIC-PORT-COLLISION-GUARD-STATIC' `
    -Category 'startup_contract' -Body {
    $serverMatches = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Start-I03ControlledEd2kServer'
    }, $true))
    Assert-I03Offline -Condition ($serverMatches.Count -eq 1) `
        -Code 'CONTROL_SERVER_FUNCTION_NOT_UNIQUE'
    $serverText = $serverMatches[0].Extent.Text
    Assert-I03Offline -Condition (
        $serverText.Contains('[int[]]$ForbiddenPorts') -and
        ($serverText.Contains('$ForbiddenPorts -contains $port') -or
            $serverText.Contains('$port -in $ForbiddenPorts') -or
            $serverText.Contains('$forbidden.Contains($candidatePort)')) -and
        ($serverText.Contains('$listener.Stop()') -or
            $serverText.Contains('$listener.Dispose()') -or
            $serverText.Contains('$candidateListener.Stop()') -or
            $serverText.Contains('$candidateListener.Dispose()')) -and
        ($serverText.Contains('MaxBindAttempts') -or
            $serverText.Contains('BindAttempts') -or
            $serverText -match '(?i)for\s*\(') -and
        $serverText.Contains(
            'I03_PORT_ALLOCATION::NO_NONCOLLIDING_PORT')) `
        -Code 'CONTROL_SERVER_DYNAMIC_PORT_REJECTION_NOT_BOUNDED'

    $coordinatorText = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Invoke-I03CoordinatorRole'
    }, $true))[0].Extent.Text
    $serverOffset = $coordinatorText.IndexOf(
        'Start-I03ControlledEd2kServer')
    $forbiddenOffset = $coordinatorText.IndexOf(
        '-ForbiddenPorts', $serverOffset + 1)
    $listenerCensusOffset = $coordinatorText.IndexOf(
        'Get-NetTCPConnection -ErrorAction Stop', $serverOffset + 1)
    $listenerRowsOffset = $coordinatorText.IndexOf(
        '$serverListeners =', $listenerCensusOffset)
    $listenerCountOffset = $coordinatorText.IndexOf(
        '$serverListeners.Count -ne 1', $listenerRowsOffset)
    $recheckOffset = $coordinatorText.IndexOf(
        'Wait-I03PortSetFree', $listenerCountOffset)
    $certifiedOffset = $coordinatorText.IndexOf(
        '$currentFixtureCertified = $true', $serverOffset + 1)
    Assert-I03Offline -Condition (
        $serverOffset -ge 0 -and
        $forbiddenOffset -gt $serverOffset -and
        $coordinatorText.IndexOf(
            '@($allPorts)', $forbiddenOffset) -gt $forbiddenOffset -and
        $coordinatorText.IndexOf(
            '$controlledServerPorts', $forbiddenOffset) -gt
                $forbiddenOffset -and
        $coordinatorText.IndexOf(
            '$activeServer.port', $serverOffset) -gt $serverOffset -and
        $listenerCensusOffset -gt $serverOffset -and
        $listenerRowsOffset -gt $listenerCensusOffset -and
        $coordinatorText.IndexOf(
            '[int]$_.LocalPort -eq $activeServer.port',
            $listenerRowsOffset) -gt $listenerRowsOffset -and
        $coordinatorText.IndexOf(
            '[int]$_.OwningProcess -eq $PID',
            $listenerRowsOffset) -gt $listenerRowsOffset -and
        $listenerCountOffset -gt $listenerRowsOffset -and
        $recheckOffset -gt $listenerCountOffset -and
        $coordinatorText.IndexOf(
            '-Ports $allPorts', $recheckOffset) -gt $recheckOffset -and
        $certifiedOffset -gt $recheckOffset) `
        -Code 'CONTROL_SERVER_PORT_NOT_REVALIDATED_BEFORE_CERTIFICATION'
}

Invoke-I03OfflineTest -Id 'STARTUP-INI-EXACT-POSITIVE' `
    -Category 'startup_contract' -Body {
    $path = Join-Path $script:TempRoot 'valid-preferences.ini'
    [IO.File]::WriteAllText(
        $path, (Get-I03OfflineValidPreferencesText),
        [Text.UTF8Encoding]::new($false))
    $expectations = @(
        @('eMule', 'OpenPortsOnStartUp', '0'),
        @('eMule', 'AutoTakeED2KLinks', '0'),
        @('eMule', 'WatchClipboard4ED2kFilelinks', '0'),
        @('eMule', 'AutoStart', '0'),
        @('eMule', 'NetworkKademlia', '0'),
        @('eMule', 'Serverlist', '0'),
        @('eMule', 'AddServersFromServer', '0'),
        @('eMule', 'AddServersFromClient', '0'),
        @('Connection', 'IPv6Mode', '1'),
        @('Connection', 'IPv6BindAddr', '2001:4860:4860::10'),
        @('Connection', 'KadNetworkMask', '0'),
        @('Connection', 'NetworkED2K', '0'),
        @('Connection', 'CryptLayerRequested', '0'),
        @('Connection', 'CryptLayerRequired', '0'),
        @('Connection', 'CryptLayerSupported', '0'),
        @('eSE', 'EseNetLabConsent', '1'),
        @('eSE', 'EseNetLabAdvancedConsent', '1'),
        @('eSE', 'EseNetLabContributionConsent', '1'),
        @('eSE', 'EseNetLabEnabled', '0'),
        @('eSE', 'EseV9Experimental', '0'),
        @('eSE', 'EnableUtpHolePunch', '0'),
        @('eSE', 'EseAutoKeepalive', '0'),
        @('eSE', 'EseKad3Rendezvous', '0'),
        @('eSE', 'EseReachSelector', '0'),
        @('eSE', 'EseHolePunchPortPredict', '0'),
        @('eSE', 'EseEd2kPunch3', '0'),
        @('eSE', 'EseRelayAccept', '0'),
        @('eSE', 'EseRelayEgress', '0'),
        @('eSE', 'Kad6BetaExitOptIn', '0'),
        @('Proxy', 'ProxyEnableProxy', '0'),
        @('UPnP', 'EnableUPnP', '0'),
        @('WebServer', 'Enabled', '1'),
        @('WebServer', 'Port', '9611'),
        @('WebServer', 'AllowedIPs', '127.0.0.1'),
        @('WebServer', 'WebUseUPnP', '0'))
    foreach ($row in $expectations) {
        $check = Invoke-I03PureScope `
            -FunctionNames @('Get-I03IniExactValueEvidence') -Body {
            param($preferencesPath, $section, $key, $expectedValue)
            Get-I03IniExactValueEvidence -Path $preferencesPath `
                -Section $section -Key $key -Expected $expectedValue
        } -ArgumentList @(
            $path, [string]$row[0], [string]$row[1], [string]$row[2])
        if (-not [bool]$check.exact) {
            throw ('VALID_INI_FIELD_' +
                ([string]$row[1]).ToUpperInvariant())
        }
    }
    Assert-I03Offline -Condition (
        Test-I03OfflinePreferenceFile -Path $path) `
        -Code 'VALID_PREFERENCE_CONTRACT_REJECTED'
}

Invoke-I03OfflineTest -Id 'STARTUP-INI-DUPLICATE-KEY-REJECTED' `
    -Category 'startup_contract' -Body {
    $path = Join-Path $script:TempRoot 'duplicate-key.ini'
    $text = (Get-I03OfflineValidPreferencesText).Replace(
        "OpenPortsOnStartUp=0`n", "OpenPortsOnStartUp=0`n" +
        "OpenPortsOnStartUp=1`n")
    [IO.File]::WriteAllText($path, $text, [Text.UTF8Encoding]::new($false))
    Assert-I03Offline -Condition (-not (
        Test-I03OfflinePreferenceFile -Path $path)) `
        -Code 'DUPLICATE_INI_KEY_ACCEPTED'
}

Invoke-I03OfflineTest -Id 'STARTUP-INI-CASE-VARIANT-REJECTED' `
    -Category 'startup_contract' -Body {
    $path = Join-Path $script:TempRoot 'case-variant-key.ini'
    $text = (Get-I03OfflineValidPreferencesText).Replace(
        "OpenPortsOnStartUp=0`n", "OpenPortsOnStartUp=0`n" +
        "openportsonstartup=1`n")
    [IO.File]::WriteAllText($path, $text, [Text.UTF8Encoding]::new($false))
    Assert-I03Offline -Condition (-not (
        Test-I03OfflinePreferenceFile -Path $path)) `
        -Code 'CASE_VARIANT_INI_KEY_ACCEPTED'
}

Invoke-I03OfflineTest -Id 'STARTUP-INI-DUPLICATE-SECTION-REJECTED' `
    -Category 'startup_contract' -Body {
    $path = Join-Path $script:TempRoot 'duplicate-section.ini'
    $text = (Get-I03OfflineValidPreferencesText) +
        "`n[eMule]`nOpenPortsOnStartUp=0`n"
    [IO.File]::WriteAllText($path, $text, [Text.UTF8Encoding]::new($false))
    Assert-I03Offline -Condition (-not (
        Test-I03OfflinePreferenceFile -Path $path)) `
        -Code 'DUPLICATE_INI_SECTION_ACCEPTED'
}

Invoke-I03OfflineTest -Id 'STARTUP-KEYS-BEFORE-FIRST-LAUNCH' `
    -Category 'startup_contract' -Body {
    $preferenceText = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Set-I03IsolatedPreferences'
    }, $true))[0].Extent.Text
    foreach ($key in @(
        'OpenPortsOnStartUp', 'AutoTakeED2KLinks',
        'WatchClipboard4ED2kFilelinks', 'AutoStart')) {
        Assert-I03Offline -Condition (
            $preferenceText -match (
                [regex]::Escape($key) + "\s*=\s*'0'")) `
            -Code 'REQUIRED_STARTUP_ZERO_MISSING'
    }
    foreach ($roleName in @('Invoke-I03PeerRole', 'Invoke-I03CoordinatorRole')) {
        $roleAst = @($script:HarnessAst.FindAll({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -ceq $roleName
        }, $true))[0]
        $directCommands = @($roleAst.FindAll({
            param($node)
            if ($node -isnot [Management.Automation.Language.CommandAst]) {
                return $false
            }
            $parent = $node.Parent
            while ($null -ne $parent -and
                $parent -isnot
                    [Management.Automation.Language.FunctionDefinitionAst]) {
                $parent = $parent.Parent
            }
            return $parent -eq $roleAst
        }, $true))
        $config = @($directCommands | Where-Object {
                $_.GetCommandName() -ceq 'Set-I03IsolatedPreferences'
            } | Sort-Object { $_.Extent.StartOffset } | Select-Object -First 1)
        $launchNames = if ($roleName -ceq 'Invoke-I03PeerRole') {
            @('Start-I03PeerSource')
        } else { @('Start-Process') }
        $launch = @($directCommands | Where-Object {
                $launchNames -ccontains $_.GetCommandName()
            } | Sort-Object { $_.Extent.StartOffset } | Select-Object -First 1)
        Assert-I03Offline -Condition (
            $config.Count -eq 1 -and $launch.Count -eq 1 -and
            $config[0].Extent.EndOffset -lt $launch[0].Extent.StartOffset) `
            -Code 'PREFERENCES_NOT_PROVEN_BEFORE_FIRST_LAUNCH'
    }
}

Invoke-I03OfflineTest -Id 'STARTUP-DISPOSABLE-ACCOUNT-GATE' `
    -Category 'startup_contract' -Body {
    $top = $script:HarnessAst.ParamBlock.Extent.Text
    Assert-I03Offline -Condition (
        $top -match '\[Parameter\(Mandatory\s*=\s*\$true\)\]\[switch\]' +
            '\$DisposableLabAccountAcknowledged' -and
        $top -match '\$ExpectedLabUserSidSha256' -and
        $top -match "ValidatePattern\('\^\[0-9a-fA-F\]\{64\}\$'\)") `
        -Code 'DISPOSABLE_ACCOUNT_PARAMETERS_NOT_STRICT'
    Assert-I03Offline -Condition (
        $script:HarnessText -match
            'WindowsIdentity\]::GetCurrent\(\)\.User\.Value' -and
        $script:HarnessText -match
            '\$currentLabSidHash\s+-cne\s+\$expectedLabSidHash') `
        -Code 'LAB_ACCOUNT_SID_NOT_BOUND'
}

Invoke-I03OfflineTest -Id 'STARTUP-MUTATION-BASELINE-BEFORE-LAUNCH' `
    -Category 'cleanup_contract' -Body {
    foreach ($roleName in @('Invoke-I03PeerRole', 'Invoke-I03CoordinatorRole')) {
        $roleAst = @($script:HarnessAst.FindAll({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -ceq $roleName
        }, $true))[0]
        $direct = @($roleAst.FindAll({
            param($node)
            if ($node -isnot [Management.Automation.Language.CommandAst]) {
                return $false
            }
            $parent = $node.Parent
            while ($null -ne $parent -and
                $parent -isnot
                    [Management.Automation.Language.FunctionDefinitionAst]) {
                $parent = $parent.Parent
            }
            return $parent -eq $roleAst
        }, $true))
        $baseline = @($direct | Where-Object {
                $_.GetCommandName() -ceq 'Get-I03MutationBaseline'
            } | Sort-Object { $_.Extent.StartOffset } | Select-Object -First 1)
        $configuration = @($direct | Where-Object {
                $_.GetCommandName() -ceq 'Set-I03IsolatedPreferences'
            } | Sort-Object { $_.Extent.StartOffset } | Select-Object -First 1)
        Assert-I03Offline -Condition (
            $baseline.Count -eq 1 -and $configuration.Count -eq 1 -and
            $baseline[0].Extent.EndOffset -lt
                $configuration[0].Extent.StartOffset) `
            -Code 'MUTATION_BASELINE_NOT_BEFORE_PROFILE_WRITE'
    }
}

Invoke-I03OfflineTest -Id 'STARTUP-MANUAL-COMMAND-ACCOUNT-PARAMS' `
    -Category 'startup_contract' -Body {
    Assert-I03Offline -Condition (
        $script:HarnessText -match
            "-DisposableLabAccountAcknowledged\s+````" -and
        $script:HarnessText -match
            "-ExpectedLabUserSidSha256\s+'<peer-current-user-sid-sha256>'") `
        -Code 'MANUAL_COMMAND_OMITS_ACCOUNT_BINDING'
}

Invoke-I03OfflineTest -Id 'REGISTRY-DATA-TYPES' `
    -Category 'cleanup_contract' -Body {
    $values = Invoke-I03PureScope `
        -FunctionNames @('ConvertTo-I03RegistryDataProjection') -Body {
        @(
            (ConvertTo-I03RegistryDataProjection `
                -Value ([byte[]](0, 1, 255)) -Kind Binary),
            (ConvertTo-I03RegistryDataProjection `
                -Value ([string[]]@('one', 'two')) -Kind MultiString),
            (ConvertTo-I03RegistryDataProjection `
                -Value 'plain' -Kind String),
            (ConvertTo-I03RegistryDataProjection -Value $null -Kind String)
        )
    }
    Assert-I03Offline -Condition (
        [string]$values[0] -ceq 'AAH/' -and
        @($values[1]).Count -eq 2 -and
        [string]$values[1][0] -ceq 'one' -and
        [string]$values[2] -ceq 'plain' -and
        $null -eq $values[3]) -Code 'REGISTRY_DATA_PROJECTION_WRONG'
}

Invoke-I03OfflineTest -Id 'REGISTRY-PLAN-NOOP-UNCHANGED' `
    -Category 'cleanup_contract' -Body {
    $run = New-I03OfflineRegistryTreeState -Exists $true
    $baseline = New-I03OfflineMutationBaseline -RunKey $run
    $plan = Get-I03OfflineRegistryCleanupPlan -Baseline $baseline `
        -CurrentAutostart (New-I03OfflineRegistryValueState `
            -KeyExists $true -ValueExists $false) `
        -CurrentRunKey $run `
        -CurrentEd2k $baseline.ed2k_association
    Assert-I03Offline -Condition (
        [string]$plan.decision -ceq 'NOOP' -and
        [string]$plan.action -ceq 'NONE') `
        -Code 'REGISTRY_UNCHANGED_NOOP_WRONG'
}

Invoke-I03OfflineTest -Id 'REGISTRY-PLAN-DELETE-OWNED-VALUE' `
    -Category 'cleanup_contract' -Body {
    $baselineRun = New-I03OfflineRegistryTreeState -Exists $true
    $baseline = New-I03OfflineMutationBaseline -RunKey $baselineRun
    $target = [pscustomobject][ordered]@{
        name = 'eMuleAutoStart'; kind = 'String'; data = 'owned-candidate'
    }
    $currentRun = New-I03OfflineRegistryTreeState -Exists $true `
        -Values @($target)
    $plan = Get-I03OfflineRegistryCleanupPlan -Baseline $baseline `
        -CurrentAutostart (New-I03OfflineRegistryValueState `
            -KeyExists $true -ValueExists $true -Kind String `
            -Data 'owned-candidate') `
        -CurrentRunKey $currentRun `
        -CurrentEd2k $baseline.ed2k_association
    Assert-I03Offline -Condition (
        [string]$plan.decision -ceq 'RESTORE_OWNED_VALUE' -and
        [string]$plan.action -ceq 'DELETE_AUTOSTART_VALUE') `
        -Code 'REGISTRY_OWNED_VALUE_PLAN_WRONG'
}

$unownedAutostartCases = @(
    [pscustomobject]@{
        id = 'ARBITRARY-DATA'; kind = 'String'; data = 'not-owned'
    },
    [pscustomobject]@{
        id = 'WRONG-KIND'; kind = 'ExpandString'; data = 'owned-candidate'
    }
)
foreach ($unownedAutostart in $unownedAutostartCases) {
    $capturedAutostart = $unownedAutostart
    Invoke-I03OfflineTest -Id (
        'REGISTRY-PLAN-' + $capturedAutostart.id + '-BLOCKED') `
        -Category 'cleanup_contract' -Body {
        $baselineRun = New-I03OfflineRegistryTreeState -Exists $true
        $baseline = New-I03OfflineMutationBaseline -RunKey $baselineRun
        $target = [pscustomobject][ordered]@{
            name = 'eMuleAutoStart'
            kind = [string]$capturedAutostart.kind
            data = [string]$capturedAutostart.data
        }
        $currentRun = New-I03OfflineRegistryTreeState -Exists $true `
            -Values @($target)
        $plan = Get-I03OfflineRegistryCleanupPlan -Baseline $baseline `
            -CurrentAutostart (New-I03OfflineRegistryValueState `
                -KeyExists $true -ValueExists $true `
                -Kind ([string]$capturedAutostart.kind) `
                -Data ([string]$capturedAutostart.data)) `
            -CurrentRunKey $currentRun `
            -CurrentEd2k $baseline.ed2k_association
        Assert-I03Offline -Condition (
            [string]$plan.decision -ceq 'BLOCK_CONCURRENT' -and
            [string]$plan.action -ceq 'NONE') `
            -Code 'UNOWNED_AUTOSTART_VALUE_NOT_BLOCKED'
    }
}

Invoke-I03OfflineTest -Id 'REGISTRY-PLAN-ABSENT-BASELINE-BLOCKED' `
    -Category 'cleanup_contract' -Body {
    $baselineRun = New-I03OfflineRegistryTreeState -Exists $false
    $baseline = New-I03OfflineMutationBaseline -RunKey $baselineRun
    $plan = Get-I03OfflineRegistryCleanupPlan -Baseline $baseline `
        -CurrentAutostart (New-I03OfflineRegistryValueState `
            -KeyExists $false -ValueExists $false) `
        -CurrentRunKey $baselineRun `
        -CurrentEd2k $baseline.ed2k_association
    Assert-I03Offline -Condition (
        [string]$plan.decision -ceq 'BLOCK_BASELINE' -and
        [string]$plan.action -ceq 'NONE') `
        -Code 'REGISTRY_ABSENT_BASELINE_NOT_BLOCKED'
}

Invoke-I03OfflineTest -Id 'REGISTRY-PLAN-EXISTING-RUN-KEY' `
    -Category 'cleanup_contract' -Body {
    $unrelated = [pscustomobject][ordered]@{
        name = 'OtherApp'; kind = 'String'; data = 'preserve'
    }
    $target = [pscustomobject][ordered]@{
        name = 'eMuleAutoStart'; kind = 'String'; data = 'owned-candidate'
    }
    $baselineRun = New-I03OfflineRegistryTreeState -Exists $true `
        -Values @($unrelated)
    $baseline = New-I03OfflineMutationBaseline -RunKey $baselineRun
    $currentRun = New-I03OfflineRegistryTreeState -Exists $true `
        -Values @($unrelated, $target)
    $plan = Get-I03OfflineRegistryCleanupPlan -Baseline $baseline `
        -CurrentAutostart (New-I03OfflineRegistryValueState `
            -KeyExists $true -ValueExists $true -Kind String `
            -Data 'owned-candidate') `
        -CurrentRunKey $currentRun `
        -CurrentEd2k $baseline.ed2k_association
    Assert-I03Offline -Condition (
        [string]$plan.decision -ceq 'RESTORE_OWNED_VALUE' -and
        [string]$plan.action -ceq 'DELETE_AUTOSTART_VALUE') `
        -Code 'REGISTRY_EXISTING_KEY_PLAN_WRONG'
}

Invoke-I03OfflineTest -Id 'REGISTRY-PLAN-CONCURRENT-CONTENT-BLOCKED' `
    -Category 'cleanup_contract' -Body {
    $preserved = [pscustomobject][ordered]@{
        name = 'PreservedApp'; kind = 'String'; data = 'baseline'
    }
    $baselineRun = New-I03OfflineRegistryTreeState -Exists $true `
        -Values @($preserved)
    $baseline = New-I03OfflineMutationBaseline -RunKey $baselineRun
    $concurrent = [pscustomobject][ordered]@{
        name = 'OtherApp'; kind = 'String'; data = 'concurrent'
    }
    $currentRun = New-I03OfflineRegistryTreeState -Exists $true `
        -Values @($preserved, $concurrent)
    $plan = Get-I03OfflineRegistryCleanupPlan -Baseline $baseline `
        -CurrentAutostart (New-I03OfflineRegistryValueState `
            -KeyExists $true -ValueExists $false) `
        -CurrentRunKey $currentRun `
        -CurrentEd2k $baseline.ed2k_association
    Assert-I03Offline -Condition (
        [string]$plan.decision -ceq 'BLOCK_CONCURRENT' -and
        [string]$plan.action -ceq 'NONE') `
        -Code 'REGISTRY_CONCURRENT_CONTENT_NOT_BLOCKED'
}

Invoke-I03OfflineTest -Id 'REGISTRY-PLAN-ED2K-CHANGE-BLOCKED' `
    -Category 'cleanup_contract' -Body {
    $run = New-I03OfflineRegistryTreeState -Exists $true
    $baseline = New-I03OfflineMutationBaseline -RunKey $run
    $ed2k = New-I03OfflineRegistryTreeState -Exists $true
    $plan = Get-I03OfflineRegistryCleanupPlan -Baseline $baseline `
        -CurrentAutostart (New-I03OfflineRegistryValueState `
            -KeyExists $true -ValueExists $false) `
        -CurrentRunKey $run -CurrentEd2k $ed2k
    Assert-I03Offline -Condition (
        [string]$plan.decision -ceq 'BLOCK_CONCURRENT' -and
        [string]$plan.action -ceq 'NONE') `
        -Code 'ED2K_CONCURRENT_CHANGE_NOT_BLOCKED'
}

Invoke-I03OfflineTest -Id 'REGISTRY-PLAN-NONEMPTY-BASELINE-BLOCKED' `
    -Category 'cleanup_contract' -Body {
    $run = New-I03OfflineRegistryTreeState -Exists $true
    $baseline = New-I03OfflineMutationBaseline -RunKey $run
    $baseline.autostart = New-I03OfflineRegistryValueState `
        -KeyExists $true -ValueExists $true -Kind String -Data preexisting
    $plan = Get-I03OfflineRegistryCleanupPlan -Baseline $baseline `
        -CurrentAutostart $baseline.autostart -CurrentRunKey $run `
        -CurrentEd2k $baseline.ed2k_association
    Assert-I03Offline -Condition (
        [string]$plan.decision -ceq 'BLOCK_BASELINE' -and
        [string]$plan.action -ceq 'NONE') `
        -Code 'NONEMPTY_BASELINE_NOT_BLOCKED'
}

Invoke-I03OfflineTest -Id 'SYSTEM-STATE-IDENTICAL-POSITIVE' `
    -Category 'cleanup_contract' -Body {
    $before = New-I03OfflineSystemState
    $after = Copy-I03OfflineObject $before
    $equal = Invoke-I03PureScope `
        -FunctionNames @('Test-I03SystemStateSnapshot') -Body {
        param($left, $right)
        Test-I03SystemStateSnapshot -Before $left -After $right
    } -ArgumentList @($before, $after)
    Assert-I03Offline -Condition ([bool]$equal) `
        -Code 'IDENTICAL_SYSTEM_STATE_REJECTED'
}

$systemDigestNames = @(
    'adapters_sha256', 'adapter_bindings_sha256',
    'ip_addresses_sha256', 'ip_interfaces_sha256',
    'routes_sha256', 'dns_sha256',
    'firewall_rules_sha256', 'firewall_ports_sha256',
    'firewall_apps_sha256', 'firewall_addresses_sha256',
    'firewall_interfaces_sha256', 'firewall_interface_types_sha256',
    'firewall_services_sha256', 'firewall_security_sha256',
    'firewall_profiles_sha256', 'hosts_sha256')

Invoke-I03OfflineTest -Id 'SYSTEM-STATE-DIGEST-SCHEMA-EXACT' `
    -Category 'cleanup_contract' -Body {
    $state = New-I03OfflineSystemState
    $actual = @($state.PSObject.Properties.Name)
    $expected = @('schema') + $systemDigestNames
    Assert-I03Offline -Condition (
        $actual.Count -eq $expected.Count -and
        @($expected | Where-Object {
                $actual -cnotcontains $_
            }).Count -eq 0 -and
        [string]$state.schema -ceq
            'ese.v91.i03-forbidden-state-digests/v1') `
        -Code 'SYSTEM_STATE_DIGEST_SCHEMA_NOT_EXACT'
    $snapshotText = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Get-I03SystemStateSnapshot'
    }, $true))[0].Extent.Text
    $compareText = (Get-I03HarnessFunctionAst `
        -Name 'Test-I03SystemStateSnapshot').Extent.Text
    foreach ($name in $systemDigestNames) {
        Assert-I03Offline -Condition (
            $snapshotText.Contains($name) -and $compareText.Contains($name)) `
            -Code 'SYSTEM_STATE_DIGEST_NOT_COLLECTED_AND_COMPARED'
    }
}

$systemDigestIndex = 0
foreach ($digestName in $systemDigestNames) {
    $systemDigestIndex++
    $capturedDigestName = $digestName
    Invoke-I03OfflineTest -Id (
        'SYSTEM-STATE-MUTATION-{0:D2}' -f $systemDigestIndex) `
        -Category 'cleanup_contract' -Body {
        $before = New-I03OfflineSystemState
        $after = Copy-I03OfflineObject $before
        $after.PSObject.Properties[$capturedDigestName].Value = 'b' * 64
        $equal = Invoke-I03PureScope `
            -FunctionNames @('Test-I03SystemStateSnapshot') -Body {
            param($left, $right)
            Test-I03SystemStateSnapshot -Before $left -After $right
        } -ArgumentList @($before, $after)
        Assert-I03Offline -Condition (-not [bool]$equal) `
            -Code 'SYSTEM_STATE_MUTATION_ACCEPTED'
    }
}

Invoke-I03OfflineTest -Id 'FIREWALL-FULL-FILTER-DIGESTS-STATIC' `
    -Category 'cleanup_contract' -Body {
    $text = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Get-I03SystemStateSnapshot'
    }, $true))[0].Extent.Text
    foreach ($collector in @(
        'Get-NetAdapter', 'Get-NetAdapterBinding', 'Get-NetIPAddress',
        'Get-NetIPInterface', 'Get-NetRoute',
        'Get-NetFirewallRule', 'Get-NetFirewallPortFilter',
        'Get-NetFirewallApplicationFilter', 'Get-NetFirewallAddressFilter',
        'Get-NetFirewallInterfaceFilter',
        'Get-NetFirewallInterfaceTypeFilter',
        'Get-NetFirewallServiceFilter', 'Get-NetFirewallSecurityFilter',
        'Get-NetFirewallProfile')) {
        Assert-I03Offline -Condition ($text.Contains($collector)) `
            -Code 'FIREWALL_FILTER_COLLECTOR_MISSING'
    }
    foreach ($digest in @(
        'adapters_sha256', 'adapter_bindings_sha256',
        'ip_addresses_sha256', 'ip_interfaces_sha256',
        'routes_sha256', 'dns_sha256',
        'firewall_rules_sha256', 'firewall_ports_sha256',
        'firewall_apps_sha256', 'firewall_addresses_sha256',
        'firewall_interfaces_sha256', 'firewall_interface_types_sha256',
        'firewall_services_sha256', 'firewall_security_sha256',
        'firewall_profiles_sha256')) {
        Assert-I03Offline -Condition ($text.Contains($digest)) `
            -Code 'FIREWALL_DIGEST_FIELD_MISSING'
    }
}

Invoke-I03OfflineTest -Id 'FIREWALL-PROJECTION-DETERMINISTIC' `
    -Category 'cleanup_contract' -Body {
    $rows = @(
        [pscustomobject]@{
            InstanceID = 'b'; Name = 'second'
            RemoteAddress = @('z', 'a'); Enabled = $true
        },
        [pscustomobject]@{
            InstanceID = 'a'; Name = 'first'
            RemoteAddress = @('y', 'b'); Enabled = $false
        }
    )
    $projected = Invoke-I03PureScope `
        -FunctionNames @('Get-I03FirewallProjection') -Body {
        param($inputRows)
        @(Get-I03FirewallProjection -Rows @($inputRows) `
            -Properties @('InstanceID', 'Name', 'RemoteAddress', 'Enabled'))
    } -ArgumentList @(,$rows)
    Assert-I03Offline -Condition (
        @($projected).Count -eq 2 -and
        [string]$projected[0].InstanceID -ceq 'a' -and
        [string]$projected[1].InstanceID -ceq 'b' -and
        [string]$projected[0].Enabled -ceq 'False' -and
        [string]$projected[1].Enabled -ceq 'True' -and
        @($projected[0].RemoteAddress).Count -eq 2 -and
        [string]$projected[0].RemoteAddress[0] -ceq 'b' -and
        [string]$projected[1].RemoteAddress[0] -ceq 'a') `
        -Code 'FIREWALL_PROJECTION_NOT_DETERMINISTIC'
}

Invoke-I03OfflineTest -Id 'CLEANUP-PROOF-NOT-HARDCODED' `
    -Category 'cleanup_contract' -Body {
    $cleanupText = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Complete-I03MutationTransaction'
    }, $true))[0].Extent.Text
    Assert-I03Offline -Condition (
        $cleanupText.Contains('Test-I03SystemStateSnapshot') -and
        $cleanupText.Contains('Get-I03RegistryCleanupPlan') -and
        $script:HarnessText.Contains(
            'Get-I03TerminalSocketCleanupEvidence') -and
        $cleanupText.Contains('autostart_restored_exact') -and
        $cleanupText.Contains('ed2k_association_restored_exact') -and
        $cleanupText.Contains('forbidden_state_unchanged') -and
        $cleanupText -notmatch
            '(?m)^\s*(adapters|routes|dns|hosts|firewall)_modified\s*=\s*\$false') `
        -Code 'CLEANUP_PROOF_HARDCODED_OR_INCOMPLETE'
}

Invoke-I03OfflineTest -Id 'API-STRICT-OFFLINE-POSITIVE' `
    -Category 'api_projection' -Body {
    $data = New-I03OfflineApiFixture
    $valid = Invoke-I03PureScope -FunctionNames @(
        'Test-I03StrictJsonInteger', 'Test-I03ApiIsolation') -Body {
        param($value)
        Test-I03ApiIsolation -Data $value
    } -ArgumentList @($data)
    Assert-I03Offline -Condition ([bool]$valid) `
        -Code 'STRICT_API_FIXTURE_REJECTED'
}

Invoke-I03OfflineTest -Id 'API-STRICT-CONTROLLED-ED2K-POSITIVE' `
    -Category 'api_projection' -Body {
    $data = New-I03OfflineApiFixture -Ed2kConnected $true
    $valid = Invoke-I03PureScope -FunctionNames @(
        'Test-I03StrictJsonInteger', 'Test-I03ApiIsolation') -Body {
        param($value)
        Test-I03ApiIsolation -Data $value -AllowControlledEd2k
    } -ArgumentList @($data)
    Assert-I03Offline -Condition ([bool]$valid) `
        -Code 'CONTROLLED_ED2K_API_FIXTURE_REJECTED'
}

Invoke-I03OfflineTest -Id 'API-ED2K-EXPECTATION-EXACT' `
    -Category 'api_projection' -Body {
    $data = New-I03OfflineApiFixture -Ed2kConnected $true
    $valid = Invoke-I03PureScope -FunctionNames @(
        'Test-I03StrictJsonInteger', 'Test-I03ApiIsolation') -Body {
        param($value)
        Test-I03ApiIsolation -Data $value
    } -ArgumentList @($data)
    Assert-I03Offline -Condition (-not [bool]$valid) `
        -Code 'UNEXPECTED_ED2K_STATE_ACCEPTED'
}

$apiTypeMutations = @(
    @('upnp_critical_error', 'false'),
    @('utp_hole_punch_enabled', 0),
    @('web_upnp_active', 'false'),
    @('kad_connected', 0),
    @('kad2_running', 'false'),
    @('kad2_connected', 0),
    @('kad6_running', 'false'),
    @('kad6_connected', 0),
    @('netlab_enabled', 'false'),
    @('keepalive_running', 'false'),
    @('keepalive_running', $true),
    @('kad_configured_mask', '0'),
    @('kad_running_mask', 0.0),
    @('netlab_consent', 0),
    @('netlab_advanced_consent', 'accepted'),
    @('netlab_contribution_consent', $false),
    @('upnp_ports_forwarded', $false),
    @('ed2k_connected', 'false')
)
$apiTypeIndex = 0
foreach ($mutation in $apiTypeMutations) {
    $apiTypeIndex++
    $capturedMutation = $mutation
    Invoke-I03OfflineTest -Id ('API-TYPE-NEGATIVE-{0:D2}' -f $apiTypeIndex) `
        -Category 'api_projection' -Body {
        $data = New-I03OfflineApiFixture
        $property = $data.PSObject.Properties[[string]$capturedMutation[0]]
        $property.Value = $capturedMutation[1]
        $valid = Invoke-I03PureScope -FunctionNames @(
            'Test-I03StrictJsonInteger', 'Test-I03ApiIsolation') -Body {
            param($value)
            Test-I03ApiIsolation -Data $value
        } -ArgumentList @($data)
        Assert-I03Offline -Condition (-not [bool]$valid) `
            -Code 'API_WRONG_TYPE_OR_VALUE_ACCEPTED'
    }
}

Invoke-I03OfflineTest -Id 'API-MISSING-FIELD-REJECTED' `
    -Category 'api_projection' -Body {
    $data = New-I03OfflineApiFixture
    $data.PSObject.Properties.Remove('kad6_connected')
    $valid = Invoke-I03PureScope -FunctionNames @(
        'Test-I03StrictJsonInteger', 'Test-I03ApiIsolation') -Body {
        param($value)
        Test-I03ApiIsolation -Data $value
    } -ArgumentList @($data)
    Assert-I03Offline -Condition (-not [bool]$valid) `
        -Code 'API_MISSING_FIELD_ACCEPTED'
}

Invoke-I03OfflineTest -Id 'API-TYPED-PROJECTION-ALLOWLIST' `
    -Category 'api_projection' -Body {
    $data = New-I03OfflineApiFixture
    $projection = Invoke-I03PureScope -FunctionNames @(
        'Test-I03StrictJsonInteger', 'Test-I03ApiIsolation',
        'Get-I03ApiEvidenceProjection') -Body {
        param($value)
        Get-I03ApiEvidenceProjection -Data $value -DurationMs 17
    } -ArgumentList @($data)
    $expectedTop = @(
        'schema', 'captured_at_utc', 'available', 'duration_ms',
        'contract_valid', 'isolation_valid', 'controlled_ed2k_expected',
        'error_code', 'safe_scalars', 'safe_response_sha256')
    $actualTop = @($projection.PSObject.Properties.Name)
    Assert-I03Offline -Condition (
        $actualTop.Count -eq $expectedTop.Count -and
        @($expectedTop | Where-Object {
                $actualTop -cnotcontains $_
            }).Count -eq 0 -and
        [string]$projection.schema -ceq
            'ese.v91.i03-api-status-evidence/v2' -and
        [bool]$projection.available -and [bool]$projection.contract_valid -and
        [string]$projection.safe_response_sha256 -match
            '^[0-9a-f]{64}$') -Code 'API_PROJECTION_SHAPE_INVALID'
    $expectedScalars = @(
        'upnp_critical_error', 'utp_hole_punch_enabled', 'web_upnp_active',
        'upnp_ports_forwarded', 'kad_connected', 'kad_configured_mask',
        'netlab_enabled', 'netlab_consent', 'netlab_advanced_consent',
        'netlab_contribution_consent', 'kad_running_mask', 'kad2_running',
        'kad2_connected', 'kad6_running', 'kad6_connected',
        'ed2k_connected', 'keepalive_running')
    $actualScalars = @($projection.safe_scalars.Keys)
    Assert-I03Offline -Condition (
        $actualScalars.Count -eq $expectedScalars.Count -and
        @($expectedScalars | Where-Object {
                $actualScalars -cnotcontains $_
            }).Count -eq 0) -Code 'API_SAFE_SCALAR_ALLOWLIST_INVALID'
    $json = $projection | ConvertTo-Json -Depth 8 -Compress
    foreach ($private in @(
        'raw-user-hash-sentinel', 'raw-token-sentinel',
        '203.0.113.123', 'raw-exception-sentinel', 'user_hash')) {
        Assert-I03Offline -Condition (-not $json.Contains($private)) `
            -Code 'RAW_API_VALUE_RETAINED'
    }
}

Invoke-I03OfflineTest -Id 'API-PRIVATE-VARIANT-STABLE-HASH' `
    -Category 'api_projection' -Body {
    $first = New-I03OfflineApiFixture
    $second = New-I03OfflineApiFixture
    $second.user_hash = 'different-private-user-hash'
    $second.token = 'different-private-token'
    $second.public_ip = '198.51.100.99'
    $values = Invoke-I03PureScope -FunctionNames @(
        'Test-I03StrictJsonInteger', 'Test-I03ApiIsolation',
        'Get-I03ApiEvidenceProjection') -Body {
        param($left, $right)
        @(
            (Get-I03ApiEvidenceProjection -Data $left -DurationMs 1),
            (Get-I03ApiEvidenceProjection -Data $right -DurationMs 1)
        )
    } -ArgumentList @($first, $second)
    Assert-I03OfflineEqual `
        -Actual $values[0].safe_response_sha256 `
        -Expected $values[1].safe_response_sha256 `
        -Code 'PRIVATE_API_VALUE_CHANGED_SAFE_HASH'
}

Invoke-I03OfflineTest -Id 'API-REQUEST-FAILURE-SANITIZED' `
    -Category 'api_projection' -Body {
    $projection = Invoke-I03PureScope -FunctionNames @(
        'Test-I03StrictJsonInteger', 'Test-I03ApiIsolation',
        'Get-I03ApiEvidenceProjection') -Body {
        Get-I03ApiEvidenceProjection -Data $null -DurationMs 2 `
            -RequestFailed
    }
    Assert-I03Offline -Condition (
        -not [bool]$projection.available -and
        -not [bool]$projection.contract_valid -and
        [string]$projection.error_code -ceq 'API_UNAVAILABLE' -and
        @($projection.safe_scalars.Keys).Count -eq 0 -and
        [string]::IsNullOrEmpty(
            [string]$projection.safe_response_sha256)) `
        -Code 'API_FAILURE_PROJECTION_NOT_SANITIZED'
}

Invoke-I03OfflineTest -Id 'FAILURE-TYPED-SCHEMA-POSITIVE' `
    -Category 'adjudication' -Body {
    $record = New-I03OfflineFailureFixture
    Assert-I03Offline -Condition (
        (Test-I03OfflineFailureFixture -Record $record) -and
        [string]$record.schema -ceq 'ese.v91.i03-failure/v1' -and
        $record.fixture_certified -is [bool] -and
        $record.cleanup.complete -is [bool] -and
        @($record.proofs).Count -eq 1) `
        -Code 'TYPED_FAILURE_RECORD_REJECTED'
    $expectedTop = @(
        'schema', 'case_id', 'run_nonce', 'role', 'policy', 'phase',
        'status', 'category', 'code', 'message_sha256', 'candidate',
        'fixture_certified', 'proofs', 'cleanup')
    $actualTop = @($record.PSObject.Properties.Name)
    Assert-I03Offline -Condition (
        $actualTop.Count -eq $expectedTop.Count -and
        @($expectedTop | Where-Object {
                $actualTop -cnotcontains $_
            }).Count -eq 0) -Code 'FAILURE_TOP_LEVEL_SHAPE'
    $json = $record | ConvertTo-Json -Depth 10 -Compress
    foreach ($private in @(
        'private failure detail', 'user_hash', 'C:\\', '\\\\')) {
        Assert-I03Offline -Condition (-not $json.Contains($private)) `
            -Code 'FAILURE_PRIVATE_VALUE_RETAINED'
    }
}

Invoke-I03OfflineTest -Id 'FAILURE-PHASE-VOCABULARY-EXACT' `
    -Category 'adjudication' -Body {
    $allowed = @(
        'preflight', 'dualstack_rearm', 'ipv4_prewarm',
        'peer_restart', 'peer_completion', 'cleanup',
        'case_setup', 'identity_bootstrap', 'candidate_startup',
        'link_injection', 'backlog_revalidation',
        'post_restart_route', 'evidence_finalize')
    foreach ($phase in $allowed) {
        $accepted = Invoke-I03PureScope `
            -FunctionNames @('Test-I03FailurePhase') -Body {
            param($value)
            Test-I03FailurePhase -Phase $value
        } -ArgumentList @($phase)
        Assert-I03Offline -Condition ([bool]$accepted) `
            -Code 'KNOWN_FAILURE_PHASE_REJECTED'
    }
    foreach ($phase in @($null, '', 'post_restart', 'unknown_phase', 7)) {
        $accepted = Invoke-I03PureScope `
            -FunctionNames @('Test-I03FailurePhase') -Body {
            param($value)
            Test-I03FailurePhase -Phase $value
        } -ArgumentList @($phase)
        Assert-I03Offline -Condition (-not [bool]$accepted) `
            -Code 'UNKNOWN_FAILURE_PHASE_ACCEPTED'
    }
    Assert-I03OfflineThrows -ExpectedCode `
        'I03_FAILURE_PROTOCOL::UNKNOWN_PHASE' -Body {
        New-I03OfflineFailureFixture -Phase 'unknown_phase'
    }
}

Invoke-I03OfflineTest -Id 'FAILURE-LAB-SCHEMA-POSITIVE' `
    -Category 'adjudication' -Body {
    $record = New-I03OfflineFailureFixture -Status LAB_BLOCKED `
        -Category LAB_COLLECTOR -Code COLLECTOR_AMBIGUOUS `
        -Policy none -FixtureCertified $false
    Assert-I03Offline -Condition (
        Test-I03OfflineFailureFixture -Record $record `
            -ExpectedPolicy none) -Code 'TYPED_LAB_RECORD_REJECTED'
}

Invoke-I03OfflineTest -Id 'FAILURE-MESSAGE-HASHED' `
    -Category 'adjudication' -Body {
    $first = New-I03OfflineFailureFixture
    $second = New-I03OfflineFailureFixture
    Assert-I03Offline -Condition (
        [string]$first.message_sha256 -match '^[0-9a-f]{64}$' -and
        [string]$first.message_sha256 -ceq
            [string]$second.message_sha256) `
        -Code 'FAILURE_MESSAGE_HASH_NOT_STABLE'
}

Invoke-I03OfflineTest -Id 'FAILURE-WRONG-ROLE-REJECTED' `
    -Category 'adjudication' -Body {
    $record = New-I03OfflineFailureFixture -Role Peer
    Assert-I03Offline -Condition (-not (
        Test-I03OfflineFailureFixture -Record $record `
            -ExpectedRole Coordinator)) -Code 'WRONG_ROLE_ACCEPTED'
}

Invoke-I03OfflineTest -Id 'FAILURE-ARBITRARY-ROLE-REJECTED' `
    -Category 'adjudication' -Body {
    $record = Copy-I03OfflineObject (New-I03OfflineFailureFixture)
    $record.role = 'ArbitraryRole'
    Assert-I03Offline -Condition (-not (
        Test-I03OfflineFailureFixture -Record $record)) `
        -Code 'ARBITRARY_ROLE_ACCEPTED'
}

Invoke-I03OfflineTest -Id 'FAILURE-WRONG-POLICY-REJECTED' `
    -Category 'adjudication' -Body {
    $record = New-I03OfflineFailureFixture -Policy preferred
    Assert-I03Offline -Condition (-not (
        Test-I03OfflineFailureFixture -Record $record `
            -ExpectedPolicy auto)) -Code 'WRONG_POLICY_ACCEPTED'
}

Invoke-I03OfflineTest -Id 'FAILURE-ARBITRARY-POLICY-REJECTED' `
    -Category 'adjudication' -Body {
    $record = Copy-I03OfflineObject (New-I03OfflineFailureFixture)
    $record.policy = 'arbitrary'
    Assert-I03Offline -Condition (-not (
        Test-I03OfflineFailureFixture -Record $record)) `
        -Code 'ARBITRARY_POLICY_ACCEPTED'
}

Invoke-I03OfflineTest -Id 'FAILURE-STALE-CANDIDATE-REJECTED' `
    -Category 'adjudication' -Body {
    $record = Copy-I03OfflineObject (New-I03OfflineFailureFixture)
    $record.candidate.emule_sha256 = '9' * 64
    Assert-I03Offline -Condition (-not (
        Test-I03OfflineFailureFixture -Record $record)) `
        -Code 'STALE_CANDIDATE_ACCEPTED'
}

Invoke-I03OfflineTest -Id 'FAILURE-UNCERTIFIED-PRODUCT-REJECTED' `
    -Category 'adjudication' -Body {
    $record = New-I03OfflineFailureFixture -FixtureCertified $false
    Assert-I03Offline -Condition (-not (
        Test-I03OfflineFailureFixture -Record $record)) `
        -Code 'UNCERTIFIED_PRODUCT_ACCEPTED'
}

Invoke-I03OfflineTest -Id 'FAILURE-UNKNOWN-CODE-REJECTED' `
    -Category 'adjudication' -Body {
    $record = Copy-I03OfflineObject (New-I03OfflineFailureFixture)
    $record.code = 'UNKNOWN_PRODUCT_CODE'
    Assert-I03Offline -Condition (-not (
        Test-I03OfflineFailureFixture -Record $record)) `
        -Code 'UNKNOWN_FAILURE_CODE_ACCEPTED'
}

Invoke-I03OfflineTest -Id 'FAILURE-WRONG-CATEGORY-REJECTED' `
    -Category 'adjudication' -Body {
    $record = Copy-I03OfflineObject (New-I03OfflineFailureFixture)
    $record.category = 'PRODUCT_LIVENESS'
    Assert-I03Offline -Condition (-not (
        Test-I03OfflineFailureFixture -Record $record)) `
        -Code 'WRONG_FAILURE_CATEGORY_ACCEPTED'
}

Invoke-I03OfflineTest -Id 'FAILURE-TOP-EXTRA-REJECTED' `
    -Category 'adjudication' -Body {
    $record = Copy-I03OfflineObject (New-I03OfflineFailureFixture)
    $record | Add-Member -NotePropertyName raw_error `
        -NotePropertyValue 'private'
    Assert-I03Offline -Condition (-not (
        Test-I03OfflineFailureFixture -Record $record)) `
        -Code 'FAILURE_TOP_EXTRA_ACCEPTED'
}

Invoke-I03OfflineTest -Id 'FAILURE-CANDIDATE-EXTRA-REJECTED' `
    -Category 'adjudication' -Body {
    $record = Copy-I03OfflineObject (New-I03OfflineFailureFixture)
    $record.candidate | Add-Member -NotePropertyName absolute_path `
        -NotePropertyValue 'private'
    Assert-I03Offline -Condition (-not (
        Test-I03OfflineFailureFixture -Record $record)) `
        -Code 'FAILURE_CANDIDATE_EXTRA_ACCEPTED'
}

Invoke-I03OfflineTest -Id 'FAILURE-CLEANUP-EXTRA-REJECTED' `
    -Category 'adjudication' -Body {
    $record = Copy-I03OfflineObject (New-I03OfflineFailureFixture)
    $record.cleanup | Add-Member -NotePropertyName raw_exception `
        -NotePropertyValue 'private'
    Assert-I03Offline -Condition (-not (
        Test-I03OfflineFailureFixture -Record $record)) `
        -Code 'FAILURE_CLEANUP_EXTRA_ACCEPTED'
}

Invoke-I03OfflineTest -Id 'FAILURE-PROOF-EXTRA-REJECTED' `
    -Category 'adjudication' -Body {
    $record = Copy-I03OfflineObject (New-I03OfflineFailureFixture)
    $record.proofs[0] | Add-Member -NotePropertyName raw_value `
        -NotePropertyValue 'private'
    Assert-I03Offline -Condition (-not (
        Test-I03OfflineFailureFixture -Record $record)) `
        -Code 'FAILURE_PROOF_EXTRA_ACCEPTED'
}

Invoke-I03OfflineTest -Id 'FAILURE-PROOF-BINDING-TAMPER-REJECTED' `
    -Category 'adjudication' -Body {
    $record = Copy-I03OfflineObject (New-I03OfflineFailureFixture)
    $record.proofs[0].source_evidence_sha256 = '6' * 64
    Assert-I03Offline -Condition (-not (
        Test-I03OfflineFailureFixture -Record $record)) `
        -Code 'FAILURE_PROOF_BINDING_TAMPER_ACCEPTED'
}

Invoke-I03OfflineTest -Id 'FAILURE-PROOF-SOURCE-CONTEXT-GUARD' `
    -Category 'adjudication' -Body {
    $ast = Get-I03HarnessFunctionAst -Name 'Get-I03FormalAdjudication'
    $parameters = @($ast.Body.ParamBlock.Parameters | ForEach-Object {
        $_.Name.VariablePath.UserPath
    })
    Assert-I03Offline -Condition (
        $parameters -ccontains 'TrustedProofBindings' -and
        $parameters -ccontains 'AllowedRolePolicyTuples') `
        -Code 'TRUSTED_PROOF_CONTEXT_PARAMETERS_MISSING'
}

Invoke-I03OfflineTest -Id 'FAILURE-CLEANUP-INCIDENT-SCALAR-REJECTED' `
    -Category 'adjudication' -Body {
    $record = Copy-I03OfflineObject (New-I03OfflineFailureFixture)
    $record.cleanup.incident_codes = 'CLEANUP_INCOMPLETE'
    Assert-I03Offline -Condition (-not (
        Test-I03OfflineFailureFixture -Record $record)) `
        -Code 'CLEANUP_INCIDENT_SCALAR_ACCEPTED'
}

$malformedFailureCases = @(
    [pscustomobject]@{
        id = 'CANDIDATE-NULL'
        mutate = { param($record) $record.candidate = $null }
    },
    [pscustomobject]@{
        id = 'CLEANUP-NULL'
        mutate = { param($record) $record.cleanup = $null }
    },
    [pscustomobject]@{
        id = 'PROOFS-NULL'
        mutate = { param($record) $record.proofs = $null }
    },
    [pscustomobject]@{
        id = 'PROOF-NULL'
        mutate = { param($record) $record.proofs = @($null) }
    },
    [pscustomobject]@{
        id = 'CANDIDATE-MISSING-FIELD'
        mutate = {
            param($record)
            $record.candidate.PSObject.Properties.Remove('commit')
        }
    },
    [pscustomobject]@{
        id = 'CLEANUP-MISSING-FIELD'
        mutate = {
            param($record)
            $record.cleanup.PSObject.Properties.Remove('complete')
        }
    },
    [pscustomobject]@{
        id = 'MESSAGE-HASH-WRONG-TYPE'
        mutate = { param($record) $record.message_sha256 = @('e' * 64) }
    },
    [pscustomobject]@{
        id = 'FIXTURE-BOOL-WRONG-TYPE'
        mutate = { param($record) $record.fixture_certified = 'true' }
    },
    [pscustomobject]@{
        id = 'CLEANUP-BOOL-WRONG-TYPE'
        mutate = { param($record) $record.cleanup.complete = 0 }
    }
)
foreach ($malformedFailure in $malformedFailureCases) {
    $capturedFailure = $malformedFailure
    Invoke-I03OfflineTest -Id (
        'FAILURE-MALFORMED-' + $capturedFailure.id + '-REJECTED') `
        -Category 'adjudication' -Body {
        $record = Copy-I03OfflineObject (New-I03OfflineFailureFixture)
        & $capturedFailure.mutate $record
        Assert-I03Offline -Condition (-not [bool](
            Test-I03OfflineFailureFixture -Record $record)) `
            -Code 'MALFORMED_NESTED_FAILURE_ACCEPTED_OR_THROWN'
    }
}

Invoke-I03OfflineTest -Id 'ADJUDICATION-PASS-EXACT' `
    -Category 'adjudication' -Body {
    $value = Get-I03OfflineAdjudication -FixtureComplete $true `
        -BothPoliciesPass $true -EvidenceComplete $true `
        -CleanupComplete $true
    Assert-I03OfflineEqual -Actual $value.formal_status -Expected 'PASS' `
        -Code 'FORMAL_PASS_NOT_RETURNED'
}

$blockedFlagCases = @(
    @($false, $true, $true, $true),
    @($true, $false, $true, $true),
    @($true, $true, $false, $true),
    @($true, $true, $true, $false)
)
$blockedFlagIndex = 0
foreach ($flags in $blockedFlagCases) {
    $blockedFlagIndex++
    $capturedFlags = $flags
    Invoke-I03OfflineTest -Id (
        'ADJUDICATION-BLOCKED-FLAG-{0:D2}' -f $blockedFlagIndex) `
        -Category 'adjudication' -Body {
        $value = Get-I03OfflineAdjudication `
            -FixtureComplete ([bool]$capturedFlags[0]) `
            -BothPoliciesPass ([bool]$capturedFlags[1]) `
            -EvidenceComplete ([bool]$capturedFlags[2]) `
            -CleanupComplete ([bool]$capturedFlags[3])
        Assert-I03OfflineEqual -Actual $value.formal_status `
            -Expected 'BLOCKED' -Code 'INCOMPLETE_FIXTURE_NOT_BLOCKED'
    }
}

Invoke-I03OfflineTest -Id 'ADJUDICATION-LAB-INCIDENT-BLOCKED' `
    -Category 'adjudication' -Body {
    $lab = New-I03OfflineFailureFixture -Status LAB_BLOCKED `
        -Category LAB_COLLECTOR -Code COLLECTOR_AMBIGUOUS `
        -Policy none -FixtureCertified $false
    $value = Get-I03OfflineAdjudication -FailureRecords @($lab) `
        -FixtureComplete $true -BothPoliciesPass $true `
        -EvidenceComplete $true -CleanupComplete $true
    Assert-I03OfflineEqual -Actual $value.formal_status -Expected 'BLOCKED' `
        -Code 'LAB_INCIDENT_NOT_BLOCKED'
}

Invoke-I03OfflineTest -Id 'ADJUDICATION-MALFORMED-CLAIM-BLOCKED' `
    -Category 'adjudication' -Body {
    $claim = Copy-I03OfflineObject (New-I03OfflineFailureFixture)
    $claim.proofs[0].binding_sha256 = '0' * 64
    $value = Get-I03OfflineAdjudication -FailureRecords @($claim) `
        -FixtureComplete $true -BothPoliciesPass $true `
        -EvidenceComplete $true -CleanupComplete $true
    Assert-I03OfflineEqual -Actual $value.formal_status -Expected 'BLOCKED' `
        -Code 'MALFORMED_PRODUCT_CLAIM_NOT_BLOCKED'
}

Invoke-I03OfflineTest -Id 'ADJUDICATION-FORGED-SOURCE-BLOCKED' `
    -Category 'adjudication' -Body {
    $claim = Copy-I03OfflineObject (New-I03OfflineFailureFixture)
    $trustedBinding = [string]$claim.proofs[0].binding_sha256
    $claim.proofs[0].source_evidence_sha256 = '6' * 64
    $canonical = '{0}|{1}|{2}|{3}|{4}|{5}|{6}' -f
        $claim.proofs[0].case_id, $claim.proofs[0].run_nonce,
        $claim.proofs[0].role, $claim.proofs[0].policy,
        $claim.proofs[0].phase, $claim.proofs[0].kind,
        $claim.proofs[0].source_evidence_sha256
    $claim.proofs[0].binding_sha256 =
        Get-OfflineStringSha256 -Value $canonical
    $value = Get-I03OfflineAdjudication -FailureRecords @($claim) `
        -TrustedProofBindings @($trustedBinding) `
        -FixtureComplete $true -BothPoliciesPass $true `
        -EvidenceComplete $true -CleanupComplete $true
    Assert-I03OfflineEqual -Actual $value.formal_status -Expected 'BLOCKED' `
        -Code 'FORGED_SOURCE_PROOF_NOT_BLOCKED'
}

Invoke-I03OfflineTest -Id `
    'ADJUDICATION-CROSS-CODE-PHASE-SOURCE-BLOCKED' `
    -Category 'adjudication' -Body {
    $claimB = New-I03OfflineFailureFixture `
        -Code WRONG_FAMILY -Category PRODUCT_ROUTE `
        -Phase post_restart_route
    $proofB = $claimB.proofs[0]
    $bindingAInput = '{0}|{1}|{2}|{3}|{4}|{5}|{6}' -f
        $proofB.case_id, $proofB.run_nonce, $proofB.role,
        $proofB.policy, 'link_injection', 'no_route',
        $proofB.source_evidence_sha256
    $trustedBindingA = Get-OfflineStringSha256 -Value $bindingAInput
    $value = Get-I03OfflineAdjudication -FailureRecords @($claimB) `
        -TrustedProofBindings @($trustedBindingA) `
        -FixtureComplete $true -BothPoliciesPass $true `
        -EvidenceComplete $true -CleanupComplete $true
    Assert-I03Offline -Condition (
        [string]$value.formal_status -ceq 'BLOCKED' -and
        [int]$value.proven_product_failure_count -eq 0 -and
        [int]$value.untrusted_product_failure_count -eq 1) `
        -Code 'SOURCE_METADATA_A_TRUSTED_PRODUCT_RECORD_B'
}

$crossSourceMetadataCases = @(
    [pscustomobject]@{
        id = 'ROLE'; role = 'Peer'; policy = 'auto'
        phase = 'post_restart_route'; kind = 'wrong_family'
    },
    [pscustomobject]@{
        id = 'POLICY'; role = 'Coordinator'; policy = 'preferred'
        phase = 'post_restart_route'; kind = 'wrong_family'
    },
    [pscustomobject]@{
        id = 'PHASE'; role = 'Coordinator'; policy = 'auto'
        phase = 'link_injection'; kind = 'wrong_family'
    },
    [pscustomobject]@{
        id = 'CODE'; role = 'Coordinator'; policy = 'auto'
        phase = 'post_restart_route'; kind = 'no_route'
    }
)
foreach ($sourceMetadataCase in $crossSourceMetadataCases) {
    $capturedSourceMetadata = $sourceMetadataCase
    Invoke-I03OfflineTest -Id (
        'ADJUDICATION-CROSS-SOURCE-' +
        [string]$capturedSourceMetadata.id + '-BLOCKED') `
        -Category 'adjudication' -Body {
        $claim = New-I03OfflineFailureFixture
        $proof = $claim.proofs[0]
        $bindingInput = '{0}|{1}|{2}|{3}|{4}|{5}|{6}' -f
            $proof.case_id, $proof.run_nonce,
            [string]$capturedSourceMetadata.role,
            [string]$capturedSourceMetadata.policy,
            [string]$capturedSourceMetadata.phase,
            [string]$capturedSourceMetadata.kind,
            $proof.source_evidence_sha256
        $trustedBinding = Get-OfflineStringSha256 -Value $bindingInput
        $value = Get-I03OfflineAdjudication -FailureRecords @($claim) `
            -AllowedRolePolicyTuples @('Coordinator|auto') `
            -TrustedProofBindings @($trustedBinding) `
            -FixtureComplete $true -BothPoliciesPass $true `
            -EvidenceComplete $true -CleanupComplete $true
        Assert-I03Offline -Condition (
            [string]$value.formal_status -ceq 'BLOCKED' -and
            [int]$value.proven_product_failure_count -eq 0 -and
            [int]$value.untrusted_product_failure_count -eq 1) `
            -Code 'CROSS_SOURCE_METADATA_TRUSTED_WRONG_RECORD'
    }
}

Invoke-I03OfflineTest -Id 'FAILURE-SOURCE-PROVENANCE-WIRING-STATIC' `
    -Category 'adjudication' -Body {
    $sourceText = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Test-I03PersistedFailureSources'
    }, $true))[0].Extent.Text
    foreach ($needle in @(
        '$sourceNames.Count -ne 8',
        "'schema', 'case_id', 'run_nonce', 'role'",
        "'policy', 'phase', 'code', 'evidence'",
        'Test-I03FailurePhase -Phase $source.phase',
        '$kind = ([string]$source.code).ToLowerInvariant()',
        '[string]$source.case_id, [string]$source.run_nonce',
        '[string]$source.role, [string]$source.policy',
        '[string]$source.phase, $kind, $sourceHash',
        'trusted_binding_sha256 = @($bindingHashes)',
        'source_bindings = @($bindings)',
        "error_code = 'FAILURE_SOURCE_INVALID'")) {
        Assert-I03Offline -Condition ($sourceText.Contains($needle)) `
            -Code 'FAILURE_SOURCE_PROVENANCE_CONTRACT_MISSING'
    }
    Assert-I03Offline -Condition (
        $script:PureFunctionAllowlist -cnotcontains
            'Test-I03PersistedFailureSources') `
        -Code 'FILESYSTEM_SOURCE_VALIDATOR_MUST_NOT_BE_EXTRACTED'
    $coordinatorText = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Invoke-I03CoordinatorRole'
    }, $true))[0].Extent.Text
    foreach ($needle in @(
        'trusted_binding_sha256', '$localProductBindingHashes',
        '$localTrustedBindings', '$trustedProofBindings.Clear()',
        '$proof.binding_sha256 -cin $verifiedBindings')) {
        Assert-I03Offline -Condition ($coordinatorText.Contains($needle)) `
            -Code 'VERIFIED_SOURCE_BINDING_NOT_WIRED_TO_ADJUDICATION'
    }
}

Invoke-I03OfflineTest -Id 'ADJUDICATION-ROLE-CONTEXT-BLOCKED' `
    -Category 'adjudication' -Body {
    $claim = New-I03OfflineFailureFixture -Role Peer -Policy auto
    $value = Get-I03OfflineAdjudication -FailureRecords @($claim) `
        -AllowedRolePolicyTuples @('Coordinator|auto') `
        -TrustedProofBindings @([string]$claim.proofs[0].binding_sha256) `
        -FixtureComplete $true -BothPoliciesPass $true `
        -EvidenceComplete $true -CleanupComplete $true
    Assert-I03OfflineEqual -Actual $value.formal_status -Expected 'BLOCKED' `
        -Code 'WRONG_ROLE_CONTEXT_NOT_BLOCKED'
}

Invoke-I03OfflineTest -Id 'ADJUDICATION-POLICY-CONTEXT-BLOCKED' `
    -Category 'adjudication' -Body {
    $claim = New-I03OfflineFailureFixture -Policy preferred
    $value = Get-I03OfflineAdjudication -FailureRecords @($claim) `
        -AllowedRolePolicyTuples @('Coordinator|auto') `
        -TrustedProofBindings @([string]$claim.proofs[0].binding_sha256) `
        -FixtureComplete $true -BothPoliciesPass $true `
        -EvidenceComplete $true -CleanupComplete $true
    Assert-I03OfflineEqual -Actual $value.formal_status -Expected 'BLOCKED' `
        -Code 'WRONG_POLICY_CONTEXT_NOT_BLOCKED'
}

Invoke-I03OfflineTest -Id 'ADJUDICATION-PRODUCT-PRECEDENCE' `
    -Category 'adjudication' -Body {
    $product = New-I03OfflineFailureFixture
    $cleanup = New-I03OfflineFailureFixture -Status LAB_BLOCKED `
        -Category LAB_CLEANUP -Code CLEANUP_INCOMPLETE `
        -Policy none -FixtureCertified $false
    $value = Get-I03OfflineAdjudication `
        -FailureRecords @($product, $cleanup) `
        -TrustedProofBindings @(
            [string]$product.proofs[0].binding_sha256) `
        -FixtureComplete $false -BothPoliciesPass $false `
        -EvidenceComplete $false -CleanupComplete $false
    if ([string]$value.formal_status -cne 'FAIL') {
        throw ('PRODUCT_PRECEDENCE_STATUS_' +
            ([string]$value.formal_status).ToUpperInvariant())
    }
    if ([int]$value.proven_product_failure_count -ne 1) {
        throw 'PRODUCT_PRECEDENCE_PROOF_COUNT'
    }
    if ([int]$value.lab_incident_count -ne 1) {
        throw 'PRODUCT_PRECEDENCE_LAB_COUNT'
    }
}

Invoke-I03OfflineTest -Id 'ADJUDICATION-PEER-ONLY-PRODUCT-FAIL' `
    -Category 'adjudication' -Body {
    $peerProduct = New-I03OfflineFailureFixture -Role Peer `
        -Policy preferred
    $peerProduct.cleanup.complete = $true
    $value = Get-I03OfflineAdjudication `
        -FailureRecords @($peerProduct) `
        -AllowedRolePolicyTuples @('Peer|preferred') `
        -TrustedProofBindings @(
            [string]$peerProduct.proofs[0].binding_sha256) `
        -FixtureComplete $true -BothPoliciesPass $false `
        -EvidenceComplete $true -CleanupComplete $true
    Assert-I03Offline -Condition (
        [string]$value.formal_status -ceq 'FAIL' -and
        [int]$value.proven_product_failure_count -eq 1 -and
        [int]$value.malformed_or_stale_failure_count -eq 0) `
        -Code 'TRUSTED_PEER_PRODUCT_FAILURE_NOT_FAIL'
}

Invoke-I03OfflineTest -Id 'NODE-BINDING-FIXTURE-INITIALIZE' `
    -Category 'node_binding' -Body {
    $script:NodePackagePath = Join-Path $script:TempRoot 'node-package'
    New-Item -ItemType Directory -Path (
        Join-Path $script:NodePackagePath 'config') -Force | Out-Null
    $nodeFixtureFiles = [ordered]@{
        'emule.exe' = 'emule-candidate'
        'ese-server.exe' = 'ese-server-candidate'
        'support.dll' = 'support-library-candidate'
        'BUILD_INFO.txt' = 'commit=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        'config\preferences.ini' = (
            "[eMule]`nPort=4662`n" +
            "UncontrolledSentinel=source-value`n")
    }
    foreach ($relative in $nodeFixtureFiles.Keys) {
        [IO.File]::WriteAllText(
            (Join-Path $script:NodePackagePath $relative),
            [string]$nodeFixtureFiles[$relative],
            [Text.UTF8Encoding]::new($false))
    }
    $script:NodePackageIdentity =
        Get-I03OfflinePackageIdentity -Path $script:NodePackagePath
    Assert-I03Offline -Condition (
        [int]$script:NodePackageIdentity.file_count -eq 5 -and
        [string]$script:NodePackageIdentity.manifest_sha256 -match
            '^[0-9a-f]{64}$') `
        -Code 'NODE_PACKAGE_FIXTURE_IDENTITY_INVALID'
}

Invoke-I03OfflineTest -Id 'NODE-BINDING-INITIAL-EXACT-POSITIVE' `
    -Category 'node_binding' -Body {
    $node = New-I03OfflinePreparedNodeFixture `
        -Name 'node-initial-positive' `
        -PackagePath $script:NodePackagePath
    [IO.File]::WriteAllText(
        (Join-Path $node 'config\preferences.ini'),
        ("[eMule]`nPort=9562`n" +
            "UncontrolledSentinel=source-value`n"),
        [Text.UTF8Encoding]::new($false))
    $expectation =
        Get-I03OfflinePreparedPreferencesExpectation -NodePath $node
    $value = Test-I03OfflinePreparedNodeBinding -Path $node `
        -Identity $script:NodePackageIdentity -Phase Initial `
        -ExpectedPreparedPreferencesSha256 $expectation.sha256 `
        -ExpectedPreparedPreferencesBytes $expectation.bytes
    Assert-I03Offline -Condition (
        [string]$value.schema -ceq
            'ese.v91.i03-prepared-node-binding/v1' -and
        [string]$value.phase -ceq 'initial' -and
        [bool]$value.collector_ok -and
        [string]$value.collector_error_code -ceq 'NONE' -and
        [bool]$value.bound -and
        [string]$value.binding_error_code -ceq 'NONE' -and
        [int]$value.verified_immutable_file_count -eq 4 -and
        [string]$value.verified_immutable_manifest_sha256 -match
            '^[0-9a-f]{64}$') `
        -Code 'EXACT_INITIAL_NODE_BINDING_REJECTED'
}

Invoke-I03OfflineTest -Id `
    'NODE-BINDING-INITIAL-UNCONTROLLED-PREFERENCE-REJECTED' `
    -Category 'node_binding' -Body {
    $node = New-I03OfflinePreparedNodeFixture `
        -Name 'node-initial-uncontrolled-preference' `
        -PackagePath $script:NodePackagePath
    $expectedText = "[eMule]`nPort=9562`n" +
        "UncontrolledSentinel=source-value`n"
    $expectedSha256 = Get-OfflineStringSha256 -Value $expectedText
    $expectedBytes = [Int64][Text.Encoding]::UTF8.GetByteCount($expectedText)
    [IO.File]::WriteAllText(
        (Join-Path $node 'config\preferences.ini'),
        ("[eMule]`nPort=9562`n" +
            "UncontrolledSentinel=tampered-value`n"),
        [Text.UTF8Encoding]::new($false))
    $value = Test-I03OfflinePreparedNodeBinding -Path $node `
        -Identity $script:NodePackageIdentity -Phase Initial `
        -ExpectedPreparedPreferencesSha256 $expectedSha256 `
        -ExpectedPreparedPreferencesBytes $expectedBytes
    Assert-I03Offline -Condition (
        [bool]$value.collector_ok -and -not [bool]$value.bound -and
        [string]$value.binding_error_code -cne 'NONE') `
        -Code 'UNCONTROLLED_PREPARED_PREFERENCE_TAMPER_ACCEPTED'
}

Invoke-I03OfflineTest -Id `
    'NODE-BINDING-INITIAL-WRONG-RUNID-ORACLE-REJECTED' `
    -Category 'node_binding' -Body {
    $node = New-I03OfflinePreparedNodeFixture `
        -Name 'node-initial-wrong-runid-oracle' `
        -PackagePath $script:NodePackagePath
    $actualText = "[eMule]`n" +
        "Nick=eSE-v9-lab-v91-i03-peer-A`n" +
        "UncontrolledSentinel=source-value`n"
    $wrongRunIdText = "[eMule]`n" +
        "Nick=eSE-v9-lab-oracle-peer-A`n" +
        "UncontrolledSentinel=source-value`n"
    [IO.File]::WriteAllText(
        (Join-Path $node 'config\preferences.ini'), $actualText,
        [Text.UTF8Encoding]::new($false))
    $value = Test-I03OfflinePreparedNodeBinding -Path $node `
        -Identity $script:NodePackageIdentity -Phase Initial `
        -ExpectedPreparedPreferencesSha256 (
            Get-OfflineStringSha256 -Value $wrongRunIdText) `
        -ExpectedPreparedPreferencesBytes (
            [Int64][Text.Encoding]::UTF8.GetByteCount($wrongRunIdText))
    Assert-I03Offline -Condition (
        [bool]$value.collector_ok -and -not [bool]$value.bound -and
        [string]$value.binding_error_code -ceq
            'PREPARED_PREFERENCES_MISMATCH') `
        -Code 'WRONG_RUNID_PREFERENCES_ORACLE_ACCEPTED'
}

$initialNodeTamperCases = @(
    [pscustomobject]@{ id = 'DLL'; path = 'support.dll' },
    [pscustomobject]@{ id = 'ESE-SERVER'; path = 'ese-server.exe' }
)
foreach ($nodeTamperCase in $initialNodeTamperCases) {
    $capturedNodeTamper = $nodeTamperCase
    Invoke-I03OfflineTest -Id (
        'NODE-BINDING-INITIAL-' + $capturedNodeTamper.id + '-REJECTED') `
        -Category 'node_binding' -Body {
        $node = New-I03OfflinePreparedNodeFixture `
            -Name ('node-initial-' +
                ([string]$capturedNodeTamper.id).ToLowerInvariant()) `
            -PackagePath $script:NodePackagePath
        [IO.File]::WriteAllText(
            (Join-Path $node ([string]$capturedNodeTamper.path)),
            'tampered-node-byte', [Text.UTF8Encoding]::new($false))
        $expectation =
            Get-I03OfflinePreparedPreferencesExpectation -NodePath $node
        $value = Test-I03OfflinePreparedNodeBinding -Path $node `
            -Identity $script:NodePackageIdentity -Phase Initial `
            -ExpectedPreparedPreferencesSha256 $expectation.sha256 `
            -ExpectedPreparedPreferencesBytes $expectation.bytes
        Assert-I03Offline -Condition (
            [bool]$value.collector_ok -and -not [bool]$value.bound -and
            [string]$value.binding_error_code -ceq
                'IMMUTABLE_FILE_MISMATCH') `
            -Code 'TAMPERED_INITIAL_NODE_FILE_ACCEPTED'
    }
}

Invoke-I03OfflineTest -Id 'NODE-BINDING-INITIAL-EXTRA-REJECTED' `
    -Category 'node_binding' -Body {
    $node = New-I03OfflinePreparedNodeFixture `
        -Name 'node-initial-extra' -PackagePath $script:NodePackagePath
    [IO.File]::WriteAllText(
        (Join-Path $node 'untrusted-extra.bin'), 'extra',
        [Text.UTF8Encoding]::new($false))
    $expectation =
        Get-I03OfflinePreparedPreferencesExpectation -NodePath $node
    $value = Test-I03OfflinePreparedNodeBinding -Path $node `
        -Identity $script:NodePackageIdentity -Phase Initial `
        -ExpectedPreparedPreferencesSha256 $expectation.sha256 `
        -ExpectedPreparedPreferencesBytes $expectation.bytes
    Assert-I03Offline -Condition (
        [bool]$value.collector_ok -and -not [bool]$value.bound -and
        [string]$value.binding_error_code -ceq
            'INITIAL_FILE_SET_MISMATCH') `
        -Code 'EXTRA_INITIAL_NODE_FILE_ACCEPTED'
}

Invoke-I03OfflineTest -Id 'NODE-BINDING-INITIAL-REPARSE-REJECTED' `
    -Category 'node_binding' -Body {
    $node = New-I03OfflinePreparedNodeFixture `
        -Name 'node-initial-reparse' -PackagePath $script:NodePackagePath
    $target = Join-Path $script:TempRoot 'node-reparse-target'
    $link = Join-Path $node 'linked-subtree'
    New-Item -ItemType Directory -Path $target -Force | Out-Null
    New-Item -ItemType Junction -Path $link -Target $target `
        -ErrorAction Stop | Out-Null
    try {
        $expectation =
            Get-I03OfflinePreparedPreferencesExpectation -NodePath $node
        $value = Test-I03OfflinePreparedNodeBinding -Path $node `
            -Identity $script:NodePackageIdentity -Phase Initial `
            -ExpectedPreparedPreferencesSha256 $expectation.sha256 `
            -ExpectedPreparedPreferencesBytes $expectation.bytes
        Assert-I03Offline -Condition (
            [bool]$value.collector_ok -and -not [bool]$value.bound -and
            [string]$value.binding_error_code -ceq
                'NODE_REPARSE_POINT') `
            -Code 'REPARSE_INITIAL_NODE_ACCEPTED'
    } finally {
        if (Test-Path -LiteralPath $link) { [IO.Directory]::Delete($link) }
    }
}

Invoke-I03OfflineTest -Id 'NODE-BINDING-TERMINAL-EXACT-POSITIVE' `
    -Category 'node_binding' -Body {
    $node = New-I03OfflinePreparedNodeFixture `
        -Name 'node-terminal-positive' `
        -PackagePath $script:NodePackagePath
    New-Item -ItemType Directory -Path (Join-Path $node 'I03Temp') `
        -Force | Out-Null
    [IO.File]::WriteAllText(
        (Join-Path $node 'I03Temp\runtime.part'), 'runtime',
        [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText(
        (Join-Path $node 'config\preferences.ini'), 'runtime preferences',
        [Text.UTF8Encoding]::new($false))
    $value = Test-I03OfflinePreparedNodeBinding -Path $node `
        -Identity $script:NodePackageIdentity -Phase Terminal
    Assert-I03Offline -Condition (
        [bool]$value.collector_ok -and [bool]$value.bound -and
        [string]$value.binding_error_code -ceq 'NONE' -and
        [int]$value.verified_immutable_file_count -eq 4) `
        -Code 'EXACT_TERMINAL_NODE_BINDING_REJECTED'
}

$terminalExtraExecutableCases = @(
    [pscustomobject]@{ id = 'EXTRA-DLL'; path = 'extra.dll' },
    [pscustomobject]@{ id = 'EXTRA-EXE'; path = 'helper.exe' }
)
foreach ($terminalExtraCase in $terminalExtraExecutableCases) {
    $capturedTerminalExtra = $terminalExtraCase
    Invoke-I03OfflineTest -Id (
        'NODE-BINDING-TERMINAL-' +
        $capturedTerminalExtra.id + '-REJECTED') `
        -Category 'node_binding' -Body {
        $node = New-I03OfflinePreparedNodeFixture `
            -Name ('node-terminal-' +
                ([string]$capturedTerminalExtra.id).ToLowerInvariant()) `
            -PackagePath $script:NodePackagePath
        [IO.File]::WriteAllText(
            (Join-Path $node ([string]$capturedTerminalExtra.path)),
            'untrusted-executable-byte', [Text.UTF8Encoding]::new($false))
        $value = Test-I03OfflinePreparedNodeBinding -Path $node `
            -Identity $script:NodePackageIdentity -Phase Terminal
        Assert-I03Offline -Condition (
            [bool]$value.collector_ok -and -not [bool]$value.bound -and
            [string]$value.binding_error_code -cne 'NONE') `
            -Code 'UNMANIFESTED_TERMINAL_EXECUTABLE_ACCEPTED'
    }
}

$terminalNodeTamperCases = @(
    [pscustomobject]@{ id = 'DLL'; path = 'support.dll' },
    [pscustomobject]@{ id = 'ESE-SERVER'; path = 'ese-server.exe' }
)
foreach ($nodeTamperCase in $terminalNodeTamperCases) {
    $capturedTerminalNodeTamper = $nodeTamperCase
    Invoke-I03OfflineTest -Id (
        'NODE-BINDING-TERMINAL-' +
        $capturedTerminalNodeTamper.id + '-REJECTED') `
        -Category 'node_binding' -Body {
        $node = New-I03OfflinePreparedNodeFixture `
            -Name ('node-terminal-' +
                ([string]$capturedTerminalNodeTamper.id).ToLowerInvariant()) `
            -PackagePath $script:NodePackagePath
        [IO.File]::WriteAllText(
            (Join-Path $node ([string]$capturedTerminalNodeTamper.path)),
            'tampered-terminal-byte', [Text.UTF8Encoding]::new($false))
        $value = Test-I03OfflinePreparedNodeBinding -Path $node `
            -Identity $script:NodePackageIdentity -Phase Terminal
        Assert-I03Offline -Condition (
            [bool]$value.collector_ok -and -not [bool]$value.bound -and
            [string]$value.binding_error_code -ceq
                'IMMUTABLE_FILE_MISMATCH') `
            -Code 'TAMPERED_TERMINAL_NODE_FILE_ACCEPTED'
    }
}

Invoke-I03OfflineTest -Id 'NODE-PREFERENCES-ORACLE-WIRING-STATIC' `
    -Category 'node_binding' -Body {
    $oracleMatches = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'New-I03PreparedPreferencesOracle'
    }, $true))
    Assert-I03Offline -Condition ($oracleMatches.Count -eq 1) `
        -Code 'PREPARED_PREFERENCES_ORACLE_NOT_UNIQUE'
    $oracleText = $oracleMatches[0].Extent.Text
    foreach ($needle in @(
        '[IO.FileShare]::None',
        "[string]`$_.relative_path -ceq 'config/preferences.ini'",
        '$sourceSha -ceq', '[Int64]$sourceBytes.Length -eq',
        "Join-Path `$root 'frozen-source'",
        "Join-Path `$root 'prepared'",
        "'prepare_node.ps1'", '-NodeRole $NodeRole',
        '-RunId $RunId', '-PortOffset $PortOffset',
        'expected_prepared_preferences_sha256',
        'expected_prepared_preferences_bytes',
        "collector_error_code = 'PREFERENCES_ORACLE_FAILED'")) {
        Assert-I03Offline -Condition ($oracleText.Contains($needle)) `
            -Code 'PREPARED_PREFERENCES_ORACLE_CONTRACT_MISSING'
    }
    Assert-I03Offline -Condition (
        $script:PureFunctionAllowlist -cnotcontains
            'New-I03PreparedPreferencesOracle') `
        -Code 'EXTERNAL_PREPARE_NODE_ORACLE_MUST_NOT_BE_EXTRACTED'

    $peerText = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Invoke-I03PeerRole'
    }, $true))[0].Extent.Text
    $coordinatorText = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Invoke-I03CoordinatorRole'
    }, $true))[0].Extent.Text
    Assert-I03Offline -Condition (
        ([regex]::Matches(
            $peerText, "-RunId\s+'v91-i03-peer'")).Count -eq 2 -and
        ([regex]::Matches(
            $peerText, '-NodeRole\s+A')).Count -eq 2 -and
        ([regex]::Matches(
            $peerText, '-PortOffset\s+\$offset')).Count -eq 2 -and
        ([regex]::Matches(
            $coordinatorText,
            '-RunId\s+"v91-i03-\$\(\$policy\.name\)"')).Count -eq 2 -and
        ([regex]::Matches(
            $coordinatorText, '-NodeRole\s+B')).Count -eq 2 -and
        ([regex]::Matches(
            $coordinatorText, '-PortOffset\s+\$offset')).Count -ge 2 -and
        -not $peerText.Contains('-RunId ''oracle') -and
        -not $coordinatorText.Contains('-RunId "oracle')) `
        -Code 'PREFERENCES_ORACLE_RUNID_ROLE_OR_OFFSET_MISMATCH'

    foreach ($roleText in @($peerText, $coordinatorText)) {
        $oracleOffset = $roleText.IndexOf(
            'New-I03PreparedPreferencesOracle')
        $prepareOffset = $roleText.IndexOf(
            "'prepare_node.ps1'", $oracleOffset + 1)
        $bindingOffset = $roleText.IndexOf(
            'Test-I03PreparedNodeBinding', $prepareOffset + 1)
        Assert-I03Offline -Condition (
            $oracleOffset -ge 0 -and $prepareOffset -gt $oracleOffset -and
            $bindingOffset -gt $prepareOffset -and
            $roleText.IndexOf('.collector_ok', $oracleOffset) -gt
                $oracleOffset -and
            $roleText.IndexOf('.source_bound', $oracleOffset) -gt
                $oracleOffset -and
            $roleText.IndexOf(
                '-ExpectedPreparedPreferencesSha256', $bindingOffset) -gt
                    $bindingOffset -and
            $roleText.IndexOf(
                '-ExpectedPreparedPreferencesBytes', $bindingOffset) -gt
                    $bindingOffset) `
            -Code 'PREFERENCES_ORACLE_NOT_GATED_BEFORE_REAL_PREPARE'
    }
}

Invoke-I03OfflineTest -Id 'NODE-BINDING-WIRING-STATIC' `
    -Category 'node_binding' -Body {
    $bindingText = (Get-I03HarnessFunctionAst `
        -Name 'Test-I03PreparedNodeBinding').Extent.Text
    foreach ($needle in @(
        "[ValidateSet('Initial', 'Terminal')]",
        "mutable_package_exclusions = @('config/preferences.ini')",
        "allowed_initial_extra_files = @('LAB_NODE.json')",
        '$ExpectedPreparedPreferencesSha256',
        '$ExpectedPreparedPreferencesBytes',
        'deterministic_preferences_match',
        "binding_error_code = 'PREPARED_PREFERENCES_MISMATCH'",
        "-cne 'config/preferences.ini'",
        "`$extension -cin @('.exe', '.dll')",
        "`$relative -ceq 'BUILD_INFO.txt'",
        "binding_error_code = 'UNEXPECTED_STATIC_FILE'",
        "binding_error_code = 'NODE_REPARSE_POINT'",
        "binding_error_code = 'INITIAL_FILE_SET_MISMATCH'",
        "binding_error_code = 'IMMUTABLE_FILE_MISMATCH'",
        '(Get-LabSha256 -Path ([string]$file.FullName))')) {
        Assert-I03Offline -Condition ($bindingText.Contains($needle)) `
            -Code 'PREPARED_NODE_BINDING_CONTRACT_MISSING'
    }
    foreach ($roleName in @(
        'Invoke-I03PeerRole', 'Invoke-I03CoordinatorRole')) {
        $roleText = @($script:HarnessAst.FindAll({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] `
                -and $node.Name -ceq $roleName
        }, $true))[0].Extent.Text
        $prepareOffset = $roleText.IndexOf("'prepare_node.ps1'")
        $initialOffset = $roleText.IndexOf(
            'Test-I03PreparedNodeBinding', $prepareOffset + 1)
        $preferenceOffset = $roleText.IndexOf(
            'Set-I03IsolatedPreferences', $initialOffset + 1)
        $terminalOffset = $roleText.LastIndexOf(
            'Test-I03PreparedNodeBinding')
        Assert-I03Offline -Condition (
            $prepareOffset -ge 0 -and $initialOffset -gt $prepareOffset -and
            $roleText.IndexOf('-Phase Initial', $initialOffset) -gt
                $initialOffset -and
            $preferenceOffset -gt $initialOffset -and
            $terminalOffset -gt $preferenceOffset -and
            $roleText.IndexOf('-Phase Terminal', $terminalOffset) -gt
                $terminalOffset -and
            $roleText.Contains('.collector_ok') -and
            $roleText.Contains('.bound')) `
            -Code 'PREPARED_NODE_BINDING_NOT_GATED_BOTH_PHASES'
    }
}

Invoke-I03OfflineTest -Id 'ZIP-FIXTURE-INITIALIZE' `
    -Category 'zip_binding' -Body {
    $script:PackagePath = Join-Path $script:TempRoot 'package'
    $nested = Join-Path $script:PackagePath 'nested'
    New-Item -ItemType Directory -Path $nested -Force | Out-Null
    [IO.File]::WriteAllBytes(
        (Join-Path $script:PackagePath 'alpha.txt'),
        [Text.Encoding]::UTF8.GetBytes('alpha-fixture'))
    [IO.File]::WriteAllBytes(
        (Join-Path $nested 'beta.bin'), [byte[]](0, 1, 2, 127, 255))
    [IO.File]::WriteAllBytes(
        (Join-Path $script:PackagePath 'empty.dat'), [byte[]]@())
    $script:PackageIdentity =
        Get-I03OfflinePackageIdentity -Path $script:PackagePath
    Assert-I03Offline -Condition (
        [int]$script:PackageIdentity.file_count -eq 3) `
        -Code 'PACKAGE_IDENTITY_FILE_COUNT'
    $script:ValidZipPath = New-I03OfflineZip `
        -Path (Join-Path $script:TempRoot 'valid-with-directories.zip') `
        -Entries @(
            [pscustomobject]@{ name = 'release/'; bytes = [byte[]]@() },
            [pscustomobject]@{
                name = 'release/alpha.txt'
                bytes = [Text.Encoding]::UTF8.GetBytes('alpha-fixture')
            },
            [pscustomobject]@{
                name = 'release/nested/'; bytes = [byte[]]@()
            },
            [pscustomobject]@{
                name = 'release/nested/beta.bin'
                bytes = [byte[]](0, 1, 2, 127, 255)
            },
            [pscustomobject]@{
                name = 'release/empty.dat'; bytes = [byte[]]@()
            }
        )
}

Invoke-I03OfflineTest -Id 'ZIP-EXACT-SINGLE-ROOT-DIRECTORIES' `
    -Category 'zip_binding' -Body {
    $sha = Get-OfflineFileSha256 -Path $script:ValidZipPath
    $binding = Get-I03OfflineZipBinding -Path $script:ValidZipPath `
        -ExpectedSha256 $sha -Identity $script:PackageIdentity
    Assert-I03Offline -Condition (
        [string]$binding.schema -ceq
            'ese.v91.i03-package-zip-binding/v1' -and
        [bool]$binding.verified -and [bool]$binding.safe_single_root -and
        [bool]$binding.exact_file_set -and
        [bool]$binding.exact_bytes_and_sha256 -and
        [int]$binding.file_count -eq 3 -and
        [string]$binding.archive_root_sha256 -match '^[0-9a-f]{64}$') `
        -Code 'ZIP_POSITIVE_BINDING_INVALID'
    $json = $binding | ConvertTo-Json -Depth 6 -Compress
    Assert-I03Offline -Condition (-not $json.Contains('release')) `
        -Code 'ZIP_ROOT_NAME_NOT_MINIMIZED'
}

Invoke-I03OfflineTest -Id 'ZIP-EXACT-SINGLE-ROOT-IMPLICIT-DIRS' `
    -Category 'zip_binding' -Body {
    $path = New-I03OfflineZip `
        -Path (Join-Path $script:TempRoot 'valid-implicit.zip') `
        -Entries @(
            [pscustomobject]@{
                name = 'release/alpha.txt'
                bytes = [Text.Encoding]::UTF8.GetBytes('alpha-fixture')
            },
            [pscustomobject]@{
                name = 'release/nested/beta.bin'
                bytes = [byte[]](0, 1, 2, 127, 255)
            },
            [pscustomobject]@{
                name = 'release/empty.dat'; bytes = [byte[]]@()
            }
        )
    $binding = Get-I03OfflineZipBinding -Path $path `
        -ExpectedSha256 (Get-OfflineFileSha256 -Path $path) `
        -Identity $script:PackageIdentity
    Assert-I03Offline -Condition ([bool]$binding.verified) `
        -Code 'ZIP_IMPLICIT_DIRECTORY_BINDING_INVALID'
}

Invoke-I03OfflineTest -Id 'ZIP-SAME-STREAM-TOCTOU-GUARD' `
    -Category 'zip_binding' -Body {
    $text = (Get-I03HarnessFunctionAst `
        -Name 'Get-I03ZipPackageBinding').Extent.Text
    foreach ($contract in @(
        '\[IO\.FileShare\]::None',
        'ComputeHash\(\$zipStream\)',
        '\$zipStream\.Position\s*=\s*0',
        '(ZipArchive\(|ZipArchive\]::new\()\s*\r?\n?\s*\$zipStream')) {
        Assert-I03Offline -Condition ($text -match $contract) `
            -Code 'ZIP_SAME_STREAM_CONTRACT_MISSING'
    }
    Assert-I03Offline -Condition (
        $text -notmatch 'ZipFile\]::OpenRead' -and
        $text -notmatch 'Get-LabSha256\s+-Path\s+\$zip') `
        -Code 'ZIP_TOCTOU_TWO_OPEN_PATTERN'
}

Invoke-I03OfflineTest -Id 'ZIP-STALE-HASH-REJECTED' `
    -Category 'zip_binding' -Body {
    Assert-I03OfflineThrows -ExpectedCode 'ZIP_SHA256_MISMATCH' -Body {
        Get-I03OfflineZipBinding -Path $script:ValidZipPath `
            -ExpectedSha256 ('0' * 64) -Identity $script:PackageIdentity
    }
}

Invoke-I03OfflineTest -Id 'ZIP-ENTRY-TAMPER-REJECTED' `
    -Category 'zip_binding' -Body {
    $path = New-I03OfflineZip `
        -Path (Join-Path $script:TempRoot 'tampered-entry.zip') `
        -Entries @(
            [pscustomobject]@{
                name = 'release/alpha.txt'
                bytes = [Text.Encoding]::UTF8.GetBytes('tampered-fixture')
            },
            [pscustomobject]@{
                name = 'release/nested/beta.bin'
                bytes = [byte[]](0, 1, 2, 127, 255)
            },
            [pscustomobject]@{
                name = 'release/empty.dat'; bytes = [byte[]]@()
            }
        )
    Assert-I03OfflineThrows -ExpectedCode 'ENTRY_MISMATCH' -Body {
        Get-I03OfflineZipBinding -Path $path `
            -ExpectedSha256 (Get-OfflineFileSha256 -Path $path) `
            -Identity $script:PackageIdentity
    }
}

$unsafeZipNames = @(
    '../escape.txt',
    'release/../escape.txt',
    '/release/alpha.txt',
    'C:/release/alpha.txt',
    'release\\alpha.txt',
    'release//alpha.txt',
    'release/con.txt',
    'release/trailing./alpha.txt',
    'release/trailing /alpha.txt'
)
$unsafeZipIndex = 0
foreach ($unsafeName in $unsafeZipNames) {
    $unsafeZipIndex++
    $capturedUnsafeName = $unsafeName
    Invoke-I03OfflineTest -Id ('ZIP-UNSAFE-PATH-{0:D2}' -f $unsafeZipIndex) `
        -Category 'zip_binding' -Body {
        $path = New-I03OfflineZip -Path (Join-Path $script:TempRoot (
            'unsafe-' + $unsafeZipIndex + '.zip')) -Entries @(
            [pscustomobject]@{
                name = $capturedUnsafeName
                bytes = [Text.Encoding]::UTF8.GetBytes('unsafe')
            }
        )
        Assert-I03OfflineThrows -ExpectedCode 'UNSAFE_ENTRY_PATH' -Body {
            Get-I03OfflineZipBinding -Path $path `
                -ExpectedSha256 (Get-OfflineFileSha256 -Path $path) `
                -Identity $script:PackageIdentity
        }
    }
}

Invoke-I03OfflineTest -Id 'ZIP-CASE-COLLISION-REJECTED' `
    -Category 'zip_binding' -Body {
    $path = New-I03OfflineZip `
        -Path (Join-Path $script:TempRoot 'case-collision.zip') -Entries @(
            [pscustomobject]@{
                name = 'release/alpha.txt'
                bytes = [Text.Encoding]::UTF8.GetBytes('alpha-fixture')
            },
            [pscustomobject]@{
                name = 'release/ALPHA.TXT'
                bytes = [Text.Encoding]::UTF8.GetBytes('alpha-fixture')
            }
        )
    Assert-I03OfflineThrows -ExpectedCode 'DUPLICATE_OR_CASE_COLLISION' `
        -Body {
        Get-I03OfflineZipBinding -Path $path `
            -ExpectedSha256 (Get-OfflineFileSha256 -Path $path) `
            -Identity $script:PackageIdentity
    }
}

Invoke-I03OfflineTest -Id 'ZIP-PACKAGE-CASE-COLLISION-REJECTED' `
    -Category 'zip_binding' -Body {
    $first = $script:PackageIdentity.files[0]
    $duplicate = [pscustomobject][ordered]@{
        relative_path = ([string]$first.relative_path).ToUpperInvariant()
        bytes = [Int64]$first.bytes
        sha256 = [string]$first.sha256
    }
    $identity = [pscustomobject][ordered]@{
        manifest_sha256 = [string]$script:PackageIdentity.manifest_sha256
        total_bytes = [Int64]$script:PackageIdentity.total_bytes
        files = @($script:PackageIdentity.files) + @($duplicate)
    }
    Assert-I03OfflineThrows -ExpectedCode 'PACKAGE_CASE_COLLISION' -Body {
        Get-I03OfflineZipBinding -Path $script:ValidZipPath `
            -ExpectedSha256 (Get-OfflineFileSha256 `
                -Path $script:ValidZipPath) -Identity $identity
    }
}

Invoke-I03OfflineTest -Id 'ZIP-SECOND-ROOT-REJECTED' `
    -Category 'zip_binding' -Body {
    $path = New-I03OfflineZip `
        -Path (Join-Path $script:TempRoot 'second-root.zip') -Entries @(
            [pscustomobject]@{
                name = 'release/alpha.txt'
                bytes = [Text.Encoding]::UTF8.GetBytes('alpha-fixture')
            },
            [pscustomobject]@{
                name = 'other/nested/beta.bin'
                bytes = [byte[]](0, 1, 2, 127, 255)
            }
        )
    Assert-I03OfflineThrows -ExpectedCode 'MULTIPLE_ROOTS' -Body {
        Get-I03OfflineZipBinding -Path $path `
            -ExpectedSha256 (Get-OfflineFileSha256 -Path $path) `
            -Identity $script:PackageIdentity
    }
}

Invoke-I03OfflineTest -Id 'ZIP-FILE-OUTSIDE-ROOT-REJECTED' `
    -Category 'zip_binding' -Body {
    $path = New-I03OfflineZip `
        -Path (Join-Path $script:TempRoot 'rootless-file.zip') -Entries @(
            [pscustomobject]@{
                name = 'alpha.txt'
                bytes = [Text.Encoding]::UTF8.GetBytes('alpha-fixture')
            }
        )
    Assert-I03OfflineThrows -ExpectedCode 'FILE_OUTSIDE_SINGLE_ROOT' -Body {
        Get-I03OfflineZipBinding -Path $path `
            -ExpectedSha256 (Get-OfflineFileSha256 -Path $path) `
            -Identity $script:PackageIdentity
    }
}

Invoke-I03OfflineTest -Id 'ZIP-MISSING-FILE-REJECTED' `
    -Category 'zip_binding' -Body {
    $path = New-I03OfflineZip `
        -Path (Join-Path $script:TempRoot 'missing-file.zip') -Entries @(
            [pscustomobject]@{
                name = 'release/alpha.txt'
                bytes = [Text.Encoding]::UTF8.GetBytes('alpha-fixture')
            }
        )
    Assert-I03OfflineThrows -ExpectedCode 'FILE_SET_MISMATCH' -Body {
        Get-I03OfflineZipBinding -Path $path `
            -ExpectedSha256 (Get-OfflineFileSha256 -Path $path) `
            -Identity $script:PackageIdentity
    }
}

Invoke-I03OfflineTest -Id 'ZIP-EXTRA-FILE-REJECTED' `
    -Category 'zip_binding' -Body {
    $path = New-I03OfflineZip `
        -Path (Join-Path $script:TempRoot 'extra-file.zip') -Entries @(
            [pscustomobject]@{
                name = 'release/alpha.txt'
                bytes = [Text.Encoding]::UTF8.GetBytes('alpha-fixture')
            },
            [pscustomobject]@{
                name = 'release/nested/beta.bin'
                bytes = [byte[]](0, 1, 2, 127, 255)
            },
            [pscustomobject]@{
                name = 'release/empty.dat'; bytes = [byte[]]@()
            },
            [pscustomobject]@{
                name = 'release/extra.txt'
                bytes = [Text.Encoding]::UTF8.GetBytes('extra')
            }
        )
    Assert-I03OfflineThrows -ExpectedCode 'FILE_SET_MISMATCH' -Body {
        Get-I03OfflineZipBinding -Path $path `
            -ExpectedSha256 (Get-OfflineFileSha256 -Path $path) `
            -Identity $script:PackageIdentity
    }
}

Invoke-I03OfflineTest -Id 'ZIP-UNIX-LINK-ENTRY-REJECTED' `
    -Category 'zip_binding' -Body {
    $path = New-I03OfflineZip `
        -Path (Join-Path $script:TempRoot 'unix-link.zip') -Entries @(
            [pscustomobject]@{
                name = 'release/link'
                bytes = [Text.Encoding]::UTF8.GetBytes('alpha.txt')
                external_attributes = -1610612736
            }
        )
    Assert-I03OfflineThrows -ExpectedCode 'LINK_OR_REPARSE_ENTRY' -Body {
        Get-I03OfflineZipBinding -Path $path `
            -ExpectedSha256 (Get-OfflineFileSha256 -Path $path) `
            -Identity $script:PackageIdentity
    }
}

Invoke-I03OfflineTest -Id 'ZIP-DOS-REPARSE-ENTRY-REJECTED' `
    -Category 'zip_binding' -Body {
    $path = New-I03OfflineZip `
        -Path (Join-Path $script:TempRoot 'dos-reparse.zip') -Entries @(
            [pscustomobject]@{
                name = 'release/link'
                bytes = [Text.Encoding]::UTF8.GetBytes('alpha.txt')
                external_attributes = 1024
            }
        )
    Assert-I03OfflineThrows -ExpectedCode 'LINK_OR_REPARSE_ENTRY' -Body {
        Get-I03OfflineZipBinding -Path $path `
            -ExpectedSha256 (Get-OfflineFileSha256 -Path $path) `
            -Identity $script:PackageIdentity
    }
}

Invoke-I03OfflineTest -Id 'ZIP-POST-ZIP-MUTATION-REJECTED' `
    -Category 'zip_binding' -Body {
    $path = New-I03OfflineZip `
        -Path (Join-Path $script:TempRoot 'post-zip-mutation.zip') `
        -Entries @(
            [pscustomobject]@{
                name = 'release/alpha.txt'
                bytes = [Text.Encoding]::UTF8.GetBytes('alpha-fixture')
            },
            [pscustomobject]@{
                name = 'release/nested/beta.bin'
                bytes = [byte[]](0, 1, 2, 127, 255)
            },
            [pscustomobject]@{
                name = 'release/empty.dat'; bytes = [byte[]]@()
            }
        )
    $beforeSha = Get-OfflineFileSha256 -Path $path
    $append = [IO.File]::Open(
        $path, [IO.FileMode]::Append, [IO.FileAccess]::Write,
        [IO.FileShare]::None)
    try { $append.WriteByte(0x42) } finally { $append.Dispose() }
    Assert-I03OfflineThrows -ExpectedCode 'ZIP_SHA256_MISMATCH' -Body {
        Get-I03OfflineZipBinding -Path $path `
            -ExpectedSha256 $beforeSha -Identity $script:PackageIdentity
    }
}

Invoke-I03OfflineTest -Id 'ZIP-POST-PACKAGE-MUTATION-REJECTED' `
    -Category 'zip_binding' -Body {
    $package = Join-Path $script:TempRoot 'mutated-package'
    $nested = Join-Path $package 'nested'
    New-Item -ItemType Directory -Path $nested -Force | Out-Null
    [IO.File]::WriteAllBytes((Join-Path $package 'alpha.txt'),
        [Text.Encoding]::UTF8.GetBytes('alpha-fixture'))
    [IO.File]::WriteAllBytes((Join-Path $nested 'beta.bin'),
        [byte[]](0, 1, 2, 127, 255))
    [IO.File]::WriteAllBytes((Join-Path $package 'empty.dat'), [byte[]]@())
    $zip = New-I03OfflineZip `
        -Path (Join-Path $script:TempRoot 'pre-package-mutation.zip') `
        -Entries @(
            [pscustomobject]@{
                name = 'release/alpha.txt'
                bytes = [Text.Encoding]::UTF8.GetBytes('alpha-fixture')
            },
            [pscustomobject]@{
                name = 'release/nested/beta.bin'
                bytes = [byte[]](0, 1, 2, 127, 255)
            },
            [pscustomobject]@{
                name = 'release/empty.dat'; bytes = [byte[]]@()
            }
        )
    [IO.File]::WriteAllBytes((Join-Path $package 'alpha.txt'),
        [Text.Encoding]::UTF8.GetBytes('post-mutation'))
    $afterIdentity = Get-I03OfflinePackageIdentity -Path $package
    Assert-I03OfflineThrows -ExpectedCode 'ENTRY_MISMATCH' -Body {
        Get-I03OfflineZipBinding -Path $zip `
            -ExpectedSha256 (Get-OfflineFileSha256 -Path $zip) `
            -Identity $afterIdentity
    }
}

Invoke-I03OfflineTest -Id 'PACKAGE-ROOT-REPARSE-REJECTED' `
    -Category 'zip_binding' -Body {
    $target = Join-Path $script:TempRoot 'root-reparse-target'
    $link = Join-Path $script:TempRoot 'root-reparse-link'
    New-Item -ItemType Directory -Path $target -Force | Out-Null
    [IO.File]::WriteAllText((Join-Path $target 'sentinel.txt'), 'target')
    New-Item -ItemType Junction -Path $link -Target $target `
        -ErrorAction Stop | Out-Null
    try {
        Assert-I03OfflineThrows `
            -ExpectedCode 'PACKAGE_ROOT_REPARSE_OR_INVALID' -Body {
            Get-I03OfflinePackageIdentity -Path $link
        }
    } finally {
        if (Test-Path -LiteralPath $link) { [IO.Directory]::Delete($link) }
    }
}

Invoke-I03OfflineTest -Id 'PACKAGE-NESTED-REPARSE-REJECTED' `
    -Category 'zip_binding' -Body {
    $package = Join-Path $script:TempRoot 'nested-reparse-package'
    $target = Join-Path $script:TempRoot 'nested-reparse-target'
    $link = Join-Path $package 'linked-subtree'
    New-Item -ItemType Directory -Path $package -Force | Out-Null
    New-Item -ItemType Directory -Path $target -Force | Out-Null
    [IO.File]::WriteAllText((Join-Path $package 'owned.txt'), 'owned')
    [IO.File]::WriteAllText((Join-Path $target 'sentinel.txt'), 'target')
    New-Item -ItemType Junction -Path $link -Target $target `
        -ErrorAction Stop | Out-Null
    try {
        Assert-I03OfflineThrows `
            -ExpectedCode 'PACKAGE_REPARSE_OR_ESCAPE' -Body {
            Get-I03OfflinePackageIdentity -Path $package
        }
    } finally {
        if (Test-Path -LiteralPath $link) { [IO.Directory]::Delete($link) }
    }
}

Invoke-I03OfflineTest -Id 'ADAPTER-OVERLAY-DENYLIST' `
    -Category 'adapter_contract' -Body {
    $text = (Get-I03HarnessFunctionAst -Name 'Get-I03NativeAddressClass').
        Extent.Text
    $adapterAst = @($script:HarnessAst.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Get-I03AdapterEvidence'
    }, $true))[0]
    $adapterText = $adapterAst.Extent.Text.ToLowerInvariant()
    foreach ($needle in @(
        'hyper-v', 'vethernet', 'loopback', 'tunnel', 'tap', 'vpn',
        'hamachi', 'teredo', '6to4', 'isatap')) {
        Assert-I03Offline -Condition ($adapterText.Contains($needle)) `
            -Code 'ADAPTER_OVERLAY_TERM_MISSING'
    }
    Assert-I03Offline -Condition (
        $adapterText -match 'ip\[- \]\?https') `
        -Code 'IPHTTPS_ADAPTER_PATTERN_MISSING'
    Assert-I03Offline -Condition ($text.Length -gt 0) `
        -Code 'CLASSIFIER_FUNCTION_EMPTY'
}

Invoke-I03OfflineTest -Id 'AST-OFFLINE-SELF-SIDE-EFFECT-FREE' `
    -Category 'side_effect_guard' -Body {
    $tokens = $null
    $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile(
        $script:SelfPath, [ref]$tokens, [ref]$errors)
    Assert-I03Offline -Condition ($errors.Count -eq 0) `
        -Code 'OFFLINE_SELF_PARSER_ERROR'
    Assert-I03AstNoExternalSideEffects -Ast $ast `
        -Code 'OFFLINE_SELF_EXTERNAL_SIDE_EFFECT_FOUND'
}

Invoke-I03OfflineTest -Id 'AST-PURE-ALLOWLIST-EXACT-AND-EXERCISED' `
    -Category 'side_effect_guard' -Body {
    foreach ($name in $script:PureFunctionAllowlist) {
        $matches = @($script:HarnessAst.FindAll({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] `
                -and $node.Name -ceq $name
        }, $true))
        Assert-I03Offline -Condition ($matches.Count -eq 1) `
            -Code 'PURE_ALLOWLIST_FUNCTION_NOT_EXACTLY_ONE'
        Assert-I03Offline -Condition (
            $script:ExtractedFunctionNames.Contains($name)) `
            -Code 'PURE_ALLOWLIST_FUNCTION_NOT_EXERCISED'
    }
    Assert-I03Offline -Condition (
        $script:ExtractedFunctionNames.Count -eq
            $script:PureFunctionAllowlist.Count) `
        -Code 'PURE_EXTRACTION_SET_NOT_EXACT'
}

Invoke-I03OfflineTest -Id 'AST-EXTRACTED-CLOSURE-SIDE-EFFECT-FREE' `
    -Category 'side_effect_guard' -Body {
    foreach ($name in @($script:ExtractedFunctionNames)) {
        $functionAst = @($script:HarnessAst.FindAll({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] `
                -and $node.Name -ceq $name
        }, $true))[0]
        Assert-I03AstNoExternalSideEffects -Ast $functionAst `
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

Invoke-I03OfflineTest -Id 'TEMP-FIXTURE-CLEANUP' `
    -Category 'side_effect_guard' -Body {
    Assert-I03Offline -Condition $script:TempCleanupProven `
        -Code 'TEMP_FIXTURE_CLEANUP_NOT_PROVEN'
}

Invoke-I03OfflineTest -Id 'AST-HARNESS-BYTES-UNCHANGED-DURING-RUN' `
    -Category 'side_effect_guard' -Body {
    Assert-I03OfflineEqual `
        -Actual (Get-OfflineFileSha256 -Path $script:HarnessPath) `
        -Expected $script:HarnessInitialSha256 `
        -Code 'HARNESS_BYTES_CHANGED_DURING_OFFLINE_RUN'
}

$failed = @($script:Results | Where-Object status -ceq 'FAIL')
$canonicalLines = @($script:Results | Sort-Object id | ForEach-Object {
    '{0}|{1}|{2}|{3}|{4}|{5}' -f $_.id, $_.category, $_.status,
        $_.failure_type, $_.failure_id, $_.failure_sha256
}) -join "`n"
$summary = [pscustomobject][ordered]@{
    schema = 'ese.v91.i03-offline-selftest/v1'
    status = if ($failed.Count -eq 0) { 'PASS' } else { 'FAIL' }
    physical_execution_performed = $false
    formal_case_status = 'BLOCKED'
    test_count = $script:Results.Count
    pass_count = $script:Results.Count - $failed.Count
    fail_count = $failed.Count
    harness_sha256 = $script:HarnessInitialSha256
    result_sha256 = Get-OfflineStringSha256 -Value $canonicalLines
    tests = @($script:Results | Sort-Object id)
}
$summary | ConvertTo-Json -Depth 8
if ($failed.Count -ne 0) { exit 1 }
