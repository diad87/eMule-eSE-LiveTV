[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$JobRequestPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$parsed = Get-Content -LiteralPath $JobRequestPath -Raw | ConvertFrom-Json
$requestProperty = $parsed.PSObject.Properties['request']
$request = if ($null -ne $requestProperty) {
    $requestProperty.Value
} else { $parsed }
$packageManifestPath = Join-Path $PSScriptRoot 'package-manifest.json'
if (-not (Test-Path -LiteralPath $packageManifestPath -PathType Leaf)) {
    throw 'Injected complete package manifest is missing.'
}
$packageManifest = $null
$jobRoot = Split-Path -Parent ([IO.Path]::GetFullPath($JobRequestPath))
$resultPath = Join-Path $jobRoot 'result.json'
$nodePath = Join-Path $jobRoot 'node'
$evidencePath = Join-Path $jobRoot 'evidence'
$process = $null
$samples = [Collections.Generic.List[object]]::new()
$phase = 'initializing'
$failure = ''
$failurePhase = ''
$mobileTopologyValidated = $false
$initialSessionValidated = $false
$transitionStartedAt = $null
$oldEndpointExpiredAt = $null
$reconnectedAt = $null
$cancelPath = Join-Path $jobRoot 'cancel-request.json'
$runnerStartedAt = [DateTimeOffset]::UtcNow
$runnerDeadline = $null
$cooperativeStopRequested = $false
$runnerDeadlineExceeded = $false
$productFailureProven = $false
$failureCategory = 'NONE'
$nodeStagingCreated = $false
$nodeEvidence = $null
$finalHome = $null
$remotePackageEvidence = $null
$watchdogProcess = $null
$watchdogEvidence = $null
$watchdogStatePath = Join-Path $jobRoot 'wifi-watchdog-state.json'
$watchdogDisarmPath = Join-Path $jobRoot 'wifi-watchdog-disarm.flag'
$remoteProcessPreflight = $null
$remotePortBaseline = @()
$accountRegistryBefore = $null
$accountRegistryAfter = $null
$processIdentity = $null
$initialRoute = $null
$mobileRoute = $null

$requiredRequestProperties = @(
    'nonce', 'candidate_zip_path',
    'expected_emule_sha256',
    'expected_ese_server_sha256', 'expected_build_info_sha256',
    'expected_zip_sha256', 'expected_zip_bytes', 'candidate_commit',
    'candidate_version',
    'home_profile', 'hotspot_profile', 'initial_server_address',
    'mobile_server_address', 'server_port', 'topology_probe_port',
    'tcp_port', 'udp_port', 'web_port', 'runner_deadline_seconds',
    'wifi_interface_alias', 'expected_package_manifest_sha256',
    'expected_package_manifest_file_count',
    'expected_account_sid_sha256', 'disposable_account_confirmed'
)
foreach ($name in $requiredRequestProperties) {
    $property = $request.PSObject.Properties[$name]
    if ($null -eq $property -or
        [string]::IsNullOrWhiteSpace([string]$property.Value)) {
        throw "Missing required R01 request property: $name"
    }
}
$actualRequestNames = @($request.PSObject.Properties.Name | Sort-Object)
$expectedRequestNames = @($requiredRequestProperties | Sort-Object)
if (($actualRequestNames -join "`n") -cne
        ($expectedRequestNames -join "`n")) {
    throw 'R01 request must contain the exact formal property set.'
}
if (-not ($request.disposable_account_confirmed -is [bool]) -or
    -not [bool]$request.disposable_account_confirmed -or
    -not ($request.expected_package_manifest_file_count -is [int] -or
        $request.expected_package_manifest_file_count -is [Int64]) -or
    [Int64]$request.expected_package_manifest_file_count -lt 3 -or
    [string]$request.expected_package_manifest_sha256 -cnotmatch
        '^[0-9a-f]{64}$' -or
    [string]$request.expected_account_sid_sha256 -cnotmatch
        '^[0-9a-f]{64}$') {
    throw 'R01 disposable-account/package request contract is malformed.'
}
if ([string]::Equals(([string]$request.home_profile).Trim(),
        ([string]$request.hotspot_profile).Trim(),
        [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Home and hotspot must be different saved WLAN profiles.'
}
$runnerDeadlineSeconds = [int]$request.runner_deadline_seconds
if ($runnerDeadlineSeconds -lt 120 -or $runnerDeadlineSeconds -gt 1800) {
    throw 'runner_deadline_seconds must be between 120 and 1800.'
}
$runnerDeadline = $runnerStartedAt.AddSeconds($runnerDeadlineSeconds)
$wifiInterfaceAlias = if (
    $null -ne $request.PSObject.Properties['wifi_interface_alias'] -and
    -not [string]::IsNullOrWhiteSpace(
        [string]$request.wifi_interface_alias)
) { [string]$request.wifi_interface_alias } else { 'Wi-Fi' }
$remotePorts = @(
    [int]$request.server_port, [int]$request.topology_probe_port,
    [int]$request.tcp_port, [int]$request.udp_port,
    [int]$request.web_port)
if (@($remotePorts | Where-Object { $_ -lt 1024 -or $_ -gt 65535 }).Count `
        -ne 0 -or
    @($remotePorts | Select-Object -Unique).Count -ne $remotePorts.Count) {
    throw 'R01 requires five distinct, valid formal ports.'
}

function Write-JsonAtomic {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][string]$Path
    )
    $temporary = $Path + '.new'
    [IO.File]::WriteAllText(
        $temporary, ($Value | ConvertTo-Json -Depth 16),
        [Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $temporary -Destination $Path -Force
}

function Get-Hash {
    param([Parameter(Mandatory = $true)][string]$Text)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString(
                $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text))
            )).Replace('-', '').ToLowerInvariant()
    } finally { $sha.Dispose() }
}

function Get-R01StreamSha256 {
    param([Parameter(Mandatory = $true)][IO.Stream]$Stream)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString(
            $sha.ComputeHash($Stream))).Replace('-', '').ToLowerInvariant()
    } finally { $sha.Dispose() }
}

function Test-R01SafeRelativePath {
    param([Parameter(Mandatory = $true)][string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path) -or
        [IO.Path]::IsPathRooted($Path) -or $Path.Contains(':') -or
        $Path.Contains([char]0)) { return $false }
    $normalized = $Path.Replace('\', '/')
    if ($normalized.StartsWith('/') -or $normalized.EndsWith('/')) {
        return $false
    }
    $parts = @($normalized.Split('/'))
    return ($parts.Count -gt 0 -and @($parts | Where-Object {
                [string]::IsNullOrWhiteSpace($_) -or $_ -in @('.', '..')
            }).Count -eq 0)
}

function Assert-R01NoReparsePath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [switch]$AllowMissingLeaf
    )
    $full = [IO.Path]::GetFullPath($Path)
    $cursor = $full
    if (-not (Test-Path -LiteralPath $cursor)) {
        if (-not $AllowMissingLeaf) { throw "Required path is missing: $full" }
        $cursor = [IO.Path]::GetDirectoryName($cursor)
    }
    while (-not [string]::IsNullOrWhiteSpace($cursor)) {
        $item = Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "R01 rejects reparse-point path component: $cursor"
        }
        $parent = [IO.Path]::GetDirectoryName($cursor.TrimEnd('\'))
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -ceq $cursor) {
            break
        }
        $cursor = $parent
    }
    return $full
}

function Get-R01PackageManifestCanonical {
    param([Parameter(Mandatory = $true)]$Files)
    [string[]]$lines = @($Files | ForEach-Object {
            "{0}`t{1}`t{2}" -f [string]$_.relative_path,
                [Int64]$_.bytes, ([string]$_.sha256).ToLowerInvariant()
        })
    [Array]::Sort($lines, [StringComparer]::Ordinal)
    return $lines -join "`n"
}

function Assert-R01PackageManifestContract {
    param(
        [Parameter(Mandatory = $true)]$Manifest,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256,
        [Parameter(Mandatory = $true)][int]$ExpectedFileCount
    )
    $rootNames = @($Manifest.PSObject.Properties.Name | Sort-Object)
    $expectedRootNames = @(
        'schema', 'zip_root_prefix', 'zip_sha256', 'zip_bytes',
        'file_count', 'manifest_sha256', 'exact_file_set',
        'exact_bytes_and_sha256', 'locked_snapshot', 'reparse_free',
        'files') | Sort-Object
    $prefix = [string]$Manifest.zip_root_prefix
    $prefixValid = ($Manifest.zip_root_prefix -is [string]) -and $(
        if ([string]::IsNullOrEmpty($prefix)) { $true }
        else {
            $prefix.EndsWith('/') -and -not $prefix.Contains('\') -and
            (Test-R01SafeRelativePath -Path $prefix.TrimEnd('/'))
        })
    if (($rootNames -join "`n") -cne ($expectedRootNames -join "`n") -or
        [string]$Manifest.schema -cne 'ese.v91.package-zip-binding/v3' -or
        -not $prefixValid -or
        -not ($Manifest.zip_sha256 -is [string]) -or
        [string]$Manifest.zip_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        -not ($Manifest.zip_bytes -is [int] -or
            $Manifest.zip_bytes -is [Int64]) -or
        [Int64]$Manifest.zip_bytes -lt 1 -or
        -not ($Manifest.file_count -is [int] -or
            $Manifest.file_count -is [Int64]) -or
        -not ($Manifest.manifest_sha256 -is [string]) -or
        [string]$Manifest.manifest_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        -not ($Manifest.files -is [Array]) -or
        -not ($Manifest.exact_file_set -is [bool]) -or
        -not [bool]$Manifest.exact_file_set -or
        -not ($Manifest.exact_bytes_and_sha256 -is [bool]) -or
        -not [bool]$Manifest.exact_bytes_and_sha256 -or
        -not ($Manifest.locked_snapshot -is [bool]) -or
        -not [bool]$Manifest.locked_snapshot -or
        -not ($Manifest.reparse_free -is [bool]) -or
        -not [bool]$Manifest.reparse_free -or
        [int]$Manifest.file_count -ne $ExpectedFileCount -or
        @($Manifest.files).Count -ne $ExpectedFileCount) {
        throw 'Remote package manifest root contract is invalid.'
    }
    $seen = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    foreach ($file in @($Manifest.files)) {
        $names = @($file.PSObject.Properties.Name | Sort-Object)
        if (($names -join ',') -cne 'bytes,relative_path,sha256' -or
            -not ($file.relative_path -is [string]) -or
            -not ($file.sha256 -is [string]) -or
            -not ($file.bytes -is [int] -or $file.bytes -is [Int64]) -or
            -not (Test-R01SafeRelativePath -Path ([string]$file.relative_path)) -or
            -not $seen.Add([string]$file.relative_path) -or
            [Int64]$file.bytes -lt 1 -or
            [string]$file.sha256 -cnotmatch '^[0-9a-f]{64}$') {
            throw 'Remote package manifest contains an unsafe file contract.'
        }
    }
    $canonical = Get-R01PackageManifestCanonical -Files @($Manifest.files)
    $actual = Get-Hash -Text $canonical
    if ($actual -cne $ExpectedSha256 -or
        [string]$Manifest.manifest_sha256 -cne $ExpectedSha256) {
        throw 'Remote package manifest canonical digest does not match request.'
    }
    return $true
}

function Get-R01RegularFileCensus {
    param([Parameter(Mandatory = $true)][string]$Root)
    $rootFull = (Assert-R01NoReparsePath -Path $Root).TrimEnd('\')
    $prefix = $rootFull + '\'
    $queue = [Collections.Generic.Queue[string]]::new()
    $queue.Enqueue($rootFull)
    $seen = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    $files = [Collections.Generic.List[object]]::new()
    while ($queue.Count -gt 0) {
        $directory = $queue.Dequeue()
        foreach ($item in @(Get-ChildItem -LiteralPath $directory -Force `
                -ErrorAction Stop)) {
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'R01 file census encountered a reparse point.'
            }
            $full = [IO.Path]::GetFullPath([string]$item.FullName)
            if (-not $full.StartsWith(
                    $prefix, [StringComparison]::OrdinalIgnoreCase)) {
                throw 'R01 file census escaped its root.'
            }
            if ($item.PSIsContainer) { $queue.Enqueue($full); continue }
            $relative = $full.Substring($prefix.Length).Replace('\', '/')
            if (-not (Test-R01SafeRelativePath -Path $relative) -or
                -not $seen.Add($relative)) {
                throw 'R01 file census found traversal or a case collision.'
            }
            $stream = [IO.File]::Open($full, [IO.FileMode]::Open,
                [IO.FileAccess]::Read, [IO.FileShare]::Read)
            try { $sha = Get-R01StreamSha256 -Stream $stream }
            finally { $stream.Dispose() }
            $files.Add([pscustomobject][ordered]@{
                    relative_path = $relative
                    full_path = $full
                    bytes = [Int64]$item.Length; sha256 = $sha
                })
        }
    }
    return @($files | Sort-Object relative_path)
}

function Get-R01RegistrySubtreeEvidence {
    param([Parameter(Mandatory = $true)][string]$RelativePath)
    $root = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey(
        $RelativePath, $false)
    if ($null -eq $root) {
        return [pscustomobject][ordered]@{
            exists = $false; node_count = 0; value_count = 0
            canonical_sha256 = Get-Hash -Text 'absent'
        }
    }
    $lines = [Collections.Generic.List[string]]::new()
    $nodeCount = 0
    $valueCount = 0
    function Visit-R01RegistryKey {
        param($Key, [string]$Name)
        $script:registryNodeCount++
        $lines.Add('K|' + $Name.ToLowerInvariant())
        foreach ($valueName in @($Key.GetValueNames() | Sort-Object)) {
            $kind = [string]$Key.GetValueKind($valueName)
            $value = $Key.GetValue($valueName, $null,
                [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            $serialized = if ($value -is [byte[]]) {
                [Convert]::ToBase64String($value)
            } elseif ($value -is [string[]]) {
                @($value | ForEach-Object {
                    ([string]$_).Length.ToString() + ':' + [string]$_
                }) -join '|'
            } else { [string]$value }
            $lines.Add(('V|{0}|{1}|{2}' -f
                ([string]$valueName).ToLowerInvariant(), $kind,
                (Get-Hash -Text $serialized)))
            $script:registryValueCount++
        }
        foreach ($childName in @($Key.GetSubKeyNames() | Sort-Object)) {
            $child = $Key.OpenSubKey($childName, $false)
            if ($null -eq $child) { throw 'Registry subtree changed during capture.' }
            try { Visit-R01RegistryKey -Key $child -Name ($Name + '\' + $childName) }
            finally { $child.Dispose() }
        }
    }
    $script:registryNodeCount = 0
    $script:registryValueCount = 0
    try { Visit-R01RegistryKey -Key $root -Name $RelativePath }
    finally { $root.Dispose() }
    $nodeCount = $script:registryNodeCount
    $valueCount = $script:registryValueCount
    Remove-Variable -Scope Script -Name registryNodeCount -ErrorAction SilentlyContinue
    Remove-Variable -Scope Script -Name registryValueCount -ErrorAction SilentlyContinue
    return [pscustomobject][ordered]@{
        exists = $true; node_count = $nodeCount; value_count = $valueCount
        canonical_sha256 = Get-Hash -Text (@($lines) -join "`n")
    }
}

function Get-R01AccountRegistrySnapshot {
    param(
        [Parameter(Mandatory = $true)][string]$ExpectedSidSha256,
        [Parameter(Mandatory = $true)][bool]$DisposableConfirmed
    )
    if (-not $DisposableConfirmed) { throw 'Disposable account was not confirmed.' }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ($null -eq $identity -or $null -eq $identity.User) {
        throw 'Current Windows account SID is unavailable.'
    }
    $sidHash = Get-Hash -Text ([string]$identity.User.Value)
    if ($sidHash -cne $ExpectedSidSha256) {
        throw 'Current H3 account SID does not match the disposable lab account.'
    }
    $runPath = 'Software\Microsoft\Windows\CurrentVersion\Run'
    $runKey = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($runPath, $false)
    if ($null -eq $runKey) {
        throw 'HKCU Run must already exist before eMule startup.'
    }
    try {
        $autoNames = @($runKey.GetValueNames() | Where-Object {
                [string]$_ -ieq 'eMuleAutoStart'
            })
        if ($autoNames.Count -ne 0) {
            throw 'HKCU Run/eMuleAutoStart must be absent before formal R01.'
        }
    } finally { $runKey.Dispose() }
    $runEvidence = Get-R01RegistrySubtreeEvidence -RelativePath $runPath
    $ed2kEvidence = Get-R01RegistrySubtreeEvidence `
        -RelativePath 'Software\Classes\ed2k'
    $canonical = @(
        $sidHash, [string]$runEvidence.canonical_sha256,
        [string]$ed2kEvidence.canonical_sha256,
        [string]$runEvidence.node_count, [string]$runEvidence.value_count,
        [string]$ed2kEvidence.node_count, [string]$ed2kEvidence.value_count
    ) -join '|'
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.r01-account-registry/v1'
        sid_sha256 = $sidHash
        account_name_sha256 = Get-Hash -Text ([string]$identity.Name)
        disposable_account_confirmed = $true
        run_key_exists = $true
        emule_autostart_absent = $true
        run_subtree = $runEvidence
        ed2k_subtree = $ed2kEvidence
        snapshot_sha256 = Get-Hash -Text $canonical
    }
}

function Test-R01AccountRegistrySnapshotEqual {
    param(
        [Parameter(Mandatory = $true)]$Before,
        [Parameter(Mandatory = $true)]$After
    )
    return ([string]$Before.schema -ceq [string]$After.schema -and
        [string]$Before.sid_sha256 -ceq [string]$After.sid_sha256 -and
        [string]$Before.snapshot_sha256 -ceq [string]$After.snapshot_sha256 -and
        [string]$Before.run_subtree.canonical_sha256 -ceq
            [string]$After.run_subtree.canonical_sha256 -and
        [string]$Before.ed2k_subtree.canonical_sha256 -ceq
            [string]$After.ed2k_subtree.canonical_sha256)
}

function Get-R01PortBaseline {
    param(
        [Parameter(Mandatory = $true)][int[]]$TcpPorts,
        [Parameter(Mandatory = $true)][int[]]$UdpPorts
    )
    $tcpRows = @(Get-NetTCPConnection -ErrorAction Stop)
    $udpRows = @(Get-NetUDPEndpoint -ErrorAction Stop)
    $rows = [Collections.Generic.List[object]]::new()
    foreach ($port in $TcpPorts) {
        $owners = @($tcpRows | Where-Object { [int]$_.LocalPort -eq $port } |
                Select-Object -ExpandProperty OwningProcess -Unique)
        $rows.Add([pscustomobject][ordered]@{
                protocol = 'TCP'; port = $port
                available = $owners.Count -eq 0; owner_count = $owners.Count
            })
    }
    foreach ($port in $UdpPorts) {
        $owners = @($udpRows | Where-Object { [int]$_.LocalPort -eq $port } |
                Select-Object -ExpandProperty OwningProcess -Unique)
        $rows.Add([pscustomobject][ordered]@{
                protocol = 'UDP'; port = $port
                available = $owners.Count -eq 0; owner_count = $owners.Count
            })
    }
    return @($rows)
}

function Remove-R01TreeNoReparse {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedParent
    )
    $parent = (Assert-R01NoReparsePath -Path $ExpectedParent).TrimEnd('\')
    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    if ([IO.Path]::GetDirectoryName($full) -cne $parent) {
        throw 'R01 cleanup target is not a direct nonce-owned child.'
    }
    if (-not (Test-Path -LiteralPath $full)) { return $true }
    $null = Assert-R01NoReparsePath -Path $full
    function Remove-R01EntryNoReparse {
        param([string]$Entry)
        $item = Get-Item -LiteralPath $Entry -Force -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'R01 cleanup refuses to traverse or delete a reparse point.'
        }
        if ($item.PSIsContainer) {
            foreach ($child in @(Get-ChildItem -LiteralPath $Entry -Force `
                    -ErrorAction Stop)) {
                Remove-R01EntryNoReparse -Entry ([string]$child.FullName)
            }
            [IO.Directory]::Delete([string]$item.FullName, $false)
        } else { [IO.File]::Delete([string]$item.FullName) }
    }
    Remove-R01EntryNoReparse -Entry $full
    return -not (Test-Path -LiteralPath $full)
}

function Assert-R01RunActive {
    if (Test-Path -LiteralPath $script:cancelPath -PathType Leaf) {
        throw [OperationCanceledException]::new(
            'R01 cooperative cancellation requested.')
    }
    if ([DateTimeOffset]::UtcNow -ge $script:runnerDeadline) {
        throw [TimeoutException]::new(
            'R01 autonomous runner deadline exceeded.')
    }
}

function Stop-R01ProductFailure {
    param([Parameter(Mandatory = $true)][string]$Message)
    throw "R01_PRODUCT::$Message"
}

function Stop-R01LabFailure {
    param([Parameter(Mandatory = $true)][string]$Message)
    throw "R01_LAB::$Message"
}

function Start-R01WifiWatchdog {
    $scriptPath = Join-Path $PSScriptRoot 'run_v91_r01_wifi_watchdog.ps1'
    if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) {
        throw 'Independent Wi-Fi watchdog script is missing.'
    }
    if ([string]$script:request.home_profile -match '"' -or
        $script:wifiInterfaceAlias -match '"') {
        throw 'Wi-Fi profile/interface contains an unsupported quote.'
    }
    Remove-Item -LiteralPath $script:watchdogStatePath,
        $script:watchdogDisarmPath -Force -ErrorAction SilentlyContinue
    $deadline = $script:runnerDeadline.AddSeconds(90)
    $powershell = Join-Path $env:SystemRoot `
        'System32\WindowsPowerShell\v1.0\powershell.exe'
    $arguments = '-NoProfile -ExecutionPolicy Bypass -File "{0}" ' +
        '-StatePath "{1}" -DisarmPath "{2}" -HomeProfile "{3}" ' +
        '-WifiInterfaceAlias "{4}" -ExpectedInterfaceGuid "{5}" ' +
        '-ExpectedHomeWlanProfileSha256 "{6}" ' +
        '-ExpectedHomeConnectionProfileSha256 "{7}" ' +
        '-DeadlineUtc "{8}" -NonceSha256 "{9}"' -f $scriptPath,
        $script:watchdogStatePath, $script:watchdogDisarmPath,
        [string]$script:request.home_profile, $script:wifiInterfaceAlias,
        [string]$script:initial.interface_guid,
        [string]$script:initial.wlan_profile_sha256,
        [string]$script:initial.connection_profile.name_sha256,
        $deadline.ToString('o'),
        (Get-Hash -Text ([string]$script:request.nonce))
    $script:watchdogProcess = Start-Process -FilePath $powershell `
        -ArgumentList $arguments -WindowStyle Hidden -PassThru
    $readyDeadline = [DateTimeOffset]::UtcNow.AddSeconds(10)
    do {
        if (Test-Path -LiteralPath $script:watchdogStatePath -PathType Leaf) {
            $state = Get-Content -LiteralPath $script:watchdogStatePath -Raw |
                ConvertFrom-Json
            if ([bool]$state.armed -and
                [string]$state.schema -ceq
                    'ese.v91.r01-wifi-watchdog/v1') {
                $script:watchdogEvidence = $state
                return
            }
        }
        $script:watchdogProcess.Refresh()
        if ($script:watchdogProcess.HasExited) {
            throw 'Independent Wi-Fi watchdog exited before arming.'
        }
        Start-Sleep -Milliseconds 100
    } while ([DateTimeOffset]::UtcNow -lt $readyDeadline)
    throw 'Timed out arming the independent Wi-Fi watchdog.'
}

function Complete-R01WifiWatchdog {
    param([Parameter(Mandatory = $true)][bool]$HomeRestored)
    if ($null -eq $script:watchdogProcess) { return }
    if ($HomeRestored) {
        [IO.File]::WriteAllText($script:watchdogDisarmPath, 'disarm',
            [Text.Encoding]::ASCII)
        $null = $script:watchdogProcess.WaitForExit(10000)
    }
    if (Test-Path -LiteralPath $script:watchdogStatePath -PathType Leaf) {
        $script:watchdogEvidence = Get-Content `
            -LiteralPath $script:watchdogStatePath -Raw | ConvertFrom-Json
    }
}

function Set-IniValue {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Section,
        [Parameter(Mandatory = $true)][string]$Key,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value
    )
    $lines = [Collections.Generic.List[string]]::new()
    if (Test-Path -LiteralPath $Path) {
        foreach ($line in [IO.File]::ReadAllLines($Path)) {
            $lines.Add($line)
        }
    }
    $sectionPattern = '^\s*\[' + [regex]::Escape($Section) + '\]\s*$'
    $keyPattern = '^\s*' + [regex]::Escape($Key) + '\s*='
    $sectionIndex = -1
    $sectionEnd = $lines.Count
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match $sectionPattern) {
            $sectionIndex = $i
            for ($j = $i + 1; $j -lt $lines.Count; $j++) {
                if ($lines[$j] -match '^\s*\[.+\]\s*$') {
                    $sectionEnd = $j
                    break
                }
            }
            break
        }
    }
    $newLine = "$Key=$Value"
    if ($sectionIndex -ge 0) {
        for ($i = $sectionIndex + 1; $i -lt $sectionEnd; $i++) {
            if ($lines[$i] -match $keyPattern) {
                $lines[$i] = $newLine
                [IO.File]::WriteAllLines(
                    $Path, $lines, [Text.UTF8Encoding]::new($false))
                return
            }
        }
        $lines.Insert($sectionEnd, $newLine)
    } else {
        if ($lines.Count -gt 0 -and $lines[$lines.Count - 1]) {
            $lines.Add('')
        }
        $lines.Add("[$Section]")
        $lines.Add($newLine)
    }
    [IO.File]::WriteAllLines(
        $Path, $lines, [Text.UTF8Encoding]::new($false))
}

function Get-CurrentProfile {
    $netsh = Join-Path $env:SystemRoot 'System32\netsh.exe'
    if (-not (Test-Path -LiteralPath $netsh -PathType Leaf)) {
        throw 'The trusted system netsh.exe is unavailable.'
    }
    $output = @(& $netsh wlan show interfaces 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "netsh wlan show interfaces failed with exit code $LASTEXITCODE."
    }
    $text = ($output | Out-String)
    foreach ($line in ($text -split "`r?`n")) {
        if ($line -match '(?i)^\s*(?:perfil|profile)\s+:\s*(.+?)\s*$') {
            return $Matches[1].Trim()
        }
    }
    return ''
}

function Connect-Profile {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [int]$TimeoutSeconds = 45,
        [switch]$Cleanup
    )
    $netsh = Join-Path $env:SystemRoot 'System32\netsh.exe'
    if (-not (Test-Path -LiteralPath $netsh -PathType Leaf)) {
        throw 'The trusted system netsh.exe is unavailable.'
    }
    $output = @(& $netsh wlan connect name="$Name" `
        interface="$script:wifiInterfaceAlias" 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "netsh wlan connect failed with exit code ${LASTEXITCODE}: $($output -join ' ')"
    }
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        if (-not $Cleanup) { Assert-R01RunActive }
        Start-Sleep -Milliseconds 500
        if ((Get-CurrentProfile) -ceq $Name) {
            Start-Sleep -Seconds 2
            return
        }
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    throw "Timed out connecting Wi-Fi profile '$Name'."
}

function Get-R01IPv4Class {
    param([Parameter(Mandatory = $true)][string]$Address)
    $parsedAddress = $null
    if (-not [Net.IPAddress]::TryParse($Address, [ref]$parsedAddress) -or
        $parsedAddress.AddressFamily -ne
            [Net.Sockets.AddressFamily]::InterNetwork) {
        return 'invalid'
    }
    $bytes = $parsedAddress.GetAddressBytes()
    if ($bytes[0] -eq 10 -or
        ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) -or
        ($bytes[0] -eq 192 -and $bytes[1] -eq 168)) { return 'private' }
    if ($bytes[0] -eq 100 -and $bytes[1] -ge 64 -and
        $bytes[1] -le 127) { return 'shared-cgnat' }
    if ($bytes[0] -eq 127) { return 'loopback' }
    if ($bytes[0] -eq 169 -and $bytes[1] -eq 254) { return 'link-local' }
    $special =
        $bytes[0] -eq 0 -or $bytes[0] -ge 224 -or
        ($bytes[0] -eq 192 -and $bytes[1] -eq 0 -and $bytes[2] -eq 0) -or
        ($bytes[0] -eq 192 -and $bytes[1] -eq 0 -and $bytes[2] -eq 2) -or
        ($bytes[0] -eq 192 -and $bytes[1] -eq 31 -and $bytes[2] -eq 196) -or
        ($bytes[0] -eq 192 -and $bytes[1] -eq 52 -and $bytes[2] -eq 193) -or
        ($bytes[0] -eq 192 -and $bytes[1] -eq 88 -and $bytes[2] -eq 99) -or
        ($bytes[0] -eq 192 -and $bytes[1] -eq 175 -and $bytes[2] -eq 48) -or
        ($bytes[0] -eq 198 -and $bytes[1] -in 18, 19) -or
        ($bytes[0] -eq 198 -and $bytes[1] -eq 51 -and $bytes[2] -eq 100) -or
        ($bytes[0] -eq 203 -and $bytes[1] -eq 0 -and $bytes[2] -eq 113)
    if ($special) {
        return 'special'
    }
    return 'global'
}

function ConvertTo-R01NetworkProfileEvidence {
    param([Parameter(Mandatory = $true)]$Profile)
    return [pscustomobject][ordered]@{
        schema = 'ese.lab.windows-network-profile/v1'
        name_sha256 = Get-Hash -Text ([string]$Profile.Name)
        network_category = [string]$Profile.NetworkCategory
        ipv4_connectivity = [string]$Profile.IPv4Connectivity
        ipv6_connectivity = [string]$Profile.IPv6Connectivity
    }
}

function Test-R01OverlayAdapter {
    param([Parameter(Mandatory = $true)]$Adapter)
    $text = @(
        [string]$Adapter.Name, [string]$Adapter.InterfaceAlias,
        [string]$Adapter.InterfaceDescription) -join ' '
    return $text -match (
        '(?i)tailscale|wireguard|cloudflare|warp|zerotier|openvpn|' +
        'hyper-v|vethernet|loopback|tunnel|tap|vpn|hamachi')
}

function Get-WifiSnapshot {
    param([Parameter(Mandatory = $true)][string]$ExpectedProfile)
    $adapter = Get-NetAdapter -Name $script:wifiInterfaceAlias `
        -ErrorAction Stop
    $currentProfile = Get-CurrentProfile
    $connectionProfiles = @(Get-NetConnectionProfile `
            -InterfaceIndex $adapter.ifIndex -ErrorAction Stop)
    if ($connectionProfiles.Count -ne 1) {
        throw 'Expected one Windows network connection profile on Wi-Fi.'
    }
    $addresses = @(
        Get-NetIPAddress -InterfaceIndex $adapter.ifIndex `
            -ErrorAction Stop |
            Where-Object {
                $_.AddressState -notin 'Invalid', 'Duplicate' -and
                $_.AddressFamily -in 'IPv4', 'IPv6'
            } |
            ForEach-Object {
                [pscustomobject][ordered]@{
                    family = [string]$_.AddressFamily
                    address = [string]$_.IPAddress
                    prefix_length = [int]$_.PrefixLength
                    address_state = [string]$_.AddressState
                    skip_as_source = [bool]$_.SkipAsSource
                }
            }
    )
    $routes = @(
        Get-NetRoute -InterfaceIndex $adapter.ifIndex `
            -ErrorAction Stop |
            Where-Object {
                $_.DestinationPrefix -in '0.0.0.0/0', '::/0'
            } |
            ForEach-Object {
                [pscustomobject][ordered]@{
                    destination = [string]$_.DestinationPrefix
                    next_hop = [string]$_.NextHop
                    metric = [int]$_.RouteMetric
                }
            }
    )
    return [pscustomobject][ordered]@{
        captured_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
        profile_matches_expected = $currentProfile -ceq $ExpectedProfile
        wlan_profile_sha256 = Get-Hash -Text $currentProfile
        connection_profile = ConvertTo-R01NetworkProfileEvidence `
            -Profile $connectionProfiles[0]
        interface_index = [int]$adapter.ifIndex
        interface_guid = [string]$adapter.InterfaceGuid
        interface_alias = [string]$adapter.Name
        interface_description = [string]$adapter.InterfaceDescription
        hardware_interface = [bool]$adapter.HardwareInterface
        virtual = [bool]$adapter.Virtual
        overlay = Test-R01OverlayAdapter -Adapter $adapter
        status = [string]$adapter.Status
        addresses = $addresses
        routes = $routes
    }
}

function Get-R01SelectedRouteEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$RemoteAddress,
        [Parameter(Mandatory = $true)]$Snapshot,
        [string]$ExpectedSourceAddress = ''
    )
    $objects = @(Find-NetRoute -RemoteIPAddress $RemoteAddress `
        -ErrorAction Stop)
    $route = @($objects | Where-Object {
            $null -ne $_.PSObject.Properties['DestinationPrefix'] -and
            -not [string]::IsNullOrWhiteSpace([string]$_.DestinationPrefix)
        }) | Select-Object -First 1
    $sourceRow = @($objects | Where-Object {
            $null -ne $_.PSObject.Properties['IPAddress'] -and
            -not [string]::IsNullOrWhiteSpace([string]$_.IPAddress)
        }) | Select-Object -First 1
    if ($null -eq $route -or $null -eq $sourceRow) {
        throw 'Find-NetRoute returned no exact route/source pair.'
    }
    $source = [string]$sourceRow.IPAddress
    $adapter = Get-NetAdapter -InterfaceIndex ([int]$route.InterfaceIndex) `
        -IncludeHidden -ErrorAction Stop
    $overlay = Test-R01OverlayAdapter -Adapter $adapter
    $valid = [int]$route.InterfaceIndex -eq [int]$Snapshot.interface_index -and
        ([string]$adapter.InterfaceGuid).Trim('{}') -ieq
            ([string]$Snapshot.interface_guid).Trim('{}') -and
        [bool]$adapter.HardwareInterface -and -not [bool]$adapter.Virtual -and
        -not $overlay -and [string]$adapter.Status -ceq 'Up' -and
        ([string]::IsNullOrWhiteSpace($ExpectedSourceAddress) -or
            $source -ceq $ExpectedSourceAddress) -and
        @($Snapshot.addresses | Where-Object {
                [string]$_.family -ceq 'IPv4' -and
                -not [bool]$_.skip_as_source -and
                [string]$_.address -ceq $source
            }).Count -eq 1
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.r01-selected-route/v1'
        captured_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
        valid = $valid; remote_address = $RemoteAddress
        source_address = $source
        interface_index = [int]$route.InterfaceIndex
        interface_guid = [string]$adapter.InterfaceGuid
        destination_prefix = [string]$route.DestinationPrefix
        next_hop = [string]$route.NextHop
        hardware_interface = [bool]$adapter.HardwareInterface
        virtual = [bool]$adapter.Virtual; overlay = $overlay
    }
}

function Test-MobileTopologyProbe {
    param(
        [Parameter(Mandatory = $true)][string]$RemoteAddress,
        [Parameter(Mandatory = $true)][int]$RemotePort,
        [Parameter(Mandatory = $true)]$Snapshot,
        [Parameter(Mandatory = $true)][string]$Nonce,
        [int]$TimeoutSeconds = 15
    )
    $selectedRoute = Get-R01SelectedRouteEvidence `
        -RemoteAddress $RemoteAddress -Snapshot $Snapshot
    if (-not [bool]$selectedRoute.valid) {
        throw 'Public topology probe route is not the selected physical Wi-Fi NIC.'
    }
    $candidates = @($Snapshot.addresses | Where-Object {
            $_.family -eq 'IPv4' -and -not $_.skip_as_source -and
            $_.address -ceq [string]$selectedRoute.source_address
        })
    foreach ($candidate in $candidates) {
        Assert-R01RunActive
        $client = New-Object Net.Sockets.TcpClient(
            [Net.Sockets.AddressFamily]::InterNetwork)
        try {
            $localAddress = [Net.IPAddress]::Parse([string]$candidate.address)
            $client.Client.Bind((New-Object Net.IPEndPoint($localAddress, 0)))
            $async = $client.BeginConnect($RemoteAddress, $RemotePort,
                $null, $null)
            if (-not $async.AsyncWaitHandle.WaitOne($TimeoutSeconds * 1000)) {
                continue
            }
            Assert-R01RunActive
            $client.EndConnect($async)
            $stream = $client.GetStream()
            $stream.ReadTimeout = $TimeoutSeconds * 1000
            $stream.WriteTimeout = $TimeoutSeconds * 1000
            $writer = New-Object IO.StreamWriter(
                $stream, (New-Object Text.UTF8Encoding($false)), 1024, $true)
            $writer.NewLine = "`n"
            $reader = New-Object IO.StreamReader(
                $stream, (New-Object Text.UTF8Encoding($false)),
                $false, 1024, $true)
            $writer.WriteLine($Nonce)
            $writer.Flush()
            $reply = $reader.ReadLine()
            if ($reply -cne $Nonce) { continue }
            $localEndpoint = [Net.IPEndPoint]$client.Client.LocalEndPoint
            $remoteEndpoint = [Net.IPEndPoint]$client.Client.RemoteEndPoint
            return [pscustomobject][ordered]@{
                status = 'PASS'
                at_utc = [DateTimeOffset]::UtcNow.ToString('o')
                local_address = $localEndpoint.Address.ToString()
                local_port = $localEndpoint.Port
                remote_address = $remoteEndpoint.Address.ToString()
                remote_port = $remoteEndpoint.Port
                interface_index = [int]$Snapshot.interface_index
                interface_guid = [string]$Snapshot.interface_guid
                physical_nonvirtual = [bool]$Snapshot.hardware_interface -and
                    -not [bool]$Snapshot.virtual -and
                    -not [bool]$Snapshot.overlay
                selected_route = $selectedRoute
            }
        } catch {
        } finally {
            $client.Dispose()
        }
    }
    throw 'Public topology probe was not reachable from the mobile Wi-Fi NIC.'
}

function Get-OwnedServerSockets {
    param(
        [Parameter(Mandatory = $true)][int]$ProcessId,
        [Parameter(Mandatory = $true)][string]$RemoteAddress
    )
    try {
        return @(
            Get-NetTCPConnection -OwningProcess $ProcessId `
                -ErrorAction Stop | Where-Object {
                    [string]$_.RemoteAddress -ceq $RemoteAddress -and
                    [int]$_.RemotePort -eq [int]$request.server_port
                } |
                ForEach-Object {
                    [pscustomobject][ordered]@{
                        state = [string]$_.State
                        local_address = [string]$_.LocalAddress
                        local_port = [int]$_.LocalPort
                        remote_address = [string]$_.RemoteAddress
                        remote_port = [int]$_.RemotePort
                        owning_process = [int]$_.OwningProcess
                        process_start_time_utc = if (
                            $null -ne $script:processIdentity) {
                            [string]$script:processIdentity.start_time_utc
                        } else { '' }
                        executable_path_sha256 = if (
                            $null -ne $script:processIdentity) {
                            [string]$script:processIdentity.executable_path_sha256
                        } else { '' }
                        executable_sha256 = if (
                            $null -ne $script:processIdentity) {
                            [string]$script:processIdentity.executable_sha256
                        } else { '' }
                    }
                }
        )
    } catch {
        Stop-R01LabFailure -Message (
            "Unable to observe PID-owned eD2K sockets: " +
            $_.Exception.Message)
    }
}

function Wait-Established {
    param(
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][string]$RemoteAddress,
        [int]$TimeoutSeconds = 180,
        [string]$DifferentLocalAddress = ''
    )
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        Assert-R01RunActive
        $Process.Refresh()
        if ($Process.HasExited) { throw 'Candidate exited during R01.' }
        if ($null -eq $script:processIdentity -or
            -not (Test-R01ProcessIdentity -Process $Process `
                -Identity $script:processIdentity `
                -ExpectedPath $script:emulePath `
                -ExpectedSha256 ([string]$script:request.expected_emule_sha256))) {
            Stop-R01LabFailure -Message 'Candidate process identity tuple changed.'
        }
        $rows = @(Get-OwnedServerSockets -ProcessId $Process.Id `
                -RemoteAddress $RemoteAddress |
                Where-Object {
                    $_.state -eq 'Established' -and
                    (-not $DifferentLocalAddress -or
                        $_.local_address -ne $DifferentLocalAddress)
                })
        $samples.Add([pscustomobject][ordered]@{
                at_utc = [DateTimeOffset]::UtcNow.ToString('o')
                phase = $script:phase
                process_id = $Process.Id
                sockets = @(Get-OwnedServerSockets -ProcessId $Process.Id `
                    -RemoteAddress $RemoteAddress)
            })
        if ($rows.Count -eq 1) { return $rows[0] }
        Start-Sleep -Milliseconds 500
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    throw "Timed out waiting for Established server socket in $phase."
}

function Wait-Api {
    param(
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [int]$TimeoutSeconds = 90
    )
    $uri = "http://127.0.0.1:$($request.web_port)/api/status"
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        Assert-R01RunActive
        $Process.Refresh()
        if ($Process.HasExited) { throw 'Candidate exited before API ready.' }
        if ($null -eq $script:processIdentity -or
            -not (Test-R01ProcessIdentity -Process $Process `
                -Identity $script:processIdentity `
                -ExpectedPath $script:emulePath `
                -ExpectedSha256 ([string]$script:request.expected_emule_sha256))) {
            Stop-R01LabFailure -Message 'Candidate process identity tuple changed.'
        }
        try {
            return Invoke-RestMethod -Uri $uri -TimeoutSec 2
        } catch {
            Start-Sleep -Milliseconds 500
        }
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    throw 'Candidate API did not become responsive.'
}

function Get-R01ApiListenerEvidence {
    param([Parameter(Mandatory = $true)][Diagnostics.Process]$Process)
    if ($null -eq $script:processIdentity -or
        -not (Test-R01ProcessIdentity -Process $Process `
            -Identity $script:processIdentity -ExpectedPath $script:emulePath `
            -ExpectedSha256 ([string]$script:request.expected_emule_sha256))) {
        Stop-R01LabFailure -Message 'API listener process identity is not proven.'
    }
    try {
        $listeners = @(Get-NetTCPConnection -State Listen `
                -ErrorAction Stop | Where-Object {
                    [int]$_.LocalPort -eq [int]$script:request.web_port
                })
    } catch {
        Stop-R01LabFailure -Message (
            "Unable to observe Web API listeners: " +
            $_.Exception.Message)
    }
    $rows = @($listeners | Where-Object {
            $_.OwningProcess -eq $Process.Id
        })
    $unexpected = @($listeners | Where-Object {
            $_.OwningProcess -ne $Process.Id
        })
    if ($rows.Count -lt 1 -or $unexpected.Count -gt 0) {
        throw 'Web API listener is not exclusively PID-owned.'
    }
    return @($rows | ForEach-Object {
            [pscustomobject][ordered]@{
                local_address = [string]$_.LocalAddress
                local_port = [int]$_.LocalPort
                state = [string]$_.State
                owning_process = [int]$_.OwningProcess
            }
        })
}

function Wait-ApiEd2kConnected {
    param(
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [int]$TimeoutSeconds = 30
    )
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        try {
            $status = Wait-Api -Process $Process -TimeoutSeconds 3
            $property = $status.PSObject.Properties['ed2k_connected']
            if ($null -ne $property -and [bool]$property.Value) {
                return $status
            }
        } catch {
            if ($_.Exception -is [OperationCanceledException] -or
                $_.Exception -is [TimeoutException]) { throw }
            $Process.Refresh()
            if ($Process.HasExited) { throw }
        }
        Start-Sleep -Milliseconds 250
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    throw 'Candidate API did not report ed2k_connected=true.'
}

function Request-Ed2kConnect {
    $uri = "http://127.0.0.1:$($request.web_port)" +
        '/api/network/connect?ed2k=1&kad=0'
    $response = Invoke-RestMethod -Uri $uri -TimeoutSec 5
    if (-not $response.success) {
        throw 'Candidate rejected the controlled eD2K connect request.'
    }
    return $response
}

function Test-GlobalNativeIpv6 {
    param([Parameter(Mandatory = $true)]$Snapshot)
    return @($Snapshot.addresses | Where-Object {
            $_.family -eq 'IPv6' -and
            $_.address -notmatch '^(?i)fe80:|^fc|^fd|^::1$'
        }).Count -gt 0 -and
        @($Snapshot.routes | Where-Object {
                $_.destination -eq '::/0'
            }).Count -gt 0 -and
        $Snapshot.hardware_interface -and -not $Snapshot.virtual
}

function Set-R01CandidateProfile {
    param(
        [Parameter(Mandatory = $true)][string]$NodePath,
        [Parameter(Mandatory = $true)]$Request
    )

    $config = Join-Path $NodePath 'config'
    $preferences = Join-Path $config 'preferences.ini'
    $null = Assert-R01NoReparsePath -Path $config
    $null = Assert-R01NoReparsePath -Path $preferences
    foreach ($entry in ([ordered]@{
        Port = [string]$Request.tcp_port
        UDPPort = [string]$Request.udp_port
        Autoconnect = '1'
        NetworkKademlia = '0'
        AutoConnectStaticOnly = '1'
        Reconnect = '1'
        Serverlist = '0'
        AddServersFromServer = '0'
        AddServersFromClient = '0'
        FilterBadIPs = '0'
        FilterServersByIP = '0'
        ServerKeepAliveTimeout = '60000'
        AutoStart = '0'
        AutoTakeED2KLinks = '0'
        WatchClipboard4ED2kFilelinks = '0'
        OpenPortsOnStartUp = '0'
    }).GetEnumerator()) {
        Set-IniValue -Path $preferences -Section 'eMule' `
            -Key $entry.Key -Value $entry.Value
    }

    # CPreferences switches CIni's active section to Connection when it
    # reads KadNetworkMask. NetworkED2K and the crypt-layer keys are read
    # after that switch, so writing them under eMule is silently ignored.
    foreach ($entry in ([ordered]@{
        IPv6Mode = '1'
        KadNetworkMask = '0'
        NetworkED2K = '1'
        CryptLayerRequested = '0'
        CryptLayerRequired = '0'
        CryptLayerSupported = '0'
    }).GetEnumerator()) {
        Set-IniValue -Path $preferences -Section 'Connection' `
            -Key $entry.Key -Value $entry.Value
    }
    Set-IniValue -Path $preferences -Section 'UPnP' `
        -Key 'EnableUPnP' -Value '0'
    foreach ($entry in ([ordered]@{
        ProxyEnableProxy = '0'
        ProxyEnablePassword = '0'
        ProxyType = '0'
    }).GetEnumerator()) {
        Set-IniValue -Path $preferences -Section 'Proxy' `
            -Key $entry.Key -Value $entry.Value
    }
    foreach ($entry in ([ordered]@{
        EseNetLabConsent = '0'
        EseNetLabAdvancedConsent = '0'
        EseNetLabContributionConsent = '0'
        EseNetLabEnabled = '0'
        EseV9Experimental = '0'
        Kad6BetaExitOptIn = '0'
        Kad6PublicExitOptIn = '0'
    }).GetEnumerator()) {
        Set-IniValue -Path $preferences -Section 'eSE' `
            -Key $entry.Key -Value $entry.Value
    }
    foreach ($entry in ([ordered]@{
        Enabled = '1'
        Port = [string]$Request.web_port
        AllowedIPs = '127.0.0.1'
        WebUseUPnP = '0'
    }).GetEnumerator()) {
        Set-IniValue -Path $preferences -Section 'WebServer' `
            -Key $entry.Key -Value $entry.Value
    }
    foreach ($name in @(
        'server.met', 'server_met.old', 'server_met.download',
        'server_met.old.bak'
    )) {
        Remove-Item -LiteralPath (Join-Path $config $name) `
            -Force -ErrorAction SilentlyContinue
    }
    $staticLines = @(
        ('{0}:{1},0,eSE-R01-LAN-{2}' -f
            $Request.initial_server_address, $Request.server_port,
            $Request.nonce),
        ('{0}:{1},0,eSE-R01-MOBILE-{2}' -f
            $Request.mobile_server_address, $Request.server_port,
            $Request.nonce)
    )
    [IO.File]::WriteAllText(
        (Join-Path $config 'staticservers.dat'),
        ($staticLines -join "`r`n") + "`r`n",
        [Text.UnicodeEncoding]::new($false, $true))
}

function Get-R01WebFirewallEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$RuleName,
        [Parameter(Mandatory = $true)][string]$Group,
        [Parameter(Mandatory = $true)][int]$LocalPort,
        [Parameter(Mandatory = $true)][string]$Program
    )
    $rules = @(Get-NetFirewallRule -Name $RuleName -ErrorAction Stop)
    if ($rules.Count -ne 1) {
        throw 'Nonce-owned Web API firewall rule is not unique.'
    }
    $rule = $rules[0]
    $portFilters = @($rule | Get-NetFirewallPortFilter -ErrorAction Stop)
    $applicationFilters = @(
        $rule | Get-NetFirewallApplicationFilter -ErrorAction Stop)
    $addressFilters = @(
        $rule | Get-NetFirewallAddressFilter -ErrorAction Stop)
    if ($portFilters.Count -ne 1 -or $applicationFilters.Count -ne 1 -or
        $addressFilters.Count -ne 1) {
        throw 'Web API firewall rule does not have one exact filter tuple.'
    }
    $portFilter = $portFilters[0]
    $applicationFilter = $applicationFilters[0]
    $addressFilter = $addressFilters[0]
    $expectedProgram = [IO.Path]::GetFullPath($Program)
    $actualProgram = [IO.Path]::GetFullPath(
        [string]$applicationFilter.Program)
    if ([string]$rule.DisplayName -cne $RuleName -or
        [string]$rule.Group -cne $Group -or
        [string]$rule.Direction -cne 'Inbound' -or
        [string]$rule.Action -cne 'Block' -or
        [string]$rule.Enabled -cne 'True' -or
        [string]$rule.Profile -cne 'Any' -or
        [string]$portFilter.Protocol -cne 'TCP' -or
        [string]$portFilter.LocalPort -cne [string]$LocalPort -or
        [string]$addressFilter.LocalAddress -cne 'Any' -or
        [string]$addressFilter.RemoteAddress -cne 'Any' -or
        -not [string]::Equals($actualProgram, $expectedProgram,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Nonce-owned Web API firewall rule is not exact.'
    }
    return [pscustomobject][ordered]@{
        name = $RuleName
        group = $Group
        direction = [string]$rule.Direction
        action = [string]$rule.Action
        enabled = [string]$rule.Enabled
        profile = [string]$rule.Profile
        protocol = [string]$portFilter.Protocol
        local_port = [string]$portFilter.LocalPort
        program_path_sha256 = Get-Hash -Text $actualProgram
        exact = $true
    }
}

function Get-R01FirewallRulesByNameFailClosed {
    param([Parameter(Mandatory = $true)][string]$Name)
    return @(Get-NetFirewallRule -ErrorAction Stop | Where-Object {
            [string]$_.Name -ceq $Name
        })
}

function Get-R01ProcessIdentity {
    param(
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][string]$ExpectedPath,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256
    )
    $Process.Refresh()
    if ($Process.HasExited) { throw 'Candidate exited before identity capture.' }
    $path = [IO.Path]::GetFullPath([string]$Process.Path)
    $expectedFull = [IO.Path]::GetFullPath($ExpectedPath)
    if ($path -ine $expectedFull) {
        throw 'Started process executable path is not the frozen candidate.'
    }
    $null = Assert-R01NoReparsePath -Path $path
    $stream = [IO.File]::Open($path, [IO.FileMode]::Open,
        [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try { $sha = Get-R01StreamSha256 -Stream $stream }
    finally { $stream.Dispose() }
    if ($sha -cne $ExpectedSha256) {
        throw 'Started process executable hash is not the frozen candidate.'
    }
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.r01-process-identity/v1'
        pid = [int]$Process.Id
        start_time_utc = $Process.StartTime.ToUniversalTime().ToString('o')
        executable_path_sha256 = Get-Hash -Text $path.ToLowerInvariant()
        executable_sha256 = $sha
    }
}

function Test-R01ProcessIdentity {
    param(
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)]$Identity,
        [Parameter(Mandatory = $true)][string]$ExpectedPath,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256
    )
    try {
        $actual = Get-R01ProcessIdentity -Process $Process `
            -ExpectedPath $ExpectedPath -ExpectedSha256 $ExpectedSha256
        return ([int]$actual.pid -eq [int]$Identity.pid -and
            [string]$actual.start_time_utc -ceq [string]$Identity.start_time_utc -and
            [string]$actual.executable_path_sha256 -ceq
                [string]$Identity.executable_path_sha256 -and
            [string]$actual.executable_sha256 -ceq
                [string]$Identity.executable_sha256)
    } catch { return $false }
}

function Start-R01IdentityBoundCandidate {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory
    )
    $full = Assert-R01NoReparsePath -Path $Path
    $locked = [IO.File]::Open($full, [IO.FileMode]::Open,
        [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $started = $null
    try {
        $sha = Get-R01StreamSha256 -Stream $locked
        if ($sha -cne $ExpectedSha256) {
            throw 'Candidate changed immediately before process creation.'
        }
        $locked.Position = 0
        $started = Start-Process -FilePath $full -ArgumentList $Arguments `
            -WorkingDirectory $WorkingDirectory -WindowStyle Hidden -PassThru
        $identity = Get-R01ProcessIdentity -Process $started `
            -ExpectedPath $full -ExpectedSha256 $ExpectedSha256
        return [pscustomobject][ordered]@{
            process = $started; identity = $identity
        }
    } catch {
        $startFailure = $_
        $rollbackFailure = ''
        if ($null -ne $started) {
            try {
                $started.Refresh()
                if (-not $started.HasExited) {
                    $rollbackIdentity = Get-R01ProcessIdentity `
                        -Process $started -ExpectedPath $full `
                        -ExpectedSha256 $ExpectedSha256
                    if ([int]$rollbackIdentity.pid -ne [int]$started.Id) {
                        throw 'Candidate rollback PID identity mismatch.'
                    }
                    $started.Kill()
                    if (-not $started.WaitForExit(10000)) {
                        throw 'Candidate did not stop during identity-safe rollback.'
                    }
                }
            } catch { $rollbackFailure = $_.Exception.Message }
        }
        if (-not [string]::IsNullOrWhiteSpace($rollbackFailure)) {
            throw ("Candidate start failed and identity-safe rollback failed: " +
                "$rollbackFailure Original failure: $($startFailure.Exception.Message)")
        }
        throw $startFailure
    } finally { $locked.Dispose() }
}

function Stop-R01IdentityBoundCandidate {
    param(
        [AllowNull()][Diagnostics.Process]$Process,
        [AllowNull()]$Identity,
        [Parameter(Mandatory = $true)][string]$ExpectedPath,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256
    )
    if ($null -eq $Process) { return $true }
    $Process.Refresh()
    if ($Process.HasExited) { return $true }
    if ($null -eq $Identity -or
        -not (Test-R01ProcessIdentity -Process $Process -Identity $Identity `
            -ExpectedPath $ExpectedPath -ExpectedSha256 $ExpectedSha256)) {
        throw 'Refusing to stop a process whose identity tuple changed.'
    }
    $Process.Kill()
    return $Process.WaitForExit(10000)
}

function Get-R01NodeEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$NodePath,
        [Parameter(Mandatory = $true)][string]$EvidencePath,
        [Parameter(Mandatory = $true)][string]$Nonce
    )
    $census = @(Get-R01RegularFileCensus -Root $NodePath)
    $files = @($census | Where-Object {
            [string]$_.relative_path -cin @(
                'BUILD_INFO.txt', 'config/preferences.ini') -or
            [IO.Path]::GetExtension([string]$_.relative_path) -cin
                @('.log', '.dmp')
        })
    $records = @($files | Sort-Object relative_path -Unique | ForEach-Object {
            [pscustomobject][ordered]@{
                relative_path_sha256 = Get-Hash -Text ([string]$_.relative_path)
                file_sha256 = [string]$_.sha256
                bytes = [Int64]$_.bytes
            }
        })
    $preferencesPath = Assert-R01NoReparsePath `
        -Path (Join-Path $NodePath 'config\preferences.ini')
    $allowed = @{
        'eMule/Port' = $true
        'eMule/UDPPort' = $true
        'eMule/NetworkKademlia' = $true
        'eMule/AutoConnectStaticOnly' = $true
        'eMule/AutoStart' = $true
        'eMule/AutoTakeED2KLinks' = $true
        'eMule/WatchClipboard4ED2kFilelinks' = $true
        'eMule/OpenPortsOnStartUp' = $true
        'Connection/IPv6Mode' = $true
        'Connection/KadNetworkMask' = $true
        'Connection/NetworkED2K' = $true
        'UPnP/EnableUPnP' = $true
        'Proxy/ProxyEnableProxy' = $true
        'WebServer/Enabled' = $true
        'WebServer/Port' = $true
        'WebServer/AllowedIPs' = $true
        'WebServer/WebUseUPnP' = $true
        'eSE/EseNetLabConsent' = $true
        'eSE/EseNetLabAdvancedConsent' = $true
        'eSE/EseNetLabContributionConsent' = $true
        'eSE/EseNetLabEnabled' = $true
        'eSE/EseV9Experimental' = $true
        'eSE/Kad6BetaExitOptIn' = $true
        'eSE/Kad6PublicExitOptIn' = $true
    }
    $effectiveValues = [ordered]@{}
    $section = ''
    if (Test-Path -LiteralPath $preferencesPath -PathType Leaf) {
        foreach ($line in Get-Content -LiteralPath $preferencesPath) {
            if ($line -match '^\s*\[([^]]+)\]\s*$') {
                $section = $Matches[1]
            } elseif ($line -match '^\s*([^;#][^=]*?)\s*=\s*(.*?)\s*$') {
                $key = $Matches[1].Trim()
                $qualified = "$section/$key"
                if ($allowed.ContainsKey($qualified)) {
                    $effectiveValues[$qualified] = $Matches[2]
                }
            }
        }
    }
    $effectiveConfigPath = Join-Path $EvidencePath 'effective-config.json'
    Write-JsonAtomic -Path $effectiveConfigPath -Value ([ordered]@{
            schema = 'ese.v91.r01-effective-config/v1'
            sanitization = 'allowlist-only'
            values = $effectiveValues
        })

    $logLines = [Collections.Generic.List[string]]::new()
    $realLogLineCount = 0
    $timestampedLogLineCount = 0
    foreach ($log in @($census | Where-Object {
                [IO.Path]::GetExtension([string]$_.relative_path) -ieq '.log'
            } | Sort-Object relative_path)) {
        $null = Assert-R01NoReparsePath -Path ([string]$log.full_path)
        $logLines.Add("--- source_sha256=$(Get-Hash -Text ([string]$log.relative_path)) ---")
        foreach ($line in @(Get-Content -LiteralPath $log.full_path `
                -Tail 200 -ErrorAction Stop)) {
            $safe = [string]$line
            if (-not [string]::IsNullOrWhiteSpace($safe)) {
                $realLogLineCount++
                if ($safe -match
                    '(?:\d{4}[-/.]\d{2}[-/.]\d{2}|\d{1,2}[-/.]\d{1,2}[-/.]\d{2,4})[ T]+\d{1,2}:\d{2}(?::\d{2})?') {
                    $timestampedLogLineCount++
                }
            }
            $safe = $safe.Replace($Nonce, '<nonce-redacted>')
            $safe = [regex]::Replace($safe,
                '(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])',
                '<ipv4-redacted>')
            $safe = [regex]::Replace($safe,
                '(?i)(?<![0-9a-f])[0-9a-f]{32,64}(?![0-9a-f])',
                '<hex-redacted>')
            $safe = [regex]::Replace($safe,
                '(?i)(?<![0-9a-f:])(?:[0-9a-f]{0,4}:){2,}' +
                    '[0-9a-f:.%]*(?![0-9a-f:])', '<ipv6-redacted>')
            $safe = [regex]::Replace($safe,
                '(?i)(password|token|secret)\s*[:=]\s*\S+', '$1=<redacted>')
            $logLines.Add($safe)
        }
    }
    if ($logLines.Count -eq 0) {
        $logLines.Add('NO_LOG_LINES_CAPTURED')
    }
    $logFragmentPath = Join-Path $EvidencePath 'log-fragment.txt'
    [IO.File]::WriteAllLines($logFragmentPath, $logLines,
        [Text.UTF8Encoding]::new($false))
    $retained = @($effectiveConfigPath, $logFragmentPath |
        ForEach-Object {
            $item = Get-Item -LiteralPath $_
            [pscustomobject][ordered]@{
                name = $item.Name
                bytes = [Int64]$item.Length
                sha256 = (Get-FileHash -LiteralPath $item.FullName `
                        -Algorithm SHA256).Hash.ToLowerInvariant()
            }
        })
    $evidence = [pscustomobject][ordered]@{
        schema = 'ese.v91.r01-node-evidence/v1'
        captured_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
        file_count = $records.Count
        files = $records
        cleartext_paths_published = $false
        real_log_line_count = $realLogLineCount
        timestamped_log_line_count = $timestampedLogLineCount
        retained_artifacts_complete = $retained.Count -eq 2 -and
            @($retained | Where-Object { $_.bytes -le 0 }).Count -eq 0 -and
            $realLogLineCount -gt 0 -and $timestampedLogLineCount -gt 0
        retained_artifacts = $retained
    }
    Write-JsonAtomic -Value $evidence `
        -Path (Join-Path $EvidencePath 'node-evidence.json')
    return $evidence
}

$initial = $null
$mobile = $null
$oldSocket = $null
$newSocket = $null
$oldExpired = $false
$apiBefore = $null
$apiAfter = $null
$apiStartup = $null
$apiListenerBefore = $null
$apiListenerAfter = $null
$mobileProbe = $null
$mobileNativeGlobalIpv6Observed = $false
$webFirewallRuleName = "eSE-R01-$([string]$request.nonce)-WebApiBlock"
$webFirewallGroup = "eSE R01 Lab $([string]$request.nonce)"
$webFirewallCreated = $false
$webFirewallEvidence = $null
$cleanup = [ordered]@{
    candidate_stopped = $false
    home_restored = $false
    final_profile_mode = 'not_attempted'
    final_wifi = $null
    wifi_watchdog_safe = $false
    web_api_firewall_removed = $false
    node_evidence_written = $false
    node_removed = $false
    account_registry_unchanged = $false
    account_registry_post_state = $null
    cleanup_incident = $false
    errors = [Collections.Generic.List[string]]::new()
}

try {
    Assert-R01RunActive
    $phase = 'remote_process_preflight'
    $accountRegistryBefore = Get-R01AccountRegistrySnapshot `
        -ExpectedSidSha256 ([string]$request.expected_account_sid_sha256) `
        -DisposableConfirmed ([bool]$request.disposable_account_confirmed)
    $preexistingEmule = @(Get-Process -ErrorAction Stop | Where-Object {
            [string]$_.ProcessName -ieq 'emule'
        })
    $remotePortBaseline = @(Get-R01PortBaseline `
        -TcpPorts @([int]$request.tcp_port, [int]$request.web_port) `
        -UdpPorts @([int]$request.udp_port))
    $remoteProcessPreflight = [pscustomobject][ordered]@{
        schema = 'ese.v91.r01-process-preflight/v1'
        captured_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
        process_name = 'emule'
        observed_count = $preexistingEmule.Count
        baseline_zero = $preexistingEmule.Count -eq 0
    }
    if ($preexistingEmule.Count -ne 0) {
        throw 'R01 refuses to run with a pre-existing eMule process on H3.'
    }
    if (@($remotePortBaseline | Where-Object {
                -not [bool]$_.available
            }).Count -ne 0) {
        throw 'R01 candidate ports are not clean before mutation.'
    }
    $mobileServerClass = Get-R01IPv4Class -Address (
        [string]$request.mobile_server_address)
    if ($mobileServerClass -cne 'global') {
        throw 'Mobile server address is not a globally routable IPv4 address.'
    }
    if ([string]$request.initial_server_address -ceq
        [string]$request.mobile_server_address) {
        throw 'Initial and mobile controlled endpoints must be distinct.'
    }
    $phase = 'validate_candidate_contract'
    $remoteZipPath = Assert-R01NoReparsePath `
        -Path ([string]$request.candidate_zip_path)
    $manifestFull = Assert-R01NoReparsePath -Path $packageManifestPath
    $manifestStream = [IO.File]::Open($manifestFull, [IO.FileMode]::Open,
        [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $manifestReader = [IO.StreamReader]::new(
            $manifestStream, [Text.UTF8Encoding]::new($false, $true),
            $true, 4096, $true)
        try { $manifestJson = $manifestReader.ReadToEnd() }
        finally { $manifestReader.Dispose() }
        $packageManifest = $manifestJson | ConvertFrom-Json
        $null = Assert-R01PackageManifestContract -Manifest $packageManifest `
            -ExpectedSha256 (
                [string]$request.expected_package_manifest_sha256) `
            -ExpectedFileCount (
                [int]$request.expected_package_manifest_file_count)
    } finally { $manifestStream.Dispose() }
    if (Test-Path -LiteralPath $nodePath) {
        throw 'Unique R01 job node staging path already exists.'
    }
    $null = Assert-R01NoReparsePath -Path $nodePath -AllowMissingLeaf
    New-Item -ItemType Directory -Path $nodePath | Out-Null
    $null = Assert-R01NoReparsePath -Path $nodePath
    $nodeStagingCreated = $true
    New-Item -ItemType Directory -Path $evidencePath -Force | Out-Null
    $null = Assert-R01NoReparsePath -Path $evidencePath
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $remoteZipStream = [IO.File]::Open(
        $remoteZipPath, [IO.FileMode]::Open, [IO.FileAccess]::Read,
        [IO.FileShare]::Read)
    $archive = $null
    try {
        $remoteZipHash = Get-R01StreamSha256 -Stream $remoteZipStream
        $remoteZipBytes = [Int64]$remoteZipStream.Length
        if ($remoteZipBytes -ne [Int64]$request.expected_zip_bytes -or
            $remoteZipHash -cne
                ([string]$request.expected_zip_sha256).ToLowerInvariant() -or
            $remoteZipHash -cne [string]$packageManifest.zip_sha256 -or
            $remoteZipBytes -ne [Int64]$packageManifest.zip_bytes) {
            throw 'Remote frozen candidate ZIP hash/size contract mismatch.'
        }
        $remoteZipStream.Position = 0
        $archive = [IO.Compression.ZipArchive]::new(
            $remoteZipStream, [IO.Compression.ZipArchiveMode]::Read, $true)
        foreach ($entry in @($archive.Entries)) {
            $normalized = ([string]$entry.FullName).Replace('\', '/').
                TrimEnd('/')
            $attributeBits = [BitConverter]::ToUInt32(
                [BitConverter]::GetBytes([int]$entry.ExternalAttributes), 0)
            $unixType = (($attributeBits -shr 16) -band 0xF000)
            if (-not (Test-R01SafeRelativePath -Path $normalized) -or
                $unixType -eq 0xA000) {
                throw "Unsafe remote ZIP entry '$($entry.FullName)'."
            }
        }
        $zipFiles = @($archive.Entries | Where-Object {
                -not ([string]$_.FullName).EndsWith('/') -and
                -not ([string]$_.FullName).EndsWith('\')
            })
        $expectedFiles = @($packageManifest.files)
        if ($zipFiles.Count -ne $expectedFiles.Count -or
            $expectedFiles.Count -ne
                [int]$packageManifest.file_count) {
            throw 'Remote ZIP and bound package manifest file counts differ.'
        }
        $rootPrefix = [string]$packageManifest.zip_root_prefix
        $zipNames = [Collections.Generic.HashSet[string]]::new(
            [StringComparer]::OrdinalIgnoreCase)
        foreach ($zipFile in $zipFiles) {
            $name = ([string]$zipFile.FullName).Replace('\', '/')
            if (-not $zipNames.Add($name)) {
                throw 'Remote ZIP contains a duplicate/case-colliding entry.'
            }
        }
        foreach ($expected in $expectedFiles) {
            $relative = [string]$expected.relative_path
            if (-not (Test-R01SafeRelativePath -Path $relative)) {
                throw "Unsafe remote package manifest path '$relative'."
            }
            $entryName = $rootPrefix + $relative.Replace('\', '/')
            $matches = @($zipFiles | Where-Object {
                    ([string]$_.FullName).Replace('\', '/') -ceq $entryName
                })
            if ($matches.Count -ne 1 -or
                [Int64]$matches[0].Length -ne [Int64]$expected.bytes) {
                throw "Remote ZIP entry contract mismatch for '$relative'."
            }
            $destination = Join-Path $nodePath $relative.Replace('/', '\')
            $destinationFull = [IO.Path]::GetFullPath($destination)
            if (-not $destinationFull.StartsWith(
                    $nodePath.TrimEnd('\') + '\',
                    [StringComparison]::OrdinalIgnoreCase)) {
                throw "Remote extraction escaped staging for '$relative'."
            }
            $destinationDirectory = Split-Path -Parent $destinationFull
            New-Item -ItemType Directory -Path $destinationDirectory `
                -Force | Out-Null
            $null = Assert-R01NoReparsePath -Path $destinationDirectory
            $source = $matches[0].Open()
            $target = [IO.File]::Open($destinationFull,
                [IO.FileMode]::CreateNew, [IO.FileAccess]::Write,
                [IO.FileShare]::None)
            try { $source.CopyTo($target) } finally {
                $target.Dispose()
                $source.Dispose()
            }
            $destinationStream = [IO.File]::Open(
                $destinationFull, [IO.FileMode]::Open,
                [IO.FileAccess]::Read, [IO.FileShare]::Read)
            try { $destinationSha = Get-R01StreamSha256 `
                    -Stream $destinationStream }
            finally { $destinationStream.Dispose() }
            if ($destinationSha -cne
                ([string]$expected.sha256).ToLowerInvariant()) {
                throw "Extracted package hash mismatch for '$relative'."
            }
        }
    } finally {
        if ($null -ne $archive) { $archive.Dispose() }
        $remoteZipStream.Dispose()
    }
    $extractedFiles = @(Get-R01RegularFileCensus -Root $nodePath)
    if ($extractedFiles.Count -ne [int]$packageManifest.file_count -or
        (Get-R01PackageManifestCanonical -Files $extractedFiles) -cne
        (Get-R01PackageManifestCanonical -Files @($packageManifest.files))) {
        throw 'Post-extraction file census differs from the exact package.'
    }
    $extractedByPath = @{}
    foreach ($file in $extractedFiles) {
        $extractedByPath[[string]$file.relative_path] = $file
    }
    foreach ($requiredIdentity in @(
            @{ path = 'emule.exe'; hash = [string]$request.expected_emule_sha256 },
            @{ path = 'ese-server.exe'; hash = [string]$request.expected_ese_server_sha256 },
            @{ path = 'BUILD_INFO.txt'; hash = [string]$request.expected_build_info_sha256 }
        )) {
        if (-not $extractedByPath.ContainsKey($requiredIdentity.path) -or
            [string]$extractedByPath[$requiredIdentity.path].sha256 -cne
                ([string]$requiredIdentity.hash).ToLowerInvariant()) {
            throw "Extracted identity mismatch for '$($requiredIdentity.path)'."
        }
    }
    $remotePackageEvidence = [pscustomobject][ordered]@{
        schema = 'ese.v91.r01-remote-package-binding/v2'
        remote_zip_path_sha256 = Get-Hash -Text $remoteZipPath
        remote_zip_sha256 = $remoteZipHash
        remote_zip_bytes = $remoteZipBytes
        manifest_sha256 =
            [string]$packageManifest.manifest_sha256
        manifest_file_count = [int]$packageManifest.file_count
        extracted_file_set_exact = $true
        extracted_bytes_and_sha256_exact = $true
        locked_zip_snapshot = $true
        reparse_free = $true
        post_extract_file_count = $extractedFiles.Count
    }
    New-Item -ItemType Directory -Path (Join-Path $nodePath 'Incoming') `
        -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $nodePath 'Temp') `
        -Force | Out-Null

    $emulePath = Join-Path $nodePath 'emule.exe'
    $emuleStream = [IO.File]::Open($emulePath, [IO.FileMode]::Open,
        [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try { $actualHash = Get-R01StreamSha256 -Stream $emuleStream }
    finally { $emuleStream.Dispose() }
    if ($actualHash -cne
        ([string]$request.expected_emule_sha256).ToLowerInvariant()) {
        throw 'Candidate SHA-256 mismatch.'
    }

    $buildValues = @{}
    $buildInfoPath = Join-Path $nodePath 'BUILD_INFO.txt'
    $buildStream = [IO.File]::Open($buildInfoPath, [IO.FileMode]::Open,
        [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $buildSha = Get-R01StreamSha256 -Stream $buildStream
        $buildStream.Position = 0
        $buildReader = [IO.StreamReader]::new(
            $buildStream, [Text.UTF8Encoding]::new($false, $true),
            $true, 4096, $true)
        try { $buildLines = @($buildReader.ReadToEnd() -split "`r?`n") }
        finally { $buildReader.Dispose() }
    } finally { $buildStream.Dispose() }
    foreach ($line in $buildLines) {
        if ($line -match '^\s*([^:]+):\s*(.*?)\s*$') {
            $buildValues[$Matches[1].Trim().ToLowerInvariant()] =
                $Matches[2].Trim()
        }
    }
    $buildVersion = [string]$buildValues['version']
    if ([string]::IsNullOrWhiteSpace($buildVersion) -and
        [string]$buildValues['release'] -match '^v0\.70b-eSE(.+)$') {
        $buildVersion = $Matches[1]
    }
    if ([string]$buildValues['commit'] -cne
            [string]$request.candidate_commit -or
        $buildVersion -cne [string]$request.candidate_version -or
        [string]$buildValues['dirty'] -cne 'false' -or
        $buildSha -cne [string]$request.expected_build_info_sha256 -or
        [string]$extractedByPath['BUILD_INFO.txt'].sha256 -cne
            [string]$request.expected_build_info_sha256) {
        throw 'Remote BUILD_INFO does not match the frozen candidate contract.'
    }

    Set-R01CandidateProfile -NodePath $nodePath -Request $request

    $phase = 'isolate_web_api'
    if (@(Get-R01FirewallRulesByNameFailClosed `
            -Name $webFirewallRuleName).Count -ne 0) {
        throw 'Nonce-owned Web API firewall rule already exists.'
    }
    $webFirewallCreated = $true
    New-NetFirewallRule -Name $webFirewallRuleName `
        -DisplayName $webFirewallRuleName -Group $webFirewallGroup `
        -Direction Inbound -Action Block -Enabled True -Profile Any `
        -Protocol TCP -LocalPort ([int]$request.web_port) `
        -Program $emulePath | Out-Null
    $webFirewallEvidence = Get-R01WebFirewallEvidence `
        -RuleName $webFirewallRuleName -Group $webFirewallGroup `
        -LocalPort ([int]$request.web_port) -Program $emulePath

    $phase = 'connect_home_lan'
    Connect-Profile -Name ([string]$request.home_profile)
    $initial = Get-WifiSnapshot -ExpectedProfile ([string]$request.home_profile)
    $initialV4 = @($initial.addresses | Where-Object {
            $_.family -eq 'IPv4' -and -not $_.skip_as_source -and
            (Get-R01IPv4Class -Address $_.address) -in
                @('private', 'shared-cgnat', 'global')
        })
    if (-not $initial.profile_matches_expected -or
        $initialV4.Count -lt 1 -or -not [bool]$initial.hardware_interface -or
        [bool]$initial.virtual -or [bool]$initial.overlay) {
        throw 'Home LAN profile or physical IPv4 was not established.'
    }

    $phase = 'initial_candidate_session'
    $startedCandidate = Start-R01IdentityBoundCandidate `
        -Path $emulePath `
        -ExpectedSha256 ([string]$request.expected_emule_sha256) `
        -Arguments @(
        '--portable', '--ignoreinstances', '--headless',
        "--metrics-port=$($request.web_port)",
        "--tcp-port=$($request.tcp_port)",
        "--udp-port=$($request.udp_port)"
    ) -WorkingDirectory $nodePath
    $process = $startedCandidate.process
    $processIdentity = $startedCandidate.identity
    $apiStartup = Wait-Api -Process $process -TimeoutSeconds 45
    $apiListenerBefore = Get-R01ApiListenerEvidence -Process $process
    $null = Request-Ed2kConnect
    $oldSocket = Wait-Established -Process $process `
        -RemoteAddress ([string]$request.initial_server_address) `
        -TimeoutSeconds 45
    if (@($initialV4 | Where-Object {
                $_.address -eq $oldSocket.local_address
            }).Count -ne 1) {
        throw 'Initial eD2K socket is not bound to the physical LAN IPv4.'
    }
    $initialRoute = Get-R01SelectedRouteEvidence `
        -RemoteAddress ([string]$request.initial_server_address) `
        -Snapshot $initial -ExpectedSourceAddress $oldSocket.local_address
    if (-not [bool]$initialRoute.valid) {
        throw 'Initial eD2K socket route is not bound to the physical Wi-Fi NIC.'
    }
    $apiBefore = Wait-ApiEd2kConnected -Process $process -TimeoutSeconds 30
    $initialSessionValidated = $true

    $phase = 'arm_wifi_watchdog'
    Start-R01WifiWatchdog
    $phase = 'switch_to_mobile_hotspot'
    $transitionStartedAt = [DateTimeOffset]::UtcNow
    Connect-Profile -Name ([string]$request.hotspot_profile)
    $mobile = Get-WifiSnapshot -ExpectedProfile ([string]$request.hotspot_profile)
    if (-not $mobile.profile_matches_expected -or
        -not $mobile.hardware_interface -or $mobile.virtual -or
        [bool]$mobile.overlay -or
        [string]$mobile.status -cne 'Up') {
        throw 'Mobile hotspot was not established on the physical Wi-Fi NIC.'
    }
    if (([string]$initial.interface_guid).Trim('{}') -ine
            ([string]$mobile.interface_guid).Trim('{}')) {
        throw 'The roaming transition moved to a different physical NIC.'
    }
    if ([string]$initial.wlan_profile_sha256 -ceq
            [string]$mobile.wlan_profile_sha256 -or
        [string]$initial.connection_profile.name_sha256 -ceq
            [string]$mobile.connection_profile.name_sha256) {
        throw 'The requested hotspot did not change both WLAN and NLA identity.'
    }
    # IPv6 is diagnostic only here. Native mobile IPv6 is adjudicated by I07,
    # and must never turn this independent roaming case into BLOCKED or FAIL.
    $mobileNativeGlobalIpv6Observed = Test-GlobalNativeIpv6 -Snapshot $mobile
    $phase = 'validate_mobile_public_path'
    $mobileProbe = Test-MobileTopologyProbe `
        -RemoteAddress ([string]$request.mobile_server_address) `
        -RemotePort ([int]$request.topology_probe_port) `
        -Snapshot $mobile -Nonce ([string]$request.nonce)
    if (-not $mobileProbe.physical_nonvirtual) {
        throw 'Mobile topology probe was not attributed to a physical NIC.'
    }
    if (([string]$mobileProbe.interface_guid).Trim('{}') -ine
            ([string]$mobile.interface_guid).Trim('{}') -or
        [string]$mobileProbe.local_address -ceq
            [string]$oldSocket.local_address) {
        throw 'The mobile probe did not prove a new address on the same Wi-Fi NIC.'
    }
    $mobileRoute = $mobileProbe.selected_route
    $mobileTopologyValidated = $true

    $phase = 'expire_old_endpoint'
    $expiryDeadline = [DateTimeOffset]::UtcNow.AddSeconds(45)
    do {
        Assert-R01RunActive
        $oldRows = @(Get-OwnedServerSockets -ProcessId $process.Id `
                -RemoteAddress ([string]$request.initial_server_address) |
                Where-Object {
                    $_.local_address -eq $oldSocket.local_address -and
                    $_.local_port -eq $oldSocket.local_port
                })
        if ($oldRows.Count -eq 0) {
            $oldExpired = $true
            $oldEndpointExpiredAt = [DateTimeOffset]::UtcNow
            break
        }
        Start-Sleep -Milliseconds 250
    } while ([DateTimeOffset]::UtcNow -lt $expiryDeadline)
    if (-not $oldExpired) {
        Stop-R01ProductFailure -Message (
            'Old LAN endpoint did not expire within 45 seconds.')
    }

    $phase = 'mobile_reconnection'
    try {
        $newSocket = Wait-Established -Process $process `
            -RemoteAddress ([string]$request.mobile_server_address) `
            -TimeoutSeconds 90 `
            -DifferentLocalAddress $oldSocket.local_address
    } catch {
        if ($_.Exception -is [OperationCanceledException] -or
            ($_.Exception -is [TimeoutException] -and
                $_.Exception.Message -ceq
                    'R01 autonomous runner deadline exceeded.') -or
            $_.Exception.Message -like 'R01_LAB::*') { throw }
        Stop-R01ProductFailure -Message (
            "Candidate did not reconnect after valid roaming topology: " +
            $_.Exception.Message)
    }
    $mobileV4 = @($mobile.addresses | Where-Object {
            $_.family -eq 'IPv4'
        })
    if (@($mobileV4 | Where-Object {
                $_.address -eq $newSocket.local_address
            }).Count -ne 1) {
        Stop-R01ProductFailure -Message (
            'Reconnected socket is not bound to the mobile physical IPv4.')
    }
    $mobileRoute = Get-R01SelectedRouteEvidence `
        -RemoteAddress ([string]$request.mobile_server_address) `
        -Snapshot $mobile -ExpectedSourceAddress $newSocket.local_address
    if (-not [bool]$mobileRoute.valid) {
        Stop-R01LabFailure -Message (
            'Reconnected eD2K socket route is not the physical Wi-Fi NIC.')
    }
    $reconnectedAt = [DateTimeOffset]::UtcNow
    try {
        $apiAfter = Wait-ApiEd2kConnected -Process $process -TimeoutSeconds 30
        $apiListenerAfter = Get-R01ApiListenerEvidence -Process $process
        $process.Refresh()
        if ($process.HasExited) {
            throw 'Candidate exited after reconnection.'
        }
    } catch {
        if ($_.Exception -is [OperationCanceledException] -or
            $_.Exception -is [TimeoutException] -or
            $_.Exception.Message -like 'R01_LAB::*') { throw }
        Stop-R01ProductFailure -Message (
            "Candidate health failed after proven reconnection: " +
            $_.Exception.Message)
    }

    $phase = 'pass'
} catch {
    $failure = $_.Exception.Message
    $failurePhase = $phase
    $cooperativeStopRequested =
        $failure -ceq 'R01 cooperative cancellation requested.'
    $runnerDeadlineExceeded =
        $failure -ceq 'R01 autonomous runner deadline exceeded.'
    if ($failure -like 'R01_PRODUCT::*' -and $mobileTopologyValidated) {
        $productFailureProven = $true
        $failureCategory = 'PRODUCT'
        $failure = $failure.Substring('R01_PRODUCT::'.Length)
    } else {
        $failureCategory = 'LAB'
        if ($failure -like 'R01_LAB::*') {
            $failure = $failure.Substring('R01_LAB::'.Length)
        } elseif ($failure -like 'R01_PRODUCT::*') {
            $failure = 'Product assertion occurred before roaming topology ' +
                'was proven: ' +
                $failure.Substring('R01_PRODUCT::'.Length)
        }
    }
    $phase = 'failed'
} finally {
    if ($null -ne $process) {
        try {
            $cleanup.candidate_stopped = Stop-R01IdentityBoundCandidate `
                -Process $process -Identity $processIdentity `
                -ExpectedPath $emulePath `
                -ExpectedSha256 ([string]$request.expected_emule_sha256)
        } catch {
            $cleanup.errors.Add("candidate_stop: $($_.Exception.Message)")
        }
    }
    if ($webFirewallCreated) {
        try {
            $null = Get-R01WebFirewallEvidence `
                -RuleName $webFirewallRuleName -Group $webFirewallGroup `
                -LocalPort ([int]$request.web_port) -Program $emulePath
            Get-NetFirewallRule -Name $webFirewallRuleName `
                -ErrorAction Stop | Remove-NetFirewallRule -ErrorAction Stop
            $cleanup.web_api_firewall_removed = @(
                Get-R01FirewallRulesByNameFailClosed `
                    -Name $webFirewallRuleName).Count -eq 0
        } catch {
            $cleanup.errors.Add("web_api_firewall: $($_.Exception.Message)")
        }
    } else {
        $cleanup.web_api_firewall_removed = $true
    }
    try {
        if ((Get-CurrentProfile) -cne [string]$request.home_profile) {
            Connect-Profile -Name ([string]$request.home_profile) -Cleanup
        }
        $finalHome = Get-WifiSnapshot `
            -ExpectedProfile ([string]$request.home_profile)
        $cleanup.home_restored = [bool]$finalHome.profile_matches_expected -and
            [string]::Equals([string]$finalHome.interface_guid,
                [string]$initial.interface_guid,
                [StringComparison]::OrdinalIgnoreCase) -and
            [string]$finalHome.wlan_profile_sha256 -ceq
                [string]$initial.wlan_profile_sha256 -and
            [string]$finalHome.connection_profile.name_sha256 -ceq
                [string]$initial.connection_profile.name_sha256
        $cleanup.final_profile_mode = if ($cleanup.home_restored) {
            'home_restored'
        } else { 'home_restore_incomplete' }
        $cleanup.final_wifi = $finalHome
    } catch {
        $cleanup.final_profile_mode = 'home_restore_error'
        $cleanup.errors.Add("home_restore: $($_.Exception.Message)")
    }
    try {
        Complete-R01WifiWatchdog -HomeRestored $cleanup.home_restored
        if ($null -ne $watchdogEvidence) {
            $cleanup.wifi_watchdog_safe =
                [bool]$watchdogEvidence.armed -and
                [bool]$watchdogEvidence.disarmed -and
                -not [bool]$watchdogEvidence.fired
        }
    } catch {
        $cleanup.errors.Add("wifi_watchdog: $($_.Exception.Message)")
    }
    if ($nodeStagingCreated -and
        (Test-Path -LiteralPath $nodePath -PathType Container)) {
        try {
            $nodeEvidence = Get-R01NodeEvidence -NodePath $nodePath `
                -EvidencePath $evidencePath -Nonce ([string]$request.nonce)
            $cleanup.node_evidence_written =
                [bool]$nodeEvidence.retained_artifacts_complete
        } catch {
            $cleanup.errors.Add("node_evidence: $($_.Exception.Message)")
        }
        try {
            $fullJobRoot = [IO.Path]::GetFullPath($jobRoot).TrimEnd('\')
            $fullNodePath = [IO.Path]::GetFullPath($nodePath).TrimEnd('\')
            if ([IO.Path]::GetFileName($fullNodePath) -cne 'node' -or
                [IO.Path]::GetDirectoryName($fullNodePath) -cne
                    $fullJobRoot) {
                throw 'Refusing to remove a staging path outside the R01 job.'
            }
            $cleanup.node_removed = Remove-R01TreeNoReparse `
                -Path $fullNodePath -ExpectedParent $fullJobRoot
        } catch {
            $cleanup.errors.Add("node_remove: $($_.Exception.Message)")
        }
    } elseif (-not (Test-Path -LiteralPath $nodePath)) {
        $cleanup.node_removed = $true
    }
    try {
        if ($null -ne $accountRegistryBefore) {
            $accountRegistryAfter = Get-R01AccountRegistrySnapshot `
                -ExpectedSidSha256 (
                    [string]$request.expected_account_sid_sha256) `
                -DisposableConfirmed (
                    [bool]$request.disposable_account_confirmed)
            $cleanup.account_registry_post_state = $accountRegistryAfter
            $cleanup.account_registry_unchanged =
                Test-R01AccountRegistrySnapshotEqual `
                    -Before $accountRegistryBefore -After $accountRegistryAfter
            if (-not $cleanup.account_registry_unchanged) {
                $cleanup.errors.Add('account_registry: post-state differs; no destructive restore attempted')
            }
        }
    } catch {
        $cleanup.errors.Add("account_registry: $($_.Exception.Message)")
    }
    $cleanup.cleanup_incident = $cleanup.errors.Count -ne 0 -or
        -not [bool]$cleanup.candidate_stopped -or
        -not [bool]$cleanup.web_api_firewall_removed -or
        -not [bool]$cleanup.node_removed -or
        -not [bool]$cleanup.account_registry_unchanged
}

$samePid = $null -ne $oldSocket -and $null -ne $newSocket -and
    $null -ne $process -and $oldSocket.owning_process -eq $process.Id -and
    $newSocket.owning_process -eq $process.Id -and
    $null -ne $processIdentity -and
    [string]$oldSocket.process_start_time_utc -ceq
        [string]$processIdentity.start_time_utc -and
    [string]$newSocket.process_start_time_utc -ceq
        [string]$processIdentity.start_time_utc -and
    [string]$oldSocket.executable_path_sha256 -ceq
        [string]$processIdentity.executable_path_sha256 -and
    [string]$newSocket.executable_path_sha256 -ceq
        [string]$processIdentity.executable_path_sha256 -and
    [string]$oldSocket.executable_sha256 -ceq
        [string]$processIdentity.executable_sha256 -and
    [string]$newSocket.executable_sha256 -ceq
        [string]$processIdentity.executable_sha256
$productSatisfied = $phase -eq 'pass' -and $oldExpired -and
    $null -ne $oldSocket -and $null -ne $newSocket -and
    $oldSocket.local_address -ne $newSocket.local_address -and
    $samePid -and $initialSessionValidated -and $mobileTopologyValidated -and
    $null -ne $initialRoute -and [bool]$initialRoute.valid -and
    $null -ne $mobileRoute -and [bool]$mobileRoute.valid
$status = if ($productFailureProven) { 'REMOTE_FAIL' }
elseif ($productSatisfied -and $cleanup.candidate_stopped -and
    $cleanup.home_restored -and $cleanup.web_api_firewall_removed -and
    $cleanup.wifi_watchdog_safe -and
    $cleanup.node_evidence_written -and $cleanup.node_removed -and
    $cleanup.account_registry_unchanged -and
    $cleanup.errors.Count -eq 0) {
    'REMOTE_PASS'
} elseif ($productSatisfied) { 'REMOTE_BLOCKED' }
elseif ($cooperativeStopRequested -or $runnerDeadlineExceeded) {
    'REMOTE_BLOCKED'
}
else { 'REMOTE_BLOCKED' }

$result = [ordered]@{
    schema = 'ese.v91.r01-remote/v4'
    case_id = 'V91-R01'
    nonce = [string]$request.nonce
    status = $status
    created_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
    failure = $failure
    failure_phase = $failurePhase
    failure_category = $failureCategory
    product_failure_proven = $productFailureProven
    control = [ordered]@{
        runner_started_at_utc = $runnerStartedAt.ToString('o')
        runner_deadline_at_utc = $runnerDeadline.ToString('o')
        runner_deadline_seconds = $runnerDeadlineSeconds
        cooperative_cancel_observed = $cooperativeStopRequested
        autonomous_deadline_observed = $runnerDeadlineExceeded
    }
    process_preflight = $remoteProcessPreflight
    port_preflight = $remotePortBaseline
    account_registry_preflight = $accountRegistryBefore
    candidate = [ordered]@{
        identity_basis = 'emule.exe SHA-256'
        version = [string]$request.candidate_version
        commit = [string]$request.candidate_commit
        dirty = $false
        emule_sha256 = [string]$request.expected_emule_sha256
        ese_server_sha256 = [string]$request.expected_ese_server_sha256
        build_info_sha256 = [string]$request.expected_build_info_sha256
        zip_sha256 = [string]$request.expected_zip_sha256
        zip_bytes = [Int64]$request.expected_zip_bytes
        package_manifest_sha256 =
            [string]$request.expected_package_manifest_sha256
        package_manifest_file_count =
            [int]$request.expected_package_manifest_file_count
        remote_package_binding = $remotePackageEvidence
        process_id = if ($null -ne $process) { $process.Id } else { 0 }
        process_identity = $processIdentity
        same_pid_before_after = $samePid
    }
    topology = [ordered]@{
        id = 'T3'
        initial = $initial
        mobile = $mobile
        home_connection_profile_sha256 = if ($null -ne $initial) {
            [string]$initial.connection_profile.name_sha256
        } else { $null }
        hotspot_connection_profile_sha256 = if ($null -ne $mobile) {
            [string]$mobile.connection_profile.name_sha256
        } else { $null }
        control_transport = 'Tailscale IPv4; excluded from candidate data'
        candidate_data_transport =
            'physical Wi-Fi IPv4 to controlled public IPv4 endpoint'
        mobile_public_probe = $mobileProbe
        initial_selected_route = $initialRoute
        mobile_selected_route = $mobileRoute
        mobile_topology_validated = $mobileTopologyValidated
        native_global_ipv6_observed_diagnostic =
            $mobileNativeGlobalIpv6Observed
    }
    session = [ordered]@{
        initial_server_address = [string]$request.initial_server_address
        mobile_server_address = [string]$request.mobile_server_address
        server_port = [int]$request.server_port
        candidate_tcp_port = [int]$request.tcp_port
        initial_socket = $oldSocket
        reconnected_socket = $newSocket
        old_endpoint_expired = $oldExpired
        transition_started_at_utc = if ($null -ne $transitionStartedAt) {
            $transitionStartedAt.ToString('o')
        } else { $null }
        old_endpoint_expired_at_utc = if ($null -ne $oldEndpointExpiredAt) {
            $oldEndpointExpiredAt.ToString('o')
        } else { $null }
        old_endpoint_expiry_seconds = if ($null -ne $transitionStartedAt -and
            $null -ne $oldEndpointExpiredAt) {
            [Math]::Round(($oldEndpointExpiredAt -
                    $transitionStartedAt).TotalSeconds, 3)
        } else { $null }
        reconnected_at_utc = if ($null -ne $reconnectedAt) {
            $reconnectedAt.ToString('o')
        } else { $null }
        reconnect_seconds = if ($null -ne $transitionStartedAt -and
            $null -ne $reconnectedAt) {
            [Math]::Round(($reconnectedAt -
                    $transitionStartedAt).TotalSeconds, 3)
        } else { $null }
    }
    health = [ordered]@{
        api_startup = $apiStartup
        api_before = $apiBefore
        api_after = $apiAfter
        api_listener_before = $apiListenerBefore
        api_listener_after = $apiListenerAfter
        inbound_firewall = $webFirewallEvidence
    }
    samples = @($samples)
    requested_home_wlan_profile_sha256 =
        Get-Hash -Text ([string]$request.home_profile)
    requested_hotspot_wlan_profile_sha256 =
        Get-Hash -Text ([string]$request.hotspot_profile)
    node_evidence = $nodeEvidence
    wifi_watchdog = $watchdogEvidence
    cleanup = $cleanup
}
Write-JsonAtomic -Value $result -Path $resultPath
if ($status -ceq 'REMOTE_FAIL') { exit 1 }
if ($status -ne 'REMOTE_PASS') { exit 2 }
exit 0
