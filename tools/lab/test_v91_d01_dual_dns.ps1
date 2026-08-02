<#
.SYNOPSIS
Runs V91-D01 on two controlled physical Windows hosts.

.DESCRIPTION
Start the Coordinator role first and the Source role second with the
coordinator-issued RunNonce.  The two roles exchange nonce-scoped JSON files
through CoordinationRoot; media never traverses that directory.

The source owns one non-sparse file and listens only on IPv4.  The coordinator
uses a fresh Preferred profile, a same-host controlled minimal eD2K server,
Kad disabled, no third-party servers and exactly one explicit-hostname link
injection.  Formal PASS requires:

  * an observed direct native T1 or T2 topology on distinct physical hosts;
  * exact and stable controlled A+AAAA DNS answers;
  * a failed AAAA path and a working A path attributed to real PID sockets;
  * one lossless PktMon/ETW capture covering both target families;
  * exclusive controlled-host PktMon use, with concurrent CLI, filter,
    driver, ETW/provider and direct pktmonapi/IOCTL mutators excluded; and
  * exactly one post-baseline localhost telemetry event proving that the
    canonical A+AAAA set was resolved and simultaneously materialized;
  * an intact one-file transfer, responsive API/UI, isolation and clean
    rollback; and
  * unchanged extracted-package, ZIP and executable identities.

The product telemetry contract is GET /api/debug/source-resolutions:

  {
    "schema": "ese.debug.source-resolutions/v1",
    "sequence": 12,
    "events": [{
      "sequence": 12,
      "hostname_sha256": "...",
        "file_ed2k_hash": "...",
      "port": 9162,
      "resolver_result": "success",
      "resolved": {
        "ipv4_count": 1, "ipv6_count": 1,
        "endpoint_set_sha256": "..."
      },
      "materialized": {
        "ipv4_count": 1, "ipv6_count": 1,
        "endpoint_set_sha256": "...",
        "simultaneously_retained": true
      },
      "candidates": [{
        "family": "ipv4",
        "endpoint_sha256": "...",
        "outcome": "added",
        "source_origin": "hostname_link"
      }]
    }]
  }

Endpoint canonical bytes are family byte 4 or 6, address bytes in network
order, and the two-byte port in network order.  Entries are sorted
lexicographically and concatenated before SHA-256.

The summary deliberately separates fixture_status, observability_status and
product_status.  Exit codes are 0=PASS, 1=FAIL and 2=BLOCKED.
#>
[CmdletBinding(DefaultParameterSetName = 'Campaign')]
param(
    [ValidateSet('Coordinator', 'Source')][string]$Role = 'Coordinator',
    [Parameter(Mandatory = $true, ParameterSetName = 'Campaign')]
    [string]$PackagePath,
    [Parameter(Mandatory = $true, ParameterSetName = 'Campaign')]
    [string]$PackageZipPath,
    [Parameter(Mandatory = $true, ParameterSetName = 'Campaign')]
    [string]$OutputRoot,
    [Parameter(Mandatory = $true, ParameterSetName = 'Campaign')]
    [string]$CoordinationRoot,
    [Parameter(Mandatory = $true, ParameterSetName = 'Campaign')]
    [ValidatePattern('^[0-9a-fA-F]{40}$')][string]$Commit,
    [Parameter(Mandatory = $true, ParameterSetName = 'Campaign')]
    [ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedEmuleSha256,
    [Parameter(Mandatory = $true, ParameterSetName = 'Campaign')]
    [ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedPackageZipSha256,
    [Parameter(Mandatory = $true, ParameterSetName = 'Campaign')]
    [string]$Hostname,
    [Parameter(Mandatory = $true, ParameterSetName = 'Campaign')]
    [string]$SourcePublicIPv4,
    [Parameter(Mandatory = $true, ParameterSetName = 'Campaign')]
    [string]$SourceLocalIPv4,
    [Parameter(Mandatory = $true, ParameterSetName = 'Campaign')]
    [string]$SourceIPv6,
    [Parameter(Mandatory = $true, ParameterSetName = 'Campaign')]
    [string]$CoordinatorPublicIPv4,
    [Parameter(Mandatory = $true, ParameterSetName = 'Campaign')]
    [string]$CoordinatorLocalIPv4,
    [Parameter(Mandatory = $true, ParameterSetName = 'Campaign')]
    [string]$CoordinatorIPv6,
    [Parameter(Mandatory = $true, ParameterSetName = 'Campaign')]
    [switch]$ControlledFixtureAcknowledged,
    [switch]$ExclusivePktmonDriverControlAcknowledged,
    [Parameter(Mandatory = $true, ParameterSetName = 'Campaign')]
    [switch]$DisposableLabAccountAcknowledged,
    [Parameter(Mandatory = $true, ParameterSetName = 'Campaign')]
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedCoordinatorMachineIdSha256,
    [Parameter(Mandatory = $true, ParameterSetName = 'Campaign')]
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedSourceMachineIdSha256,
    [Parameter(Mandatory = $true, ParameterSetName = 'Campaign')]
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedCoordinatorUserSidSha256,
    [Parameter(Mandatory = $true, ParameterSetName = 'Campaign')]
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedSourceUserSidSha256,
    [ValidateRange(1024, 65535)][int]$SourceTcpPort = 9162,
    [ValidateRange(1024, 65535)][int]$SourceUdpPort = 9172,
    [ValidateRange(1024, 65535)][int]$SourceWebPort = 9211,
    [ValidateRange(1024, 65535)][int]$DownloaderTcpPort = 9262,
    [ValidateRange(1024, 65535)][int]$DownloaderUdpPort = 9272,
    [ValidateRange(1024, 65535)][int]$DownloaderWebPort = 9311,
    [ValidateRange(1048576, 1073741824)]
    [Int64]$FileSizeBytes = 67108864,
    [ValidateRange(30, 900)][int]$PeerReadyTimeoutSeconds = 300,
    [ValidateRange(60, 3600)][int]$TransferTimeoutSeconds = 1200,
    [ValidateRange(250, 10000)]
    [int]$EndpointProbeTimeoutMilliseconds = 2500,
    [ValidatePattern('^[0-9a-fA-F]{32}$')][string]$RunNonce = '',
    [Parameter(Mandatory = $true, ParameterSetName = 'NativeHelper')]
    [ValidateSet('driver-status', 'driver-stop', 'etw-probe',
        'etw-query', 'etw-stop')]
    [string]$InternalNativeOperation,
    [Parameter(Mandatory = $true, ParameterSetName = 'NativeHelper')]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$InternalExpectedScriptSha256,
    [Parameter(ParameterSetName = 'NativeHelper')]
    [ValidatePattern('^(?:|[0-9a-f]{64})$')]
    [string]$InternalExpectedLibrarySha256 = '',
    [Parameter(ParameterSetName = 'NativeHelper')]
    [ValidatePattern('^(?:|[0-9a-f]{64})$')]
    [string]$InternalExpectedDriverSha256 = '',
    [Parameter(ParameterSetName = 'NativeHelper')]
    [string]$InternalExpectedLogFilePath = '',
    [Parameter(ParameterSetName = 'NativeHelper')]
    [ValidatePattern('^(?:|[0-9a-f]{16})$')]
    [string]$InternalExpectedControlTraceIdHex = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
. (Join-Path $PSScriptRoot 'common.ps1')

$caseId = 'V91-D01'
$expectedEmuleHash = if ($PSCmdlet.ParameterSetName -eq 'Campaign') {
    $ExpectedEmuleSha256.ToLowerInvariant()
} else { '' }
$expectedZipHash = if ($PSCmdlet.ParameterSetName -eq 'Campaign') {
    $ExpectedPackageZipSha256.ToLowerInvariant()
} else { '' }
$canonicalHostname = $Hostname
$webPassword = 'v91-d01-local-api'
$overlayPattern =
    '(?i)tailscale|wireguard|cloudflare|warp|zerotier|openvpn|' +
    'hyper-v|vethernet|loopback|tunnel|tap|vpn|hamachi|' +
    'teredo|6to4|isatap|ip-?https'
$script:d01CandidateLocks =
    [System.Collections.Generic.List[IDisposable]]::new()
$script:d01CandidateBinding = $null
$script:d01HostIdentity = $null
$script:d01AccountRegistryTransaction = $null
$script:d01AccountRegistryPostcheck = $null
$script:d01AccountRegistryPostcheckComplete = $false
$script:d01HostsBaseline = $null
$script:d01HostsPostcheck = $null
$script:d01CommittedExitCode = $null
$script:d01PktmonBinaryTuple = $null
$script:d01TrustedCommandLeases =
    [System.Collections.Generic.List[object]]::new()
$script:d01NativeHelperLogPath = ''
$script:d01PendingPktmonCleanupState = $null
$script:d01PendingPktmonCleanupFailures = $null

function Convert-D01Address {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)]
        [Net.Sockets.AddressFamily]$Family,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $parsed = $null
    if (-not [Net.IPAddress]::TryParse(
        $Value.Trim('[', ']').Split('%')[0], [ref]$parsed
    ) -or $parsed.AddressFamily -ne $Family -or
        ($Family -eq [Net.Sockets.AddressFamily]::InterNetworkV6 -and
            $parsed.IsIPv4MappedToIPv6)) {
        throw "$Name is not an address in the required family: '$Value'"
    }
    return $parsed
}

function Get-D01NormalizedIp {
    param([Parameter(Mandatory = $true)][string]$Address)

    $parsed = $null
    if (-not [Net.IPAddress]::TryParse(
        $Address.Trim('[', ']').Split('%')[0], [ref]$parsed
    )) {
        return $Address
    }
    if ($parsed.IsIPv4MappedToIPv6) {
        return $parsed.MapToIPv4().ToString()
    }
    return $parsed.ToString()
}

function Get-D01StrictAddressClass {
    param([Parameter(Mandatory = $true)][string]$Address)

    $parsed = $null
    if (-not [Net.IPAddress]::TryParse(
        $Address.Trim('[', ']').Split('%')[0], [ref]$parsed
    )) { return 'invalid' }
    $bytes = $parsed.GetAddressBytes()
    if ($parsed.AddressFamily -eq
        [Net.Sockets.AddressFamily]::InterNetwork) {
        if ($bytes[0] -eq 0) { return 'unspecified-or-this-network-v4' }
        if ($bytes[0] -eq 10 -or
            ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and
                $bytes[1] -le 31) -or
            ($bytes[0] -eq 192 -and $bytes[1] -eq 168)) {
            return 'private-v4'
        }
        if ($bytes[0] -eq 100 -and $bytes[1] -ge 64 -and
            $bytes[1] -le 127) { return 'shared-cgnat-v4' }
        if ($bytes[0] -eq 127) { return 'loopback-v4' }
        if ($bytes[0] -eq 169 -and $bytes[1] -eq 254) {
            return 'linklocal-v4'
        }
        if (($bytes[0] -eq 192 -and $bytes[1] -eq 0 -and
                ($bytes[2] -in @(0, 2))) -or
            ($bytes[0] -eq 192 -and $bytes[1] -eq 31 -and
                $bytes[2] -eq 196) -or
            ($bytes[0] -eq 192 -and $bytes[1] -eq 52 -and
                $bytes[2] -eq 193) -or
            ($bytes[0] -eq 192 -and $bytes[1] -eq 88 -and
                $bytes[2] -eq 99) -or
            ($bytes[0] -eq 192 -and $bytes[1] -eq 175 -and
                $bytes[2] -eq 48) -or
            ($bytes[0] -eq 198 -and $bytes[1] -in @(18, 19)) -or
            ($bytes[0] -eq 198 -and $bytes[1] -eq 51 -and
                $bytes[2] -eq 100) -or
            ($bytes[0] -eq 203 -and $bytes[1] -eq 0 -and
                $bytes[2] -eq 113)) {
            return 'special-purpose-v4'
        }
        if ($bytes[0] -ge 224) { return 'multicast-or-reserved-v4' }
        return 'public-unicast-v4'
    }
    if ($parsed.AddressFamily -ne
        [Net.Sockets.AddressFamily]::InterNetworkV6 -or
        $parsed.IsIPv4MappedToIPv6) { return 'non-native-v6' }
    if ([Net.IPAddress]::IsLoopback($parsed)) { return 'loopback-v6' }
    if ($parsed.IsIPv6LinkLocal) { return 'linklocal-v6' }
    if ($parsed.IsIPv6Multicast) { return 'multicast-v6' }
    if (($bytes[0] -band 0xfe) -eq 0xfc) { return 'ula-v6' }
    if (($bytes[0] -band 0xe0) -ne 0x20) {
        return 'non-global-unicast-v6'
    }
    # Reject transition, documentation and IETF-special ranges within 2000::/3.
    if (($bytes[0] -eq 0x20 -and $bytes[1] -eq 0x01 -and
            $bytes[2] -le 0x01) -or
        ($bytes[0] -eq 0x20 -and $bytes[1] -eq 0x01 -and
            $bytes[2] -eq 0x0d -and $bytes[3] -eq 0xb8) -or
        ($bytes[0] -eq 0x20 -and $bytes[1] -eq 0x02) -or
        ($bytes[0] -eq 0x3f -and $bytes[1] -eq 0xfe) -or
        ($bytes[0] -eq 0x20 -and $bytes[1] -eq 0x01 -and
            $bytes[2] -eq 0x00 -and $bytes[3] -eq 0x04 -and
            $bytes[4] -eq 0x01 -and $bytes[5] -eq 0x12) -or
        ($bytes[0] -eq 0x26 -and $bytes[1] -eq 0x20 -and
            $bytes[2] -eq 0x00 -and $bytes[3] -eq 0x4f -and
            $bytes[4] -eq 0x80 -and $bytes[5] -eq 0x00) -or
        ($bytes[0] -eq 0x3f -and $bytes[1] -eq 0xff -and
            ($bytes[2] -band 0xf0) -eq 0)) {
        return 'transition-or-documentation-v6'
    }
    return 'native-global-v6'
}

function Test-D01UsableLocalIPv4 {
    param([Parameter(Mandatory = $true)][string]$Address)
    return (Get-D01StrictAddressClass -Address $Address) -in @(
        'private-v4', 'shared-cgnat-v4', 'public-unicast-v4'
    )
}

function Get-D01CanonicalHostname {
    param([Parameter(Mandatory = $true)][string]$Value)

    $trimmed = $Value.Trim().Trim('[', ']').TrimEnd('.').Normalize(
        [Text.NormalizationForm]::FormC)
    if ([string]::IsNullOrWhiteSpace($trimmed)) {
        throw 'Hostname is empty'
    }
    $idn = [Globalization.IdnMapping]::new()
    $ascii = $idn.GetAscii($trimmed).ToLowerInvariant()
    $roundTrip = $idn.GetAscii($idn.GetUnicode($ascii)).ToLowerInvariant()
    if ($ascii -cne $roundTrip -or $ascii.Length -gt 253 -or
        $ascii.IndexOfAny([char[]]'|,[]:') -ge 0) {
        throw 'Hostname is not one canonical IDNA A-label name'
    }
    $labels = @($ascii.Split('.'))
    if ($labels.Count -lt 2 -or @($labels | Where-Object {
        $_.Length -lt 1 -or $_.Length -gt 63 -or
        $_ -notmatch '^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$'
    }).Count -ne 0) {
        throw 'Hostname must use canonical DNS A-label syntax'
    }
    return $ascii
}

function Test-D01Administrator {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator
        )
    } catch {
        return $false
    }
}

function Get-D01CurrentHostIdentity {
    $machineGuidText = [string](Get-ItemProperty `
        -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Cryptography' `
        -Name MachineGuid -ErrorAction Stop).MachineGuid
    $machineGuid = [Guid]::Empty
    if (-not [Guid]::TryParse($machineGuidText, [ref]$machineGuid) -or
        $machineGuid -eq [Guid]::Empty) {
        throw 'MachineGuid is absent or invalid; host identity is unprovable'
    }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ($null -eq $identity -or $null -eq $identity.User) {
        throw 'Current Windows account has no SID'
    }
    $sid = [string]$identity.User.Value
    if ($sid -in @('S-1-5-18', 'S-1-5-19', 'S-1-5-20') -or
        $sid -match '-500$') {
        throw 'Built-in Administrator/service identities are forbidden; use the acknowledged disposable lab account'
    }
    if ([string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
        throw 'USERPROFILE is unavailable'
    }
    $profile = Assert-D01NoReparsePath -Path $env:USERPROFILE -Kind Directory
    return [pscustomobject][ordered]@{
        machine_id_sha256 = Get-LabStringSha256 `
            -Value $machineGuid.ToString('D').ToLowerInvariant()
        user_sid_sha256 = Get-LabStringSha256 -Value $sid
        account_name_sha256 = Get-LabStringSha256 -Value ([string]$identity.Name)
        profile_path_sha256 = Get-LabStringSha256 -Value (
            [IO.Path]::GetFullPath($profile).ToLowerInvariant())
        builtin_or_service = $false
        disposable_account_operator_attested = $true
    }
}

function Get-D01HostIdentityEvidence {
    if ($null -eq $script:d01HostIdentity) {
        throw 'Host identity was not initialized'
    }
    return [pscustomobject][ordered]@{
        machine_id_sha256 = $script:d01HostIdentity.machine_id_sha256
        user_sid_sha256 = $script:d01HostIdentity.user_sid_sha256
        account_name_sha256 = $script:d01HostIdentity.account_name_sha256
        profile_path_sha256 = $script:d01HostIdentity.profile_path_sha256
        builtin_or_service = $script:d01HostIdentity.builtin_or_service
        disposable_account_operator_attested =
            $script:d01HostIdentity.disposable_account_operator_attested
    }
}

function Get-D01MachineId {
    if ($null -eq $script:d01HostIdentity) {
        throw 'Host identity was not initialized'
    }
    return [string]$script:d01HostIdentity.machine_id_sha256
}

function ConvertTo-D01RegistryValueCanonical {
    param([AllowNull()]$Value)

    if ($null -eq $Value) { return 'null' }
    if ($Value -is [byte[]]) {
        return 'bytes:' + [Convert]::ToBase64String([byte[]]$Value)
    }
    if ($Value -is [string[]]) {
        [string[]]$members = @([string[]]$Value | ForEach-Object {
            ([string]$_).Length.ToString(
                [Globalization.CultureInfo]::InvariantCulture) + ':' +
                [string]$_
        })
        return 'multi:' + ($members -join '|')
    }
    if ($Value -is [string]) {
        return 'string:' + ([string]$Value).Length.ToString(
            [Globalization.CultureInfo]::InvariantCulture) + ':' +
            [string]$Value
    }
    if ($Value -is [int] -or $Value -is [Int64]) {
        return 'integer:' + ([IConvertible]$Value).ToString(
            [Globalization.CultureInfo]::InvariantCulture)
    }
    throw "Unsupported registry value type: $($Value.GetType().FullName)"
}

function Get-D01RegistrySubtreeSnapshotOnce {
    param(
        [Parameter(Mandatory = $true)][string]$RelativePath,
        [AllowEmptyString()][string]$TrackedRootValueName = ''
    )

    $root = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey(
        $RelativePath, $false)
    if ($null -eq $root) {
        return [pscustomobject][ordered]@{
            schema = 'ese.v91.d01-registry-subtree/v1'
            path_sha256 = Get-LabStringSha256 -Value $RelativePath
            exists = $false
            node_count = 0
            value_count = 0
            tracked_root_value_count = 0
            canonical_sha256 = Get-LabStringSha256 -Value 'absent'
        }
    }
    $lines = [Collections.Generic.List[string]]::new()
    $state = [pscustomobject]@{ node_count = 0; value_count = 0 }
    $visit = $null
    $visit = {
        param(
            [Parameter(Mandatory = $true)]
            [Microsoft.Win32.RegistryKey]$Key,
            [Parameter(Mandatory = $true)][string]$LogicalPath
        )
        $state.node_count++
        $lines.Add('K|' + $LogicalPath.ToLowerInvariant())
        [string[]]$valueNames = @($Key.GetValueNames())
        [string[]]$subkeyNames = @($Key.GetSubKeyNames())
        [Array]::Sort($valueNames, [StringComparer]::Ordinal)
        [Array]::Sort($subkeyNames, [StringComparer]::Ordinal)
        foreach ($valueName in $valueNames) {
            $kind = $Key.GetValueKind($valueName)
            $value = $Key.GetValue(
                $valueName, $null,
                [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            $canonical = ConvertTo-D01RegistryValueCanonical -Value $value
            $valueAgain = $Key.GetValue(
                $valueName, $null,
                [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            if ($kind -ne $Key.GetValueKind($valueName) -or
                $canonical -cne
                    (ConvertTo-D01RegistryValueCanonical -Value $valueAgain)) {
                throw 'Registry value changed during fail-closed capture'
            }
            $lines.Add(('V|{0}|{1}|{2}' -f
                $valueName.ToLowerInvariant(), [string]$kind,
                (Get-LabStringSha256 -Value $canonical)))
            $state.value_count++
        }
        foreach ($subkeyName in $subkeyNames) {
            $child = $Key.OpenSubKey($subkeyName, $false)
            if ($null -eq $child) {
                throw 'Registry subtree changed during capture'
            }
            try {
                & $visit -Key $child `
                    -LogicalPath ($LogicalPath + '\' + $subkeyName)
            } finally { $child.Dispose() }
        }
        [string[]]$valueNamesAfter = @($Key.GetValueNames())
        [string[]]$subkeyNamesAfter = @($Key.GetSubKeyNames())
        [Array]::Sort($valueNamesAfter, [StringComparer]::Ordinal)
        [Array]::Sort($subkeyNamesAfter, [StringComparer]::Ordinal)
        if (($valueNamesAfter -join "`n") -cne ($valueNames -join "`n") -or
            ($subkeyNamesAfter -join "`n") -cne
                ($subkeyNames -join "`n")) {
            throw 'Registry subtree names changed during capture'
        }
    }
    try {
        $trackedCount = if ([string]::IsNullOrEmpty($TrackedRootValueName)) {
            0
        } else {
            @($root.GetValueNames() | Where-Object {
                [string]$_ -ieq $TrackedRootValueName
            }).Count
        }
        & $visit -Key $root -LogicalPath $RelativePath
    } finally { $root.Dispose() }
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.d01-registry-subtree/v1'
        path_sha256 = Get-LabStringSha256 -Value $RelativePath
        exists = $true
        node_count = [int]$state.node_count
        value_count = [int]$state.value_count
        tracked_root_value_count = [int]$trackedCount
        canonical_sha256 = Get-LabStringSha256 -Value ($lines -join "`n")
    }
}

function Test-D01RegistrySubtreeSnapshotEqual {
    param(
        [Parameter(Mandatory = $true)]$Left,
        [Parameter(Mandatory = $true)]$Right
    )
    return [string]$Left.schema -ceq [string]$Right.schema -and
        [string]$Left.path_sha256 -ceq [string]$Right.path_sha256 -and
        [bool]$Left.exists -eq [bool]$Right.exists -and
        [int]$Left.node_count -eq [int]$Right.node_count -and
        [int]$Left.value_count -eq [int]$Right.value_count -and
        [int]$Left.tracked_root_value_count -eq
            [int]$Right.tracked_root_value_count -and
        [string]$Left.canonical_sha256 -ceq [string]$Right.canonical_sha256
}

function Get-D01RegistrySubtreeSnapshot {
    param(
        [Parameter(Mandatory = $true)][string]$RelativePath,
        [AllowEmptyString()][string]$TrackedRootValueName = ''
    )
    $first = Get-D01RegistrySubtreeSnapshotOnce `
        -RelativePath $RelativePath `
        -TrackedRootValueName $TrackedRootValueName
    $second = Get-D01RegistrySubtreeSnapshotOnce `
        -RelativePath $RelativePath `
        -TrackedRootValueName $TrackedRootValueName
    if (-not (Test-D01RegistrySubtreeSnapshotEqual `
        -Left $first -Right $second)) {
        throw 'Registry subtree was unstable across capture'
    }
    return $second
}

function ConvertTo-D01FirewallValueCanonical {
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return 'null' }
    if ($Value -is [Array]) {
        [string[]]$members = @($Value | ForEach-Object {
            ConvertTo-D01FirewallValueCanonical -Value $_
        })
        [Array]::Sort($members, [StringComparer]::Ordinal)
        return 'array:[' + ($members -join ',') + ']'
    }
    if ($Value -is [string]) {
        return 'string:' + ([string]$Value).Length.ToString(
            [Globalization.CultureInfo]::InvariantCulture) + ':' +
            [string]$Value
    }
    if ($Value -is [bool]) {
        return 'bool:' + ([bool]$Value).ToString().ToLowerInvariant()
    }
    if ($Value -is [DateTime]) {
        return 'datetime:' + ([DateTime]$Value).ToUniversalTime().ToString('o')
    }
    if ($Value -is [Guid]) {
        return 'guid:' + ([Guid]$Value).ToString('D').ToLowerInvariant()
    }
    if ($Value -is [IFormattable]) {
        return $Value.GetType().FullName + ':' +
            ([IFormattable]$Value).ToString(
                $null, [Globalization.CultureInfo]::InvariantCulture)
    }
    return $Value.GetType().FullName + ':' + [string]$Value
}

function Get-D01FirewallCimCanonical {
    param([Parameter(Mandatory = $true)]$Instance)
    $properties = @($Instance.CimInstanceProperties)
    if ($properties.Count -eq 0) {
        throw 'Firewall collector returned an object without CIM properties'
    }
    [string[]]$records = @($properties | ForEach-Object {
        '{0}|{1}|{2}' -f ([string]$_.Name).ToLowerInvariant(),
            [string]$_.CimType,
            (ConvertTo-D01FirewallValueCanonical -Value $_.Value)
    })
    [Array]::Sort($records, [StringComparer]::Ordinal)
    return $records -join "`n"
}

function Get-D01GlobalFirewallSnapshotOnce {
    $collectors = [ordered]@{
        rules = 'Get-NetFirewallRule'
        port_filters = 'Get-NetFirewallPortFilter'
        application_filters = 'Get-NetFirewallApplicationFilter'
        address_filters = 'Get-NetFirewallAddressFilter'
        interface_filters = 'Get-NetFirewallInterfaceFilter'
        interface_type_filters = 'Get-NetFirewallInterfaceTypeFilter'
        service_filters = 'Get-NetFirewallServiceFilter'
        security_filters = 'Get-NetFirewallSecurityFilter'
    }
    $categories = [ordered]@{}
    [string[]]$aggregate = @()
    foreach ($entry in $collectors.GetEnumerator()) {
        $command = Get-Command -Name $entry.Value -ErrorAction Stop
        $items = @(& $command -PolicyStore ActiveStore -ErrorAction Stop)
        if ($items.Count -eq 0) {
            throw "Global firewall collector returned no $($entry.Key)"
        }
        [string[]]$records = @($items | ForEach-Object {
            Get-D01FirewallCimCanonical -Instance $_
        })
        [Array]::Sort($records, [StringComparer]::Ordinal)
        $digest = Get-LabStringSha256 -Value (
            $records -join "`n--ITEM--`n")
        $categories[$entry.Key] = [pscustomobject][ordered]@{
            item_count = $items.Count
            canonical_sha256 = $digest
        }
        $aggregate += ('{0}|{1}|{2}' -f $entry.Key,
            $items.Count, $digest)
    }
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.d01-global-firewall-snapshot/v1'
        captured_at_utc = Get-LabUtcTimestamp
        policy_store = 'ActiveStore'
        privacy_safe = $true
        categories = [pscustomobject]$categories
        canonical_sha256 = Get-LabStringSha256 -Value ($aggregate -join "`n")
    }
}

function Get-D01GlobalFirewallSnapshot {
    $first = Get-D01GlobalFirewallSnapshotOnce
    $second = Get-D01GlobalFirewallSnapshotOnce
    if ([string]$first.schema -cne [string]$second.schema -or
        [string]$first.policy_store -cne [string]$second.policy_store -or
        [string]$first.canonical_sha256 -cne
            [string]$second.canonical_sha256) {
        throw 'Global firewall inventory was unstable across capture'
    }
    return $second
}

function Get-D01AccountRegistrySnapshot {
    param([Parameter(Mandatory = $true)][string]$ExpectedUserSidSha256)
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ($null -eq $identity -or $null -eq $identity.User) {
        throw 'Current Windows SID is unavailable for registry capture'
    }
    $sidHash = Get-LabStringSha256 -Value ([string]$identity.User.Value)
    if ($sidHash -cne $ExpectedUserSidSha256.ToLowerInvariant()) {
        throw 'Registry capture account differs from the bound lab account'
    }
    $run = Get-D01RegistrySubtreeSnapshot `
        -RelativePath 'Software\Microsoft\Windows\CurrentVersion\Run' `
        -TrackedRootValueName 'eMuleAutoStart'
    $ed2k = Get-D01RegistrySubtreeSnapshot `
        -RelativePath 'Software\Classes\ed2k'
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.d01-account-registry-snapshot/v1'
        captured_at_utc = Get-LabUtcTimestamp
        user_sid_sha256 = $sidHash
        run_subtree = $run
        ed2k_subtree = $ed2k
        emule_autostart_absent = [int]$run.tracked_root_value_count -eq 0
        ed2k_subtree_absent = -not [bool]$ed2k.exists
    }
}

function Start-D01AccountRegistryTransaction {
    param([Parameter(Mandatory = $true)][string]$ExpectedUserSidSha256)
    $baseline = Get-D01AccountRegistrySnapshot `
        -ExpectedUserSidSha256 $ExpectedUserSidSha256
    if (-not [bool]$baseline.emule_autostart_absent -or
        -not [bool]$baseline.ed2k_subtree_absent) {
        throw 'D01 requires eMuleAutoStart and HKCU Classes ed2k to be initially absent'
    }
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.d01-account-registry-transaction/v1'
        expected_user_sid_sha256 = $ExpectedUserSidSha256.ToLowerInvariant()
        disposable_lab_account_attested = $true
        baseline = $baseline
        global_firewall_baseline = Get-D01GlobalFirewallSnapshot
        initial_absence_proved = $true
        destructive_restore_permitted = $false
    }
}

function Get-D01AccountRegistryPostcheckEvidence {
    param([Parameter(Mandatory = $true)]$Transaction)
    try {
        $after = Get-D01AccountRegistrySnapshot `
            -ExpectedUserSidSha256 (
                [string]$Transaction.expected_user_sid_sha256)
        $runUnchanged = Test-D01RegistrySubtreeSnapshotEqual `
            -Left $Transaction.baseline.run_subtree `
            -Right $after.run_subtree
        $ed2kUnchanged = Test-D01RegistrySubtreeSnapshotEqual `
            -Left $Transaction.baseline.ed2k_subtree `
            -Right $after.ed2k_subtree
        $firewallAfter = Get-D01GlobalFirewallSnapshot
        $firewallUnchanged = [string]$firewallAfter.canonical_sha256 -ceq
            [string]$Transaction.global_firewall_baseline.canonical_sha256
        $safe = $runUnchanged -and $ed2kUnchanged -and $firewallUnchanged -and
            [bool]$after.emule_autostart_absent -and
            [bool]$after.ed2k_subtree_absent -and
            [string]$after.user_sid_sha256 -ceq
                [string]$Transaction.expected_user_sid_sha256
        return [pscustomobject][ordered]@{
            schema = 'ese.v91.d01-account-registry-postcheck/v1'
            collector_ok = $true
            baseline = $Transaction.baseline
            post_state = $after
            global_firewall_baseline = $Transaction.global_firewall_baseline
            global_firewall_post_state = $firewallAfter
            bound_sid_unchanged = [string]$after.user_sid_sha256 -ceq
                [string]$Transaction.expected_user_sid_sha256
            run_subtree_unchanged = $runUnchanged
            ed2k_subtree_unchanged = $ed2kUnchanged
            global_firewall_unchanged = $firewallUnchanged
            emule_autostart_absent_after = [bool]$after.emule_autostart_absent
            ed2k_subtree_absent_after = [bool]$after.ed2k_subtree_absent
            destructive_restore_attempted = $false
            nonce_owned_firewall_cleanup_only = $true
            safe_to_pass = $safe
            error_sha256 = ''
        }
    } catch {
        return [pscustomobject][ordered]@{
            schema = 'ese.v91.d01-account-registry-postcheck/v1'
            collector_ok = $false
            baseline = $Transaction.baseline
            post_state = $null
            global_firewall_baseline = $Transaction.global_firewall_baseline
            global_firewall_post_state = $null
            bound_sid_unchanged = $false
            run_subtree_unchanged = $false
            ed2k_subtree_unchanged = $false
            global_firewall_unchanged = $false
            emule_autostart_absent_after = $false
            ed2k_subtree_absent_after = $false
            destructive_restore_attempted = $false
            nonce_owned_firewall_cleanup_only = $true
            safe_to_pass = $false
            error_sha256 = Get-LabStringSha256 -Value $_.Exception.Message
        }
    }
}

function New-D01ClockAnchor {
    $frequency = [Diagnostics.Stopwatch]::Frequency
    $qpcBefore = [Diagnostics.Stopwatch]::GetTimestamp()
    $utcTicks = [DateTime]::UtcNow.Ticks
    $qpcAfter = [Diagnostics.Stopwatch]::GetTimestamp()
    $midpoint = [Int64][Math]::Round(
        ([decimal]$qpcBefore + [decimal]$qpcAfter) / 2,
        [MidpointRounding]::AwayFromZero
    )
    $unixNanoseconds = [Int64](
        ([decimal]$utcTicks - [decimal]621355968000000000L) * 100
    )
    $uncertaintyNanoseconds = [Int64][Math]::Ceiling(
        [double](
            ([decimal]($qpcAfter - $qpcBefore) * 1000000000) /
            [decimal]$frequency / 2
        )
    ) + 100L
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.d01-clock-anchor/v1'
        clock_domain = 'windows-query-performance-counter'
        anchor_id = [Guid]::NewGuid().ToString('N')
        qpc_frequency = [Int64]$frequency
        anchor_qpc_ticks = $midpoint
        anchor_epoch_unix_ns = $unixNanoseconds
        anchor_uncertainty_ns = $uncertaintyNanoseconds
        generated_at_utc = Get-LabUtcTimestamp
    }
}

function Get-D01ClockObservation {
    param(
        [Parameter(Mandatory = $true)][object]$Anchor,
        [Parameter(Mandatory = $true)][Int64]$QpcStart,
        [Parameter(Mandatory = $true)][Int64]$QpcEnd
    )

    if ($QpcEnd -lt $QpcStart -or
        [Int64]$Anchor.qpc_frequency -le 0) {
        throw 'Invalid QPC observation interval'
    }
    $midpoint = [Int64][Math]::Round(
        ([decimal]$QpcStart + [decimal]$QpcEnd) / 2,
        [MidpointRounding]::AwayFromZero
    )
    $deltaNanoseconds = [decimal](
        ([decimal]($midpoint - [Int64]$Anchor.anchor_qpc_ticks) *
            1000000000) / [decimal][Int64]$Anchor.qpc_frequency
    )
    $epochNanoseconds = [Int64][Math]::Round(
        [decimal][Int64]$Anchor.anchor_epoch_unix_ns + $deltaNanoseconds,
        [MidpointRounding]::AwayFromZero
    )
    $intervalUncertainty = [Int64][Math]::Ceiling(
        [double](
            ([decimal]($QpcEnd - $QpcStart) * 1000000000) /
            [decimal][Int64]$Anchor.qpc_frequency / 2
        )
    )
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.d01-clock-observation/v1'
        clock_domain = [string]$Anchor.clock_domain
        anchor_id = [string]$Anchor.anchor_id
        qpc_frequency = [Int64]$Anchor.qpc_frequency
        qpc_start_ticks = $QpcStart
        qpc_end_ticks = $QpcEnd
        qpc_midpoint_ticks = $midpoint
        epoch_unix_ns = $epochNanoseconds
        uncertainty_ns =
            [Int64]$Anchor.anchor_uncertainty_ns + $intervalUncertainty
    }
}

function Write-D01JsonAtomic {
    param(
        [Parameter(Mandatory = $true)][object]$Value,
        [Parameter(Mandatory = $true)][string]$Path
    )

    $Path = [IO.Path]::GetFullPath($Path)
    $parent = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        $null = New-Item -ItemType Directory -Path $parent -Force
    }
    $parent = Assert-D01NoReparsePath -Path $parent -Kind Directory
    if (Test-Path -LiteralPath $Path) {
        throw "Atomic JSON target already exists: $Path"
    }
    $temporary = Join-Path $parent (
        '.{0}.{1}.tmp' -f (Split-Path -Leaf $Path),
        [Guid]::NewGuid().ToString('N')
    )
    try {
        $stream = [IO.File]::Open(
            $temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write,
            [IO.FileShare]::None)
        try {
            $writer = [IO.StreamWriter]::new(
                $stream, [Text.UTF8Encoding]::new($false), 4096, $true)
            try {
                $writer.Write(($Value | ConvertTo-Json -Depth 48))
                $writer.Flush()
                $stream.Flush($true)
            } finally { $writer.Dispose() }
        } finally { $stream.Dispose() }
        $null = Assert-D01NoReparsePath -Path $parent -Kind Directory
        $null = Assert-D01NoReparsePath -Path $temporary -Kind File
        if (Test-Path -LiteralPath $Path) {
            throw "Atomic JSON target appeared before commit: $Path"
        }
        [IO.File]::Move($temporary, $Path)
        $null = Assert-D01NoReparsePath -Path $Path -Kind File
    } finally {
        if (Test-Path -LiteralPath $temporary -PathType Leaf) {
            Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
        }
    }
}

function Add-D01JsonLine {
    param(
        [Parameter(Mandatory = $true)][object]$Value,
        [Parameter(Mandatory = $true)][string]$Path
    )

    Add-Content -LiteralPath $Path -Encoding utf8 -Value (
        $Value | ConvertTo-Json -Depth 32 -Compress
    )
}

function Read-D01ImmutableJsonFile {
    param([Parameter(Mandatory = $true)][string]$Path)

    $safePath = Assert-D01NoReparsePath -Path $Path -Kind File
    $stream = [IO.File]::Open(
        $safePath, [IO.FileMode]::Open, [IO.FileAccess]::Read,
        [IO.FileShare]::Read
    )
    try {
        if ($stream.Length -le 0 -or $stream.Length -gt 16777216) {
            throw 'Coordination JSON size is outside its bounded contract'
        }
        $bytes = New-Object byte[] ([int]$stream.Length)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $read = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($read -le 0) {
                throw 'Coordination JSON ended before its locked length'
            }
            $offset += $read
        }
        $utf8 = [Text.UTF8Encoding]::new($false, $true)
        $text = $utf8.GetString($bytes)
        if ($text.Length -gt 0 -and $text[0] -eq [char]0xfeff) {
            $text = $text.Substring(1)
        }
        $value = $text | ConvertFrom-Json -ErrorAction Stop
        $memory = [IO.MemoryStream]::new($bytes, $false)
        try { $sha256 = Get-D01Sha256FromStream -Stream $memory }
        finally { $memory.Dispose() }
        $script:d01CandidateLocks.Add($stream)
        return [pscustomobject][ordered]@{
            value = $value
            sha256 = $sha256
            byte_count = [Int64]$bytes.Length
            immutable_read_lock_held = $true
        }
    } catch {
        $stream.Dispose()
        throw
    }
}

function Wait-D01JsonFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds,
        [AllowEmptyString()][string]$StopPath = ''
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        if ($StopPath -and
            (Test-Path -LiteralPath $StopPath -PathType Leaf)) {
            try {
                $lockedStop = Read-D01ImmutableJsonFile -Path $StopPath
                return [pscustomobject]@{
                    kind = 'stop'
                    value = $lockedStop.value
                    sha256 = $lockedStop.sha256
                    immutable_read_lock_held =
                        $lockedStop.immutable_read_lock_held
                }
            } catch {}
        }
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            try {
                $lockedValue = Read-D01ImmutableJsonFile -Path $Path
                return [pscustomobject]@{
                    kind = 'value'
                    value = $lockedValue.value
                    sha256 = $lockedValue.sha256
                    immutable_read_lock_held =
                        $lockedValue.immutable_read_lock_held
                }
            } catch {}
        }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    return $null
}

function Get-D01Sha256FromStream {
    param([Parameter(Mandatory = $true)][IO.Stream]$Stream)

    if ($Stream.CanSeek) { $Stream.Position = 0 }
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $hash = $sha.ComputeHash($Stream) } finally {
        $sha.Dispose()
        if ($Stream.CanSeek) { $Stream.Position = 0 }
    }
    return ([BitConverter]::ToString($hash)).Replace('-', '').ToLowerInvariant()
}

function Assert-D01NoReparsePath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [ValidateSet('File', 'Directory')][string]$Kind
    )

    $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    if ($Kind -eq 'File' -and
        -not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
        throw "Required file is not regular: $resolved"
    }
    if ($Kind -eq 'Directory' -and
        -not (Test-Path -LiteralPath $resolved -PathType Container)) {
        throw "Required directory is not a directory: $resolved"
    }
    $cursor = if ($Kind -eq 'File') {
        Split-Path -Parent $resolved
    } else { $resolved }
    $volumeRoot = [IO.Path]::GetPathRoot($cursor).TrimEnd('\')
    while ($cursor -and $cursor.TrimEnd('\') -ne $volumeRoot) {
        $item = Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Path crosses a reparse point: $cursor"
        }
        $parent = Split-Path -Parent $cursor
        if (-not $parent -or $parent -eq $cursor) { break }
        $cursor = $parent
    }
    $leaf = Get-Item -LiteralPath $resolved -Force -ErrorAction Stop
    if (($leaf.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Path leaf is a reparse point: $resolved"
    }
    return $resolved
}

function Assert-D01SafeCreationPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    $full = [IO.Path]::GetFullPath($Path)
    $cursor = $full
    while (-not (Test-Path -LiteralPath $cursor)) {
        $parent = Split-Path -Parent $cursor
        if (-not $parent -or $parent -eq $cursor) {
            throw "No safe existing ancestor for $full"
        }
        $cursor = $parent
    }
    $null = Assert-D01NoReparsePath -Path $cursor -Kind Directory
    return $full
}

function Convert-D01SafeRelativePath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [switch]$AllowTrailingSlash
    )

    if ([string]::IsNullOrWhiteSpace($Path) -or $Path.Contains('\') -or
        $Path.StartsWith('/') -or $Path.Contains(':') -or
        [IO.Path]::IsPathRooted($Path)) {
        throw "Unsafe package path: '$Path'"
    }
    $normalized = $Path.Normalize([Text.NormalizationForm]::FormC)
    if (-not [StringComparer]::Ordinal.Equals($normalized, $Path)) {
        throw "Package path is not Unicode NFC: '$Path'"
    }
    $plain = if ($AllowTrailingSlash) { $Path.TrimEnd('/') } else { $Path }
    if (-not $plain -or (-not $AllowTrailingSlash -and $Path.EndsWith('/'))) {
        throw "Unsafe package file path: '$Path'"
    }
    foreach ($segment in @($plain -split '/')) {
        if (-not $segment -or $segment -in @('.', '..') -or
            $segment -match '[<>:"|?*]' -or $segment.EndsWith('.') -or
            $segment.EndsWith(' ')) {
            throw "Unsafe package segment '$segment'"
        }
        $deviceStem = ($segment -split '\.')[0]
        if ($deviceStem -match
            '^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$') {
            throw "Reserved Windows device package segment '$segment'"
        }
    }
    return $plain
}

function Get-D01SafeTreeFiles {
    param([Parameter(Mandatory = $true)][string]$Root)

    $resolvedRoot = Assert-D01NoReparsePath -Path $Root -Kind Directory
    $prefix = $resolvedRoot.TrimEnd('\') + '\'
    $queue = New-Object 'Collections.Generic.Queue[IO.DirectoryInfo]'
    $queue.Enqueue((Get-Item -LiteralPath $resolvedRoot -Force))
    $files = [System.Collections.Generic.List[object]]::new()
    $seen = New-Object 'Collections.Generic.HashSet[string]' `
        ([StringComparer]::OrdinalIgnoreCase)
    while ($queue.Count -gt 0) {
        $directory = $queue.Dequeue()
        $children = @(
            Get-ChildItem -LiteralPath $directory.FullName -Force `
                -ErrorAction Stop
        )
        if ($directory.FullName -cne $resolvedRoot -and
            $children.Count -eq 0) {
            throw "Candidate tree contains an empty directory: $($directory.FullName)"
        }
        foreach ($item in $children) {
            if (($item.Attributes -band
                    [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Candidate tree contains a reparse point: $($item.FullName)"
            }
            if ($item.PSIsContainer) {
                $queue.Enqueue([IO.DirectoryInfo]$item)
                continue
            }
            if (-not (Test-Path -LiteralPath $item.FullName -PathType Leaf)) {
                throw "Candidate tree contains a non-regular entry: $($item.FullName)"
            }
            $relative = Convert-D01SafeRelativePath -Path (
                $item.FullName.Substring($prefix.Length).Replace('\', '/')
            )
            if (-not $seen.Add($relative)) {
                throw "Candidate has a case/Unicode path collision: $relative"
            }
            $files.Add([pscustomobject][ordered]@{
                relative_path = $relative
                full_path = $item.FullName
                length = [Int64]$item.Length
            })
        }
    }
    $ordered = @($files.ToArray())
    [Array]::Sort($ordered, [Comparison[object]]{
        param($left, $right)
        return [StringComparer]::Ordinal.Compare(
            [string]$left.relative_path, [string]$right.relative_path)
    })
    return $ordered
}

function Open-D01LockedFile {
    param([Parameter(Mandatory = $true)][string]$Path)

    $resolved = Assert-D01NoReparsePath -Path $Path -Kind File
    $exclusive = [IO.FileStream]::new(
        $resolved, [IO.FileMode]::Open, [IO.FileAccess]::Read,
        [IO.FileShare]::None
    )
    try {
        $exclusiveHash = Get-D01Sha256FromStream -Stream $exclusive
        $exclusiveLength = [Int64]$exclusive.Length
    } finally { $exclusive.Dispose() }
    $locked = [IO.FileStream]::new(
        $resolved, [IO.FileMode]::Open, [IO.FileAccess]::Read,
        [IO.FileShare]::Read
    )
    try {
        $lockedHash = Get-D01Sha256FromStream -Stream $locked
        if ($lockedHash -cne $exclusiveHash -or
            [Int64]$locked.Length -ne $exclusiveLength) {
            throw "Candidate changed while immutable lock was acquired: $resolved"
        }
        $script:d01CandidateLocks.Add($locked)
    } catch {
        $locked.Dispose()
        throw
    }
    return [pscustomobject][ordered]@{
        path = $resolved
        length = $exclusiveLength
        sha256 = $lockedHash
        stream = $locked
    }
}

function Get-D01CandidateIdentity {
    if ($null -eq $script:d01CandidateBinding) {
        $packageRoot = Assert-D01NoReparsePath -Path $PackagePath `
            -Kind Directory
        $zipLock = Open-D01LockedFile -Path $PackageZipPath
        if ([string]$zipLock.sha256 -cne $expectedZipHash) {
            throw 'Package ZIP hash differs from ExpectedPackageZipSha256'
        }
        $packageFiles = @(Get-D01SafeTreeFiles -Root $packageRoot)
        if ($packageFiles.Count -eq 0) { throw 'Candidate package is empty' }
        $packageMap = New-Object `
            'Collections.Generic.Dictionary[string,object]' `
            ([StringComparer]::OrdinalIgnoreCase)
        foreach ($file in $packageFiles) {
            $locked = Open-D01LockedFile -Path $file.full_path
            $packageMap.Add([string]$file.relative_path,
                [pscustomobject][ordered]@{
                    length = [Int64]$locked.length
                    sha256 = [string]$locked.sha256
                })
        }

        Add-Type -AssemblyName System.IO.Compression -ErrorAction Stop
        $zipLock.stream.Position = 0
        $archive = [IO.Compression.ZipArchive]::new(
            $zipLock.stream, [IO.Compression.ZipArchiveMode]::Read, $true
        )
        try {
            $records = [System.Collections.Generic.List[object]]::new()
            $names = New-Object 'Collections.Generic.HashSet[string]' `
                ([StringComparer]::OrdinalIgnoreCase)
            $directoryNames = [System.Collections.Generic.List[string]]::new()
            foreach ($entry in $archive.Entries) {
                $directoryEntry = ([string]$entry.FullName).EndsWith('/')
                $safeName = Convert-D01SafeRelativePath `
                    -Path ([string]$entry.FullName) `
                    -AllowTrailingSlash:$directoryEntry
                $external = [UInt32](
                    [Int64]$entry.ExternalAttributes -band 0xffffffffL
                )
                $unixType = ($external -shr 16) -band 0xF000
                if ($unixType -eq 0xA000 -or
                    ($external -band 0x400) -ne 0) {
                    throw "ZIP contains a symlink/reparse entry: $safeName"
                }
                if (-not $names.Add($safeName)) {
                    throw "ZIP has a case/Unicode path collision: $safeName"
                }
                if ($directoryEntry) {
                    $directoryNames.Add($safeName)
                    continue
                }
                $records.Add([pscustomobject]@{
                    safe_name = $safeName
                    entry = $entry
                })
            }
            $exeEntries = @($records.ToArray() | Where-Object {
                ([string]$_.safe_name).Split('/')[-1] -ieq 'emule.exe'
            })
            if ($exeEntries.Count -ne 1) {
                throw "ZIP must contain exactly one emule.exe; found $($exeEntries.Count)"
            }
            $exeName = [string]$exeEntries[0].safe_name
            $rootPrefix = $exeName.Substring(
                0, $exeName.Length - 'emule.exe'.Length
            )
            $rootDirectoryName = $rootPrefix.TrimEnd('/')
            foreach ($directoryName in $directoryNames.ToArray()) {
                if ($directoryName -ceq $rootDirectoryName) { continue }
                if (-not $directoryName.StartsWith(
                    $rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
                    throw "ZIP directory is outside the candidate root: $directoryName"
                }
                $logicalDirectory = Convert-D01SafeRelativePath -Path (
                    $directoryName.Substring($rootPrefix.Length))
                $hasChild = @($records.ToArray() | Where-Object {
                    ([string]$_.safe_name).StartsWith(
                        $directoryName + '/',
                        [StringComparison]::OrdinalIgnoreCase)
                }).Count -gt 0
                if (-not $hasChild) {
                    throw "ZIP contains an empty directory: $directoryName"
                }
                $packageDirectory = Join-Path $packageRoot (
                    $logicalDirectory.Replace('/', '\'))
                $null = Assert-D01NoReparsePath -Path $packageDirectory `
                    -Kind Directory
            }
            $zipMap = New-Object `
                'Collections.Generic.Dictionary[string,object]' `
                ([StringComparer]::OrdinalIgnoreCase)
            foreach ($record in $records.ToArray()) {
                $entryName = [string]$record.safe_name
                if (-not $entryName.StartsWith(
                    $rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
                    throw "ZIP entry is outside the candidate root: $entryName"
                }
                $relative = Convert-D01SafeRelativePath -Path (
                    $entryName.Substring($rootPrefix.Length)
                )
                if ($zipMap.ContainsKey($relative)) {
                    throw "ZIP logical-root collision: $relative"
                }
                $entryStream = $record.entry.Open()
                try {
                    $entryHash = Get-D01Sha256FromStream `
                        -Stream $entryStream
                } finally { $entryStream.Dispose() }
                $zipMap.Add($relative, [pscustomobject][ordered]@{
                    length = [Int64]$record.entry.Length
                    sha256 = $entryHash
                })
            }
        } finally {
            $archive.Dispose()
            $zipLock.stream.Position = 0
        }
        if ($zipMap.Count -ne $packageMap.Count) {
            throw 'ZIP/package file census differs'
        }
        foreach ($relative in @($packageMap.Keys)) {
            if (-not $zipMap.ContainsKey($relative) -or
                [Int64]$zipMap[$relative].length -ne
                    [Int64]$packageMap[$relative].length -or
                [string]$zipMap[$relative].sha256 -cne
                    [string]$packageMap[$relative].sha256) {
                throw "ZIP/package content differs: $relative"
            }
        }
        if (-not $packageMap.ContainsKey('emule.exe') -or
            [string]$packageMap['emule.exe'].sha256 -cne
                $expectedEmuleHash) {
            throw 'Bound package emule.exe is not the expected executable'
        }
        if ($packageMap.ContainsKey('LAB_NODE.json')) {
            throw 'Candidate package may not predefine LAB_NODE.json'
        }
        $candidate = Get-LabCandidateInfo -PackagePath $packageRoot `
            -ExpectedCommit $Commit
        if ([string]$candidate.emule_sha256 -cne $expectedEmuleHash) {
            throw 'BUILD_INFO candidate hash disagrees with held package bytes'
        }
        [string[]]$manifestKeys = @($packageMap.Keys)
        [Array]::Sort($manifestKeys, [StringComparer]::Ordinal)
        $manifestLines = @($manifestKeys | ForEach-Object {
            '{0}|{1}|{2}' -f $_, $packageMap[$_].length,
                $packageMap[$_].sha256
        })
        $script:d01CandidateBinding = [pscustomobject][ordered]@{
            package_path = $packageRoot
            package_zip_path = $zipLock.path
            package_zip_sha256 = $zipLock.sha256
            package_manifest_sha256 = Get-LabStringSha256 `
                -Value ($manifestLines -join "`n")
            package_file_count = $packageMap.Count
            package_file_hashes = $packageMap
            release = $candidate.release
            version = $candidate.version
            commit = $candidate.commit
            dirty = $candidate.dirty
            emule_sha256 = $candidate.emule_sha256
            ese_server_sha256 = $candidate.ese_server_sha256
            build_info_sha256 = $candidate.build_info_sha256
            immutable_locks_held = $true
        }
    } else {
        $null = Assert-D01CandidateBindingUnchanged `
            -Binding $script:d01CandidateBinding
    }
    $binding = $script:d01CandidateBinding
    $totalBytes = [Int64]0
    foreach ($key in @($binding.package_file_hashes.Keys)) {
        $totalBytes += [Int64]$binding.package_file_hashes[$key].length
    }
    $directory = [pscustomobject][ordered]@{
        schema = 'ese.v91.d01-extracted-package-manifest/v3'
        file_count = [int]$binding.package_file_count
        total_bytes = $totalBytes
        manifest_sha256 = [string]$binding.package_manifest_sha256
    }
    $zip = [pscustomobject][ordered]@{
        schema = 'ese.v91.d01-zip-manifest/v3'
        zip_sha256 = [string]$binding.package_zip_sha256
        file_count = [int]$binding.package_file_count
        total_uncompressed_bytes = $totalBytes
        manifest_sha256 = [string]$binding.package_manifest_sha256
    }
    return [pscustomobject][ordered]@{
        candidate = $binding
        extracted_manifest = $directory
        zip_manifest = $zip
        emule_sha256_matches = [string]$binding.emule_sha256 -ceq
            $expectedEmuleHash
        zip_sha256_matches = [string]$binding.package_zip_sha256 -ceq
            $expectedZipHash
        zip_matches_extracted_directory = $true
        exact = [string]$binding.emule_sha256 -ceq $expectedEmuleHash -and
            [string]$binding.package_zip_sha256 -ceq $expectedZipHash -and
            [bool]$binding.immutable_locks_held
    }
}

function Assert-D01CandidateBindingUnchanged {
    param([Parameter(Mandatory = $true)][object]$Binding)

    if ((Get-LabSha256 -Path $Binding.package_zip_path) -cne
        [string]$Binding.package_zip_sha256) {
        throw 'Held package ZIP changed after binding'
    }
    $files = @(Get-D01SafeTreeFiles -Root $Binding.package_path)
    if ($files.Count -ne [int]$Binding.package_file_count) {
        throw 'Candidate package file census changed after binding'
    }
    $lines = foreach ($file in $files) {
        if (-not $Binding.package_file_hashes.ContainsKey(
            [string]$file.relative_path)) {
            throw "New candidate file appeared: $($file.relative_path)"
        }
        $hash = Get-LabSha256 -Path $file.full_path
        $expected = $Binding.package_file_hashes[$file.relative_path]
        if ($hash -cne [string]$expected.sha256 -or
            [Int64]$file.length -ne [Int64]$expected.length) {
            throw "Candidate file changed: $($file.relative_path)"
        }
        '{0}|{1}|{2}' -f $file.relative_path, $file.length, $hash
    }
    [string[]]$orderedLines = @($lines)
    [Array]::Sort($orderedLines, [StringComparer]::Ordinal)
    if ((Get-LabStringSha256 -Value (
        $orderedLines -join "`n")) -cne
        [string]$Binding.package_manifest_sha256) {
        throw 'Candidate manifest fingerprint changed'
    }
    return $true
}

function Assert-D01PreparedNodeDerivedFromBinding {
    param(
        [Parameter(Mandatory = $true)][string]$NodePath,
        [Parameter(Mandatory = $true)][object]$Binding
    )

    $files = @(Get-D01SafeTreeFiles -Root $NodePath)
    if ($files.Count -ne ([int]$Binding.package_file_count + 1)) {
        throw 'Prepared node is not exactly package plus LAB_NODE.json'
    }
    $seen = New-Object 'Collections.Generic.HashSet[string]' `
        ([StringComparer]::OrdinalIgnoreCase)
    foreach ($file in $files) {
        $relative = [string]$file.relative_path
        if ($relative -ieq 'LAB_NODE.json') { continue }
        if (-not $Binding.package_file_hashes.ContainsKey($relative)) {
            throw "Prepared node contains an unbound file: $relative"
        }
        $null = $seen.Add($relative)
        if ($relative -ieq 'config/preferences.ini') {
            continue
        }
        $expected = $Binding.package_file_hashes[$relative]
        if ([Int64]$file.length -ne [Int64]$expected.length -or
            (Get-LabSha256 -Path $file.full_path) -cne
                [string]$expected.sha256) {
            throw "Prepared node differs from package: $relative"
        }
    }
    foreach ($relative in @($Binding.package_file_hashes.Keys)) {
        if (-not $seen.Contains([string]$relative)) {
            throw "Prepared node omitted package file: $relative"
        }
    }
    return $true
}

function Lock-D01PreparedNodeCode {
    param(
        [Parameter(Mandatory = $true)][string]$NodePath,
        [Parameter(Mandatory = $true)][string]$ExpectedExeSha256
    )

    $codeFiles = @(Get-D01SafeTreeFiles -Root $NodePath | Where-Object {
        [IO.Path]::GetExtension([string]$_.relative_path) -in @('.exe', '.dll')
    })
    $rootExe = @($codeFiles | Where-Object {
        [string]$_.relative_path -ieq 'emule.exe'
    })
    if ($rootExe.Count -ne 1) {
        throw 'Prepared node must have exactly one root emule.exe'
    }
    $records = [System.Collections.Generic.List[object]]::new()
    foreach ($file in $codeFiles) {
        $lock = Open-D01LockedFile -Path $file.full_path
        $records.Add([pscustomobject][ordered]@{
            relative_path_sha256 = Get-LabStringSha256 `
                -Value ([string]$file.relative_path)
            length = [Int64]$lock.length
            sha256 = [string]$lock.sha256
        })
    }
    if ((Get-LabSha256 -Path (Join-Path $NodePath 'emule.exe')) -cne
        $ExpectedExeSha256.ToLowerInvariant()) {
        throw 'Prepared node executable differs from expected candidate'
    }
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.d01-prepared-code-lock/v1'
        executable_sha256 = $ExpectedExeSha256.ToLowerInvariant()
        code_module_count = $records.Count
        code_modules = $records.ToArray()
        immutable_code_locks_held = $true
    }
}

function Get-D01EndpointBytes {
    param(
        [Parameter(Mandatory = $true)][Net.IPAddress]$Address,
        [Parameter(Mandatory = $true)][int]$Port
    )

    $familyByte = if ($Address.AddressFamily -eq
        [Net.Sockets.AddressFamily]::InterNetwork) { [byte]4 } else { [byte]6 }
    $addressBytes = $Address.GetAddressBytes()
    $result = New-Object byte[] (1 + $addressBytes.Length + 2)
    $result[0] = $familyByte
    [Array]::Copy($addressBytes, 0, $result, 1, $addressBytes.Length)
    $result[$result.Length - 2] = [byte](($Port -shr 8) -band 0xff)
    $result[$result.Length - 1] = [byte]($Port -band 0xff)
    return $result
}

function Get-D01BytesSha256 {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)

    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString(
            $sha.ComputeHash($Bytes)
        )).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function Get-D01CanonicalEndpointEvidence {
    param(
        [Parameter(Mandatory = $true)][Net.IPAddress[]]$Addresses,
        [Parameter(Mandatory = $true)][int]$Port
    )

    $entries = @(
        foreach ($address in $Addresses) {
            $bytes = Get-D01EndpointBytes -Address $address -Port $Port
            [pscustomobject][ordered]@{
                family = if ($address.AddressFamily -eq
                    [Net.Sockets.AddressFamily]::InterNetwork) {
                    'IPv4'
                } else { 'IPv6' }
                endpoint_sha256 = Get-D01BytesSha256 -Bytes $bytes
                canonical_hex = [BitConverter]::ToString($bytes).
                    Replace('-', '').ToLowerInvariant()
                bytes = $bytes
            }
        }
    )
    $sorted = @($entries | Sort-Object canonical_hex)
    $stream = New-Object IO.MemoryStream
    try {
        foreach ($entry in $sorted) {
            $stream.Write($entry.bytes, 0, $entry.bytes.Length)
        }
        $setBytes = $stream.ToArray()
    } finally {
        $stream.Dispose()
    }
    return [pscustomobject][ordered]@{
        algorithm =
            'family-byte(4|6)||address-network-bytes||port-big-endian; ' +
            'lexicographic-entry-sort; concatenation; sha256'
        port = $Port
        endpoint_set_sha256 = Get-D01BytesSha256 -Bytes $setBytes
        endpoints = @(
            $sorted | Select-Object family, endpoint_sha256, canonical_hex
        )
    }
}

function Get-D01AdapterEvidence {
    param(
        [Parameter(Mandatory = $true)][int]$InterfaceIndex,
        [Parameter(Mandatory = $true)][string]$Context
    )

    $adapters = @(Get-NetAdapter -IncludeHidden `
        -InterfaceIndex $InterfaceIndex -ErrorAction Stop)
    if ($adapters.Count -ne 1) {
        throw "$Context adapter inventory was not singular"
    }
    $adapter = $adapters[0]
    if ($adapter.PSObject.Properties.Name -notcontains 'Virtual' -or
        $adapter.Virtual -isnot [bool] -or
        $adapter.PSObject.Properties.Name -notcontains 'HardwareInterface' -or
        $adapter.HardwareInterface -isnot [bool]) {
        throw "$Context adapter physical/virtual metadata is missing or mistyped"
    }
    $isVirtual = [bool]$adapter.Virtual
    $overlayLike = ([string]$adapter.Name) -match $overlayPattern -or
        ([string]$adapter.InterfaceDescription) -match $overlayPattern
    $physical = [bool]$adapter.HardwareInterface -and -not $isVirtual -and
        -not $overlayLike -and [string]$adapter.Status -eq 'Up'
    return [pscustomobject][ordered]@{
        context = $Context
        interface_index = [int]$adapter.InterfaceIndex
        interface_id = Get-LabInterfaceId `
            -Id ([string]$adapter.InterfaceGuid) `
            -Name ([string]$adapter.Name) `
            -Description ([string]$adapter.InterfaceDescription)
        interface_guid_sha256 = Get-LabStringSha256 -Value (
            ([string]$adapter.InterfaceGuid).ToLowerInvariant())
        interface_name_sha256 = Get-LabStringSha256 -Value (
            ([string]$adapter.Name).ToLowerInvariant())
        interface_description_sha256 = Get-LabStringSha256 -Value (
            ([string]$adapter.InterfaceDescription).ToLowerInvariant())
        status = [string]$adapter.Status
        hardware_interface = [bool]$adapter.HardwareInterface
        virtual = $isVirtual
        overlay_or_vpn_like = $overlayLike
        physical_nonvirtual = $physical
    }
}

function Get-D01NetworkPrefix {
    param(
        [Parameter(Mandatory = $true)][string]$Address,
        [Parameter(Mandatory = $true)][int]$PrefixLength
    )

    $parsed = [Net.IPAddress]::Parse($Address.Split('%')[0])
    $bytes = $parsed.GetAddressBytes()
    if ($PrefixLength -lt 0 -or
        $PrefixLength -gt ($bytes.Length * 8)) {
        throw "Invalid prefix length $PrefixLength for $Address"
    }
    $remaining = $PrefixLength
    for ($index = 0; $index -lt $bytes.Length; $index++) {
        if ($remaining -ge 8) {
            $remaining -= 8
            continue
        }
        if ($remaining -le 0) {
            $bytes[$index] = 0
        } else {
            $mask = [byte](0xff -band (0xff -shl (8 - $remaining)))
            $bytes[$index] = [byte]($bytes[$index] -band $mask)
            $remaining = 0
        }
    }
    return '{0}/{1}' -f (New-Object Net.IPAddress -ArgumentList (, $bytes)),
        $PrefixLength
}

function Get-D01AssignedAddress {
    param(
        [Parameter(Mandatory = $true)][string]$Address,
        [Parameter(Mandatory = $true)]
        [Net.Sockets.AddressFamily]$Family,
        [Parameter(Mandatory = $true)][string]$Context
    )

    $familyName = if ($Family -eq
        [Net.Sockets.AddressFamily]::InterNetwork) { 'IPv4' } else { 'IPv6' }
    $normalized = Get-D01NormalizedIp -Address $Address
    $items = @(Get-NetIPAddress -AddressFamily $familyName `
        -ErrorAction Stop | Where-Object {
            (Get-D01NormalizedIp -Address ([string]$_.IPAddress)) -eq
                $normalized -and [string]$_.AddressState -eq 'Preferred'
        })
    if ($items.Count -ne 1) {
        throw "$Context must be exactly one Preferred address on this host"
    }
    $item = $items[0]
    $adapter = Get-D01AdapterEvidence `
        -InterfaceIndex ([int]$item.InterfaceIndex) -Context $Context
    return [pscustomobject][ordered]@{
        address = $normalized
        address_class = Get-D01StrictAddressClass -Address $normalized
        interface_index = [int]$item.InterfaceIndex
        prefix_length = [int]$item.PrefixLength
        network_prefix = Get-D01NetworkPrefix `
            -Address $normalized -PrefixLength ([int]$item.PrefixLength)
        adapter = $adapter
    }
}

function Get-D01RouteEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$RemoteAddress,
        [Parameter(Mandatory = $true)][string]$Context
    )

    try {
        $routes = @(Find-NetRoute -RemoteIPAddress $RemoteAddress `
            -ErrorAction Stop)
        if ($routes.Count -ne 1) {
            throw 'Find-NetRoute did not return exactly one selected route'
        }
        $route = $routes[0]
        $adapter = Get-D01AdapterEvidence `
            -InterfaceIndex ([int]$route.InterfaceIndex) -Context $Context
        $source = Get-D01NormalizedIp -Address ([string]$route.IPAddress)
        $nextHop = Get-D01NormalizedIp -Address ([string]$route.NextHop)
        $onLink = $nextHop -in @('0.0.0.0', '::')
        return [pscustomobject][ordered]@{
            available = $true
            remote_address = Get-D01NormalizedIp -Address $RemoteAddress
            source_address = $source
            source_class = Get-D01StrictAddressClass -Address $source
            interface_index = [int]$route.InterfaceIndex
            next_hop = $nextHop
            next_hop_class = if ($onLink) {
                'on-link'
            } else {
                Get-D01StrictAddressClass -Address $nextHop
            }
            on_link = $onLink
            adapter = $adapter
            collector_ok = $true
            error_sha256 = ''
        }
    } catch {
        return [pscustomobject][ordered]@{
            available = $false
            remote_address = Get-D01NormalizedIp -Address $RemoteAddress
            source_address = ''
            source_class = 'invalid'
            interface_index = $null
            next_hop = ''
            next_hop_class = 'unknown'
            on_link = $false
            adapter = $null
            collector_ok = $false
            error_sha256 = Get-LabStringSha256 -Value $_.Exception.Message
        }
    }
}

function Get-D01IsolationEvidence {
    $allAdapters = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop)
    if ($allAdapters.Count -eq 0) {
        throw 'Adapter inventory was empty'
    }
    foreach ($adapter in $allAdapters) {
        if ($adapter.PSObject.Properties.Name -notcontains 'Virtual' -or
            $adapter.Virtual -isnot [bool]) {
            throw 'Adapter Virtual metadata is missing or mistyped'
        }
    }
    $overlays = @($allAdapters | Where-Object {
        [string]$_.Status -eq 'Up' -and (
            [bool]$_.Virtual -or
            ([string]$_.Name) -match $overlayPattern -or
            ([string]$_.InterfaceDescription) -match $overlayPattern)
    } | ForEach-Object {
            [pscustomobject][ordered]@{
                interface_index = [int]$_.InterfaceIndex
                interface_id = Get-LabInterfaceId `
                    -Id ([string]$_.InterfaceGuid) `
                    -Name ([string]$_.Name) `
                    -Description ([string]$_.InterfaceDescription)
                virtual = [bool]$_.Virtual
            }
        })
    $proxyEnvironmentNames = @(
        'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY',
        'http_proxy', 'https_proxy', 'all_proxy'
    )
    $setProxyEnvironmentNames = @(
        $proxyEnvironmentNames | Where-Object {
            -not [string]::IsNullOrWhiteSpace(
                [Environment]::GetEnvironmentVariable($_)
            )
        } | Sort-Object -Unique
    )
    $internetSettings = Get-ItemProperty `
        -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' `
        -ErrorAction Stop
    $proxyEnabled = $internetSettings.PSObject.Properties.Name -contains
        'ProxyEnable' -and [int]$internetSettings.ProxyEnable -ne 0
    $autoConfigSet = $internetSettings.PSObject.Properties.Name -contains
        'AutoConfigURL' -and -not [string]::IsNullOrWhiteSpace(
            [string]$internetSettings.AutoConfigURL)
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.d01-isolation/v2'
        collector_ok = $true
        captured_at_utc = Get-LabUtcTimestamp
        active_overlay_or_vpn_adapters = $overlays
        active_overlay_or_vpn_count = $overlays.Count
        proxy_environment_variable_names_set = $setProxyEnvironmentNames
        proxy_environment_variable_count = $setProxyEnvironmentNames.Count
        system_proxy_enabled = $proxyEnabled
        automatic_proxy_configuration_set = $autoConfigSet
        strict_isolation_valid =
            $overlays.Count -eq 0 -and $setProxyEnvironmentNames.Count -eq 0 -and
            -not $proxyEnabled -and -not $autoConfigSet
    }
}

function Convert-D01IpAddressToUnsignedBigInteger {
    param([Parameter(Mandatory = $true)][Net.IPAddress]$Address)

    [byte[]]$networkBytes = $Address.GetAddressBytes()
    [Array]::Reverse($networkBytes)
    [byte[]]$unsignedBytes = New-Object byte[] ($networkBytes.Length + 1)
    [Array]::Copy($networkBytes, 0, $unsignedBytes, 0, $networkBytes.Length)
    return [Numerics.BigInteger]::new($unsignedBytes)
}

function Convert-D01UnsignedBigIntegerToIpAddress {
    param(
        [Parameter(Mandatory = $true)][Numerics.BigInteger]$Value,
        [ValidateSet(4, 16)][int]$ByteCount
    )

    if ($Value -lt [Numerics.BigInteger]::Zero) {
        throw 'IP integer cannot be negative'
    }
    [byte[]]$littleEndian = $Value.ToByteArray()
    if ($littleEndian.Length -gt $ByteCount + 1 -or
        ($littleEndian.Length -eq $ByteCount + 1 -and
            $littleEndian[$ByteCount] -ne 0)) {
        throw 'IP integer exceeds the requested address family'
    }
    [byte[]]$networkBytes = New-Object byte[] $ByteCount
    [Array]::Copy($littleEndian, 0, $networkBytes, 0,
        [Math]::Min($littleEndian.Length, $ByteCount))
    [Array]::Reverse($networkBytes)
    return [Net.IPAddress]::new($networkBytes)
}

function Get-D01FirewallAddressExclusionRanges {
    param(
        [Parameter(Mandatory = $true)][string[]]$AllowedAddresses,
        [ValidateSet('IPv4', 'IPv6')][string]$Family
    )

    $byteCount = if ($Family -eq 'IPv4') { 4 } else { 16 }
    $addressFamily = if ($Family -eq 'IPv4') {
        [Net.Sockets.AddressFamily]::InterNetwork
    } else { [Net.Sockets.AddressFamily]::InterNetworkV6 }
    $allowedNumbers = @($AllowedAddresses | ForEach-Object {
        $address = Convert-D01Address -Value ([string]$_) -Name 'allowed address'
        if ($address.AddressFamily -eq $addressFamily) {
            Convert-D01IpAddressToUnsignedBigInteger -Address $address
        }
    } | Sort-Object -Unique)
    $maximum = ([Numerics.BigInteger]::One -shl ($byteCount * 8)) -
        [Numerics.BigInteger]::One
    $cursor = [Numerics.BigInteger]::Zero
    $ranges = [Collections.Generic.List[string]]::new()
    foreach ($allowed in $allowedNumbers) {
        if ($allowed -gt $cursor) {
            $first = Convert-D01UnsignedBigIntegerToIpAddress `
                -Value $cursor -ByteCount $byteCount
            $last = Convert-D01UnsignedBigIntegerToIpAddress `
                -Value ($allowed - [Numerics.BigInteger]::One) `
                -ByteCount $byteCount
            $ranges.Add("$($first.ToString())-$($last.ToString())")
        }
        if ($allowed -ge $cursor) {
            $cursor = $allowed + [Numerics.BigInteger]::One
        }
    }
    if ($cursor -le $maximum) {
        $first = Convert-D01UnsignedBigIntegerToIpAddress `
            -Value $cursor -ByteCount $byteCount
        $last = Convert-D01UnsignedBigIntegerToIpAddress `
            -Value $maximum -ByteCount $byteCount
        $ranges.Add("$($first.ToString())-$($last.ToString())")
    }
    return $ranges.ToArray()
}

function Get-D01FirewallPortExclusionRanges {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [int[]]$AllowedPorts
    )

    [int[]]$allowed = @($AllowedPorts | Where-Object {
        $_ -ge 1 -and $_ -le 65535
    } | Sort-Object -Unique)
    if ($allowed.Count -ne @($AllowedPorts | Sort-Object -Unique).Count) {
        throw 'Allowed firewall ports are outside 1..65535'
    }
    $cursor = 1
    $ranges = [Collections.Generic.List[string]]::new()
    foreach ($port in $allowed) {
        if ($port -gt $cursor) {
            $ranges.Add($(if ($port - 1 -eq $cursor) {
                [string]$cursor
            } else { "$cursor-$($port - 1)" }))
        }
        $cursor = $port + 1
    }
    if ($cursor -le 65535) {
        $ranges.Add($(if ($cursor -eq 65535) {
            '65535'
        } else { "$cursor-65535" }))
    }
    return $ranges.ToArray()
}

function Convert-D01FirewallAddressTokenCanonical {
    param([Parameter(Mandatory = $true)][string]$Token)

    if ($Token -ceq 'Any') { return 'Any' }
    $parts = @($Token.Split('-'))
    if ($parts.Count -eq 1) {
        return Get-D01NormalizedIp -Address $parts[0]
    }
    if ($parts.Count -ne 2) {
        throw 'Firewall address token is not an IP or closed range'
    }
    return '{0}-{1}' -f
        (Get-D01NormalizedIp -Address $parts[0]),
        (Get-D01NormalizedIp -Address $parts[1])
}

function Get-D01FirewallEnforcementEnvironment {
    $services = @()
    $profiles = @()
    $errorSha256 = ''
    $collectorOk = $false
    try {
        $services = @(Get-Service -Name @('BFE', 'MpsSvc') `
            -ErrorAction Stop | ForEach-Object {
                [pscustomobject][ordered]@{
                    name = [string]$_.Name
                    status = [string]$_.Status
                }
            } | Sort-Object name)
        $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore `
            -ErrorAction Stop | ForEach-Object {
                [pscustomobject][ordered]@{
                    name = [string]$_.Name
                    enabled = [bool]$_.Enabled
                }
            } | Sort-Object name)
        $collectorOk = $true
    } catch {
        $errorSha256 = Get-LabStringSha256 -Value $_.Exception.Message
    }
    [string[]]$serviceNames = @($services | ForEach-Object {
        [string]$_.name
    })
    [string[]]$profileNames = @($profiles | ForEach-Object {
        [string]$_.name
    })
    $exact = $collectorOk -and $services.Count -eq 2 -and
        ($serviceNames -join "`n") -ceq "BFE`nMpsSvc" -and
        @($services | Where-Object {
            [string]$_.status -cne 'Running'
        }).Count -eq 0 -and $profiles.Count -eq 3 -and
        ($profileNames -join "`n") -ceq "Domain`nPrivate`nPublic" -and
        @($profiles | Where-Object { -not [bool]$_.enabled }).Count -eq 0
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.d01-firewall-enforcement-environment/v1'
        captured_at_utc = Get-LabUtcTimestamp
        collector_ok = $collectorOk
        services = $services
        profiles = $profiles
        exact = $exact
        error_sha256 = $errorSha256
    }
}

function Get-D01ProgramContainmentRuleEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$RuleName,
        [Parameter(Mandatory = $true)][string]$DisplayName,
        [ValidateSet('Inbound', 'Outbound')][string]$Direction,
        [ValidateSet('TCP', 'UDP')][string]$Protocol,
        [Parameter(Mandatory = $true)][string[]]$RemoteAddresses,
        [Parameter(Mandatory = $true)][string[]]$RemotePorts,
        [Parameter(Mandatory = $true)][string]$Program
    )

    $rules = @(Get-NetFirewallRule -Name $RuleName `
        -PolicyStore ActiveStore -ErrorAction Stop)
    $ports = @(); $addresses = @(); $applications = @(); $interfaces = @()
    $interfaceTypes = @(); $services = @(); $security = @()
    if ($rules.Count -eq 1) {
        $ports = @($rules[0] | Get-NetFirewallPortFilter -ErrorAction Stop)
        $addresses = @($rules[0] | Get-NetFirewallAddressFilter -ErrorAction Stop)
        $applications = @($rules[0] | Get-NetFirewallApplicationFilter `
            -ErrorAction Stop)
        $interfaces = @($rules[0] | Get-NetFirewallInterfaceFilter `
            -ErrorAction Stop)
        $interfaceTypes = @($rules[0] | Get-NetFirewallInterfaceTypeFilter `
            -ErrorAction Stop)
        $services = @($rules[0] | Get-NetFirewallServiceFilter -ErrorAction Stop)
        $security = @($rules[0] | Get-NetFirewallSecurityFilter `
            -ErrorAction Stop)
    }
    [string[]]$expectedAddresses = @($RemoteAddresses | ForEach-Object {
        Convert-D01FirewallAddressTokenCanonical -Token ([string]$_)
    } | Sort-Object -Unique)
    [string[]]$actualAddresses = @(
        if ($addresses.Count -eq 1) {
            $addresses[0].RemoteAddress | ForEach-Object {
                Convert-D01FirewallAddressTokenCanonical -Token ([string]$_)
            } | Sort-Object -Unique
        })
    [string[]]$expectedPorts = @($RemotePorts | ForEach-Object {
        [string]$_
    } | Sort-Object -Unique)
    [string[]]$actualPorts = @(
        if ($ports.Count -eq 1) {
            $ports[0].RemotePort | ForEach-Object { [string]$_ } |
                Sort-Object -Unique
        })
    $protocolExact = $ports.Count -eq 1 -and
        ([string]$ports[0].Protocol).ToLowerInvariant() -in @(
            $Protocol.ToLowerInvariant(),
            $(if ($Protocol -eq 'TCP') { '6' } else { '17' }))
    $programExact = $applications.Count -eq 1 -and
        [string]::Equals(
            [IO.Path]::GetFullPath([string]$applications[0].Program),
            [IO.Path]::GetFullPath($Program),
            [StringComparison]::OrdinalIgnoreCase)
    $exact = $rules.Count -eq 1 -and $ports.Count -eq 1 -and
        $addresses.Count -eq 1 -and $applications.Count -eq 1 -and
        $interfaces.Count -eq 1 -and $interfaceTypes.Count -eq 1 -and
        $services.Count -eq 1 -and $security.Count -eq 1 -and
        $protocolExact -and $programExact -and
        [string]$rules[0].Name -ceq $RuleName -and
        [string]$rules[0].DisplayName -ceq $DisplayName -and
        [string]$rules[0].Direction -eq $Direction -and
        [string]$rules[0].Action -eq 'Block' -and
        [string]$rules[0].Enabled -eq 'True' -and
        [string]$rules[0].Profile -eq 'Any' -and
        [string]$rules[0].EdgeTraversalPolicy -eq 'Block' -and
        -not [bool]$rules[0].LooseSourceMapping -and
        -not [bool]$rules[0].LocalOnlyMapping -and
        @($ports[0].LocalPort).Count -eq 1 -and
        [string]$ports[0].LocalPort -eq 'Any' -and
        ($expectedPorts -join "`n") -ceq ($actualPorts -join "`n") -and
        @($addresses[0].LocalAddress).Count -eq 1 -and
        [string]$addresses[0].LocalAddress -eq 'Any' -and
        ($expectedAddresses -join "`n") -ceq
            ($actualAddresses -join "`n") -and
        @($interfaces[0].InterfaceAlias).Count -eq 1 -and
        [string]$interfaces[0].InterfaceAlias -eq 'Any' -and
        @($interfaceTypes[0].InterfaceType).Count -eq 1 -and
        [string]$interfaceTypes[0].InterfaceType -eq 'Any' -and
        [string]$services[0].Service -eq 'Any' -and
        [string]$security[0].Authentication -eq 'NotRequired' -and
        [string]$security[0].Encryption -eq 'NotRequired' -and
        -not [bool]$security[0].OverrideBlockRules -and
        [string]$rules[0].PrimaryStatus -ceq 'OK' -and
        [UInt32]$rules[0].StatusCode -in @([UInt32]0, [UInt32]65536) -and
        @($rules[0].EnforcementStatus).Count -eq 1 -and
        [string]$rules[0].EnforcementStatus -ceq 'Full'
    $canonical = [Collections.Generic.List[string]]::new()
    foreach ($item in @($rules + $ports + $addresses + $applications +
        $interfaces + $interfaceTypes + $services + $security)) {
        $canonical.Add((Get-D01FirewallCimCanonical -Instance $item))
    }
    [string[]]$records = @($canonical.ToArray())
    [Array]::Sort($records, [StringComparer]::Ordinal)
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.d01-program-containment-rule/v1'
        rule_name = $RuleName
        display_name = $DisplayName
        direction = $Direction
        protocol = $Protocol
        remote_addresses = $expectedAddresses
        remote_ports = $expectedPorts
        program_path_sha256 = Get-LabStringSha256 -Value (
            [IO.Path]::GetFullPath($Program).ToLowerInvariant())
        canonical_sha256 = Get-LabStringSha256 -Value (
            $records -join "`n--FILTER--`n")
        primary_status = if ($rules.Count -eq 1) {
            [string]$rules[0].PrimaryStatus
        } else { '' }
        status_code = if ($rules.Count -eq 1) {
            [UInt32]$rules[0].StatusCode
        } else { [UInt32]0 }
        enforcement_status = if ($rules.Count -eq 1) {
            @($rules[0].EnforcementStatus | ForEach-Object { [string]$_ })
        } else { @() }
        exact = $exact
    }
}

function Start-D01ProgramNetworkContainment {
    param(
        [Parameter(Mandatory = $true)][string]$Nonce,
        [ValidateSet('Source', 'Coordinator')][string]$Role,
        [Parameter(Mandatory = $true)][string]$Program,
        [Parameter(Mandatory = $true)][string[]]$AllowedTcpRemoteAddresses,
        [object[]]$OutboundTcpRestrictions = @()
    )

    [string[]]$allowed = @($AllowedTcpRemoteAddresses | ForEach-Object {
        Get-D01NormalizedIp -Address ([string]$_)
    } | Sort-Object -Unique)
    $disallowed = @(
        Get-D01FirewallAddressExclusionRanges -AllowedAddresses $allowed `
            -Family IPv4
        Get-D01FirewallAddressExclusionRanges -AllowedAddresses $allowed `
            -Family IPv6
    )
    $prefix = 'ESE_V91_D01_' + $Nonce + '_' + $Role.ToUpperInvariant()
    $displayPrefix = 'eSE V91 D01 ' + $Nonce + ' ' + $Role
    $specs = [Collections.Generic.List[object]]::new()
    foreach ($direction in @('Inbound', 'Outbound')) {
        $suffix = 'TCP_' + $direction.ToUpperInvariant() + '_DENY_OTHER'
        $specs.Add([pscustomobject]@{
            name = $prefix + '_' + $suffix
            display = $displayPrefix + ' ' + $suffix
            direction = $direction
            protocol = 'TCP'
            remote_addresses = if ($Role -eq 'Source' -and
                $direction -eq 'Outbound') { @('Any') } else { $disallowed }
            remote_ports = @('Any')
            armed = $null
        })
        $suffix = 'UDP_' + $direction.ToUpperInvariant() + '_DENY_ALL'
        $specs.Add([pscustomobject]@{
            name = $prefix + '_' + $suffix
            display = $displayPrefix + ' ' + $suffix
            direction = $direction
            protocol = 'UDP'
            remote_addresses = @('Any')
            remote_ports = @('Any')
            armed = $null
        })
    }
    foreach ($restriction in @($OutboundTcpRestrictions)) {
        [string]$label = [string]$restriction.label
        if ($label -cnotmatch '^[A-Z0-9_]{1,24}$') {
            throw 'Containment restriction label is not canonical'
        }
        [string[]]$addresses = @($restriction.addresses | ForEach-Object {
            Get-D01NormalizedIp -Address ([string]$_)
        } | Sort-Object -Unique)
        [int[]]$allowedPorts = @($restriction.allowed_ports | ForEach-Object {
            [int]$_
        } | Sort-Object -Unique)
        $specs.Add([pscustomobject]@{
            name = $prefix + '_TCP_OUTBOUND_' + $label
            display = $displayPrefix + ' TCP_OUTBOUND_' + $label
            direction = 'Outbound'
            protocol = 'TCP'
            remote_addresses = $addresses
            remote_ports = @(
                Get-D01FirewallPortExclusionRanges `
                    -AllowedPorts $allowedPorts)
            armed = $null
        })
    }
    $enforcementEnvironment = Get-D01FirewallEnforcementEnvironment
    $state = [pscustomobject][ordered]@{
        schema = 'ese.v91.d01-program-network-containment/v1'
        role = $Role
        program_path_sha256 = Get-LabStringSha256 -Value (
            [IO.Path]::GetFullPath($Program).ToLowerInvariant())
        allowed_tcp_remote_addresses = $allowed
        specs = $specs.ToArray()
        created_names = @()
        armed_rule_evidence = @()
        armed_enforcement_environment = $enforcementEnvironment
        disarm_enforcement_environment = $null
        enforcement_exact_through_disarm = $false
        armed_exact = $false
        cleanup_exact = $false
        error_sha256 = ''
    }
    try {
        if (-not [bool]$enforcementEnvironment.exact) {
            throw 'Windows firewall enforcement environment is not exact'
        }
        $inventory = @(Get-NetFirewallRule -PolicyStore ActiveStore `
            -ErrorAction Stop)
        if (@($inventory | Where-Object {
            [string]$_.Name -in @($state.specs.name) -or
            [string]$_.DisplayName -in @($state.specs.display)
        }).Count -ne 0) {
            throw 'A nonce-owned containment rule already exists'
        }
        foreach ($spec in @($state.specs)) {
            New-NetFirewallRule -Name $spec.name -DisplayName $spec.display `
                -Direction $spec.direction -Action Block `
                -Protocol $spec.protocol -Program $Program `
                -LocalAddress Any -RemoteAddress $spec.remote_addresses `
                -LocalPort Any -RemotePort $spec.remote_ports -Profile Any `
                -ErrorAction Stop | Out-Null
            $state.created_names = @($state.created_names) + [string]$spec.name
            $spec.armed = Get-D01ProgramContainmentRuleEvidence `
                -RuleName $spec.name -DisplayName $spec.display `
                -Direction $spec.direction -Protocol $spec.protocol `
                -RemoteAddresses @($spec.remote_addresses) `
                -RemotePorts @($spec.remote_ports) -Program $Program
            if (-not [bool]$spec.armed.exact) {
                throw "Containment rule is not exact: $($spec.name)"
            }
        }
        $state.armed_rule_evidence = @($state.specs.armed)
        $state.armed_exact = $state.created_names.Count -eq $state.specs.Count -and
            @($state.armed_rule_evidence | Where-Object {
                -not [bool]$_.exact
            }).Count -eq 0
    } catch {
        $state.error_sha256 = Get-LabStringSha256 -Value $_.Exception.Message
    }
    return $state
}

function Remove-D01ProgramNetworkContainment {
    param(
        [Parameter(Mandatory = $true)][object]$State,
        [Parameter(Mandatory = $true)][string]$Program
    )

    try {
        $State.disarm_enforcement_environment =
            Get-D01FirewallEnforcementEnvironment
        if (-not [bool]$State.disarm_enforcement_environment.exact) {
            throw 'Firewall enforcement was not exact immediately before disarm'
        }
        $validatedNames = [Collections.Generic.List[string]]::new()
        foreach ($spec in @($State.specs)) {
            if ([string]$spec.name -notin @($State.created_names)) { continue }
            if ($null -eq $spec.armed) {
                throw "Containment rule lacks armed identity: $($spec.name)"
            }
            $current = Get-D01ProgramContainmentRuleEvidence `
                -RuleName $spec.name -DisplayName $spec.display `
                -Direction $spec.direction -Protocol $spec.protocol `
                -RemoteAddresses @($spec.remote_addresses) `
                -RemotePorts @($spec.remote_ports) -Program $Program
            if (-not [bool]$current.exact -or
                [string]$current.canonical_sha256 -cne
                    [string]$spec.armed.canonical_sha256) {
                throw "Containment rule changed; cleanup refused: $($spec.name)"
            }
            $validatedNames.Add([string]$spec.name)
        }
        $State.enforcement_exact_through_disarm =
            [bool]$State.armed_enforcement_environment.exact -and
            $validatedNames.Count -eq @($State.created_names).Count
        if (-not $State.enforcement_exact_through_disarm) {
            throw 'Containment enforcement identity changed before disarm'
        }
        foreach ($validatedName in $validatedNames) {
            Remove-NetFirewallRule -Name $validatedName `
                -PolicyStore ActiveStore -ErrorAction Stop
        }
        $inventory = @(Get-NetFirewallRule -PolicyStore ActiveStore `
            -ErrorAction Stop)
        $remaining = @($inventory | Where-Object {
            [string]$_.Name -in @($State.specs.name) -or
            [string]$_.DisplayName -in @($State.specs.display)
        })
        $State.cleanup_exact = $remaining.Count -eq 0
        if (-not $State.cleanup_exact) {
            throw 'One or more nonce-owned containment rules remain'
        }
    } catch {
        $State.cleanup_exact = $false
        $State.enforcement_exact_through_disarm = $false
        $State.error_sha256 = Get-LabStringSha256 -Value $_.Exception.Message
    }
    return $State
}

function Get-D01ProgramContainmentArmedProjection {
    param([Parameter(Mandatory = $true)][object]$State)

    $rules = @($State.armed_rule_evidence)
    [string[]]$canonicalRows = @($rules | ForEach-Object {
        '{0}|{1}' -f [string]$_.rule_name, [string]$_.canonical_sha256
    })
    [Array]::Sort($canonicalRows, [StringComparer]::Ordinal)
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.d01-program-network-containment-armed/v1'
        role = [string]$State.role
        program_path_sha256 = [string]$State.program_path_sha256
        allowed_tcp_remote_addresses = @(
            $State.allowed_tcp_remote_addresses)
        rule_count = $rules.Count
        rules = $rules
        enforcement_environment = $State.armed_enforcement_environment
        rule_set_sha256 = Get-LabStringSha256 -Value (
            $canonicalRows -join "`n")
        exact = [bool]$State.armed_exact
    }
}

function Assert-D01FirewallEnforcementEnvironmentContract {
    param(
        [Parameter(Mandatory = $true)][object]$Evidence,
        [Parameter(Mandatory = $true)][string]$Context
    )

    $null = Assert-D01ExactPropertySet -Object $Evidence -Expected @(
        'schema', 'captured_at_utc', 'collector_ok', 'services', 'profiles',
        'exact', 'error_sha256'
    ) -Context $Context
    if ([string]$Evidence.schema -cne
            'ese.v91.d01-firewall-enforcement-environment/v1') {
        throw "$Context schema is not exact"
    }
    foreach ($name in @('collector_ok', 'exact')) {
        $null = Assert-D01JsonBoolean `
            -Value $Evidence.PSObject.Properties[$name].Value `
            -Context "$Context.$name"
    }
    $null = Assert-D01JsonStringValue -Value $Evidence.captured_at_utc `
        -Context "$Context.captured_at_utc"
    $services = @($Evidence.services)
    $profiles = @($Evidence.profiles)
    if ($Evidence.services -isnot [Array] -or $services.Count -ne 2 -or
        $Evidence.profiles -isnot [Array] -or $profiles.Count -ne 3) {
        throw "$Context service/profile inventory is not exact"
    }
    foreach ($service in $services) {
        $null = Assert-D01ExactPropertySet -Object $service `
            -Expected @('name', 'status') -Context "$Context.services[]"
    }
    foreach ($profile in $profiles) {
        $null = Assert-D01ExactPropertySet -Object $profile `
            -Expected @('name', 'enabled') -Context "$Context.profiles[]"
        $null = Assert-D01JsonBoolean -Value $profile.enabled `
            -Context "$Context.profiles[].enabled"
    }
    [string[]]$serviceRows = @($services | ForEach-Object {
        '{0}|{1}' -f [string]$_.name, [string]$_.status
    } | Sort-Object)
    [string[]]$profileRows = @($profiles | ForEach-Object {
        '{0}|{1}' -f [string]$_.name, ([bool]$_.enabled).ToString()
    } | Sort-Object)
    if (-not [bool]$Evidence.collector_ok -or -not [bool]$Evidence.exact -or
        [string]$Evidence.error_sha256 -cne '' -or
        ($serviceRows -join "`n") -cne "BFE|Running`nMpsSvc|Running" -or
        ($profileRows -join "`n") -cne
            "Domain|True`nPrivate|True`nPublic|True") {
        throw "$Context does not prove effective firewall enforcement"
    }
    return $true
}

function Assert-D01ProgramContainmentArmedContract {
    param(
        [Parameter(Mandatory = $true)][object]$Evidence,
        [Parameter(Mandatory = $true)][string]$Context
    )

    $null = Assert-D01ExactPropertySet -Object $Evidence -Expected @(
        'schema', 'role', 'program_path_sha256',
        'allowed_tcp_remote_addresses', 'rule_count', 'rules',
        'enforcement_environment',
        'rule_set_sha256', 'exact'
    ) -Context $Context
    if ([string]$Evidence.schema -cne
            'ese.v91.d01-program-network-containment-armed/v1' -or
        [string]$Evidence.role -cnotin @('Source', 'Coordinator')) {
        throw "$Context identity is not exact"
    }
    foreach ($name in @('program_path_sha256', 'rule_set_sha256')) {
        $null = Assert-D01JsonStringValue `
            -Value $Evidence.PSObject.Properties[$name].Value `
            -Context "$Context.$name" -Pattern '^[0-9a-f]{64}$'
    }
    $null = Assert-D01JsonBoolean -Value $Evidence.exact `
        -Context "$Context.exact"
    $null = Assert-D01FirewallEnforcementEnvironmentContract `
        -Evidence $Evidence.enforcement_environment `
        -Context "$Context.enforcement_environment"
    $null = Assert-D01JsonStringArray `
        -Value $Evidence.allowed_tcp_remote_addresses `
        -Context "$Context.allowed_tcp_remote_addresses" -RequireUnique
    [string[]]$allowed = @(
        $Evidence.allowed_tcp_remote_addresses | ForEach-Object {
            Get-D01NormalizedIp -Address ([string]$_)
        } | Sort-Object -Unique)
    if ($allowed.Count -eq 0 -or
        ($allowed -join "`n") -cne
            (@($Evidence.allowed_tcp_remote_addresses) -join "`n")) {
        throw "$Context allowed TCP address set is not canonical"
    }
    $ruleCount = Assert-D01JsonInteger -Value $Evidence.rule_count `
        -Context "$Context.rule_count" -Minimum 4 -Maximum 16
    if ($Evidence.rules -isnot [Array] -or
        @($Evidence.rules).Count -ne $ruleCount) {
        throw "$Context rule collection count is not exact"
    }
    $seenNames = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal)
    $canonicalRows = [Collections.Generic.List[string]]::new()
    foreach ($rule in @($Evidence.rules)) {
        $null = Assert-D01ExactPropertySet -Object $rule -Expected @(
            'schema', 'rule_name', 'display_name', 'direction', 'protocol',
            'remote_addresses', 'remote_ports', 'program_path_sha256',
            'canonical_sha256', 'primary_status', 'status_code',
            'enforcement_status', 'exact'
        ) -Context "$Context.rules[]"
        if ([string]$rule.schema -cne
                'ese.v91.d01-program-containment-rule/v1' -or
            [string]$rule.rule_name -cnotmatch
                '^ESE_V91_D01_[0-9a-f]{32}_(SOURCE|COORDINATOR)_[A-Z0-9_]+$' -or
            [string]$rule.direction -cnotin @('Inbound', 'Outbound') -or
            [string]$rule.protocol -cnotin @('TCP', 'UDP') -or
            [string]$rule.program_path_sha256 -cne
                [string]$Evidence.program_path_sha256 -or
            [string]$rule.canonical_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            [string]$rule.primary_status -cne 'OK' -or
            [UInt32]$rule.status_code -notin @([UInt32]0, [UInt32]65536) -or
            @($rule.enforcement_status).Count -ne 1 -or
            [string]$rule.enforcement_status -cne 'Full' -or
            -not ($rule.exact -is [bool]) -or -not [bool]$rule.exact -or
            -not $seenNames.Add([string]$rule.rule_name)) {
            throw "$Context contains an invalid or duplicate rule"
        }
        foreach ($field in @('display_name', 'rule_name')) {
            $null = Assert-D01JsonStringValue `
                -Value $rule.PSObject.Properties[$field].Value `
                -Context "$Context.rules[].$field"
        }
        foreach ($field in @('remote_addresses', 'remote_ports')) {
            $null = Assert-D01JsonStringArray `
                -Value $rule.PSObject.Properties[$field].Value `
                -Context "$Context.rules[].$field" -RequireUnique
        }
        $canonicalRows.Add(('{0}|{1}' -f
            [string]$rule.rule_name, [string]$rule.canonical_sha256))
    }
    [string[]]$rows = @($canonicalRows.ToArray())
    [Array]::Sort($rows, [StringComparer]::Ordinal)
    if (-not [bool]$Evidence.exact -or
        (Get-LabStringSha256 -Value ($rows -join "`n")) -cne
            [string]$Evidence.rule_set_sha256) {
        throw "$Context aggregate identity is not exact"
    }
    return $true
}

function Get-D01FirewallRuleEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$RuleName,
        [Parameter(Mandatory = $true)][string]$DisplayName,
        [ValidateSet('Allow', 'Block')]
        [Parameter(Mandatory = $true)][string]$ExpectedAction,
        [Parameter(Mandatory = $true)][string]$ExpectedLocalAddress,
        [Parameter(Mandatory = $true)][string[]]$ExpectedRemoteAddress,
        [Parameter(Mandatory = $true)][int]$ExpectedLocalPort,
        [Parameter(Mandatory = $true)][string]$ExpectedRemotePort,
        [Parameter(Mandatory = $true)][string]$ExpectedProgram,
        [Parameter(Mandatory = $true)][string]$ExpectedProfile
    )

    $rules = @(Get-NetFirewallRule -Name $RuleName `
        -PolicyStore ActiveStore -ErrorAction Stop)
    $ports = @()
    $addresses = @()
    $applications = @()
    $interfaces = @()
    $interfaceTypes = @()
    $services = @()
    $security = @()
    if ($rules.Count -eq 1) {
        $ports = @($rules[0] | Get-NetFirewallPortFilter -ErrorAction Stop)
        $addresses = @($rules[0] | Get-NetFirewallAddressFilter `
            -ErrorAction Stop)
        $applications = @($rules[0] | Get-NetFirewallApplicationFilter `
            -ErrorAction Stop)
        $interfaces = @($rules[0] | Get-NetFirewallInterfaceFilter `
            -ErrorAction Stop)
        $interfaceTypes = @($rules[0] | Get-NetFirewallInterfaceTypeFilter `
            -ErrorAction Stop)
        $services = @($rules[0] | Get-NetFirewallServiceFilter `
            -ErrorAction Stop)
        $security = @($rules[0] | Get-NetFirewallSecurityFilter `
            -ErrorAction Stop)
    }
    $localAddresses = @(
        if ($addresses.Count -eq 1) {
            $addresses[0].LocalAddress |
                ForEach-Object { [string]$_ }
        }
    )
    $remoteAddresses = @(
        if ($addresses.Count -eq 1) {
            $addresses[0].RemoteAddress |
                ForEach-Object { [string]$_ }
        }
    )
    [string[]]$expectedRemoteAddresses = @($ExpectedRemoteAddress |
        ForEach-Object { Get-D01NormalizedIp -Address ([string]$_) } |
        Select-Object -Unique)
    [string[]]$actualRemoteAddresses = @($remoteAddresses |
        ForEach-Object { Get-D01NormalizedIp -Address ([string]$_) } |
        Select-Object -Unique)
    [Array]::Sort($expectedRemoteAddresses, [StringComparer]::Ordinal)
    [Array]::Sort($actualRemoteAddresses, [StringComparer]::Ordinal)
    $remoteAddressesMatch =
        $expectedRemoteAddresses.Count -gt 0 -and
        $actualRemoteAddresses.Count -eq
            $expectedRemoteAddresses.Count -and
        ($expectedRemoteAddresses -join "`n") -ceq
            ($actualRemoteAddresses -join "`n")
    $programMatches = if ($ExpectedProgram -eq 'Any') {
        $applications.Count -eq 1 -and
        [string]$applications[0].Program -eq 'Any'
    } else {
        $applications.Count -eq 1 -and
        [string]::Equals(
            [IO.Path]::GetFullPath([string]$applications[0].Program),
            [IO.Path]::GetFullPath($ExpectedProgram),
            [StringComparison]::OrdinalIgnoreCase)
    }
    $exact = $rules.Count -eq 1 -and $ports.Count -eq 1 -and
        $addresses.Count -eq 1 -and $applications.Count -eq 1 -and
        $interfaces.Count -eq 1 -and $interfaceTypes.Count -eq 1 -and
        $services.Count -eq 1 -and $security.Count -eq 1 -and
        $programMatches -and
        [string]$rules[0].Name -ceq $RuleName -and
        [string]$rules[0].DisplayName -ceq $DisplayName -and
        [string]$rules[0].Direction -eq 'Inbound' -and
        [string]$rules[0].Action -eq $ExpectedAction -and
        [string]$rules[0].Enabled -eq 'True' -and
        [string]$rules[0].Profile -eq $ExpectedProfile -and
        ([string]$rules[0].EdgeTraversalPolicy) -eq 'Block' -and
        -not [bool]$rules[0].LooseSourceMapping -and
        -not [bool]$rules[0].LocalOnlyMapping -and
        ([string]$ports[0].Protocol).ToLowerInvariant() -in @('6', 'tcp') -and
        [string]$ports[0].LocalPort -eq [string]$ExpectedLocalPort -and
        [string]$ports[0].RemotePort -eq $ExpectedRemotePort -and
        $localAddresses.Count -eq 1 -and
        (Get-D01NormalizedIp -Address $localAddresses[0]) -ceq
            (Get-D01NormalizedIp -Address $ExpectedLocalAddress) -and
        $remoteAddressesMatch -and
        @($interfaces[0].InterfaceAlias).Count -eq 1 -and
        [string]$interfaces[0].InterfaceAlias -eq 'Any' -and
        @($interfaceTypes[0].InterfaceType).Count -eq 1 -and
        [string]$interfaceTypes[0].InterfaceType -eq 'Any' -and
        [string]$services[0].Service -eq 'Any' -and
        [string]$security[0].Authentication -eq 'NotRequired' -and
        [string]$security[0].Encryption -eq 'NotRequired' -and
        -not [bool]$security[0].OverrideBlockRules
    $canonicalParts = [Collections.Generic.List[string]]::new()
    foreach ($item in @($rules + $ports + $addresses + $applications +
        $interfaces + $interfaceTypes + $services + $security)) {
        $canonicalParts.Add((Get-D01FirewallCimCanonical -Instance $item))
    }
    [string[]]$canonicalRecords = @($canonicalParts.ToArray())
    [Array]::Sort($canonicalRecords, [StringComparer]::Ordinal)
    $canonicalHash = Get-LabStringSha256 -Value (
        $canonicalRecords -join "`n--FILTER--`n")
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.d01-firewall-rule-evidence/v2'
        captured_at_utc = Get-LabUtcTimestamp
        rule_name = $RuleName
        display_name = $DisplayName
        rule_count = $rules.Count
        action = if ($rules.Count -eq 1) {
            [string]$rules[0].Action
        } else { '' }
        direction = if ($rules.Count -eq 1) {
            [string]$rules[0].Direction
        } else { '' }
        enabled = $rules.Count -eq 1 -and
            [string]$rules[0].Enabled -eq 'True'
        profile = if ($rules.Count -eq 1) {
            [string]$rules[0].Profile
        } else { '' }
        protocol = if ($ports.Count -eq 1) {
            [string]$ports[0].Protocol
        } else { '' }
        local_port = if ($ports.Count -eq 1) {
            [string]$ports[0].LocalPort
        } else { '' }
        remote_port = if ($ports.Count -eq 1) {
            [string]$ports[0].RemotePort
        } else { '' }
        local_addresses = $localAddresses
        remote_addresses = $remoteAddresses
        program = if ($applications.Count -eq 1) {
            [string]$applications[0].Program
        } else { '' }
        interface_alias = if ($interfaces.Count -eq 1) {
            @($interfaces[0].InterfaceAlias)
        } else { @() }
        interface_type = if ($interfaceTypes.Count -eq 1) {
            @($interfaceTypes[0].InterfaceType)
        } else { @() }
        service = if ($services.Count -eq 1) {
            [string]$services[0].Service
        } else { '' }
        authentication = if ($security.Count -eq 1) {
            [string]$security[0].Authentication
        } else { '' }
        encryption = if ($security.Count -eq 1) {
            [string]$security[0].Encryption
        } else { '' }
        canonical_sha256 = $canonicalHash
        exact = $exact
    }
}

function Assert-D01OutputLocation {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][string]$CandidateRoot
    )

    $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $packagePrefix = [IO.Path]::GetFullPath($CandidateRoot).TrimEnd('\') + '\'
    if (($full + '\').StartsWith(
        $packagePrefix, [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "$Label must not be inside the candidate package"
    }
    return $full
}

function Assert-D01DisjointOperationalPaths {
    param(
        [Parameter(Mandatory = $true)][string]$PackageDirectory,
        [Parameter(Mandatory = $true)][string]$PackageZip,
        [Parameter(Mandatory = $true)][string]$OutputDirectory,
        [Parameter(Mandatory = $true)][string]$CoordinationDirectory
    )
    $entries = @(
        [pscustomobject]@{ name = 'package'; path =
            (Assert-D01NoReparsePath -Path $PackageDirectory -Kind Directory); directory = $true },
        [pscustomobject]@{ name = 'package_zip'; path =
            (Assert-D01NoReparsePath -Path $PackageZip -Kind File); directory = $false },
        [pscustomobject]@{ name = 'output'; path =
            (Assert-D01SafeCreationPath -Path $OutputDirectory); directory = $true },
        [pscustomobject]@{ name = 'coordination'; path =
            (Assert-D01SafeCreationPath -Path $CoordinationDirectory); directory = $true }
    )
    foreach ($entry in $entries) {
        $entry.path = [IO.Path]::GetFullPath([string]$entry.path).TrimEnd('\')
    }
    for ($leftIndex = 0; $leftIndex -lt $entries.Count; $leftIndex++) {
        for ($rightIndex = $leftIndex + 1;
            $rightIndex -lt $entries.Count; $rightIndex++) {
            $left = $entries[$leftIndex]
            $right = $entries[$rightIndex]
            $equal = [string]::Equals($left.path, $right.path,
                [StringComparison]::OrdinalIgnoreCase)
            $leftContainsRight = [bool]$left.directory -and
                ([string]$right.path).StartsWith(
                    ([string]$left.path) + '\',
                    [StringComparison]::OrdinalIgnoreCase)
            $rightContainsLeft = [bool]$right.directory -and
                ([string]$left.path).StartsWith(
                    ([string]$right.path) + '\',
                    [StringComparison]::OrdinalIgnoreCase)
            if ($equal -or $leftContainsRight -or $rightContainsLeft) {
                throw "D01 operational roots overlap: $($left.name)/$($right.name)"
            }
        }
    }
    return $true
}

function Enter-D01CampaignLocks {
    param(
        [Parameter(Mandatory = $true)][string[]]$Roots,
        [Parameter(Mandatory = $true)][int[]]$Ports,
        [switch]$IncludePktmon
    )
    [string[]]$lockKeys = @(
        'host-global|account-registry-firewall') + @($Roots | ForEach-Object {
        'root|' + [IO.Path]::GetFullPath($_).ToLowerInvariant()
    }) + @($Ports | ForEach-Object { 'port|' + [string][int]$_ })
    if ($IncludePktmon) {
        $lockKeys += 'host-global|pktmon-etw-and-filter-inventory'
    }
    [Array]::Sort($lockKeys, [StringComparer]::Ordinal)
    foreach ($key in $lockKeys) {
        $name = 'Global\ESE_V91_D01_' + (Get-LabStringSha256 -Value $key)
        $createdNew = $false
        $mutex = [Threading.Mutex]::new($false, $name, [ref]$createdNew)
        try {
            if (-not $mutex.WaitOne(0)) {
                throw "D01 campaign resource is already locked: $key"
            }
            $script:d01CandidateLocks.Add($mutex)
        } catch {
            $mutex.Dispose()
            throw
        }
    }
    return $true
}

function Test-D01PortsFree {
    param([Parameter(Mandatory = $true)][int[]]$Ports)

    $tcp = @(Get-NetTCPConnection -ErrorAction Stop)
    $udp = @(Get-NetUDPEndpoint -ErrorAction Stop)
    foreach ($port in @($Ports | Select-Object -Unique)) {
        if (@($tcp | Where-Object { [int]$_.LocalPort -eq $port }).Count) {
            throw "TCP port $port is already owned"
        }
        if (@($udp | Where-Object { [int]$_.LocalPort -eq $port }).Count) {
            throw "UDP port $port is already owned"
        }
    }
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.d01-port-baseline/v1'
        collector_ok = $true
        checked_ports = @($Ports | Select-Object -Unique)
        all_free = $true
    }
}

function Get-D01Md5Text {
    param([Parameter(Mandatory = $true)][string]$Value)

    $md5 = [Security.Cryptography.MD5]::Create()
    try {
        return ([BitConverter]::ToString(
            $md5.ComputeHash([Text.Encoding]::Unicode.GetBytes($Value))
        )).Replace('-', '')
    } finally {
        $md5.Dispose()
    }
}

function Assert-D01SafetyPreferenceContract {
    param([Parameter(Mandatory = $true)][string]$Path)

    $required = @(
        'OpenPortsOnStartUp', 'AutoStart', 'AutoTakeED2KLinks',
        'WatchClipboard4ED2kFilelinks'
    )
    $values = New-Object `
        'Collections.Generic.Dictionary[string,object]' `
        ([StringComparer]::OrdinalIgnoreCase)
    foreach ($name in $required) {
        $values.Add($name, [System.Collections.Generic.List[string]]::new())
    }
    $section = ''
    $emuleSectionCount = 0
    foreach ($lineValue in @(
        Get-Content -LiteralPath $Path -ErrorAction Stop
    )) {
        $line = [string]$lineValue
        if ($line -match '^\s*\[(?<section>[^\]]+)\]\s*$') {
            $section = [string]$Matches.section
            if ([string]$section -ieq 'eMule') { $emuleSectionCount++ }
            continue
        }
        if ([string]$section -ine 'eMule' -or
            $line -notmatch '^\s*(?<key>[^;#][^=]*?)\s*=\s*(?<value>.*?)\s*$') {
            continue
        }
        $key = ([string]$Matches.key).Trim()
        if ($values.ContainsKey($key)) {
            $values[$key].Add([string]$Matches.value)
        }
    }
    if ($emuleSectionCount -ne 1) {
        throw 'Preference section [eMule] must occur exactly once'
    }
    foreach ($name in $required) {
        if ($values[$name].Count -ne 1 -or
            -not [StringComparer]::Ordinal.Equals(
                [string]$values[$name][0], '0')) {
            throw "Preference [eMule] $name must occur once with value 0"
        }
    }
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.d01-safety-preferences/v1'
        exact = $true
        section = 'eMule'
        required_keys = $required
        required_value = '0'
    }
}

function Set-D01IsolatedPreferences {
    param(
        [Parameter(Mandatory = $true)][string]$NodePath,
        [Parameter(Mandatory = $true)][int]$IPv6Mode,
        [AllowEmptyString()][string]$IPv6BindAddress = '',
        [Parameter(Mandatory = $true)][int]$WebPort,
        [Parameter(Mandatory = $true)][int]$TcpPort,
        [Parameter(Mandatory = $true)][int]$UdpPort,
        [Parameter(Mandatory = $true)][string]$IncomingPath,
        [Parameter(Mandatory = $true)][string]$TempPath,
        [switch]$SourceProfile
    )

    $config = Join-Path $NodePath 'config'
    $preferences = Join-Path $config 'preferences.ini'
    foreach ($identityName in @(
        'preferences.dat', 'cryptkey.dat', 'clients.met'
    )) {
        $identityPath = Join-Path $config $identityName
        if (Test-Path -LiteralPath $identityPath -PathType Leaf) {
            Remove-Item -LiteralPath $identityPath -Force -ErrorAction Stop
        }
    }
    foreach ($entry in ([ordered]@{
        Port = [string]$TcpPort
        UDPPort = [string]$UdpPort
        Autoconnect = '0'
        OpenPortsOnStartUp = '0'
        AutoStart = '0'
        AutoTakeED2KLinks = '0'
        WatchClipboard4ED2kFilelinks = '0'
        NetworkKademlia = '0'
        AutoConnectStaticOnly = '1'
        Reconnect = '0'
        Serverlist = '0'
        UpdateNotifyTestClient = '0'
        AddServersFromServer = '0'
        AddServersFromClient = '0'
        FilterBadIPs = '0'
        FilterServersByIP = '0'
        VerboseOptions = '1'
        Verbose = '1'
        SaveLogToDisk = '1'
        SaveDebugToDisk = '1'
        DebugClientTCP = '1'
        ConfirmExit = '0'
        IncomingDir = ($IncomingPath + '\')
        TempDir = ($TempPath + '\')
    }).GetEnumerator()) {
        Set-LabIniValue -Path $preferences -Section 'eMule' `
            -Key $entry.Key -Value $entry.Value
    }
    if ($SourceProfile) {
        foreach ($entry in ([ordered]@{
            MaxUpload = '512'
            UploadCapacityNew = '1024'
            MinUpload = '1'
            USSEnabled = '0'
        }).GetEnumerator()) {
            Set-LabIniValue -Path $preferences -Section 'eMule' `
                -Key $entry.Key -Value $entry.Value
        }
    }
    foreach ($entry in ([ordered]@{
        IPv6Mode = [string]$IPv6Mode
        IPv6BindAddr = $IPv6BindAddress
        KadNetworkMask = '0'
        NetworkED2K = '0'
        CryptLayerRequested = '0'
        CryptLayerRequired = '0'
        CryptLayerSupported = '0'
    }).GetEnumerator()) {
        Set-LabIniValue -Path $preferences -Section 'Connection' `
            -Key $entry.Key -Value $entry.Value
    }
    foreach ($entry in ([ordered]@{
        EseNetLabConsent = '0'
        EseNetLabAdvancedConsent = '0'
        EseNetLabContributionConsent = '0'
        EseNetLabEnabled = '0'
        EseV9Experimental = '0'
        EnableUtpHolePunch = '0'
        EseAutoKeepalive = '0'
        EseKad3Rendezvous = '0'
        EseReachSelector = '0'
        EseHolePunchPortPredict = '0'
        EseEd2kPunch3 = '0'
        EseRelayAccept = '0'
        EseRelayEgress = '0'
        Kad6BetaExitOptIn = '0'
    }).GetEnumerator()) {
        Set-LabIniValue -Path $preferences -Section 'eSE' `
            -Key $entry.Key -Value $entry.Value
    }
    Set-LabIniValue -Path $preferences -Section 'Proxy' `
        -Key 'ProxyEnableProxy' -Value '0'
    Set-LabIniValue -Path $preferences -Section 'UPnP' `
        -Key 'EnableUPnP' -Value '0'
    foreach ($entry in ([ordered]@{
        Enabled = '1'
        Port = [string]$WebPort
        Password = Get-D01Md5Text -Value $webPassword
        AllowedIPs = '127.0.0.1'
        WebUseUPnP = '0'
    }).GetEnumerator()) {
        Set-LabIniValue -Path $preferences -Section 'WebServer' `
            -Key $entry.Key -Value $entry.Value
    }
    Set-LabIniValue -Path $preferences -Section 'KRPRelay' `
        -Key 'KrpRelayEnabled' -Value '0'
    Set-LabIniValue -Path $preferences -Section 'KRPRelay' `
        -Key 'KrpRelayKillSwitch' -Value '1'

    foreach ($name in @(
        'server.met', 'server_met.old', 'server_met.download',
        'server_met.old.bak', 'staticservers.dat', 'nodes.dat',
        'nodes_v6.dat', 'bootstrap.dat'
    )) {
        $path = Join-Path $config $name
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            Remove-Item -LiteralPath $path -Force -ErrorAction Stop
        }
    }
    [IO.File]::WriteAllText(
        (Join-Path $config 'shareddir.dat'), '',
        (New-Object Text.UTF8Encoding($false))
    )
    foreach ($runtimeLog in @(
        Get-ChildItem -LiteralPath $NodePath -Recurse -File -Filter '*.log' `
            -ErrorAction Stop
    )) {
        Remove-Item -LiteralPath $runtimeLog.FullName -Force `
            -ErrorAction Stop
    }
    $safetyContract = Assert-D01SafetyPreferenceContract `
        -Path $preferences
    return [pscustomobject][ordered]@{
        preferences_path = $preferences
        preferences_sha256 = Get-LabSha256 -Path $preferences
        ipv6_mode = $IPv6Mode
        ipv6_bind_address = $IPv6BindAddress
        network_ed2k = $false
        network_kad = $false
        proxy_enabled = $false
        web_allowed_ips = @('127.0.0.1')
        inherited_server_and_kad_files_removed = $true
        fresh_identity = $true
        safety_preferences = $safetyContract
    }
}

function Enable-D01ControlledEd2kProfile {
    param(
        [Parameter(Mandatory = $true)][string]$NodePath,
        [Parameter(Mandatory = $true)][string]$ServerAddress,
        [Parameter(Mandatory = $true)][int]$ServerPort,
        [Parameter(Mandatory = $true)][string]$Nonce
    )

    $preferences = Join-Path $NodePath 'config\preferences.ini'
    foreach ($entry in ([ordered]@{
        Autoconnect = '1'
        NetworkKademlia = '0'
        AutoConnectStaticOnly = '1'
        Reconnect = '1'
        Serverlist = '0'
        UpdateNotifyTestClient = '0'
        AddServersFromServer = '0'
        AddServersFromClient = '0'
        FilterBadIPs = '0'
        FilterServersByIP = '0'
        ServerKeepAliveTimeout = '60000'
    }).GetEnumerator()) {
        Set-LabIniValue -Path $preferences -Section 'eMule' `
            -Key $entry.Key -Value $entry.Value
    }
    foreach ($entry in ([ordered]@{
        NetworkED2K = '1'
        CryptLayerRequested = '0'
        CryptLayerRequired = '0'
        CryptLayerSupported = '0'
    }).GetEnumerator()) {
        Set-LabIniValue -Path $preferences -Section 'Connection' `
            -Key $entry.Key -Value $entry.Value
    }
    $static = Join-Path $NodePath 'config\staticservers.dat'
    $line = '{0}:{1},0,eSE-D01-{2}' -f $ServerAddress, $ServerPort, $Nonce
    [IO.File]::WriteAllText(
        $static, ($line + "`r`n"),
        (New-Object Text.UnicodeEncoding($false, $true))
    )
    return [pscustomobject][ordered]@{
        endpoint = "$ServerAddress`:$ServerPort"
        endpoint_scope = 'same-host assigned physical IPv4'
        staticservers_sha256 = Get-LabSha256 -Path $static
        preferences_sha256 = Get-LabSha256 -Path $preferences
        network_ed2k = $true
        network_kad = $false
        auto_connect_static_only = $true
        third_party_server_files_removed = $true
    }
}

function Get-D01WebEndpointOwnershipEvidence {
    param(
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][string]$ExpectedPath
    )
    try {
        $bindingExact = Test-D01OwnedProcessBinding `
            -Process $Process -ExpectedPath $ExpectedPath
        $listeners = @(Get-NetTCPConnection -State Listen `
            -LocalPort $Port -ErrorAction Stop)
        $ownerIds = @($listeners | ForEach-Object {
            [int]$_.OwningProcess
        } | Select-Object -Unique)
        $loopbackOnly = $listeners.Count -gt 0 -and @($listeners | Where-Object {
            (Get-D01NormalizedIp -Address ([string]$_.LocalAddress)) -notin
                @('127.0.0.1', '::1')
        }).Count -eq 0
        $exact = $bindingExact -and $loopbackOnly -and
            $ownerIds.Count -eq 1 -and [int]$ownerIds[0] -eq $Process.Id
        return [pscustomobject][ordered]@{
            schema = 'ese.v91.d01-web-endpoint-ownership/v1'
            collector_ok = $true
            port = $Port
            candidate_process_id = [int]$Process.Id
            listener_count = $listeners.Count
            owner_process_ids = $ownerIds
            loopback_only = $loopbackOnly
            process_binding_exact = $bindingExact
            endpoint_bound_to_candidate = $exact
            candidate_ownership_id_sha256 = if (
                $Process.PSObject.Properties.Name -contains
                    'd01_ownership_id_sha256') {
                [string]$Process.d01_ownership_id_sha256
            } else { '' }
            error_sha256 = ''
        }
    } catch {
        return [pscustomobject][ordered]@{
            schema = 'ese.v91.d01-web-endpoint-ownership/v1'
            collector_ok = $false
            port = $Port
            candidate_process_id = [int]$Process.Id
            listener_count = 0
            owner_process_ids = @()
            loopback_only = $false
            process_binding_exact = $false
            endpoint_bound_to_candidate = $false
            candidate_ownership_id_sha256 = ''
            error_sha256 = Get-LabStringSha256 -Value $_.Exception.Message
        }
    }
}

function Wait-D01Api {
    param(
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][string]$ExpectedPath
    )

    $deadline = [DateTime]::UtcNow.AddSeconds(90)
    do {
        $Process.Refresh()
        if ($Process.HasExited) {
            throw "eMule exited before API startup (exit $($Process.ExitCode))"
        }
        try {
            $ownership = Get-D01WebEndpointOwnershipEvidence `
                -Port $Port -Process $Process -ExpectedPath $ExpectedPath
            if (-not $ownership.collector_ok) {
                throw 'Endpoint ownership collector failed'
            }
            if ($ownership.endpoint_bound_to_candidate) {
                return Invoke-RestMethod `
                    -Uri "http://127.0.0.1:$Port/api/status" -TimeoutSec 2
            }
        } catch {}
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "API on localhost port $Port did not become ready"
}

function Wait-D01Listener {
    param(
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [switch]$RequireIPv4Only
    )

    $deadline = [DateTime]::UtcNow.AddSeconds(90)
    do {
        $Process.Refresh()
        if ($Process.HasExited) {
            throw "eMule exited before listener $Port became ready"
        }
        $listeners = @(Get-NetTCPConnection -State Listen -LocalPort $Port `
            -ErrorAction Stop)
        if (@($listeners | Where-Object {
            [int]$_.OwningProcess -ne $Process.Id
        }).Count -ne 0) {
            throw "Foreign listener owns configured port $Port"
        }
        if ($listeners.Count -gt 0) {
            $v6Listeners = @($listeners | Where-Object {
                (Get-D01NormalizedIp -Address ([string]$_.LocalAddress)).
                    Contains(':')
            })
            if (-not $RequireIPv4Only -or $v6Listeners.Count -eq 0) {
                return [pscustomobject][ordered]@{
                    process_id = $Process.Id
                    ipv4_only = $v6Listeners.Count -eq 0
                    listeners = @(
                        $listeners | ForEach-Object {
                            [pscustomobject][ordered]@{
                                local_address = Get-D01NormalizedIp `
                                    -Address ([string]$_.LocalAddress)
                                local_port = [int]$_.LocalPort
                                owning_process = [int]$_.OwningProcess
                            }
                        }
                    )
                }
            }
        }
        Start-Sleep -Milliseconds 200
    } while ([DateTime]::UtcNow -lt $deadline)
    if ($RequireIPv4Only) {
        throw "An IPv4-only PID-owned listener on port $Port did not become ready"
    }
    throw "PID-owned listener on port $Port did not become ready"
}

function Get-D01ApiIsolationAssessment {
    param(
        [AllowNull()][object]$Data,
        [switch]$AllowControlledEd2k
    )

    if ($null -eq $Data) {
        return [pscustomobject][ordered]@{
            contract_valid = $false
            isolation_valid = $false
            contamination_proven = $false
        }
    }
    $names = @($Data.PSObject.Properties.Name)
    $contractValid = $true
    foreach ($name in @('ed2k_connected', 'netlab_enabled')) {
        if ($names -notcontains $name -or $Data.$name -isnot [bool]) {
            $contractValid = $false
        }
    }
    if ($names -notcontains 'netlab_consent' -or
        $Data.netlab_consent -isnot [string] -or
        $names -notcontains 'kad_running_mask' -or
        ($Data.kad_running_mask -isnot [int] -and
            $Data.kad_running_mask -isnot [Int64])) {
        $contractValid = $false
    }
    if (-not $contractValid) {
        return [pscustomobject][ordered]@{
            contract_valid = $false
            isolation_valid = $false
            contamination_proven = $false
        }
    }
    $ed2kValid = if ($AllowControlledEd2k) {
        [bool]$Data.ed2k_connected
    } else {
        -not [bool]$Data.ed2k_connected
    }
    $isolationValid =
        -not [bool]$Data.netlab_enabled -and
        [string]$Data.netlab_consent -eq 'declined' -and
        [int]$Data.kad_running_mask -eq 0 -and $ed2kValid
    $forbiddenEd2k = if ($AllowControlledEd2k) {
        $false
    } else { [bool]$Data.ed2k_connected }
    return [pscustomobject][ordered]@{
        contract_valid = $true
        isolation_valid = $isolationValid
        contamination_proven =
            [bool]$Data.netlab_enabled -or
            [string]$Data.netlab_consent -ne 'declined' -or
            [int]$Data.kad_running_mask -ne 0 -or $forbiddenEd2k
    }
}

function Test-D01ApiIsolation {
    param(
        [AllowNull()][object]$Data,
        [switch]$AllowControlledEd2k
    )
    return [bool](Get-D01ApiIsolationAssessment -Data $Data `
        -AllowControlledEd2k:$AllowControlledEd2k).isolation_valid
}

function Get-D01ApiProbe {
    param(
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][string]$ExpectedPath,
        [switch]$AllowControlledEd2k
    )

    $watch = [Diagnostics.Stopwatch]::StartNew()
    $data = $null
    $errorText = $null
    $ownershipBefore = Get-D01WebEndpointOwnershipEvidence `
        -Port $Port -Process $Process -ExpectedPath $ExpectedPath
    $ownershipAfter = $null
    try {
        if (-not $ownershipBefore.collector_ok -or
            -not $ownershipBefore.endpoint_bound_to_candidate) {
            throw 'Local API endpoint is not uniquely candidate-owned'
        }
        $data = Invoke-RestMethod `
            -Uri "http://127.0.0.1:$Port/api/status" -TimeoutSec 2
        $ownershipAfter = Get-D01WebEndpointOwnershipEvidence `
            -Port $Port -Process $Process -ExpectedPath $ExpectedPath
        if (-not $ownershipAfter.collector_ok -or
            -not $ownershipAfter.endpoint_bound_to_candidate -or
            [string]$ownershipAfter.candidate_ownership_id_sha256 -cne
                [string]$ownershipBefore.candidate_ownership_id_sha256) {
            throw 'Local API endpoint ownership changed across the request'
        }
    } catch {
        $errorText = $_.Exception.Message
    } finally {
        if ($null -eq $ownershipAfter) {
            $ownershipAfter = Get-D01WebEndpointOwnershipEvidence `
                -Port $Port -Process $Process -ExpectedPath $ExpectedPath
        }
        $watch.Stop()
    }
    $ownershipStable = $ownershipBefore.collector_ok -and
        $ownershipAfter.collector_ok -and
        $ownershipBefore.endpoint_bound_to_candidate -and
        $ownershipAfter.endpoint_bound_to_candidate -and
        [string]$ownershipBefore.candidate_ownership_id_sha256 -cne '' -and
        [string]$ownershipBefore.candidate_ownership_id_sha256 -ceq
            [string]$ownershipAfter.candidate_ownership_id_sha256
    $isolationAssessment = Get-D01ApiIsolationAssessment -Data $data `
        -AllowControlledEd2k:$AllowControlledEd2k
    return [pscustomobject][ordered]@{
        captured_at_utc = Get-LabUtcTimestamp
        available = $null -ne $data -and $ownershipStable
        duration_ms = [Int64]$watch.ElapsedMilliseconds
        contract_valid = [bool]$isolationAssessment.contract_valid
        isolation_valid = $ownershipStable -and
            [bool]$isolationAssessment.isolation_valid
        contamination_proven = $ownershipStable -and
            [bool]$isolationAssessment.contamination_proven
        endpoint_ownership = $ownershipAfter
        endpoint_ownership_before = $ownershipBefore
        endpoint_ownership_after = $ownershipAfter
        ownership_stable_across_request = $ownershipStable
        error_sha256 = if ($errorText) {
            Get-LabStringSha256 -Value $errorText
        } else { '' }
        data = $data
    }
}

function Initialize-D01UiProbe {
    if ('V91D01UiProbeV2' -as [type]) { return }
    Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class V91D01UiProbeV2 {
    [DllImport("user32.dll", SetLastError=true)]
    public static extern IntPtr SendMessageTimeout(
        IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam,
        uint flags, uint timeout, out IntPtr result);
    [DllImport("kernel32.dll")]
    public static extern void SetLastError(uint errorCode);
}
'@
}

function Get-D01UiProbe {
    param([Parameter(Mandatory = $true)][Diagnostics.Process]$Process)

    Initialize-D01UiProbe
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $present = $false
    $responsive = $false
    $collectorOk = $false
    $sourceBound = $false
    $timeoutProven = $false
    $errorCode = 0
    $errorText = ''
    try {
        $bindingBefore = Test-D01OwnedProcessBinding -Process $Process `
            -ExpectedPath ([string]$Process.Path)
        $Process.Refresh()
        if (-not $Process.HasExited -and
            $Process.MainWindowHandle -ne [IntPtr]::Zero) {
            $present = $true
            $windowHandle = $Process.MainWindowHandle
            $result = [IntPtr]::Zero
            [V91D01UiProbeV2]::SetLastError(0)
            $sent = [V91D01UiProbeV2]::SendMessageTimeout(
                $windowHandle, 0x0000,
                [IntPtr]::Zero, [IntPtr]::Zero,
                2, 500, [ref]$result
            )
            $responsive = $sent -ne [IntPtr]::Zero
            if (-not $responsive) {
                $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                $timeoutProven = $errorCode -eq 1460
            }
        }
        $Process.Refresh()
        $bindingAfter = -not $Process.HasExited -and
            (Test-D01OwnedProcessBinding -Process $Process `
                -ExpectedPath ([string]$Process.Path))
        $handleStable = -not $present -or
            $Process.MainWindowHandle -eq $windowHandle
        $sourceBound = $bindingBefore -and $bindingAfter -and $handleStable
        $collectorOk = $sourceBound -and
            (-not $present -or $responsive -or $timeoutProven)
    } catch {
        $responsive = $false
        $collectorOk = $false
        $sourceBound = $false
        $timeoutProven = $false
        $errorText = $_.Exception.Message
    } finally {
        $watch.Stop()
    }
    return [pscustomobject][ordered]@{
        captured_at_utc = Get-LabUtcTimestamp
        process_id = $Process.Id
        main_window_present = $present
        message_pump_responsive = $responsive
        timeout_proven = $timeoutProven
        collector_ok = $collectorOk
        source_bound = $sourceBound
        win32_error_code = $errorCode
        error_sha256 = if ($errorText) {
            Get-LabStringSha256 -Value $errorText
        } else { '' }
        duration_ms = [Int64]$watch.ElapsedMilliseconds
    }
}

function Get-D01ProcessOwnerSidHash {
    param([Parameter(Mandatory = $true)][int]$ProcessId)
    $rows = @(Get-CimInstance -ClassName Win32_Process `
        -Filter "ProcessId = $ProcessId" -ErrorAction Stop)
    if ($rows.Count -ne 1) {
        throw "Process owner query was not singular for PID $ProcessId"
    }
    $owner = Invoke-CimMethod -InputObject $rows[0] `
        -MethodName GetOwnerSid -ErrorAction Stop
    if ([UInt32]$owner.ReturnValue -ne 0 -or
        [string]::IsNullOrWhiteSpace([string]$owner.Sid)) {
        throw "Process owner SID query failed for PID $ProcessId"
    }
    $sid = [Security.Principal.SecurityIdentifier]::new(
        [string]$owner.Sid).Value
    return Get-LabStringSha256 -Value $sid
}

function Get-D01CimProcessCreationUtcTicks {
    param([Parameter(Mandatory = $true)][object]$ProcessRow)
    $value = $ProcessRow.CreationDate
    if ($value -is [DateTimeOffset]) {
        return [Int64]$value.UtcDateTime.Ticks
    }
    if ($value -is [DateTime]) {
        return [Int64]$value.ToUniversalTime().Ticks
    }
    if ([string]::IsNullOrWhiteSpace([string]$value)) {
        throw 'CIM process row has no CreationDate'
    }
    $parsed = [System.Management.ManagementDateTimeConverter]::ToDateTime(
        [string]$value)
    return [Int64]$parsed.ToUniversalTime().Ticks
}

function Get-D01DescendantCensus {
    param(
        [Parameter(Mandatory = $true)][int]$RootProcessId,
        [Parameter(Mandatory = $true)][Int64]$RootCreationUtcTicks,
        [switch]$RootMayHaveExited
    )
    $rows = @(Get-CimInstance -ClassName Win32_Process -ErrorAction Stop)
    $rootRows = @($rows | Where-Object {
        [int]$_.ProcessId -eq $RootProcessId
    })
    if ($rootRows.Count -gt 1) {
        throw 'CIM returned duplicate root PID rows'
    }
    $rootPresent = $rootRows.Count -eq 1
    $rootExact = $false
    $observedTicks = $null
    if ($rootPresent) {
        $observedTicks = Get-D01CimProcessCreationUtcTicks `
            -ProcessRow $rootRows[0]
        $rootExact = [Int64]$observedTicks -eq $RootCreationUtcTicks
    } elseif ($RootMayHaveExited) { $rootExact = $true }
    $known = New-Object 'Collections.Generic.HashSet[int]'
    $seen = New-Object 'Collections.Generic.HashSet[int]'
    $null = $known.Add($RootProcessId)
    $descendants = [Collections.Generic.List[object]]::new()
    do {
        $added = $false
        foreach ($row in $rows) {
            $ownedProcessId = [int]$row.ProcessId
            if ($ownedProcessId -eq $RootProcessId -or
                $seen.Contains($ownedProcessId) -or
                -not $known.Contains([int]$row.ParentProcessId)) { continue }
            $ticks = Get-D01CimProcessCreationUtcTicks -ProcessRow $row
            if ($ticks -lt $RootCreationUtcTicks) { continue }
            $null = $seen.Add($ownedProcessId)
            $null = $known.Add($ownedProcessId)
            $descendants.Add([pscustomobject][ordered]@{
                process_id = $ownedProcessId
                parent_process_id = [int]$row.ParentProcessId
                creation_utc_ticks = [Int64]$ticks
            })
            $added = $true
        }
    } while ($added)
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.d01-descendant-census/v1'
        root_process_id = $RootProcessId
        root_creation_utc_ticks = $RootCreationUtcTicks
        root_present = $rootPresent
        root_identity_exact = $rootExact
        observed_root_creation_utc_ticks = $observedTicks
        descendant_count = $descendants.Count
        descendants = $descendants.ToArray()
        clear = $rootExact -and $descendants.Count -eq 0
    }
}

function Initialize-D01RestrictedProcessLauncher {
    if ('V91D01RestrictedProcessLauncherV1' -as [type]) { return }
    Add-Type @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

public sealed class V91D01RestrictedLaunchResultV1 {
    public int ProcessId { get; set; }
    public long JobHandle { get; set; }
    public bool CreatedSuspended { get; set; }
    public bool AssignedBeforeResume { get; set; }
}

public sealed class V91D01RestrictedJobSnapshotV1 {
    public uint LimitFlags { get; set; }
    public uint ActiveProcessLimit { get; set; }
    public uint TotalProcesses { get; set; }
    public uint ActiveProcesses { get; set; }
    public uint TotalTerminatedProcesses { get; set; }
}

public static class V91D01RestrictedProcessLauncherV1 {
    private const uint CREATE_SUSPENDED = 0x00000004;
    private const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
    private const uint STARTF_USESHOWWINDOW = 0x00000001;
    private const short SW_HIDE = 0;
    private const uint JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008;
    private const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
    private const int JobObjectBasicAccountingInformation = 1;
    private const int JobObjectExtendedLimitInformation = 9;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFO {
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public int dwX;
        public int dwY;
        public int dwXSize;
        public int dwYSize;
        public int dwXCountChars;
        public int dwYCountChars;
        public int dwFillAttribute;
        public uint dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_BASIC_LIMIT_INFORMATION {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IO_COUNTERS {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
        public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
        public IO_COUNTERS IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_BASIC_ACCOUNTING_INFORMATION {
        public long TotalUserTime;
        public long TotalKernelTime;
        public long ThisPeriodTotalUserTime;
        public long ThisPeriodTotalKernelTime;
        public uint TotalPageFaultCount;
        public uint TotalProcesses;
        public uint ActiveProcesses;
        public uint TotalTerminatedProcesses;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode,
        SetLastError = true)]
    private static extern bool CreateProcessW(
        string applicationName, StringBuilder commandLine,
        IntPtr processAttributes, IntPtr threadAttributes,
        bool inheritHandles, uint creationFlags, IntPtr environment,
        string currentDirectory, ref STARTUPINFO startupInfo,
        out PROCESS_INFORMATION processInformation);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode,
        SetLastError = true)]
    private static extern IntPtr CreateJobObjectW(
        IntPtr jobAttributes, string name);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetInformationJobObject(
        IntPtr job, int informationClass, IntPtr information,
        uint informationLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool QueryInformationJobObject(
        IntPtr job, int informationClass, IntPtr information,
        uint informationLength, IntPtr returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AssignProcessToJobObject(
        IntPtr job, IntPtr process);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint ResumeThread(IntPtr thread);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateProcess(IntPtr process, uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    private static string Quote(string value) {
        if (value == null) throw new ArgumentNullException("value");
        if (value.Length != 0 && value.IndexOfAny(
                new char[] { ' ', '\t', '\n', '\v', '"' }) < 0) {
            return value;
        }
        StringBuilder output = new StringBuilder();
        output.Append('"');
        int slashes = 0;
        foreach (char current in value) {
            if (current == '\\') {
                slashes++;
                continue;
            }
            if (current == '"') {
                output.Append('\\', (slashes * 2) + 1);
                output.Append('"');
                slashes = 0;
                continue;
            }
            output.Append('\\', slashes);
            slashes = 0;
            output.Append(current);
        }
        output.Append('\\', slashes * 2);
        output.Append('"');
        return output.ToString();
    }

    private static void ThrowLastError(string operation) {
        throw new Win32Exception(
            Marshal.GetLastWin32Error(), operation + " failed");
    }

    public static V91D01RestrictedLaunchResultV1 Start(
            string executable, string[] arguments, string workingDirectory) {
        if (String.IsNullOrWhiteSpace(executable))
            throw new ArgumentException("Executable is required", "executable");
        if (String.IsNullOrWhiteSpace(workingDirectory))
            throw new ArgumentException(
                "Working directory is required", "workingDirectory");

        IntPtr job = CreateJobObjectW(IntPtr.Zero, null);
        if (job == IntPtr.Zero) ThrowLastError("CreateJobObjectW");
        PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
        bool processCreated = false;
        try {
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits =
                new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
            limits.BasicLimitInformation.LimitFlags =
                JOB_OBJECT_LIMIT_ACTIVE_PROCESS |
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            limits.BasicLimitInformation.ActiveProcessLimit = 1;
            int limitsSize = Marshal.SizeOf(
                typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
            IntPtr limitsBuffer = Marshal.AllocHGlobal(limitsSize);
            try {
                Marshal.StructureToPtr(limits, limitsBuffer, false);
                if (!SetInformationJobObject(
                        job, JobObjectExtendedLimitInformation,
                        limitsBuffer, (uint)limitsSize)) {
                    ThrowLastError("SetInformationJobObject");
                }
            } finally {
                Marshal.FreeHGlobal(limitsBuffer);
            }

            List<string> command = new List<string>();
            command.Add(Quote(executable));
            if (arguments != null) {
                foreach (string argument in arguments)
                    command.Add(Quote(argument));
            }
            STARTUPINFO si = new STARTUPINFO();
            si.cb = Marshal.SizeOf(typeof(STARTUPINFO));
            si.dwFlags = STARTF_USESHOWWINDOW;
            si.wShowWindow = SW_HIDE;
            if (!CreateProcessW(
                    executable, new StringBuilder(String.Join(" ", command)),
                    IntPtr.Zero, IntPtr.Zero, false,
                    CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
                    IntPtr.Zero, workingDirectory, ref si, out pi)) {
                ThrowLastError("CreateProcessW");
            }
            processCreated = true;
            if (!AssignProcessToJobObject(job, pi.hProcess))
                ThrowLastError("AssignProcessToJobObject");
            V91D01RestrictedJobSnapshotV1 snapshot = Query(job.ToInt64());
            if (snapshot.ActiveProcessLimit != 1 ||
                (snapshot.LimitFlags & JOB_OBJECT_LIMIT_ACTIVE_PROCESS) == 0 ||
                (snapshot.LimitFlags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE) == 0 ||
                snapshot.TotalProcesses != 1 || snapshot.ActiveProcesses != 1) {
                throw new InvalidOperationException(
                    "Restricted job limits/accounting are not exact");
            }
            if (ResumeThread(pi.hThread) == UInt32.MaxValue)
                ThrowLastError("ResumeThread");
            return new V91D01RestrictedLaunchResultV1 {
                ProcessId = pi.dwProcessId,
                JobHandle = job.ToInt64(),
                CreatedSuspended = true,
                AssignedBeforeResume = true
            };
        } catch {
            if (processCreated && pi.hProcess != IntPtr.Zero)
                TerminateProcess(pi.hProcess, 2);
            CloseHandle(job);
            throw;
        } finally {
            if (pi.hThread != IntPtr.Zero) CloseHandle(pi.hThread);
            if (pi.hProcess != IntPtr.Zero) CloseHandle(pi.hProcess);
        }
    }

    public static V91D01RestrictedJobSnapshotV1 Query(long jobHandle) {
        IntPtr job = new IntPtr(jobHandle);
        if (job == IntPtr.Zero)
            throw new ArgumentException("Job handle is invalid", "jobHandle");
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits;
        JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting;
        int limitsSize = Marshal.SizeOf(
            typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
        int accountingSize = Marshal.SizeOf(
            typeof(JOBOBJECT_BASIC_ACCOUNTING_INFORMATION));
        IntPtr limitsBuffer = Marshal.AllocHGlobal(limitsSize);
        IntPtr accountingBuffer = Marshal.AllocHGlobal(accountingSize);
        try {
            if (!QueryInformationJobObject(
                    job, JobObjectExtendedLimitInformation,
                    limitsBuffer, (uint)limitsSize, IntPtr.Zero)) {
                ThrowLastError("QueryInformationJobObject(limits)");
            }
            if (!QueryInformationJobObject(
                    job, JobObjectBasicAccountingInformation,
                    accountingBuffer, (uint)accountingSize, IntPtr.Zero)) {
                ThrowLastError("QueryInformationJobObject(accounting)");
            }
            limits = (JOBOBJECT_EXTENDED_LIMIT_INFORMATION)
                Marshal.PtrToStructure(
                    limitsBuffer,
                    typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
            accounting = (JOBOBJECT_BASIC_ACCOUNTING_INFORMATION)
                Marshal.PtrToStructure(
                    accountingBuffer,
                    typeof(JOBOBJECT_BASIC_ACCOUNTING_INFORMATION));
        } finally {
            Marshal.FreeHGlobal(limitsBuffer);
            Marshal.FreeHGlobal(accountingBuffer);
        }
        return new V91D01RestrictedJobSnapshotV1 {
            LimitFlags = limits.BasicLimitInformation.LimitFlags,
            ActiveProcessLimit =
                limits.BasicLimitInformation.ActiveProcessLimit,
            TotalProcesses = accounting.TotalProcesses,
            ActiveProcesses = accounting.ActiveProcesses,
            TotalTerminatedProcesses = accounting.TotalTerminatedProcesses
        };
    }

    public static void CloseJob(long jobHandle) {
        IntPtr job = new IntPtr(jobHandle);
        if (job == IntPtr.Zero || !CloseHandle(job))
            ThrowLastError("CloseHandle(job)");
    }
}
'@
}

function Get-D01JobContainmentEvidence {
    param(
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [switch]$RootMayHaveExited
    )
    Initialize-D01RestrictedProcessLauncher
    $required = @(
        'd01_job_handle', 'd01_job_created_suspended',
        'd01_job_assigned_before_resume', 'd01_job_assigned_process_id',
        'd01_job_closed'
    )
    if (@($required | Where-Object {
        $Process.PSObject.Properties.Name -notcontains $_
    }).Count -ne 0 -or [bool]$Process.d01_job_closed) {
        throw 'Candidate lacks a live restricted Job Object binding'
    }
    $snapshot = [V91D01RestrictedProcessLauncherV1]::Query(
        [Int64]$Process.d01_job_handle)
    $Process.Refresh()
    $rootExited = [bool]$Process.HasExited
    if (-not $RootMayHaveExited -and $rootExited) {
        throw 'Restricted job root exited before a live evidence boundary'
    }
    $expectedActive = if ($rootExited) { 0 } else { 1 }
    $exact = [bool]$Process.d01_job_created_suspended -and
        [bool]$Process.d01_job_assigned_before_resume -and
        [int]$Process.d01_job_assigned_process_id -eq [int]$Process.Id -and
        ([UInt32]$snapshot.LimitFlags -band [UInt32]0x00000008) -ne 0 -and
        ([UInt32]$snapshot.LimitFlags -band [UInt32]0x00002000) -ne 0 -and
        [UInt32]$snapshot.ActiveProcessLimit -eq 1 -and
        [UInt32]$snapshot.TotalProcesses -eq 1 -and
        [UInt32]$snapshot.ActiveProcesses -eq $expectedActive
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.d01-child-process-prevention/v1'
        mechanism = 'windows-job-active-process-limit'
        created_suspended = [bool]$Process.d01_job_created_suspended
        assigned_before_resume =
            [bool]$Process.d01_job_assigned_before_resume
        assigned_process_id = [int]$Process.d01_job_assigned_process_id
        active_process_limit = [int]$snapshot.ActiveProcessLimit
        active_process_limit_enabled =
            ([UInt32]$snapshot.LimitFlags -band [UInt32]0x00000008) -ne 0
        kill_on_job_close_enabled =
            ([UInt32]$snapshot.LimitFlags -band [UInt32]0x00002000) -ne 0
        total_processes_ever_assigned = [int]$snapshot.TotalProcesses
        active_processes = [int]$snapshot.ActiveProcesses
        total_terminated_processes =
            [int]$snapshot.TotalTerminatedProcesses
        root_exited = $rootExited
        exact = $exact
    }
}

function Close-D01OwnedJobHandle {
    param([Parameter(Mandatory = $true)][Diagnostics.Process]$Process)
    if ($Process.PSObject.Properties.Name -notcontains 'd01_job_handle' -or
        $Process.PSObject.Properties.Name -notcontains 'd01_job_closed') {
        throw 'Candidate lacks a restricted Job Object handle'
    }
    if (-not [bool]$Process.d01_job_closed) {
        [V91D01RestrictedProcessLauncherV1]::CloseJob(
            [Int64]$Process.d01_job_handle)
        $Process.d01_job_closed = $true
    }
}

function Start-D01OwnedCandidateProcess {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$ArgumentList,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [Parameter(Mandatory = $true)][string]$OwnerRole,
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[0-9a-fA-F]{32}$')][string]$Nonce
    )
    Initialize-D01RestrictedProcessLauncher
    $launch = [V91D01RestrictedProcessLauncherV1]::Start(
        $FilePath, $ArgumentList, $WorkingDirectory)
    $process = $null
    try {
        $process = [Diagnostics.Process]::GetProcessById(
            [int]$launch.ProcessId)
        foreach ($entry in ([ordered]@{
            d01_job_handle = [Int64]$launch.JobHandle
            d01_job_created_suspended = [bool]$launch.CreatedSuspended
            d01_job_assigned_before_resume =
                [bool]$launch.AssignedBeforeResume
            d01_job_assigned_process_id = [int]$launch.ProcessId
            d01_job_closed = $false
        }).GetEnumerator()) {
            $process | Add-Member -NotePropertyName $entry.Key `
                -NotePropertyValue $entry.Value -Force
        }
        $process = Register-D01OwnedProcess -Process $process `
            -ExpectedPath $FilePath -OwnerRole $OwnerRole -Nonce $Nonce
        $jobEvidence = Get-D01JobContainmentEvidence -Process $process
        if (-not [bool]$jobEvidence.exact) {
            throw 'Candidate restricted Job Object binding is not exact'
        }
        return $process
    } catch {
        try {
            [V91D01RestrictedProcessLauncherV1]::CloseJob(
                [Int64]$launch.JobHandle)
        } catch {}
        throw
    }
}

function Test-D01OwnedProcessDescendants {
    param(
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [switch]$RootMayHaveExited
    )
    try {
        $audit = Get-D01DescendantCensus `
            -RootProcessId ([int]$Process.d01_owner_pid) `
            -RootCreationUtcTicks (
                [Int64]$Process.d01_owner_cim_creation_utc_ticks) `
            -RootMayHaveExited:$RootMayHaveExited
        $Process | Add-Member -NotePropertyName d01_descendant_last_census `
            -NotePropertyValue $audit -Force
        if (-not [bool]$audit.root_identity_exact) {
            $Process.d01_descendant_root_identity_contradicted = $true
        }
        if ([int]$audit.descendant_count -gt 0) {
            $Process.d01_descendant_observed = $true
            $ids = @($Process.d01_descendant_observed_process_ids) +
                @($audit.descendants | ForEach-Object { [int]$_.process_id })
            $Process.d01_descendant_observed_process_ids = @(
                $ids | Select-Object -Unique)
        }
    } catch {
        $Process.d01_descendant_collector_failed = $true
        $Process.d01_descendant_error_sha256 =
            Get-LabStringSha256 -Value $_.Exception.Message
        return $false
    }
    return -not [bool]$Process.d01_descendant_collector_failed -and
        -not [bool]$Process.d01_descendant_root_identity_contradicted -and
        -not [bool]$Process.d01_descendant_observed -and
        [bool]$Process.d01_descendant_last_census.clear
}

function Register-D01OwnedProcess {
    param(
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][string]$ExpectedPath,
        [Parameter(Mandatory = $true)][string]$OwnerRole,
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[0-9a-fA-F]{32}$')][string]$Nonce
    )
    [void]$Process.Handle
    $Process.Refresh()
    if ($Process.HasExited) { throw 'Process exited before ownership binding' }
    $path = Assert-D01NoReparsePath -Path $Process.Path -Kind File
    if (-not [string]::Equals(
        [IO.Path]::GetFullPath($path), [IO.Path]::GetFullPath($ExpectedPath),
        [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Started process path differs from intended executable'
    }
    $pathHash = Get-LabStringSha256 -Value $path.ToLowerInvariant()
    $exeHash = Get-LabSha256 -Path $path
    if ($exeHash -cne $expectedEmuleHash) {
        throw 'Started process executable differs from bound candidate'
    }
    $creationTicks = [Int64]$Process.StartTime.ToUniversalTime().Ticks
    $cimRows = @(Get-CimInstance -ClassName Win32_Process `
        -Filter "ProcessId = $($Process.Id)" -ErrorAction Stop)
    if ($cimRows.Count -ne 1) {
        throw 'Started process CIM binding was not singular'
    }
    $cimTicks = Get-D01CimProcessCreationUtcTicks -ProcessRow $cimRows[0]
    if ([Math]::Abs([double]($cimTicks - $creationTicks)) -gt
        [TimeSpan]::TicksPerSecond) {
        throw 'Process creation clocks disagree'
    }
    $sidHash = Get-D01ProcessOwnerSidHash -ProcessId $Process.Id
    if ($sidHash -cne [string]$script:d01HostIdentity.user_sid_sha256) {
        throw 'Started process is not owned by the bound disposable account'
    }
    $ownershipId = Get-LabStringSha256 -Value (
        '{0}|{1}|{2}|{3}|{4}|{5}|{6}|{7}' -f
        $Nonce.ToLowerInvariant(), $OwnerRole, $Process.Id, $creationTicks,
        $cimTicks, $pathHash, $exeHash, $sidHash)
    foreach ($entry in ([ordered]@{
        d01_owner_nonce = $Nonce.ToLowerInvariant()
        d01_owner_role = $OwnerRole
        d01_owner_pid = [int]$Process.Id
        d01_owner_creation_utc_ticks = $creationTicks
        d01_owner_cim_creation_utc_ticks = [Int64]$cimTicks
        d01_owner_path_sha256 = $pathHash
        d01_owner_executable_sha256 = $exeHash
        d01_owner_sid_sha256 = $sidHash
        d01_ownership_id_sha256 = $ownershipId
        d01_descendant_collector_failed = $false
        d01_descendant_root_identity_contradicted = $false
        d01_descendant_observed = $false
        d01_descendant_observed_process_ids = @()
        d01_descendant_error_sha256 = ''
        d01_descendant_last_census = $null
    }).GetEnumerator()) {
        $Process | Add-Member -NotePropertyName $entry.Key `
            -NotePropertyValue $entry.Value -Force
    }
    if (-not (Test-D01OwnedProcessDescendants -Process $Process)) {
        throw 'Owned process spawned a descendant or descendant census failed'
    }
    return $Process
}

function Test-D01OwnedProcessBinding {
    param(
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][string]$ExpectedPath
    )
    $required = @(
        'd01_owner_nonce', 'd01_owner_role', 'd01_owner_pid',
        'd01_owner_creation_utc_ticks',
        'd01_owner_cim_creation_utc_ticks', 'd01_owner_path_sha256',
        'd01_owner_executable_sha256', 'd01_owner_sid_sha256',
        'd01_ownership_id_sha256', 'd01_descendant_collector_failed',
        'd01_descendant_root_identity_contradicted',
        'd01_descendant_observed', 'd01_descendant_observed_process_ids',
        'd01_descendant_error_sha256', 'd01_descendant_last_census',
        'd01_job_handle', 'd01_job_created_suspended',
        'd01_job_assigned_before_resume', 'd01_job_assigned_process_id',
        'd01_job_closed'
    )
    if (@($required | Where-Object {
        $Process.PSObject.Properties.Name -notcontains $_
    }).Count -ne 0) { return $false }
    [void]$Process.Handle
    $Process.Refresh()
    if ($Process.HasExited -or [int]$Process.Id -ne
        [int]$Process.d01_owner_pid) { return $false }
    $path = Assert-D01NoReparsePath -Path $Process.Path -Kind File
    $ticks = [Int64]$Process.StartTime.ToUniversalTime().Ticks
    $pathHash = Get-LabStringSha256 -Value $path.ToLowerInvariant()
    $exeHash = Get-LabSha256 -Path $path
    $sidHash = Get-D01ProcessOwnerSidHash -ProcessId $Process.Id
    $ownershipId = Get-LabStringSha256 -Value (
        '{0}|{1}|{2}|{3}|{4}|{5}|{6}|{7}' -f
        [string]$Process.d01_owner_nonce,
        [string]$Process.d01_owner_role, [int]$Process.d01_owner_pid,
        [Int64]$Process.d01_owner_creation_utc_ticks,
        [Int64]$Process.d01_owner_cim_creation_utc_ticks,
        [string]$Process.d01_owner_path_sha256,
        [string]$Process.d01_owner_executable_sha256,
        [string]$Process.d01_owner_sid_sha256)
    if (-not [string]::Equals(
            [IO.Path]::GetFullPath($path),
            [IO.Path]::GetFullPath($ExpectedPath),
            [StringComparison]::OrdinalIgnoreCase) -or
        $ticks -ne [Int64]$Process.d01_owner_creation_utc_ticks -or
        $pathHash -cne [string]$Process.d01_owner_path_sha256 -or
        $exeHash -cne [string]$Process.d01_owner_executable_sha256 -or
        $exeHash -cne $expectedEmuleHash -or
        $sidHash -cne [string]$Process.d01_owner_sid_sha256 -or
        $sidHash -cne [string]$script:d01HostIdentity.user_sid_sha256 -or
        $ownershipId -cne [string]$Process.d01_ownership_id_sha256) {
        return $false
    }
    if (-not (Test-D01OwnedProcessDescendants -Process $Process)) {
        return $false
    }
    try {
        $jobEvidence = Get-D01JobContainmentEvidence -Process $Process
        return [bool]$jobEvidence.exact
    } catch { return $false }
}

function Stop-D01OwnedProcess {
    param(
        [AllowNull()][Diagnostics.Process]$Process,
        [AllowEmptyString()][string]$ExpectedPath = ''
    )

    $jobEvidence = $null
    $jobExact = $false
    if ($null -eq $Process) {
        return [pscustomobject]@{
            stopped = $true
            path_owned = $true
            graceful = $true
            process_id = $null
        }
    }
    try {
        $Process.Refresh()
    } catch {
        return [pscustomobject]@{
            stopped = $false
            path_owned = $false
            graceful = $false
            process_id = $Process.Id
            descendants_clear = $false
            collector_ok = $false
        }
    }
    if ($Process.HasExited) {
        $clear = Test-D01OwnedProcessDescendants -Process $Process `
            -RootMayHaveExited
        try {
            $jobEvidence = Get-D01JobContainmentEvidence -Process $Process `
                -RootMayHaveExited
            $jobExact = [bool]$jobEvidence.exact
            if ($jobExact) { Close-D01OwnedJobHandle -Process $Process }
        } catch { $jobExact = $false }
        return [pscustomobject]@{
            stopped = $clear -and $jobExact
            path_owned = $true
            graceful = $true
            process_id = $Process.Id
            descendants_clear = $clear
            collector_ok = $clear -and $jobExact
            child_process_prevention = $jobEvidence
            job_handle_closed = $jobExact -and [bool]$Process.d01_job_closed
        }
    }
    $pathOwned = $false
    try { $pathOwned = Test-D01OwnedProcessBinding `
        -Process $Process -ExpectedPath $ExpectedPath } catch {}
    if (-not $pathOwned) {
        return [pscustomobject]@{
            stopped = $false; path_owned = $false; graceful = $false
            process_id = $Process.Id; descendants_clear = $false
            collector_ok = $false
        }
    }
    $graceful = $false
    try {
        if ($Process.MainWindowHandle -ne [IntPtr]::Zero) {
            $null = $Process.CloseMainWindow()
            $graceful = $Process.WaitForExit(15000)
        }
        if (-not $graceful) {
            if (-not (Test-D01OwnedProcessBinding `
                -Process $Process -ExpectedPath $ExpectedPath)) {
                throw 'Ownership changed before forced termination'
            }
            $Process.Kill()
            $null = $Process.WaitForExit(10000)
        }
        $clear = Test-D01OwnedProcessDescendants -Process $Process `
            -RootMayHaveExited
        $jobEvidence = Get-D01JobContainmentEvidence -Process $Process `
            -RootMayHaveExited
        $jobExact = [bool]$jobEvidence.exact
        if ($jobExact) { Close-D01OwnedJobHandle -Process $Process }
    } catch {
        $clear = $false
        $jobExact = $false
    }
    return [pscustomobject]@{
        stopped = $Process.HasExited -and $clear -and $jobExact
        path_owned = $true
        graceful = $graceful
        process_id = $Process.Id
        descendants_clear = $clear
        collector_ok = $clear -and $jobExact
        child_process_prevention = $jobEvidence
        job_handle_closed = $jobExact -and [bool]$Process.d01_job_closed
    }
}

function Get-D01TerminalOwnershipCensus {
    param(
        [AllowNull()][Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][int[]]$Ports,
        [Parameter(Mandatory = $true)][string]$HostRole
    )
    try {
        $tcpAll = @(Get-NetTCPConnection -ErrorAction Stop)
        $udpAll = @(Get-NetUDPEndpoint -ErrorAction Stop)
        $ownedProcessId = if ($null -ne $Process) {
            [int]$Process.Id
        } else { 0 }
        $tcp = @($tcpAll | Where-Object {
            ($ownedProcessId -gt 0 -and
                [int]$_.OwningProcess -eq $ownedProcessId) -or
            [int]$_.LocalPort -in $Ports
        })
        $udp = @($udpAll | Where-Object {
            ($ownedProcessId -gt 0 -and
                [int]$_.OwningProcess -eq $ownedProcessId) -or
            [int]$_.LocalPort -in $Ports
        })
        $processExited = if ($null -eq $Process) { $true } else {
            $Process.Refresh(); [bool]$Process.HasExited
        }
        $descendantsClear = if ($null -eq $Process) { $true } else {
            Test-D01OwnedProcessDescendants -Process $Process `
                -RootMayHaveExited
        }
        return [pscustomobject][ordered]@{
            schema = 'ese.v91.d01-terminal-ownership-census/v1'
            collected_at_utc = Get-LabUtcTimestamp
            role = $HostRole
            collector_ok = $true
            process_id = if ($ownedProcessId -gt 0) {
                $ownedProcessId
            } else { $null }
            process_exited = $processExited
            descendants_clear = $descendantsClear
            remaining_tcp_count = $tcp.Count
            remaining_udp_count = $udp.Count
            remaining_tcp = @($tcp | ForEach-Object {
                [pscustomobject][ordered]@{
                    owning_process = [int]$_.OwningProcess
                    local_port = [int]$_.LocalPort
                    remote_port = [int]$_.RemotePort
                    state = [string]$_.State
                }
            })
            remaining_udp = @($udp | ForEach-Object {
                [pscustomobject][ordered]@{
                    owning_process = [int]$_.OwningProcess
                    local_port = [int]$_.LocalPort
                }
            })
            all_clear = $processExited -and $descendantsClear -and
                $tcp.Count -eq 0 -and $udp.Count -eq 0
            error_sha256 = ''
        }
    } catch {
        return [pscustomobject][ordered]@{
            schema = 'ese.v91.d01-terminal-ownership-census/v1'
            collected_at_utc = Get-LabUtcTimestamp
            role = $HostRole
            collector_ok = $false
            process_id = if ($null -ne $Process) {
                [int]$Process.Id
            } else { $null }
            process_exited = $false
            descendants_clear = $false
            remaining_tcp_count = 0
            remaining_udp_count = 0
            remaining_tcp = @()
            remaining_udp = @()
            all_clear = $false
            error_sha256 = Get-LabStringSha256 -Value $_.Exception.Message
        }
    }
}

function Get-D01ClassicSession {
    param(
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][string]$ExpectedPath
    )

    $encoded = [Uri]::EscapeDataString($webPassword)
    $deadline = [DateTime]::UtcNow.AddMinutes(10)
    do {
        try {
            $ownership = Get-D01WebEndpointOwnershipEvidence `
                -Port $Port -Process $Process -ExpectedPath $ExpectedPath
            if (-not $ownership.collector_ok -or
                -not $ownership.endpoint_bound_to_candidate) {
                throw 'Classic endpoint is not uniquely candidate-owned'
            }
            $response = Invoke-WebRequest `
                -Uri "http://127.0.0.1:$Port/?w=password&p=$encoded" `
                -UseBasicParsing -TimeoutSec 10
            $match = [regex]::Match($response.Content, 'ses=(\d+)')
            if ($match.Success) { return $match.Groups[1].Value }
        } catch {}
        Start-Sleep -Milliseconds 500
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "Classic WebServer login failed on localhost port $Port"
}

function Get-D01SharedLink {
    param(
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][string]$ExpectedPath,
        [Parameter(Mandatory = $true)][string]$Session,
        [Parameter(Mandatory = $true)][string]$FileName,
        [Parameter(Mandatory = $true)][Int64]$FileBytes
    )

    $deadline = [DateTime]::UtcNow.AddMinutes(10)
    do {
        $ownership = Get-D01WebEndpointOwnershipEvidence `
            -Port $Port -Process $Process -ExpectedPath $ExpectedPath
        if (-not $ownership.collector_ok -or
            -not $ownership.endpoint_bound_to_candidate) {
            throw 'Shared-list endpoint is not uniquely candidate-owned'
        }
        $response = Invoke-WebRequest `
            -Uri "http://127.0.0.1:$Port/?ses=$Session&w=shared" `
            -UseBasicParsing -TimeoutSec 15
        $pattern = 'ed2k://\|file\|' + [regex]::Escape($FileName) +
            '\|' + $FileBytes +
            '\|([A-Fa-f0-9]{32})(?:\|h=[A-Z2-7]{32})?\|/'
        $match = [regex]::Match($response.Content, $pattern)
        if ($match.Success) {
            return [pscustomobject][ordered]@{
                link = $match.Value
                ed2k_hash = $match.Groups[1].Value.ToUpperInvariant()
            }
        }
        Start-Sleep -Seconds 1
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "Timed out waiting for '$FileName' to enter the shared list"
}

function Send-D01Ed2kLink {
    param(
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][string]$ExpectedPath,
        [Parameter(Mandatory = $true)][string]$Link
    )

    if (-not (Test-D01OwnedProcessBinding -Process $Process `
        -ExpectedPath $ExpectedPath)) {
        throw 'Downloader ownership binding failed before link injection'
    }
    if (-not ('V91D01CopyDataV2' -as [type])) {
        Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class V91D01CopyDataV2 {
    [StructLayout(LayoutKind.Sequential)]
    public struct COPYDATASTRUCT {
        public IntPtr dwData;
        public int cbData;
        public IntPtr lpData;
    }
    [DllImport("user32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern IntPtr SendMessageTimeout(
        IntPtr hWnd, uint msg, IntPtr wParam, ref COPYDATASTRUCT lParam,
        uint flags, uint timeout, out IntPtr result);
}
'@
    }
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    $handle = [IntPtr]::Zero
    do {
        $Process.Refresh()
        if ($Process.HasExited) {
            throw 'Downloader exited before the sole ED2K link injection'
        }
        $handle = $Process.MainWindowHandle
        if ($handle -ne [IntPtr]::Zero) { break }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    if ($handle -eq [IntPtr]::Zero) {
        throw 'Downloader main window handle was unavailable'
    }

    $pointer = [Runtime.InteropServices.Marshal]::StringToHGlobalUni($Link)
    try {
        $payload = New-Object V91D01CopyDataV2+COPYDATASTRUCT
        $payload.dwData = [IntPtr]12000
        $payload.cbData = ($Link.Length + 1) * 2
        $payload.lpData = $pointer
        $result = [IntPtr]::Zero
        $sent = [V91D01CopyDataV2]::SendMessageTimeout(
            $handle, 0x004A, [IntPtr]::Zero, [ref]$payload,
            2, 5000, [ref]$result
        )
        if ($sent -eq [IntPtr]::Zero) {
            throw "WM_COPYDATA timed out or failed (Win32 $([Runtime.InteropServices.Marshal]::GetLastWin32Error()))"
        }
        return [pscustomobject][ordered]@{
            injected_at_utc = Get-LabUtcTimestamp
            process_id = $Process.Id
            link_sha256 = Get-LabStringSha256 -Value $Link
            send_message_timeout_ms = 5000
            one_injection = $true
        }
    } finally {
        [Runtime.InteropServices.Marshal]::FreeHGlobal($pointer)
    }
}

function New-D01FixtureFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][Int64]$Bytes
    )

    $stream = [IO.File]::Open(
        $Path, [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write, [IO.FileShare]::None
    )
    $rng = $null
    try {
        $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
        $buffer = New-Object byte[] (1MB)
        [Int64]$remaining = $Bytes
        while ($remaining -gt 0) {
            $rng.GetBytes($buffer)
            $count = [int][Math]::Min([Int64]$buffer.Length, $remaining)
            $stream.Write($buffer, 0, $count)
            $remaining -= $count
        }
        $stream.Flush($true)
    } finally {
        if ($null -ne $rng) { $rng.Dispose() }
        $stream.Dispose()
    }
    $item = Get-Item -LiteralPath $Path
    return [pscustomobject][ordered]@{
        bytes = [Int64]$item.Length
        sha256 = Get-LabSha256 -Path $Path
        generation = 'fully materialized CSPRNG bytes; non-sparse'
    }
}

function Test-D01TcpEndpoint {
    param(
        [Parameter(Mandatory = $true)][Net.IPAddress]$Address,
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][int]$TimeoutMilliseconds
    )

    $watch = [Diagnostics.Stopwatch]::StartNew()
    $client = New-Object Net.Sockets.TcpClient($Address.AddressFamily)
    $connected = $false
    $timedOut = $false
    $errorText = $null
    try {
        $task = $client.ConnectAsync($Address, $Port)
        if (-not $task.Wait($TimeoutMilliseconds)) {
            $timedOut = $true
        } elseif ($task.IsFaulted) {
            $errorText = $task.Exception.GetBaseException().Message
        } else {
            $connected = $client.Connected
        }
    } catch {
        $errorText = $_.Exception.GetBaseException().Message
    } finally {
        $watch.Stop()
        $client.Dispose()
    }
    return [pscustomobject][ordered]@{
        address = $Address.ToString()
        family = if ($Address.AddressFamily -eq
            [Net.Sockets.AddressFamily]::InterNetwork) { 'IPv4' } else { 'IPv6' }
        port = $Port
        connected = $connected
        timed_out = $timedOut
        duration_ms = [Int64]$watch.ElapsedMilliseconds
        error = $errorText
    }
}

function Get-D01TargetConnections {
    param(
        [ValidateRange(0, 2147483647)][int]$ProcessId = 0,
        [Parameter(Mandatory = $true)][string[]]$RemoteAddresses,
        [ValidateRange(0, 65535)][int]$RemotePort = 0
    )

    $normalizedTargets = @(
        $RemoteAddresses | ForEach-Object {
            Get-D01NormalizedIp -Address $_
        }
    )
    $connections = @(Get-NetTCPConnection -ErrorAction Stop | Where-Object {
        ($ProcessId -le 0 -or [int]$_.OwningProcess -eq $ProcessId) -and
        ($RemotePort -le 0 -or [int]$_.RemotePort -eq $RemotePort)
    })
    return @(
        $connections |
            Where-Object {
                (Get-D01NormalizedIp -Address ([string]$_.RemoteAddress)) -in
                    $normalizedTargets
            } | ForEach-Object {
                $remote = Get-D01NormalizedIp `
                    -Address ([string]$_.RemoteAddress)
                $local = Get-D01NormalizedIp `
                    -Address ([string]$_.LocalAddress)
                $assignedItems = @(Get-NetIPAddress -ErrorAction Stop |
                    Where-Object {
                    (Get-D01NormalizedIp -Address ([string]$_.IPAddress)) -eq
                        $local
                })
                if ($assignedItems.Count -ne 1) {
                    throw 'Target socket local-address ownership was not singular'
                }
                $assigned = $assignedItems[0]
                $adapter = Get-D01AdapterEvidence `
                    -InterfaceIndex ([int]$assigned.InterfaceIndex) `
                    -Context 'target-process-socket'
                [pscustomobject][ordered]@{
                    captured_at_utc = Get-LabUtcTimestamp
                    owning_process = [int]$_.OwningProcess
                    state = [string]$_.State
                    family = if ($remote.Contains(':')) { 'IPv6' } else { 'IPv4' }
                    local_address = $local
                    local_port = [int]$_.LocalPort
                    remote_address = $remote
                    remote_port = [int]$_.RemotePort
                    local_address_assigned = $null -ne $assigned
                    adapter = $adapter
                    physical_nonvirtual = $null -ne $adapter -and
                        [bool]$adapter.physical_nonvirtual
                }
            }
    )
}

function Get-D01CandidateTcpPeerConnectionCensus {
    param(
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][string]$ExpectedPath,
        [Parameter(Mandatory = $true)][string[]]$SourceAddresses,
        [Parameter(Mandatory = $true)][int]$SourcePort,
        [Parameter(Mandatory = $true)][string]$SchedulerAddress,
        [Parameter(Mandatory = $true)][int]$SchedulerPort,
        [Parameter(Mandatory = $true)][int]$WebPort,
        [Parameter(Mandatory = $true)][object]$ClockAnchor
    )

    $before = Get-D01OwnedProcessBindingEvidence -Process $Process `
        -ExpectedPath $ExpectedPath -RequireLive
    $queryQpcStart = [Diagnostics.Stopwatch]::GetTimestamp()
    $rows = @(Get-NetTCPConnection -OwningProcess $Process.Id `
        -ErrorAction Stop)
    $queryQpcEnd = [Diagnostics.Stopwatch]::GetTimestamp()
    $queryClock = Get-D01ClockObservation -Anchor $ClockAnchor `
        -QpcStart $queryQpcStart -QpcEnd $queryQpcEnd
    $after = Get-D01OwnedProcessBindingEvidence -Process $Process `
        -ExpectedPath $ExpectedPath -RequireLive
    if ([string]$before.ownership_id_sha256 -cne
            [string]$after.ownership_id_sha256) {
        throw 'Candidate ownership changed across TCP peer census'
    }
    [string[]]$normalizedSources = @($SourceAddresses | ForEach-Object {
        Get-D01NormalizedIp -Address ([string]$_)
    } | Sort-Object -Unique)
    $normalizedScheduler = Get-D01NormalizedIp -Address $SchedulerAddress
    $connections = @($rows | ForEach-Object {
        [pscustomobject][ordered]@{
            state = [string]$_.State
            local_address = Get-D01NormalizedIp `
                -Address ([string]$_.LocalAddress)
            local_port = [int]$_.LocalPort
            remote_address = Get-D01NormalizedIp `
                -Address ([string]$_.RemoteAddress)
            remote_port = [int]$_.RemotePort
            owning_process = [int]$_.OwningProcess
        }
    })
    $peerConnections = @($connections | Where-Object {
        [string]$_.state -notin @('Listen', 'Bound') -and
        [string]$_.remote_address -notin @('0.0.0.0', '::') -and
        [int]$_.remote_port -gt 0
    })
    $unexpected = @($peerConnections | Where-Object {
        $remote = [string]$_.remote_address
        $remotePort = [int]$_.remote_port
        $ownedLoopbackApi =
            $remote -in @('127.0.0.1', '::1') -and
            [int]$_.local_port -eq $WebPort
        $controlledScheduler = $remote -eq $normalizedScheduler -and
            $remotePort -eq $SchedulerPort
        $controlledSource = $remote -in $normalizedSources -and
            $remotePort -eq $SourcePort
        -not ($ownedLoopbackApi -or $controlledScheduler -or
            $controlledSource)
    })
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.d01-candidate-tcp-peer-connection-census/v1'
        captured_at_utc = Get-LabUtcTimestamp
        transport = 'tcp'
        scope = 'connected-peer-tuples-only'
        query_clock = $queryClock
        process_binding_before = $before
        process_binding_after = $after
        binding_exact_across_query = $true
        tcp_row_count = $connections.Count
        peer_connection_count = $peerConnections.Count
        unexpected_peer_connection_count = $unexpected.Count
        peer_connections = $peerConnections
        unexpected_peer_connections = $unexpected
    }
}

function Get-D01IncomingConnections {
    param(
        [ValidateRange(0, 2147483647)][int]$ProcessId = 0,
        [Parameter(Mandatory = $true)][int]$LocalPort
    )

    $connections = @(Get-NetTCPConnection -ErrorAction Stop | Where-Object {
        ($ProcessId -le 0 -or [int]$_.OwningProcess -eq $ProcessId) -and
        [int]$_.LocalPort -eq $LocalPort
    })
    return @(
        $connections |
            Where-Object { [string]$_.State -ne 'Listen' } |
            ForEach-Object {
                $local = Get-D01NormalizedIp `
                    -Address ([string]$_.LocalAddress)
                $assignedItems = @(Get-NetIPAddress -ErrorAction Stop |
                    Where-Object {
                    (Get-D01NormalizedIp -Address ([string]$_.IPAddress)) -eq
                        $local
                })
                if ($assignedItems.Count -ne 1) {
                    throw 'Inverse socket local-address ownership was not singular'
                }
                $assigned = $assignedItems[0]
                $adapter = Get-D01AdapterEvidence `
                    -InterfaceIndex ([int]$assigned.InterfaceIndex) `
                    -Context 'source-inverse-socket'
                [pscustomobject][ordered]@{
                    captured_at_utc = Get-LabUtcTimestamp
                    owning_process = [int]$_.OwningProcess
                    state = [string]$_.State
                    local_address = $local
                    local_port = [int]$_.LocalPort
                    remote_address = Get-D01NormalizedIp `
                        -Address ([string]$_.RemoteAddress)
                    remote_port = [int]$_.RemotePort
                    local_address_assigned = $null -ne $assigned
                    adapter = $adapter
                    physical_nonvirtual = $null -ne $adapter -and
                        [bool]$adapter.physical_nonvirtual
                }
            }
    )
}

function Get-D01DnsEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$ExpectedA,
        [Parameter(Mandatory = $true)][string]$ExpectedAAAA,
        [Parameter(Mandatory = $true)][string]$Stage
    )

    $canonicalName = Get-D01CanonicalHostname -Value $Name
    if ($canonicalName -cne $canonicalHostname) {
        throw 'DNS query hostname differs from the canonical fixture A-label'
    }
    $aRows = @(Resolve-DnsName -Name $canonicalName -Type A `
        -DnsOnly -NoHostsFile -ErrorAction Stop)
    $aaaaRows = @(Resolve-DnsName -Name $canonicalName -Type AAAA `
        -DnsOnly -NoHostsFile -ErrorAction Stop)
    $aDnsOnly = @($aRows | Where-Object {
        $_.PSObject.Properties.Name -contains 'IPAddress'
    } | ForEach-Object {
        $parsed = Convert-D01Address -Value ([string]$_.IPAddress) `
            -Family ([Net.Sockets.AddressFamily]::InterNetwork) `
            -Name 'DNS A response'
        $parsed.ToString()
    } | Select-Object -Unique)
    $aaaaDnsOnly = @($aaaaRows | Where-Object {
        $_.PSObject.Properties.Name -contains 'IPAddress'
    } | ForEach-Object {
        $parsed = Convert-D01Address -Value ([string]$_.IPAddress) `
            -Family ([Net.Sockets.AddressFamily]::InterNetworkV6) `
            -Name 'DNS AAAA response'
        $parsed.ToString()
    } | Select-Object -Unique)
    $addresses = @([Net.Dns]::GetHostAddresses($canonicalName))
    $answers = @(
        $addresses | ForEach-Object {
            [pscustomobject][ordered]@{
                family = if ($_.AddressFamily -eq
                    [Net.Sockets.AddressFamily]::InterNetwork) {
                    'IPv4'
                } else { 'IPv6' }
                address = Get-D01NormalizedIp -Address $_.ToString()
                address_class = Get-D01StrictAddressClass -Address $_.ToString()
            }
        } | Sort-Object family, address -Unique
    )
    $a = @($answers | Where-Object family -eq 'IPv4' |
        Select-Object -ExpandProperty address)
    $aaaa = @($answers | Where-Object family -eq 'IPv6' |
        Select-Object -ExpandProperty address)
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.d01-controlled-dns/v3'
        captured_at_utc = Get-LabUtcTimestamp
        stage = $Stage
        resolver = 'Resolve-DnsName DnsOnly NoHostsFile + System.Net.Dns'
        dns_only = $true
        no_hosts_file = $true
        hostname = $canonicalName
        expected = [ordered]@{ A = $ExpectedA; AAAA = $ExpectedAAAA }
        answers = $answers
        dns_only_A = $aDnsOnly
        dns_only_AAAA = $aaaaDnsOnly
        exact_controlled_answer_set = $aDnsOnly.Count -eq 1 -and
            $aaaaDnsOnly.Count -eq 1 -and
            $aDnsOnly[0] -ceq $ExpectedA -and
            $aaaaDnsOnly[0] -ceq $ExpectedAAAA -and
            (Get-D01StrictAddressClass -Address $aDnsOnly[0]) -ceq
                'public-unicast-v4' -and
            (Get-D01StrictAddressClass -Address $aaaaDnsOnly[0]) -ceq
                'native-global-v6' -and
            $a.Count -eq 1 -and
            $aaaa.Count -eq 1 -and $a[0] -eq $ExpectedA -and
            $aaaa[0] -eq $ExpectedAAAA
    }
}

function Get-D01HostsFileSnapshot {
    param([switch]$CompatibleWithHeldBaseline)

    $path = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
    $resolved = Assert-D01NoReparsePath -Path $path -Kind File
    if ($CompatibleWithHeldBaseline) {
        $locked = [IO.FileStream]::new(
            $resolved, [IO.FileMode]::Open, [IO.FileAccess]::Read,
            [IO.FileShare]::Read
        )
        try {
            $firstHash = Get-D01Sha256FromStream -Stream $locked
            $length = [Int64]$locked.Length
            $secondHash = Get-D01Sha256FromStream -Stream $locked
            if ($firstHash -cne $secondHash -or
                [Int64]$locked.Length -ne $length) {
                throw 'Hosts file changed during compatible post snapshot'
            }
            $script:d01CandidateLocks.Add($locked)
        } catch {
            $locked.Dispose()
            throw
        }
        $snapshotLength = $length
        $snapshotHash = $secondHash
    } else {
        $first = Open-D01LockedFile -Path $resolved
        $snapshotLength = [Int64]$first.length
        $snapshotHash = [string]$first.sha256
    }
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.d01-hosts-file-snapshot/v1'
        path_sha256 = Get-LabStringSha256 -Value $resolved.ToLowerInvariant()
        length = [Int64]$snapshotLength
        sha256 = [string]$snapshotHash
        immutable_read_lock_held = $true
    }
}

function Get-D01HostsFilePostcheckEvidence {
    param([Parameter(Mandatory = $true)][object]$Baseline)
    try {
        $after = Get-D01HostsFileSnapshot -CompatibleWithHeldBaseline
        $unchanged = [Int64]$after.length -eq [Int64]$Baseline.length -and
            [string]$after.sha256 -ceq [string]$Baseline.sha256 -and
            [string]$after.path_sha256 -ceq [string]$Baseline.path_sha256
        return [pscustomobject][ordered]@{
            schema = 'ese.v91.d01-hosts-file-postcheck/v1'
            collector_ok = $true
            baseline = $Baseline
            post_state = $after
            unchanged = $unchanged
            safe_to_pass = $unchanged
            error_sha256 = ''
        }
    } catch {
        return [pscustomobject][ordered]@{
            schema = 'ese.v91.d01-hosts-file-postcheck/v1'
            collector_ok = $false
            baseline = $Baseline
            post_state = $null
            unchanged = $false
            safe_to_pass = $false
            error_sha256 = Get-LabStringSha256 -Value $_.Exception.Message
        }
    }
}

function Get-D01TelemetrySnapshot {
    param(
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][string]$ExpectedPath,
        [Int64]$AfterSequence = -1
    )

    $watch = [Diagnostics.Stopwatch]::StartNew()
    $data = $null
    $errorText = $null
    $ownershipBefore = Get-D01WebEndpointOwnershipEvidence `
        -Port $Port -Process $Process -ExpectedPath $ExpectedPath
    $ownershipAfter = $null
    try {
        if (-not $ownershipBefore.collector_ok -or
            -not $ownershipBefore.endpoint_bound_to_candidate) {
            throw 'Telemetry endpoint is not uniquely candidate-owned'
        }
        $uri = "http://127.0.0.1:$Port/api/debug/source-resolutions"
        if ($AfterSequence -ge 0) {
            $uri += '?after=' + [string]$AfterSequence
        }
        $data = Invoke-RestMethod -Uri $uri -TimeoutSec 2
        $ownershipAfter = Get-D01WebEndpointOwnershipEvidence `
            -Port $Port -Process $Process -ExpectedPath $ExpectedPath
        if (-not $ownershipAfter.collector_ok -or
            -not $ownershipAfter.endpoint_bound_to_candidate -or
            [string]$ownershipAfter.candidate_ownership_id_sha256 -cne
                [string]$ownershipBefore.candidate_ownership_id_sha256) {
            throw 'Telemetry endpoint ownership changed across the request'
        }
    } catch {
        $errorText = $_.Exception.Message
    } finally {
        if ($null -eq $ownershipAfter) {
            $ownershipAfter = Get-D01WebEndpointOwnershipEvidence `
                -Port $Port -Process $Process -ExpectedPath $ExpectedPath
        }
        $watch.Stop()
    }
    $ownershipStable = $ownershipBefore.collector_ok -and
        $ownershipAfter.collector_ok -and
        $ownershipBefore.endpoint_bound_to_candidate -and
        $ownershipAfter.endpoint_bound_to_candidate -and
        [string]$ownershipBefore.candidate_ownership_id_sha256 -cne '' -and
        [string]$ownershipBefore.candidate_ownership_id_sha256 -ceq
            [string]$ownershipAfter.candidate_ownership_id_sha256
    $contractValid = $false
    if ($null -ne $data) {
        try {
            $null = Assert-D01TelemetryPayloadContract -Data $data
            $contractValid = $true
        } catch {
            if (-not $errorText) { $errorText = $_.Exception.Message }
        }
    }
    return [pscustomobject][ordered]@{
        captured_at_utc = Get-LabUtcTimestamp
        available = $null -ne $data
        duration_ms = [Int64]$watch.ElapsedMilliseconds
        after_sequence = $AfterSequence
        contract_valid = $contractValid
        endpoint_ownership = $ownershipAfter
        endpoint_ownership_before = $ownershipBefore
        endpoint_ownership_after = $ownershipAfter
        ownership_stable_across_request = $ownershipStable
        source_bound = $contractValid -and
            $ownershipStable
        candidate_ownership_id_sha256 = if (
            $Process.PSObject.Properties.Name -contains
                'd01_ownership_id_sha256') {
            [string]$Process.d01_ownership_id_sha256
        } else { '' }
        error_sha256 = if ($errorText) {
            Get-LabStringSha256 -Value $errorText
        } else { '' }
        data = $data
    }
}

function Assert-D01ExactPropertySet {
    param(
        [Parameter(Mandatory = $true)][object]$Object,
        [Parameter(Mandatory = $true)][string[]]$Expected,
        [Parameter(Mandatory = $true)][string]$Context
    )
    if ($null -eq $Object -or $Object -is [Array] -or
        $Object -is [ValueType] -or $Object -is [string]) {
        throw "$Context is not a JSON object"
    }
    [string[]]$actual = @($Object.PSObject.Properties.Name)
    [string[]]$wanted = @($Expected)
    [Array]::Sort($actual, [StringComparer]::Ordinal)
    [Array]::Sort($wanted, [StringComparer]::Ordinal)
    if (($actual -join "`n") -cne ($wanted -join "`n")) {
        throw "$Context property set is not exact"
    }
    return $true
}

function Assert-D01JsonInteger {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][string]$Context,
        [Int64]$Minimum = [Int64]::MinValue,
        [Int64]$Maximum = [Int64]::MaxValue
    )
    if ($Value -isnot [int] -and $Value -isnot [Int64]) {
        throw "$Context is not an exact JSON integer"
    }
    $number = [Int64]$Value
    if ($number -lt $Minimum -or $number -gt $Maximum) {
        throw "$Context integer is outside its contract"
    }
    return $number
}

function Get-D01EpochUnixNs {
    $ticks = [DateTime]::UtcNow.Ticks
    return [Int64](
        ([decimal]$ticks - [decimal]621355968000000000L) * 100
    )
}

function Get-D01OwnedProcessBindingEvidence {
    param(
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][string]$ExpectedPath,
        [switch]$RequireLive
    )

    $required = @(
        'd01_owner_nonce', 'd01_owner_role', 'd01_owner_pid',
        'd01_owner_creation_utc_ticks',
        'd01_owner_cim_creation_utc_ticks', 'd01_owner_path_sha256',
        'd01_owner_executable_sha256', 'd01_owner_sid_sha256',
        'd01_ownership_id_sha256'
    )
    if (@($required | Where-Object {
        $Process.PSObject.Properties.Name -notcontains $_
    }).Count -ne 0) {
        throw 'Candidate process lacks the retained ownership contract'
    }
    $liveExact = if ($RequireLive) {
        Test-D01OwnedProcessBinding -Process $Process `
            -ExpectedPath $ExpectedPath
    } else { $true }
    if (-not $liveExact) {
        throw 'Candidate process ownership was not exact at evidence boundary'
    }
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.d01-process-binding/v2'
        exact_at_boundary = [bool]$liveExact
        owner_role = [string]$Process.d01_owner_role
        run_nonce = [string]$Process.d01_owner_nonce
        process_id = [int]$Process.d01_owner_pid
        creation_utc_ticks =
            [Int64]$Process.d01_owner_creation_utc_ticks
        cim_creation_utc_ticks =
            [Int64]$Process.d01_owner_cim_creation_utc_ticks
        path_sha256 = [string]$Process.d01_owner_path_sha256
        executable_sha256 =
            [string]$Process.d01_owner_executable_sha256
        owner_sid_sha256 = [string]$Process.d01_owner_sid_sha256
        ownership_id_sha256 =
            [string]$Process.d01_ownership_id_sha256
        child_process_prevention =
            Get-D01JobContainmentEvidence -Process $Process
    }
}

function Assert-D01ProcessBindingEvidenceContract {
    param(
        [Parameter(Mandatory = $true)][object]$Binding,
        [Parameter(Mandatory = $true)][string]$Context
    )

    $null = Assert-D01ExactPropertySet -Object $Binding -Expected @(
        'schema', 'exact_at_boundary', 'owner_role', 'run_nonce',
        'process_id', 'creation_utc_ticks', 'cim_creation_utc_ticks',
        'path_sha256', 'executable_sha256', 'owner_sid_sha256',
        'ownership_id_sha256', 'child_process_prevention'
    ) -Context $Context
    if ($Binding.schema -isnot [string] -or
        [string]$Binding.schema -cne 'ese.v91.d01-process-binding/v2' -or
        $Binding.exact_at_boundary -isnot [bool] -or
        -not $Binding.exact_at_boundary -or
        $Binding.owner_role -isnot [string] -or
        [string]$Binding.owner_role -notin @('Coordinator', 'Source') -or
        $Binding.run_nonce -isnot [string] -or
        [string]$Binding.run_nonce -notmatch '^[0-9a-f]{32}$') {
        throw "$Context identity fields are not exact"
    }
    $null = Assert-D01JsonInteger -Value $Binding.process_id `
        -Context "$Context.process_id" -Minimum 1 -Maximum ([int]::MaxValue)
    $null = Assert-D01JsonInteger -Value $Binding.creation_utc_ticks `
        -Context "$Context.creation_utc_ticks" -Minimum 1
    $null = Assert-D01JsonInteger -Value $Binding.cim_creation_utc_ticks `
        -Context "$Context.cim_creation_utc_ticks" -Minimum 1
    foreach ($name in @(
        'path_sha256', 'executable_sha256', 'owner_sid_sha256',
        'ownership_id_sha256'
    )) {
        $value = $Binding.PSObject.Properties[$name].Value
        if ($value -isnot [string] -or
            [string]$value -cnotmatch '^[0-9a-f]{64}$') {
            throw "$Context.$name is not a lowercase SHA-256"
        }
    }
    $expectedOwnershipId = Get-LabStringSha256 -Value (
        '{0}|{1}|{2}|{3}|{4}|{5}|{6}|{7}' -f
        [string]$Binding.run_nonce, [string]$Binding.owner_role,
        [Int64]$Binding.process_id, [Int64]$Binding.creation_utc_ticks,
        [Int64]$Binding.cim_creation_utc_ticks,
        [string]$Binding.path_sha256,
        [string]$Binding.executable_sha256,
        [string]$Binding.owner_sid_sha256)
    if ([string]$Binding.ownership_id_sha256 -cne $expectedOwnershipId) {
        throw "$Context ownership digest is not canonical"
    }
    $childPrevention = $Binding.child_process_prevention
    $null = Assert-D01ExactPropertySet -Object $childPrevention -Expected @(
        'schema', 'mechanism', 'created_suspended',
        'assigned_before_resume', 'assigned_process_id',
        'active_process_limit', 'active_process_limit_enabled',
        'kill_on_job_close_enabled', 'total_processes_ever_assigned',
        'active_processes', 'total_terminated_processes', 'root_exited',
        'exact'
    ) -Context "$Context.child_process_prevention"
    foreach ($name in @(
        'created_suspended', 'assigned_before_resume',
        'active_process_limit_enabled', 'kill_on_job_close_enabled',
        'root_exited', 'exact'
    )) {
        $null = Assert-D01JsonBoolean `
            -Value $childPrevention.PSObject.Properties[$name].Value `
            -Context "$Context.child_process_prevention.$name"
    }
    foreach ($name in @(
        'assigned_process_id', 'active_process_limit',
        'total_processes_ever_assigned', 'active_processes',
        'total_terminated_processes'
    )) {
        $null = Assert-D01JsonInteger `
            -Value $childPrevention.PSObject.Properties[$name].Value `
            -Context "$Context.child_process_prevention.$name" -Minimum 0
    }
    if ([string]$childPrevention.schema -cne
            'ese.v91.d01-child-process-prevention/v1' -or
        [string]$childPrevention.mechanism -cne
            'windows-job-active-process-limit' -or
        -not [bool]$childPrevention.created_suspended -or
        -not [bool]$childPrevention.assigned_before_resume -or
        [Int64]$childPrevention.assigned_process_id -ne
            [Int64]$Binding.process_id -or
        [Int64]$childPrevention.active_process_limit -ne 1 -or
        -not [bool]$childPrevention.active_process_limit_enabled -or
        -not [bool]$childPrevention.kill_on_job_close_enabled -or
        [Int64]$childPrevention.total_processes_ever_assigned -ne 1 -or
        [Int64]$childPrevention.active_processes -ne 1 -or
        [Int64]$childPrevention.total_terminated_processes -ne 0 -or
        [bool]$childPrevention.root_exited -or
        -not [bool]$childPrevention.exact) {
        throw "$Context child-process prevention is not exact"
    }
    return $true
}

function New-D01ProductFailure {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet(
            'candidate-process-exit', 'telemetry-materialization',
            'A-forward', 'AAAA-silent-DROP', 'transfer-integrity',
            'network-isolation', 'UI-responsiveness',
            'unexpected-candidate-tcp-peer-connection'
        )][string]$FailureType,
        [Parameter(Mandatory = $true)][string]$DisplayMessage,
        [Parameter(Mandatory = $true)]
        [ValidateSet(
            'candidate-process', 'candidate-telemetry',
            'candidate-network', 'candidate-output'
        )][string]$SourceKind,
        [Parameter(Mandatory = $true)][Int64]$ObservedEpochUnixNs,
        [Parameter(Mandatory = $true)][Int64]$ArmBoundaryEpochUnixNs,
        [Parameter(Mandatory = $true)][object]$CandidateProcessBinding,
        [Parameter(Mandatory = $true)][bool]$CollectorOk,
        [Parameter(Mandatory = $true)][bool]$SourceBound,
        [Parameter(Mandatory = $true)][object]$Evidence
    )

    $null = Assert-D01ProcessBindingEvidenceContract `
        -Binding $CandidateProcessBinding `
        -Context 'product failure candidate_process_binding'
    if ($ArmBoundaryEpochUnixNs -le 0 -or
        $ObservedEpochUnixNs -lt $ArmBoundaryEpochUnixNs) {
        throw 'Product failure is not proven after the armed boundary'
    }
    if (-not $CollectorOk -or -not $SourceBound) {
        throw 'Product failure is not collector-complete and source-bound'
    }
    $evidenceJson = $Evidence | ConvertTo-Json -Depth 100 -Compress
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.d01-product-failure/v1'
        failure_type = $FailureType
        display_message = $DisplayMessage
        observed_epoch_unix_ns = $ObservedEpochUnixNs
        arm_boundary_epoch_unix_ns = $ArmBoundaryEpochUnixNs
        post_boundary = $true
        source_kind = $SourceKind
        collector_ok = $true
        source_bound = $true
        adjudicable = $true
        candidate_process_binding = $CandidateProcessBinding
        evidence_sha256 = Get-LabStringSha256 -Value $evidenceJson
    }
}

function Assert-D01ProductFailureContract {
    param(
        [Parameter(Mandatory = $true)][object]$Failure,
        [Parameter(Mandatory = $true)][Int64]$ArmBoundaryEpochUnixNs
    )

    $null = Assert-D01ExactPropertySet -Object $Failure -Expected @(
        'schema', 'failure_type', 'display_message',
        'observed_epoch_unix_ns', 'arm_boundary_epoch_unix_ns',
        'post_boundary', 'source_kind', 'collector_ok', 'source_bound',
        'adjudicable', 'candidate_process_binding', 'evidence_sha256'
    ) -Context 'product failure'
    if ($Failure.schema -isnot [string] -or
        [string]$Failure.schema -cne 'ese.v91.d01-product-failure/v1' -or
        $Failure.failure_type -isnot [string] -or
        [string]::IsNullOrWhiteSpace([string]$Failure.failure_type) -or
        $Failure.display_message -isnot [string] -or
        [string]::IsNullOrWhiteSpace([string]$Failure.display_message) -or
        $Failure.source_kind -isnot [string] -or
        [string]$Failure.source_kind -notin @(
            'candidate-process', 'candidate-telemetry',
            'candidate-network', 'candidate-output'
        ) -or
        $Failure.post_boundary -isnot [bool] -or
        -not $Failure.post_boundary -or
        $Failure.collector_ok -isnot [bool] -or
        -not $Failure.collector_ok -or
        $Failure.source_bound -isnot [bool] -or
        -not $Failure.source_bound -or
        $Failure.adjudicable -isnot [bool] -or
        -not $Failure.adjudicable -or
        $Failure.evidence_sha256 -isnot [string] -or
        [string]$Failure.evidence_sha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'Product failure field types are not exact'
    }
    $observed = Assert-D01JsonInteger `
        -Value $Failure.observed_epoch_unix_ns `
        -Context 'product failure observed_epoch_unix_ns' -Minimum 1
    $boundary = Assert-D01JsonInteger `
        -Value $Failure.arm_boundary_epoch_unix_ns `
        -Context 'product failure arm_boundary_epoch_unix_ns' -Minimum 1
    if ($boundary -ne $ArmBoundaryEpochUnixNs -or
        $observed -lt $boundary) {
        throw 'Product failure boundary is not exact'
    }
    $null = Assert-D01ProcessBindingEvidenceContract `
        -Binding $Failure.candidate_process_binding `
        -Context 'product failure candidate_process_binding'
    return $true
}

function Assert-D01ProductFailureEvidenceHashBinding {
    param(
        [Parameter(Mandatory = $true)][object[]]$ProductFailures,
        [Parameter(Mandatory = $true)][object]$Evidence,
        [Parameter(Mandatory = $true)][string]$ExpectedFailureType,
        [Parameter(Mandatory = $true)]
        [ValidateSet(
            'candidate-process', 'candidate-telemetry',
            'candidate-network', 'candidate-output'
        )][string]$ExpectedSourceKind,
        [Parameter(Mandatory = $true)][object]$CandidateProcessBinding,
        [switch]$RequireEvidenceObservedEpochMatch
    )
    $null = Assert-D01ProcessBindingEvidenceContract `
        -Binding $CandidateProcessBinding `
        -Context 'positive evidence hash candidate binding'
    $expectedOwnershipId =
        [string]$CandidateProcessBinding.ownership_id_sha256
    $matches = @($ProductFailures | Where-Object {
        [string]$_.failure_type -ceq $ExpectedFailureType -and
        [string]$_.source_kind -ceq $ExpectedSourceKind -and
        [string]$_.candidate_process_binding.ownership_id_sha256 -ceq
            $expectedOwnershipId
    })
    if ($matches.Count -ne 1) {
        throw 'Positive evidence does not map to exactly one typed failure'
    }
    $expectedEvidenceHash = Get-LabStringSha256 -Value (
        $Evidence | ConvertTo-Json -Depth 100 -Compress)
    $evidenceObservedEpoch = Assert-D01JsonInteger `
        -Value $Evidence.observed_epoch_unix_ns `
        -Context 'positive evidence observed_epoch_unix_ns' -Minimum 1
    if ([string]$matches[0].evidence_sha256 -cne $expectedEvidenceHash -or
        ($RequireEvidenceObservedEpochMatch -and
            [Int64]$matches[0].observed_epoch_unix_ns -ne
                $evidenceObservedEpoch)) {
        throw 'Typed failure hash/timestamp does not bind to positive evidence'
    }
    return $true
}

function Assert-D01JsonStringValue {
    param(
        [AllowEmptyString()][Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][string]$Context,
        [AllowEmptyString()][string]$Pattern = ''
    )
    if ($Value -isnot [string]) {
        throw "$Context is not an exact JSON string"
    }
    if ($Pattern -and [string]$Value -cnotmatch $Pattern) {
        throw "$Context does not match its exact string contract"
    }
    return [string]$Value
}

function Assert-D01JsonBoolean {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][string]$Context
    )
    if ($Value -isnot [bool]) {
        throw "$Context is not an exact JSON boolean"
    }
    return [bool]$Value
}

function Assert-D01JsonStringArray {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][string]$Context,
        [switch]$RequireUnique
    )
    if ($Value -isnot [Array]) {
        throw "$Context is not an exact JSON array"
    }
    [string[]]$members = @()
    foreach ($member in @($Value)) {
        if ($member -isnot [string]) {
            throw "$Context contains a non-string member"
        }
        $members += [string]$member
    }
    if ($RequireUnique -and
        @($members | Sort-Object -Unique).Count -ne $members.Count) {
        throw "$Context contains duplicate members"
    }
    return $members
}

function Assert-D01HostIdentityEvidenceContract {
    param(
        [Parameter(Mandatory = $true)][object]$Identity,
        [Parameter(Mandatory = $true)][string]$Context
    )
    $null = Assert-D01ExactPropertySet -Object $Identity -Expected @(
        'machine_id_sha256', 'user_sid_sha256', 'account_name_sha256',
        'profile_path_sha256', 'builtin_or_service',
        'disposable_account_operator_attested'
    ) -Context $Context
    foreach ($name in @(
        'machine_id_sha256', 'user_sid_sha256', 'account_name_sha256',
        'profile_path_sha256'
    )) {
        $null = Assert-D01JsonStringValue `
            -Value $Identity.PSObject.Properties[$name].Value `
            -Context "$Context.$name" -Pattern '^[0-9a-f]{64}$'
    }
    $null = Assert-D01JsonBoolean -Value $Identity.builtin_or_service `
        -Context "$Context.builtin_or_service"
    $null = Assert-D01JsonBoolean `
        -Value $Identity.disposable_account_operator_attested `
        -Context "$Context.disposable_account_operator_attested"
    return $true
}

function Assert-D01AdapterEvidenceContract {
    param(
        [Parameter(Mandatory = $true)][object]$Adapter,
        [Parameter(Mandatory = $true)][string]$Context
    )
    $null = Assert-D01ExactPropertySet -Object $Adapter -Expected @(
        'context', 'interface_index', 'interface_id',
        'interface_guid_sha256', 'interface_name_sha256',
        'interface_description_sha256', 'status', 'hardware_interface',
        'virtual', 'overlay_or_vpn_like', 'physical_nonvirtual'
    ) -Context $Context
    $null = Assert-D01JsonInteger -Value $Adapter.interface_index `
        -Context "$Context.interface_index" -Minimum 1 `
        -Maximum ([int]::MaxValue)
    foreach ($name in @(
        'context', 'interface_id', 'status'
    )) {
        $null = Assert-D01JsonStringValue `
            -Value $Adapter.PSObject.Properties[$name].Value `
            -Context "$Context.$name"
    }
    foreach ($name in @(
        'interface_guid_sha256', 'interface_name_sha256',
        'interface_description_sha256'
    )) {
        $null = Assert-D01JsonStringValue `
            -Value $Adapter.PSObject.Properties[$name].Value `
            -Context "$Context.$name" -Pattern '^[0-9a-f]{64}$'
    }
    foreach ($name in @(
        'hardware_interface', 'virtual', 'overlay_or_vpn_like',
        'physical_nonvirtual'
    )) {
        $null = Assert-D01JsonBoolean `
            -Value $Adapter.PSObject.Properties[$name].Value `
            -Context "$Context.$name"
    }
    return $true
}

function Assert-D01AssignedAddressEvidenceContract {
    param(
        [Parameter(Mandatory = $true)][object]$Assigned,
        [Parameter(Mandatory = $true)][string]$Context
    )
    $null = Assert-D01ExactPropertySet -Object $Assigned -Expected @(
        'address', 'address_class', 'interface_index', 'prefix_length',
        'network_prefix', 'adapter'
    ) -Context $Context
    foreach ($name in @('address', 'address_class', 'network_prefix')) {
        $null = Assert-D01JsonStringValue `
            -Value $Assigned.PSObject.Properties[$name].Value `
            -Context "$Context.$name"
    }
    $null = Assert-D01JsonInteger -Value $Assigned.interface_index `
        -Context "$Context.interface_index" -Minimum 1 `
        -Maximum ([int]::MaxValue)
    $null = Assert-D01JsonInteger -Value $Assigned.prefix_length `
        -Context "$Context.prefix_length" -Minimum 0 -Maximum 128
    $null = Assert-D01AdapterEvidenceContract -Adapter $Assigned.adapter `
        -Context "$Context.adapter"
    return $true
}

function Assert-D01RouteEvidenceContract {
    param(
        [Parameter(Mandatory = $true)][object]$Route,
        [Parameter(Mandatory = $true)][string]$Context
    )
    $null = Assert-D01ExactPropertySet -Object $Route -Expected @(
        'available', 'remote_address', 'source_address', 'source_class',
        'interface_index', 'next_hop', 'next_hop_class', 'on_link',
        'adapter', 'collector_ok', 'error_sha256'
    ) -Context $Context
    foreach ($name in @('available', 'on_link', 'collector_ok')) {
        $null = Assert-D01JsonBoolean `
            -Value $Route.PSObject.Properties[$name].Value `
            -Context "$Context.$name"
    }
    foreach ($name in @(
        'remote_address', 'source_address', 'source_class', 'next_hop',
        'next_hop_class', 'error_sha256'
    )) {
        $null = Assert-D01JsonStringValue `
            -Value $Route.PSObject.Properties[$name].Value `
            -Context "$Context.$name"
    }
    if (-not $Route.available -or -not $Route.collector_ok) {
        throw "$Context is not an available exact route"
    }
    $null = Assert-D01JsonInteger -Value $Route.interface_index `
        -Context "$Context.interface_index" -Minimum 1 `
        -Maximum ([int]::MaxValue)
    $null = Assert-D01AdapterEvidenceContract -Adapter $Route.adapter `
        -Context "$Context.adapter"
    return $true
}

function Assert-D01FirewallRuleEvidenceContract {
    param(
        [Parameter(Mandatory = $true)][object]$Rule,
        [Parameter(Mandatory = $true)][string]$Context
    )
    $null = Assert-D01ExactPropertySet -Object $Rule -Expected @(
        'schema', 'captured_at_utc', 'rule_name', 'display_name',
        'rule_count', 'action', 'direction', 'enabled', 'profile',
        'protocol', 'local_port', 'remote_port', 'local_addresses',
        'remote_addresses', 'program', 'interface_alias',
        'interface_type', 'service', 'authentication', 'encryption',
        'canonical_sha256', 'exact'
    ) -Context $Context
    foreach ($name in @(
        'schema', 'captured_at_utc', 'rule_name', 'display_name', 'action',
        'direction', 'profile', 'protocol', 'local_port', 'remote_port',
        'program', 'service', 'authentication', 'encryption'
    )) {
        $null = Assert-D01JsonStringValue `
            -Value $Rule.PSObject.Properties[$name].Value `
            -Context "$Context.$name"
    }
    if ([string]$Rule.schema -cne
        'ese.v91.d01-firewall-rule-evidence/v2') {
        throw "$Context schema is not exact"
    }
    $null = Assert-D01JsonStringValue -Value $Rule.canonical_sha256 `
        -Context "$Context.canonical_sha256" -Pattern '^[0-9a-f]{64}$'
    $null = Assert-D01JsonInteger -Value $Rule.rule_count `
        -Context "$Context.rule_count" -Minimum 0 -Maximum 1
    foreach ($name in @('enabled', 'exact')) {
        $null = Assert-D01JsonBoolean `
            -Value $Rule.PSObject.Properties[$name].Value `
            -Context "$Context.$name"
    }
    foreach ($name in @(
        'local_addresses', 'remote_addresses', 'interface_alias',
        'interface_type'
    )) {
        $null = Assert-D01JsonStringArray `
            -Value $Rule.PSObject.Properties[$name].Value `
            -Context "$Context.$name" -RequireUnique
    }
    return $true
}

function Assert-D01SourceFirewallFixtureSemantics {
    param(
        [Parameter(Mandatory = $true)][object]$Firewall,
        [Parameter(Mandatory = $true)][object]$ProcessBinding,
        [Parameter(Mandatory = $true)][string]$RunNonce,
        [Parameter(Mandatory = $true)][string]$SourceLocalIPv4,
        [Parameter(Mandatory = $true)][string]$SourceIPv6,
        [Parameter(Mandatory = $true)][string]$CoordinatorIPv6,
        [Parameter(Mandatory = $true)][string[]]$AllowedIPv4Remotes,
        [Parameter(Mandatory = $true)][int]$SourcePort
    )

    $v4 = $Firewall.ipv4_allow
    $v6 = $Firewall.ipv6_drop
    [string[]]$expectedV4Remotes = @($AllowedIPv4Remotes |
        ForEach-Object { Get-D01NormalizedIp -Address $_ } |
        Sort-Object -Unique)
    [string[]]$actualV4Remotes = @($v4.remote_addresses |
        ForEach-Object { Get-D01NormalizedIp -Address ([string]$_) } |
        Sort-Object -Unique)
    [string[]]$actualV4Locals = @($v4.local_addresses |
        ForEach-Object { Get-D01NormalizedIp -Address ([string]$_) } |
        Sort-Object -Unique)
    [string[]]$actualV6Locals = @($v6.local_addresses |
        ForEach-Object { Get-D01NormalizedIp -Address ([string]$_) } |
        Sort-Object -Unique)
    [string[]]$actualV6Remotes = @($v6.remote_addresses |
        ForEach-Object { Get-D01NormalizedIp -Address ([string]$_) } |
        Sort-Object -Unique)
    $v4ProgramPathHash = Get-LabStringSha256 -Value (
        [IO.Path]::GetFullPath([string]$v4.program).ToLowerInvariant())
    $commonExact = {
        param($Rule, [string]$Action, [string]$NameSuffix)
        $displaySuffix = if ($Action -ceq 'Allow') {
            ' v4-allow'
        } else { ' v6-drop' }
        return [bool]$Rule.exact -and [bool]$Rule.enabled -and
            [Int64]$Rule.rule_count -eq 1 -and
            [string]$Rule.rule_name -ceq
                ('ESE_V91_D01_' + $RunNonce + $NameSuffix) -and
            [string]$Rule.display_name -ceq
                ('eSE V91 D01 ' + $RunNonce + $displaySuffix) -and
            [string]$Rule.direction -ceq 'Inbound' -and
            [string]$Rule.action -ceq $Action -and
            [string]$Rule.profile -ceq 'Any' -and
            ([string]$Rule.protocol).ToLowerInvariant() -in @('6', 'tcp') -and
            [string]$Rule.local_port -ceq [string]$SourcePort -and
            [string]$Rule.remote_port -ceq 'Any' -and
            @($Rule.interface_alias).Count -eq 1 -and
            [string]$Rule.interface_alias[0] -ceq 'Any' -and
            @($Rule.interface_type).Count -eq 1 -and
            [string]$Rule.interface_type[0] -ceq 'Any' -and
            [string]$Rule.service -ceq 'Any' -and
            [string]$Rule.authentication -ceq 'NotRequired' -and
            [string]$Rule.encryption -ceq 'NotRequired'
    }
    $v4Exact = & $commonExact $v4 'Allow' '_V4_ALLOW'
    $v6Exact = & $commonExact $v6 'Block' '_V6_DROP'
    if (-not [bool]$Firewall.rules_created -or
        -not [bool]$Firewall.exact -or
        [string]$Firewall.AAAA_failure_mode -cne
            'controlled silent inbound DROP' -or
        -not $v4Exact -or -not $v6Exact -or
        $actualV4Locals.Count -ne 1 -or
        [string]$actualV4Locals[0] -cne
            (Get-D01NormalizedIp -Address $SourceLocalIPv4) -or
        $actualV4Remotes.Count -ne $expectedV4Remotes.Count -or
        ($actualV4Remotes -join "`n") -cne
            ($expectedV4Remotes -join "`n") -or
        $v4ProgramPathHash -cne [string]$ProcessBinding.path_sha256 -or
        $actualV6Locals.Count -ne 1 -or
        [string]$actualV6Locals[0] -cne
            (Get-D01NormalizedIp -Address $SourceIPv6) -or
        $actualV6Remotes.Count -ne 1 -or
        [string]$actualV6Remotes[0] -cne
            (Get-D01NormalizedIp -Address $CoordinatorIPv6) -or
        [string]$v6.program -cne 'Any' -or
        [string]$v4.canonical_sha256 -ceq
            [string]$v6.canonical_sha256) {
        throw 'Source firewall fixture semantics are not exact'
    }
    return $true
}

function Assert-D01AccountRegistryPostcheckContract {
    param(
        [Parameter(Mandatory = $true)][object]$Postcheck,
        [Parameter(Mandatory = $true)][string]$Context
    )
    $null = Assert-D01ExactPropertySet -Object $Postcheck -Expected @(
        'schema', 'collector_ok', 'baseline', 'post_state',
        'global_firewall_baseline', 'global_firewall_post_state',
        'bound_sid_unchanged', 'run_subtree_unchanged',
        'ed2k_subtree_unchanged', 'global_firewall_unchanged',
        'emule_autostart_absent_after', 'ed2k_subtree_absent_after',
        'destructive_restore_attempted',
        'nonce_owned_firewall_cleanup_only', 'safe_to_pass',
        'error_sha256'
    ) -Context $Context
    $null = Assert-D01JsonStringValue -Value $Postcheck.schema `
        -Context "$Context.schema"
    $null = Assert-D01JsonStringValue -Value $Postcheck.error_sha256 `
        -Context "$Context.error_sha256"
    if ([string]$Postcheck.schema -cne
        'ese.v91.d01-account-registry-postcheck/v1') {
        throw "$Context schema is not exact"
    }
    foreach ($name in @(
        'collector_ok', 'bound_sid_unchanged', 'run_subtree_unchanged',
        'ed2k_subtree_unchanged', 'global_firewall_unchanged',
        'emule_autostart_absent_after', 'ed2k_subtree_absent_after',
        'destructive_restore_attempted',
        'nonce_owned_firewall_cleanup_only', 'safe_to_pass'
    )) {
        $null = Assert-D01JsonBoolean `
            -Value $Postcheck.PSObject.Properties[$name].Value `
            -Context "$Context.$name"
    }
    $assertRegistrySubtree = {
        param([object]$Snapshot, [string]$SnapshotContext)
        $null = Assert-D01ExactPropertySet -Object $Snapshot -Expected @(
            'schema', 'path_sha256', 'exists', 'node_count', 'value_count',
            'tracked_root_value_count', 'canonical_sha256'
        ) -Context $SnapshotContext
        foreach ($name in @('schema', 'path_sha256', 'canonical_sha256')) {
            $null = Assert-D01JsonStringValue `
                -Value $Snapshot.PSObject.Properties[$name].Value `
                -Context "$SnapshotContext.$name"
        }
        $null = Assert-D01JsonBoolean -Value $Snapshot.exists `
            -Context "$SnapshotContext.exists"
        foreach ($name in @(
            'node_count', 'value_count', 'tracked_root_value_count'
        )) {
            $null = Assert-D01JsonInteger `
                -Value $Snapshot.PSObject.Properties[$name].Value `
                -Context "$SnapshotContext.$name" -Minimum 0
        }
        if ([string]$Snapshot.schema -cne
                'ese.v91.d01-registry-subtree/v1' -or
            [string]$Snapshot.path_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            [string]$Snapshot.canonical_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            [int]$Snapshot.tracked_root_value_count -gt
                [int]$Snapshot.value_count -or
            ([bool]$Snapshot.exists -and
                [int]$Snapshot.node_count -lt 1) -or
            (-not [bool]$Snapshot.exists -and (
                [int]$Snapshot.node_count -ne 0 -or
                [int]$Snapshot.value_count -ne 0 -or
                [int]$Snapshot.tracked_root_value_count -ne 0 -or
                [string]$Snapshot.canonical_sha256 -cne
                    (Get-LabStringSha256 -Value 'absent')))) {
            throw "$SnapshotContext registry snapshot is contradictory"
        }
    }
    $assertAccountSnapshot = {
        param([object]$Snapshot, [string]$SnapshotContext)
        $null = Assert-D01ExactPropertySet -Object $Snapshot -Expected @(
            'schema', 'captured_at_utc', 'user_sid_sha256', 'run_subtree',
            'ed2k_subtree', 'emule_autostart_absent',
            'ed2k_subtree_absent'
        ) -Context $SnapshotContext
        foreach ($name in @('schema', 'captured_at_utc', 'user_sid_sha256')) {
            $null = Assert-D01JsonStringValue `
                -Value $Snapshot.PSObject.Properties[$name].Value `
                -Context "$SnapshotContext.$name"
        }
        foreach ($name in @(
            'emule_autostart_absent', 'ed2k_subtree_absent'
        )) {
            $null = Assert-D01JsonBoolean `
                -Value $Snapshot.PSObject.Properties[$name].Value `
                -Context "$SnapshotContext.$name"
        }
        & $assertRegistrySubtree $Snapshot.run_subtree `
            "$SnapshotContext.run_subtree"
        & $assertRegistrySubtree $Snapshot.ed2k_subtree `
            "$SnapshotContext.ed2k_subtree"
        $computedAutostartAbsent =
            [int]$Snapshot.run_subtree.tracked_root_value_count -eq 0
        $computedEd2kAbsent = -not [bool]$Snapshot.ed2k_subtree.exists
        if ([string]$Snapshot.schema -cne
                'ese.v91.d01-account-registry-snapshot/v1' -or
            [string]$Snapshot.user_sid_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            [bool]$Snapshot.emule_autostart_absent -ne
                $computedAutostartAbsent -or
            [bool]$Snapshot.ed2k_subtree_absent -ne $computedEd2kAbsent) {
            throw "$SnapshotContext account snapshot is contradictory"
        }
    }
    $assertGlobalFirewallSnapshot = {
        param([object]$Snapshot, [string]$SnapshotContext)
        [string[]]$categoryNames = @(
            'rules', 'port_filters', 'application_filters',
            'address_filters', 'interface_filters',
            'interface_type_filters', 'service_filters', 'security_filters'
        )
        $null = Assert-D01ExactPropertySet -Object $Snapshot -Expected @(
            'schema', 'captured_at_utc', 'policy_store', 'privacy_safe',
            'categories', 'canonical_sha256'
        ) -Context $SnapshotContext
        foreach ($name in @(
            'schema', 'captured_at_utc', 'policy_store', 'canonical_sha256'
        )) {
            $null = Assert-D01JsonStringValue `
                -Value $Snapshot.PSObject.Properties[$name].Value `
                -Context "$SnapshotContext.$name"
        }
        $null = Assert-D01JsonBoolean -Value $Snapshot.privacy_safe `
            -Context "$SnapshotContext.privacy_safe"
        $null = Assert-D01ExactPropertySet -Object $Snapshot.categories `
            -Expected $categoryNames -Context "$SnapshotContext.categories"
        [string[]]$aggregate = @()
        foreach ($name in $categoryNames) {
            $category = $Snapshot.categories.PSObject.Properties[$name].Value
            $null = Assert-D01ExactPropertySet -Object $category -Expected @(
                'item_count', 'canonical_sha256'
            ) -Context "$SnapshotContext.categories.$name"
            $count = Assert-D01JsonInteger -Value $category.item_count `
                -Context "$SnapshotContext.categories.$name.item_count" `
                -Minimum 1
            $null = Assert-D01JsonStringValue `
                -Value $category.canonical_sha256 `
                -Context "$SnapshotContext.categories.$name.canonical_sha256" `
                -Pattern '^[0-9a-f]{64}$'
            $aggregate += ('{0}|{1}|{2}' -f $name, $count,
                [string]$category.canonical_sha256)
        }
        $computedCanonical = Get-LabStringSha256 -Value ($aggregate -join "`n")
        if ([string]$Snapshot.schema -cne
                'ese.v91.d01-global-firewall-snapshot/v1' -or
            [string]$Snapshot.policy_store -cne 'ActiveStore' -or
            -not [bool]$Snapshot.privacy_safe -or
            [string]$Snapshot.canonical_sha256 -cne $computedCanonical) {
            throw "$SnapshotContext global firewall snapshot is contradictory"
        }
    }
    & $assertAccountSnapshot $Postcheck.baseline "$Context.baseline"
    & $assertAccountSnapshot $Postcheck.post_state "$Context.post_state"
    & $assertGlobalFirewallSnapshot $Postcheck.global_firewall_baseline `
        "$Context.global_firewall_baseline"
    & $assertGlobalFirewallSnapshot $Postcheck.global_firewall_post_state `
        "$Context.global_firewall_post_state"
    $computedBoundSidUnchanged =
        [string]$Postcheck.baseline.user_sid_sha256 -ceq
        [string]$Postcheck.post_state.user_sid_sha256
    $computedRunUnchanged = Test-D01RegistrySubtreeSnapshotEqual `
        -Left $Postcheck.baseline.run_subtree `
        -Right $Postcheck.post_state.run_subtree
    $computedEd2kUnchanged = Test-D01RegistrySubtreeSnapshotEqual `
        -Left $Postcheck.baseline.ed2k_subtree `
        -Right $Postcheck.post_state.ed2k_subtree
    $computedFirewallUnchanged =
        [string]$Postcheck.global_firewall_baseline.canonical_sha256 -ceq
        [string]$Postcheck.global_firewall_post_state.canonical_sha256
    $computedSafe = $computedBoundSidUnchanged -and
        $computedRunUnchanged -and $computedEd2kUnchanged -and
        $computedFirewallUnchanged -and
        [bool]$Postcheck.post_state.emule_autostart_absent -and
        [bool]$Postcheck.post_state.ed2k_subtree_absent -and
        -not [bool]$Postcheck.destructive_restore_attempted -and
        [bool]$Postcheck.nonce_owned_firewall_cleanup_only
    if (-not [bool]$Postcheck.collector_ok -or
        [bool]$Postcheck.bound_sid_unchanged -ne
            $computedBoundSidUnchanged -or
        [bool]$Postcheck.run_subtree_unchanged -ne $computedRunUnchanged -or
        [bool]$Postcheck.ed2k_subtree_unchanged -ne
            $computedEd2kUnchanged -or
        [bool]$Postcheck.global_firewall_unchanged -ne
            $computedFirewallUnchanged -or
        [bool]$Postcheck.emule_autostart_absent_after -ne
            [bool]$Postcheck.post_state.emule_autostart_absent -or
        [bool]$Postcheck.ed2k_subtree_absent_after -ne
            [bool]$Postcheck.post_state.ed2k_subtree_absent -or
        [bool]$Postcheck.safe_to_pass -ne $computedSafe -or
        -not $computedSafe -or [string]$Postcheck.error_sha256 -cne '') {
        throw "$Context is not safe to pass"
    }
    return $true
}

function Assert-D01HostsFilePostcheckContract {
    param(
        [Parameter(Mandatory = $true)][object]$Postcheck,
        [Parameter(Mandatory = $true)][string]$Context
    )
    $null = Assert-D01ExactPropertySet -Object $Postcheck -Expected @(
        'schema', 'collector_ok', 'baseline', 'post_state', 'unchanged',
        'safe_to_pass', 'error_sha256'
    ) -Context $Context
    $null = Assert-D01JsonStringValue -Value $Postcheck.schema `
        -Context "$Context.schema"
    $null = Assert-D01JsonStringValue -Value $Postcheck.error_sha256 `
        -Context "$Context.error_sha256"
    foreach ($name in @('collector_ok', 'unchanged', 'safe_to_pass')) {
        $null = Assert-D01JsonBoolean `
            -Value $Postcheck.PSObject.Properties[$name].Value `
            -Context "$Context.$name"
    }
    foreach ($snapshotName in @('baseline', 'post_state')) {
        $snapshot = $Postcheck.PSObject.Properties[$snapshotName].Value
        $null = Assert-D01ExactPropertySet -Object $snapshot -Expected @(
            'schema', 'path_sha256', 'length', 'sha256',
            'immutable_read_lock_held'
        ) -Context "$Context.$snapshotName"
        if ([string]$snapshot.schema -cne
                'ese.v91.d01-hosts-file-snapshot/v1' -or
            [string]$snapshot.path_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            [string]$snapshot.sha256 -cnotmatch '^[0-9a-f]{64}$') {
            throw "$Context.$snapshotName identity is not exact"
        }
        $null = Assert-D01JsonInteger -Value $snapshot.length `
            -Context "$Context.$snapshotName.length" -Minimum 0
        $null = Assert-D01JsonBoolean `
            -Value $snapshot.immutable_read_lock_held `
            -Context "$Context.$snapshotName.immutable_read_lock_held"
        if (-not [bool]$snapshot.immutable_read_lock_held) {
            throw "$Context.$snapshotName was not immutably locked"
        }
    }
    $computedUnchanged =
        [string]$Postcheck.baseline.path_sha256 -ceq
            [string]$Postcheck.post_state.path_sha256 -and
        [Int64]$Postcheck.baseline.length -eq
            [Int64]$Postcheck.post_state.length -and
        [string]$Postcheck.baseline.sha256 -ceq
            [string]$Postcheck.post_state.sha256
    if ([string]$Postcheck.schema -cne
            'ese.v91.d01-hosts-file-postcheck/v1' -or
        -not [bool]$Postcheck.collector_ok -or
        [bool]$Postcheck.unchanged -ne $computedUnchanged -or
        [bool]$Postcheck.safe_to_pass -ne $computedUnchanged -or
        -not $computedUnchanged -or
        [string]$Postcheck.error_sha256 -cne '') {
        throw "$Context is not safe to pass"
    }
    return $true
}

function Assert-D01TerminalOwnershipContract {
    param(
        [Parameter(Mandatory = $true)][object]$Census,
        [Parameter(Mandatory = $true)][string]$Context
    )
    $null = Assert-D01ExactPropertySet -Object $Census -Expected @(
        'schema', 'collected_at_utc', 'role', 'collector_ok', 'process_id',
        'process_exited', 'descendants_clear', 'remaining_tcp_count',
        'remaining_udp_count', 'remaining_tcp', 'remaining_udp',
        'all_clear', 'error_sha256'
    ) -Context $Context
    foreach ($name in @(
        'schema', 'collected_at_utc', 'role', 'error_sha256'
    )) {
        $null = Assert-D01JsonStringValue `
            -Value $Census.PSObject.Properties[$name].Value `
            -Context "$Context.$name"
    }
    foreach ($name in @(
        'collector_ok', 'process_exited', 'descendants_clear', 'all_clear'
    )) {
        $null = Assert-D01JsonBoolean `
            -Value $Census.PSObject.Properties[$name].Value `
            -Context "$Context.$name"
    }
    foreach ($name in @('remaining_tcp_count', 'remaining_udp_count')) {
        $null = Assert-D01JsonInteger `
            -Value $Census.PSObject.Properties[$name].Value `
            -Context "$Context.$name" -Minimum 0
    }
    if ($Census.remaining_tcp -isnot [Array] -or
        $Census.remaining_udp -isnot [Array]) {
        throw "$Context remaining socket fields are not arrays"
    }
    if ([string]$Census.schema -cne
            'ese.v91.d01-terminal-ownership-census/v1' -or
        [string]$Census.role -notin @('Coordinator', 'Source') -or
        -not [bool]$Census.collector_ok -or
        -not [bool]$Census.process_exited -or
        -not [bool]$Census.descendants_clear -or
        [Int64]$Census.remaining_tcp_count -ne 0 -or
        [Int64]$Census.remaining_udp_count -ne 0 -or
        @($Census.remaining_tcp).Count -ne 0 -or
        @($Census.remaining_udp).Count -ne 0 -or
        -not [bool]$Census.all_clear -or
        [string]$Census.error_sha256 -cne '') {
        throw "$Context is not clear"
    }
    return $true
}

function Assert-D01RunCoordinationContract {
    param([Parameter(Mandatory = $true)][object]$Run)
    $null = Assert-D01ExactPropertySet -Object $Run -Expected @(
        'schema', 'case_id', 'run_nonce', 'created_at_utc',
        'controlled_fixture_acknowledged', 'operator_identity',
        'candidate', 'coordinator', 'fixture'
    ) -Context 'run.json'
    foreach ($name in @('schema', 'case_id', 'run_nonce', 'created_at_utc')) {
        $null = Assert-D01JsonStringValue `
            -Value $Run.PSObject.Properties[$name].Value `
            -Context "run.json.$name"
    }
    if ([string]$Run.schema -cne 'ese.v91.d01-run/v3' -or
        [string]$Run.run_nonce -cnotmatch '^[0-9a-f]{32}$') {
        throw 'run.json identity contract is not exact'
    }
    $ack = Assert-D01JsonBoolean `
        -Value $Run.controlled_fixture_acknowledged `
        -Context 'run.json.controlled_fixture_acknowledged'
    if (-not $ack) { throw 'run.json fixture acknowledgement is false' }
    $null = Assert-D01ExactPropertySet -Object $Run.operator_identity `
        -Expected @(
            'coordinator', 'expected_source_machine_id_sha256',
            'expected_source_user_sid_sha256'
        ) -Context 'run.json.operator_identity'
    $null = Assert-D01HostIdentityEvidenceContract `
        -Identity $Run.operator_identity.coordinator `
        -Context 'run.json.operator_identity.coordinator'
    foreach ($name in @(
        'expected_source_machine_id_sha256',
        'expected_source_user_sid_sha256'
    )) {
        $null = Assert-D01JsonStringValue `
            -Value $Run.operator_identity.PSObject.Properties[$name].Value `
            -Context "run.json.operator_identity.$name" `
            -Pattern '^[0-9a-f]{64}$'
    }
    $null = Assert-D01ExactPropertySet -Object $Run.candidate -Expected @(
        'commit', 'emule_sha256', 'ese_server_sha256',
        'build_info_sha256', 'package_zip_sha256',
        'extracted_manifest_sha256', 'zip_manifest_sha256'
    ) -Context 'run.json.candidate'
    $null = Assert-D01JsonStringValue -Value $Run.candidate.commit `
        -Context 'run.json.candidate.commit' -Pattern '^[0-9a-f]{40}$'
    foreach ($name in @(
        'emule_sha256', 'ese_server_sha256', 'build_info_sha256',
        'package_zip_sha256', 'extracted_manifest_sha256',
        'zip_manifest_sha256'
    )) {
        $null = Assert-D01JsonStringValue `
            -Value $Run.candidate.PSObject.Properties[$name].Value `
            -Context "run.json.candidate.$name" `
            -Pattern '^[0-9a-f]{64}$'
    }
    $null = Assert-D01ExactPropertySet -Object $Run.coordinator `
        -Expected @(
            'machine_id_sha256', 'coordinator_local_ipv4',
            'coordinator_public_ipv4', 'coordinator_public_ipv4_is_nat',
            'coordinator_ipv6', 'route_to_source_public_ipv4',
            'route_to_source_ipv6', 'native_physical',
            'overlay_vpn_proxy_absent'
        ) -Context 'run.json.coordinator'
    $null = Assert-D01JsonStringValue `
        -Value $Run.coordinator.machine_id_sha256 `
        -Context 'run.json.coordinator.machine_id_sha256' `
        -Pattern '^[0-9a-f]{64}$'
    foreach ($name in @(
        'coordinator_public_ipv4_is_nat', 'native_physical',
        'overlay_vpn_proxy_absent'
    )) {
        $null = Assert-D01JsonBoolean `
            -Value $Run.coordinator.PSObject.Properties[$name].Value `
            -Context "run.json.coordinator.$name"
    }
    $null = Assert-D01AssignedAddressEvidenceContract `
        -Assigned $Run.coordinator.coordinator_local_ipv4 `
        -Context 'run.json.coordinator.coordinator_local_ipv4'
    $null = Assert-D01AssignedAddressEvidenceContract `
        -Assigned $Run.coordinator.coordinator_ipv6 `
        -Context 'run.json.coordinator.coordinator_ipv6'
    $null = Assert-D01JsonStringValue `
        -Value $Run.coordinator.coordinator_public_ipv4 `
        -Context 'run.json.coordinator.coordinator_public_ipv4'
    $null = Assert-D01RouteEvidenceContract `
        -Route $Run.coordinator.route_to_source_public_ipv4 `
        -Context 'run.json.coordinator.route_to_source_public_ipv4'
    $null = Assert-D01RouteEvidenceContract `
        -Route $Run.coordinator.route_to_source_ipv6 `
        -Context 'run.json.coordinator.route_to_source_ipv6'
    $fixtureFields = @(
        'hostname', 'hostname_sha256', 'source_public_ipv4',
        'source_local_ipv4', 'source_ipv6', 'coordinator_public_ipv4',
        'coordinator_local_ipv4', 'coordinator_ipv6', 'source_tcp_port',
        'source_udp_port', 'source_web_port', 'downloader_tcp_port',
        'downloader_udp_port', 'downloader_web_port', 'file_size_bytes'
    )
    $null = Assert-D01ExactPropertySet -Object $Run.fixture `
        -Expected $fixtureFields -Context 'run.json.fixture'
    foreach ($name in @(
        'hostname', 'source_public_ipv4', 'source_local_ipv4',
        'source_ipv6', 'coordinator_public_ipv4',
        'coordinator_local_ipv4', 'coordinator_ipv6'
    )) {
        $null = Assert-D01JsonStringValue `
            -Value $Run.fixture.PSObject.Properties[$name].Value `
            -Context "run.json.fixture.$name"
    }
    $null = Assert-D01JsonStringValue `
        -Value $Run.fixture.hostname_sha256 `
        -Context 'run.json.fixture.hostname_sha256' `
        -Pattern '^[0-9a-f]{64}$'
    foreach ($name in @(
        'source_tcp_port', 'source_udp_port', 'source_web_port',
        'downloader_tcp_port', 'downloader_udp_port',
        'downloader_web_port'
    )) {
        $null = Assert-D01JsonInteger `
            -Value $Run.fixture.PSObject.Properties[$name].Value `
            -Context "run.json.fixture.$name" -Minimum 1 -Maximum 65535
    }
    $null = Assert-D01JsonInteger -Value $Run.fixture.file_size_bytes `
        -Context 'run.json.fixture.file_size_bytes' -Minimum 1
    return $true
}

function Assert-D01SourceReadyCoordinationContract {
    param([Parameter(Mandatory = $true)][object]$Ready)
    $null = Assert-D01ExactPropertySet -Object $Ready -Expected @(
        'schema', 'case_id', 'run_nonce', 'generated_at_utc',
        'machine_id_sha256', 'operator_identity', 'candidate', 'topology',
        'process', 'fixture', 'preferences', 'firewall'
    ) -Context 'source-ready.json'
    foreach ($name in @(
        'schema', 'case_id', 'run_nonce', 'generated_at_utc',
        'machine_id_sha256'
    )) {
        $null = Assert-D01JsonStringValue `
            -Value $Ready.PSObject.Properties[$name].Value `
            -Context "source-ready.json.$name"
    }
    if ([string]$Ready.schema -cne 'ese.v91.d01-source-ready/v6' -or
        [string]$Ready.run_nonce -cnotmatch '^[0-9a-f]{32}$' -or
        [string]$Ready.machine_id_sha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'source-ready.json identity contract is not exact'
    }
    $null = Assert-D01ExactPropertySet -Object $Ready.operator_identity `
        -Expected @(
            'source', 'expected_coordinator_machine_id_sha256',
            'expected_coordinator_user_sid_sha256'
        ) -Context 'source-ready.json.operator_identity'
    $null = Assert-D01HostIdentityEvidenceContract `
        -Identity $Ready.operator_identity.source `
        -Context 'source-ready.json.operator_identity.source'
    foreach ($name in @(
        'expected_coordinator_machine_id_sha256',
        'expected_coordinator_user_sid_sha256'
    )) {
        $null = Assert-D01JsonStringValue `
            -Value $Ready.operator_identity.PSObject.Properties[$name].Value `
            -Context "source-ready.json.operator_identity.$name" `
            -Pattern '^[0-9a-f]{64}$'
    }
    $null = Assert-D01ExactPropertySet -Object $Ready.candidate -Expected @(
        'commit', 'emule_sha256', 'package_zip_sha256',
        'extracted_manifest_sha256', 'zip_manifest_sha256'
    ) -Context 'source-ready.json.candidate'
    $null = Assert-D01JsonStringValue -Value $Ready.candidate.commit `
        -Context 'source-ready.json.candidate.commit' `
        -Pattern '^[0-9a-f]{40}$'
    foreach ($name in @(
        'emule_sha256', 'package_zip_sha256',
        'extracted_manifest_sha256', 'zip_manifest_sha256'
    )) {
        $null = Assert-D01JsonStringValue `
            -Value $Ready.candidate.PSObject.Properties[$name].Value `
            -Context "source-ready.json.candidate.$name" `
            -Pattern '^[0-9a-f]{64}$'
    }
    $null = Assert-D01ExactPropertySet -Object $Ready.topology -Expected @(
        'machine_id_sha256', 'source_local_ipv4', 'source_public_ipv4',
        'source_public_ipv4_is_nat', 'source_ipv6',
        'route_to_coordinator_public_ipv4', 'route_to_coordinator_ipv6',
        'allowed_inverse_remote_addresses', 'native_physical',
        'overlay_vpn_proxy_absent'
    ) -Context 'source-ready.json.topology'
    $null = Assert-D01JsonStringValue `
        -Value $Ready.topology.machine_id_sha256 `
        -Context 'source-ready.json.topology.machine_id_sha256' `
        -Pattern '^[0-9a-f]{64}$'
    $null = Assert-D01AssignedAddressEvidenceContract `
        -Assigned $Ready.topology.source_local_ipv4 `
        -Context 'source-ready.json.topology.source_local_ipv4'
    $null = Assert-D01AssignedAddressEvidenceContract `
        -Assigned $Ready.topology.source_ipv6 `
        -Context 'source-ready.json.topology.source_ipv6'
    $null = Assert-D01JsonStringValue `
        -Value $Ready.topology.source_public_ipv4 `
        -Context 'source-ready.json.topology.source_public_ipv4'
    foreach ($name in @(
        'source_public_ipv4_is_nat', 'native_physical',
        'overlay_vpn_proxy_absent'
    )) {
        $null = Assert-D01JsonBoolean `
            -Value $Ready.topology.PSObject.Properties[$name].Value `
            -Context "source-ready.json.topology.$name"
    }
    $null = Assert-D01RouteEvidenceContract `
        -Route $Ready.topology.route_to_coordinator_public_ipv4 `
        -Context 'source-ready.json.topology.route_to_coordinator_public_ipv4'
    $null = Assert-D01RouteEvidenceContract `
        -Route $Ready.topology.route_to_coordinator_ipv6 `
        -Context 'source-ready.json.topology.route_to_coordinator_ipv6'
    $null = Assert-D01JsonStringArray `
        -Value $Ready.topology.allowed_inverse_remote_addresses `
        -Context 'source-ready.json.topology.allowed_inverse_remote_addresses' `
        -RequireUnique
    $null = Assert-D01ExactPropertySet -Object $Ready.process -Expected @(
        'process_id', 'process_emule_sha256', 'binding', 'listener',
        'api_isolation_valid'
    ) -Context 'source-ready.json.process'
    $processId = Assert-D01JsonInteger -Value $Ready.process.process_id `
        -Context 'source-ready.json.process.process_id' -Minimum 1 `
        -Maximum ([int]::MaxValue)
    $null = Assert-D01JsonStringValue `
        -Value $Ready.process.process_emule_sha256 `
        -Context 'source-ready.json.process.process_emule_sha256' `
        -Pattern '^[0-9a-f]{64}$'
    $null = Assert-D01JsonBoolean `
        -Value $Ready.process.api_isolation_valid `
        -Context 'source-ready.json.process.api_isolation_valid'
    $null = Assert-D01ProcessBindingEvidenceContract `
        -Binding $Ready.process.binding `
        -Context 'source-ready.json.process.binding'
    if ([Int64]$Ready.process.binding.process_id -ne $processId -or
        [string]$Ready.process.binding.owner_role -cne 'Source' -or
        [string]$Ready.process.binding.run_nonce -cne
            [string]$Ready.run_nonce -or
        [string]$Ready.process.binding.executable_sha256 -cne
            [string]$Ready.process.process_emule_sha256 -or
        [string]$Ready.process.binding.owner_sid_sha256 -cne
            [string]$Ready.operator_identity.source.user_sid_sha256) {
        throw 'source-ready.json process binding is contradictory'
    }
    $null = Assert-D01ExactPropertySet -Object $Ready.process.listener `
        -Expected @('process_id', 'ipv4_only', 'listeners') `
        -Context 'source-ready.json.process.listener'
    $listenerProcessId = Assert-D01JsonInteger `
        -Value $Ready.process.listener.process_id `
        -Context 'source-ready.json.process.listener.process_id' `
        -Minimum 1 -Maximum ([int]::MaxValue)
    $null = Assert-D01JsonBoolean `
        -Value $Ready.process.listener.ipv4_only `
        -Context 'source-ready.json.process.listener.ipv4_only'
    if ($Ready.process.listener.listeners -isnot [Array] -or
        @($Ready.process.listener.listeners).Count -eq 0 -or
        $listenerProcessId -ne $processId) {
        throw 'source-ready.json listener collection is not exact'
    }
    foreach ($listener in @($Ready.process.listener.listeners)) {
        $null = Assert-D01ExactPropertySet -Object $listener -Expected @(
            'local_address', 'local_port', 'owning_process'
        ) -Context 'source-ready.json.process.listener.listeners[]'
        $null = Assert-D01JsonStringValue `
            -Value $listener.local_address `
            -Context (
                'source-ready.json.process.listener.listeners[].local_address')
        $null = Assert-D01JsonInteger -Value $listener.local_port `
            -Context (
                'source-ready.json.process.listener.listeners[].local_port') `
            -Minimum 1 -Maximum 65535
        $listenerOwner = Assert-D01JsonInteger `
            -Value $listener.owning_process `
            -Context (
                'source-ready.json.process.listener.listeners[].owning_process') `
            -Minimum 1 -Maximum ([int]::MaxValue)
        if ($listenerOwner -ne $processId) {
            throw 'source-ready.json listener has a foreign owner'
        }
    }
    $null = Assert-D01ExactPropertySet -Object $Ready.fixture -Expected @(
        'file_name', 'file_bytes', 'file_sha256', 'ed2k_hash',
        'shared_link', 'shared_link_sha256', 'immutable_read_lock_held',
        'locked_byte_count', 'locked_sha256'
    ) -Context 'source-ready.json.fixture'
    foreach ($name in @('file_name', 'ed2k_hash', 'shared_link')) {
        $null = Assert-D01JsonStringValue `
            -Value $Ready.fixture.PSObject.Properties[$name].Value `
            -Context "source-ready.json.fixture.$name"
    }
    $fileName = [string]$Ready.fixture.file_name
    if ($fileName.Length -gt 200 -or $fileName -in @('.', '..') -or
        [IO.Path]::IsPathRooted($fileName) -or
        [string]::IsNullOrWhiteSpace($fileName) -or
        [IO.Path]::GetFileName($fileName) -cne $fileName -or
        $fileName.IndexOfAny([IO.Path]::GetInvalidFileNameChars()) -ge 0) {
        throw 'source-ready.json.fixture.file_name is not a safe leaf name'
    }
    $null = Assert-D01JsonInteger -Value $Ready.fixture.file_bytes `
        -Context 'source-ready.json.fixture.file_bytes' -Minimum 1
    foreach ($name in @('file_sha256', 'shared_link_sha256')) {
        $null = Assert-D01JsonStringValue `
            -Value $Ready.fixture.PSObject.Properties[$name].Value `
            -Context "source-ready.json.fixture.$name" `
            -Pattern '^[0-9a-f]{64}$'
    }
    $null = Assert-D01JsonBoolean `
        -Value $Ready.fixture.immutable_read_lock_held `
        -Context 'source-ready.json.fixture.immutable_read_lock_held'
    $null = Assert-D01JsonInteger -Value $Ready.fixture.locked_byte_count `
        -Context 'source-ready.json.fixture.locked_byte_count' -Minimum 1
    $null = Assert-D01JsonStringValue -Value $Ready.fixture.locked_sha256 `
        -Context 'source-ready.json.fixture.locked_sha256' `
        -Pattern '^[0-9a-f]{64}$'
    $null = Assert-D01JsonStringValue -Value $Ready.fixture.ed2k_hash `
        -Context 'source-ready.json.fixture.ed2k_hash' `
        -Pattern '^[0-9A-F]{32}$'
    $linkMatch = [regex]::Match(
        [string]$Ready.fixture.shared_link,
        '^ed2k://\|file\|([^|]+)\|([1-9][0-9]*)\|([0-9A-F]{32})' +
            '(?:\|h=[A-Z2-7]{32})?\|/$',
        [Text.RegularExpressions.RegexOptions]::CultureInvariant)
    if (-not $linkMatch.Success -or
        [string]$linkMatch.Groups[1].Value -cne $fileName -or
        [Int64]$linkMatch.Groups[2].Value -ne
            [Int64]$Ready.fixture.file_bytes -or
        [string]$linkMatch.Groups[3].Value -cne
            [string]$Ready.fixture.ed2k_hash -or
        -not [bool]$Ready.fixture.immutable_read_lock_held -or
        [Int64]$Ready.fixture.locked_byte_count -ne
            [Int64]$Ready.fixture.file_bytes -or
        [string]$Ready.fixture.locked_sha256 -cne
            [string]$Ready.fixture.file_sha256 -or
        (Get-LabStringSha256 -Value ([string]$Ready.fixture.shared_link)) -cne
            [string]$Ready.fixture.shared_link_sha256) {
        throw 'source-ready.json.fixture ED2K link identity is contradictory'
    }
    $null = Assert-D01ExactPropertySet -Object $Ready.firewall -Expected @(
        'rules_created', 'exact', 'ipv4_allow', 'ipv6_drop',
        'program_containment', 'AAAA_failure_mode'
    ) -Context 'source-ready.json.firewall'
    foreach ($name in @('rules_created', 'exact')) {
        $null = Assert-D01JsonBoolean `
            -Value $Ready.firewall.PSObject.Properties[$name].Value `
            -Context "source-ready.json.firewall.$name"
    }
    $null = Assert-D01JsonStringValue `
        -Value $Ready.firewall.AAAA_failure_mode `
        -Context 'source-ready.json.firewall.AAAA_failure_mode'
    $null = Assert-D01FirewallRuleEvidenceContract `
        -Rule $Ready.firewall.ipv4_allow `
        -Context 'source-ready.json.firewall.ipv4_allow'
    $null = Assert-D01FirewallRuleEvidenceContract `
        -Rule $Ready.firewall.ipv6_drop `
        -Context 'source-ready.json.firewall.ipv6_drop'
    $null = Assert-D01ProgramContainmentArmedContract `
        -Evidence $Ready.firewall.program_containment `
        -Context 'source-ready.json.firewall.program_containment'
    [string[]]$expectedContainmentAllowed = @(
        @($Ready.topology.allowed_inverse_remote_addresses) +
            @('127.0.0.1', '::1') | ForEach-Object {
                Get-D01NormalizedIp -Address ([string]$_)
            } | Sort-Object -Unique)
    [string[]]$publishedContainmentAllowed = @(
        $Ready.firewall.program_containment.allowed_tcp_remote_addresses |
            ForEach-Object { [string]$_ } | Sort-Object -Unique)
    if ([string]$Ready.firewall.program_containment.role -cne 'Source' -or
        [int]$Ready.firewall.program_containment.rule_count -ne 4 -or
        [string]$Ready.firewall.program_containment.program_path_sha256 -cne
            [string]$Ready.process.binding.path_sha256 -or
        ($expectedContainmentAllowed -join "`n") -cne
            ($publishedContainmentAllowed -join "`n")) {
        throw 'source-ready.json program containment binding is contradictory'
    }
    [string[]]$expectedDisallowed = @(
        Get-D01FirewallAddressExclusionRanges `
            -AllowedAddresses $expectedContainmentAllowed -Family IPv4
        Get-D01FirewallAddressExclusionRanges `
            -AllowedAddresses $expectedContainmentAllowed -Family IPv6
    )
    $expectedDisallowed = @($expectedDisallowed | Sort-Object -Unique)
    $expectedContainmentRules = @(
        [pscustomobject]@{ suffix = 'TCP_INBOUND_DENY_OTHER';
            direction = 'Inbound'; protocol = 'TCP';
            addresses = $expectedDisallowed; ports = @('Any') },
        [pscustomobject]@{ suffix = 'UDP_INBOUND_DENY_ALL';
            direction = 'Inbound'; protocol = 'UDP';
            addresses = @('Any'); ports = @('Any') },
        [pscustomobject]@{ suffix = 'TCP_OUTBOUND_DENY_OTHER';
            direction = 'Outbound'; protocol = 'TCP';
            addresses = @('Any'); ports = @('Any') },
        [pscustomobject]@{ suffix = 'UDP_OUTBOUND_DENY_ALL';
            direction = 'Outbound'; protocol = 'UDP';
            addresses = @('Any'); ports = @('Any') }
    )
    foreach ($expectedRule in $expectedContainmentRules) {
        $expectedName = 'ESE_V91_D01_{0}_SOURCE_{1}' -f
            [string]$Ready.run_nonce, [string]$expectedRule.suffix
        $matches = @($Ready.firewall.program_containment.rules |
            Where-Object { [string]$_.rule_name -ceq $expectedName })
        if ($matches.Count -ne 1 -or
            [string]$matches[0].direction -cne
                [string]$expectedRule.direction -or
            [string]$matches[0].protocol -cne [string]$expectedRule.protocol -or
            (@($matches[0].remote_addresses) -join "`n") -cne
                (@($expectedRule.addresses) -join "`n") -or
            (@($matches[0].remote_ports) -join "`n") -cne
                (@($expectedRule.ports) -join "`n")) {
            throw 'source-ready.json containment rule semantics are not exact'
        }
    }
    return $true
}

function Assert-D01ObserveCommandContract {
    param([Parameter(Mandatory = $true)][object]$Command)
    $null = Assert-D01ExactPropertySet -Object $Command -Expected @(
        'schema', 'case_id', 'run_nonce', 'generated_at_utc',
        'candidate_commit', 'candidate_emule_sha256',
        'downloader_process_id', 'downloader_process_emule_sha256',
        'hostname_sha256', 'telemetry_baseline_sequence', 'pktmon_started'
    ) -Context 'observe.json'
    foreach ($name in @(
        'schema', 'case_id', 'run_nonce', 'generated_at_utc',
        'candidate_commit', 'candidate_emule_sha256',
        'downloader_process_emule_sha256', 'hostname_sha256'
    )) {
        $null = Assert-D01JsonStringValue `
            -Value $Command.PSObject.Properties[$name].Value `
            -Context "observe.json.$name"
    }
    if ([string]$Command.schema -cne
            'ese.v91.d01-observe-command/v2' -or
        [string]$Command.run_nonce -cnotmatch '^[0-9a-f]{32}$' -or
        [string]$Command.candidate_commit -cnotmatch '^[0-9a-f]{40}$') {
        throw 'observe.json identity contract is not exact'
    }
    foreach ($name in @(
        'candidate_emule_sha256', 'downloader_process_emule_sha256',
        'hostname_sha256'
    )) {
        if ([string]$Command.PSObject.Properties[$name].Value -cnotmatch
            '^[0-9a-f]{64}$') {
            throw "observe.json.$name is not a lowercase SHA-256"
        }
    }
    $null = Assert-D01JsonInteger -Value $Command.downloader_process_id `
        -Context 'observe.json.downloader_process_id' -Minimum 1 `
        -Maximum ([int]::MaxValue)
    $null = Assert-D01JsonInteger `
        -Value $Command.telemetry_baseline_sequence `
        -Context 'observe.json.telemetry_baseline_sequence' -Minimum 0
    $null = Assert-D01JsonBoolean -Value $Command.pktmon_started `
        -Context 'observe.json.pktmon_started'
    return $true
}

function Assert-D01SourceObservingContract {
    param([Parameter(Mandatory = $true)][object]$Ack)
    $null = Assert-D01ExactPropertySet -Object $Ack -Expected @(
        'schema', 'case_id', 'run_nonce', 'generated_at_utc',
        'source_process_id', 'source_process_emule_sha256',
        'expected_downloader_process_id',
        'all_processes_and_nonlisten_states_checked',
        'allowed_source_visible_remote_addresses',
        'baseline_established_connection_count',
        'baseline_nonlisten_connection_count', 'baseline_wait_sample_count',
        'baseline_wait_duration_ms', 'baseline_zero'
    ) -Context 'source-observing.json'
    foreach ($name in @(
        'schema', 'case_id', 'run_nonce', 'generated_at_utc',
        'source_process_emule_sha256'
    )) {
        $null = Assert-D01JsonStringValue `
            -Value $Ack.PSObject.Properties[$name].Value `
            -Context "source-observing.json.$name"
    }
    if ([string]$Ack.schema -cne
            'ese.v91.d01-source-observing/v4' -or
        [string]$Ack.run_nonce -cnotmatch '^[0-9a-f]{32}$' -or
        [string]$Ack.source_process_emule_sha256 -cnotmatch
            '^[0-9a-f]{64}$') {
        throw 'source-observing.json identity contract is not exact'
    }
    foreach ($name in @(
        'source_process_id', 'expected_downloader_process_id'
    )) {
        $null = Assert-D01JsonInteger `
            -Value $Ack.PSObject.Properties[$name].Value `
            -Context "source-observing.json.$name" -Minimum 1 `
            -Maximum ([int]::MaxValue)
    }
    foreach ($name in @(
        'baseline_established_connection_count',
        'baseline_nonlisten_connection_count', 'baseline_wait_sample_count',
        'baseline_wait_duration_ms'
    )) {
        $null = Assert-D01JsonInteger `
            -Value $Ack.PSObject.Properties[$name].Value `
            -Context "source-observing.json.$name" -Minimum 0
    }
    foreach ($name in @(
        'all_processes_and_nonlisten_states_checked', 'baseline_zero'
    )) {
        $null = Assert-D01JsonBoolean `
            -Value $Ack.PSObject.Properties[$name].Value `
            -Context "source-observing.json.$name"
    }
    $null = Assert-D01JsonStringArray `
        -Value $Ack.allowed_source_visible_remote_addresses `
        -Context 'source-observing.json.allowed_source_visible_remote_addresses' `
        -RequireUnique
    return $true
}

function Assert-D01ArmCommandContract {
    param([Parameter(Mandatory = $true)][object]$Command)
    $null = Assert-D01ExactPropertySet -Object $Command -Expected @(
        'schema', 'case_id', 'run_nonce', 'generated_at_utc', 'arm_id',
        'candidate_commit', 'candidate_emule_sha256',
        'downloader_process_id', 'downloader_ownership_id_sha256'
    ) -Context 'arm.json'
    foreach ($name in @(
        'schema', 'case_id', 'run_nonce', 'generated_at_utc', 'arm_id',
        'candidate_commit', 'candidate_emule_sha256',
        'downloader_ownership_id_sha256'
    )) {
        $null = Assert-D01JsonStringValue `
            -Value $Command.PSObject.Properties[$name].Value `
            -Context "arm.json.$name"
    }
    $null = Assert-D01JsonInteger -Value $Command.downloader_process_id `
        -Context 'arm.json.downloader_process_id' -Minimum 1 `
        -Maximum ([int]::MaxValue)
    if ([string]$Command.schema -cne 'ese.v91.d01-arm-command/v1' -or
        [string]$Command.run_nonce -cnotmatch '^[0-9a-f]{32}$' -or
        [string]$Command.arm_id -cnotmatch '^[0-9a-f]{32}$' -or
        [string]$Command.candidate_commit -cnotmatch '^[0-9a-f]{40}$' -or
        [string]$Command.candidate_emule_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$Command.downloader_ownership_id_sha256 -cnotmatch
            '^[0-9a-f]{64}$') {
        throw 'arm.json contract is not exact'
    }
    return $true
}

function Assert-D01SourceArmedContract {
    param([Parameter(Mandatory = $true)][object]$Ack)
    $null = Assert-D01ExactPropertySet -Object $Ack -Expected @(
        'schema', 'case_id', 'run_nonce', 'generated_at_utc', 'arm_id',
        'source_process_id', 'source_ownership_id_sha256',
        'downloader_process_id', 'downloader_ownership_id_sha256',
        'health_counters_reset', 'local_arm_boundary_epoch_unix_ns'
    ) -Context 'source-armed.json'
    foreach ($name in @(
        'schema', 'case_id', 'run_nonce', 'generated_at_utc', 'arm_id',
        'source_ownership_id_sha256', 'downloader_ownership_id_sha256'
    )) {
        $null = Assert-D01JsonStringValue `
            -Value $Ack.PSObject.Properties[$name].Value `
            -Context "source-armed.json.$name"
    }
    foreach ($name in @('source_process_id', 'downloader_process_id')) {
        $null = Assert-D01JsonInteger `
            -Value $Ack.PSObject.Properties[$name].Value `
            -Context "source-armed.json.$name" -Minimum 1 `
            -Maximum ([int]::MaxValue)
    }
    $null = Assert-D01JsonInteger `
        -Value $Ack.local_arm_boundary_epoch_unix_ns `
        -Context 'source-armed.json.local_arm_boundary_epoch_unix_ns' `
        -Minimum 1
    $null = Assert-D01JsonBoolean -Value $Ack.health_counters_reset `
        -Context 'source-armed.json.health_counters_reset'
    if ([string]$Ack.schema -cne 'ese.v91.d01-source-armed/v1' -or
        [string]$Ack.run_nonce -cnotmatch '^[0-9a-f]{32}$' -or
        [string]$Ack.arm_id -cnotmatch '^[0-9a-f]{32}$' -or
        [string]$Ack.source_ownership_id_sha256 -cnotmatch
            '^[0-9a-f]{64}$' -or
        [string]$Ack.downloader_ownership_id_sha256 -cnotmatch
            '^[0-9a-f]{64}$' -or
        -not [bool]$Ack.health_counters_reset) {
        throw 'source-armed.json contract is not exact'
    }
    return $true
}

function Assert-D01SourceApiFailureEvidenceContract {
    param(
        [Parameter(Mandatory = $true)][object]$Evidence,
        [Parameter(Mandatory = $true)][object]$SourceArm,
        [Parameter(Mandatory = $true)][object]$SourceBinding,
        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 65535)][int]$ExpectedWebPort,
        [switch]$AllowControlledEd2k
    )
    $null = Assert-D01ExactPropertySet -Object $Evidence -Expected @(
        'schema', 'arm_id', 'observed_epoch_unix_ns', 'sample_number',
        'source_process_id', 'source_ownership_id_sha256', 'probe'
    ) -Context 'source API failure evidence'
    $observed = Assert-D01JsonInteger `
        -Value $Evidence.observed_epoch_unix_ns `
        -Context 'source API failure evidence.observed_epoch_unix_ns' `
        -Minimum 1
    $null = Assert-D01JsonInteger -Value $Evidence.sample_number `
        -Context 'source API failure evidence.sample_number' -Minimum 1
    $null = Assert-D01JsonInteger -Value $Evidence.source_process_id `
        -Context 'source API failure evidence.source_process_id' -Minimum 1 `
        -Maximum ([int]::MaxValue)
    $null = Assert-D01JsonStringValue -Value $Evidence.arm_id `
        -Context 'source API failure evidence.arm_id' `
        -Pattern '^[0-9a-f]{32}$'
    $null = Assert-D01JsonStringValue `
        -Value $Evidence.source_ownership_id_sha256 `
        -Context 'source API failure evidence.source_ownership_id_sha256' `
        -Pattern '^[0-9a-f]{64}$'
    $null = Assert-D01JsonInteger -Value $Evidence.source_process_id `
        -Context 'source API failure evidence.source_process_id' -Minimum 1 `
        -Maximum ([int]::MaxValue)
    $probe = $Evidence.probe
    $null = Assert-D01ExactPropertySet -Object $probe -Expected @(
        'captured_at_utc', 'available', 'duration_ms', 'contract_valid',
        'isolation_valid', 'contamination_proven', 'endpoint_ownership',
        'endpoint_ownership_before', 'endpoint_ownership_after',
        'ownership_stable_across_request', 'error_sha256', 'data'
    ) -Context 'source API failure evidence.probe'
    foreach ($name in @(
        'available', 'contract_valid', 'isolation_valid',
        'contamination_proven', 'ownership_stable_across_request'
    )) {
        $null = Assert-D01JsonBoolean `
            -Value $probe.PSObject.Properties[$name].Value `
            -Context "source API failure evidence.probe.$name"
    }
    $null = Assert-D01JsonInteger -Value $probe.duration_ms `
        -Context 'source API failure evidence.probe.duration_ms' -Minimum 0
    $null = Assert-D01JsonStringValue -Value $probe.captured_at_utc `
        -Context 'source API failure evidence.probe.captured_at_utc'
    $null = Assert-D01JsonStringValue -Value $probe.error_sha256 `
        -Context 'source API failure evidence.probe.error_sha256' `
        -Pattern '^(|[0-9a-f]{64})$'
    $assessment = Get-D01ApiIsolationAssessment -Data $probe.data `
        -AllowControlledEd2k:$AllowControlledEd2k
    if ([string]$Evidence.schema -cne
            'ese.v91.d01-source-api-isolation-failure/v1' -or
        [string]$Evidence.arm_id -cne [string]$SourceArm.arm_id -or
        $observed -lt [Int64]$SourceArm.local_arm_boundary_epoch_unix_ns -or
        [Int64]$Evidence.source_process_id -ne
            [Int64]$SourceBinding.process_id -or
        [string]$Evidence.source_ownership_id_sha256 -cne
            [string]$SourceBinding.ownership_id_sha256 -or
        -not [bool]$probe.available -or -not [bool]$probe.contract_valid -or
        [bool]$probe.isolation_valid -or
        -not [bool]$probe.contamination_proven -or
        -not [bool]$probe.ownership_stable_across_request -or
        -not [bool]$assessment.contract_valid -or
        -not [bool]$assessment.contamination_proven) {
        throw 'Source API failure evidence is not exact and post-arm'
    }
    $expectedListenerCount = $null
    foreach ($ownership in @(
        $probe.endpoint_ownership_before, $probe.endpoint_ownership_after,
        $probe.endpoint_ownership
    )) {
        $null = Assert-D01ExactPropertySet -Object $ownership -Expected @(
            'schema', 'collector_ok', 'port', 'candidate_process_id',
            'listener_count', 'owner_process_ids', 'loopback_only',
            'process_binding_exact', 'endpoint_bound_to_candidate',
            'candidate_ownership_id_sha256', 'error_sha256'
        ) -Context 'source API failure endpoint ownership'
        foreach ($name in @(
            'collector_ok', 'loopback_only', 'process_binding_exact',
            'endpoint_bound_to_candidate'
        )) {
            $null = Assert-D01JsonBoolean `
                -Value $ownership.PSObject.Properties[$name].Value `
                -Context "source API failure endpoint ownership.$name"
        }
        $ownershipPort = Assert-D01JsonInteger -Value $ownership.port `
            -Context 'source API failure endpoint ownership.port' `
            -Minimum 1 -Maximum 65535
        $ownershipProcessId = Assert-D01JsonInteger `
            -Value $ownership.candidate_process_id `
            -Context (
                'source API failure endpoint ownership.candidate_process_id') `
            -Minimum 1 -Maximum ([int]::MaxValue)
        $listenerCount = Assert-D01JsonInteger `
            -Value $ownership.listener_count `
            -Context 'source API failure endpoint ownership.listener_count' `
            -Minimum 1
        $null = Assert-D01JsonStringValue `
            -Value $ownership.candidate_ownership_id_sha256 `
            -Context (
                'source API failure endpoint ownership.' +
                'candidate_ownership_id_sha256') `
            -Pattern '^[0-9a-f]{64}$'
        $null = Assert-D01JsonStringValue `
            -Value $ownership.error_sha256 `
            -Context 'source API failure endpoint ownership.error_sha256' `
            -Pattern '^$'
        if ($ownership.owner_process_ids -isnot [Array] -or
            @($ownership.owner_process_ids).Count -ne 1 -or
            ($ownership.owner_process_ids[0] -isnot [int] -and
                $ownership.owner_process_ids[0] -isnot [Int64])) {
            throw 'Source API failure endpoint owners are not exact'
        }
        $ownerProcessId = Assert-D01JsonInteger `
            -Value $ownership.owner_process_ids[0] `
            -Context 'source API failure endpoint ownership.owner_process_ids[0]' `
            -Minimum 1 -Maximum ([int]::MaxValue)
        if ([string]$ownership.schema -cne
                'ese.v91.d01-web-endpoint-ownership/v1' -or
            -not [bool]$ownership.collector_ok -or
            -not [bool]$ownership.loopback_only -or
            -not [bool]$ownership.process_binding_exact -or
            -not [bool]$ownership.endpoint_bound_to_candidate -or
            $ownershipPort -ne $ExpectedWebPort -or
            $ownershipProcessId -ne
                [Int64]$SourceBinding.process_id -or
            $ownerProcessId -ne [Int64]$SourceBinding.process_id -or
            [string]$ownership.candidate_ownership_id_sha256 -cne
                [string]$SourceBinding.ownership_id_sha256) {
            throw 'Source API failure endpoint ownership is not exact'
        }
        if ($null -eq $expectedListenerCount) {
            $expectedListenerCount = $listenerCount
        } elseif ($listenerCount -ne $expectedListenerCount) {
            throw 'Source API failure endpoint ownership changed across request'
        }
    }
    return $true
}

function Assert-D01SourceUiFailureEvidenceContract {
    param(
        [Parameter(Mandatory = $true)][object]$Evidence,
        [Parameter(Mandatory = $true)][object]$SourceArm,
        [Parameter(Mandatory = $true)][object]$SourceBinding
    )
    $null = Assert-D01ExactPropertySet -Object $Evidence -Expected @(
        'schema', 'arm_id', 'observed_epoch_unix_ns', 'sample_number',
        'source_process_id', 'source_ownership_id_sha256', 'probe'
    ) -Context 'source UI failure evidence'
    $observed = Assert-D01JsonInteger `
        -Value $Evidence.observed_epoch_unix_ns `
        -Context 'source UI failure evidence.observed_epoch_unix_ns' `
        -Minimum 1
    $null = Assert-D01JsonInteger -Value $Evidence.sample_number `
        -Context 'source UI failure evidence.sample_number' -Minimum 1
    $null = Assert-D01JsonInteger -Value $Evidence.source_process_id `
        -Context 'source UI failure evidence.source_process_id' -Minimum 1 `
        -Maximum ([int]::MaxValue)
    $null = Assert-D01JsonStringValue -Value $Evidence.arm_id `
        -Context 'source UI failure evidence.arm_id' `
        -Pattern '^[0-9a-f]{32}$'
    $null = Assert-D01JsonStringValue `
        -Value $Evidence.source_ownership_id_sha256 `
        -Context 'source UI failure evidence.source_ownership_id_sha256' `
        -Pattern '^[0-9a-f]{64}$'
    $probe = $Evidence.probe
    $null = Assert-D01ExactPropertySet -Object $probe -Expected @(
        'captured_at_utc', 'process_id', 'main_window_present',
        'message_pump_responsive', 'timeout_proven', 'collector_ok',
        'source_bound', 'win32_error_code', 'error_sha256', 'duration_ms'
    ) -Context 'source UI failure evidence.probe'
    foreach ($name in @(
        'main_window_present', 'message_pump_responsive', 'timeout_proven',
        'collector_ok', 'source_bound'
    )) {
        $null = Assert-D01JsonBoolean `
            -Value $probe.PSObject.Properties[$name].Value `
            -Context "source UI failure evidence.probe.$name"
    }
    foreach ($name in @(
        'process_id', 'win32_error_code', 'duration_ms'
    )) {
        $null = Assert-D01JsonInteger `
            -Value $probe.PSObject.Properties[$name].Value `
            -Context "source UI failure evidence.probe.$name" -Minimum 0
    }
    $null = Assert-D01JsonStringValue -Value $probe.captured_at_utc `
        -Context 'source UI failure evidence.probe.captured_at_utc' `
        -Pattern '^.+$'
    $null = Assert-D01JsonStringValue -Value $probe.error_sha256 `
        -Context 'source UI failure evidence.probe.error_sha256' `
        -Pattern '^$'
    if ([string]$Evidence.schema -cne
            'ese.v91.d01-source-ui-timeout-failure/v1' -or
        [string]$Evidence.arm_id -cne [string]$SourceArm.arm_id -or
        $observed -lt [Int64]$SourceArm.local_arm_boundary_epoch_unix_ns -or
        [Int64]$Evidence.source_process_id -ne
            [Int64]$SourceBinding.process_id -or
        [string]$Evidence.source_ownership_id_sha256 -cne
            [string]$SourceBinding.ownership_id_sha256 -or
        [Int64]$probe.process_id -ne [Int64]$SourceBinding.process_id -or
        -not [bool]$probe.main_window_present -or
        [bool]$probe.message_pump_responsive -or
        -not [bool]$probe.timeout_proven -or
        -not [bool]$probe.collector_ok -or -not [bool]$probe.source_bound -or
        [Int64]$probe.win32_error_code -ne 1460) {
        throw 'Source UI timeout evidence is not exact and post-arm'
    }
    return $true
}

function Assert-D01CoordinatorApiFailureEvidenceContract {
    param(
        [Parameter(Mandatory = $true)][object]$Evidence,
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[0-9a-f]{32}$')][string]$ExpectedArmId,
        [Parameter(Mandatory = $true)][Int64]$ArmBoundaryEpochUnixNs,
        [Parameter(Mandatory = $true)][object]$CandidateBinding,
        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 65535)][int]$ExpectedWebPort
    )
    $null = Assert-D01ExactPropertySet -Object $Evidence -Expected @(
        'schema', 'arm_id', 'observed_epoch_unix_ns', 'sample_number',
        'candidate_process_id', 'candidate_ownership_id_sha256', 'probe'
    ) -Context 'coordinator API failure evidence'
    if ([string]$Evidence.schema -cne
            'ese.v91.d01-coordinator-api-isolation-failure/v1') {
        throw 'Coordinator API failure evidence schema is not exact'
    }
    $sourceShapedEvidence = [pscustomobject][ordered]@{
        schema = 'ese.v91.d01-source-api-isolation-failure/v1'
        arm_id = $Evidence.arm_id
        observed_epoch_unix_ns = $Evidence.observed_epoch_unix_ns
        sample_number = $Evidence.sample_number
        source_process_id = $Evidence.candidate_process_id
        source_ownership_id_sha256 =
            $Evidence.candidate_ownership_id_sha256
        probe = $Evidence.probe
    }
    $localArm = [pscustomobject][ordered]@{
        arm_id = $ExpectedArmId
        local_arm_boundary_epoch_unix_ns = $ArmBoundaryEpochUnixNs
    }
    $null = Assert-D01SourceApiFailureEvidenceContract `
        -Evidence $sourceShapedEvidence -SourceArm $localArm `
        -SourceBinding $CandidateBinding -ExpectedWebPort $ExpectedWebPort `
        -AllowControlledEd2k
    return $true
}

function Assert-D01CoordinatorUiFailureEvidenceContract {
    param(
        [Parameter(Mandatory = $true)][object]$Evidence,
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[0-9a-f]{32}$')][string]$ExpectedArmId,
        [Parameter(Mandatory = $true)][Int64]$ArmBoundaryEpochUnixNs,
        [Parameter(Mandatory = $true)][object]$CandidateBinding
    )
    $null = Assert-D01ExactPropertySet -Object $Evidence -Expected @(
        'schema', 'arm_id', 'observed_epoch_unix_ns', 'sample_number',
        'candidate_process_id', 'candidate_ownership_id_sha256', 'probe'
    ) -Context 'coordinator UI failure evidence'
    if ([string]$Evidence.schema -cne
            'ese.v91.d01-coordinator-ui-timeout-failure/v1') {
        throw 'Coordinator UI failure evidence schema is not exact'
    }
    $sourceShapedEvidence = [pscustomobject][ordered]@{
        schema = 'ese.v91.d01-source-ui-timeout-failure/v1'
        arm_id = $Evidence.arm_id
        observed_epoch_unix_ns = $Evidence.observed_epoch_unix_ns
        sample_number = $Evidence.sample_number
        source_process_id = $Evidence.candidate_process_id
        source_ownership_id_sha256 =
            $Evidence.candidate_ownership_id_sha256
        probe = $Evidence.probe
    }
    $localArm = [pscustomobject][ordered]@{
        arm_id = $ExpectedArmId
        local_arm_boundary_epoch_unix_ns = $ArmBoundaryEpochUnixNs
    }
    $null = Assert-D01SourceUiFailureEvidenceContract `
        -Evidence $sourceShapedEvidence -SourceArm $localArm `
        -SourceBinding $CandidateBinding
    return $true
}

function Assert-D01CoordinatorProcessExitEvidenceContract {
    param(
        [Parameter(Mandatory = $true)][object]$Evidence,
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[0-9a-f]{32}$')][string]$ExpectedArmId,
        [Parameter(Mandatory = $true)][Int64]$ArmBoundaryEpochUnixNs,
        [Parameter(Mandatory = $true)][object]$CandidateBinding
    )
    $null = Assert-D01ExactPropertySet -Object $Evidence -Expected @(
        'schema', 'arm_id', 'observed_epoch_unix_ns',
        'candidate_process_id', 'candidate_ownership_id_sha256',
        'retained_handle_observed_exit', 'has_exited', 'exit_code'
    ) -Context 'coordinator process exit evidence'
    if ([string]$Evidence.schema -cne
            'ese.v91.d01-coordinator-process-exit/v1') {
        throw 'Coordinator process exit evidence schema is not exact'
    }
    $sourceShapedEvidence = [pscustomobject][ordered]@{
        schema = 'ese.v91.d01-source-process-exit/v1'
        arm_id = $Evidence.arm_id
        observed_epoch_unix_ns = $Evidence.observed_epoch_unix_ns
        source_process_id = $Evidence.candidate_process_id
        source_ownership_id_sha256 =
            $Evidence.candidate_ownership_id_sha256
        retained_handle_observed_exit =
            $Evidence.retained_handle_observed_exit
        has_exited = $Evidence.has_exited
        exit_code = $Evidence.exit_code
    }
    $localArm = [pscustomobject][ordered]@{
        arm_id = $ExpectedArmId
        local_arm_boundary_epoch_unix_ns = $ArmBoundaryEpochUnixNs
    }
    $null = Assert-D01SourceProcessExitEvidenceContract `
        -Evidence $sourceShapedEvidence -SourceArm $localArm `
        -SourceBinding $CandidateBinding
    return $true
}

function New-D01CoordinatorProcessExitEvidence {
    param(
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[0-9a-f]{32}$')][string]$ArmId,
        [Parameter(Mandatory = $true)][object]$CandidateBinding
    )
    $Process.Refresh()
    if (-not $Process.HasExited -or
        [Int64]$CandidateBinding.process_id -ne [Int64]$Process.Id) {
        throw 'Retained coordinator process handle did not prove exact exit'
    }
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.d01-coordinator-process-exit/v1'
        arm_id = $ArmId
        observed_epoch_unix_ns = Get-D01EpochUnixNs
        candidate_process_id = [int]$Process.Id
        candidate_ownership_id_sha256 =
            [string]$CandidateBinding.ownership_id_sha256
        retained_handle_observed_exit = $true
        has_exited = $true
        exit_code = [int]$Process.ExitCode
    }
}

function Assert-D01UnexpectedTcpPeerFailureEvidenceContract {
    param(
        [Parameter(Mandatory = $true)][object]$Evidence,
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[0-9a-f]{32}$')][string]$ExpectedArmId,
        [Parameter(Mandatory = $true)][Int64]$ArmBoundaryEpochUnixNs,
        [Parameter(Mandatory = $true)][Int64]$ArmBoundaryQpcTicks,
        [Parameter(Mandatory = $true)][object]$ExpectedClockAnchor,
        [Parameter(Mandatory = $true)][object]$CandidateBinding,
        [Parameter(Mandatory = $true)][string[]]$ExpectedSourceAddresses,
        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 65535)][int]$ExpectedSourcePort,
        [Parameter(Mandatory = $true)][string]$ExpectedSchedulerAddress,
        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 65535)][int]$ExpectedSchedulerPort,
        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 65535)][int]$ExpectedWebPort
    )
    $null = Assert-D01ExactPropertySet -Object $Evidence -Expected @(
        'schema', 'arm_id', 'observed_epoch_unix_ns', 'process_binding',
        'transport', 'scope', 'query_clock',
        'expected_source_addresses', 'expected_source_port',
        'expected_scheduler_address', 'expected_scheduler_port',
        'expected_web_port', 'connection'
    ) -Context 'unexpected TCP peer failure evidence'
    $observed = Assert-D01JsonInteger `
        -Value $Evidence.observed_epoch_unix_ns `
        -Context 'unexpected TCP peer failure evidence.observed_epoch_unix_ns' `
        -Minimum 1
    $sourcePort = Assert-D01JsonInteger `
        -Value $Evidence.expected_source_port `
        -Context 'unexpected TCP peer failure evidence.expected_source_port' `
        -Minimum 1 -Maximum 65535
    $schedulerPort = Assert-D01JsonInteger `
        -Value $Evidence.expected_scheduler_port `
        -Context 'unexpected TCP peer failure evidence.expected_scheduler_port' `
        -Minimum 1 -Maximum 65535
    $webPort = Assert-D01JsonInteger `
        -Value $Evidence.expected_web_port `
        -Context 'unexpected TCP peer failure evidence.expected_web_port' `
        -Minimum 1 -Maximum 65535
    $null = Assert-D01JsonStringValue -Value $Evidence.arm_id `
        -Context 'unexpected TCP peer failure evidence.arm_id' `
        -Pattern '^[0-9a-f]{32}$'
    $null = Assert-D01JsonStringValue -Value $Evidence.transport `
        -Context 'unexpected TCP peer failure evidence.transport'
    $null = Assert-D01JsonStringValue -Value $Evidence.scope `
        -Context 'unexpected TCP peer failure evidence.scope'
    $null = Assert-D01JsonStringArray `
        -Value $Evidence.expected_source_addresses `
        -Context 'unexpected TCP peer failure evidence.expected_source_addresses' `
        -RequireUnique
    $null = Assert-D01ProcessBindingEvidenceContract `
        -Binding $Evidence.process_binding `
        -Context 'unexpected TCP peer failure evidence.process_binding'
    [string[]]$actualSources = @(
        $Evidence.expected_source_addresses | ForEach-Object {
            Get-D01NormalizedIp -Address ([string]$_)
        } | Sort-Object -Unique)
    [string[]]$expectedSources = @(
        $ExpectedSourceAddresses | ForEach-Object {
            Get-D01NormalizedIp -Address ([string]$_)
        } | Sort-Object -Unique)
    $actualScheduler = Get-D01NormalizedIp `
        -Address ([string]$Evidence.expected_scheduler_address)
    $expectedScheduler = Get-D01NormalizedIp `
        -Address $ExpectedSchedulerAddress
    $clock = $Evidence.query_clock
    $null = Assert-D01ExactPropertySet -Object $clock -Expected @(
        'schema', 'clock_domain', 'anchor_id', 'qpc_frequency',
        'qpc_start_ticks', 'qpc_end_ticks', 'qpc_midpoint_ticks',
        'epoch_unix_ns', 'uncertainty_ns'
    ) -Context 'unexpected TCP peer failure evidence.query_clock'
    foreach ($name in @('schema', 'clock_domain', 'anchor_id')) {
        $null = Assert-D01JsonStringValue `
            -Value $clock.PSObject.Properties[$name].Value `
            -Context "unexpected TCP peer failure evidence.query_clock.$name"
    }
    $qpcFrequency = Assert-D01JsonInteger -Value $clock.qpc_frequency `
        -Context 'unexpected TCP peer failure evidence.query_clock.qpc_frequency' `
        -Minimum 1
    $qpcStart = Assert-D01JsonInteger -Value $clock.qpc_start_ticks `
        -Context 'unexpected TCP peer failure evidence.query_clock.qpc_start_ticks' `
        -Minimum 1
    $qpcEnd = Assert-D01JsonInteger -Value $clock.qpc_end_ticks `
        -Context 'unexpected TCP peer failure evidence.query_clock.qpc_end_ticks' `
        -Minimum 1
    $qpcMidpoint = Assert-D01JsonInteger `
        -Value $clock.qpc_midpoint_ticks `
        -Context 'unexpected TCP peer failure evidence.query_clock.qpc_midpoint_ticks' `
        -Minimum 1
    $clockEpoch = Assert-D01JsonInteger -Value $clock.epoch_unix_ns `
        -Context 'unexpected TCP peer failure evidence.query_clock.epoch_unix_ns' `
        -Minimum 1
    $clockUncertainty = Assert-D01JsonInteger `
        -Value $clock.uncertainty_ns `
        -Context 'unexpected TCP peer failure evidence.query_clock.uncertainty_ns' `
        -Minimum 0
    $expectedClock = Get-D01ClockObservation `
        -Anchor $ExpectedClockAnchor -QpcStart $qpcStart -QpcEnd $qpcEnd
    if ([string]$clock.schema -cne
            'ese.v91.d01-clock-observation/v1' -or
        [string]$clock.clock_domain -cne
            [string]$ExpectedClockAnchor.clock_domain -or
        [string]$clock.anchor_id -cne
            [string]$ExpectedClockAnchor.anchor_id -or
        $qpcFrequency -ne [Int64]$ExpectedClockAnchor.qpc_frequency -or
        $qpcStart -lt $ArmBoundaryQpcTicks -or $qpcEnd -lt $qpcStart -or
        $qpcMidpoint -ne [Int64]$expectedClock.qpc_midpoint_ticks -or
        $clockEpoch -ne [Int64]$expectedClock.epoch_unix_ns -or
        $clockUncertainty -ne [Int64]$expectedClock.uncertainty_ns -or
        $observed -ne $clockEpoch) {
        throw 'Unexpected TCP peer query clock is not exact and post-arm'
    }
    $connection = $Evidence.connection
    $null = Assert-D01ExactPropertySet -Object $connection -Expected @(
        'state', 'local_address', 'local_port', 'remote_address',
        'remote_port', 'owning_process'
    ) -Context 'unexpected TCP peer failure evidence.connection'
    $null = Assert-D01JsonStringValue -Value $connection.state `
        -Context 'unexpected TCP peer failure evidence.connection.state' `
        -Pattern '^.+$'
    $localPort = Assert-D01JsonInteger -Value $connection.local_port `
        -Context 'unexpected TCP peer failure evidence.connection.local_port' `
        -Minimum 0 -Maximum 65535
    $remotePort = Assert-D01JsonInteger -Value $connection.remote_port `
        -Context 'unexpected TCP peer failure evidence.connection.remote_port' `
        -Minimum 0 -Maximum 65535
    $ownerProcessId = Assert-D01JsonInteger `
        -Value $connection.owning_process `
        -Context 'unexpected TCP peer failure evidence.connection.owning_process' `
        -Minimum 1 -Maximum ([int]::MaxValue)
    $localAddress = Get-D01NormalizedIp `
        -Address ([string]$connection.local_address)
    $remoteAddress = Get-D01NormalizedIp `
        -Address ([string]$connection.remote_address)
    $nonConnectedState = [string]$connection.state -in @('Listen', 'Bound') -or
        $remoteAddress -in @('0.0.0.0', '::') -or $remotePort -eq 0
    $ownedLoopbackApi = $remoteAddress -in @('127.0.0.1', '::1') -and
        $localPort -eq $ExpectedWebPort
    $controlledScheduler = $remoteAddress -eq $expectedScheduler -and
        $remotePort -eq $ExpectedSchedulerPort
    $controlledSource = $remoteAddress -in $expectedSources -and
        $remotePort -eq $ExpectedSourcePort
    if ([string]$Evidence.schema -cne
            'ese.v91.d01-unexpected-tcp-peer-connection-failure/v1' -or
        [string]$Evidence.transport -cne 'tcp' -or
        [string]$Evidence.scope -cne 'connected-peer-tuples-only' -or
        [string]$Evidence.arm_id -cne $ExpectedArmId -or
        $observed -lt $ArmBoundaryEpochUnixNs -or
        [string]$Evidence.process_binding.ownership_id_sha256 -cne
            [string]$CandidateBinding.ownership_id_sha256 -or
        $ownerProcessId -ne [Int64]$CandidateBinding.process_id -or
        $sourcePort -ne $ExpectedSourcePort -or
        $schedulerPort -ne $ExpectedSchedulerPort -or
        $webPort -ne $ExpectedWebPort -or
        $actualScheduler -cne $expectedScheduler -or
        ($actualSources -join "`n") -cne ($expectedSources -join "`n") -or
        [string]$connection.local_address -cne $localAddress -or
        [string]$connection.remote_address -cne $remoteAddress -or
        $nonConnectedState -or $ownedLoopbackApi -or $controlledScheduler -or
        $controlledSource) {
        throw 'Unexpected TCP peer failure evidence is not exact and post-arm'
    }
    return $true
}

function Assert-D01SourceProcessExitEvidenceContract {
    param(
        [Parameter(Mandatory = $true)][object]$Evidence,
        [Parameter(Mandatory = $true)][object]$SourceArm,
        [Parameter(Mandatory = $true)][object]$SourceBinding
    )
    $null = Assert-D01ExactPropertySet -Object $Evidence -Expected @(
        'schema', 'arm_id', 'observed_epoch_unix_ns', 'source_process_id',
        'source_ownership_id_sha256', 'retained_handle_observed_exit',
        'has_exited', 'exit_code'
    ) -Context 'source process exit evidence'
    $observed = Assert-D01JsonInteger `
        -Value $Evidence.observed_epoch_unix_ns `
        -Context 'source process exit evidence.observed_epoch_unix_ns' `
        -Minimum 1
    $null = Assert-D01JsonInteger -Value $Evidence.exit_code `
        -Context 'source process exit evidence.exit_code' `
        -Minimum ([int]::MinValue) -Maximum ([int]::MaxValue)
    $null = Assert-D01JsonInteger -Value $Evidence.source_process_id `
        -Context 'source process exit evidence.source_process_id' -Minimum 1 `
        -Maximum ([int]::MaxValue)
    $null = Assert-D01JsonStringValue -Value $Evidence.arm_id `
        -Context 'source process exit evidence.arm_id' `
        -Pattern '^[0-9a-f]{32}$'
    $null = Assert-D01JsonStringValue `
        -Value $Evidence.source_ownership_id_sha256 `
        -Context 'source process exit evidence.source_ownership_id_sha256' `
        -Pattern '^[0-9a-f]{64}$'
    foreach ($name in @('retained_handle_observed_exit', 'has_exited')) {
        $null = Assert-D01JsonBoolean `
            -Value $Evidence.PSObject.Properties[$name].Value `
            -Context "source process exit evidence.$name"
    }
    if ([string]$Evidence.schema -cne
            'ese.v91.d01-source-process-exit/v1' -or
        [string]$Evidence.arm_id -cne [string]$SourceArm.arm_id -or
        $observed -lt [Int64]$SourceArm.local_arm_boundary_epoch_unix_ns -or
        [Int64]$Evidence.source_process_id -ne
            [Int64]$SourceBinding.process_id -or
        [string]$Evidence.source_ownership_id_sha256 -cne
            [string]$SourceBinding.ownership_id_sha256 -or
        -not [bool]$Evidence.retained_handle_observed_exit -or
        -not [bool]$Evidence.has_exited) {
        throw 'Source process exit evidence is not exact and post-arm'
    }
    return $true
}

function Assert-D01SourceObservationContract {
    param([Parameter(Mandatory = $true)][object]$Observation)
    $null = Assert-D01ExactPropertySet -Object $Observation -Expected @(
        'schema', 'case_id', 'run_nonce', 'captured_at_utc',
        'source_process_id', 'source_process_emule_sha256', 'connection',
        'exact_inverse_pid_socket', 'physical_adapter_proven',
        'baseline_zero', 'baseline_established_connection_count',
        'baseline_nonlisten_connection_count',
        'all_processes_and_nonlisten_states_checked',
        'allowed_source_visible_remote_addresses',
        'source_visible_remote_address_allowed', 'foreign_connection_count',
        'all_nonlisten_unique_socket_count', 'new_socket_key_sha256',
        'first_seen_sample', 'confirmed_sample', 'unique_new_socket_count',
        'ambiguity_count', 'generation_count',
        'observation_window_started_at_utc',
        'hairpin_nat_remote_address_not_assumed'
    ) -Context 'source-observation.json'
    foreach ($name in @(
        'schema', 'case_id', 'run_nonce', 'captured_at_utc',
        'source_process_emule_sha256', 'new_socket_key_sha256',
        'observation_window_started_at_utc'
    )) {
        $null = Assert-D01JsonStringValue `
            -Value $Observation.PSObject.Properties[$name].Value `
            -Context "source-observation.json.$name"
    }
    if ([string]$Observation.schema -cne
            'ese.v91.d01-source-observation/v4' -or
        [string]$Observation.run_nonce -cnotmatch '^[0-9a-f]{32}$' -or
        [string]$Observation.source_process_emule_sha256 -cnotmatch
            '^[0-9a-f]{64}$' -or
        [string]$Observation.new_socket_key_sha256 -cnotmatch
            '^[0-9a-f]{64}$') {
        throw 'source-observation.json identity contract is not exact'
    }
    foreach ($name in @(
        'source_process_id', 'baseline_established_connection_count',
        'baseline_nonlisten_connection_count', 'foreign_connection_count',
        'all_nonlisten_unique_socket_count', 'first_seen_sample',
        'confirmed_sample', 'unique_new_socket_count', 'ambiguity_count',
        'generation_count'
    )) {
        $minimum = if ($name -eq 'source_process_id') { 1 } else { 0 }
        $null = Assert-D01JsonInteger `
            -Value $Observation.PSObject.Properties[$name].Value `
            -Context "source-observation.json.$name" -Minimum $minimum
    }
    foreach ($name in @(
        'exact_inverse_pid_socket', 'physical_adapter_proven',
        'baseline_zero', 'all_processes_and_nonlisten_states_checked',
        'source_visible_remote_address_allowed',
        'hairpin_nat_remote_address_not_assumed'
    )) {
        $null = Assert-D01JsonBoolean `
            -Value $Observation.PSObject.Properties[$name].Value `
            -Context "source-observation.json.$name"
    }
    $null = Assert-D01JsonStringArray `
        -Value $Observation.allowed_source_visible_remote_addresses `
        -Context 'source-observation.json.allowed_source_visible_remote_addresses' `
        -RequireUnique
    $connection = $Observation.connection
    $null = Assert-D01ExactPropertySet -Object $connection -Expected @(
        'captured_at_utc', 'owning_process', 'state', 'local_address',
        'local_port', 'remote_address', 'remote_port',
        'local_address_assigned', 'adapter', 'physical_nonvirtual'
    ) -Context 'source-observation.json.connection'
    foreach ($name in @(
        'captured_at_utc', 'state', 'local_address', 'remote_address'
    )) {
        $null = Assert-D01JsonStringValue `
            -Value $connection.PSObject.Properties[$name].Value `
            -Context "source-observation.json.connection.$name"
    }
    foreach ($name in @('owning_process', 'local_port', 'remote_port')) {
        $null = Assert-D01JsonInteger `
            -Value $connection.PSObject.Properties[$name].Value `
            -Context "source-observation.json.connection.$name" `
            -Minimum 1 -Maximum ([int]::MaxValue)
    }
    foreach ($name in @('local_address_assigned', 'physical_nonvirtual')) {
        $null = Assert-D01JsonBoolean `
            -Value $connection.PSObject.Properties[$name].Value `
            -Context "source-observation.json.connection.$name"
    }
    $null = Assert-D01AdapterEvidenceContract -Adapter $connection.adapter `
        -Context 'source-observation.json.connection.adapter'
    return $true
}

function Assert-D01StopCommandContract {
    param([Parameter(Mandatory = $true)][object]$Command)
    $null = Assert-D01ExactPropertySet -Object $Command -Expected @(
        'schema', 'case_id', 'run_nonce', 'generated_at_utc',
        'candidate_commit', 'candidate_emule_sha256', 'action'
    ) -Context 'stop.json'
    foreach ($name in @(
        'schema', 'case_id', 'run_nonce', 'generated_at_utc',
        'candidate_commit', 'candidate_emule_sha256', 'action'
    )) {
        $null = Assert-D01JsonStringValue `
            -Value $Command.PSObject.Properties[$name].Value `
            -Context "stop.json.$name"
    }
    if ([string]$Command.schema -cne 'ese.v91.d01-stop-command/v2' -or
        [string]$Command.run_nonce -cnotmatch '^[0-9a-f]{32}$' -or
        [string]$Command.candidate_commit -cnotmatch '^[0-9a-f]{40}$' -or
        [string]$Command.candidate_emule_sha256 -cnotmatch
            '^[0-9a-f]{64}$' -or
        [string]$Command.action -cne 'stop-owned-source') {
        throw 'stop.json contract is not exact'
    }
    return $true
}

function Assert-D01SourceResultCoordinationContract {
    param(
        [Parameter(Mandatory = $true)][object]$Result,
        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 65535)][int]$ExpectedSourceWebPort
    )
    $null = Assert-D01ExactPropertySet -Object $Result -Expected @(
        'schema', 'case_id', 'run_nonce', 'publication_id',
        'generated_at_utc', 'status',
        'runtime_error', 'failure_stage', 'machine_id_sha256',
        'operator_identity', 'candidate', 'topology', 'source_process_id',
        'source_process_binding', 'source_listener', 'source_arm',
        'product_process_exited_after_arm',
        'first_api_isolation_failure_evidence',
        'first_ui_timeout_failure_evidence', 'process_exit_evidence', 'fixture',
        'inverse_socket_observation', 'inverse_socket_observed',
        'inverse_socket_baseline_zero',
        'inverse_socket_baseline_all_nonlisten_states_checked',
        'inverse_socket_allowed_remote_addresses',
        'inverse_socket_foreign_connection_count',
        'inverse_socket_all_nonlisten_unique_count',
        'inverse_socket_unique_new_count', 'inverse_socket_ambiguity_count',
        'inverse_socket_generation_count', 'product_observability_complete',
        'health', 'cleanup'
    ) -Context 'source-result.json'
    foreach ($name in @(
        'schema', 'case_id', 'run_nonce', 'generated_at_utc', 'status',
        'failure_stage', 'machine_id_sha256'
    )) {
        $null = Assert-D01JsonStringValue `
            -Value $Result.PSObject.Properties[$name].Value `
            -Context "source-result.json.$name"
    }
    $null = Assert-D01JsonBoolean `
        -Value $Result.product_observability_complete `
        -Context 'source-result.json.product_observability_complete'
    $null = Assert-D01JsonBoolean `
        -Value $Result.product_process_exited_after_arm `
        -Context 'source-result.json.product_process_exited_after_arm'
    if ([string]$Result.schema -cne 'ese.v91.d01-source-result/v8' -or
        [string]$Result.run_nonce -cnotmatch '^[0-9a-f]{32}$' -or
        [string]$Result.publication_id -cnotmatch '^[0-9a-f]{32}$' -or
        [string]$Result.status -notin @('COMPLETE', 'INCOMPLETE') -or
        [string]$Result.machine_id_sha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'source-result.json identity contract is not exact'
    }
    if ($null -ne $Result.runtime_error -and
        $Result.runtime_error -isnot [string]) {
        throw 'source-result.json.runtime_error is not null or a string'
    }
    $null = Assert-D01HostIdentityEvidenceContract `
        -Identity $Result.operator_identity `
        -Context 'source-result.json.operator_identity'
    if ($null -ne $Result.source_arm) {
        $null = Assert-D01SourceArmedContract -Ack $Result.source_arm
        if ([string]$Result.source_arm.case_id -cne
                [string]$Result.case_id -or
            [string]$Result.source_arm.run_nonce -cne
                [string]$Result.run_nonce -or
            ($null -ne $Result.source_process_id -and
                [Int64]$Result.source_arm.source_process_id -ne
                    [Int64]$Result.source_process_id)) {
            throw 'source-result.json source arm identity is contradictory'
        }
    }
    if ($null -ne $Result.source_process_binding) {
        $null = Assert-D01ProcessBindingEvidenceContract `
            -Binding $Result.source_process_binding `
            -Context 'source-result.json.source_process_binding'
        if ($null -eq $Result.source_process_id -or
            [Int64]$Result.source_process_binding.process_id -ne
                [Int64]$Result.source_process_id -or
            [string]$Result.source_process_binding.owner_role -cne 'Source' -or
            [string]$Result.source_process_binding.run_nonce -cne
                [string]$Result.run_nonce) {
            throw 'source-result.json retained process binding is contradictory'
        }
    }
    if ($null -ne $Result.source_arm -and
        $null -eq $Result.source_process_binding) {
        throw 'source-result.json source arm lacks retained process binding'
    }
    $null = Assert-D01ExactPropertySet -Object $Result.candidate -Expected @(
        'commit', 'emule_sha256', 'package_zip_sha256', 'unchanged',
        'prepared_executable_unchanged'
    ) -Context 'source-result.json.candidate'
    $null = Assert-D01JsonStringValue -Value $Result.candidate.commit `
        -Context 'source-result.json.candidate.commit' `
        -Pattern '^[0-9a-f]{40}$'
    foreach ($name in @('emule_sha256', 'package_zip_sha256')) {
        $null = Assert-D01JsonStringValue `
            -Value $Result.candidate.PSObject.Properties[$name].Value `
            -Context "source-result.json.candidate.$name" `
            -Pattern '^[0-9a-f]{64}$'
    }
    foreach ($name in @('unchanged', 'prepared_executable_unchanged')) {
        $null = Assert-D01JsonBoolean `
            -Value $Result.candidate.PSObject.Properties[$name].Value `
            -Context "source-result.json.candidate.$name"
    }
    if ($null -ne $Result.fixture) {
        $null = Assert-D01ExactPropertySet -Object $Result.fixture -Expected @(
            'file_name', 'file_bytes', 'file_sha256', 'ed2k_hash',
            'immutable_source_lock_held', 'post_stop_bytes',
            'post_stop_sha256', 'unchanged_after_stop'
        ) -Context 'source-result.json.fixture'
        $resultFileName = [string]$Result.fixture.file_name
        $null = Assert-D01JsonStringValue -Value $resultFileName `
            -Context 'source-result.json.fixture.file_name'
        if ($resultFileName.Length -gt 200 -or
            $resultFileName -in @('.', '..') -or
            [IO.Path]::IsPathRooted($resultFileName) -or
            [IO.Path]::GetFileName($resultFileName) -cne $resultFileName -or
            $resultFileName.IndexOfAny(
                [IO.Path]::GetInvalidFileNameChars()) -ge 0) {
            throw 'source-result.json.fixture.file_name is not a safe leaf name'
        }
        $null = Assert-D01JsonInteger -Value $Result.fixture.file_bytes `
            -Context 'source-result.json.fixture.file_bytes' -Minimum 1
        $null = Assert-D01JsonStringValue -Value $Result.fixture.file_sha256 `
            -Context 'source-result.json.fixture.file_sha256' `
            -Pattern '^[0-9a-f]{64}$'
        $null = Assert-D01JsonStringValue -Value $Result.fixture.ed2k_hash `
            -Context 'source-result.json.fixture.ed2k_hash' `
            -Pattern '^[0-9A-F]{32}$'
        foreach ($name in @(
            'immutable_source_lock_held', 'unchanged_after_stop'
        )) {
            $null = Assert-D01JsonBoolean `
                -Value $Result.fixture.PSObject.Properties[$name].Value `
                -Context "source-result.json.fixture.$name"
        }
        $null = Assert-D01JsonInteger -Value $Result.fixture.post_stop_bytes `
            -Context 'source-result.json.fixture.post_stop_bytes' -Minimum 1
        $null = Assert-D01JsonStringValue `
            -Value $Result.fixture.post_stop_sha256 `
            -Context 'source-result.json.fixture.post_stop_sha256' `
            -Pattern '^[0-9a-f]{64}$'
    }
    foreach ($name in @(
        'inverse_socket_observed', 'inverse_socket_baseline_zero',
        'inverse_socket_baseline_all_nonlisten_states_checked'
    )) {
        $null = Assert-D01JsonBoolean `
            -Value $Result.PSObject.Properties[$name].Value `
            -Context "source-result.json.$name"
    }
    $null = Assert-D01JsonStringArray `
        -Value $Result.inverse_socket_allowed_remote_addresses `
        -Context 'source-result.json.inverse_socket_allowed_remote_addresses' `
        -RequireUnique
    foreach ($name in @(
        'inverse_socket_foreign_connection_count',
        'inverse_socket_all_nonlisten_unique_count',
        'inverse_socket_unique_new_count', 'inverse_socket_ambiguity_count',
        'inverse_socket_generation_count'
    )) {
        $null = Assert-D01JsonInteger `
            -Value $Result.PSObject.Properties[$name].Value `
            -Context "source-result.json.$name" -Minimum 0
    }
    $null = Assert-D01ExactPropertySet -Object $Result.health -Expected @(
        'observability_available', 'api_sample_count',
        'api_unavailable_count', 'api_isolation_failure_count',
        'ui_sample_count', 'ui_unavailable_count',
        'ui_unresponsive_count'
    ) -Context 'source-result.json.health'
    $null = Assert-D01JsonBoolean `
        -Value $Result.health.observability_available `
        -Context 'source-result.json.health.observability_available'
    foreach ($name in @(
        'api_sample_count', 'api_unavailable_count',
        'api_isolation_failure_count', 'ui_sample_count',
        'ui_unavailable_count', 'ui_unresponsive_count'
    )) {
        $null = Assert-D01JsonInteger `
            -Value $Result.health.PSObject.Properties[$name].Value `
            -Context "source-result.json.health.$name" -Minimum 0
    }
    $hasApiFailureEvidence =
        $null -ne $Result.first_api_isolation_failure_evidence
    $hasUiFailureEvidence =
        $null -ne $Result.first_ui_timeout_failure_evidence
    $hasProcessExitEvidence = $null -ne $Result.process_exit_evidence
    if (($Result.health.api_isolation_failure_count -gt 0) -ne
            $hasApiFailureEvidence -or
        ($Result.health.ui_unresponsive_count -gt 0) -ne
            $hasUiFailureEvidence -or
        [bool]$Result.product_process_exited_after_arm -ne
            $hasProcessExitEvidence) {
        throw 'source-result.json positive failure counters lack exact evidence'
    }
    if ($hasApiFailureEvidence -or $hasUiFailureEvidence -or
        $hasProcessExitEvidence) {
        if ($null -eq $Result.source_arm -or
            $null -eq $Result.source_process_binding) {
            throw 'source-result.json positive evidence lacks arm/process binding'
        }
    }
    if ($hasApiFailureEvidence) {
        $null = Assert-D01SourceApiFailureEvidenceContract `
            -Evidence $Result.first_api_isolation_failure_evidence `
            -SourceArm $Result.source_arm `
            -SourceBinding $Result.source_process_binding `
            -ExpectedWebPort $ExpectedSourceWebPort
        if ([Int64]$Result.first_api_isolation_failure_evidence.sample_number -gt
            [Int64]$Result.health.api_sample_count) {
            throw 'source-result.json API failure sample is outside aggregate'
        }
    }
    if ($hasUiFailureEvidence) {
        $null = Assert-D01SourceUiFailureEvidenceContract `
            -Evidence $Result.first_ui_timeout_failure_evidence `
            -SourceArm $Result.source_arm `
            -SourceBinding $Result.source_process_binding
        if ([Int64]$Result.first_ui_timeout_failure_evidence.sample_number -gt
            [Int64]$Result.health.ui_sample_count) {
            throw 'source-result.json UI failure sample is outside aggregate'
        }
    }
    if ($hasProcessExitEvidence) {
        $null = Assert-D01SourceProcessExitEvidenceContract `
            -Evidence $Result.process_exit_evidence `
            -SourceArm $Result.source_arm `
            -SourceBinding $Result.source_process_binding
    }
    $null = Assert-D01ExactPropertySet -Object $Result.cleanup -Expected @(
        'source_process_stopped', 'temporary_firewall_rules_created',
        'temporary_firewall_rules_removed', 'ipv4_allow_rule_name',
        'ipv6_drop_rule_name', 'firewall_armed_evidence',
        'program_containment_armed_evidence',
        'program_containment_removed',
        'program_containment_enforcement_exact_through_disarm',
        'candidate_unchanged', 'prepared_executable_unchanged',
        'dns_modified', 'hosts_modified', 'routes_modified',
        'adapters_modified', 'overlay_vpn_modified', 'proxy_modified',
        'account_registry_firewall_postcheck', 'terminal_ownership',
        'hosts_file_postcheck', 'failures'
    ) -Context 'source-result.json.cleanup'
    foreach ($name in @(
        'source_process_stopped', 'temporary_firewall_rules_created',
        'temporary_firewall_rules_removed', 'program_containment_removed',
        'program_containment_enforcement_exact_through_disarm',
        'candidate_unchanged',
        'prepared_executable_unchanged', 'dns_modified', 'hosts_modified',
        'routes_modified', 'adapters_modified', 'overlay_vpn_modified',
        'proxy_modified'
    )) {
        $null = Assert-D01JsonBoolean `
            -Value $Result.cleanup.PSObject.Properties[$name].Value `
            -Context "source-result.json.cleanup.$name"
    }
    foreach ($name in @('ipv4_allow_rule_name', 'ipv6_drop_rule_name')) {
        $null = Assert-D01JsonStringValue `
            -Value $Result.cleanup.PSObject.Properties[$name].Value `
            -Context "source-result.json.cleanup.$name"
    }
    $null = Assert-D01JsonStringArray -Value $Result.cleanup.failures `
        -Context 'source-result.json.cleanup.failures'
    if ($null -ne $Result.cleanup.program_containment_armed_evidence) {
        $null = Assert-D01ProgramContainmentArmedContract `
            -Evidence $Result.cleanup.program_containment_armed_evidence `
            -Context (
                'source-result.json.cleanup.program_containment_armed_evidence')
    }
    if ([bool]$Result.product_observability_complete) {
        if ($null -eq $Result.source_arm) {
            throw 'source-result.json product observation lacks source arm'
        }
        if ($null -eq $Result.fixture) {
            throw 'source-result.json COMPLETE lacks exact fixture identity'
        }
        if (-not [bool]$Result.fixture.immutable_source_lock_held -or
            -not [bool]$Result.fixture.unchanged_after_stop -or
            [Int64]$Result.fixture.post_stop_bytes -ne
                [Int64]$Result.fixture.file_bytes -or
            [string]$Result.fixture.post_stop_sha256 -cne
                [string]$Result.fixture.file_sha256) {
            throw 'source-result.json COMPLETE fixture was not immutable'
        }
        $null = Assert-D01JsonInteger -Value $Result.source_process_id `
            -Context 'source-result.json.source_process_id' -Minimum 1 `
            -Maximum ([int]::MaxValue)
        $null = Assert-D01ProcessBindingEvidenceContract `
            -Binding $Result.source_process_binding `
            -Context 'source-result.json.source_process_binding'
        if ([Int64]$Result.source_process_binding.process_id -ne
                [Int64]$Result.source_process_id -or
            [string]$Result.source_process_binding.owner_role -cne 'Source' -or
            [string]$Result.source_process_binding.run_nonce -cne
                [string]$Result.run_nonce -or
            [string]$Result.source_process_binding.executable_sha256 -cne
                [string]$Result.candidate.emule_sha256) {
            throw 'source-result.json process binding is contradictory'
        }
        if ([Int64]$Result.source_arm.source_process_id -ne
                [Int64]$Result.source_process_id -or
            [string]$Result.source_arm.source_ownership_id_sha256 -cne
                [string]$Result.source_process_binding.ownership_id_sha256) {
            throw 'source-result.json source arm is not process-bound'
        }
        $null = Assert-D01ExactPropertySet -Object $Result.source_listener `
            -Expected @('process_id', 'ipv4_only', 'listeners') `
            -Context 'source-result.json.source_listener'
        $listenerProcessId = Assert-D01JsonInteger `
            -Value $Result.source_listener.process_id `
            -Context 'source-result.json.source_listener.process_id' `
            -Minimum 1 -Maximum ([int]::MaxValue)
        $null = Assert-D01JsonBoolean `
            -Value $Result.source_listener.ipv4_only `
            -Context 'source-result.json.source_listener.ipv4_only'
        if ($listenerProcessId -ne [Int64]$Result.source_process_id -or
            -not [bool]$Result.source_listener.ipv4_only -or
            $Result.source_listener.listeners -isnot [Array] -or
            @($Result.source_listener.listeners).Count -eq 0) {
            throw 'source-result.json source listener is not exact'
        }
        foreach ($listener in @($Result.source_listener.listeners)) {
            $null = Assert-D01ExactPropertySet -Object $listener -Expected @(
                'local_address', 'local_port', 'owning_process'
            ) -Context 'source-result.json.source_listener.listeners[]'
            if ([int]$listener.owning_process -ne
                    [int]$Result.source_process_id -or
                [int]$listener.local_port -lt 1 -or
                [int]$listener.local_port -gt 65535) {
                throw 'source-result.json listener is foreign or invalid'
            }
            $null = Get-D01NormalizedIp -Address ([string]$listener.local_address)
        }
        $null = Assert-D01ExactPropertySet -Object $Result.topology -Expected @(
            'machine_id_sha256', 'source_local_ipv4', 'source_public_ipv4',
            'source_public_ipv4_is_nat', 'source_ipv6',
            'route_to_coordinator_public_ipv4', 'route_to_coordinator_ipv6',
            'allowed_inverse_remote_addresses', 'native_physical',
            'overlay_vpn_proxy_absent'
        ) -Context 'source-result.json.topology'
        $null = Assert-D01AssignedAddressEvidenceContract `
            -Assigned $Result.topology.source_local_ipv4 `
            -Context 'source-result.json.topology.source_local_ipv4'
        $null = Assert-D01AssignedAddressEvidenceContract `
            -Assigned $Result.topology.source_ipv6 `
            -Context 'source-result.json.topology.source_ipv6'
        $null = Assert-D01RouteEvidenceContract `
            -Route $Result.topology.route_to_coordinator_public_ipv4 `
            -Context 'source-result.json.topology.route_to_coordinator_public_ipv4'
        $null = Assert-D01RouteEvidenceContract `
            -Route $Result.topology.route_to_coordinator_ipv6 `
            -Context 'source-result.json.topology.route_to_coordinator_ipv6'
        $null = Assert-D01JsonStringArray `
            -Value $Result.topology.allowed_inverse_remote_addresses `
            -Context (
                'source-result.json.topology.allowed_inverse_remote_addresses') `
            -RequireUnique
        if ([string]$Result.topology.machine_id_sha256 -cne
                [string]$Result.machine_id_sha256 -or
            -not [bool]$Result.topology.native_physical -or
            -not [bool]$Result.topology.overlay_vpn_proxy_absent) {
            throw 'source-result.json topology is not role-bound and physical'
        }
        $null = Assert-D01SourceObservationContract `
            -Observation $Result.inverse_socket_observation
        if ([string]$Result.inverse_socket_observation.case_id -cne
                [string]$Result.case_id -or
            [string]$Result.inverse_socket_observation.run_nonce -cne
                [string]$Result.run_nonce -or
            [Int64]$Result.inverse_socket_observation.source_process_id -ne
                [Int64]$Result.source_process_id -or
            [string]$Result.inverse_socket_observation.
                source_process_emule_sha256 -cne
                [string]$Result.candidate.emule_sha256) {
            throw 'source-result.json inverse observation is contradictory'
        }
        [string[]]$resultAllowed = @(
            $Result.inverse_socket_allowed_remote_addresses |
                ForEach-Object { [string]$_ } | Sort-Object -Unique)
        [string[]]$observationAllowed = @(
            $Result.inverse_socket_observation.
                allowed_source_visible_remote_addresses |
                ForEach-Object { [string]$_ } | Sort-Object -Unique)
        if (-not [bool]$Result.inverse_socket_observed -or
            -not [bool]$Result.inverse_socket_baseline_zero -or
            -not [bool]$Result.
                inverse_socket_baseline_all_nonlisten_states_checked -or
            $resultAllowed.Count -eq 0 -or
            ($resultAllowed -join "`n") -cne
                ($observationAllowed -join "`n") -or
            [int]$Result.inverse_socket_foreign_connection_count -ne 0 -or
            [int]$Result.inverse_socket_all_nonlisten_unique_count -ne 1 -or
            [int]$Result.inverse_socket_unique_new_count -ne 1 -or
            [int]$Result.inverse_socket_ambiguity_count -ne 0 -or
            [int]$Result.inverse_socket_generation_count -ne 1 -or
            [int]$Result.inverse_socket_observation.foreign_connection_count -ne
                [int]$Result.inverse_socket_foreign_connection_count -or
            [int]$Result.inverse_socket_observation.
                all_nonlisten_unique_socket_count -ne
                [int]$Result.inverse_socket_all_nonlisten_unique_count -or
            [int]$Result.inverse_socket_observation.unique_new_socket_count -ne
                [int]$Result.inverse_socket_unique_new_count -or
            [int]$Result.inverse_socket_observation.ambiguity_count -ne
                [int]$Result.inverse_socket_ambiguity_count -or
            [int]$Result.inverse_socket_observation.generation_count -ne
                [int]$Result.inverse_socket_generation_count -or
            -not [bool]$Result.inverse_socket_observation.baseline_zero -or
            -not [bool]$Result.inverse_socket_observation.
                all_processes_and_nonlisten_states_checked -or
            -not [bool]$Result.inverse_socket_observation.
                exact_inverse_pid_socket -or
            -not [bool]$Result.inverse_socket_observation.
                physical_adapter_proven -or
            -not [bool]$Result.inverse_socket_observation.
                source_visible_remote_address_allowed -or
            -not [bool]$Result.inverse_socket_observation.
                hairpin_nat_remote_address_not_assumed) {
            throw 'source-result.json final inverse uniqueness is not exact'
        }
        if (-not [bool]$Result.health.observability_available -or
            [int]$Result.health.api_sample_count -lt 1 -or
            [int]$Result.health.ui_sample_count -lt 1 -or
            [int]$Result.health.api_unavailable_count -ne 0 -or
            [int]$Result.health.ui_unavailable_count -ne 0) {
            throw 'source-result.json product health observability is false'
        }
        if ($null -eq $Result.cleanup.program_containment_armed_evidence -or
            -not [bool]$Result.cleanup.
                program_containment_armed_evidence.exact -or
            [string]$Result.cleanup.program_containment_armed_evidence.role -cne
                'Source' -or
            [int]$Result.cleanup.program_containment_armed_evidence.rule_count -ne
                4 -or
            [string]$Result.cleanup.program_containment_armed_evidence.
                program_path_sha256 -cne
                [string]$Result.source_process_binding.path_sha256) {
            throw 'source-result.json product containment is not exact'
        }
    }
    if ([string]$Result.status -ceq 'COMPLETE') {
        if (-not [bool]$Result.product_observability_complete -or
            $null -ne $Result.runtime_error -or
            [bool]$Result.product_process_exited_after_arm -or
            [int]$Result.health.api_isolation_failure_count -ne 0 -or
            [int]$Result.health.ui_unresponsive_count -ne 0) {
            throw 'source-result.json COMPLETE product contract is false'
        }
        if (-not [bool]$Result.cleanup.source_process_stopped -or
            -not [bool]$Result.cleanup.temporary_firewall_rules_created -or
            -not [bool]$Result.cleanup.temporary_firewall_rules_removed -or
            -not [bool]$Result.cleanup.program_containment_removed -or
            -not [bool]$Result.cleanup.
                program_containment_enforcement_exact_through_disarm -or
            $null -eq $Result.cleanup.program_containment_armed_evidence -or
            -not [bool]$Result.cleanup.
                program_containment_armed_evidence.exact -or
            [string]$Result.cleanup.program_containment_armed_evidence.role -cne
                'Source' -or
            [int]$Result.cleanup.program_containment_armed_evidence.rule_count -ne
                4 -or
            [string]$Result.cleanup.program_containment_armed_evidence.
                program_path_sha256 -cne
                [string]$Result.source_process_binding.path_sha256 -or
            -not [bool]$Result.cleanup.candidate_unchanged -or
            -not [bool]$Result.cleanup.prepared_executable_unchanged -or
            [bool]$Result.cleanup.dns_modified -or
            [bool]$Result.cleanup.hosts_modified -or
            [bool]$Result.cleanup.routes_modified -or
            [bool]$Result.cleanup.adapters_modified -or
            [bool]$Result.cleanup.overlay_vpn_modified -or
            [bool]$Result.cleanup.proxy_modified -or
            @($Result.cleanup.failures).Count -ne 0 -or
            [bool]$Result.cleanup.candidate_unchanged -ne
                [bool]$Result.candidate.unchanged -or
            [bool]$Result.cleanup.prepared_executable_unchanged -ne
                [bool]$Result.candidate.prepared_executable_unchanged) {
            throw 'source-result.json COMPLETE cleanup contract is false'
        }
        $null = Assert-D01ExactPropertySet `
            -Object $Result.cleanup.firewall_armed_evidence `
            -Expected @('ipv4_allow', 'ipv6_drop') `
            -Context 'source-result.json.cleanup.firewall_armed_evidence'
        $null = Assert-D01FirewallRuleEvidenceContract `
            -Rule $Result.cleanup.firewall_armed_evidence.ipv4_allow `
            -Context (
                'source-result.json.cleanup.firewall_armed_evidence.ipv4_allow')
        $null = Assert-D01FirewallRuleEvidenceContract `
            -Rule $Result.cleanup.firewall_armed_evidence.ipv6_drop `
            -Context (
                'source-result.json.cleanup.firewall_armed_evidence.ipv6_drop')
        $null = Assert-D01AccountRegistryPostcheckContract `
            -Postcheck $Result.cleanup.account_registry_firewall_postcheck `
            -Context (
                'source-result.json.cleanup.account_registry_firewall_postcheck')
        if ([string]$Result.cleanup.account_registry_firewall_postcheck.
                baseline.user_sid_sha256 -cne
                [string]$Result.operator_identity.user_sid_sha256 -or
            [string]$Result.cleanup.account_registry_firewall_postcheck.
                post_state.user_sid_sha256 -cne
                [string]$Result.operator_identity.user_sid_sha256) {
            throw 'source-result.json registry postcheck SID is not role-bound'
        }
        $null = Assert-D01TerminalOwnershipContract `
            -Census $Result.cleanup.terminal_ownership `
            -Context 'source-result.json.cleanup.terminal_ownership'
        if ([string]$Result.cleanup.terminal_ownership.role -cne 'Source') {
            throw 'source-result.json terminal census role is not Source'
        }
        if ([Int64]$Result.cleanup.terminal_ownership.process_id -ne
                [Int64]$Result.source_process_id) {
            throw 'source-result.json terminal census process is not source-bound'
        }
        $null = Assert-D01HostsFilePostcheckContract `
            -Postcheck $Result.cleanup.hosts_file_postcheck `
            -Context 'source-result.json.cleanup.hosts_file_postcheck'
    }
    return $true
}

function Assert-D01SourceResultCommitContract {
    param([Parameter(Mandatory = $true)][object]$Commit)

    $null = Assert-D01ExactPropertySet -Object $Commit -Expected @(
        'schema', 'case_id', 'run_nonce', 'publication_id',
        'committed_at_utc', 'status', 'exit_code',
        'private_summary_sha256', 'public_summary_sha256',
        'coordination_result_sha256', 'local_commit_sha256'
    ) -Context 'source-result-commit.json'
    foreach ($name in @(
        'schema', 'case_id', 'run_nonce', 'publication_id',
        'committed_at_utc', 'status', 'private_summary_sha256',
        'public_summary_sha256', 'coordination_result_sha256',
        'local_commit_sha256'
    )) {
        $null = Assert-D01JsonStringValue `
            -Value $Commit.PSObject.Properties[$name].Value `
            -Context "source-result-commit.json.$name"
    }
    $exitCode = Assert-D01JsonInteger -Value $Commit.exit_code `
        -Context 'source-result-commit.json.exit_code' -Minimum 0 -Maximum 2
    if ([string]$Commit.schema -cne
            'ese.v91.d01-source-result-commit/v1' -or
        [string]$Commit.run_nonce -cnotmatch '^[0-9a-f]{32}$' -or
        [string]$Commit.publication_id -cnotmatch '^[0-9a-f]{32}$' -or
        [string]$Commit.status -notin @('COMPLETE', 'INCOMPLETE') -or
        ($Commit.status -ceq 'COMPLETE' -and $exitCode -ne 0) -or
        ($Commit.status -ceq 'INCOMPLETE' -and $exitCode -ne 2)) {
        throw 'source-result-commit.json identity/status is not exact'
    }
    foreach ($name in @(
        'private_summary_sha256', 'public_summary_sha256',
        'coordination_result_sha256', 'local_commit_sha256'
    )) {
        if ([string]$Commit.PSObject.Properties[$name].Value -cnotmatch
            '^[0-9a-f]{64}$') {
            throw "source-result-commit.json.$name is not a lowercase SHA-256"
        }
    }
    if ([string]$Commit.private_summary_sha256 -cne
            [string]$Commit.coordination_result_sha256) {
        throw (
            'source-result-commit.json does not bind the committed private ' +
            'result to the coordinator-facing result'
        )
    }
    return $true
}

function Assert-D01AdjudicationCommitContract {
    param(
        [Parameter(Mandatory = $true)][object]$Commit,
        [Parameter(Mandatory = $true)][string]$ExpectedCaseId,
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[0-9a-f]{32}$')][string]$ExpectedPublicationId,
        [Parameter(Mandatory = $true)]
        [ValidateSet('PASS', 'FAIL', 'BLOCKED')][string]$ExpectedStatus,
        [Parameter(Mandatory = $true)]
        [ValidateRange(0, 2)][int]$ExpectedExitCode,
        [AllowEmptyString()]
        [ValidatePattern('^(?:|[0-9a-f]{64})$')]
        [string]$ExpectedPktmonPrecommitSha256 = ''
    )
    $null = Assert-D01ExactPropertySet -Object $Commit -Expected @(
        'schema', 'case_id', 'publication_id', 'committed_at_utc',
        'formal_status', 'exit_code', 'public_summary_sha256',
        'private_summary_sha256', 'pktmon_precommit_state_sha256'
    ) -Context 'adjudication-commit.json'
    foreach ($name in @(
        'schema', 'case_id', 'publication_id', 'committed_at_utc',
        'formal_status', 'public_summary_sha256', 'private_summary_sha256'
    )) {
        $null = Assert-D01JsonStringValue `
            -Value $Commit.PSObject.Properties[$name].Value `
            -Context "adjudication-commit.json.$name" -Pattern '^.+$'
    }
    $exitCode = Assert-D01JsonInteger -Value $Commit.exit_code `
        -Context 'adjudication-commit.json.exit_code' -Minimum 0 -Maximum 2
    if ([string]$Commit.schema -cne
            'ese.v91.d01-adjudication-commit/v2' -or
        [string]$Commit.case_id -cne $ExpectedCaseId -or
        [string]$Commit.publication_id -cne $ExpectedPublicationId -or
        [string]$Commit.formal_status -cne $ExpectedStatus -or
        [string]$Commit.pktmon_precommit_state_sha256 -cne
            $ExpectedPktmonPrecommitSha256 -or
        $exitCode -ne $ExpectedExitCode -or
        ($ExpectedStatus -ceq 'PASS' -and $exitCode -ne 0) -or
        ($ExpectedStatus -ceq 'FAIL' -and $exitCode -ne 1) -or
        ($ExpectedStatus -ceq 'BLOCKED' -and $exitCode -ne 2)) {
        throw 'adjudication-commit.json status/identity is not exact'
    }
    foreach ($name in @(
        'public_summary_sha256', 'private_summary_sha256'
    )) {
        if ([string]$Commit.PSObject.Properties[$name].Value -cnotmatch
            '^[0-9a-f]{64}$') {
            throw "adjudication-commit.json.$name is not a lowercase SHA-256"
        }
    }
    $null = Assert-D01JsonStringValue `
        -Value $Commit.pktmon_precommit_state_sha256 `
        -Context 'adjudication-commit.json.pktmon_precommit_state_sha256' `
        -Pattern '^(?:|[0-9a-f]{64})$'
    return $true
}

function Assert-D01TelemetryPayloadContract {
    param([Parameter(Mandatory = $true)][object]$Data)
    $null = Assert-D01ExactPropertySet -Object $Data `
        -Expected @('schema', 'sequence', 'events') -Context 'telemetry'
    if ($Data.schema -isnot [string] -or
        [string]$Data.schema -cne 'ese.debug.source-resolutions/v1') {
        throw 'Telemetry schema is not exact'
    }
    $topSequence = Assert-D01JsonInteger -Value $Data.sequence `
        -Context 'telemetry.sequence' -Minimum 0
    if ($Data.events -isnot [Array]) {
        throw 'Telemetry events is not a JSON array'
    }
    $lastSequence = [Int64]-1
    foreach ($event in @($Data.events)) {
        $null = Assert-D01ExactPropertySet -Object $event -Expected @(
            'sequence', 'hostname_sha256', 'file_ed2k_hash', 'port',
            'resolver_result', 'resolved', 'materialized', 'candidates'
        ) -Context 'telemetry.event'
        $sequence = Assert-D01JsonInteger -Value $event.sequence `
            -Context 'telemetry.event.sequence' -Minimum 0
        if ($sequence -le $lastSequence -or $sequence -gt $topSequence) {
            throw 'Telemetry event sequence is non-monotonic/out of range'
        }
        $lastSequence = $sequence
        if ($event.hostname_sha256 -isnot [string] -or
            [string]$event.hostname_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            $event.file_ed2k_hash -isnot [string] -or
            [string]$event.file_ed2k_hash -cnotmatch '^[0-9a-f]{32}$' -or
            $event.resolver_result -isnot [string] -or
            [string]$event.resolver_result -cne 'success') {
            throw 'Telemetry event scalar contract is invalid'
        }
        $null = Assert-D01JsonInteger -Value $event.port `
            -Context 'telemetry.event.port' -Minimum 1 -Maximum 65535
        $null = Assert-D01ExactPropertySet -Object $event.resolved `
            -Expected @('ipv4_count', 'ipv6_count', 'endpoint_set_sha256') `
            -Context 'telemetry.event.resolved'
        $null = Assert-D01ExactPropertySet -Object $event.materialized `
            -Expected @('ipv4_count', 'ipv6_count', 'endpoint_set_sha256',
                'simultaneously_retained') `
            -Context 'telemetry.event.materialized'
        foreach ($set in @($event.resolved, $event.materialized)) {
            $null = Assert-D01JsonInteger -Value $set.ipv4_count `
                -Context 'telemetry endpoint-set ipv4_count' -Minimum 0
            $null = Assert-D01JsonInteger -Value $set.ipv6_count `
                -Context 'telemetry endpoint-set ipv6_count' -Minimum 0
            if ($set.endpoint_set_sha256 -isnot [string] -or
                [string]$set.endpoint_set_sha256 -cnotmatch '^[0-9a-f]{64}$') {
                throw 'Telemetry endpoint-set hash is invalid'
            }
        }
        if ($event.materialized.simultaneously_retained -isnot [bool]) {
            throw 'Telemetry simultaneously_retained is not Boolean'
        }
        if ($event.candidates -isnot [Array]) {
            throw 'Telemetry candidates is not a JSON array'
        }
        foreach ($candidate in @($event.candidates)) {
            $null = Assert-D01ExactPropertySet -Object $candidate `
                -Expected @('family', 'endpoint_sha256', 'outcome',
                    'source_origin') -Context 'telemetry.event.candidate'
            if ($candidate.family -isnot [string] -or
                [string]$candidate.family -notin @('ipv4', 'ipv6') -or
                $candidate.endpoint_sha256 -isnot [string] -or
                [string]$candidate.endpoint_sha256 -cnotmatch
                    '^[0-9a-f]{64}$' -or
                $candidate.outcome -isnot [string] -or
                [string]$candidate.outcome -notin
                    @('added', 'merged_existing') -or
                $candidate.source_origin -isnot [string] -or
                [string]$candidate.source_origin -cne 'hostname_link') {
                throw 'Telemetry candidate scalar contract is invalid'
            }
        }
    }
    return $true
}

function Test-D01NoRawTelemetryFields {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) { return $false }
    if ($Value -is [string] -or $Value -is [ValueType]) { return $true }
    if ($Value -is [Collections.IDictionary]) {
        foreach ($key in $Value.Keys) {
            if ([string]$key -in @(
                'hostname', 'address', 'ip', 'ip_address', 'endpoint'
            )) {
                return $false
            }
            if (-not (Test-D01NoRawTelemetryFields -Value $Value[$key])) {
                return $false
            }
        }
        return $true
    }
    if ($Value -is [Collections.IEnumerable]) {
        foreach ($item in $Value) {
            if (-not (Test-D01NoRawTelemetryFields -Value $item)) {
                return $false
            }
        }
        return $true
    }
    foreach ($property in $Value.PSObject.Properties) {
        if ([string]$property.Name -in @(
            'hostname', 'address', 'ip', 'ip_address', 'endpoint'
        )) {
            return $false
        }
        if (-not (Test-D01NoRawTelemetryFields -Value $property.Value)) {
            return $false
        }
    }
    return $true
}

function Get-D01TelemetryVerdict {
    param(
        [Parameter(Mandatory = $true)][object]$Snapshot,
        [Parameter(Mandatory = $true)][Int64]$BaselineSequence,
        [Parameter(Mandatory = $true)][string]$HostnameSha256,
        [Parameter(Mandatory = $true)][string]$FileEd2kHash,
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][object]$CanonicalEndpoints
    )

    $newEvents = @()
    if ($Snapshot.available -and $Snapshot.contract_valid) {
        $newEvents = @(
            @($Snapshot.data.events) | Where-Object {
                [Int64]$_.sequence -gt $BaselineSequence
            } | Sort-Object { [Int64]$_.sequence }
        )
    }
    $event = if ($newEvents.Count -eq 1) { $newEvents[0] } else { $null }
    $expectedSequence = if ($BaselineSequence -lt [Int64]::MaxValue) {
        [Int64]($BaselineSequence + 1)
    } else { $null }
    $sequenceDeltaExact = $null -ne $expectedSequence -and
        $Snapshot.available -and $Snapshot.contract_valid -and
        [Int64]$Snapshot.data.sequence -eq [Int64]$expectedSequence
    $eventSequenceExact = $null -ne $event -and
        $null -ne $expectedSequence -and
        [Int64]$event.sequence -eq [Int64]$expectedSequence
    $exactlyOneNewEvent = $newEvents.Count -eq 1 -and
        $sequenceDeltaExact -and $eventSequenceExact
    $candidateEvidence = @()
    if ($null -ne $event) { $candidateEvidence = @($event.candidates) }
    $expectedEndpointHashes = @(
        $CanonicalEndpoints.endpoints |
            Select-Object -ExpandProperty endpoint_sha256 |
            Sort-Object -Unique
    )
    $actualEndpointHashes = @(
        $candidateEvidence |
            Select-Object -ExpandProperty endpoint_sha256 |
            ForEach-Object { ([string]$_).ToLowerInvariant() } |
            Sort-Object -Unique
    )
    $candidateFamilies = @(
        $candidateEvidence |
            Select-Object -ExpandProperty family |
            ForEach-Object { [string]$_ } |
            Sort-Object -Unique
    )
    $candidateOutcomesValid = $candidateEvidence.Count -eq 2 -and
        @($candidateEvidence | Where-Object {
            [string]$_.outcome -notin @('added', 'merged_existing') -or
            [string]$_.source_origin -ne 'hostname_link'
        }).Count -eq 0
    $eventFieldsMatch = $null -ne $event -and
        ([string]$event.hostname_sha256).ToLowerInvariant() -eq
            $HostnameSha256 -and
        ([string]$event.file_ed2k_hash).ToLowerInvariant() -eq
            $FileEd2kHash.ToLowerInvariant() -and
        [int]$event.port -eq $Port -and
        [string]$event.resolver_result -eq 'success'
    $resolvedMatch = $null -ne $event -and
        [int]$event.resolved.ipv4_count -eq 1 -and
        [int]$event.resolved.ipv6_count -eq 1 -and
        ([string]$event.resolved.endpoint_set_sha256).ToLowerInvariant() -eq
            $CanonicalEndpoints.endpoint_set_sha256
    $materializedMatch = $null -ne $event -and
        [int]$event.materialized.ipv4_count -eq 1 -and
        [int]$event.materialized.ipv6_count -eq 1 -and
        ([string]$event.materialized.endpoint_set_sha256).ToLowerInvariant() -eq
            $CanonicalEndpoints.endpoint_set_sha256 -and
        [bool]$event.materialized.simultaneously_retained
    $candidateSetMatch =
        ($expectedEndpointHashes -join ',') -eq
            ($actualEndpointHashes -join ',') -and
        ($candidateFamilies -join ',') -eq 'ipv4,ipv6' -and
        $candidateOutcomesValid
    $privacyValid = $null -ne $event -and
        (Test-D01NoRawTelemetryFields -Value $event)
    return [pscustomobject][ordered]@{
        baseline_sequence = $BaselineSequence
        snapshot_sequence = if ($Snapshot.available) {
            [Int64]$Snapshot.data.sequence
        } else { $null }
        new_event_count = $newEvents.Count
        exactly_one_new_event = $exactlyOneNewEvent
        top_sequence_delta_exact = $sequenceDeltaExact
        event_sequence_exact = $eventSequenceExact
        event_sequence = if ($null -ne $event) {
            [Int64]$event.sequence
        } else { $null }
        event_fields_match = $eventFieldsMatch
        resolved_set_match = $resolvedMatch
        materialized_set_match = $materializedMatch
        candidate_set_match = $candidateSetMatch
        raw_sensitive_fields_absent = $privacyValid
        expected_endpoint_set_sha256 =
            $CanonicalEndpoints.endpoint_set_sha256
        expected_endpoint_hashes = $expectedEndpointHashes
        event = $event
        product_contract_pass = $exactlyOneNewEvent -and
            $eventFieldsMatch -and $resolvedMatch -and
            $materializedMatch -and $candidateSetMatch -and $privacyValid
        observability_contract_pass = $Snapshot.available -and
            $Snapshot.contract_valid
    }
}

function Get-D01AdjudicationStatus {
    param(
        [Parameter(Mandatory = $true)][bool]$CaseArmed,
        [Parameter(Mandatory = $true)][Int64]$ArmBoundaryEpochUnixNs,
        [Parameter(Mandatory = $true)]
        [ValidateSet('PASS', 'BLOCKED')][string]$FixtureStatus,
        [Parameter(Mandatory = $true)]
        [ValidateSet('PASS', 'BLOCKED')][string]$ObservabilityStatus,
        [Parameter(Mandatory = $true)][object[]]$ProductFailures
    )

    if ($CaseArmed -and $ArmBoundaryEpochUnixNs -le 0) {
        throw 'Armed adjudication lacks an exact arm boundary'
    }
    foreach ($failure in @($ProductFailures)) {
        $null = Assert-D01ProductFailureContract -Failure $failure `
            -ArmBoundaryEpochUnixNs $ArmBoundaryEpochUnixNs
    }
    $productStatus = if (-not $CaseArmed) {
        'NOT_EVALUATED'
    } elseif (@($ProductFailures).Count -gt 0) {
        'FAIL'
    } elseif ($FixtureStatus -eq 'PASS' -and
        $ObservabilityStatus -eq 'PASS') {
        'PASS'
    } else {
        'NOT_EVALUATED'
    }
    $formalStatus = if ($productStatus -eq 'FAIL') {
        'FAIL'
    } elseif ($FixtureStatus -ne 'PASS' -or
        $ObservabilityStatus -ne 'PASS') {
        'BLOCKED'
    } elseif ($productStatus -eq 'PASS') {
        'PASS'
    } else {
        'BLOCKED'
    }
    return [pscustomobject][ordered]@{
        product_status = $productStatus
        formal_status = $formalStatus
        typed_product_failure_count = @($ProductFailures).Count
    }
}

function Get-D01PublicSummaryProjection {
    param([Parameter(Mandatory = $true)][object]$PrivateSummary)

    $sourceCleanupExact = $false
    if ($null -ne $PrivateSummary.cleanup.source) {
        try {
            $sourceCleanupExact =
                [bool]$PrivateSummary.cleanup.source.source_process_stopped -and
                [bool]$PrivateSummary.cleanup.source.
                    temporary_firewall_rules_removed -and
                [bool]$PrivateSummary.cleanup.source.candidate_unchanged -and
                [bool]$PrivateSummary.cleanup.source.
                    prepared_executable_unchanged -and
                -not [bool]$PrivateSummary.cleanup.source.hosts_modified -and
                @($PrivateSummary.cleanup.source.failures).Count -eq 0
        } catch { $sourceCleanupExact = $false }
    }
    $localPostchecksExact = $null -ne
            $PrivateSummary.cleanup.account_registry_firewall_postcheck -and
        [bool]$PrivateSummary.cleanup.
            account_registry_firewall_postcheck.safe_to_pass -and
        $null -ne $PrivateSummary.cleanup.terminal_ownership -and
        [bool]$PrivateSummary.cleanup.terminal_ownership.all_clear -and
        $null -ne $PrivateSummary.cleanup.hosts_file_postcheck -and
        [bool]$PrivateSummary.cleanup.hosts_file_postcheck.safe_to_pass
    $cleanupExact = [bool]$PrivateSummary.cleanup.
            downloader_process_stopped -and
        [bool]$PrivateSummary.cleanup.controlled_server_stopped -and
        [bool]$PrivateSummary.cleanup.source_stop_published -and
        [bool]$PrivateSummary.cleanup.candidate_unchanged -and
        [bool]$PrivateSummary.cleanup.pktmon_filter_inventory_restored -and
        [bool]$PrivateSummary.cleanup.pktmon_driver_monitoring_stopped -and
        [bool]$PrivateSummary.cleanup.
            pktmon_driver_configuration_restored -and
        [bool]$PrivateSummary.cleanup.
            pktmon_global_counter_state_restored -and
        [bool]$PrivateSummary.cleanup.pktmon_etw_session_stopped -and
        -not [bool]$PrivateSummary.cleanup.hosts_modified -and
        @($PrivateSummary.cleanup.failures).Count -eq 0 -and
        $sourceCleanupExact -and $localPostchecksExact
    $failureTypes = @(
        @($PrivateSummary.adjudication.typed_product_failures) |
            ForEach-Object { [string]$_.failure_type } |
            Sort-Object -Unique
    )
    $packetCaptureAdjudicable =
        $null -ne $PrivateSummary.packet_capture -and
        [bool]$PrivateSummary.packet_capture.
            product_capture_observability_pass -and
        [bool]$PrivateSummary.packet_capture.capture_observability_pass
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.d01-public-summary/v2'
        case_id = 'V91-D01'
        generated_at_utc = Get-LabUtcTimestamp
        publication_id = [string]$PrivateSummary.publication.publication_id
        publication_commit_required = $true
        publication_commit_file = 'adjudication-commit.json'
        case_armed = [bool]$PrivateSummary.case_armed
        formal_status = [string]$PrivateSummary.formal_status
        fixture_status = [string]$PrivateSummary.fixture_status
        observability_status =
            [string]$PrivateSummary.observability_status
        product_status = [string]$PrivateSummary.product_status
        exit_code = [int]$PrivateSummary.exit_code
        observed_topology = if (
            [string]$PrivateSummary.observed_topology -in @('T1', 'T2')
        ) { [string]$PrivateSummary.observed_topology } else { 'NOT_PROVEN' }
        typed_product_failure_types = $failureTypes
        fixture_blocker_count =
            @($PrivateSummary.adjudication.fixture_blockers).Count
        observability_blocker_count =
            @($PrivateSummary.adjudication.observability_blockers).Count
        A_forward_proved = $packetCaptureAdjudicable -and
            [bool]$PrivateSummary.packet_capture.A_forward.proved
        AAAA_silent_DROP_proved =
            $packetCaptureAdjudicable -and
            [bool]$PrivateSummary.packet_capture.AAAA_silent_DROP.proved
        transfer_hash_match = [bool]$PrivateSummary.transfer.hash_match
        cleanup_exact = $cleanupExact
    }
}

function Assert-D01PublicSummaryProjection {
    param([Parameter(Mandatory = $true)][object]$Projection)

    $null = Assert-D01ExactPropertySet -Object $Projection -Expected @(
        'schema', 'case_id', 'generated_at_utc', 'publication_id',
        'publication_commit_required', 'publication_commit_file', 'case_armed',
        'formal_status', 'fixture_status', 'observability_status',
        'product_status', 'exit_code', 'observed_topology',
        'typed_product_failure_types', 'fixture_blocker_count',
        'observability_blocker_count', 'A_forward_proved',
        'AAAA_silent_DROP_proved', 'transfer_hash_match', 'cleanup_exact'
    ) -Context 'public summary'
    foreach ($name in @(
        'schema', 'case_id', 'generated_at_utc', 'publication_id',
        'publication_commit_file', 'formal_status',
        'fixture_status', 'observability_status', 'product_status',
        'observed_topology'
    )) {
        $null = Assert-D01JsonStringValue `
            -Value $Projection.PSObject.Properties[$name].Value `
            -Context "public summary.$name"
    }
    if ([string]$Projection.schema -cne
            'ese.v91.d01-public-summary/v2' -or
        [string]$Projection.case_id -cne 'V91-D01' -or
        [string]$Projection.publication_id -cnotmatch '^[0-9a-f]{32}$' -or
        [string]$Projection.publication_commit_file -cne
            'adjudication-commit.json' -or
        [string]$Projection.formal_status -notin
            @('PASS', 'FAIL', 'BLOCKED') -or
        [string]$Projection.fixture_status -notin @('PASS', 'BLOCKED') -or
        [string]$Projection.observability_status -notin
            @('PASS', 'BLOCKED') -or
        [string]$Projection.product_status -notin
            @('PASS', 'FAIL', 'NOT_EVALUATED') -or
        [string]$Projection.observed_topology -notin
            @('T1', 'T2', 'NOT_PROVEN')) {
        throw 'Public summary status contract is not exact'
    }
    $exit = Assert-D01JsonInteger -Value $Projection.exit_code `
        -Context 'public summary.exit_code' -Minimum 0 -Maximum 2
    if (($Projection.formal_status -eq 'PASS' -and $exit -ne 0) -or
        ($Projection.formal_status -eq 'FAIL' -and $exit -ne 1) -or
        ($Projection.formal_status -eq 'BLOCKED' -and $exit -ne 2)) {
        throw 'Public summary status/exit code is contradictory'
    }
    foreach ($name in @(
        'fixture_blocker_count', 'observability_blocker_count'
    )) {
        $null = Assert-D01JsonInteger `
            -Value $Projection.PSObject.Properties[$name].Value `
            -Context "public summary.$name" -Minimum 0
    }
    foreach ($name in @(
        'publication_commit_required', 'case_armed', 'A_forward_proved',
        'AAAA_silent_DROP_proved',
        'transfer_hash_match', 'cleanup_exact'
    )) {
        $null = Assert-D01JsonBoolean `
            -Value $Projection.PSObject.Properties[$name].Value `
            -Context "public summary.$name"
    }
    if (-not [bool]$Projection.publication_commit_required) {
        throw 'Public summary must be paired with its commit artifact'
    }
    $types = Assert-D01JsonStringArray `
        -Value $Projection.typed_product_failure_types `
        -Context 'public summary.typed_product_failure_types' `
        -RequireUnique
    foreach ($type in $types) {
        if ($type -notin @(
            'candidate-process-exit', 'telemetry-materialization',
            'A-forward', 'AAAA-silent-DROP', 'transfer-integrity',
            'network-isolation', 'UI-responsiveness',
            'unexpected-candidate-tcp-peer-connection'
        )) {
            throw 'Public summary contains an unknown product failure type'
        }
    }
    $fixtureBlockerCount = [Int64]$Projection.fixture_blocker_count
    $observabilityBlockerCount =
        [Int64]$Projection.observability_blocker_count
    $passInvariant = [bool]$Projection.case_armed -and
        [string]$Projection.fixture_status -ceq 'PASS' -and
        [string]$Projection.observability_status -ceq 'PASS' -and
        [string]$Projection.product_status -ceq 'PASS' -and
        $types.Count -eq 0 -and $fixtureBlockerCount -eq 0 -and
        $observabilityBlockerCount -eq 0 -and
        [string]$Projection.observed_topology -in @('T1', 'T2') -and
        [bool]$Projection.A_forward_proved -and
        [bool]$Projection.AAAA_silent_DROP_proved -and
        [bool]$Projection.transfer_hash_match -and
        [bool]$Projection.cleanup_exact
    $failInvariant = [bool]$Projection.case_armed -and
        [string]$Projection.product_status -ceq 'FAIL' -and
        $types.Count -gt 0
    $blockedInvariant = [string]$Projection.product_status -ceq
            'NOT_EVALUATED' -and $types.Count -eq 0 -and
        ((-not [bool]$Projection.case_armed) -or
            [string]$Projection.fixture_status -ceq 'BLOCKED' -or
            [string]$Projection.observability_status -ceq 'BLOCKED')
    if (($Projection.formal_status -ceq 'PASS' -and -not $passInvariant) -or
        ($Projection.formal_status -ceq 'FAIL' -and -not $failInvariant) -or
        ($Projection.formal_status -ceq 'BLOCKED' -and
            -not $blockedInvariant)) {
        throw 'Public summary formal status projection is contradictory'
    }
    $serialized = $Projection | ConvertTo-Json -Depth 20 -Compress
    if ($serialized -match
        '(?i)"[^"\\]*(?:hostname|user|sid|machine|process|pid|address|port|path|error|evidence|nonce|raw)[^"\\]*"\s*:') {
        throw 'Public summary contains a forbidden identifying field name'
    }
    return $true
}

function Get-D01SourcePublicSummaryProjection {
    param(
        [Parameter(Mandatory = $true)][object]$PrivateResult,
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[0-9a-f]{32}$')][string]$PublicationId
    )

    $immutablePostchecksExact =
        $null -ne $PrivateResult.cleanup.
            account_registry_firewall_postcheck -and
        [bool]$PrivateResult.cleanup.
            account_registry_firewall_postcheck.safe_to_pass -and
        $null -ne $PrivateResult.cleanup.hosts_file_postcheck -and
        [bool]$PrivateResult.cleanup.hosts_file_postcheck.safe_to_pass -and
        $null -ne $PrivateResult.cleanup.terminal_ownership -and
        [bool]$PrivateResult.cleanup.terminal_ownership.all_clear
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.d01-source-public-summary/v2'
        case_id = 'V91-D01'
        generated_at_utc = Get-LabUtcTimestamp
        publication_id = $PublicationId
        publication_commit_required = $true
        publication_commit_file = 'source-publication-commit.json'
        status = [string]$PrivateResult.status
        health_observable =
            [bool]$PrivateResult.health.observability_available
        source_stopped =
            [bool]$PrivateResult.cleanup.source_process_stopped
        firewall_cleanup_exact =
            [bool]$PrivateResult.cleanup.temporary_firewall_rules_removed
        candidate_unchanged =
            [bool]$PrivateResult.cleanup.candidate_unchanged
        prepared_executable_unchanged =
            [bool]$PrivateResult.cleanup.prepared_executable_unchanged
        immutable_state_postchecks_exact = $immutablePostchecksExact
        cleanup_failure_count = @($PrivateResult.cleanup.failures).Count
    }
}

function Assert-D01SourcePublicSummaryProjection {
    param([Parameter(Mandatory = $true)][object]$Projection)

    $null = Assert-D01ExactPropertySet -Object $Projection -Expected @(
        'schema', 'case_id', 'generated_at_utc', 'publication_id',
        'publication_commit_required', 'publication_commit_file', 'status',
        'health_observable', 'source_stopped', 'firewall_cleanup_exact',
        'candidate_unchanged', 'prepared_executable_unchanged',
        'immutable_state_postchecks_exact', 'cleanup_failure_count'
    ) -Context 'source public summary'
    foreach ($name in @(
        'schema', 'case_id', 'generated_at_utc', 'publication_id',
        'publication_commit_file', 'status'
    )) {
        $null = Assert-D01JsonStringValue `
            -Value $Projection.PSObject.Properties[$name].Value `
            -Context "source public summary.$name"
    }
    if ([string]$Projection.schema -cne
            'ese.v91.d01-source-public-summary/v2' -or
        [string]$Projection.case_id -cne 'V91-D01' -or
        [string]$Projection.publication_id -cnotmatch '^[0-9a-f]{32}$' -or
        [string]$Projection.publication_commit_file -cne
            'source-publication-commit.json' -or
        [string]$Projection.status -notin @('COMPLETE', 'INCOMPLETE')) {
        throw 'Source public summary status contract is not exact'
    }
    foreach ($name in @(
        'publication_commit_required', 'health_observable', 'source_stopped',
        'firewall_cleanup_exact',
        'candidate_unchanged', 'prepared_executable_unchanged',
        'immutable_state_postchecks_exact'
    )) {
        $null = Assert-D01JsonBoolean `
            -Value $Projection.PSObject.Properties[$name].Value `
            -Context "source public summary.$name"
    }
    if (-not [bool]$Projection.publication_commit_required) {
        throw 'Source public summary must be paired with its commit artifact'
    }
    $null = Assert-D01JsonInteger `
        -Value $Projection.cleanup_failure_count `
        -Context 'source public summary.cleanup_failure_count' -Minimum 0
    if ([string]$Projection.status -ceq 'COMPLETE' -and
        (-not [bool]$Projection.health_observable -or
            -not [bool]$Projection.source_stopped -or
            -not [bool]$Projection.firewall_cleanup_exact -or
            -not [bool]$Projection.candidate_unchanged -or
            -not [bool]$Projection.prepared_executable_unchanged -or
            -not [bool]$Projection.immutable_state_postchecks_exact -or
            [Int64]$Projection.cleanup_failure_count -ne 0)) {
        throw 'Source public COMPLETE projection is contradictory'
    }
    $serialized = $Projection | ConvertTo-Json -Depth 10 -Compress
    if ($serialized -match
        '(?i)"[^"\\]*(?:hostname|user|sid|machine|process|pid|address|port|path|error|evidence|nonce|raw)[^"\\]*"\s*:') {
        throw 'Source public summary contains a forbidden identifying field name'
    }
    return $true
}

function Get-D01OptionalProperty {
    param(
        [AllowNull()][object]$InputObject,
        [Parameter(Mandatory = $true)][string]$Name,
        [AllowNull()][object]$DefaultValue = $null
    )

    if ($null -eq $InputObject) { return $DefaultValue }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) { return $DefaultValue }
    return $property.Value
}

function Start-D01ControlledEd2kServer {
    param(
        [Parameter(Mandatory = $true)][string]$EvidencePath,
        [Parameter(Mandatory = $true)][string]$ListenAddress,
        [Parameter(Mandatory = $true)][string]$ExpectedClientAddress,
        [Parameter(Mandatory = $true)][string]$Nonce,
        [Parameter(Mandatory = $true)][ref]$PublishedOwner,
        [ValidateSet(
            '', 'owner-published', 'listener-published',
            'listener-started', 'powershell-published',
            'script-configured', 'async-published'
        )][string]$FaultInjectionPhase = ''
    )

    $state = New-Object `
        'Collections.Concurrent.ConcurrentDictionary[string,object]'
    $state['phase'] = 'owner-published'
    $state['stop_requested'] = $false
    $state['logged_in'] = $false
    $state['reply_sent'] = $false
    $state['error'] = ''
    $state['frames_received'] = 0
    $state['listen_port'] = 0
    $state['high_id'] = [uint32]0x01000001
    $state['listen_address'] = $ListenAddress
    $state['expected_client_address'] = $ExpectedClientAddress
    $owner = [pscustomobject][ordered]@{
        schema = 'ese.v91.d01-controlled-server-owner/v1'
        owner_id = [Guid]::NewGuid().ToString('N')
        phase = 'owner-published'
        listener = $null
        port = 0
        state = $state
        powershell = $null
        async = $null
        evidence_path = $EvidencePath
        started_at_utc = $null
        start_error = $null
        start_rollback = $null
        stop_attempts = 0
        listener_stopped = $false
        client_closed = $false
        powershell_stop_requested = $false
        end_invoke_called = $false
        powershell_disposed = $false
        async_completed = $false
    }
    $PublishedOwner.Value = $owner

    try {
        if ($FaultInjectionPhase -eq 'owner-published') {
            throw 'Injected controlled-server failure after owner publication'
        }
        $listenIp = [Net.IPAddress]::Parse($ListenAddress)
        if ($listenIp.AddressFamily -ne
            [Net.Sockets.AddressFamily]::InterNetwork -or
            [Net.IPAddress]::IsLoopback($listenIp)) {
            throw 'Controlled eD2K server requires assigned non-loopback IPv4'
        }
        $listener = New-Object Net.Sockets.TcpListener($listenIp, 0)
        $owner.listener = $listener
        $owner.phase = 'listener-published'
        $state['phase'] = 'listener-published'
        $listener.Server.ExclusiveAddressUse = $true
        if ($FaultInjectionPhase -eq 'listener-published') {
            throw 'Injected controlled-server failure after listener publication'
        }
        $listener.Start(1)
        $port = [int]([Net.IPEndPoint]$listener.LocalEndpoint).Port
        $owner.port = $port
        $owner.phase = 'listener-started'
        $state['phase'] = 'listening'
        $state['listen_port'] = $port
        if ($FaultInjectionPhase -eq 'listener-started') {
            throw 'Injected controlled-server failure after listener start'
        }

    $serverBody = {
        param(
            $Listener, $State, $ResultPath, $RunNonceValue,
            $AllowedClientAddress
        )

        function Read-ExactD01 {
            param(
                [Parameter(Mandatory = $true)]
                [Net.Sockets.NetworkStream]$Stream,
                [Parameter(Mandatory = $true)][int]$Count
            )
            $buffer = New-Object byte[] $Count
            $offset = 0
            while ($offset -lt $Count) {
                $read = $Stream.Read($buffer, $offset, $Count - $offset)
                if ($read -le 0) {
                    throw "Controlled server stream closed after $offset/$Count bytes"
                }
                $offset += $read
            }
            return $buffer
        }

        function Send-D01Frame {
            param(
                [Parameter(Mandatory = $true)]
                [Net.Sockets.NetworkStream]$Stream,
                [Parameter(Mandatory = $true)][byte]$Opcode,
                [Parameter(Mandatory = $true)][byte[]]$Payload
            )
            $header = New-Object byte[] 6
            $header[0] = 0xE3
            [Array]::Copy(
                [BitConverter]::GetBytes([uint32]($Payload.Length + 1)),
                0, $header, 1, 4
            )
            $header[5] = $Opcode
            $Stream.Write($header, 0, $header.Length)
            if ($Payload.Length -gt 0) {
                $Stream.Write($Payload, 0, $Payload.Length)
            }
            $Stream.Flush()
        }

        $client = $null
        $stream = $null
        $loginAt = ''
        try {
            $State['phase'] = 'accepting'
            $client = $Listener.AcceptTcpClient()
            $State['client'] = $client
            $remote = [Net.IPEndPoint]$client.Client.RemoteEndPoint
            if ($remote.Address.ToString() -ne $AllowedClientAddress) {
                throw "Unexpected controlled-server client $remote"
            }
            $State['accepted_remote'] = $remote.ToString()
            $stream = $client.GetStream()
            $stream.ReadTimeout = 30000
            $header = Read-ExactD01 -Stream $stream -Count 6
            $packetLength = [BitConverter]::ToUInt32($header, 1)
            if ($header[0] -ne 0xE3 -or $header[5] -ne 0x01 -or
                $packetLength -lt 23 -or $packetLength -gt 1048576) {
                throw (
                    'Expected OP_EDONKEYPROT:OP_LOGINREQUEST; ' +
                    "protocol=0x$('{0:X2}' -f $header[0]) " +
                    "opcode=0x$('{0:X2}' -f $header[5]) length=$packetLength"
                )
            }
            $payload = Read-ExactD01 -Stream $stream `
                -Count ([int]$packetLength - 1)
            $sha = [Security.Cryptography.SHA256]::Create()
            try {
                $payloadSha = ([BitConverter]::ToString(
                    $sha.ComputeHash($payload)
                )).Replace('-', '').ToLowerInvariant()
            } finally {
                $sha.Dispose()
            }
            $State['login_protocol'] = [int]$header[0]
            $State['login_opcode'] = [int]$header[5]
            $State['login_payload_bytes'] = $payload.Length
            $State['login_payload_sha256'] = $payloadSha
            $State['login_advertised_tcp_port'] =
                [int][BitConverter]::ToUInt16($payload, 20)
            $loginAt = [DateTime]::UtcNow.ToString('o')
            Send-D01Frame -Stream $stream -Opcode 0x40 `
                -Payload ([BitConverter]::GetBytes([uint32]0x01000001))
            $State['reply_sent'] = $true
            $State['logged_in'] = $true
            $State['phase'] = 'connected'
            $State['login_at_utc'] = $loginAt
            $stream.ReadTimeout = 2000
            $nextStatus = [DateTime]::UtcNow.AddSeconds(10)
            while (-not [bool]$State['stop_requested']) {
                if ($stream.DataAvailable) {
                    $nextHeader = Read-ExactD01 -Stream $stream -Count 6
                    $nextLength = [BitConverter]::ToUInt32($nextHeader, 1)
                    if ($nextLength -lt 1 -or $nextLength -gt 16777216) {
                        throw "Invalid client frame length $nextLength"
                    }
                    if ($nextLength -gt 1) {
                        $null = Read-ExactD01 -Stream $stream `
                            -Count ([int]$nextLength - 1)
                    }
                    $State['frames_received'] =
                        [int]$State['frames_received'] + 1
                    $State['last_client_opcode'] = [int]$nextHeader[5]
                } elseif ([DateTime]::UtcNow -ge $nextStatus) {
                    Send-D01Frame -Stream $stream -Opcode 0x34 `
                        -Payload (New-Object byte[] 8)
                    $State['status_frames_sent'] = if (
                        $State.ContainsKey('status_frames_sent')
                    ) {
                        [int]$State['status_frames_sent'] + 1
                    } else { 1 }
                    $nextStatus = [DateTime]::UtcNow.AddSeconds(10)
                } else {
                    Start-Sleep -Milliseconds 50
                }
            }
        } catch {
            if (-not [bool]$State['stop_requested']) {
                $State['error'] = $_.Exception.Message
                $State['phase'] = 'error'
            }
        } finally {
            if ($null -ne $stream) { try { $stream.Dispose() } catch {} }
            if ($null -ne $client) { try { $client.Dispose() } catch {} }
            try { $Listener.Stop() } catch {}
            if ([string]$State['phase'] -ne 'error') {
                $State['phase'] = 'stopped'
            }
            $result = [ordered]@{
                schema = 'ese.v91.d01-controlled-ed2k-server/v2'
                run_nonce = $RunNonceValue
                listen_address = [string]$State['listen_address']
                listen_port = [int]$State['listen_port']
                high_id = [uint32]$State['high_id']
                login_at_utc = $loginAt
                stopped_at_utc = [DateTime]::UtcNow.ToString('o')
                phase = [string]$State['phase']
                logged_in = [bool]$State['logged_in']
                reply_sent = [bool]$State['reply_sent']
                login_protocol = if ($State.ContainsKey('login_protocol')) {
                    [int]$State['login_protocol']
                } else { $null }
                login_opcode = if ($State.ContainsKey('login_opcode')) {
                    [int]$State['login_opcode']
                } else { $null }
                login_payload_bytes = if (
                    $State.ContainsKey('login_payload_bytes')
                ) {
                    [int]$State['login_payload_bytes']
                } else { 0 }
                login_payload_sha256 = if (
                    $State.ContainsKey('login_payload_sha256')
                ) {
                    [string]$State['login_payload_sha256']
                } else { '' }
                login_advertised_tcp_port = if (
                    $State.ContainsKey('login_advertised_tcp_port')
                ) {
                    [int]$State['login_advertised_tcp_port']
                } else { 0 }
                accepted_remote = if (
                    $State.ContainsKey('accepted_remote')
                ) {
                    [string]$State['accepted_remote']
                } else { '' }
                frames_received = [int]$State['frames_received']
                error = [string]$State['error']
            }
            [IO.File]::WriteAllText(
                $ResultPath, ($result | ConvertTo-Json -Depth 16),
                (New-Object Text.UTF8Encoding($false))
            )
        }
    }

        $powershell = [PowerShell]::Create()
        $owner.powershell = $powershell
        $owner.phase = 'powershell-published'
        $state['phase'] = 'powershell-published'
        if ($FaultInjectionPhase -eq 'powershell-published') {
            throw 'Injected controlled-server failure after PowerShell publication'
        }
        $null = $powershell.AddScript($serverBody.ToString())
        $null = $powershell.AddArgument($listener)
        $null = $powershell.AddArgument($state)
        $null = $powershell.AddArgument($EvidencePath)
        $null = $powershell.AddArgument($Nonce)
        $null = $powershell.AddArgument($ExpectedClientAddress)
        $owner.phase = 'script-configured'
        $state['phase'] = 'script-configured'
        if ($FaultInjectionPhase -eq 'script-configured') {
            throw 'Injected controlled-server failure after script configuration'
        }
        $async = $powershell.BeginInvoke()
        $owner.async = $async
        $owner.phase = 'async-published'
        $state['phase'] = 'accepting'
        if ($FaultInjectionPhase -eq 'async-published') {
            throw 'Injected controlled-server failure after async publication'
        }
        $owner.started_at_utc = Get-LabUtcTimestamp
        $owner.phase = 'running'
        return $owner
    } catch {
        $owner.start_error = $_.Exception.Message
        $owner.phase = 'start-failed'
        $state['phase'] = 'start-failed'
        $rollback = Stop-D01ControlledEd2kServer -Server $owner
        $owner.start_rollback = $rollback
        throw (
            "Controlled eD2K server construction failed: " +
            "$($owner.start_error); rollback_stopped=$($rollback.stopped)"
        )
    }
}

function Wait-D01ControlledEd2kLogin {
    param(
        [Parameter(Mandatory = $true)][object]$Server,
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][int]$ExpectedTcpPort
    )

    $deadline = [DateTime]::UtcNow.AddSeconds(90)
    do {
        $Process.Refresh()
        if ($Process.HasExited) {
            throw 'Candidate exited before controlled eD2K login'
        }
        if ([string]$Server.state['error']) {
            throw "Controlled eD2K server failed: $($Server.state['error'])"
        }
        if ([bool]$Server.state['logged_in'] -and
            [bool]$Server.state['reply_sent']) {
            $connections = @(Get-NetTCPConnection -ErrorAction Stop |
                Where-Object {
                    [string]$_.State -eq 'Established' -and
                    [int]$_.OwningProcess -eq $Process.Id -and
                    (Get-D01NormalizedIp -Address ([string]$_.RemoteAddress)) -eq
                        (Get-D01NormalizedIp -Address (
                            [string]$Server.state['listen_address'])) -and
                    [int]$_.RemotePort -eq [int]$Server.port
                })
            if ($connections.Count -eq 1 -and
                [int]$Server.state['login_protocol'] -eq 0xE3 -and
                [int]$Server.state['login_opcode'] -eq 0x01 -and
                [int]$Server.state['login_payload_bytes'] -ge 22 -and
                [int]$Server.state['login_advertised_tcp_port'] -eq
                    $ExpectedTcpPort) {
                return [pscustomobject][ordered]@{
                    connected = $true
                    server_address =
                        [string]$Server.state['listen_address']
                    server_port = $Server.port
                    client_process_id = $Process.Id
                    client_local_address = Get-D01NormalizedIp `
                        -Address ([string]$connections[0].LocalAddress)
                    client_local_port = [int]$connections[0].LocalPort
                    login_payload_sha256 =
                        [string]$Server.state['login_payload_sha256']
                    advertised_tcp_port =
                        [int]$Server.state['login_advertised_tcp_port']
                    assigned_high_id = [uint32]$Server.state['high_id']
                    same_host_physical_server = $true
                }
            }
        }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'Timed out proving the controlled same-host eD2K login'
}

function Stop-D01ControlledEd2kServer {
    param([AllowNull()][object]$Server)

    if ($null -eq $Server) {
        return [pscustomobject][ordered]@{
            stopped = $true
            error = $null
            evidence = $null
            ownership = [ordered]@{
                owner_published = $false
                all_owned_resources_released = $true
            }
        }
    }
    $errors = New-Object 'Collections.Generic.List[string]'
    $state = if ($null -ne $Server.PSObject.Properties['state']) {
        $Server.state
    } else { $null }
    $listener = if (
        $null -ne $Server.PSObject.Properties['listener']
    ) { $Server.listener } else { $null }
    $powershell = if (
        $null -ne $Server.PSObject.Properties['powershell']
    ) { $Server.powershell } else { $null }
    $async = if ($null -ne $Server.PSObject.Properties['async']) {
        $Server.async
    } else { $null }
    if ($null -ne $Server.PSObject.Properties['stop_attempts']) {
        $Server.stop_attempts = [int]$Server.stop_attempts + 1
    }

    if ($null -ne $state) {
        try { $state['stop_requested'] = $true } catch {
            $errors.Add("stop flag: $($_.Exception.Message)")
        }
        if ($state.ContainsKey('client')) {
            try {
                $state['client'].Close()
                if ($null -ne
                    $Server.PSObject.Properties['client_closed']) {
                    $Server.client_closed = $true
                }
            } catch {
                $errors.Add("client close: $($_.Exception.Message)")
            }
        }
    }
    if ($null -ne $listener) {
        try {
            $listener.Stop()
            if ($null -ne
                $Server.PSObject.Properties['listener_stopped']) {
                $Server.listener_stopped = $true
            }
        } catch {
            $errors.Add("listener stop: $($_.Exception.Message)")
        }
    } elseif ($null -ne
        $Server.PSObject.Properties['listener_stopped']) {
        $Server.listener_stopped = $true
    }

    $asyncCompleted = $null -eq $async
    if ($null -ne $async) {
        try {
            $asyncCompleted = [bool]$async.IsCompleted
            if (-not $asyncCompleted) {
                $asyncCompleted = $async.AsyncWaitHandle.WaitOne(
                    [TimeSpan]::FromSeconds(10)
                )
            }
        } catch {
            if ($null -ne
                $Server.PSObject.Properties['async_completed']) {
                $asyncCompleted = [bool]$Server.async_completed
            }
            if (-not $asyncCompleted) {
                $errors.Add("async wait: $($_.Exception.Message)")
            }
        }
        if (-not $asyncCompleted -and $null -ne $powershell) {
            try {
                $powershell.Stop()
                if ($null -ne $Server.PSObject.Properties[
                    'powershell_stop_requested'
                ]) {
                    $Server.powershell_stop_requested = $true
                }
                $asyncCompleted = $async.AsyncWaitHandle.WaitOne(
                    [TimeSpan]::FromSeconds(5)
                )
            } catch {
                $errors.Add("PowerShell stop: $($_.Exception.Message)")
            }
        }
    }
    if ($null -ne $powershell -and $null -ne $async -and
        $asyncCompleted -and
        (
            $null -eq $Server.PSObject.Properties['end_invoke_called'] -or
            -not [bool]$Server.end_invoke_called
        )) {
        try {
            $null = $powershell.EndInvoke($async)
        } catch {
            $stopRequested = $null -ne $state -and
                $state.ContainsKey('stop_requested') -and
                [bool]$state['stop_requested']
            if (-not $stopRequested) {
                $errors.Add("EndInvoke: $($_.Exception.Message)")
            }
        } finally {
            if ($null -ne
                $Server.PSObject.Properties['end_invoke_called']) {
                $Server.end_invoke_called = $true
            }
        }
    }
    if ($null -ne $powershell -and
        (
            $null -eq $Server.PSObject.Properties['powershell_disposed'] -or
            -not [bool]$Server.powershell_disposed
        )) {
        try {
            $powershell.Dispose()
            if ($null -ne
                $Server.PSObject.Properties['powershell_disposed']) {
                $Server.powershell_disposed = $true
            }
        } catch {
            $errors.Add("PowerShell dispose: $($_.Exception.Message)")
        }
    } elseif ($null -eq $powershell -and $null -ne
        $Server.PSObject.Properties['powershell_disposed']) {
        $Server.powershell_disposed = $true
    }
    if ($null -ne $Server.PSObject.Properties['async_completed']) {
        $Server.async_completed = $asyncCompleted
    }
    if ($null -ne $state -and $errors.Count -eq 0) {
        try { $state['phase'] = 'stopped' } catch {}
    }

    $evidence = $null
    $evidencePath = if (
        $null -ne $Server.PSObject.Properties['evidence_path']
    ) { [string]$Server.evidence_path } else { '' }
    if ($evidencePath -and
        (Test-Path -LiteralPath $evidencePath -PathType Leaf)) {
        try {
            $lockedEvidence = Read-D01ImmutableJsonFile `
                -Path $evidencePath
            $evidence = $lockedEvidence.value
        } catch {
            $errors.Add("evidence read: $($_.Exception.Message)")
        }
    }
    $listenerReleased = $null -eq $listener -or
        (
            $null -ne $Server.PSObject.Properties['listener_stopped'] -and
            [bool]$Server.listener_stopped
        )
    $powershellReleased = $null -eq $powershell -or
        (
            $null -ne $Server.PSObject.Properties['powershell_disposed'] -and
            [bool]$Server.powershell_disposed
        )
    $allReleased = $listenerReleased -and $powershellReleased -and
        $asyncCompleted
    return [pscustomobject][ordered]@{
        stopped = $allReleased
        error = if ($errors.Count -eq 0) {
            $null
        } else { $errors -join '; ' }
        evidence = $evidence
        ownership = [ordered]@{
            owner_published = $true
            owner_id = if (
                $null -ne $Server.PSObject.Properties['owner_id']
            ) { [string]$Server.owner_id } else { '' }
            phase = if ($null -ne
                $Server.PSObject.Properties['phase']) {
                [string]$Server.phase
            } else { '' }
            stop_attempts = if ($null -ne
                $Server.PSObject.Properties['stop_attempts']) {
                [int]$Server.stop_attempts
            } else { 1 }
            listener_published = $null -ne $listener
            listener_released = $listenerReleased
            client_released = $null -eq $state -or
                -not $state.ContainsKey('client') -or
                (
                    $null -ne
                        $Server.PSObject.Properties['client_closed'] -and
                    [bool]$Server.client_closed
                ) -or $asyncCompleted
            powershell_published = $null -ne $powershell
            powershell_released = $powershellReleased
            async_published = $null -ne $async
            async_completed = $asyncCompleted
            all_owned_resources_released = $allReleased
        }
    }
}

function Get-D01TrustedSystemBinaryPath {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('pktmon.exe', 'logman.exe', 'powershell.exe',
            'pktmonapi.dll', 'pktmon.sys')][string]$Name
    )
    $systemDirectory = [Environment]::GetFolderPath(
        [Environment+SpecialFolder]::System)
    if ([string]::IsNullOrWhiteSpace($systemDirectory)) {
        throw 'Windows system directory could not be resolved'
    }
    $relativeSystemPath = if ($Name -ceq 'powershell.exe') {
        'WindowsPowerShell\v1.0\powershell.exe'
    } elseif ($Name.EndsWith(
        '.sys', [StringComparison]::OrdinalIgnoreCase)) {
        Join-Path 'drivers' $Name
    } else { $Name }
    $expected = Assert-D01NoReparsePath `
        -Path (Join-Path $systemDirectory $relativeSystemPath) -Kind File
    if ($Name.EndsWith('.exe', [StringComparison]::OrdinalIgnoreCase)) {
        $command = Get-Command $Name -CommandType Application `
            -ErrorAction Stop
        if (-not [string]::Equals(
                [IO.Path]::GetFullPath([string]$command.Source),
                [IO.Path]::GetFullPath($expected),
                [StringComparison]::OrdinalIgnoreCase)) {
            throw "$Name command resolution is not the protected System32 binary"
        }
    }
    $signature = Get-AuthenticodeSignature -FilePath $expected
    $file = Get-Item -LiteralPath $expected -Force -ErrorAction Stop
    $identityExact = if ($Name -ceq 'powershell.exe') {
        [string]::Equals(
            [string]$file.VersionInfo.InternalName, 'PowerShell',
            [StringComparison]::OrdinalIgnoreCase) -and
        [string]::Equals(
            [string]$file.VersionInfo.OriginalFilename, 'PowerShell.EXE',
            [StringComparison]::OrdinalIgnoreCase)
    } elseif ($Name.EndsWith(
            '.exe', [StringComparison]::OrdinalIgnoreCase) -or
        $Name.EndsWith(
            '.sys', [StringComparison]::OrdinalIgnoreCase)) {
        [string]::Equals(
            [string]$file.VersionInfo.InternalName, $Name,
            [StringComparison]::OrdinalIgnoreCase) -and
        ([string]::Equals(
                [string]$file.VersionInfo.OriginalFilename, $Name,
                [StringComparison]::OrdinalIgnoreCase) -or
            [string]::Equals(
                [string]$file.VersionInfo.OriginalFilename, $Name + '.mui',
                [StringComparison]::OrdinalIgnoreCase))
    } else {
        [string]::Equals(
            [string]$file.VersionInfo.OriginalFilename, $Name,
            [StringComparison]::OrdinalIgnoreCase)
    }
    if ([string]$signature.Status -cne 'Valid' -or
        $null -eq $signature.SignerCertificate -or
        [string]$signature.SignerCertificate.Subject -notmatch
            '(?i)(^|,\s*)O=Microsoft Corporation(,|$)' -or
        -not $identityExact) {
        throw "$Name is not an exact Microsoft-signed Windows system binary"
    }
    return [IO.Path]::GetFullPath($expected)
}

function Get-D01TrustedPktmonMuiPath {
    $systemDirectory = [Environment]::GetFolderPath(
        [Environment+SpecialFolder]::System)
    if ([string]::IsNullOrWhiteSpace($systemDirectory)) {
        throw 'Windows system directory could not be resolved'
    }
    $path = Assert-D01NoReparsePath -Path (
        Join-Path $systemDirectory 'es-ES\pktmon.exe.mui') -Kind File
    $file = Get-Item -LiteralPath $path -Force -ErrorAction Stop
    if (-not [string]::Equals(
            [string]$file.VersionInfo.OriginalFilename, 'pktmon.exe.mui',
            [StringComparison]::OrdinalIgnoreCase)) {
        throw 'PktMon MUI is not the exact audited resource image'
    }
    return [IO.Path]::GetFullPath($path)
}

function Initialize-D01PktmonDriverControl {
    if (-not ('V91D01PktmonDriverControlV2' -as [type])) {
        Add-Type @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

public sealed class V91D01PktmonDriverStopResultV1 {
    public UInt32 StopErrorCode;
    public UInt32 StatusErrorCode;
    public byte Active;
    public UInt32 Configuration;
    public UInt32 ComponentMode;
    public UInt16 PacketSize;
    public byte LoggerPresent;
}

public static class V91D01PktmonDriverControlV2 {
    private const UInt32 LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR = 0x00000100;
    private const UInt32 LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x00000800;

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate UInt32 PktmonStopDelegate(IntPtr status);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate UInt32 PktmonGetStatusDelegate(IntPtr status);

    [DllImport("kernel32.dll", CharSet=CharSet.Unicode,
        SetLastError=true)]
    private static extern IntPtr LoadLibraryExW(
        string fileName, IntPtr file, UInt32 flags);

    [DllImport("kernel32.dll", CharSet=CharSet.Ansi,
        SetLastError=true)]
    private static extern IntPtr GetProcAddress(
        IntPtr module, string procedureName);

    [DllImport("kernel32.dll", SetLastError=true)]
    private static extern bool FreeLibrary(IntPtr module);

    private static string GetSha256(string path) {
        using (SHA256 sha = SHA256.Create())
        using (FileStream stream = new FileStream(
                path, FileMode.Open, FileAccess.Read, FileShare.Read)) {
            return BitConverter.ToString(sha.ComputeHash(stream)).
                Replace("-", "").ToLowerInvariant();
        }
    }

    private static IntPtr LoadExact(
            string libraryPath, string expectedSha256) {
        if (String.IsNullOrEmpty(expectedSha256) ||
                expectedSha256.Length != 64) {
            throw new ArgumentException("Expected SHA-256 is invalid");
        }
        IntPtr module = LoadLibraryExW(
            libraryPath, IntPtr.Zero,
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR |
            LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (module == IntPtr.Zero) {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(), "LoadLibraryExW failed");
        }
        try {
            string actualSha256 = GetSha256(libraryPath);
            if (!String.Equals(actualSha256, expectedSha256,
                    StringComparison.Ordinal)) {
                throw new InvalidOperationException(
                    "Loaded pktmonapi.dll hash differs from the audited ABI");
            }
            return module;
        } catch {
            FreeLibrary(module);
            throw;
        }
    }

    private static IntPtr Export(IntPtr module, string name) {
        IntPtr address = GetProcAddress(module, name);
        if (address == IntPtr.Zero) {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "GetProcAddress(" + name + ") failed");
        }
        return address;
    }

    public static V91D01PktmonDriverStopResultV1 StopAndGetStatus(
            string libraryPath, string expectedSha256) {
        IntPtr module = LoadExact(libraryPath, expectedSha256);
        try {
            PktmonStopDelegate stop =
                (PktmonStopDelegate)Marshal.GetDelegateForFunctionPointer(
                    Export(module, "PktmonStop"),
                    typeof(PktmonStopDelegate));
            PktmonGetStatusDelegate getStatus =
                (PktmonGetStatusDelegate)Marshal.GetDelegateForFunctionPointer(
                    Export(module, "PktmonGetStatus"),
                    typeof(PktmonGetStatusDelegate));
            V91D01PktmonDriverStopResultV1 result =
                new V91D01PktmonDriverStopResultV1();
            result.StopErrorCode = stop(IntPtr.Zero);
            const int statusBytes = 65536;
            IntPtr status = Marshal.AllocHGlobal(statusBytes);
            try {
                Marshal.Copy(new byte[statusBytes], 0, status, statusBytes);
                result.StatusErrorCode = getStatus(status);
                if (result.StatusErrorCode == 0) {
                    result.Active = Marshal.ReadByte(status, 0);
                    result.Configuration = unchecked(
                        (UInt32)Marshal.ReadInt32(status, 4));
                    result.ComponentMode = unchecked(
                        (UInt32)Marshal.ReadInt32(status, 8));
                    result.PacketSize = unchecked(
                        (UInt16)Marshal.ReadInt16(status, 12));
                    result.LoggerPresent = Marshal.ReadByte(status, 14);
                }
            } finally {
                Marshal.FreeHGlobal(status);
            }
            return result;
        } finally {
            FreeLibrary(module);
        }
    }

    public static V91D01PktmonDriverStopResultV1 GetStatus(
            string libraryPath, string expectedSha256) {
        IntPtr module = LoadExact(libraryPath, expectedSha256);
        try {
            PktmonGetStatusDelegate getStatus =
                (PktmonGetStatusDelegate)Marshal.GetDelegateForFunctionPointer(
                    Export(module, "PktmonGetStatus"),
                    typeof(PktmonGetStatusDelegate));
            V91D01PktmonDriverStopResultV1 result =
                new V91D01PktmonDriverStopResultV1();
            const int statusBytes = 65536;
            IntPtr status = Marshal.AllocHGlobal(statusBytes);
            try {
                Marshal.Copy(new byte[statusBytes], 0, status, statusBytes);
                result.StatusErrorCode = getStatus(status);
                if (result.StatusErrorCode == 0) {
                    result.Active = Marshal.ReadByte(status, 0);
                    result.Configuration = unchecked(
                        (UInt32)Marshal.ReadInt32(status, 4));
                    result.ComponentMode = unchecked(
                        (UInt32)Marshal.ReadInt32(status, 8));
                    result.PacketSize = unchecked(
                        (UInt16)Marshal.ReadInt16(status, 12));
                    result.LoggerPresent = Marshal.ReadByte(status, 14);
                }
            } finally {
                Marshal.FreeHGlobal(status);
            }
            return result;
        } finally {
            FreeLibrary(module);
        }
    }
}
'@
    }
}

function Invoke-D01PktmonDriverStop {
    param(
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[0-9a-f]{64}$')]
        [string]$ExpectedLibrarySha256,
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[0-9a-f]{64}$')]
        [string]$ExpectedDriverSha256,
        [switch]$DirectInternal
    )

    if (-not $DirectInternal) {
        return Invoke-D01BoundedNativeOperation -Operation 'driver-stop' `
            -ExpectedLibrarySha256 $ExpectedLibrarySha256 `
            -ExpectedDriverSha256 $ExpectedDriverSha256
    }
    Initialize-D01PktmonDriverControl
    $libraryPath = ''
    $observedLibrarySha256 = ''
    try {
        $libraryPath = Get-D01TrustedSystemBinaryPath `
            -Name 'pktmonapi.dll'
        $observedLibrarySha256 = Get-LabSha256 -Path $libraryPath
        $observedDriverSha256 = Get-LabSha256 -Path (
            Get-D01TrustedSystemBinaryPath -Name 'pktmon.sys')
        if ($observedLibrarySha256 -cne $ExpectedLibrarySha256 -or
            $observedDriverSha256 -cne $ExpectedDriverSha256) {
            throw 'PktMon driver STOP refused after a binary tuple change'
        }
        $native = [V91D01PktmonDriverControlV2]::StopAndGetStatus(
            $libraryPath, $ExpectedLibrarySha256)
        return [pscustomobject][ordered]@{
            schema = 'ese.v91.d01-pktmon-driver-stop/v1'
            api = 'pktmonapi!PktmonStop'
            api_contract =
                'global-non-tokenized-stop-under-exclusive-controlled-host'
            library_sha256 = $observedLibrarySha256
            attempted = $true
            stop_error_code = [Int64][UInt32]$native.StopErrorCode
            status_error_code = [Int64][UInt32]$native.StatusErrorCode
            active_after_stop = [int][byte]$native.Active
            configuration_after_stop = [Int64][UInt32]$native.Configuration
            component_mode_after_stop = [Int64][UInt32]$native.ComponentMode
            packet_size_after_stop = [int][UInt16]$native.PacketSize
            logger_present_after_stop = [int][byte]$native.LoggerPresent
            success = [UInt32]$native.StopErrorCode -eq 0 -and
                [UInt32]$native.StatusErrorCode -eq 0 -and
                [byte]$native.Active -eq 0
            error_sha256 = ''
        }
    } catch {
        return [pscustomobject][ordered]@{
            schema = 'ese.v91.d01-pktmon-driver-stop/v1'
            api = 'pktmonapi!PktmonStop'
            api_contract =
                'global-non-tokenized-stop-under-exclusive-controlled-host'
            library_sha256 = $observedLibrarySha256
            attempted = $true
            stop_error_code = $null
            status_error_code = $null
            active_after_stop = $null
            configuration_after_stop = $null
            component_mode_after_stop = $null
            packet_size_after_stop = $null
            logger_present_after_stop = $null
            success = $false
            error_sha256 =
                Get-LabStringSha256 -Value $_.Exception.Message
        }
    }
}

function Get-D01PktmonDriverStatus {
    param(
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[0-9a-f]{64}$')]
        [string]$ExpectedLibrarySha256,
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[0-9a-f]{64}$')]
        [string]$ExpectedDriverSha256,
        [switch]$DirectInternal
    )

    if (-not $DirectInternal) {
        return Invoke-D01BoundedNativeOperation -Operation 'driver-status' `
            -ExpectedLibrarySha256 $ExpectedLibrarySha256 `
            -ExpectedDriverSha256 $ExpectedDriverSha256
    }
    Initialize-D01PktmonDriverControl
    $libraryPath = ''
    $observedLibrarySha256 = ''
    try {
        $libraryPath = Get-D01TrustedSystemBinaryPath `
            -Name 'pktmonapi.dll'
        $observedLibrarySha256 = Get-LabSha256 -Path $libraryPath
        $observedDriverSha256 = Get-LabSha256 -Path (
            Get-D01TrustedSystemBinaryPath -Name 'pktmon.sys')
        if ($observedLibrarySha256 -cne $ExpectedLibrarySha256 -or
            $observedDriverSha256 -cne $ExpectedDriverSha256) {
            throw 'PktMon driver status refused after a binary tuple change'
        }
        $native = [V91D01PktmonDriverControlV2]::GetStatus(
            $libraryPath, $ExpectedLibrarySha256)
        return [pscustomobject][ordered]@{
            schema = 'ese.v91.d01-pktmon-driver-status/v1'
            api = 'pktmonapi!PktmonGetStatus'
            library_sha256 = $observedLibrarySha256
            status_error_code = [Int64][UInt32]$native.StatusErrorCode
            active = [int][byte]$native.Active
            configuration = [Int64][UInt32]$native.Configuration
            component_mode = [Int64][UInt32]$native.ComponentMode
            packet_size = [int][UInt16]$native.PacketSize
            logger_present = [int][byte]$native.LoggerPresent
            available = [UInt32]$native.StatusErrorCode -eq 0
            inactive_exact = [UInt32]$native.StatusErrorCode -eq 0 -and
                [byte]$native.Active -eq 0
            read_only = $true
            error_sha256 = ''
        }
    } catch {
        return [pscustomobject][ordered]@{
            schema = 'ese.v91.d01-pktmon-driver-status/v1'
            api = 'pktmonapi!PktmonGetStatus'
            library_sha256 = $observedLibrarySha256
            status_error_code = $null
            active = $null
            configuration = $null
            component_mode = $null
            packet_size = $null
            logger_present = $null
            available = $false
            inactive_exact = $false
            read_only = $true
            error_sha256 =
                Get-LabStringSha256 -Value $_.Exception.Message
        }
    }
}

function Get-D01PktmonDriverApiCompatibility {
    param(
        [Parameter(Mandatory = $true)]
        [bool]$ExclusiveControlOperatorAttested
    )

    $libraryPath = Get-D01TrustedSystemBinaryPath -Name 'pktmonapi.dll'
    $executablePath = Get-D01TrustedSystemBinaryPath -Name 'pktmon.exe'
    $driverPath = Get-D01TrustedSystemBinaryPath -Name 'pktmon.sys'
    $muiPath = Get-D01TrustedPktmonMuiPath
    $library = Get-Item -LiteralPath $libraryPath -Force -ErrorAction Stop
    $executable = Get-Item -LiteralPath $executablePath -Force `
        -ErrorAction Stop
    $driver = Get-Item -LiteralPath $driverPath -Force -ErrorAction Stop
    $mui = Get-Item -LiteralPath $muiPath -Force -ErrorAction Stop
    $librarySha256 = Get-LabSha256 -Path $libraryPath
    $executableSha256 = Get-LabSha256 -Path $executablePath
    $driverSha256 = Get-LabSha256 -Path $driverPath
    $muiSha256 = Get-LabSha256 -Path $muiPath
    $tupleExact =
        $librarySha256 -ceq
            '8a3e1913e6f3336357299eaf3d2917c03c4bc2a6e9c5e63ddacf3d83a4f15cdd' -and
        $executableSha256 -ceq
            '155195f7564e24d0093111e30b66eab82596a4fec7f82b4674ea286ce33f2f53' -and
        $driverSha256 -ceq
            'fa339fb4f6125b492a9f390a9ec790169374865cdac2a48e54c490fe3b7a1d52' -and
        $muiSha256 -ceq
            'edd35dd6665747ae4ea41f10591ebbe4d5f6d64e3fc5186ef7cbcb651e1476bc'
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.d01-pktmon-binary-tuple-compatibility/v1'
        library_sha256 = $librarySha256
        executable_sha256 = $executableSha256
        driver_sha256 = $driverSha256
        mui_sha256 = $muiSha256
        library_file_version = '{0}.{1}.{2}.{3}' -f
            $library.VersionInfo.FileMajorPart,
            $library.VersionInfo.FileMinorPart,
            $library.VersionInfo.FileBuildPart,
            $library.VersionInfo.FilePrivatePart
        executable_file_version = '{0}.{1}.{2}.{3}' -f
            $executable.VersionInfo.FileMajorPart,
            $executable.VersionInfo.FileMinorPart,
            $executable.VersionInfo.FileBuildPart,
            $executable.VersionInfo.FilePrivatePart
        driver_file_version = '{0}.{1}.{2}.{3}' -f
            $driver.VersionInfo.FileMajorPart,
            $driver.VersionInfo.FileMinorPart,
            $driver.VersionInfo.FileBuildPart,
            $driver.VersionInfo.FilePrivatePart
        mui_file_version = '{0}.{1}.{2}.{3}' -f
            $mui.VersionInfo.FileMajorPart,
            $mui.VersionInfo.FileMinorPart,
            $mui.VersionInfo.FileBuildPart,
            $mui.VersionInfo.FilePrivatePart
        private_abi =
            'PktmonStop(ptr);PktmonGetStatus(ptr64k);active-u8@0;configuration-u32@4;component-mode-u32@8;packet-size-u16@12;logger-present-u8@14'
        cli_contract =
            'pktmon-filter-list-es-es-table;counter-json;etl-capture-convert'
        operational_exclusion_contract =
            'exclusive-controlled-host;no-concurrent-pktmon-cli-filter-driver-etw-provider-or-direct-api-ioctl-mutators'
        exclusive_driver_control_operator_attested =
            $ExclusiveControlOperatorAttested
        compatible = $tupleExact
    }
}

function Assert-D01PktmonDriverApiCompatibilityContract {
    param([Parameter(Mandatory = $true)][object]$Evidence)

    $null = Assert-D01ExactPropertySet -Object $Evidence -Expected @(
        'schema', 'library_sha256', 'executable_sha256', 'driver_sha256',
        'mui_sha256', 'library_file_version', 'executable_file_version',
        'driver_file_version', 'mui_file_version', 'private_abi',
        'cli_contract',
        'operational_exclusion_contract',
        'exclusive_driver_control_operator_attested', 'compatible'
    ) -Context 'PktMon binary tuple compatibility'
    $schema = Assert-D01JsonStringValue -Value $Evidence.schema `
        -Context 'PktMon private driver API schema'
    $libraryHash = Assert-D01JsonStringValue `
        -Value $Evidence.library_sha256 `
        -Context 'PktMon private driver API library_sha256' `
        -Pattern '^[0-9a-f]{64}$'
    $executableHash = Assert-D01JsonStringValue `
        -Value $Evidence.executable_sha256 `
        -Context 'PktMon executable_sha256' -Pattern '^[0-9a-f]{64}$'
    $driverHash = Assert-D01JsonStringValue `
        -Value $Evidence.driver_sha256 `
        -Context 'PktMon driver_sha256' -Pattern '^[0-9a-f]{64}$'
    $muiHash = Assert-D01JsonStringValue -Value $Evidence.mui_sha256 `
        -Context 'PktMon MUI sha256' -Pattern '^[0-9a-f]{64}$'
    $libraryVersion = Assert-D01JsonStringValue `
        -Value $Evidence.library_file_version `
        -Context 'PktMon library file version'
    $executableVersion = Assert-D01JsonStringValue `
        -Value $Evidence.executable_file_version `
        -Context 'PktMon executable file version'
    $driverVersion = Assert-D01JsonStringValue `
        -Value $Evidence.driver_file_version `
        -Context 'PktMon driver file version'
    $muiVersion = Assert-D01JsonStringValue `
        -Value $Evidence.mui_file_version `
        -Context 'PktMon MUI file version'
    $privateAbi = Assert-D01JsonStringValue -Value $Evidence.private_abi `
        -Context 'PktMon private driver API private_abi'
    $cliContract = Assert-D01JsonStringValue -Value $Evidence.cli_contract `
        -Context 'PktMon CLI contract'
    $operationalExclusion = Assert-D01JsonStringValue `
        -Value $Evidence.operational_exclusion_contract `
        -Context 'PktMon private driver API operational exclusion'
    $exclusiveControlAttested = Assert-D01JsonBoolean `
        -Value $Evidence.exclusive_driver_control_operator_attested `
        -Context 'PktMon private driver API exclusive-control attestation'
    $compatible = Assert-D01JsonBoolean -Value $Evidence.compatible `
        -Context 'PktMon private driver API compatible'
    if ($schema -cne
            'ese.v91.d01-pktmon-binary-tuple-compatibility/v1' -or
        $libraryHash -cne
            '8a3e1913e6f3336357299eaf3d2917c03c4bc2a6e9c5e63ddacf3d83a4f15cdd' -or
        $executableHash -cne
            '155195f7564e24d0093111e30b66eab82596a4fec7f82b4674ea286ce33f2f53' -or
        $driverHash -cne
            'fa339fb4f6125b492a9f390a9ec790169374865cdac2a48e54c490fe3b7a1d52' -or
        $muiHash -cne
            'edd35dd6665747ae4ea41f10591ebbe4d5f6d64e3fc5186ef7cbcb651e1476bc' -or
        $libraryVersion -cne '10.0.26100.8737' -or
        $executableVersion -cne '10.0.26100.8875' -or
        $driverVersion -cne '10.0.26100.8875' -or
        $muiVersion -cne '10.0.26100.3624' -or
        $privateAbi -cne
            'PktmonStop(ptr);PktmonGetStatus(ptr64k);active-u8@0;configuration-u32@4;component-mode-u32@8;packet-size-u16@12;logger-present-u8@14' -or
        $cliContract -cne
            'pktmon-filter-list-es-es-table;counter-json;etl-capture-convert' -or
        $operationalExclusion -cne
            'exclusive-controlled-host;no-concurrent-pktmon-cli-filter-driver-etw-provider-or-direct-api-ioctl-mutators' -or
        -not $exclusiveControlAttested -or
        -not $compatible) {
        throw 'PktMon private driver API is outside the audited ABI whitelist'
    }
    return $true
}

function Assert-D01PktmonDriverStopContract {
    param(
        [Parameter(Mandatory = $true)][object]$Evidence,
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[0-9a-f]{64}$')][string]$ExpectedLibrarySha256,
        [AllowNull()][object]$ExpectedConfigurationBaseline = $null
    )
    $null = Assert-D01ExactPropertySet -Object $Evidence -Expected @(
        'schema', 'api', 'api_contract', 'library_sha256', 'attempted',
        'stop_error_code', 'status_error_code', 'active_after_stop',
        'configuration_after_stop', 'component_mode_after_stop',
        'packet_size_after_stop', 'logger_present_after_stop',
        'success', 'error_sha256'
    ) -Context 'PktMon driver stop evidence'
    foreach ($name in @('attempted', 'success')) {
        $null = Assert-D01JsonBoolean `
            -Value $Evidence.PSObject.Properties[$name].Value `
            -Context "PktMon driver stop evidence.$name"
    }
    $schema = Assert-D01JsonStringValue -Value $Evidence.schema `
        -Context 'PktMon driver stop evidence.schema'
    $api = Assert-D01JsonStringValue -Value $Evidence.api `
        -Context 'PktMon driver stop evidence.api'
    $apiContract = Assert-D01JsonStringValue -Value $Evidence.api_contract `
        -Context 'PktMon driver stop evidence.api_contract'
    $libraryHash = Assert-D01JsonStringValue `
        -Value $Evidence.library_sha256 `
        -Context 'PktMon driver stop evidence.library_sha256' `
        -Pattern '^[0-9a-f]{64}$'
    $errorHash = Assert-D01JsonStringValue -Value $Evidence.error_sha256 `
        -Context 'PktMon driver stop evidence.error_sha256' `
        -Pattern '^(?:|[0-9a-f]{64})$'
    $stopError = Assert-D01JsonInteger -Value $Evidence.stop_error_code `
        -Context 'PktMon driver stop evidence.stop_error_code' -Minimum 0
    $statusError = Assert-D01JsonInteger `
        -Value $Evidence.status_error_code `
        -Context 'PktMon driver stop evidence.status_error_code' -Minimum 0
    $active = Assert-D01JsonInteger -Value $Evidence.active_after_stop `
        -Context 'PktMon driver stop evidence.active_after_stop' `
        -Minimum 0 -Maximum 255
    foreach ($name in @(
        'configuration_after_stop', 'component_mode_after_stop',
        'packet_size_after_stop', 'logger_present_after_stop'
    )) {
        $maximum = if ($name -eq 'packet_size_after_stop') {
            65535
        } elseif ($name -eq 'logger_present_after_stop') {
            1
        } else { 4294967295 }
        $null = Assert-D01JsonInteger `
            -Value $Evidence.PSObject.Properties[$name].Value `
            -Context "PktMon driver stop evidence.$name" `
            -Minimum 0 -Maximum $maximum
    }
    if ($schema -cne
            'ese.v91.d01-pktmon-driver-stop/v1' -or
        $api -cne 'pktmonapi!PktmonStop' -or
        $apiContract -cne
            'global-non-tokenized-stop-under-exclusive-controlled-host' -or
        $libraryHash -cne $ExpectedLibrarySha256 -or
        -not [bool]$Evidence.attempted -or $stopError -ne 0 -or
        $statusError -ne 0 -or $active -ne 0 -or
        -not [bool]$Evidence.success -or
        $errorHash -cne '') {
        throw 'PktMon driver stop/status evidence is not exact'
    }
    if ($null -ne $ExpectedConfigurationBaseline) {
        $null = Assert-D01PktmonDriverStatusContract `
            -Evidence $ExpectedConfigurationBaseline `
            -ExpectedLibrarySha256 $ExpectedLibrarySha256
        $fieldMap = [ordered]@{
            configuration_after_stop = 'configuration'
            component_mode_after_stop = 'component_mode'
            packet_size_after_stop = 'packet_size'
            logger_present_after_stop = 'logger_present'
        }
        foreach ($field in $fieldMap.Keys) {
            if ([Int64]$Evidence.PSObject.Properties[$field].Value -ne
                [Int64]$ExpectedConfigurationBaseline.PSObject.Properties[
                    $fieldMap[$field]].Value) {
                throw "PktMon driver stop changed persistent field $field"
            }
        }
    }
    return $true
}

function Assert-D01PktmonDriverStatusContract {
    param(
        [Parameter(Mandatory = $true)][object]$Evidence,
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[0-9a-f]{64}$')][string]$ExpectedLibrarySha256,
        [switch]$RequireInactive,
        [switch]$RequireCaptureConfigurationBaseline,
        [switch]$IgnoreLoggerPresenceInBaselineComparison,
        [AllowNull()][object]$ExpectedConfigurationBaseline = $null
    )
    $null = Assert-D01ExactPropertySet -Object $Evidence -Expected @(
        'schema', 'api', 'library_sha256', 'status_error_code', 'active',
        'configuration', 'component_mode', 'packet_size', 'logger_present',
        'available', 'inactive_exact', 'read_only', 'error_sha256'
    ) -Context 'PktMon driver status evidence'
    foreach ($name in @('available', 'inactive_exact', 'read_only')) {
        $null = Assert-D01JsonBoolean `
            -Value $Evidence.PSObject.Properties[$name].Value `
            -Context "PktMon driver status evidence.$name"
    }
    $schema = Assert-D01JsonStringValue -Value $Evidence.schema `
        -Context 'PktMon driver status evidence.schema'
    $api = Assert-D01JsonStringValue -Value $Evidence.api `
        -Context 'PktMon driver status evidence.api'
    $libraryHash = Assert-D01JsonStringValue `
        -Value $Evidence.library_sha256 `
        -Context 'PktMon driver status evidence.library_sha256' `
        -Pattern '^[0-9a-f]{64}$'
    $errorHash = Assert-D01JsonStringValue -Value $Evidence.error_sha256 `
        -Context 'PktMon driver status evidence.error_sha256' `
        -Pattern '^(?:|[0-9a-f]{64})$'
    $statusError = Assert-D01JsonInteger `
        -Value $Evidence.status_error_code `
        -Context 'PktMon driver status evidence.status_error_code' -Minimum 0
    $active = Assert-D01JsonInteger -Value $Evidence.active `
        -Context 'PktMon driver status evidence.active' `
        -Minimum 0 -Maximum 255
    foreach ($name in @(
        'configuration', 'component_mode', 'packet_size', 'logger_present'
    )) {
        $maximum = if ($name -eq 'packet_size') {
            65535
        } elseif ($name -eq 'logger_present') { 1 } else { 4294967295 }
        $null = Assert-D01JsonInteger `
            -Value $Evidence.PSObject.Properties[$name].Value `
            -Context "PktMon driver status evidence.$name" `
            -Minimum 0 -Maximum $maximum
    }
    if ($schema -cne
            'ese.v91.d01-pktmon-driver-status/v1' -or
        $api -cne 'pktmonapi!PktmonGetStatus' -or
        $libraryHash -cne $ExpectedLibrarySha256 -or
        $statusError -ne 0 -or -not [bool]$Evidence.available -or
        -not [bool]$Evidence.read_only -or
        [bool]$Evidence.inactive_exact -ne ($active -eq 0) -or
        ($RequireInactive -and $active -ne 0) -or
        $errorHash -cne '') {
        throw 'PktMon driver status evidence is not exact'
    }
    if ($RequireCaptureConfigurationBaseline -and (
        [UInt32]$Evidence.configuration -ne 1 -or
        [UInt32]$Evidence.component_mode -ne 2 -or
        [UInt16]$Evidence.packet_size -ne 0 -or
        [byte]$Evidence.logger_present -ne 0)) {
        throw 'PktMon persistent state is not the exact inactive nics baseline'
    }
    if ($null -ne $ExpectedConfigurationBaseline) {
        $null = Assert-D01PktmonDriverStatusContract `
            -Evidence $ExpectedConfigurationBaseline `
            -ExpectedLibrarySha256 $ExpectedLibrarySha256
        foreach ($name in @(
            'configuration', 'component_mode', 'packet_size', 'logger_present'
        )) {
            if ($IgnoreLoggerPresenceInBaselineComparison -and
                $name -ceq 'logger_present') { continue }
            if ([Int64]$Evidence.PSObject.Properties[$name].Value -ne
                [Int64]$ExpectedConfigurationBaseline.PSObject.
                    Properties[$name].Value) {
                throw "PktMon driver status $name was not restored"
            }
        }
    }
    return $true
}

function Test-D01PktmonDriverLifecycleEvidence {
    param([Parameter(Mandatory = $true)][object]$State)

    try {
        $null = Assert-D01PktmonDriverApiCompatibilityContract `
            -Evidence $State.pktmon_driver_api_compatibility
        $libraryHash = [string]$State.pktmon_driver_api_compatibility.
            library_sha256
        $null = Assert-D01PktmonDriverStatusContract `
            -Evidence $State.pktmon_driver_status_before `
            -ExpectedLibrarySha256 $libraryHash -RequireInactive `
            -RequireCaptureConfigurationBaseline
        $null = Assert-D01PktmonDriverStatusContract `
            -Evidence $State.pktmon_driver_status_armed `
            -ExpectedLibrarySha256 $libraryHash `
            -ExpectedConfigurationBaseline $State.pktmon_driver_status_before `
            -IgnoreLoggerPresenceInBaselineComparison
        if ([int]$State.pktmon_driver_status_armed.active -ne 1 -or
            [int]$State.pktmon_driver_status_armed.logger_present -ne 1) {
            throw 'PktMon driver armed status is not active'
        }
        $null = Assert-D01PktmonDriverStopContract `
            -Evidence $State.pktmon_driver_stop `
            -ExpectedLibrarySha256 $libraryHash `
            -ExpectedConfigurationBaseline $State.pktmon_driver_status_before
        $null = Assert-D01PktmonDriverStatusContract `
            -Evidence $State.pktmon_driver_status_final `
            -ExpectedLibrarySha256 $libraryHash -RequireInactive `
            -ExpectedConfigurationBaseline $State.pktmon_driver_status_before
        $controlTraceId =
            [string]$State.etw_session_identity.control_trace_id_hex
        foreach ($identity in @(
            $State.pktmon_driver_stop_pre_identity,
            $State.pktmon_driver_stop_post_identity
        )) {
            $null = Assert-D01EtwIdentityBindingContract `
                -Evidence $identity `
                -ExpectedPhase 'post-flush-live-query' `
                -ExpectedLogFilePath ([string]$State.etl_path) `
                -ExpectedControlTraceIdHex $controlTraceId
            if ([string]$identity.session_identity_sha256 -cne
                [string]$State.etw_session_identity.
                    session_identity_sha256) {
                throw 'PktMon driver lifecycle ETW identity changed'
            }
        }
        return [bool]$State.pktmon_driver_stop_verified -and
            [bool]$State.pktmon_driver_configuration_restored_verified
    } catch { return $false }
}

function Test-D01PktmonInventoryMetadataLine {
    param([AllowEmptyString()][Parameter(Mandatory = $true)][string]$Line)

    $value = $Line.Trim()
    if ([string]::IsNullOrWhiteSpace($value) -or
        $value -match '^[\s\-=|+]+$' -or
        $value -match
            '(?i)^(?:packet\s+filters?|filtros?\s+de\s+paquete)\s*:?\s*$') {
        return $true
    }
    $residual = $value
    foreach ($label in @(
        'direcci\S+n\s+mac', 'mac\s+address',
        'puerto\s+vxlan', 'vxlan\s+port',
        'direcci\S+n\s+ip', 'ip\s+address',
        'id\.?\s+de\s+vlan', 'vlan\s+id',
        'encapsulaci\S+n', 'encapsulation',
        'protocolo', 'protocol', 'ethertype', 'dscp',
        'nombre', 'name', 'puerto', 'port', 'id\.?'
    )) {
        $residual = [regex]::Replace(
            $residual, '(?i)(?<![A-Z0-9])' + $label +
                '(?![A-Z0-9])', '')
    }
    $residual = [regex]::Replace($residual, '[\s\-=|:+#().\[\]]+', '')
    return [string]::IsNullOrEmpty($residual)
}

function Get-D01PktmonInventoryCensus {
    param([AllowEmptyString()][Parameter(Mandatory = $true)][string]$Text)

    $normalized = (($Text -replace "`r`n", "`n") -replace "`r", "`n").
        Trim()
    $canonicalSha256 = if ([string]::IsNullOrWhiteSpace($normalized)) {
        ''
    } else { Get-LabStringSha256 -Value $normalized }
    $invalid = {
        param([string]$Reason)
        return [pscustomobject][ordered]@{
            schema = 'ese.v91.d01-pktmon-filter-census/v1'
            exact = $false
            empty = $false
            reason = $Reason
            canonical_sha256 = $canonicalSha256
            line_count = 0
            entry_count = 0
            entries = @()
        }
    }
    if ([string]::IsNullOrWhiteSpace($normalized)) {
        return & $invalid 'empty-output'
    }
    $lines = @($normalized -split "`n" | ForEach-Object {
        ([string]$_).TrimEnd()
    } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $rowPattern = '^\s*(?<id>\d+)\s+(?<name>\S+)(?<rest>(?:\s+.*)?)$'
    $titlePattern = '(?i)^\s*filtros\s+de\s+paquete\s*:\s*$'
    $emptyPattern = '(?i)^\s*ninguno\s*$'
    $entries = [System.Collections.Generic.List[object]]::new()
    $headerLines = [System.Collections.Generic.List[string]]::new()
    $ids = [Collections.Generic.HashSet[UInt64]]::new()
    $names = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    $emptyMarkers = 0
    $titleMarkers = 0
    foreach ($line in $lines) {
        $match = [regex]::Match([string]$line, $rowPattern)
        if ([regex]::IsMatch([string]$line, $titlePattern)) {
            $titleMarkers++
        } elseif ($match.Success) {
            $id = [UInt64]0
            $name = [string]$match.Groups['name'].Value
            if (-not [UInt64]::TryParse(
                    [string]$match.Groups['id'].Value, [ref]$id) -or
                -not $ids.Add($id) -or -not $names.Add($name)) {
                return & $invalid 'non-unique-filter-id-or-name'
            }
            $entries.Add([pscustomobject][ordered]@{
                id = [UInt64]$id
                name = $name
                raw_text = [string]$line
                text = ([regex]::Replace(
                    [string]$line, '\s+', ' ')).Trim()
                ip_value = ''
            })
        } elseif ([regex]::IsMatch([string]$line, $emptyPattern)) {
            $emptyMarkers++
        } elseif (Test-D01PktmonInventoryMetadataLine -Line $line) {
            if ([string]$line -notmatch '^[\s\-=|+]+$') {
                $headerLines.Add([string]$line)
            }
        } else {
            return & $invalid 'unrecognized-inventory-line'
        }
    }
    if ($titleMarkers -ne 1 -or
        -not [regex]::IsMatch([string]$lines[0], $titlePattern)) {
        return & $invalid 'packet-filter-title-census'
    }
    if ($entries.Count -eq 0) {
        if ($emptyMarkers -ne 1 -or $lines.Count -ne 2 -or
            -not [regex]::IsMatch([string]$lines[1], $emptyPattern)) {
            return & $invalid 'empty-filter-envelope-census'
        }
    } elseif ($emptyMarkers -ne 0) {
        return & $invalid 'inconsistent-empty-marker-census'
    } else {
        $header = $headerLines.ToArray() -join ' '
        if ($header -notmatch
            '(?i)#.*nombre.*mac.*vlan.*ethertype.*dscp.*protocolo.*' +
                '(?:direcci\S+n\s+ip|(?<![a-z])ip(?![a-z])).*puerto.*' +
                'encapsulaci\S+n.*vxlan') {
            return & $invalid 'packet-filter-header-order-census'
        }
        foreach ($requiredHeader in @(
            '#', '(?i)(?<![a-z])nombre(?![a-z])',
            '(?i)(?<![a-z])mac(?![a-z])',
            '(?i)(?<![a-z])vlan(?![a-z])',
            '(?i)(?<![a-z])ethertype(?![a-z])',
            '(?i)(?<![a-z])dscp(?![a-z])',
            '(?i)(?<![a-z])protocolo(?![a-z])',
            '(?i)(?:direcci\S+n\s+ip|(?<![a-z])ip(?![a-z]))',
            '(?i)(?<![a-z])puerto(?![a-z])',
            '(?i)encapsulaci\S+n', '(?i)(?<![a-z])vxlan(?![a-z])'
        )) {
            if ($header -notmatch $requiredHeader) {
                return & $invalid 'packet-filter-header-census'
            }
        }
        $columnPatterns = @(
            '#', '(?i)nombre', '(?i)direcci\S+n\s+mac',
            '(?i)id\.?\s+de\s+vlan', '(?i)ethertype', '(?i)dscp',
            '(?i)protocolo', '(?i)direcci\S+n\s+ip',
            '(?i)puerto(?!\s+vxlan)',
            '(?i)encapsulaci\S+n', '(?i)puerto\s+vxlan'
        )
        $headerCandidates = @($headerLines.ToArray() | Where-Object {
            $candidate = [string]$_
            $cursor = 0
            $all = $true
            foreach ($pattern in $columnPatterns) {
                $match = [regex]::Match(
                    $candidate.Substring($cursor), $pattern)
                if (-not $match.Success) { $all = $false; break }
                $cursor += $match.Index + $match.Length
            }
            $all
        })
        if ($headerCandidates.Count -ne 1) {
            return & $invalid 'packet-filter-header-row-census'
        }
        $headerRow = [string]$headerCandidates[0]
        $columnStarts = [System.Collections.Generic.List[int]]::new()
        $cursor = 0
        foreach ($pattern in $columnPatterns) {
            $match = [regex]::Match($headerRow.Substring($cursor), $pattern)
            if (-not $match.Success) {
                return & $invalid 'packet-filter-column-offset-census'
            }
            $columnStarts.Add($cursor + $match.Index)
            $cursor += $match.Index + $match.Length
        }
        foreach ($entry in $entries.ToArray()) {
            $raw = [string]$entry.raw_text
            $values = [System.Collections.Generic.List[string]]::new()
            for ($columnIndex = 0;
                $columnIndex -lt $columnStarts.Count;
                $columnIndex++) {
                $start = $columnStarts[$columnIndex]
                $end = if ($columnIndex + 1 -lt $columnStarts.Count) {
                    $columnStarts[$columnIndex + 1]
                } else { $raw.Length }
                if ($start -ge $raw.Length) {
                    $values.Add('')
                } else {
                    $boundedEnd = [Math]::Min($end, $raw.Length)
                    $values.Add($raw.Substring(
                        $start, $boundedEnd - $start).Trim())
                }
            }
            if ([string]$values[0] -cne ([UInt64]$entry.id).ToString(
                    [Globalization.CultureInfo]::InvariantCulture) -or
                [string]$values[1] -cne [string]$entry.name -or
                [string]::IsNullOrWhiteSpace([string]$values[7]) -or
                @((2..6) + (8..10) | Where-Object {
                    -not [string]::IsNullOrEmpty([string]$values[$_])
                }).Count -ne 0) {
                return & $invalid 'packet-filter-non-address-column-census'
            }
            $entry.ip_value = [string]$values[7]
        }
        $orderedIds = @($entries.ToArray() | ForEach-Object {
            [UInt64]$_.id
        } | Sort-Object)
        if ($orderedIds.Count -eq 0 -or $orderedIds[0] -ne 1) {
            return & $invalid 'filter-id-origin-census'
        }
        for ($index = 1; $index -lt $orderedIds.Count; $index++) {
            if ($orderedIds[$index] -ne $orderedIds[$index - 1] + 1) {
                return & $invalid 'non-contiguous-filter-id-census'
            }
        }
    }
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.d01-pktmon-filter-census/v1'
        exact = $true
        empty = $entries.Count -eq 0
        reason = ''
        canonical_sha256 = $canonicalSha256
        line_count = $lines.Count
        entry_count = $entries.Count
        entries = $entries.ToArray()
    }
}

function Get-D01PktmonFilterRows {
    param([AllowEmptyString()][string]$Text = '')
    $census = Get-D01PktmonInventoryCensus -Text $Text
    if (-not [bool]$census.exact) {
        throw "PktMon filter inventory is not exact: $($census.reason)"
    }
    return @($census.entries | ForEach-Object {
        ([string]$_.text).ToLowerInvariant()
    } | Sort-Object)
}

function Test-D01PktmonArmedAllProtocolFilterContracts {
    param(
        [Parameter(Mandatory = $true)][object]$Census,
        [Parameter(Mandatory = $true)][string]$FilterV4,
        [Parameter(Mandatory = $true)][string]$FilterV6,
        [Parameter(Mandatory = $true)][string]$IPv4,
        [Parameter(Mandatory = $true)][string]$IPv6
    )

    if (-not [bool]$Census.exact -or [bool]$Census.empty -or
        [int]$Census.entry_count -ne 2) { return $false }
    $definitions = @(
        [pscustomobject]@{
            name = $FilterV4; address = $IPv4; family = 'ipv4'
            id = 1; prefix = '32'
        },
        [pscustomobject]@{
            name = $FilterV6; address = $IPv6; family = 'ipv6'
            id = 2; prefix = '128'
        }
    )
    foreach ($definition in $definitions) {
        $matches = @($Census.entries | Where-Object {
            [string]$_.name -ceq [string]$definition.name
        })
        if ($matches.Count -ne 1 -or
            [UInt64]$matches[0].id -ne [UInt64]$definition.id) {
            return $false
        }
        $normalizedAddress = Get-D01NormalizedIp `
            -Address ([string]$definition.address)
        $ipCell = [string]$matches[0].ip_value
        $parts = @($ipCell.Split('/'))
        if ($parts.Count -lt 1 -or $parts.Count -gt 2 -or
            ($parts.Count -eq 2 -and
                [string]$parts[1] -cne [string]$definition.prefix)) {
            return $false
        }
        if ((Get-D01NormalizedIp -Address ([string]$parts[0])) -cne
            $normalizedAddress) {
            return $false
        }
    }
    return $true
}

function Complete-D01TrustedCommandLease {
    param(
        [Parameter(Mandatory = $true)][object]$Lease,
        [switch]$Terminate
    )

    if ([bool]$Lease.process_exited) { return $true }
    $process = $Lease.process
    if ($null -eq $process) { return $false }
    try {
        $process.Refresh()
        if (-not $process.HasExited -and $Terminate) {
            try { $process.Kill() } catch {}
            try { $null = $process.WaitForExit(10000) } catch {}
            $process.Refresh()
        }
        if (-not $process.HasExited) { return $false }
        $Lease.process_exited = $true
        $Lease.exit_code = try { [int]$process.ExitCode } catch { 9009 }
        try { $process.Dispose() } catch {}
        $Lease.process = $null
        $Lease.disposed = $true
        return $true
    } catch { return $false }
}

function Test-D01TrustedCommandLedgerQuiescent {
    param([switch]$Terminate)

    $exact = $true
    foreach ($lease in @($script:d01TrustedCommandLeases)) {
        if (-not (Complete-D01TrustedCommandLease `
            -Lease $lease -Terminate:$Terminate)) { $exact = $false }
    }
    return $exact
}

function Invoke-D01TrustedSystemBinaryCommand {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('pktmon.exe', 'logman.exe',
            'powershell.exe')][string]$Name,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$LogPath,
        [ValidateRange(1, 300)][int]$TimeoutSeconds = 30
    )

    $process = $null
    $timedOut = $false
    $stdout = ''
    $stderr = ''
    $exitCode = 9009
    $outputComplete = $false
    $stdoutTask = $null
    $stderrTask = $null
    $processStarted = $false
    $processExited = $false
    $processId = 0
    $lease = $null
    if (-not (Test-D01TrustedCommandLedgerQuiescent -Terminate)) {
        return [pscustomobject][ordered]@{
            exit_code = 1460
            timed_out = $true
            output_complete = $false
            process_started = $false
            process_id = 0
            process_exited = $false
            stdout = ''
            stderr = 'A prior trusted command process is still active'
        }
    }
    try {
        $startInfo = New-Object Diagnostics.ProcessStartInfo
        $startInfo.FileName = Get-D01TrustedSystemBinaryPath -Name $Name
        if ($Name -ceq 'pktmon.exe') {
            if ($null -eq $script:d01PktmonBinaryTuple) {
                throw 'PktMon CLI refused without an audited binary tuple'
            }
            $null = Assert-D01PktmonDriverApiCompatibilityContract `
                -Evidence $script:d01PktmonBinaryTuple
            $currentExecutableHash = Get-LabSha256 `
                -Path ([string]$startInfo.FileName)
            $currentDriverHash = Get-LabSha256 -Path (
                Get-D01TrustedSystemBinaryPath -Name 'pktmon.sys')
            $currentLibraryHash = Get-LabSha256 -Path (
                Get-D01TrustedSystemBinaryPath -Name 'pktmonapi.dll')
            $currentMuiHash = Get-LabSha256 -Path (
                Get-D01TrustedPktmonMuiPath)
            if ($currentExecutableHash -cne
                    [string]$script:d01PktmonBinaryTuple.executable_sha256 -or
                $currentDriverHash -cne
                    [string]$script:d01PktmonBinaryTuple.driver_sha256 -or
                $currentLibraryHash -cne
                    [string]$script:d01PktmonBinaryTuple.library_sha256 -or
                $currentMuiHash -cne
                    [string]$script:d01PktmonBinaryTuple.mui_sha256) {
                throw 'PktMon CLI refused after an audited binary tuple change'
            }
        }
        $quoted = foreach ($argumentValue in $Arguments) {
            $argument = [string]$argumentValue
            if ($argument -notmatch '[\s"]') {
                $argument
                continue
            }
            $builder = New-Object Text.StringBuilder
            $null = $builder.Append('"')
            $backslashes = 0
            foreach ($character in $argument.ToCharArray()) {
                if ($character -eq '\') {
                    $backslashes++
                    continue
                }
                if ($character -eq '"') {
                    $null = $builder.Append(('\' * ($backslashes * 2 + 1)))
                    $null = $builder.Append('"')
                    $backslashes = 0
                    continue
                }
                if ($backslashes -gt 0) {
                    $null = $builder.Append(('\' * $backslashes))
                    $backslashes = 0
                }
                $null = $builder.Append($character)
            }
            if ($backslashes -gt 0) {
                $null = $builder.Append(('\' * ($backslashes * 2)))
            }
            $null = $builder.Append('"')
            $builder.ToString()
        }
        $startInfo.Arguments = $quoted -join ' '
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        $process = New-Object Diagnostics.Process
        $process.StartInfo = $startInfo
        if (-not $process.Start()) {
            throw "$Name process did not start"
        }
        $processStarted = $true
        $processId = [int]$process.Id
        $processStartUtcTicks = [Int64]$process.StartTime.
            ToUniversalTime().Ticks
        $observedProcessPath = [IO.Path]::GetFullPath(
            [string]$process.MainModule.FileName)
        if (-not [string]::Equals(
                $observedProcessPath,
                [IO.Path]::GetFullPath([string]$startInfo.FileName),
                [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Trusted command process image changed after Process.Start'
        }
        $lease = [pscustomobject][ordered]@{
            process = $process
            process_id = $processId
            process_start_utc_ticks = $processStartUtcTicks
            process_path = $observedProcessPath
            process_sha256 = Get-LabSha256 -Path $observedProcessPath
            command_name = $Name
            process_exited = $false
            exit_code = $null
            disposed = $false
        }
        $script:d01TrustedCommandLeases.Add($lease)
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $processExited = $process.WaitForExit($TimeoutSeconds * 1000)
        if (-not $processExited) {
            $timedOut = $true
            try { $process.Kill() } catch {}
            $processExited = $process.WaitForExit(10000)
        }
        if ($processExited) {
            $stdoutReady = $stdoutTask.Wait(5000)
            $stderrReady = $stderrTask.Wait(5000)
            if ($stdoutReady -and $stderrReady -and
                $stdoutTask.Status -eq
                    [Threading.Tasks.TaskStatus]::RanToCompletion -and
                $stderrTask.Status -eq
                    [Threading.Tasks.TaskStatus]::RanToCompletion) {
                $stdout = $stdoutTask.Result
                $stderr = $stderrTask.Result
                $outputComplete = $true
            } else {
                $stderr = 'bounded command output drain did not complete'
            }
        } else {
            try { $process.StandardOutput.Close() } catch {}
            try { $process.StandardError.Close() } catch {}
            $stderr = 'bounded command could not be terminated'
        }
        if ($timedOut -or -not $processExited -or -not $outputComplete) {
            $exitCode = 1460
        } else {
            $exitCode = $process.ExitCode
        }
    } catch {
        $stderr += "`n" + $_.Exception.Message
        $exitCode = 9009
    } finally {
        if ($processStarted -and $null -eq $lease -and $null -ne $process) {
            try {
                $lease = [pscustomobject][ordered]@{
                    process = $process
                    process_id = $processId
                    process_start_utc_ticks = 0
                    process_path = [string]$startInfo.FileName
                    process_sha256 = ''
                    command_name = $Name
                    process_exited = $false
                    exit_code = $null
                    disposed = $false
                }
                $script:d01TrustedCommandLeases.Add($lease)
            } catch {}
        }
        if ($null -ne $lease) {
            $processExited = Complete-D01TrustedCommandLease `
                -Lease $lease -Terminate
            if (-not $processExited) {
                $exitCode = 1460
                $stderr += "`ntrusted command process remains active"
            }
        } elseif ($null -ne $process) {
            try { $process.Dispose() } catch {}
        }
    }
    try {
        Add-Content -LiteralPath $LogPath -Encoding utf8 -Value @(
            ('[{0}] {1} {2}' -f (Get-LabUtcTimestamp), $Name,
                ($Arguments -join ' ')), $stdout, $stderr,
            "timed_out=$timedOut", "output_complete=$outputComplete",
            "process_started=$processStarted", "process_id=$processId",
            "process_exited=$processExited", "exit_code=$exitCode"
        )
    } catch {
        $stderr += "`ncommand log: " + $_.Exception.Message
        $exitCode = 9009
    }
    return [pscustomobject][ordered]@{
        exit_code = $exitCode
        timed_out = $timedOut
        output_complete = $outputComplete
        process_started = $processStarted
        process_id = $processId
        process_exited = $processExited
        stdout = $stdout
        stderr = $stderr
    }
}

function Invoke-D01BoundedNativeOperation {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('driver-status', 'driver-stop', 'etw-probe',
            'etw-query', 'etw-stop')]
        [string]$Operation,
        [AllowEmptyString()][string]$ExpectedLibrarySha256 = '',
        [AllowEmptyString()][string]$ExpectedDriverSha256 = '',
        [AllowEmptyString()][string]$ExpectedLogFilePath = '',
        [AllowEmptyString()][string]$ExpectedControlTraceIdHex = ''
    )

    if ([string]::IsNullOrWhiteSpace($script:d01NativeHelperLogPath)) {
        throw 'Native helper log path is unavailable'
    }
    $scriptPath = Assert-D01NoReparsePath -Path $PSCommandPath -Kind File
    $scriptSha256 = Get-LabSha256 -Path $scriptPath
    $arguments = @(
        '-NoLogo', '-NoProfile', '-NonInteractive',
        '-ExecutionPolicy', 'Bypass', '-File', $scriptPath,
        '-InternalNativeOperation', $Operation,
        '-InternalExpectedScriptSha256', $scriptSha256
    )
    if ($ExpectedLibrarySha256) {
        $arguments += @(
            '-InternalExpectedLibrarySha256', $ExpectedLibrarySha256)
    }
    if ($ExpectedDriverSha256) {
        $arguments += @(
            '-InternalExpectedDriverSha256', $ExpectedDriverSha256)
    }
    if ($ExpectedLogFilePath) {
        $arguments += @('-InternalExpectedLogFilePath', $ExpectedLogFilePath)
    }
    if ($ExpectedControlTraceIdHex) {
        $arguments += @(
            '-InternalExpectedControlTraceIdHex',
            $ExpectedControlTraceIdHex)
    }
    $result = Invoke-D01TrustedSystemBinaryCommand `
        -Name 'powershell.exe' -Arguments $arguments `
        -LogPath $script:d01NativeHelperLogPath -TimeoutSeconds 60
    if ([int]$result.exit_code -ne 0 -or
        -not [bool]$result.process_exited -or
        -not [bool]$result.output_complete -or
        -not [string]::IsNullOrWhiteSpace([string]$result.stderr) -or
        [string]::IsNullOrWhiteSpace([string]$result.stdout)) {
        throw "Bounded native helper failed for $Operation"
    }
    $envelope = [string]$result.stdout | ConvertFrom-Json -ErrorAction Stop
    $null = Assert-D01ExactPropertySet -Object $envelope -Expected @(
        'schema', 'operation', 'success', 'payload', 'error_sha256'
    ) -Context 'bounded native helper envelope'
    $null = Assert-D01JsonStringValue -Value $envelope.schema `
        -Context 'bounded native helper envelope.schema'
    $null = Assert-D01JsonStringValue -Value $envelope.operation `
        -Context 'bounded native helper envelope.operation'
    $helperSuccess = Assert-D01JsonBoolean -Value $envelope.success `
        -Context 'bounded native helper envelope.success'
    $errorHash = Assert-D01JsonStringValue -Value $envelope.error_sha256 `
        -Context 'bounded native helper envelope.error_sha256' `
        -Pattern '^(?:|[0-9a-f]{64})$'
    if ([string]$envelope.schema -cne
            'ese.v91.d01-bounded-native-helper/v1' -or
        [string]$envelope.operation -cne $Operation -or
        -not $helperSuccess -or $errorHash -cne '' -or
        $null -eq $envelope.payload) {
        throw "Bounded native helper contract failed for $Operation"
    }
    return $envelope.payload
}

function Invoke-D01Pktmon {
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$LogPath,
        [ValidateRange(1, 300)][int]$TimeoutSeconds = 30
    )
    return Invoke-D01TrustedSystemBinaryCommand -Name 'pktmon.exe' `
        -Arguments $Arguments -LogPath $LogPath `
        -TimeoutSeconds $TimeoutSeconds
}

function Get-D01EtwLossEvidence {
    param(
        [switch]$StopOwnedSession,
        [AllowEmptyString()][string]$ExpectedLogFilePath = '',
        [AllowEmptyString()][string]$ExpectedControlTraceIdHex = '',
        [switch]$IdentityProbeOnly,
        [switch]$DirectInternal
    )

    if (-not $DirectInternal) {
        $operation = if ($IdentityProbeOnly) {
            'etw-probe'
        } elseif ($StopOwnedSession) { 'etw-stop' } else { 'etw-query' }
        return Invoke-D01BoundedNativeOperation -Operation $operation `
            -ExpectedLogFilePath $ExpectedLogFilePath `
            -ExpectedControlTraceIdHex $ExpectedControlTraceIdHex
    }
    if (-not ('V91D01EtwTraceControlV4' -as [type])) {
        Add-Type @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class V91D01EtwTraceControlV4 {
    [StructLayout(LayoutKind.Sequential)]
    private struct WNODE_HEADER {
        public UInt32 BufferSize;
        public UInt32 ProviderId;
        public UInt64 HistoricalContext;
        public Int64 TimeStamp;
        public Guid Guid;
        public UInt32 ClientContext;
        public UInt32 Flags;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct EVENT_TRACE_PROPERTIES {
        public WNODE_HEADER Wnode;
        public UInt32 BufferSize;
        public UInt32 MinimumBuffers;
        public UInt32 MaximumBuffers;
        public UInt32 MaximumFileSize;
        public UInt32 LogFileMode;
        public UInt32 FlushTimer;
        public UInt32 EnableFlags;
        public Int32 AgeLimit;
        public UInt32 NumberOfBuffers;
        public UInt32 FreeBuffers;
        public UInt32 EventsLost;
        public UInt32 BuffersWritten;
        public UInt32 LogBuffersLost;
        public UInt32 RealTimeBuffersLost;
        public IntPtr LoggerThreadId;
        public UInt32 LogFileNameOffset;
        public UInt32 LoggerNameOffset;
    }
    public sealed class Result {
        public UInt32 ErrorCode;
        public UInt64 ControlTraceId;
        public string LoggerName = "";
        public string LogFileName = "";
        public UInt32 EventsLost;
        public UInt32 LogBuffersLost;
        public UInt32 RealTimeBuffersLost;
        public UInt32 BuffersWritten;
    }
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode)]
    private static extern UInt32 ControlTrace(
        UInt64 sessionHandle, string sessionName, IntPtr properties,
        UInt32 controlCode);
    private static string ReadUnicodeString(
        IntPtr buffer, UInt32 offset, int total) {
        if (offset == 0 || offset >= total || (offset & 1) != 0) {
            return "";
        }
        int maximumChars = (total - checked((int)offset)) / sizeof(char);
        if (maximumChars <= 0) {
            return "";
        }
        string value = Marshal.PtrToStringUni(
            IntPtr.Add(buffer, checked((int)offset)), maximumChars);
        if (value == null) {
            return "";
        }
        int terminator = value.IndexOf('\0');
        return terminator >= 0 ? value.Substring(0, terminator) : value;
    }
    private static Result Control(
        UInt64 sessionHandle, string sessionName, UInt32 controlCode) {
        int size = Marshal.SizeOf(typeof(EVENT_TRACE_PROPERTIES));
        const int loggerNameCapacityChars = 1024;
        const int logFileNameCapacityChars = 32768;
        int loggerNameCapacityBytes = loggerNameCapacityChars * sizeof(char);
        int logFileNameCapacityBytes = logFileNameCapacityChars * sizeof(char);
        byte[] name = null;
        if (sessionName != null) {
            name = Encoding.Unicode.GetBytes(sessionName + "\0");
            if (name.Length > loggerNameCapacityBytes) {
                throw new ArgumentOutOfRangeException("sessionName");
            }
        }
        int total = checked(
            size + loggerNameCapacityBytes + logFileNameCapacityBytes);
        IntPtr buffer = Marshal.AllocHGlobal(total);
        try {
            Marshal.Copy(new byte[total], 0, buffer, total);
            EVENT_TRACE_PROPERTIES p = new EVENT_TRACE_PROPERTIES();
            p.Wnode.BufferSize = (UInt32)total;
            p.Wnode.Flags = 0x00020000;
            p.LoggerNameOffset = (UInt32)size;
            p.LogFileNameOffset =
                (UInt32)(size + loggerNameCapacityBytes);
            Marshal.StructureToPtr(p, buffer, false);
            if (name != null) {
                Marshal.Copy(name, 0, IntPtr.Add(buffer, size), name.Length);
            }
            UInt32 error = ControlTrace(
                sessionHandle, sessionName, buffer, controlCode);
            Result r = new Result();
            r.ErrorCode = error;
            if (error == 0) {
                p = (EVENT_TRACE_PROPERTIES)Marshal.PtrToStructure(
                    buffer, typeof(EVENT_TRACE_PROPERTIES));
                r.ControlTraceId = p.Wnode.HistoricalContext;
                r.LoggerName = ReadUnicodeString(
                    buffer, p.LoggerNameOffset, total);
                r.LogFileName = ReadUnicodeString(
                    buffer, p.LogFileNameOffset, total);
                r.EventsLost = p.EventsLost;
                r.LogBuffersLost = p.LogBuffersLost;
                r.RealTimeBuffersLost = p.RealTimeBuffersLost;
                r.BuffersWritten = p.BuffersWritten;
            }
            return r;
        } finally {
            Marshal.FreeHGlobal(buffer);
        }
    }
    public static Result QueryByName(string sessionName) {
        return Control(0, sessionName, 0);
    }
    public static Result QueryById(UInt64 controlTraceId) {
        return Control(controlTraceId, null, 0);
    }
    public static Result StopById(UInt64 controlTraceId) {
        return Control(controlTraceId, null, 1);
    }
    public static UInt32 FlushById(UInt64 controlTraceId) {
        return Control(controlTraceId, null, 3).ErrorCode;
    }
}
'@
    }
    $phase = if ($StopOwnedSession) {
        'post-final-flush-control-stop'
    } else { 'post-flush-live-query' }
    $expectedPathHash = ''
    $observedPathHash = ''
    $observedIdHex = ''
    $observedLoggerName = ''
    $identityHash = ''
    $loggerNameExact = $false
    $logFileNameExact = $false
    $controlTraceIdExact = $false
    $queryByIdIdentityExact = $false
    $sessionIdentityExact = $false
    $flushError = $null
    try {
        if ($IdentityProbeOnly -and $StopOwnedSession) {
            throw 'ETW identity-only probe cannot stop a session'
        }
        if ($ExpectedControlTraceIdHex -and
            $ExpectedControlTraceIdHex -cnotmatch '^[0-9a-f]{16}$') {
            throw 'Expected ETW ControlTrace ID is not canonical hexadecimal'
        }
        $queryByName =
            [V91D01EtwTraceControlV4]::QueryByName('PktMon')
        if ($IdentityProbeOnly) {
            if ([UInt32]$queryByName.ErrorCode -eq 0) {
                if ([UInt64]$queryByName.ControlTraceId -ne 0) {
                    $observedIdHex =
                        ([UInt64]$queryByName.ControlTraceId).ToString(
                            'x16',
                            [Globalization.CultureInfo]::InvariantCulture)
                }
                $observedLoggerName = [string]$queryByName.LoggerName
                if (-not [string]::IsNullOrWhiteSpace(
                        [string]$queryByName.LogFileName)) {
                    $probePath = [IO.Path]::GetFullPath(
                        [string]$queryByName.LogFileName)
                    $observedPathHash = Get-LabStringSha256 -Value (
                        $probePath.ToLowerInvariant())
                }
            }
            return [pscustomobject][ordered]@{
                schema = 'ese.v91.d01-etw-session-name-probe/v1'
                available = [UInt32]$queryByName.ErrorCode -eq 0
                absent_exact =
                    [UInt32]$queryByName.ErrorCode -eq [UInt32]4201
                error_code = [int][UInt32]$queryByName.ErrorCode
                control_trace_id_hex = $observedIdHex
                logger_name = $observedLoggerName
                log_file_name_sha256 = $observedPathHash
                read_only = $true
                error_sha256 = ''
            }
        }
        if ([UInt32]$queryByName.ErrorCode -ne 0) {
            throw 'PktMon ETW session could not be queried by its fixed name'
        }
        if ([string]::IsNullOrWhiteSpace($ExpectedLogFilePath)) {
            throw 'Expected ETW log-file path is required'
        }
        $expectedPath = [IO.Path]::GetFullPath($ExpectedLogFilePath)
        $expectedPathHash = Get-LabStringSha256 -Value (
            $expectedPath.ToLowerInvariant())
        if ([UInt64]$queryByName.ControlTraceId -eq 0) {
            throw 'PktMon ETW query returned a zero ControlTrace ID'
        }
        $observedIdHex = ([UInt64]$queryByName.ControlTraceId).ToString(
            'x16', [Globalization.CultureInfo]::InvariantCulture)
        $observedLoggerName = [string]$queryByName.LoggerName
        $loggerNameExact = $observedLoggerName -ceq 'PktMon'
        if ([string]::IsNullOrWhiteSpace(
                [string]$queryByName.LogFileName)) {
            throw 'PktMon ETW query omitted its log-file name'
        }
        $observedPath = [IO.Path]::GetFullPath(
            [string]$queryByName.LogFileName)
        $observedPathHash = Get-LabStringSha256 -Value (
            $observedPath.ToLowerInvariant())
        $logFileNameExact = [string]::Equals(
            $expectedPath, $observedPath,
            [StringComparison]::OrdinalIgnoreCase)
        $controlTraceIdExact = -not $ExpectedControlTraceIdHex -or
            $observedIdHex -ceq $ExpectedControlTraceIdHex
        if (-not $loggerNameExact -or -not $logFileNameExact -or
            -not $controlTraceIdExact) {
            throw 'PktMon ETW name, ControlTrace ID, or ETL path is foreign'
        }
        [UInt64]$boundControlTraceId = [UInt64]::Parse(
            $observedIdHex, [Globalization.NumberStyles]::HexNumber,
            [Globalization.CultureInfo]::InvariantCulture)
        $flushError = [V91D01EtwTraceControlV4]::FlushById(
            $boundControlTraceId)
        $queryById = [V91D01EtwTraceControlV4]::QueryById(
            $boundControlTraceId)
        if ([UInt32]$queryById.ErrorCode -ne 0 -or
            [UInt64]$queryById.ControlTraceId -ne $boundControlTraceId -or
            [string]$queryById.LoggerName -cne 'PktMon' -or
            [string]::IsNullOrWhiteSpace(
                [string]$queryById.LogFileName)) {
            throw 'PktMon ETW identity changed after the ID-bound flush'
        }
        $queryByIdPath = [IO.Path]::GetFullPath(
            [string]$queryById.LogFileName)
        $queryByIdIdentityExact = [string]::Equals(
            $expectedPath, $queryByIdPath,
            [StringComparison]::OrdinalIgnoreCase)
        if (-not $queryByIdIdentityExact) {
            throw 'PktMon ETW ID now resolves to a foreign ETL path'
        }
        $sessionIdentityExact = $true
        $identityProjection = [ordered]@{
            schema = 'ese.v91.d01-etw-session-identity/v1'
            control_trace_id_hex = $observedIdHex
            logger_name = $observedLoggerName
            log_file_name_sha256 = $observedPathHash
        }
        $identityHash = Get-LabStringSha256 -Value (
            $identityProjection | ConvertTo-Json -Depth 4 -Compress)
        $result = if ($StopOwnedSession) {
            [V91D01EtwTraceControlV4]::StopById($boundControlTraceId)
        } else { $queryById }
        $buffersLost = [UInt64]$result.LogBuffersLost +
            [UInt64]$result.RealTimeBuffersLost
        return [pscustomobject][ordered]@{
            schema = 'ese.v91.d01-etw-final-loss/v3'
            phase = $phase
            control_trace_id_hex = $observedIdHex
            expected_control_trace_id_hex =
                $ExpectedControlTraceIdHex
            logger_name = $observedLoggerName
            logger_name_exact = $loggerNameExact
            log_file_name_sha256 = $observedPathHash
            expected_log_file_name_sha256 = $expectedPathHash
            log_file_name_exact = $logFileNameExact
            control_trace_id_exact = $controlTraceIdExact
            query_by_id_identity_exact = $queryByIdIdentityExact
            session_identity_sha256 = $identityHash
            session_identity_exact = $sessionIdentityExact
            flush_error_code = [UInt32]$flushError
            flush_success = [UInt32]$flushError -eq 0
            available = [UInt32]$flushError -eq 0 -and
                [UInt32]$result.ErrorCode -eq 0 -and
                $sessionIdentityExact
            error_code = [UInt32]$result.ErrorCode
            events_lost = [UInt64]$result.EventsLost
            log_buffers_lost = [UInt64]$result.LogBuffersLost
            realtime_buffers_lost = [UInt64]$result.RealTimeBuffersLost
            buffers_lost = $buffersLost
            buffers_written = [UInt64]$result.BuffersWritten
            session_stopped_by_control_trace =
                [bool]$StopOwnedSession -and
                [UInt32]$result.ErrorCode -eq 0 -and
                $sessionIdentityExact
            proved_zero = [UInt32]$flushError -eq 0 -and
                [UInt32]$result.ErrorCode -eq 0 -and
                $sessionIdentityExact -and
                [UInt64]$result.EventsLost -eq 0 -and $buffersLost -eq 0
            error_sha256 = ''
        }
    } catch {
        if ($IdentityProbeOnly) {
            return [pscustomobject][ordered]@{
                schema = 'ese.v91.d01-etw-session-name-probe/v1'
                available = $false
                absent_exact = $false
                error_code = $null
                control_trace_id_hex = $observedIdHex
                logger_name = $observedLoggerName
                log_file_name_sha256 = $observedPathHash
                read_only = $true
                error_sha256 =
                    Get-LabStringSha256 -Value $_.Exception.Message
            }
        }
        return [pscustomobject][ordered]@{
            schema = 'ese.v91.d01-etw-final-loss/v3'
            phase = $phase
            control_trace_id_hex = $observedIdHex
            expected_control_trace_id_hex =
                $ExpectedControlTraceIdHex
            logger_name = $observedLoggerName
            logger_name_exact = $loggerNameExact
            log_file_name_sha256 = $observedPathHash
            expected_log_file_name_sha256 = $expectedPathHash
            log_file_name_exact = $logFileNameExact
            control_trace_id_exact = $controlTraceIdExact
            query_by_id_identity_exact = $queryByIdIdentityExact
            session_identity_sha256 = $identityHash
            session_identity_exact = $sessionIdentityExact
            flush_error_code = $null
            flush_success = $false
            available = $false
            error_code = $null
            events_lost = $null
            log_buffers_lost = $null
            realtime_buffers_lost = $null
            buffers_lost = $null
            buffers_written = $null
            session_stopped_by_control_trace = $false
            proved_zero = $false
            error_sha256 = Get-LabStringSha256 -Value $_.Exception.Message
        }
    }
}

function Assert-D01EtwSessionNameProbeContract {
    param(
        [Parameter(Mandatory = $true)][object]$Probe,
        [switch]$RequirePresent,
        [switch]$RequireAbsent
    )

    if ($RequirePresent -and $RequireAbsent) {
        throw 'ETW session-name probe cannot require present and absent'
    }
    $null = Assert-D01ExactPropertySet -Object $Probe -Expected @(
        'schema', 'available', 'absent_exact', 'error_code',
        'control_trace_id_hex', 'logger_name', 'log_file_name_sha256',
        'read_only', 'error_sha256'
    ) -Context 'PktMon ETW session-name probe'
    foreach ($name in @(
        'schema', 'control_trace_id_hex', 'logger_name',
        'log_file_name_sha256', 'error_sha256'
    )) {
        $null = Assert-D01JsonStringValue `
            -Value $Probe.PSObject.Properties[$name].Value `
            -Context "PktMon ETW session-name probe.$name"
    }
    foreach ($name in @('available', 'absent_exact', 'read_only')) {
        $null = Assert-D01JsonBoolean `
            -Value $Probe.PSObject.Properties[$name].Value `
            -Context "PktMon ETW session-name probe.$name"
    }
    if ([string]$Probe.schema -cne
            'ese.v91.d01-etw-session-name-probe/v1' -or
        -not [bool]$Probe.read_only -or
        ([bool]$Probe.available -and [bool]$Probe.absent_exact)) {
        throw 'PktMon ETW session-name probe envelope is contradictory'
    }
    if ([bool]$Probe.available) {
        $errorCode = Assert-D01JsonInteger -Value $Probe.error_code `
            -Context 'PktMon ETW session-name probe.error_code' `
            -Minimum 0
        if ($errorCode -ne 0 -or
            [string]$Probe.control_trace_id_hex -cnotmatch
                '^[0-9a-f]{16}$' -or
            [string]$Probe.logger_name -cne 'PktMon' -or
            [string]$Probe.log_file_name_sha256 -cnotmatch
                '^[0-9a-f]{64}$' -or
            [string]$Probe.error_sha256 -cne '') {
            throw 'Present PktMon ETW session-name probe is not exact'
        }
    } elseif ([bool]$Probe.absent_exact) {
        $errorCode = Assert-D01JsonInteger -Value $Probe.error_code `
            -Context 'PktMon ETW absent probe.error_code' -Minimum 0
        if ($errorCode -ne 4201 -or
            [string]$Probe.control_trace_id_hex -cne '' -or
            [string]$Probe.logger_name -cne '' -or
            [string]$Probe.log_file_name_sha256 -cne '' -or
            [string]$Probe.error_sha256 -cne '') {
            throw 'Absent PktMon ETW session-name probe is not exact'
        }
    } else {
        throw 'PktMon ETW session-name probe did not prove a state'
    }
    if (($RequirePresent -and -not [bool]$Probe.available) -or
        ($RequireAbsent -and -not [bool]$Probe.absent_exact)) {
        throw 'PktMon ETW session-name probe has the wrong required state'
    }
    return $true
}

function Assert-D01EtwIdentityBindingContract {
    param(
        [Parameter(Mandatory = $true)][object]$Evidence,
        [Parameter(Mandatory = $true)]
        [ValidateSet('post-flush-live-query',
            'post-final-flush-control-stop')][string]$ExpectedPhase,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()][string]$ExpectedLogFilePath,
        [AllowEmptyString()][string]$ExpectedControlTraceIdHex = ''
    )

    $null = Assert-D01ExactPropertySet -Object $Evidence -Expected @(
        'schema', 'phase', 'control_trace_id_hex',
        'expected_control_trace_id_hex', 'logger_name',
        'logger_name_exact', 'log_file_name_sha256',
        'expected_log_file_name_sha256', 'log_file_name_exact',
        'control_trace_id_exact', 'query_by_id_identity_exact',
        'session_identity_sha256', 'session_identity_exact',
        'flush_error_code', 'flush_success', 'available', 'error_code',
        'events_lost', 'log_buffers_lost', 'realtime_buffers_lost',
        'buffers_lost', 'buffers_written',
        'session_stopped_by_control_trace', 'proved_zero',
        'error_sha256'
    ) -Context 'PktMon ETW identity binding'
    $expectedPathHash = Get-LabStringSha256 -Value (
        [IO.Path]::GetFullPath(
            $ExpectedLogFilePath).ToLowerInvariant())
    $identityProjection = [ordered]@{
        schema = 'ese.v91.d01-etw-session-identity/v1'
        control_trace_id_hex = [string]$Evidence.control_trace_id_hex
        logger_name = [string]$Evidence.logger_name
        log_file_name_sha256 = [string]$Evidence.log_file_name_sha256
    }
    $expectedIdentityHash = Get-LabStringSha256 -Value (
        $identityProjection | ConvertTo-Json -Depth 4 -Compress)
    if ([string]$Evidence.schema -cne
            'ese.v91.d01-etw-final-loss/v3' -or
        [string]$Evidence.phase -cne $ExpectedPhase -or
        [string]$Evidence.control_trace_id_hex -cnotmatch
            '^[0-9a-f]{16}$' -or
        [string]$Evidence.expected_control_trace_id_hex -cne
            $ExpectedControlTraceIdHex -or
        ($ExpectedControlTraceIdHex -and
            [string]$Evidence.control_trace_id_hex -cne
                $ExpectedControlTraceIdHex) -or
        [string]$Evidence.logger_name -cne 'PktMon' -or
        [string]$Evidence.log_file_name_sha256 -cne $expectedPathHash -or
        [string]$Evidence.expected_log_file_name_sha256 -cne
            $expectedPathHash -or
        [string]$Evidence.session_identity_sha256 -cne
            $expectedIdentityHash -or
        -not [bool]$Evidence.logger_name_exact -or
        -not [bool]$Evidence.log_file_name_exact -or
        -not [bool]$Evidence.control_trace_id_exact -or
        -not [bool]$Evidence.query_by_id_identity_exact -or
        -not [bool]$Evidence.session_identity_exact -or
        [string]$Evidence.error_sha256 -cne '') {
        throw 'PktMon ETW session identity binding is not exact'
    }
    return $true
}

function Assert-D01EtwLossEvidenceContract {
    param(
        [Parameter(Mandatory = $true)][object]$Evidence,
        [Parameter(Mandatory = $true)]
        [ValidateSet('post-flush-live-query',
            'post-final-flush-control-stop')][string]$ExpectedPhase,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()][string]$ExpectedLogFilePath,
        [AllowEmptyString()][string]$ExpectedControlTraceIdHex = '',
        [switch]$RequireStopped,
        [switch]$RequireZero
    )

    $null = Assert-D01ExactPropertySet -Object $Evidence -Expected @(
        'schema', 'phase', 'control_trace_id_hex',
        'expected_control_trace_id_hex', 'logger_name',
        'logger_name_exact', 'log_file_name_sha256',
        'expected_log_file_name_sha256', 'log_file_name_exact',
        'control_trace_id_exact', 'query_by_id_identity_exact',
        'session_identity_sha256', 'session_identity_exact',
        'flush_error_code', 'flush_success', 'available', 'error_code',
        'events_lost', 'log_buffers_lost', 'realtime_buffers_lost',
        'buffers_lost', 'buffers_written',
        'session_stopped_by_control_trace', 'proved_zero',
        'error_sha256'
    ) -Context 'PktMon ETW loss evidence'
    foreach ($name in @(
        'schema', 'phase', 'control_trace_id_hex',
        'expected_control_trace_id_hex', 'logger_name',
        'log_file_name_sha256', 'expected_log_file_name_sha256',
        'session_identity_sha256', 'error_sha256'
    )) {
        $null = Assert-D01JsonStringValue `
            -Value $Evidence.PSObject.Properties[$name].Value `
            -Context "PktMon ETW loss evidence.$name"
    }
    foreach ($name in @(
        'logger_name_exact', 'log_file_name_exact',
        'control_trace_id_exact', 'query_by_id_identity_exact',
        'session_identity_exact', 'flush_success', 'available',
        'session_stopped_by_control_trace', 'proved_zero'
    )) {
        $null = Assert-D01JsonBoolean `
            -Value $Evidence.PSObject.Properties[$name].Value `
            -Context "PktMon ETW loss evidence.$name"
    }
    if ([string]$Evidence.schema -cne
            'ese.v91.d01-etw-final-loss/v3' -or
        [string]$Evidence.phase -cne $ExpectedPhase -or
        [string]$Evidence.control_trace_id_hex -cnotmatch
            '^[0-9a-f]{16}$' -or
        [string]$Evidence.expected_control_trace_id_hex -cne
            $ExpectedControlTraceIdHex -or
        ($ExpectedControlTraceIdHex -and
            [string]$Evidence.control_trace_id_hex -cne
                $ExpectedControlTraceIdHex) -or
        [string]$Evidence.logger_name -cne 'PktMon' -or
        [string]$Evidence.error_sha256 -cne '') {
        throw 'PktMon ETW loss evidence identity strings are not exact'
    }
    $expectedPath = [IO.Path]::GetFullPath(
        $ExpectedLogFilePath).ToLowerInvariant()
    $expectedPathHash = Get-LabStringSha256 -Value $expectedPath
    if ([string]$Evidence.log_file_name_sha256 -cne $expectedPathHash -or
        [string]$Evidence.expected_log_file_name_sha256 -cne
            $expectedPathHash) {
        throw 'PktMon ETW loss evidence is not bound to the expected ETL'
    }
    $identityProjection = [ordered]@{
        schema = 'ese.v91.d01-etw-session-identity/v1'
        control_trace_id_hex = [string]$Evidence.control_trace_id_hex
        logger_name = [string]$Evidence.logger_name
        log_file_name_sha256 = [string]$Evidence.log_file_name_sha256
    }
    $expectedIdentityHash = Get-LabStringSha256 -Value (
        $identityProjection | ConvertTo-Json -Depth 4 -Compress)
    if ([string]$Evidence.session_identity_sha256 -cne
            $expectedIdentityHash -or
        -not [bool]$Evidence.logger_name_exact -or
        -not [bool]$Evidence.log_file_name_exact -or
        -not [bool]$Evidence.control_trace_id_exact -or
        -not [bool]$Evidence.query_by_id_identity_exact -or
        -not [bool]$Evidence.session_identity_exact) {
        throw 'PktMon ETW loss evidence identity digest is not exact'
    }
    $numbers = @{}
    foreach ($name in @(
        'flush_error_code', 'error_code', 'events_lost',
        'log_buffers_lost', 'realtime_buffers_lost', 'buffers_lost',
        'buffers_written'
    )) {
        $value = $Evidence.PSObject.Properties[$name].Value
        if ($null -eq $value -or $value -isnot [int] -and
            $value -isnot [Int64] -and $value -isnot [UInt32] -and
            $value -isnot [UInt64]) {
            throw "PktMon ETW loss evidence.$name is not an exact integer"
        }
        try { $numbers[$name] = [UInt64]$value } catch {
            throw "PktMon ETW loss evidence.$name is outside UInt64"
        }
    }
    $buffersLostExact = [UInt64]$numbers.log_buffers_lost +
        [UInt64]$numbers.realtime_buffers_lost
    $computedZero = [UInt64]$numbers.flush_error_code -eq 0 -and
        [UInt64]$numbers.error_code -eq 0 -and
        [UInt64]$numbers.events_lost -eq 0 -and
        $buffersLostExact -eq 0
    if ([UInt64]$numbers.buffers_lost -ne $buffersLostExact -or
        [bool]$Evidence.flush_success -ne
            ([UInt64]$numbers.flush_error_code -eq 0) -or
        -not [bool]$Evidence.available -or
        [bool]$Evidence.proved_zero -ne $computedZero -or
        [bool]$Evidence.session_stopped_by_control_trace -ne
            [bool]$RequireStopped -or
        ($RequireStopped -and $ExpectedPhase -cne
            'post-final-flush-control-stop') -or
        (-not $RequireStopped -and $ExpectedPhase -cne
            'post-flush-live-query') -or
        ($RequireZero -and -not $computedZero)) {
        throw 'PktMon ETW loss/status arithmetic is not exact'
    }
    return $true
}

function Test-D01EtwSessionEvidenceChain {
    param([Parameter(Mandatory = $true)][object]$State)

    try {
        $null = Assert-D01EtwLossEvidenceContract `
            -Evidence $State.etw_session_identity `
            -ExpectedPhase 'post-flush-live-query' `
            -ExpectedLogFilePath ([string]$State.etl_path) -RequireZero
        $controlTraceIdHex =
            [string]$State.etw_session_identity.control_trace_id_hex
        foreach ($evidence in @(
            $State.etw_session_post_counter_identity,
            $State.etw_session_pre_stop_identity,
            $State.pktmon_driver_stop_pre_identity,
            $State.pktmon_driver_stop_post_identity
        )) {
            $null = Assert-D01EtwLossEvidenceContract `
                -Evidence $evidence `
                -ExpectedPhase 'post-flush-live-query' `
                -ExpectedLogFilePath ([string]$State.etl_path) `
                -ExpectedControlTraceIdHex $controlTraceIdHex
        }
        $null = Assert-D01EtwLossEvidenceContract `
            -Evidence $State.etw_loss `
            -ExpectedPhase 'post-final-flush-control-stop' `
            -ExpectedLogFilePath ([string]$State.etl_path) `
            -ExpectedControlTraceIdHex $controlTraceIdHex `
            -RequireStopped -RequireZero
        $identityHashes = @(
            [string]$State.etw_session_identity.session_identity_sha256,
            [string]$State.etw_session_post_counter_identity.
                session_identity_sha256,
            [string]$State.etw_session_pre_stop_identity.
                session_identity_sha256,
            [string]$State.pktmon_driver_stop_pre_identity.
                session_identity_sha256,
            [string]$State.pktmon_driver_stop_post_identity.
                session_identity_sha256,
            [string]$State.etw_loss.session_identity_sha256
        ) | Sort-Object -Unique
        return $identityHashes.Count -eq 1
    } catch { return $false }
}

function Get-D01PktmonCounterLossEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$Stdout,
        [AllowEmptyString()][string]$Stderr = '',
        [Parameter(Mandatory = $true)][int]$ExitCode,
        [Parameter(Mandatory = $true)][bool]$ProcessExited,
        [Parameter(Mandatory = $true)][bool]$OutputComplete,
        [string[]]$ExpectedComponentIds = @(),
        [AllowNull()][object]$ExpectedSnapshot = $null
    )

    $metricCount = 0
    $dropMetricCount = 0
    $nonzeroCount = 0
    $unexpectedReasonCount = 0
    $invalidCount = 0
    $groupCount = 0
    $componentCount = 0
    [string[]]$componentIds = @()
    $componentCoverageExact = $false
    $nativeSchema = ''
    $componentSchemaSha256 = ''
    $snapshotSha256 = ''
    $snapshotEqualToBaseline = $false
    $baselineSnapshotSha256 = ''
    $snapshotRows = [Collections.Generic.List[object]]::new()
    $schemaRows = [Collections.Generic.List[object]]::new()
    $errorText = ''
    try {
        if ($ExitCode -ne 0 -or -not $ProcessExited -or
            -not $OutputComplete -or
            [string]::IsNullOrWhiteSpace($Stdout) -or
            $Stdout.Length -gt 4194304 -or
            -not [string]::IsNullOrWhiteSpace($Stderr)) {
            throw 'PktMon JSON counters command was not clean and bounded'
        }
        $trimmedJson = $Stdout.Trim()
        if ($trimmedJson.Length -lt 2 -or $trimmedJson[0] -cne '[' -or
            $trimmedJson[$trimmedJson.Length - 1] -cne ']') {
            throw 'PktMon drop counters root is not the exact group array'
        }
        $parsedRoot = $Stdout | ConvertFrom-Json -ErrorAction Stop
        $groups = @($parsedRoot)
        if ($groups.Count -eq 0) {
            throw 'PktMon drop counters root has no groups'
        }
        $ids = [Collections.Generic.HashSet[string]]::new(
            [StringComparer]::Ordinal)
        $groupNames = [Collections.Generic.HashSet[string]]::new(
            [StringComparer]::Ordinal)
        foreach ($group in $groups) {
            $null = Assert-D01ExactPropertySet -Object $group `
                -Expected @('Group', 'Components') `
                -Context 'PktMon drop counters group'
            $groupName = Assert-D01JsonStringValue -Value $group.Group `
                -Context 'PktMon drop counters group.Group'
            if (-not $groupNames.Add([string]$groupName)) {
                throw 'PktMon drop counters repeat a group name'
            }
            if ($group.Components -isnot [Array] -or
                @($group.Components).Count -eq 0) {
                throw 'PktMon drop counters group has no component array'
            }
            $groupCount++
            foreach ($component in @($group.Components)) {
                $null = Assert-D01ExactPropertySet -Object $component `
                    -Expected @('Name', 'Id', 'Counters') `
                    -Context 'PktMon drop counter component'
                $shape = 'Counters,Id,Name'
                $id = Assert-D01JsonInteger -Value $component.Id `
                    -Context 'PktMon drop counters component.Id' -Minimum 0 `
                    -Maximum ([UInt32]::MaxValue)
                [string]$idText = $id.ToString(
                    [Globalization.CultureInfo]::InvariantCulture)
                if (-not $ids.Add($idText)) {
                    throw 'PktMon drop counters repeat a component Id'
                }
                $componentName = Assert-D01JsonStringValue `
                    -Value $component.Name `
                    -Context 'PktMon drop counters component.Name' `
                    -Pattern '^.+$'
                if ($component.Counters -isnot [Array] -or
                    @($component.Counters).Count -ne 1) {
                    throw 'PktMon component does not contain one drop counter'
                }
                $counter = @($component.Counters)[0]
                $null = Assert-D01ExactPropertySet -Object $counter `
                    -Expected @('Name', 'Type', 'Inbound', 'Outbound') `
                    -Context 'PktMon component drop counter'
                $counterName = Assert-D01JsonStringValue `
                    -Value $counter.Name `
                    -Context 'PktMon component drop counter.Name' `
                    -Pattern '^.+$'
                if ([string]$counterName -cne [string]$componentName) {
                    throw 'PktMon drop counter/component names are not identical'
                }
                $counterType = Assert-D01JsonStringValue `
                    -Value $counter.Type `
                    -Context 'PktMon component drop counter.Type' `
                    -Pattern '^Descartes$'
                if ([string]$counterType -cne 'Descartes') {
                    throw 'PktMon counter is not the audited es-ES drop counter'
                }
                $row = [ordered]@{
                    group = [string]$groupName
                    component_id = $idText
                    component_name = [string]$componentName
                    component_shape = $shape
                    counter_name = [string]$counterName
                    counter_type = [string]$counterType
                    inbound_shape = ''
                    inbound_direction_tag = ''
                    inbound_packets = [Int64]0
                    inbound_bytes = [Int64]0
                    inbound_last_drop_reason_sha256 = ''
                    outbound_shape = ''
                    outbound_direction_tag = ''
                    outbound_packets = [Int64]0
                    outbound_bytes = [Int64]0
                    outbound_last_drop_reason_sha256 = ''
                }
                foreach ($directionName in @('Inbound', 'Outbound')) {
                    $direction = $counter.PSObject.Properties[
                        $directionName].Value
                    [string[]]$directionNames =
                        @($direction.PSObject.Properties.Name)
                    [Array]::Sort($directionNames, [StringComparer]::Ordinal)
                    if (($directionNames -join ',') -cne
                        'Bytes,DirectionTag,Last Drop Reason,Packets') {
                        throw 'PktMon drop direction shape is not exact'
                    }
                    $directionKey = $directionName.ToLowerInvariant()
                    $row["${directionKey}_shape"] =
                        $directionNames -join ','
                    $directionTag = Assert-D01JsonStringValue `
                        -Value $direction.DirectionTag `
                        -Context "PktMon $directionName drop DirectionTag" `
                        -Pattern '^.+$'
                    $row["${directionKey}_direction_tag"] =
                        [string]$directionTag
                    foreach ($metricName in @('Packets', 'Bytes')) {
                        $metric = Assert-D01JsonInteger `
                            -Value $direction.PSObject.Properties[
                                $metricName].Value `
                            -Context (
                                "PktMon $directionName drop $metricName") `
                            -Minimum 0
                        $metricCount++
                        $dropMetricCount++
                        if ($metric -ne 0) { $nonzeroCount++ }
                        $metricKey = $metricName.ToLowerInvariant()
                        $row["${directionKey}_${metricKey}"] =
                            [Int64]$metric
                    }
                    $reason = Assert-D01JsonStringValue `
                        -Value $direction.PSObject.Properties[
                            'Last Drop Reason'].Value `
                        -Context "PktMon $directionName Last Drop Reason"
                    if ([string]$reason -cne 'No especificado') {
                        $unexpectedReasonCount++
                    }
                    $row["${directionKey}_last_drop_reason_sha256"] =
                        Get-LabStringSha256 -Value ([string]$reason)
                }
                $directionPair = '{0}|{1}' -f
                    $row.inbound_direction_tag, $row.outbound_direction_tag
                if ($directionPair -cnotin @(
                    'Entrada|Salida',
                    ('Recepci{0}n|Transmisi{0}n' -f [char]0x00f3))) {
                    throw 'PktMon drop direction tags are outside audited pairs'
                }
                $snapshotRows.Add([pscustomobject]$row)
                $schemaRows.Add([pscustomobject][ordered]@{
                    group = [string]$groupName
                    component_id = $idText
                    component_name = [string]$componentName
                    component_shape = $shape
                    counter_name = [string]$counterName
                    counter_type = [string]$counterType
                    inbound_shape = [string]$row.inbound_shape
                    inbound_direction_tag =
                        [string]$row.inbound_direction_tag
                    outbound_shape = [string]$row.outbound_shape
                    outbound_direction_tag =
                        [string]$row.outbound_direction_tag
                })
                $componentCount++
            }
        }
        $componentIds = @($ids | Sort-Object)
        [string[]]$expectedIds = @($ExpectedComponentIds |
            ForEach-Object { [string]$_ } | Sort-Object -Unique)
        $componentCoverageExact = $expectedIds.Count -eq 0 -or (
            $expectedIds.Count -eq $componentIds.Count -and
            (Compare-Object -ReferenceObject $expectedIds `
                -DifferenceObject $componentIds).Count -eq 0)
        if (-not $componentCoverageExact) {
            throw 'PktMon final drop counters omit or add captured components'
        }
        $orderedSchemaRows = @($schemaRows.ToArray() |
            Sort-Object component_id)
        $componentSchemaSha256 = Get-LabStringSha256 -Value (
            ([ordered]@{
                schema = 'groups-components-single-drop-counter-es-es/v3'
                rows = $orderedSchemaRows
            }) | ConvertTo-Json -Depth 8 -Compress)
        $nativeSchema =
            'groups-components-single-drop-counter-es-es/v3:' +
            $componentSchemaSha256
        $orderedSnapshotRows = @($snapshotRows.ToArray() |
            Sort-Object component_id)
        $snapshotSha256 = Get-LabStringSha256 -Value (
            ([ordered]@{
                schema = 'ese.v91.d01-pktmon-counter-snapshot/v2'
                rows = $orderedSnapshotRows
            }) | ConvertTo-Json -Depth 8 -Compress)
        if ($null -ne $ExpectedSnapshot) {
            if ([string]$ExpectedSnapshot.schema -cne
                    'ese.v91.d01-pktmon-counter-loss/v4' -or
                -not [bool]$ExpectedSnapshot.json_contract_valid -or
                [string]$ExpectedSnapshot.snapshot_sha256 -cnotmatch
                    '^[0-9a-f]{64}$' -or
                [string]$ExpectedSnapshot.component_schema_sha256 `
                    -cnotmatch '^[0-9a-f]{64}$') {
                throw 'PktMon expected counter snapshot contract is invalid'
            }
            $baselineSnapshotSha256 =
                [string]$ExpectedSnapshot.snapshot_sha256
            $snapshotEqualToBaseline =
                $snapshotSha256 -ceq $baselineSnapshotSha256 -and
                $componentSchemaSha256 -ceq
                    [string]$ExpectedSnapshot.component_schema_sha256
        }
    } catch { $errorText = $_.Exception.Message }
    $valid = [string]::IsNullOrEmpty($errorText)
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.d01-pktmon-counter-loss/v4'
        command_exit_code = $ExitCode
        process_exited = $ProcessExited
        output_complete = $OutputComplete
        command_contract =
            'counters --type drop --include-hidden --zero --json;read-only'
        json_contract_valid = $valid
        native_schema = $nativeSchema
        component_schema_sha256 = $componentSchemaSha256
        group_count = $groupCount
        component_count = $componentCount
        component_ids = $componentIds
        component_coverage_exact = $componentCoverageExact
        loss_metric_count = $metricCount
        drop_metric_count = $dropMetricCount
        nonzero_loss_metric_count = $nonzeroCount
        unexpected_drop_reason_count = $unexpectedReasonCount
        invalid_loss_metric_count = $invalidCount
        snapshot_rows = @($snapshotRows.ToArray() | Sort-Object component_id)
        snapshot_sha256 = $snapshotSha256
        baseline_snapshot_sha256 = $baselineSnapshotSha256
        snapshot_equal_to_baseline = $snapshotEqualToBaseline
        proved_all_zero = $valid -and $groupCount -gt 0 -and
            $componentCount -gt 0 -and
            $metricCount -eq ($componentCount * 4) -and
            $nonzeroCount -eq 0 -and $unexpectedReasonCount -eq 0
        proved_no_counter_change = $valid -and
            $null -ne $ExpectedSnapshot -and $snapshotEqualToBaseline -and
            $groupCount -gt 0 -and
            $componentCount -gt 0 -and $componentCoverageExact -and
            $metricCount -eq ($componentCount * 4) -and
            $dropMetricCount -gt 0 -and
            $invalidCount -eq 0
        stdout_sha256 = Get-LabStringSha256 -Value $Stdout
        stderr_sha256 = if ([string]::IsNullOrEmpty($Stderr)) {
            ''
        } else { Get-LabStringSha256 -Value $Stderr }
        error_sha256 = if ($errorText) {
            Get-LabStringSha256 -Value $errorText
        } else { '' }
    }
}

function Assert-D01PktmonCounterSnapshotContract {
    param(
        [Parameter(Mandatory = $true)][object]$Evidence,
        [AllowNull()][object]$ExpectedBaseline = $null,
        [switch]$RequireAllZero,
        [switch]$RequireUnchanged
    )

    $null = Assert-D01ExactPropertySet -Object $Evidence -Expected @(
        'schema', 'command_exit_code', 'process_exited', 'output_complete',
        'command_contract',
        'json_contract_valid', 'native_schema',
        'component_schema_sha256', 'group_count', 'component_count',
        'component_ids', 'component_coverage_exact', 'loss_metric_count',
        'drop_metric_count', 'nonzero_loss_metric_count',
        'unexpected_drop_reason_count',
        'invalid_loss_metric_count', 'snapshot_rows', 'snapshot_sha256',
        'baseline_snapshot_sha256', 'snapshot_equal_to_baseline',
        'proved_all_zero', 'proved_no_counter_change',
        'stdout_sha256', 'stderr_sha256',
        'error_sha256'
    ) -Context 'PktMon counter snapshot evidence'
    foreach ($name in @(
        'schema', 'command_contract', 'native_schema',
        'component_schema_sha256', 'snapshot_sha256',
        'baseline_snapshot_sha256', 'stdout_sha256', 'stderr_sha256',
        'error_sha256'
    )) {
        $null = Assert-D01JsonStringValue `
            -Value $Evidence.PSObject.Properties[$name].Value `
            -Context "PktMon counter snapshot evidence.$name"
    }
    foreach ($name in @(
        'process_exited', 'output_complete', 'json_contract_valid',
        'component_coverage_exact', 'snapshot_equal_to_baseline',
        'proved_all_zero', 'proved_no_counter_change'
    )) {
        $null = Assert-D01JsonBoolean `
            -Value $Evidence.PSObject.Properties[$name].Value `
            -Context "PktMon counter snapshot evidence.$name"
    }
    if ([string]$Evidence.schema -cne
            'ese.v91.d01-pktmon-counter-loss/v4' -or
        [string]$Evidence.command_contract -cne
            'counters --type drop --include-hidden --zero --json;read-only' -or
        -not [bool]$Evidence.process_exited -or
        -not [bool]$Evidence.output_complete -or
        -not [bool]$Evidence.json_contract_valid -or
        -not [bool]$Evidence.component_coverage_exact -or
        [string]$Evidence.component_schema_sha256 -cnotmatch
            '^[0-9a-f]{64}$' -or
        [string]$Evidence.snapshot_sha256 -cnotmatch
            '^[0-9a-f]{64}$' -or
        [string]$Evidence.stdout_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$Evidence.stderr_sha256 -cne '' -or
        [string]$Evidence.error_sha256 -cne '') {
        throw 'PktMon counter snapshot envelope is not exact'
    }
    foreach ($name in @(
        'command_exit_code', 'group_count', 'component_count',
        'loss_metric_count', 'drop_metric_count',
        'nonzero_loss_metric_count', 'unexpected_drop_reason_count',
        'invalid_loss_metric_count'
    )) {
        $null = Assert-D01JsonInteger `
            -Value $Evidence.PSObject.Properties[$name].Value `
            -Context "PktMon counter snapshot evidence.$name" -Minimum 0
    }
    if ([int]$Evidence.command_exit_code -ne 0 -or
        [int]$Evidence.invalid_loss_metric_count -ne 0 -or
        $Evidence.snapshot_rows -isnot [Array]) {
        throw 'PktMon counter snapshot result/status is not exact'
    }
    $componentIds = Assert-D01JsonStringArray `
        -Value $Evidence.component_ids `
        -Context 'PktMon counter snapshot component_ids' -RequireUnique
    $orderedRows = @($Evidence.snapshot_rows | Sort-Object component_id)
    $rowIds = [Collections.Generic.List[string]]::new()
    $schemaRows = [Collections.Generic.List[object]]::new()
    $groupNames = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal)
    $computedNonzero = 0
    $computedUnexpectedReason = 0
    $noDropReasonSha256 = Get-LabStringSha256 -Value 'No especificado'
    foreach ($row in $orderedRows) {
        $null = Assert-D01ExactPropertySet -Object $row -Expected @(
            'group', 'component_id', 'component_name', 'component_shape',
            'counter_name', 'counter_type', 'inbound_shape',
            'inbound_direction_tag', 'inbound_packets', 'inbound_bytes',
            'inbound_last_drop_reason_sha256', 'outbound_shape',
            'outbound_direction_tag', 'outbound_packets', 'outbound_bytes',
            'outbound_last_drop_reason_sha256'
        ) -Context 'PktMon counter snapshot row'
        foreach ($name in @(
            'group', 'component_id', 'component_name', 'component_shape',
            'counter_name', 'counter_type', 'inbound_shape',
            'inbound_direction_tag', 'inbound_last_drop_reason_sha256',
            'outbound_shape', 'outbound_direction_tag',
            'outbound_last_drop_reason_sha256'
        )) {
            $null = Assert-D01JsonStringValue `
                -Value $row.PSObject.Properties[$name].Value `
                -Context "PktMon counter snapshot row.$name"
        }
        if ([string]$row.component_id -cnotmatch '^\d+$' -or
            [string]::IsNullOrEmpty([string]$row.component_name) -or
            [string]$row.component_shape -cne 'Counters,Id,Name' -or
            [string]::IsNullOrEmpty([string]$row.counter_name) -or
            [string]$row.counter_name -cne [string]$row.component_name -or
            [string]$row.counter_type -cne 'Descartes' -or
            [string]$row.inbound_shape -cne
                'Bytes,DirectionTag,Last Drop Reason,Packets' -or
            [string]::IsNullOrEmpty([string]$row.inbound_direction_tag) -or
            [string]$row.outbound_shape -cne
                'Bytes,DirectionTag,Last Drop Reason,Packets' -or
            [string]::IsNullOrEmpty([string]$row.outbound_direction_tag) -or
            ('{0}|{1}' -f $row.inbound_direction_tag,
                $row.outbound_direction_tag) -cnotin @(
                    'Entrada|Salida',
                    ('Recepci{0}n|Transmisi{0}n' -f [char]0x00f3)) -or
            [string]$row.inbound_last_drop_reason_sha256 -cnotmatch
                '^[0-9a-f]{64}$' -or
            [string]$row.outbound_last_drop_reason_sha256 -cnotmatch
                '^[0-9a-f]{64}$') {
            throw 'PktMon counter snapshot row schema is not exact'
        }
        $rowIds.Add([string]$row.component_id)
        $null = $groupNames.Add([string]$row.group)
        foreach ($name in @(
            'inbound_packets', 'inbound_bytes',
            'outbound_packets', 'outbound_bytes'
        )) {
            $value = Assert-D01JsonInteger `
                -Value $row.PSObject.Properties[$name].Value `
                -Context "PktMon counter snapshot row.$name" -Minimum 0
            if ($value -ne 0) { $computedNonzero++ }
        }
        foreach ($name in @(
            'inbound_last_drop_reason_sha256',
            'outbound_last_drop_reason_sha256'
        )) {
            if ([string]$row.PSObject.Properties[$name].Value -cne
                $noDropReasonSha256) { $computedUnexpectedReason++ }
        }
        $schemaRows.Add([pscustomobject][ordered]@{
            group = [string]$row.group
            component_id = [string]$row.component_id
            component_name = [string]$row.component_name
            component_shape = [string]$row.component_shape
            counter_name = [string]$row.counter_name
            counter_type = [string]$row.counter_type
            inbound_shape = [string]$row.inbound_shape
            inbound_direction_tag = [string]$row.inbound_direction_tag
            outbound_shape = [string]$row.outbound_shape
            outbound_direction_tag = [string]$row.outbound_direction_tag
        })
    }
    [string[]]$sortedIds = @($rowIds.ToArray() | Sort-Object -Unique)
    [string[]]$declaredIds = @($componentIds | Sort-Object -Unique)
    if ($orderedRows.Count -eq 0 -or
        $orderedRows.Count -ne $sortedIds.Count -or
        ($sortedIds -join "`n") -cne ($declaredIds -join "`n") -or
        [int]$Evidence.component_count -ne $orderedRows.Count -or
        [int]$Evidence.group_count -ne $groupNames.Count -or
        [int]$Evidence.loss_metric_count -ne ($orderedRows.Count * 4) -or
        [int]$Evidence.drop_metric_count -ne ($orderedRows.Count * 4) -or
        [int]$Evidence.nonzero_loss_metric_count -ne $computedNonzero -or
        [int]$Evidence.unexpected_drop_reason_count -ne
            $computedUnexpectedReason -or
        [bool]$Evidence.proved_all_zero -ne (
            $computedNonzero -eq 0 -and $computedUnexpectedReason -eq 0) -or
        ($RequireAllZero -and -not [bool]$Evidence.proved_all_zero)) {
        throw 'PktMon counter snapshot counts/coverage are not exact'
    }
    $expectedSchemaHash = Get-LabStringSha256 -Value (
        ([ordered]@{
            schema = 'groups-components-single-drop-counter-es-es/v3'
            rows = @($schemaRows.ToArray() | Sort-Object component_id)
        }) | ConvertTo-Json -Depth 8 -Compress)
    $expectedSnapshotHash = Get-LabStringSha256 -Value (
        ([ordered]@{
            schema = 'ese.v91.d01-pktmon-counter-snapshot/v2'
            rows = $orderedRows
        }) | ConvertTo-Json -Depth 8 -Compress)
    if ([string]$Evidence.component_schema_sha256 -cne
            $expectedSchemaHash -or
        [string]$Evidence.native_schema -cne
            ('groups-components-single-drop-counter-es-es/v3:' +
                $expectedSchemaHash) -or
        [string]$Evidence.snapshot_sha256 -cne $expectedSnapshotHash) {
        throw 'PktMon counter snapshot digest is not exact'
    }
    if ($null -eq $ExpectedBaseline) {
        if ([string]$Evidence.baseline_snapshot_sha256 -cne '' -or
            [bool]$Evidence.snapshot_equal_to_baseline -or
            [bool]$Evidence.proved_no_counter_change) {
            throw 'PktMon baseline snapshot claims a final comparison'
        }
    } else {
        $null = Assert-D01PktmonCounterSnapshotContract `
            -Evidence $ExpectedBaseline -RequireAllZero
        [string[]]$baselineIds = @(
            $ExpectedBaseline.component_ids | ForEach-Object { [string]$_ } |
                Sort-Object -Unique)
        $coverageEqual = ($declaredIds -join "`n") -ceq
            ($baselineIds -join "`n")
        $schemaEqual = [string]$Evidence.component_schema_sha256 -ceq
            [string]$ExpectedBaseline.component_schema_sha256
        $equal = $coverageEqual -and $schemaEqual -and
            [string]$Evidence.snapshot_sha256 -ceq
                [string]$ExpectedBaseline.snapshot_sha256
        if ([string]$Evidence.baseline_snapshot_sha256 -cne
                [string]$ExpectedBaseline.snapshot_sha256 -or
            -not $coverageEqual -or -not $schemaEqual -or
            [bool]$Evidence.snapshot_equal_to_baseline -ne $equal -or
            [bool]$Evidence.proved_no_counter_change -ne $equal -or
            ($RequireUnchanged -and -not $equal)) {
            throw 'PktMon final counter snapshot changed from baseline'
        }
    }
    return $true
}

function Test-D01PktmonCounterEvidenceChain {
    param([Parameter(Mandatory = $true)][object]$State)

    try {
        $null = Assert-D01PktmonCounterSnapshotContract `
            -Evidence $State.counter_baseline -RequireAllZero
        $null = Assert-D01PktmonCounterSnapshotContract `
            -Evidence $State.counter_loss `
            -ExpectedBaseline $State.counter_baseline -RequireUnchanged
        return $true
    } catch { return $false }
}

function Get-D01PktmonAllCounterSnapshotEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$Stdout,
        [AllowEmptyString()][string]$Stderr = '',
        [Parameter(Mandatory = $true)][int]$ExitCode,
        [Parameter(Mandatory = $true)][bool]$ProcessExited,
        [Parameter(Mandatory = $true)][bool]$OutputComplete,
        [AllowNull()][object]$ExpectedBaseline = $null
    )

    $groupCount = 0
    $componentCount = 0
    $counterCount = 0
    $metricCount = 0
    $nonzeroMetricCount = 0
    $unexpectedDropReasonCount = 0
    $nativeSchemaSha256 = ''
    $snapshotSha256 = ''
    $baselineSnapshotSha256 = ''
    $snapshotEqualToBaseline = $false
    $counterCoverageExact = $false
    [string[]]$counterKeys = @()
    $snapshotRows = [Collections.Generic.List[object]]::new()
    $schemaRows = [Collections.Generic.List[object]]::new()
    $errorText = ''
    try {
        if ($ExitCode -ne 0 -or -not $ProcessExited -or
            -not $OutputComplete -or
            [string]::IsNullOrWhiteSpace($Stdout) -or
            $Stdout.Length -gt 4194304 -or
            -not [string]::IsNullOrWhiteSpace($Stderr)) {
            throw 'PktMon all-counter command was not clean, exited and bounded'
        }
        $trimmedJson = $Stdout.Trim()
        if ($trimmedJson.Length -lt 2 -or $trimmedJson[0] -cne '[' -or
            $trimmedJson[$trimmedJson.Length - 1] -cne ']') {
            throw 'PktMon all-counter root is not the exact nonempty array'
        }
        $parsedRoot = $Stdout | ConvertFrom-Json -ErrorAction Stop
        $root = @($parsedRoot)
        if ($root.Count -eq 0) {
            throw 'PktMon all-counter root has no groups'
        }
        $groupNames = [Collections.Generic.HashSet[string]]::new(
            [StringComparer]::Ordinal)
        $componentKeys = [Collections.Generic.HashSet[string]]::new(
            [StringComparer]::Ordinal)
        $counterKeySet = [Collections.Generic.HashSet[string]]::new(
            [StringComparer]::Ordinal)
        foreach ($group in $root) {
            $null = Assert-D01ExactPropertySet -Object $group `
                -Expected @('Group', 'Components') `
                -Context 'PktMon all-counter group'
            $groupName = Assert-D01JsonStringValue -Value $group.Group `
                -Context 'PktMon all-counter group.Group' `
                -Pattern '^[^\x00-\x1f]+$'
            if (-not $groupNames.Add([string]$groupName)) {
                throw 'PktMon all-counter group name is repeated'
            }
            if ($group.Components -isnot [Array] -or
                @($group.Components).Count -eq 0) {
                throw 'PktMon all-counter group has no exact component array'
            }
            $groupCount++
            foreach ($component in @($group.Components)) {
                $null = Assert-D01ExactPropertySet -Object $component `
                    -Expected @('Name', 'Id', 'Counters') `
                    -Context 'PktMon all-counter component'
                $componentName = Assert-D01JsonStringValue `
                    -Value $component.Name `
                    -Context 'PktMon all-counter component.Name' `
                    -Pattern '^[^\x00-\x1f]+$'
                $componentId = Assert-D01JsonInteger -Value $component.Id `
                    -Context 'PktMon all-counter component.Id' -Minimum 0 `
                    -Maximum ([UInt32]::MaxValue)
                $componentIdText = $componentId.ToString(
                    [Globalization.CultureInfo]::InvariantCulture)
                $componentKey = '{0}\u001f{1}\u001f{2}' -f
                    $groupName, $componentName, $componentIdText
                if (-not $componentKeys.Add($componentKey)) {
                    throw 'PktMon all-counter component tuple is repeated'
                }
                if ($component.Counters -isnot [Array] -or
                    @($component.Counters).Count -eq 0) {
                    throw 'PktMon all-counter component has no counter array'
                }
                $componentCount++
                foreach ($counter in @($component.Counters)) {
                    $null = Assert-D01ExactPropertySet -Object $counter `
                        -Expected @('Name', 'Type', 'Inbound', 'Outbound') `
                        -Context 'PktMon all-counter counter'
                    $counterName = Assert-D01JsonStringValue `
                        -Value $counter.Name `
                        -Context 'PktMon all-counter counter.Name' `
                        -Pattern '^[^\x00-\x1f]+$'
                    $counterType = Assert-D01JsonStringValue `
                        -Value $counter.Type `
                        -Context 'PktMon all-counter counter.Type' `
                        -Pattern '^(?:Descartes|Flujos)$'
                    if ($counterType -ceq 'Descartes' -and
                        $counterName -cne $componentName) {
                        throw (
                            'PktMon all-counter drop counter name does not ' +
                            'match its component name')
                    }
                    $counterKey = '{0}\u001f{1}\u001f{2}\u001f{3}\u001f{4}' -f
                        $groupName, $componentName, $componentIdText,
                        $counterName, $counterType
                    if (-not $counterKeySet.Add($counterKey)) {
                        throw 'PktMon all-counter identity tuple is repeated'
                    }
                    $row = [ordered]@{
                        group = [string]$groupName
                        component_name = [string]$componentName
                        component_id = [string]$componentIdText
                        counter_name = [string]$counterName
                        counter_type = [string]$counterType
                        inbound_shape = ''
                        inbound_direction_tag = ''
                        inbound_packets = [Int64]0
                        inbound_bytes = [Int64]0
                        inbound_last_drop_reason_sha256 = ''
                        outbound_shape = ''
                        outbound_direction_tag = ''
                        outbound_packets = [Int64]0
                        outbound_bytes = [Int64]0
                        outbound_last_drop_reason_sha256 = ''
                        has_last_drop_reason = $false
                        counter_key = $counterKey
                    }
                    $reasonPresence = [Collections.Generic.List[bool]]::new()
                    foreach ($directionName in @('Inbound', 'Outbound')) {
                        $direction = $counter.PSObject.Properties[
                            $directionName].Value
                        [string[]]$directionNames =
                            @($direction.PSObject.Properties.Name)
                        [Array]::Sort($directionNames, [StringComparer]::Ordinal)
                        $directionShape = $directionNames -join ','
                        if ($directionShape -cnotin @(
                            'Bytes,DirectionTag,Packets',
                            'Bytes,DirectionTag,Last Drop Reason,Packets')) {
                            throw 'PktMon all-counter direction shape is not exact'
                        }
                        $hasReason = $directionNames -contains
                            'Last Drop Reason'
                        $reasonPresence.Add($hasReason)
                        $directionKey = $directionName.ToLowerInvariant()
                        $row["${directionKey}_shape"] = $directionShape
                        $directionTag = Assert-D01JsonStringValue `
                            -Value $direction.DirectionTag `
                            -Context "PktMon all-counter $directionName.DirectionTag" `
                            -Pattern '^[^\x00-\x1f]+$'
                        $row["${directionKey}_direction_tag"] =
                            [string]$directionTag
                        foreach ($metricName in @('Packets', 'Bytes')) {
                            $metric = Assert-D01JsonInteger `
                                -Value $direction.PSObject.Properties[
                                    $metricName].Value `
                                -Context (
                                    "PktMon all-counter $directionName.$metricName") `
                                -Minimum 0
                            $metricCount++
                            if ($metric -ne 0) { $nonzeroMetricCount++ }
                            $row["${directionKey}_$($metricName.ToLowerInvariant())"] =
                                [Int64]$metric
                        }
                        if ($hasReason) {
                            $reason = Assert-D01JsonStringValue `
                                -Value $direction.PSObject.Properties[
                                    'Last Drop Reason'].Value `
                                -Context (
                                    "PktMon all-counter $directionName Last Drop Reason")
                            if ([string]$reason -cne 'No especificado') {
                                $unexpectedDropReasonCount++
                            }
                            $row["${directionKey}_last_drop_reason_sha256"] =
                                Get-LabStringSha256 -Value ([string]$reason)
                        }
                    }
                    if ($reasonPresence.Count -ne 2 -or
                        [bool]$reasonPresence[0] -ne [bool]$reasonPresence[1]) {
                        throw 'PktMon all-counter drop-reason presence is not bilateral'
                    }
                    if ([bool]$reasonPresence[0] -ne
                        ([string]$counterType -ceq 'Descartes')) {
                        throw 'PktMon all-counter drop-reason/type mapping is not exact'
                    }
                    $directionPair = '{0}|{1}' -f
                        $row.inbound_direction_tag,
                        $row.outbound_direction_tag
                    if ($directionPair -cnotin @(
                        'Entrada|Salida',
                        ('Recepci{0}n|Transmisi{0}n' -f [char]0x00f3))) {
                        throw 'PktMon all-counter direction tags are outside audited pairs'
                    }
                    $row.has_last_drop_reason = [bool]$reasonPresence[0]
                    $snapshotRows.Add([pscustomobject]$row)
                    $schemaRows.Add([pscustomobject][ordered]@{
                        group = [string]$groupName
                        component_name = [string]$componentName
                        component_id = [string]$componentIdText
                        counter_name = [string]$counterName
                        counter_type = [string]$counterType
                        inbound_shape = [string]$row.inbound_shape
                        inbound_direction_tag =
                            [string]$row.inbound_direction_tag
                        outbound_shape = [string]$row.outbound_shape
                        outbound_direction_tag =
                            [string]$row.outbound_direction_tag
                        has_last_drop_reason =
                            [bool]$row.has_last_drop_reason
                        counter_key = $counterKey
                    })
                    $counterCount++
                }
            }
        }
        $orderedRows = @($snapshotRows.ToArray() | Sort-Object counter_key)
        $orderedSchemaRows = @($schemaRows.ToArray() | Sort-Object counter_key)
        $counterKeys = @($counterKeySet | Sort-Object)
        $nativeSchemaSha256 = Get-LabStringSha256 -Value (
            ([ordered]@{
                schema = 'pktmon-all-counter-native-es-es/v1'
                rows = $orderedSchemaRows
            }) | ConvertTo-Json -Depth 10 -Compress)
        $snapshotSha256 = Get-LabStringSha256 -Value (
            ([ordered]@{
                schema = 'ese.v91.d01-pktmon-all-counter-canonical/v1'
                rows = $orderedRows
            }) | ConvertTo-Json -Depth 10 -Compress)
        if ($null -eq $ExpectedBaseline) {
            $counterCoverageExact = $true
        } else {
            if ([string]$ExpectedBaseline.schema -cne
                    'ese.v91.d01-pktmon-all-counter-snapshot/v1' -or
                -not [bool]$ExpectedBaseline.json_contract_valid -or
                -not [bool]$ExpectedBaseline.proved_all_zero -or
                [string]$ExpectedBaseline.snapshot_sha256 -cnotmatch
                    '^[0-9a-f]{64}$' -or
                [string]$ExpectedBaseline.native_schema_sha256 -cnotmatch
                    '^[0-9a-f]{64}$') {
                throw 'PktMon expected all-counter baseline is invalid'
            }
            [string[]]$expectedKeys = @(
                $ExpectedBaseline.counter_keys | ForEach-Object { [string]$_ } |
                    Sort-Object -Unique)
            $counterCoverageExact = $expectedKeys.Count -eq $counterKeys.Count -and
                ($expectedKeys -join "`n") -ceq ($counterKeys -join "`n")
            if (-not $counterCoverageExact) {
                throw 'PktMon all-counter coverage changed from baseline'
            }
            $baselineSnapshotSha256 =
                [string]$ExpectedBaseline.snapshot_sha256
            $snapshotEqualToBaseline =
                $snapshotSha256 -ceq $baselineSnapshotSha256 -and
                $nativeSchemaSha256 -ceq
                    [string]$ExpectedBaseline.native_schema_sha256
        }
    } catch { $errorText = $_.Exception.Message }
    $valid = [string]::IsNullOrEmpty($errorText)
    $allZero = $valid -and $groupCount -gt 0 -and
        $componentCount -gt 0 -and $counterCount -gt 0 -and
        $metricCount -eq ($counterCount * 4) -and
        $nonzeroMetricCount -eq 0
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.d01-pktmon-all-counter-snapshot/v1'
        command_exit_code = $ExitCode
        process_exited = $ProcessExited
        output_complete = $OutputComplete
        command_contract =
            'counters --type all --include-hidden --zero --json;read-only'
        json_contract_valid = $valid
        native_schema_sha256 = $nativeSchemaSha256
        group_count = $groupCount
        component_count = $componentCount
        counter_count = $counterCount
        metric_count = $metricCount
        nonzero_metric_count = $nonzeroMetricCount
        unexpected_drop_reason_count = $unexpectedDropReasonCount
        counter_keys = $counterKeys
        counter_coverage_exact = $counterCoverageExact
        snapshot_rows = @($snapshotRows.ToArray() | Sort-Object counter_key)
        snapshot_sha256 = $snapshotSha256
        baseline_snapshot_sha256 = $baselineSnapshotSha256
        snapshot_equal_to_baseline = $snapshotEqualToBaseline
        proved_all_zero = $allZero -and $unexpectedDropReasonCount -eq 0
        proved_restored = $allZero -and $null -ne $ExpectedBaseline -and
            $unexpectedDropReasonCount -eq 0 -and
            $counterCoverageExact -and $snapshotEqualToBaseline
        stdout_sha256 = Get-LabStringSha256 -Value $Stdout
        stderr_sha256 = if ([string]::IsNullOrEmpty($Stderr)) {
            ''
        } else { Get-LabStringSha256 -Value $Stderr }
        error_sha256 = if ($errorText) {
            Get-LabStringSha256 -Value $errorText
        } else { '' }
    }
}

function Assert-D01PktmonAllCounterSnapshotContract {
    param(
        [Parameter(Mandatory = $true)][object]$Evidence,
        [AllowNull()][object]$ExpectedBaseline = $null,
        [switch]$RequireAllZero,
        [switch]$RequireRestored
    )

    $null = Assert-D01ExactPropertySet -Object $Evidence -Expected @(
        'schema', 'command_exit_code', 'process_exited', 'output_complete',
        'command_contract', 'json_contract_valid', 'native_schema_sha256',
        'group_count', 'component_count', 'counter_count', 'metric_count',
        'nonzero_metric_count', 'unexpected_drop_reason_count',
        'counter_keys', 'counter_coverage_exact',
        'snapshot_rows', 'snapshot_sha256', 'baseline_snapshot_sha256',
        'snapshot_equal_to_baseline', 'proved_all_zero', 'proved_restored',
        'stdout_sha256', 'stderr_sha256', 'error_sha256'
    ) -Context 'PktMon all-counter snapshot evidence'
    foreach ($name in @(
        'process_exited', 'output_complete', 'json_contract_valid',
        'counter_coverage_exact', 'snapshot_equal_to_baseline',
        'proved_all_zero', 'proved_restored'
    )) {
        $null = Assert-D01JsonBoolean `
            -Value $Evidence.PSObject.Properties[$name].Value `
            -Context "PktMon all-counter snapshot evidence.$name"
    }
    foreach ($name in @(
        'schema', 'command_contract', 'native_schema_sha256',
        'snapshot_sha256', 'baseline_snapshot_sha256', 'stdout_sha256',
        'stderr_sha256', 'error_sha256'
    )) {
        $null = Assert-D01JsonStringValue `
            -Value $Evidence.PSObject.Properties[$name].Value `
            -Context "PktMon all-counter snapshot evidence.$name"
    }
    foreach ($name in @(
        'command_exit_code', 'group_count', 'component_count', 'counter_count',
        'metric_count', 'nonzero_metric_count',
        'unexpected_drop_reason_count'
    )) {
        $null = Assert-D01JsonInteger `
            -Value $Evidence.PSObject.Properties[$name].Value `
            -Context "PktMon all-counter snapshot evidence.$name" -Minimum 0
    }
    if ([string]$Evidence.schema -cne
            'ese.v91.d01-pktmon-all-counter-snapshot/v1' -or
        [string]$Evidence.command_contract -cne
            'counters --type all --include-hidden --zero --json;read-only' -or
        [int]$Evidence.command_exit_code -ne 0 -or
        -not [bool]$Evidence.process_exited -or
        -not [bool]$Evidence.output_complete -or
        -not [bool]$Evidence.json_contract_valid -or
        -not [bool]$Evidence.counter_coverage_exact -or
        [string]$Evidence.native_schema_sha256 -cnotmatch
            '^[0-9a-f]{64}$' -or
        [string]$Evidence.snapshot_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$Evidence.stdout_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$Evidence.stderr_sha256 -cne '' -or
        [string]$Evidence.error_sha256 -cne '' -or
        $Evidence.snapshot_rows -isnot [Array]) {
        throw 'PktMon all-counter snapshot envelope is not exact and zero'
    }
    $declaredKeys = Assert-D01JsonStringArray -Value $Evidence.counter_keys `
        -Context 'PktMon all-counter snapshot counter_keys' -RequireUnique
    $rows = @($Evidence.snapshot_rows | Sort-Object counter_key)
    $rowKeys = [Collections.Generic.List[string]]::new()
    $groupNames = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal)
    $componentKeys = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal)
    $schemaRows = [Collections.Generic.List[object]]::new()
    $computedNonzero = 0
    $computedUnexpectedReason = 0
    $noDropReasonSha256 = Get-LabStringSha256 -Value 'No especificado'
    foreach ($row in $rows) {
        $null = Assert-D01ExactPropertySet -Object $row -Expected @(
            'group', 'component_name', 'component_id', 'counter_name',
            'counter_type', 'inbound_shape', 'inbound_direction_tag',
            'inbound_packets', 'inbound_bytes',
            'inbound_last_drop_reason_sha256', 'outbound_shape',
            'outbound_direction_tag', 'outbound_packets', 'outbound_bytes',
            'outbound_last_drop_reason_sha256', 'has_last_drop_reason',
            'counter_key'
        ) -Context 'PktMon all-counter snapshot row'
        foreach ($name in @(
            'group', 'component_name', 'component_id', 'counter_name',
            'counter_type', 'inbound_shape', 'inbound_direction_tag',
            'inbound_last_drop_reason_sha256', 'outbound_shape',
            'outbound_direction_tag', 'outbound_last_drop_reason_sha256',
            'counter_key'
        )) {
            $null = Assert-D01JsonStringValue `
                -Value $row.PSObject.Properties[$name].Value `
                -Context "PktMon all-counter snapshot row.$name"
        }
        $hasReason = Assert-D01JsonBoolean -Value $row.has_last_drop_reason `
            -Context 'PktMon all-counter snapshot row.has_last_drop_reason'
        $expectedKey = '{0}\u001f{1}\u001f{2}\u001f{3}\u001f{4}' -f
            $row.group, $row.component_name, $row.component_id,
            $row.counter_name, $row.counter_type
        if ([string]$row.component_id -cnotmatch '^\d+$' -or
            [string]$row.counter_key -cne $expectedKey -or
            [string]::IsNullOrWhiteSpace([string]$row.group) -or
            [string]::IsNullOrWhiteSpace([string]$row.component_name) -or
            [string]::IsNullOrWhiteSpace([string]$row.counter_name) -or
            [string]$row.counter_type -cnotin @(
                'Descartes', 'Flujos') -or
            ([string]$row.counter_type -ceq 'Descartes' -and
                [string]$row.counter_name -cne
                    [string]$row.component_name) -or
            [string]::IsNullOrWhiteSpace(
                [string]$row.inbound_direction_tag) -or
            [string]::IsNullOrWhiteSpace(
                [string]$row.outbound_direction_tag) -or
            ('{0}|{1}' -f $row.inbound_direction_tag,
                $row.outbound_direction_tag) -cnotin @(
                    'Entrada|Salida',
                    ('Recepci{0}n|Transmisi{0}n' -f [char]0x00f3))) {
            throw 'PktMon all-counter snapshot row identity is not exact'
        }
        $shapeWithoutReason = 'Bytes,DirectionTag,Packets'
        $shapeWithReason =
            'Bytes,DirectionTag,Last Drop Reason,Packets'
        $expectedShape = if ($hasReason) {
            $shapeWithReason
        } else { $shapeWithoutReason }
        if ([string]$row.inbound_shape -cne $expectedShape -or
            [string]$row.outbound_shape -cne $expectedShape -or
            $hasReason -ne ([string]$row.counter_type -ceq 'Descartes') -or
            ($hasReason -and (
                [string]$row.inbound_last_drop_reason_sha256 -cnotmatch
                    '^[0-9a-f]{64}$' -or
                [string]$row.outbound_last_drop_reason_sha256 -cnotmatch
                    '^[0-9a-f]{64}$')) -or
            (-not $hasReason -and (
                [string]$row.inbound_last_drop_reason_sha256 -cne '' -or
                [string]$row.outbound_last_drop_reason_sha256 -cne ''))) {
            throw 'PktMon all-counter snapshot row direction shape is not exact'
        }
        foreach ($name in @(
            'inbound_packets', 'inbound_bytes',
            'outbound_packets', 'outbound_bytes'
        )) {
            $metric = Assert-D01JsonInteger `
                -Value $row.PSObject.Properties[$name].Value `
                -Context "PktMon all-counter snapshot row.$name" -Minimum 0
            if ($metric -ne 0) { $computedNonzero++ }
        }
        if ($hasReason) {
            foreach ($name in @(
                'inbound_last_drop_reason_sha256',
                'outbound_last_drop_reason_sha256'
            )) {
                if ([string]$row.PSObject.Properties[$name].Value -cne
                    $noDropReasonSha256) { $computedUnexpectedReason++ }
            }
        }
        $rowKeys.Add([string]$row.counter_key)
        $null = $groupNames.Add([string]$row.group)
        $null = $componentKeys.Add(('{0}\u001f{1}\u001f{2}' -f
            $row.group, $row.component_name, $row.component_id))
        $schemaRows.Add([pscustomobject][ordered]@{
            group = [string]$row.group
            component_name = [string]$row.component_name
            component_id = [string]$row.component_id
            counter_name = [string]$row.counter_name
            counter_type = [string]$row.counter_type
            inbound_shape = [string]$row.inbound_shape
            inbound_direction_tag = [string]$row.inbound_direction_tag
            outbound_shape = [string]$row.outbound_shape
            outbound_direction_tag = [string]$row.outbound_direction_tag
            has_last_drop_reason = [bool]$hasReason
            counter_key = [string]$row.counter_key
        })
    }
    [string[]]$computedKeys = @($rowKeys.ToArray() | Sort-Object -Unique)
    [string[]]$orderedDeclaredKeys = @($declaredKeys | Sort-Object -Unique)
    if ($rows.Count -eq 0 -or $rows.Count -ne $computedKeys.Count -or
        ($computedKeys -join "`n") -cne ($orderedDeclaredKeys -join "`n") -or
        [int]$Evidence.group_count -ne $groupNames.Count -or
        [int]$Evidence.component_count -ne $componentKeys.Count -or
        [int]$Evidence.counter_count -ne $rows.Count -or
        [int]$Evidence.metric_count -ne ($rows.Count * 4) -or
        [int]$Evidence.nonzero_metric_count -ne $computedNonzero -or
        [int]$Evidence.unexpected_drop_reason_count -ne
            $computedUnexpectedReason -or
        [bool]$Evidence.proved_all_zero -ne (
            $computedNonzero -eq 0 -and $computedUnexpectedReason -eq 0) -or
        ($RequireAllZero -and -not [bool]$Evidence.proved_all_zero)) {
        throw 'PktMon all-counter snapshot counts/coverage are not exact'
    }
    $expectedSchemaHash = Get-LabStringSha256 -Value (
        ([ordered]@{
            schema = 'pktmon-all-counter-native-es-es/v1'
            rows = @($schemaRows.ToArray() | Sort-Object counter_key)
        }) | ConvertTo-Json -Depth 10 -Compress)
    $expectedSnapshotHash = Get-LabStringSha256 -Value (
        ([ordered]@{
            schema = 'ese.v91.d01-pktmon-all-counter-canonical/v1'
            rows = $rows
        }) | ConvertTo-Json -Depth 10 -Compress)
    if ([string]$Evidence.native_schema_sha256 -cne
            $expectedSchemaHash -or
        [string]$Evidence.snapshot_sha256 -cne $expectedSnapshotHash) {
        throw 'PktMon all-counter snapshot digest is not exact'
    }
    if ($null -eq $ExpectedBaseline) {
        if ([string]$Evidence.baseline_snapshot_sha256 -cne '' -or
            [bool]$Evidence.snapshot_equal_to_baseline -or
            [bool]$Evidence.proved_restored -or $RequireRestored) {
            throw 'PktMon all-counter baseline claims restoration'
        }
    } else {
        $null = Assert-D01PktmonAllCounterSnapshotContract `
            -Evidence $ExpectedBaseline -RequireAllZero
        $coverageEqual = ($computedKeys -join "`n") -ceq
            (@($ExpectedBaseline.counter_keys | Sort-Object -Unique) -join
                "`n")
        $snapshotEqual = $coverageEqual -and
            [string]$Evidence.snapshot_sha256 -ceq
                [string]$ExpectedBaseline.snapshot_sha256 -and
            [string]$Evidence.native_schema_sha256 -ceq
                [string]$ExpectedBaseline.native_schema_sha256
        $restored = $snapshotEqual -and [bool]$Evidence.proved_all_zero
        if ([string]$Evidence.baseline_snapshot_sha256 -cne
                [string]$ExpectedBaseline.snapshot_sha256 -or
            -not $coverageEqual -or
            [bool]$Evidence.snapshot_equal_to_baseline -ne $snapshotEqual -or
            [bool]$Evidence.proved_restored -ne $restored -or
            ($RequireRestored -and (-not $snapshotEqual -or
                -not [bool]$Evidence.proved_restored))) {
            throw 'PktMon all-counter state was not restored exactly'
        }
    }
    return $true
}

function Get-D01PktmonCounterResetEvidence {
    param([Parameter(Mandatory = $true)][object]$CommandResult)

    $clean = [int]$CommandResult.exit_code -eq 0 -and
        [bool]$CommandResult.process_started -and
        [int]$CommandResult.process_id -gt 0 -and
        [bool]$CommandResult.process_exited -and
        [bool]$CommandResult.output_complete -and
        -not [bool]$CommandResult.timed_out -and
        [string]::IsNullOrWhiteSpace([string]$CommandResult.stderr)
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.d01-pktmon-counter-reset/v1'
        command_contract =
            'reset;single-global-mutation;exclusive-all-zero-prebaseline'
        exit_code = [int]$CommandResult.exit_code
        process_started = [bool]$CommandResult.process_started
        process_id = [int]$CommandResult.process_id
        process_exited = [bool]$CommandResult.process_exited
        output_complete = [bool]$CommandResult.output_complete
        timed_out = [bool]$CommandResult.timed_out
        stdout_sha256 = Get-LabStringSha256 -Value (
            [string]$CommandResult.stdout)
        stderr_sha256 = if ([string]::IsNullOrEmpty(
                [string]$CommandResult.stderr)) {
            ''
        } else {
            Get-LabStringSha256 -Value ([string]$CommandResult.stderr)
        }
        succeeded = $clean
    }
}

function Assert-D01PktmonCounterResetContract {
    param([Parameter(Mandatory = $true)][object]$Evidence)

    $null = Assert-D01ExactPropertySet -Object $Evidence -Expected @(
        'schema', 'command_contract', 'exit_code', 'process_started',
        'process_id', 'process_exited', 'output_complete', 'timed_out',
        'stdout_sha256', 'stderr_sha256', 'succeeded'
    ) -Context 'PktMon counter reset evidence'
    foreach ($name in @(
        'process_started', 'process_exited', 'output_complete', 'timed_out',
        'succeeded'
    )) {
        $null = Assert-D01JsonBoolean `
            -Value $Evidence.PSObject.Properties[$name].Value `
            -Context "PktMon counter reset evidence.$name"
    }
    foreach ($name in @(
        'schema', 'command_contract', 'stdout_sha256', 'stderr_sha256'
    )) {
        $null = Assert-D01JsonStringValue `
            -Value $Evidence.PSObject.Properties[$name].Value `
            -Context "PktMon counter reset evidence.$name"
    }
    $exitCode = Assert-D01JsonInteger -Value $Evidence.exit_code `
        -Context 'PktMon counter reset evidence.exit_code' -Minimum 0
    $processId = Assert-D01JsonInteger -Value $Evidence.process_id `
        -Context 'PktMon counter reset evidence.process_id' -Minimum 1
    if ([string]$Evidence.schema -cne
            'ese.v91.d01-pktmon-counter-reset/v1' -or
        [string]$Evidence.command_contract -cne
            'reset;single-global-mutation;exclusive-all-zero-prebaseline' -or
        $exitCode -ne 0 -or $processId -le 0 -or
        -not [bool]$Evidence.process_started -or
        -not [bool]$Evidence.process_exited -or
        -not [bool]$Evidence.output_complete -or
        [bool]$Evidence.timed_out -or -not [bool]$Evidence.succeeded -or
        [string]$Evidence.stdout_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$Evidence.stderr_sha256 -cne '') {
        throw 'PktMon counter reset command was not exact and bounded'
    }
    return $true
}

function Get-D01AtomicJsonSerializationFingerprint {
    param([Parameter(Mandatory = $true)][object]$Value)

    $json = [string]($Value | ConvertTo-Json -Depth 48)
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($json)
    $memory = [IO.MemoryStream]::new($bytes, $false)
    try {
        $sha256 = Get-D01Sha256FromStream -Stream $memory
    } finally { $memory.Dispose() }
    return [pscustomobject][ordered]@{
        byte_count = [Int64]$bytes.Length
        sha256 = [string]$sha256
    }
}

function Test-D01ImmutableCounterEvidenceSnapshot {
    param(
        [Parameter(Mandatory = $true)][object]$Snapshot,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][object]$ExpectedValue
    )
    try {
        $null = Assert-D01ExactPropertySet -Object $Snapshot -Expected @(
            'bytes', 'byte_count', 'sha256', 'immutable_read_lock_held'
        ) -Context 'immutable counter evidence snapshot'
        $byteCount = Assert-D01JsonInteger -Value $Snapshot.byte_count `
            -Context 'immutable counter evidence snapshot.byte_count' `
            -Minimum 1
        $sha256 = Assert-D01JsonStringValue -Value $Snapshot.sha256 `
            -Context 'immutable counter evidence snapshot.sha256' `
            -Pattern '^[0-9a-f]{64}$'
        $lockHeld = Assert-D01JsonBoolean `
            -Value $Snapshot.immutable_read_lock_held `
            -Context (
                'immutable counter evidence snapshot.immutable_read_lock_held')
        $expected = Get-D01AtomicJsonSerializationFingerprint `
            -Value $ExpectedValue
        return $null -eq $Snapshot.bytes -and $byteCount -gt 0 -and
            $byteCount -eq [Int64]$expected.byte_count -and
            $sha256 -ceq [string]$expected.sha256 -and
            $lockHeld -and
            (Test-Path -LiteralPath $Path -PathType Leaf) -and
            (Get-LabSha256 -Path $Path) -ceq $sha256
    } catch { return $false }
}

function Test-D01PktmonGlobalCounterEvidenceChain {
    param([Parameter(Mandatory = $true)][object]$State)

    try {
        $null = Assert-D01PktmonAllCounterSnapshotContract `
            -Evidence $State.counter_global_baseline -RequireAllZero
        if (-not [bool]$State.start_attempted) {
            return -not [bool]$State.counter_reset_required -and
                -not [bool]$State.counter_reset_attempted -and
                [int]$State.counter_reset_invocation_count -eq 0 -and
                [bool]$State.counter_global_restored_verified
        }
        if ($null -ne $State.counter_baseline) {
            $null = Assert-D01PktmonCounterSnapshotContract `
                -Evidence $State.counter_loss `
                -ExpectedBaseline $State.counter_baseline
        } else {
            $null = Assert-D01PktmonCounterSnapshotContract `
                -Evidence $State.counter_loss
        }
        if (-not (Test-D01ImmutableCounterEvidenceSnapshot `
                -Snapshot $State.counter_loss_snapshot `
                -Path $State.counter_loss_path `
                -ExpectedValue $State.counter_loss) -or
            -not [bool]$State.counter_loss_frozen_verified) {
            throw 'Frozen final drop-counter evidence is not exact'
        }
        $null = Assert-D01PktmonAllCounterSnapshotContract `
            -Evidence $State.counter_global_final `
            -ExpectedBaseline $State.counter_global_baseline
        if (-not (Test-D01ImmutableCounterEvidenceSnapshot `
                -Snapshot $State.counter_global_final_snapshot `
                -Path $State.counter_global_final_path `
                -ExpectedValue $State.counter_global_final) -or
            -not [bool]$State.counter_global_final_frozen_verified) {
            throw 'Frozen final all-counter evidence is not exact'
        }
        $null = Assert-D01PktmonCounterResetContract `
            -Evidence $State.counter_reset_result
        $null = Assert-D01PktmonAllCounterSnapshotContract `
            -Evidence $State.counter_global_post_reset `
            -ExpectedBaseline $State.counter_global_baseline `
            -RequireAllZero -RequireRestored
        return -not [bool]$State.counter_reset_required -and
            [bool]$State.counter_reset_attempted -and
            [int]$State.counter_reset_invocation_count -eq 1 -and
            [bool]$State.counter_global_restored_verified
    } catch { return $false }
}

function Start-D01PacketCapture {
    param(
        [Parameter(Mandatory = $true)][string]$EvidencePath,
        [Parameter(Mandatory = $true)][string]$Nonce,
        [Parameter(Mandatory = $true)][string]$IPv4,
        [Parameter(Mandatory = $true)][string]$IPv6,
        [Parameter(Mandatory = $true)][int]$Port
    )

    $prefix = 'ese-d01-' + $Nonce.Substring(0, 8)
    $state = [pscustomobject][ordered]@{
        available = $false
        start_attempted = $false
        started = $false
        capture_started_verified = $false
        session_owned = $false
        filters = @("$prefix-v4", "$prefix-v6")
        filters_created = @()
        owned_filter_rows = @()
        expected_filter_addresses = @($IPv4, $IPv6)
        filter_scope = 'target-address-all-ip-protocols'
        expected_destination_port = $Port
        filters_applied_verified = $false
        filter_content_verified = $false
        filter_rows_before = @()
        filter_rows_armed = @()
        filter_rows_after = @()
        filter_census_before = $null
        filter_census_armed = $null
        filter_census_after = $null
        filter_inventory_before_valid = $false
        filters_absent_verified = $false
        filter_inventory_restored_verified = $false
        etw_session_stopped_verified = $false
        etw_session_control_stop_verified = $false
        pre_start_session_absence = $null
        pre_start_session_absence_exact = $false
        session_adopted_for_rollback = $false
        etw_session_identity = $null
        etw_session_post_counter_identity = $null
        etw_session_pre_stop_identity = $null
        pktmon_driver_stop_pre_identity = $null
        pktmon_driver_stop_post_identity = $null
        pktmon_driver_stop = $null
        pktmon_driver_stop_verified = $false
        pktmon_driver_rollback_stop_verified = $false
        pktmon_driver_api_compatibility = $null
        pktmon_driver_status_before = $null
        pktmon_driver_status_armed = $null
        pktmon_driver_status_pre_stop = $null
        pktmon_driver_inactive_pre_stop_verified = $false
        pktmon_driver_status_final = $null
        pktmon_driver_configuration_restored_verified = $false
        etw_loss = $null
        counter_baseline = $null
        counter_loss = $null
        counter_global_baseline = $null
        counter_global_final = $null
        counter_global_post_reset = $null
        counter_global_precommit = $null
        counter_reset_required = $false
        counter_reset_attempted = $false
        counter_reset_invocation_count = 0
        counter_reset_result = $null
        counter_global_restored_verified = $false
        counter_loss_snapshot = $null
        counter_loss_frozen_verified = $false
        counter_global_final_snapshot = $null
        counter_global_final_frozen_verified = $false
        cleanup_invocation_count = 0
        cleanup_entry_ledger_quiescent = $false
        cleanup_deferred_for_active_lease = $false
        cleanup_sequence_completed = $false
        capture_file_limit_bytes = [Int64](256 * 1MB)
        etl_path = Join-Path $EvidencePath 'd01-packets.etl'
        pcapng_path = Join-Path $EvidencePath 'd01-packets.pcapng'
        text_path = Join-Path $EvidencePath 'd01-packets.txt'
        command_log = Join-Path $EvidencePath 'pktmon.log'
        filters_before_path =
            Join-Path $EvidencePath 'pktmon-filters-before.txt'
        filters_armed_path =
            Join-Path $EvidencePath 'pktmon-filters-armed.txt'
        filters_after_path =
            Join-Path $EvidencePath 'pktmon-filters-after.txt'
        counters_path = Join-Path $EvidencePath 'pktmon-counters.txt'
        counter_loss_path =
            Join-Path $EvidencePath 'pktmon-drop-counters-final.json'
        counter_global_final_path =
            Join-Path $EvidencePath 'pktmon-all-counters-final.json'
        error = $null
    }
    $script:d01PendingPktmonCleanupState = $state
    $script:d01NativeHelperLogPath = [string]$state.command_log
    Write-D01JsonAtomic -Value ([ordered]@{
        schema = 'ese.v91.d01-pktmon-intent/v2'
        captured_at_utc = Get-LabUtcTimestamp
        run_nonce = $Nonce
        filters = $state.filters
        ipv4 = $IPv4
        ipv6 = $IPv6
        expected_destination_port = $Port
        capture_scope = 'both target addresses, all IP protocols and ports'
        operational_exclusion_contract =
            'exclusive-controlled-host;no-concurrent-pktmon-cli-filter-driver-etw-provider-or-direct-api-ioctl-mutators'
        exclusive_driver_control_operator_attested =
            [bool]$ExclusivePktmonDriverControlAcknowledged
    }) -Path (Join-Path $EvidencePath 'pktmon-intent.json')
    try {
        $null = Get-D01TrustedSystemBinaryPath -Name 'pktmon.exe'
        $state.pktmon_driver_api_compatibility =
            Get-D01PktmonDriverApiCompatibility `
                -ExclusiveControlOperatorAttested (
                    [bool]$ExclusivePktmonDriverControlAcknowledged)
        $null = Assert-D01PktmonDriverApiCompatibilityContract `
            -Evidence $state.pktmon_driver_api_compatibility
        $script:d01PktmonBinaryTuple =
            $state.pktmon_driver_api_compatibility
        $state.pktmon_driver_status_before =
            Get-D01PktmonDriverStatus -ExpectedLibrarySha256 (
                [string]$state.pktmon_driver_api_compatibility.
                    library_sha256) -ExpectedDriverSha256 (
                [string]$state.pktmon_driver_api_compatibility.driver_sha256)
        $null = Assert-D01PktmonDriverStatusContract `
            -Evidence $state.pktmon_driver_status_before `
            -ExpectedLibrarySha256 (
                [string]$state.pktmon_driver_api_compatibility.
                    library_sha256) `
            -RequireInactive -RequireCaptureConfigurationBaseline
    } catch {
        $state.error = $_.Exception.Message
        return $state
    }
    $beforeResult = Invoke-D01Pktmon -LogPath $state.command_log `
        -Arguments @('filter', 'list')
    if ($beforeResult.exit_code -ne 0) {
        $state.error = 'PktMon pre-run filter inventory failed'
        return $state
    }
    $beforeText = [string]$beforeResult.stdout
    Set-Content -LiteralPath $state.filters_before_path -Encoding utf8 `
        -Value $beforeText
    $state.filter_census_before =
        Get-D01PktmonInventoryCensus -Text $beforeText
    if (-not [bool]$state.filter_census_before.exact -or
        -not [bool]$state.filter_census_before.empty -or
        [int]$state.filter_census_before.entry_count -ne 0) {
        $state.error =
            'PktMon pre-run filter inventory is not exactly empty'
        return $state
    }
    $state.filter_rows_before = @()
    $state.filter_inventory_before_valid = $true
    $sessionBefore = Get-D01EtwLossEvidence -IdentityProbeOnly
    $state.pre_start_session_absence = $sessionBefore
    try {
        $null = Assert-D01EtwSessionNameProbeContract `
            -Probe $sessionBefore -RequireAbsent
        $state.pre_start_session_absence_exact = $true
    } catch {
        $state.error =
            'PktMon ETW pre-start absence was not proven exactly'
        return $state
    }
    try {
        $counterGlobalBaselineResult = Invoke-D01Pktmon `
            -LogPath $state.command_log `
            -Arguments @(
                'counters', '--type', 'all', '--include-hidden',
                '--zero', '--json')
        $state.counter_global_baseline =
            Get-D01PktmonAllCounterSnapshotEvidence `
                -Stdout ([string]$counterGlobalBaselineResult.stdout) `
                -Stderr ([string]$counterGlobalBaselineResult.stderr) `
                -ExitCode ([int]$counterGlobalBaselineResult.exit_code) `
                -ProcessExited (
                    [bool]$counterGlobalBaselineResult.process_exited) `
                -OutputComplete (
                    [bool]$counterGlobalBaselineResult.output_complete)
        $null = Assert-D01PktmonAllCounterSnapshotContract `
            -Evidence $state.counter_global_baseline -RequireAllZero
        $state.counter_global_restored_verified = $true
    } catch {
        $state.error =
            'PktMon global counters were not exactly zero before mutation: ' +
            $_.Exception.Message
        return $state
    }
    try {
        $state.filters_created = @($state.filters_created) +
            [string]$state.filters[0]
        $v4Result = Invoke-D01Pktmon -LogPath $state.command_log `
            -Arguments @(
                'filter', 'add', $state.filters[0], '-i', $IPv4
            )
        if ($v4Result.exit_code -ne 0) {
            throw 'PktMon rejected the all-protocol IPv4 target filter'
        }
        $state.filters_created = @($state.filters_created) +
            [string]$state.filters[1]
        $v6Result = Invoke-D01Pktmon -LogPath $state.command_log `
            -Arguments @(
                'filter', 'add', $state.filters[1], '-i', $IPv6
            )
        if ($v6Result.exit_code -ne 0) {
            throw 'PktMon rejected the all-protocol IPv6 target filter'
        }
        $armedResult = Invoke-D01Pktmon -LogPath $state.command_log `
            -Arguments @('filter', 'list')
        if ($armedResult.exit_code -ne 0) {
            throw 'PktMon armed filter inventory failed'
        }
        $armed = [string]$armedResult.stdout
        $state.filter_census_armed =
            Get-D01PktmonInventoryCensus -Text $armed
        $state.filter_rows_armed = @(Get-D01PktmonFilterRows -Text $armed)
        Set-Content -LiteralPath $state.filters_armed_path -Encoding utf8 `
            -Value $armed
        $armedRows = @($state.filter_rows_armed)
        $state.filter_content_verified =
            Test-D01PktmonArmedAllProtocolFilterContracts `
                -Census $state.filter_census_armed `
                -FilterV4 ([string]$state.filters[0]) `
                -FilterV6 ([string]$state.filters[1]) `
                -IPv4 $IPv4 -IPv6 $IPv6
        $state.filters_applied_verified =
            [bool]$state.filter_inventory_before_valid -and
            $state.filter_content_verified
        if (-not $state.filters_applied_verified) {
            throw 'PktMon did not list both exact run-owned filters'
        }
        $state.owned_filter_rows = @($armedRows | Sort-Object)
        # START clears the global PktMon counter bank before the CLI can report
        # success.  Mark rollback required before crossing that mutation point.
        $state.counter_reset_required = $true
        $state.counter_global_restored_verified = $false
        $state.start_attempted = $true
        $startResult = $null
        $startIdentityExact = $false
        try {
            $startResult = Invoke-D01Pktmon -LogPath $state.command_log `
                -Arguments @(
                    'start', '--capture', '--comp', 'nics', '--pkt-size', '0',
                    '--file-name', $state.etl_path, '--file-size', '256'
                )
        } finally {
            # Reconcile even when the command runner itself faults after
            # Process.Start: an exact logger ID/path is the only safe ownership
            # acquisition point for later ControlTrace cleanup.
            $state.etw_session_identity = Get-D01EtwLossEvidence `
                -ExpectedLogFilePath $state.etl_path
            try {
                $null = Assert-D01EtwIdentityBindingContract `
                    -Evidence $state.etw_session_identity `
                    -ExpectedPhase 'post-flush-live-query' `
                    -ExpectedLogFilePath $state.etl_path
                $startIdentityExact = $true
                $state.session_owned = $true
                $state.started = $true
            } catch { $startIdentityExact = $false }
        }
        if ($null -eq $startResult) {
            throw 'PktMon start command returned no bounded result'
        }
        if ($startResult.exit_code -ne 0) {
            if ($startIdentityExact) {
                throw 'PktMon start reported failure after applying the owned session'
            }
            throw 'PktMon capture could not be started or identity-bound'
        }
        if (-not $startIdentityExact) {
            throw 'PktMon start succeeded without an exact ETW identity'
        }
        $state.pktmon_driver_status_armed =
            Get-D01PktmonDriverStatus -ExpectedLibrarySha256 (
                [string]$state.pktmon_driver_api_compatibility.
                    library_sha256) -ExpectedDriverSha256 (
                [string]$state.pktmon_driver_api_compatibility.driver_sha256)
        $null = Assert-D01PktmonDriverStatusContract `
            -Evidence $state.pktmon_driver_status_armed `
            -ExpectedLibrarySha256 (
                [string]$state.pktmon_driver_api_compatibility.
                    library_sha256) `
            -ExpectedConfigurationBaseline $state.pktmon_driver_status_before `
            -IgnoreLoggerPresenceInBaselineComparison
        if ([int]$state.pktmon_driver_status_armed.active -ne 1 -or
            [int]$state.pktmon_driver_status_armed.logger_present -ne 1) {
            throw 'PktMon driver did not become active for the owned capture'
        }
        $null = Assert-D01EtwLossEvidenceContract `
            -Evidence $state.etw_session_identity `
            -ExpectedPhase 'post-flush-live-query' `
            -ExpectedLogFilePath $state.etl_path -RequireZero
        if ([string]$state.etw_session_identity.schema -cne
                'ese.v91.d01-etw-final-loss/v3' -or
            [string]$state.etw_session_identity.phase -cne
                'post-flush-live-query' -or
            [string]$state.etw_session_identity.control_trace_id_hex `
                -cnotmatch '^[0-9a-f]{16}$' -or
            -not [bool]$state.etw_session_identity.available -or
            -not [bool]$state.etw_session_identity.session_identity_exact -or
            -not [bool]$state.etw_session_identity.proved_zero -or
            [bool]$state.etw_session_identity.
                session_stopped_by_control_trace) {
            throw 'PktMon ETW session identity/loss baseline is not exact'
        }
        $state.capture_started_verified = $true
        $counterBaselineResult = Invoke-D01Pktmon `
            -LogPath $state.command_log `
            -Arguments @(
                'counters', '--type', 'drop', '--include-hidden',
                '--zero', '--json')
        $state.counter_baseline = Get-D01PktmonCounterLossEvidence `
            -Stdout ([string]$counterBaselineResult.stdout) `
            -Stderr ([string]$counterBaselineResult.stderr) `
            -ExitCode ([int]$counterBaselineResult.exit_code) `
            -ProcessExited ([bool]$counterBaselineResult.process_exited) `
            -OutputComplete ([bool]$counterBaselineResult.output_complete)
        $null = Assert-D01PktmonCounterSnapshotContract `
            -Evidence $state.counter_baseline -RequireAllZero
        if ([string]$state.counter_baseline.schema -cne
                'ese.v91.d01-pktmon-counter-loss/v4' -or
            -not [bool]$state.counter_baseline.json_contract_valid -or
            -not [bool]$state.counter_baseline.
                component_coverage_exact -or
            [string]$state.counter_baseline.snapshot_sha256 -cnotmatch
                '^[0-9a-f]{64}$' -or
            [string]$state.counter_baseline.component_schema_sha256 `
                -cnotmatch '^[0-9a-f]{64}$') {
            throw 'PktMon baseline drop-counter snapshot was not exact'
        }
        $state.etw_session_post_counter_identity =
            Get-D01EtwLossEvidence `
                -ExpectedLogFilePath $state.etl_path `
                -ExpectedControlTraceIdHex (
                    [string]$state.etw_session_identity.
                        control_trace_id_hex)
        $null = Assert-D01EtwLossEvidenceContract `
            -Evidence $state.etw_session_post_counter_identity `
            -ExpectedPhase 'post-flush-live-query' `
            -ExpectedLogFilePath $state.etl_path `
            -ExpectedControlTraceIdHex (
                [string]$state.etw_session_identity.
                    control_trace_id_hex) `
            -RequireZero
        if ([string]$state.etw_session_post_counter_identity.schema -cne
                'ese.v91.d01-etw-final-loss/v3' -or
            [string]$state.etw_session_post_counter_identity.phase -cne
                'post-flush-live-query' -or
            -not [bool]$state.etw_session_post_counter_identity.available -or
            -not [bool]$state.etw_session_post_counter_identity.
                session_identity_exact -or
            -not [bool]$state.etw_session_post_counter_identity.proved_zero -or
            [string]$state.etw_session_post_counter_identity.
                session_identity_sha256 -cne
                [string]$state.etw_session_identity.
                    session_identity_sha256) {
            throw 'PktMon counter read was not bracketed by one ETW session'
        }
        $state.available = $true
    } catch {
        $state.error = $_.Exception.Message
    }
    return $state
}

function Stop-D01PacketCapture {
    param(
        [Parameter(Mandatory = $true)][object]$State,
        [Parameter(Mandatory = $true)]
        [Collections.Generic.List[string]]$CleanupFailures
    )

    $State.cleanup_invocation_count =
        [int]$State.cleanup_invocation_count + 1
    $State.cleanup_sequence_completed = $false
    if (-not (Test-D01TrustedCommandLedgerQuiescent -Terminate)) {
        $State.cleanup_entry_ledger_quiescent = $false
        $State.cleanup_deferred_for_active_lease = $true
        $script:d01PendingPktmonCleanupState = $State
        $script:d01PendingPktmonCleanupFailures = $CleanupFailures
        $CleanupFailures.Add(
            'A trusted command process remained active; PktMon cleanup was deferred')
        return $false
    }
    $State.cleanup_entry_ledger_quiescent = $true
    $State.cleanup_deferred_for_active_lease = $false
    $pktmonCliAvailable = $false
    try {
        $null = Get-D01TrustedSystemBinaryPath -Name 'pktmon.exe'
        $pktmonCliAvailable = $true
    } catch {
        $CleanupFailures.Add(
            "trusted pktmon unavailable during cleanup: $($_.Exception.Message)"
        )
    }
    $driverApiCompatible = $false
    try {
        $null = Assert-D01PktmonDriverApiCompatibilityContract `
            -Evidence $State.pktmon_driver_api_compatibility
        $driverApiCompatible = $true
    } catch {
        $CleanupFailures.Add(
            'PktMon private driver API is outside the audited whitelist')
    }
    $sessionProbe = Get-D01EtwLossEvidence -IdentityProbeOnly
    $sessionStateProven = $false
    $sessionPresent = $false
    try {
        $null = Assert-D01EtwSessionNameProbeContract -Probe $sessionProbe
        $sessionStateProven = $true
        $sessionPresent = [bool]$sessionProbe.available
    } catch {
        $CleanupFailures.Add(
            'PktMon ETW session state was not proven before cleanup')
    }
    if (-not [bool]$State.session_owned -and $sessionPresent -and
        [bool]$State.start_attempted -and
        [bool]$State.pre_start_session_absence_exact) {
        try {
            $rollbackIdentity = Get-D01EtwLossEvidence `
                -ExpectedLogFilePath ([string]$State.etl_path)
            $null = Assert-D01EtwIdentityBindingContract `
                -Evidence $rollbackIdentity `
                -ExpectedPhase 'post-flush-live-query' `
                -ExpectedLogFilePath ([string]$State.etl_path)
            $State.etw_session_identity = $rollbackIdentity
            $State.session_owned = $true
            $State.started = $true
            $State.session_adopted_for_rollback = $true
        } catch {
            $CleanupFailures.Add(
                'Ambiguous post-start PktMon logger could not be adopted for rollback')
        }
    }
    $boundSessionReady = $false
    if (-not $sessionStateProven) {
        $boundSessionReady = $false
    } elseif ($State.session_owned -and $sessionPresent) {
        $baselineIdentityExact = $false
        try {
            $null = Assert-D01EtwIdentityBindingContract `
                -Evidence $State.etw_session_identity `
                -ExpectedPhase 'post-flush-live-query' `
                -ExpectedLogFilePath ([string]$State.etl_path)
            $baselineIdentityExact = $true
        } catch {
            $CleanupFailures.Add(
                "Owned PktMon session lacks its immutable ETW identity: $($_.Exception.Message)")
        }
        if ($baselineIdentityExact) {
            $State.etw_session_pre_stop_identity =
                Get-D01EtwLossEvidence `
                    -ExpectedLogFilePath ([string]$State.etl_path) `
                    -ExpectedControlTraceIdHex (
                        [string]$State.etw_session_identity.
                            control_trace_id_hex)
            try {
                $null = Assert-D01EtwIdentityBindingContract `
                    -Evidence $State.etw_session_pre_stop_identity `
                    -ExpectedPhase 'post-flush-live-query' `
                    -ExpectedLogFilePath ([string]$State.etl_path) `
                    -ExpectedControlTraceIdHex (
                        [string]$State.etw_session_identity.
                            control_trace_id_hex)
                $boundSessionReady =
                    [string]$State.etw_session_pre_stop_identity.
                        session_identity_sha256 -ceq
                        [string]$State.etw_session_identity.
                            session_identity_sha256
            } catch {
                $boundSessionReady = $false
            }
            if ($boundSessionReady) {
                try {
                    $null = Assert-D01EtwLossEvidenceContract `
                        -Evidence $State.etw_session_pre_stop_identity `
                        -ExpectedPhase 'post-flush-live-query' `
                        -ExpectedLogFilePath ([string]$State.etl_path) `
                        -ExpectedControlTraceIdHex (
                            [string]$State.etw_session_identity.
                                control_trace_id_hex)
                } catch {
                    $CleanupFailures.Add(
                        'Pre-stop ETW loss evidence was not fully observable')
                }
            }
            if (-not $boundSessionReady) {
                $CleanupFailures.Add(
                    'PktMon ETW identity changed; all destructive stop operations were refused')
            } elseif (-not [bool]$State.etw_session_pre_stop_identity.
                    proved_zero) {
                $CleanupFailures.Add(
                    'Pre-stop ETW query did not prove zero trace loss')
            }
        }
    } elseif ($State.session_owned -and -not $sessionPresent) {
        $State.started = $false
        $CleanupFailures.Add(
            'Owned PktMon session disappeared before controlled stop')
    } elseif (-not $State.session_owned -and $sessionPresent) {
        $CleanupFailures.Add(
            'A foreign PktMon session appeared; destructive stop was refused')
    }
    $driverInactiveForCleanup = $false
    if ($boundSessionReady) {
        $driverStopEtwBindingExact = $false
        try {
            if (-not $driverApiCompatible) {
                throw 'PktMon driver STOP refused for unsupported private ABI'
            }
            $State.pktmon_driver_stop_pre_identity =
                Get-D01EtwLossEvidence `
                    -ExpectedLogFilePath ([string]$State.etl_path) `
                    -ExpectedControlTraceIdHex (
                        [string]$State.etw_session_identity.
                            control_trace_id_hex)
            $null = Assert-D01EtwIdentityBindingContract `
                -Evidence $State.pktmon_driver_stop_pre_identity `
                -ExpectedPhase 'post-flush-live-query' `
                -ExpectedLogFilePath ([string]$State.etl_path) `
                -ExpectedControlTraceIdHex (
                    [string]$State.etw_session_identity.
                        control_trace_id_hex)
            if ([string]$State.pktmon_driver_stop_pre_identity.
                    session_identity_sha256 -cne
                    [string]$State.etw_session_identity.
                        session_identity_sha256) {
                throw 'PktMon driver-stop pre-identity changed'
            }
            $driverStopResultExact = $false
            $State.pktmon_driver_status_pre_stop =
                Get-D01PktmonDriverStatus -ExpectedLibrarySha256 (
                    [string]$State.pktmon_driver_api_compatibility.
                        library_sha256) -ExpectedDriverSha256 (
                    [string]$State.pktmon_driver_api_compatibility.driver_sha256)
            $null = Assert-D01PktmonDriverStatusContract `
                -Evidence $State.pktmon_driver_status_pre_stop `
                -ExpectedLibrarySha256 (
                    [string]$State.pktmon_driver_api_compatibility.
                        library_sha256) `
                -ExpectedConfigurationBaseline `
                    $State.pktmon_driver_status_before `
                -IgnoreLoggerPresenceInBaselineComparison
            $driverActivePreStop =
                [int]$State.pktmon_driver_status_pre_stop.active
            if ($driverActivePreStop -eq 0) {
                if ([int]$State.pktmon_driver_status_pre_stop.
                        logger_present -ne 0) {
                    throw 'Inactive PktMon driver still reports a logger'
                }
                $State.pktmon_driver_inactive_pre_stop_verified = $true
            } elseif ($driverActivePreStop -eq 1) {
                if ([int]$State.pktmon_driver_status_pre_stop.
                        logger_present -ne 1) {
                    throw 'Active PktMon driver lacks its logger-present flag'
                }
                $State.pktmon_driver_stop = Invoke-D01PktmonDriverStop `
                    -ExpectedLibrarySha256 (
                        [string]$State.pktmon_driver_api_compatibility.
                            library_sha256) -ExpectedDriverSha256 (
                        [string]$State.pktmon_driver_api_compatibility.
                            driver_sha256)
                try {
                    $null = Assert-D01PktmonDriverStopContract `
                        -Evidence $State.pktmon_driver_stop `
                        -ExpectedLibrarySha256 (
                            [string]$State.pktmon_driver_api_compatibility.
                                library_sha256) `
                        -ExpectedConfigurationBaseline `
                            $State.pktmon_driver_status_before
                    $driverStopResultExact = $true
                } catch {
                    $CleanupFailures.Add(
                        'PktMon driver stop/status result was not exact')
                }
            } else {
                throw 'PktMon pre-stop driver active flag is outside its audited ABI'
            }
            $State.pktmon_driver_stop_post_identity =
                Get-D01EtwLossEvidence `
                    -ExpectedLogFilePath ([string]$State.etl_path) `
                    -ExpectedControlTraceIdHex (
                        [string]$State.etw_session_identity.
                            control_trace_id_hex)
            $null = Assert-D01EtwIdentityBindingContract `
                -Evidence $State.pktmon_driver_stop_post_identity `
                -ExpectedPhase 'post-flush-live-query' `
                -ExpectedLogFilePath ([string]$State.etl_path) `
                -ExpectedControlTraceIdHex (
                    [string]$State.etw_session_identity.
                        control_trace_id_hex)
            $driverStopEtwBindingExact =
                [string]$State.pktmon_driver_stop_post_identity.
                    session_identity_sha256 -ceq
                    [string]$State.etw_session_identity.
                        session_identity_sha256
            $State.pktmon_driver_stop_verified =
                $driverActivePreStop -eq 1 -and
                $driverStopEtwBindingExact -and
                $driverStopResultExact -and
                [bool]$State.pktmon_driver_stop.success
            $driverInactiveForCleanup =
                [bool]$State.pktmon_driver_stop_verified -or
                [bool]$State.pktmon_driver_inactive_pre_stop_verified
        } catch {
            $CleanupFailures.Add(
                "PktMon driver cleanup was not ETW-bracketed and exact: $($_.Exception.Message)")
        }
        if (-not $driverInactiveForCleanup) {
            $CleanupFailures.Add(
                'PktMon driver monitoring was not proven inactive')
        }
        if ($driverInactiveForCleanup) {
            $State.etw_loss = Get-D01EtwLossEvidence `
                -StopOwnedSession `
                -ExpectedLogFilePath ([string]$State.etl_path) `
                -ExpectedControlTraceIdHex (
                    [string]$State.etw_session_identity.
                        control_trace_id_hex)
            $finalStopContractExact = $false
            try {
                $null = Assert-D01EtwIdentityBindingContract `
                    -Evidence $State.etw_loss `
                    -ExpectedPhase 'post-final-flush-control-stop' `
                    -ExpectedLogFilePath ([string]$State.etl_path) `
                    -ExpectedControlTraceIdHex (
                        [string]$State.etw_session_identity.
                            control_trace_id_hex)
                $finalStopContractExact =
                    [bool]$State.etw_loss.
                        session_stopped_by_control_trace -and
                    [int]$State.etw_loss.error_code -eq 0
            } catch {
                $CleanupFailures.Add(
                    "Final ETW ControlTrace identity is invalid: $($_.Exception.Message)")
            }
            if ($finalStopContractExact) {
                try {
                    $null = Assert-D01EtwLossEvidenceContract `
                        -Evidence $State.etw_loss `
                        -ExpectedPhase 'post-final-flush-control-stop' `
                        -ExpectedLogFilePath ([string]$State.etl_path) `
                        -ExpectedControlTraceIdHex (
                            [string]$State.etw_session_identity.
                                control_trace_id_hex) `
                        -RequireStopped
                } catch {
                    $CleanupFailures.Add(
                        'Final ETW loss evidence was not fully observable')
                }
            }
            $State.etw_session_control_stop_verified =
                $finalStopContractExact -and
                [bool]$State.etw_loss.session_stopped_by_control_trace -and
                [bool]$State.etw_loss.session_identity_exact -and
                [string]$State.etw_loss.control_trace_id_hex -ceq
                    [string]$State.etw_session_identity.
                        control_trace_id_hex -and
                [string]$State.etw_loss.session_identity_sha256 -ceq
                    [string]$State.etw_session_identity.
                        session_identity_sha256
            if (-not $State.etw_session_control_stop_verified -or
                -not [bool]$State.etw_loss.proved_zero) {
                $CleanupFailures.Add(
                    'Final ETW ControlTrace STOP did not prove zero loss')
            } else {
                $State.started = $false
            }
        } else {
            $CleanupFailures.Add(
                'ETW ControlTrace STOP was refused until the driver is proven inactive')
        }
    }
    if (-not $boundSessionReady -and [bool]$State.start_attempted -and
        $sessionStateProven -and -not $sessionPresent) {
        try {
            if (-not $driverApiCompatible -or
                -not [bool]$State.pre_start_session_absence_exact) {
                throw 'Partial START rollback lacks its exclusive preconditions'
            }
            $null = Assert-D01PktmonAllCounterSnapshotContract `
                -Evidence $State.counter_global_baseline -RequireAllZero
            $State.pktmon_driver_status_pre_stop =
                Get-D01PktmonDriverStatus -ExpectedLibrarySha256 (
                    [string]$State.pktmon_driver_api_compatibility.
                        library_sha256) -ExpectedDriverSha256 (
                    [string]$State.pktmon_driver_api_compatibility.driver_sha256)
            $null = Assert-D01PktmonDriverStatusContract `
                -Evidence $State.pktmon_driver_status_pre_stop `
                -ExpectedLibrarySha256 (
                    [string]$State.pktmon_driver_api_compatibility.
                        library_sha256) `
                -ExpectedConfigurationBaseline `
                    $State.pktmon_driver_status_before `
                -IgnoreLoggerPresenceInBaselineComparison
            $partialActive =
                [int]$State.pktmon_driver_status_pre_stop.active
            if ($partialActive -eq 1) {
                $State.pktmon_driver_stop = Invoke-D01PktmonDriverStop `
                    -ExpectedLibrarySha256 (
                        [string]$State.pktmon_driver_api_compatibility.
                            library_sha256) -ExpectedDriverSha256 (
                        [string]$State.pktmon_driver_api_compatibility.
                            driver_sha256)
                $null = Assert-D01PktmonDriverStopContract `
                    -Evidence $State.pktmon_driver_stop `
                    -ExpectedLibrarySha256 (
                        [string]$State.pktmon_driver_api_compatibility.
                            library_sha256) `
                    -ExpectedConfigurationBaseline `
                        $State.pktmon_driver_status_before
                $State.pktmon_driver_rollback_stop_verified = $true
                $driverInactiveForCleanup = $true
            } elseif ($partialActive -eq 0) {
                $null = Assert-D01PktmonDriverStatusContract `
                    -Evidence $State.pktmon_driver_status_pre_stop `
                    -ExpectedLibrarySha256 (
                        [string]$State.pktmon_driver_api_compatibility.
                            library_sha256) -RequireInactive `
                    -ExpectedConfigurationBaseline `
                        $State.pktmon_driver_status_before
                $State.pktmon_driver_inactive_pre_stop_verified = $true
                $driverInactiveForCleanup = $true
            } else {
                throw 'Partial START driver active flag is outside the ABI'
            }
        } catch {
            $driverInactiveForCleanup = $false
            $CleanupFailures.Add(
                "Partial PktMon START rollback failed: $($_.Exception.Message)")
        }
    }
    $etwInactiveForCounterRollback = if ($boundSessionReady) {
        [bool]$State.etw_session_control_stop_verified
    } else {
        $sessionStateProven -and -not $sessionPresent
    }
    if ([bool]$State.counter_reset_required) {
        if (-not $pktmonCliAvailable -or -not $driverInactiveForCleanup -or
            -not $etwInactiveForCounterRollback) {
            $CleanupFailures.Add(
                'PktMon global counter rollback lacked inactive driver/ETW proof')
        } else {
            $globalBaselineExact = $false
            try {
                $null = Assert-D01PktmonAllCounterSnapshotContract `
                    -Evidence $State.counter_global_baseline -RequireAllZero
                $globalBaselineExact = $true
            } catch {
                $CleanupFailures.Add(
                    'PktMon global counter baseline is not exact/all-zero')
            }
            $dropBaselineExact = $false
            try {
                $null = Assert-D01PktmonCounterSnapshotContract `
                    -Evidence $State.counter_baseline -RequireAllZero
                $dropBaselineExact = $true
            } catch { $dropBaselineExact = $false }
            try {
                $dropResult = Invoke-D01Pktmon -LogPath $State.command_log `
                    -Arguments @(
                    'counters', '--type', 'drop', '--include-hidden',
                    '--zero', '--json')
            } catch {
                $dropResult = [pscustomobject][ordered]@{
                    exit_code = 9009
                    timed_out = $false
                    output_complete = $false
                    process_started = $false
                    process_id = 0
                    process_exited = $false
                    stdout = ''
                    stderr = $_.Exception.Message
                }
            }
            if ($dropBaselineExact) {
                $State.counter_loss = Get-D01PktmonCounterLossEvidence `
                    -Stdout ([string]$dropResult.stdout) `
                    -Stderr ([string]$dropResult.stderr) `
                    -ExitCode ([int]$dropResult.exit_code) `
                    -ProcessExited ([bool]$dropResult.process_exited) `
                    -OutputComplete ([bool]$dropResult.output_complete) `
                    -ExpectedComponentIds @(
                        $State.counter_baseline.component_ids) `
                    -ExpectedSnapshot $State.counter_baseline
            } else {
                $State.counter_loss = Get-D01PktmonCounterLossEvidence `
                    -Stdout ([string]$dropResult.stdout) `
                    -Stderr ([string]$dropResult.stderr) `
                    -ExitCode ([int]$dropResult.exit_code) `
                    -ProcessExited ([bool]$dropResult.process_exited) `
                    -OutputComplete ([bool]$dropResult.output_complete)
            }
            try {
                Write-D01JsonAtomic -Value $State.counter_loss `
                    -Path $State.counter_loss_path
                $State.counter_loss_snapshot =
                    Open-D01ImmutableEvidenceSnapshot `
                        -Path $State.counter_loss_path -MetadataOnly
                $State.counter_loss_frozen_verified =
                    Test-D01ImmutableCounterEvidenceSnapshot `
                        -Snapshot $State.counter_loss_snapshot `
                        -Path $State.counter_loss_path `
                        -ExpectedValue $State.counter_loss
            } catch { $State.counter_loss_frozen_verified = $false }
            try {
                if ($dropBaselineExact) {
                    $null = Assert-D01PktmonCounterSnapshotContract `
                        -Evidence $State.counter_loss `
                        -ExpectedBaseline $State.counter_baseline
                } else {
                    $null = Assert-D01PktmonCounterSnapshotContract `
                        -Evidence $State.counter_loss
                }
            } catch {
                $CleanupFailures.Add(
                    'Final drop-counter command/schema was not exact')
            }
            try {
                $allFinalResult = Invoke-D01Pktmon `
                    -LogPath $State.command_log `
                    -Arguments @(
                        'counters', '--type', 'all', '--include-hidden',
                        '--zero', '--json')
            } catch {
                $allFinalResult = [pscustomobject][ordered]@{
                    exit_code = 9009
                    timed_out = $false
                    output_complete = $false
                    process_started = $false
                    process_id = 0
                    process_exited = $false
                    stdout = ''
                    stderr = $_.Exception.Message
                }
            }
            $State.counter_global_final =
                Get-D01PktmonAllCounterSnapshotEvidence `
                    -Stdout ([string]$allFinalResult.stdout) `
                    -Stderr ([string]$allFinalResult.stderr) `
                    -ExitCode ([int]$allFinalResult.exit_code) `
                    -ProcessExited ([bool]$allFinalResult.process_exited) `
                    -OutputComplete ([bool]$allFinalResult.output_complete) `
                    -ExpectedBaseline $State.counter_global_baseline
            try {
                Write-D01JsonAtomic -Value $State.counter_global_final `
                    -Path $State.counter_global_final_path
                $State.counter_global_final_snapshot =
                    Open-D01ImmutableEvidenceSnapshot `
                        -Path $State.counter_global_final_path -MetadataOnly
                $State.counter_global_final_frozen_verified =
                    Test-D01ImmutableCounterEvidenceSnapshot `
                        -Snapshot $State.counter_global_final_snapshot `
                        -Path $State.counter_global_final_path `
                        -ExpectedValue $State.counter_global_final
            } catch {
                $State.counter_global_final_frozen_verified = $false
            }
            try {
                $null = Assert-D01PktmonAllCounterSnapshotContract `
                    -Evidence $State.counter_global_final `
                    -ExpectedBaseline $State.counter_global_baseline
            } catch {
                $CleanupFailures.Add(
                    'Final all-counter command/schema was not exact')
            }
            $frozenBeforeReset =
                [bool]$State.counter_loss_frozen_verified -and
                [bool]$State.counter_global_final_frozen_verified -and
                (Test-D01TrustedCommandLedgerQuiescent)
            if (-not $globalBaselineExact -or -not $frozenBeforeReset) {
                $CleanupFailures.Add(
                    'PktMon reset refused before frozen drop/all evidence')
            } elseif ([bool]$State.counter_reset_attempted -or
                [int]$State.counter_reset_invocation_count -ne 0) {
                $CleanupFailures.Add('PktMon counter reset was already attempted')
            } else {
                $State.counter_reset_attempted = $true
                $State.counter_reset_invocation_count = 1
                try {
                    $resetCommandResult = Invoke-D01Pktmon `
                        -LogPath $State.command_log -Arguments @('reset')
                } catch {
                    $resetCommandResult = [pscustomobject][ordered]@{
                        exit_code = 9009
                        timed_out = $false
                        output_complete = $false
                        process_started = $false
                        process_id = 0
                        process_exited = $false
                        stdout = ''
                        stderr = $_.Exception.Message
                    }
                }
                $State.counter_reset_result =
                    Get-D01PktmonCounterResetEvidence `
                        -CommandResult $resetCommandResult
                try {
                    $postResetResult = Invoke-D01Pktmon `
                        -LogPath $State.command_log `
                        -Arguments @(
                            'counters', '--type', 'all', '--include-hidden',
                            '--zero', '--json')
                } catch {
                    $postResetResult = [pscustomobject][ordered]@{
                        exit_code = 9009
                        timed_out = $false
                        output_complete = $false
                        process_started = $false
                        process_id = 0
                        process_exited = $false
                        stdout = ''
                        stderr = $_.Exception.Message
                    }
                }
                $State.counter_global_post_reset =
                    Get-D01PktmonAllCounterSnapshotEvidence `
                        -Stdout ([string]$postResetResult.stdout) `
                        -Stderr ([string]$postResetResult.stderr) `
                        -ExitCode ([int]$postResetResult.exit_code) `
                        -ProcessExited ([bool]$postResetResult.process_exited) `
                        -OutputComplete ([bool]$postResetResult.output_complete) `
                        -ExpectedBaseline $State.counter_global_baseline
                $resetContractExact = $false
                try {
                    $null = Assert-D01PktmonCounterResetContract `
                        -Evidence $State.counter_reset_result
                    $resetContractExact = $true
                } catch {
                    $CleanupFailures.Add(
                        'PktMon reset command/process was not exact')
                }
                $postResetExact = $false
                try {
                    $null = Assert-D01PktmonAllCounterSnapshotContract `
                        -Evidence $State.counter_global_post_reset `
                        -ExpectedBaseline $State.counter_global_baseline `
                        -RequireAllZero -RequireRestored
                    $postResetExact = $true
                    $State.counter_reset_required = $false
                } catch {
                    $CleanupFailures.Add(
                        'PktMon post-reset all-counter state is not restored')
                }
                $State.counter_global_restored_verified =
                    $resetContractExact -and $postResetExact -and
                    (Test-D01TrustedCommandLedgerQuiescent)
                if (-not $State.counter_global_restored_verified) {
                    $CleanupFailures.Add(
                        'PktMon global counter rollback is not fully proven')
                }
            }
        }
    }
    if ($pktmonCliAvailable -and
        $State.pktmon_driver_stop_verified -and
        $State.etw_session_control_stop_verified -and
        (Test-Path -LiteralPath $State.etl_path -PathType Leaf)) {
        $pcapResult = Invoke-D01Pktmon -LogPath $State.command_log `
            -TimeoutSeconds 300 `
            -Arguments @(
                'etl2pcap', $State.etl_path, '--out', $State.pcapng_path
            )
        if ($pcapResult.exit_code -ne 0) {
            $CleanupFailures.Add('PktMon ETL to PCAPNG conversion failed')
        }
        $textResult = Invoke-D01Pktmon -LogPath $State.command_log `
            -TimeoutSeconds 300 `
            -Arguments @(
                'etl2txt', $State.etl_path, '--out', $State.text_path,
                '--brief'
            )
        if ($textResult.exit_code -ne 0) {
            $CleanupFailures.Add('PktMon ETL to text conversion failed')
        }
    } elseif (-not $pktmonCliAvailable) {
        $CleanupFailures.Add(
            'PktMon evidence conversion was refused without the trusted CLI')
    } elseif (-not $State.pktmon_driver_stop_verified) {
        $CleanupFailures.Add(
            'PktMon evidence conversion was refused before an exact driver stop')
    } elseif (-not $State.etw_session_control_stop_verified) {
        $CleanupFailures.Add(
            'PktMon evidence conversion was refused before an ID-bound ETW stop')
    } else {
        $CleanupFailures.Add('PktMon ETL evidence is missing')
    }

    if (-not $pktmonCliAvailable) {
        $CleanupFailures.Add(
            'PktMon filter cleanup was refused without the trusted CLI')
    } else {
        $inventoryResult = Invoke-D01Pktmon -LogPath $State.command_log `
            -Arguments @('filter', 'list')
        $inventoryCensus = if ($inventoryResult.exit_code -eq 0) {
            Get-D01PktmonInventoryCensus `
                -Text ([string]$inventoryResult.stdout)
        } else { $null }
        if ($null -eq $inventoryCensus -or
            -not [bool]$inventoryCensus.exact) {
            $CleanupFailures.Add(
                'PktMon cleanup filter census could not be proven exactly')
        } else {
            $ownedOnlyExact = [int]$inventoryCensus.entry_count -le
                @($State.filters_created).Count
            foreach ($entry in @($inventoryCensus.entries)) {
                $filterIndex = -1
                for ($candidateIndex = 0;
                    $candidateIndex -lt @($State.filters_created).Count;
                    $candidateIndex++) {
                    if ([string]$entry.name -ceq
                        [string]@($State.filters_created)[$candidateIndex]) {
                        $filterIndex = $candidateIndex
                        break
                    }
                }
                if ($filterIndex -lt 0) {
                    $ownedOnlyExact = $false
                    continue
                }
                $filter = [string]@($State.filters_created)[$filterIndex]
                $row = ([string]$entry.text).ToLowerInvariant()
                $expectedRows = @($State.owned_filter_rows | Where-Object {
                    [string]$_ -like ('*' + $filter.ToLowerInvariant() + '*')
                })
                $contentExact = $expectedRows.Count -eq 1 -and
                    $row -ceq [string]$expectedRows[0]
                if (-not $contentExact -and
                    -not [bool]$State.filters_applied_verified -and
                    $filterIndex -lt @($State.expected_filter_addresses).Count) {
                    $expectedAddress = Get-D01NormalizedIp -Address (
                        [string]@($State.expected_filter_addresses)[$filterIndex])
                    $expandedAddress = if ($expectedAddress.Contains(':')) {
                        Get-D01ExpandedIPv6 -Address (
                            [Net.IPAddress]::Parse($expectedAddress))
                    } else { $expectedAddress }
                    $contentExact =
                        $row.Contains($expectedAddress.ToLowerInvariant()) -or
                        $row.Contains($expandedAddress.ToLowerInvariant())
                }
                if (-not $contentExact) { $ownedOnlyExact = $false }
            }
            if (-not $ownedOnlyExact) {
                $CleanupFailures.Add(
                    'PktMon filter inventory was not exclusively run-owned; global removal refused')
            } elseif ([int]$inventoryCensus.entry_count -gt 0) {
                # This audited CLI implements `filter remove` as one global
                # remove-all IOCTL; it accepts no filter-name selector.
                $remove = Invoke-D01Pktmon -LogPath $State.command_log `
                    -Arguments @('filter', 'remove')
                if ($remove.exit_code -ne 0 -or
                    -not [bool]$remove.process_exited) {
                    $CleanupFailures.Add(
                        'PktMon run-owned filters could not be removed')
                }
            }
        }
        $afterResult = Invoke-D01Pktmon -LogPath $State.command_log `
            -Arguments @('filter', 'list')
        $afterText = [string]$afterResult.stdout
        if ($afterResult.exit_code -eq 0) {
            $State.filter_census_after =
                Get-D01PktmonInventoryCensus -Text $afterText
            if ([bool]$State.filter_census_after.exact) {
                $State.filter_rows_after = @(
                    $State.filter_census_after.entries | ForEach-Object {
                        ([string]$_.text).ToLowerInvariant()
                    } | Sort-Object)
            }
        }
        try {
            Set-Content -LiteralPath $State.filters_after_path -Encoding utf8 `
                -Value $afterText
        } catch {
            $CleanupFailures.Add('PktMon post-cleanup inventory could not be persisted')
        }
        $State.filters_absent_verified =
            $null -ne $State.filter_census_after -and
            [bool]$State.filter_census_after.exact -and
            [bool]$State.filter_census_after.empty
        $State.filter_inventory_restored_verified =
            [bool]$State.filter_inventory_before_valid -and
            $State.filters_absent_verified -and
            [int]$State.filter_census_after.entry_count -eq 0
    }
    if (-not $State.filters_absent_verified) {
        $CleanupFailures.Add('A run-owned PktMon filter remains')
    }
    if (-not $State.filter_inventory_restored_verified) {
        $CleanupFailures.Add(
            'PktMon filter inventory differs from its pre-run snapshot'
        )
    }
    if ($driverApiCompatible) {
        $State.pktmon_driver_status_final =
            Get-D01PktmonDriverStatus -ExpectedLibrarySha256 (
                [string]$State.pktmon_driver_api_compatibility.
                    library_sha256) -ExpectedDriverSha256 (
                [string]$State.pktmon_driver_api_compatibility.driver_sha256)
        try {
            $null = Assert-D01PktmonDriverStatusContract `
                -Evidence $State.pktmon_driver_status_final `
                -ExpectedLibrarySha256 (
                    [string]$State.pktmon_driver_api_compatibility.
                        library_sha256) `
                -RequireInactive -ExpectedConfigurationBaseline `
                    $State.pktmon_driver_status_before
            $State.pktmon_driver_configuration_restored_verified = $true
        } catch {
            $State.pktmon_driver_configuration_restored_verified = $false
            $CleanupFailures.Add(
                'PktMon driver final inactive/configuration state was not restored')
        }
    } else {
        $CleanupFailures.Add(
            'PktMon driver final status was not queried with an unsupported ABI')
    }
    $sessionAfter = Get-D01EtwLossEvidence -IdentityProbeOnly
    $sessionAbsentAfter = $false
    try {
        $null = Assert-D01EtwSessionNameProbeContract `
            -Probe $sessionAfter -RequireAbsent
        $sessionAbsentAfter = $true
    } catch {
        $CleanupFailures.Add(
            'PktMon ETW post-stop absence was not proven exactly')
    }
    $State.etw_session_stopped_verified = $sessionAbsentAfter -and (
        (-not [bool]$State.session_owned) -or
        [bool]$State.etw_session_control_stop_verified)
    if (-not $State.etw_session_stopped_verified) {
        $CleanupFailures.Add('PktMon ETW session remains active')
    }
    $State.cleanup_sequence_completed = $true
    if ([object]::ReferenceEquals(
            $script:d01PendingPktmonCleanupState, $State)) {
        $script:d01PendingPktmonCleanupState = $null
        $script:d01PendingPktmonCleanupFailures = $null
    }
    return $true
}

function Get-D01ExpandedIPv6 {
    param([Parameter(Mandatory = $true)][Net.IPAddress]$Address)

    $bytes = $Address.GetAddressBytes()
    $groups = for ($index = 0; $index -lt 16; $index += 2) {
        '{0:x4}' -f (($bytes[$index] -shl 8) -bor $bytes[$index + 1])
    }
    return $groups -join ':'
}

function Read-D01PcapUInt16 {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][int]$Offset,
        [Parameter(Mandatory = $true)][bool]$LittleEndian
    )

    if ($Offset -lt 0 -or $Offset + 2 -gt $Bytes.Length) {
        throw 'PCAP read exceeded the available UInt16 bytes'
    }
    if ($LittleEndian) {
        return [uint16]([uint32]$Bytes[$Offset] +
            ([uint32]$Bytes[$Offset + 1] * 256))
    }
    return [uint16](([uint32]$Bytes[$Offset] * 256) +
        [uint32]$Bytes[$Offset + 1])
}

function Read-D01PcapUInt32 {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][int]$Offset,
        [Parameter(Mandatory = $true)][bool]$LittleEndian
    )

    if ($Offset -lt 0 -or $Offset + 4 -gt $Bytes.Length) {
        throw 'PCAP read exceeded the available UInt32 bytes'
    }
    [uint64]$value = 0
    if ($LittleEndian) {
        for ($index = 3; $index -ge 0; $index--) {
            $value = ($value * 256) + [uint64]$Bytes[$Offset + $index]
        }
    } else {
        for ($index = 0; $index -lt 4; $index++) {
            $value = ($value * 256) + [uint64]$Bytes[$Offset + $index]
        }
    }
    return [uint32]$value
}

function Read-D01PcapUInt64 {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][int]$Offset,
        [Parameter(Mandatory = $true)][bool]$LittleEndian
    )

    if ($Offset -lt 0 -or $Offset + 8 -gt $Bytes.Length) {
        throw 'PCAP read exceeded the available UInt64 bytes'
    }
    [decimal]$value = 0
    if ($LittleEndian) {
        for ($index = 7; $index -ge 0; $index--) {
            $value = ($value * 256) + [decimal]$Bytes[$Offset + $index]
        }
    } else {
        for ($index = 0; $index -lt 8; $index++) {
            $value = ($value * 256) + [decimal]$Bytes[$Offset + $index]
        }
    }
    return [uint64]$value
}

function Read-D01PcapTimestampRaw64 {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][int]$Offset
    )

    # PCAPNG timestamps are not an endian-native UInt64.  They are two
    # endian-native UInt32 words, most-significant word first, exactly like
    # the timestamp_high/timestamp_low fields in an EPB.
    [uint64]$high = Read-D01PcapUInt32 -Bytes $Bytes -Offset $Offset `
        -LittleEndian $true
    [uint64]$low = Read-D01PcapUInt32 -Bytes $Bytes -Offset ($Offset + 4) `
        -LittleEndian $true
    return [uint64](($high -shl 32) -bor $low)
}

function Get-D01PcapTimestampTickNanoseconds {
    param([Parameter(Mandatory = $true)][byte]$Resolution)

    $binary = ($Resolution -band 0x80) -ne 0
    $exponent = [int]($Resolution -band 0x7f)
    # Decimal gives exact and locale-independent bounds.  Exponents which do
    # not fit its domain are rejected instead of being rounded through double.
    if (($binary -and $exponent -gt 93) -or
        (-not $binary -and $exponent -gt 28)) {
        throw 'PCAP timestamp resolution is outside the exact decimal domain'
    }
    [decimal]$denominator = 1
    for ($index = 0; $index -lt $exponent; $index++) {
        $denominator *= if ($binary) { 2 } else { 10 }
    }
    if ($denominator -le 0) {
        throw 'Invalid PCAP timestamp resolution'
    }
    return [decimal]1000000000 / $denominator
}

function Convert-D01PcapTimestampToUnixNs {
    param(
        [Parameter(Mandatory = $true)][uint64]$RawTimestamp,
        [Parameter(Mandatory = $true)][byte]$Resolution,
        [Parameter(Mandatory = $true)][Int64]$OffsetSeconds
    )

    [decimal]$tickNanoseconds =
        Get-D01PcapTimestampTickNanoseconds -Resolution $Resolution
    $nanoseconds = (
        [decimal]$RawTimestamp * $tickNanoseconds
    ) + ([decimal]$OffsetSeconds * [decimal]1000000000)
    if ($nanoseconds -lt [decimal][Int64]::MinValue -or
        $nanoseconds -gt [decimal][Int64]::MaxValue) {
        throw 'PCAP timestamp is outside Int64 Unix-nanosecond range'
    }
    return [Int64][Math]::Round(
        $nanoseconds, [MidpointRounding]::AwayFromZero
    )
}

function Open-D01ImmutableEvidenceSnapshot {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [switch]$MetadataOnly
    )

    $safePath = Assert-D01NoReparsePath -Path $Path -Kind File
    $stream = [IO.File]::Open(
        $safePath, [IO.FileMode]::Open, [IO.FileAccess]::Read,
        [IO.FileShare]::Read
    )
    try {
        if ($MetadataOnly) {
            $sha256 = Get-D01Sha256FromStream -Stream $stream
            $bytes = $null
        } elseif ($stream.Length -gt [int]::MaxValue) {
            throw 'Evidence snapshot exceeds the bounded in-memory parser limit'
        } else {
            $bytes = New-Object byte[] ([int]$stream.Length)
            $offset = 0
            while ($offset -lt $bytes.Length) {
                $read = $stream.Read($bytes, $offset, $bytes.Length - $offset)
                if ($read -le 0) {
                    throw 'Evidence snapshot ended before its declared length'
                }
                $offset += $read
            }
            $memory = [IO.MemoryStream]::new($bytes, $false)
            try { $sha256 = Get-D01Sha256FromStream -Stream $memory }
            finally { $memory.Dispose() }
        }
        $script:d01CandidateLocks.Add($stream)
        return [pscustomobject][ordered]@{
            bytes = $bytes
            byte_count = [Int64]$stream.Length
            sha256 = $sha256
            immutable_read_lock_held = $true
        }
    } catch {
        $stream.Dispose()
        throw
    }
}

function Read-D01UInt16LE {
    param([byte[]]$Bytes, [int]$Offset)
    return [BitConverter]::ToUInt16($Bytes, $Offset)
}

function Read-D01UInt32LE {
    param([byte[]]$Bytes, [int]$Offset)
    return [BitConverter]::ToUInt32($Bytes, $Offset)
}

function Read-D01UInt16BE {
    param([byte[]]$Bytes, [int]$Offset)
    return ([int]$Bytes[$Offset] -shl 8) -bor [int]$Bytes[$Offset + 1]
}

function Read-D01UInt32BE {
    param([byte[]]$Bytes, [int]$Offset)
    return [uint32](
        ([uint32]$Bytes[$Offset] -shl 24) -bor
        ([uint32]$Bytes[$Offset + 1] -shl 16) -bor
        ([uint32]$Bytes[$Offset + 2] -shl 8) -bor
        [uint32]$Bytes[$Offset + 3]
    )
}

function Convert-D01Packet {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Packet,
        [Parameter(Mandatory = $true)][int]$LinkType,
        [Parameter(Mandatory = $true)][double]$TimestampMs
    )

    $offset = 0
    $etherType = 0
    if ($LinkType -eq 1) {
        if ($Packet.Length -lt 14) { return $null }
        $etherType = Read-D01UInt16BE -Bytes $Packet -Offset 12
        $offset = 14
        while ($etherType -eq 0x8100 -or $etherType -eq 0x88a8) {
            if ($Packet.Length -lt $offset + 4) { return $null }
            $etherType = Read-D01UInt16BE -Bytes $Packet -Offset ($offset + 2)
            $offset += 4
        }
    } elseif ($LinkType -eq 101) {
        if ($Packet.Length -lt 1) { return $null }
        $version = $Packet[0] -shr 4
        $etherType = if ($version -eq 4) { 0x0800 } elseif ($version -eq 6) {
            0x86dd
        } else { 0 }
    } elseif ($LinkType -eq 228) {
        $etherType = 0x0800
    } elseif ($LinkType -eq 229) {
        $etherType = 0x86dd
    } else {
        return $null
    }

    if ($etherType -eq 0x0800) {
        if ($Packet.Length -lt $offset + 20 -or
            ($Packet[$offset] -shr 4) -ne 4) { return $null }
        $ihl = ($Packet[$offset] -band 0x0f) * 4
        if ($ihl -lt 20 -or $Packet.Length -lt $offset + $ihl) { return $null }
        $totalLength = Read-D01UInt16BE -Bytes $Packet -Offset ($offset + 2)
        $ipEnd = $offset + $totalLength
        $fragmentField = Read-D01UInt16BE -Bytes $Packet `
            -Offset ($offset + 6)
        if ($totalLength -lt $ihl -or $ipEnd -gt $Packet.Length -or
            ($fragmentField -band 0x3fff) -ne 0) { return $null }
        $protocol = [int]$Packet[$offset + 9]
        $sourceBytes = New-Object byte[] 4
        $destinationBytes = New-Object byte[] 4
        [Array]::Copy($Packet, $offset + 12, $sourceBytes, 0, 4)
        [Array]::Copy($Packet, $offset + 16, $destinationBytes, 0, 4)
        $source = ([Net.IPAddress]::new($sourceBytes)).ToString()
        $destination = ([Net.IPAddress]::new($destinationBytes)).ToString()
        $transportOffset = $offset + $ihl
        if ($protocol -eq 6) {
            if ($ipEnd -lt $transportOffset + 20) { return $null }
            $tcpHeaderLength = ($Packet[$transportOffset + 12] -shr 4) * 4
            if ($tcpHeaderLength -lt 20 -or
                $transportOffset + $tcpHeaderLength -gt $ipEnd) { return $null }
            $sourcePort = Read-D01UInt16BE -Bytes $Packet -Offset $transportOffset
            $destinationPort = Read-D01UInt16BE -Bytes $Packet `
                -Offset ($transportOffset + 2)
            $flags = [int]$Packet[$transportOffset + 13]
            return [pscustomobject][ordered]@{
                timestamp_ms = $TimestampMs
                family = 'IPv4'
                protocol = 'TCP'
                source = $source
                destination = $destination
                source_port = $sourcePort
                destination_port = $destinationPort
                sequence_number = Read-D01UInt32BE -Bytes $Packet `
                    -Offset ($transportOffset + 4)
                acknowledgement_number = Read-D01UInt32BE -Bytes $Packet `
                    -Offset ($transportOffset + 8)
                syn = ($flags -band 0x02) -ne 0
                ack = ($flags -band 0x10) -ne 0
                rst = ($flags -band 0x04) -ne 0
                fin = ($flags -band 0x01) -ne 0
                icmp_type = $null
                quoted_family = $null
                quoted_protocol = $null
                quoted_source = $null
                quoted_destination = $null
                quoted_source_port = $null
                quoted_destination_port = $null
                quoted_sequence_number = $null
                quoted_parse_complete = $null
            }
        }
        if ($protocol -eq 17) {
            if ($ipEnd -lt $transportOffset + 8) { return $null }
            $udpLength = Read-D01UInt16BE -Bytes $Packet `
                -Offset ($transportOffset + 4)
            if ($udpLength -lt 8 -or $transportOffset + $udpLength -gt $ipEnd) {
                return $null
            }
            return [pscustomobject][ordered]@{
                timestamp_ms = $TimestampMs
                family = 'IPv4'
                protocol = 'UDP'
                source = $source
                destination = $destination
                source_port = Read-D01UInt16BE -Bytes $Packet `
                    -Offset $transportOffset
                destination_port = Read-D01UInt16BE -Bytes $Packet `
                    -Offset ($transportOffset + 2)
                sequence_number = $null
                acknowledgement_number = $null
                syn = $false
                ack = $false
                rst = $false
                fin = $false
                icmp_type = $null
                quoted_family = $null
                quoted_protocol = $null
                quoted_source = $null
                quoted_destination = $null
                quoted_source_port = $null
                quoted_destination_port = $null
                quoted_sequence_number = $null
                quoted_parse_complete = $null
            }
        }
        if ($protocol -eq 1) {
            if ($ipEnd -lt $transportOffset + 8) { return $null }
            $icmpType = [int]$Packet[$transportOffset]
            $quotedFamily = $null
            $quotedProtocol = $null
            $quotedSource = $null
            $quotedDestination = $null
            $quotedSourcePort = $null
            $quotedDestinationPort = $null
            $quotedSequence = $null
            $quotedParseComplete = $null
            if ($icmpType -in @(3, 4, 5, 11, 12)) {
                $quotedParseComplete = $false
                $quotedOffset = $transportOffset + 8
                if ($ipEnd -ge $quotedOffset + 20 -and
                    ($Packet[$quotedOffset] -shr 4) -eq 4) {
                    $quotedIhl = ($Packet[$quotedOffset] -band 0x0f) * 4
                    if ($quotedIhl -ge 20 -and
                        $ipEnd -ge $quotedOffset + $quotedIhl + 8) {
                        $quotedFamily = 'IPv4'
                        $quotedSourceBytes = New-Object byte[] 4
                        $quotedDestinationBytes = New-Object byte[] 4
                        [Array]::Copy($Packet, $quotedOffset + 12,
                            $quotedSourceBytes, 0, 4)
                        [Array]::Copy($Packet, $quotedOffset + 16,
                            $quotedDestinationBytes, 0, 4)
                        $quotedSource = ([Net.IPAddress]::new(
                            $quotedSourceBytes)).ToString()
                        $quotedDestination = ([Net.IPAddress]::new(
                            $quotedDestinationBytes)).ToString()
                        $quotedIpProtocol = [int]$Packet[$quotedOffset + 9]
                        $quotedTransport = $quotedOffset + $quotedIhl
                        if ($quotedIpProtocol -eq 6) {
                            $quotedProtocol = 'TCP'
                            $quotedSourcePort = Read-D01UInt16BE `
                                -Bytes $Packet -Offset $quotedTransport
                            $quotedDestinationPort = Read-D01UInt16BE `
                                -Bytes $Packet -Offset ($quotedTransport + 2)
                            $quotedSequence = Read-D01UInt32BE `
                                -Bytes $Packet -Offset ($quotedTransport + 4)
                        } elseif ($quotedIpProtocol -eq 17) {
                            $quotedProtocol = 'UDP'
                            $quotedSourcePort = Read-D01UInt16BE `
                                -Bytes $Packet -Offset $quotedTransport
                            $quotedDestinationPort = Read-D01UInt16BE `
                                -Bytes $Packet -Offset ($quotedTransport + 2)
                        } else {
                            $quotedProtocol = 'IPPROTO-' +
                                [string]$quotedIpProtocol
                        }
                        $quotedParseComplete = $true
                    }
                }
                if (-not $quotedParseComplete) { return $null }
            }
            return [pscustomobject][ordered]@{
                timestamp_ms = $TimestampMs
                family = 'IPv4'
                protocol = 'ICMPv4'
                source = $source
                destination = $destination
                source_port = $null
                destination_port = $null
                sequence_number = $null
                acknowledgement_number = $null
                syn = $false
                ack = $false
                rst = $false
                fin = $false
                icmp_type = $icmpType
                quoted_family = $quotedFamily
                quoted_protocol = $quotedProtocol
                quoted_source = $quotedSource
                quoted_destination = $quotedDestination
                quoted_source_port = $quotedSourcePort
                quoted_destination_port = $quotedDestinationPort
                quoted_sequence_number = $quotedSequence
                quoted_parse_complete = $quotedParseComplete
            }
        }
        # A structurally complete non-TCP IP packet is relevant capture
        # metadata, not a parser failure.  Retaining it prevents an ambient
        # ICMP/other-IP frame from suppressing typed product adjudication.
        return [pscustomobject][ordered]@{
            timestamp_ms = $TimestampMs
            family = 'IPv4'
            protocol = 'IPPROTO-' + [string]$protocol
            source = $source
            destination = $destination
            source_port = $null
            destination_port = $null
            sequence_number = $null
            acknowledgement_number = $null
            syn = $false
            ack = $false
            rst = $false
            fin = $false
            icmp_type = $null
            quoted_family = $null
            quoted_protocol = $null
            quoted_source = $null
            quoted_destination = $null
            quoted_source_port = $null
            quoted_destination_port = $null
            quoted_sequence_number = $null
            quoted_parse_complete = $null
        }
    }

    if ($etherType -ne 0x86dd -or $Packet.Length -lt $offset + 40 -or
        ($Packet[$offset] -shr 4) -ne 6) {
        return $null
    }
    $ipv6PayloadLength = Read-D01UInt16BE -Bytes $Packet `
        -Offset ($offset + 4)
    if ($ipv6PayloadLength -eq 0 -or
        $offset + 40 + $ipv6PayloadLength -gt $Packet.Length) {
        return $null
    }
    $ipv6End = $offset + 40 + $ipv6PayloadLength
    $nextHeader = [int]$Packet[$offset + 6]
    $sourceV6Bytes = New-Object byte[] 16
    $destinationV6Bytes = New-Object byte[] 16
    [Array]::Copy($Packet, $offset + 8, $sourceV6Bytes, 0, 16)
    [Array]::Copy($Packet, $offset + 24, $destinationV6Bytes, 0, 16)
    $sourceV6 = ([Net.IPAddress]::new($sourceV6Bytes)).ToString()
    $destinationV6 = ([Net.IPAddress]::new($destinationV6Bytes)).ToString()
    $transport = $offset + 40
    while ($nextHeader -in @(0, 43, 44, 51, 60)) {
        if ($nextHeader -eq 44 -or $ipv6End -lt $transport + 8) {
            return $null
        }
        $following = [int]$Packet[$transport]
        $extensionBytes = if ($nextHeader -eq 44) {
            8
        } elseif ($nextHeader -eq 51) {
            ([int]$Packet[$transport + 1] + 2) * 4
        } else {
            ([int]$Packet[$transport + 1] + 1) * 8
        }
        $transport += $extensionBytes
        $nextHeader = $following
        if ($ipv6End -lt $transport) { return $null }
    }
    if ($nextHeader -eq 58 -and $ipv6End -ge $transport + 8) {
        $quotedFamily = $null
        $quotedProtocol = $null
        $quotedSource = $null
        $quotedDestination = $null
        $quotedSourcePort = $null
        $quotedDestinationPort = $null
        $quotedSequence = $null
        $quotedParseComplete = $false
        $quotedOffset = $transport + 8
        if ($ipv6End -ge $quotedOffset + 40 -and
            ($Packet[$quotedOffset] -shr 4) -eq 6) {
            $quotedFamily = 'IPv6'
            $quotedNext = [int]$Packet[$quotedOffset + 6]
            $quotedSourceBytes = New-Object byte[] 16
            $quotedDestinationBytes = New-Object byte[] 16
            [Array]::Copy(
                $Packet, $quotedOffset + 8, $quotedSourceBytes, 0, 16
            )
            [Array]::Copy(
                $Packet, $quotedOffset + 24, $quotedDestinationBytes, 0, 16
            )
            $quotedSource = ([Net.IPAddress]::new(
                $quotedSourceBytes
            )).ToString()
            $quotedDestination = ([Net.IPAddress]::new(
                $quotedDestinationBytes
            )).ToString()
            $quotedTransport = $quotedOffset + 40
            while ($quotedNext -in @(0, 43, 44, 51, 60)) {
                if ($ipv6End -lt $quotedTransport + 8) { break }
                $quotedFollowing = [int]$Packet[$quotedTransport]
                $quotedExtensionBytes = if ($quotedNext -eq 44) {
                    8
                } elseif ($quotedNext -eq 51) {
                    ([int]$Packet[$quotedTransport + 1] + 2) * 4
                } else {
                    ([int]$Packet[$quotedTransport + 1] + 1) * 8
                }
                $quotedTransport += $quotedExtensionBytes
                $quotedNext = $quotedFollowing
            }
            if ($quotedNext -eq 6 -and
                $ipv6End -ge $quotedTransport + 8) {
                $quotedProtocol = 'TCP'
                $quotedSourcePort = Read-D01UInt16BE -Bytes $Packet `
                    -Offset $quotedTransport
                $quotedDestinationPort = Read-D01UInt16BE -Bytes $Packet `
                    -Offset ($quotedTransport + 2)
                $quotedSequence = Read-D01UInt32BE -Bytes $Packet `
                    -Offset ($quotedTransport + 4)
                $quotedParseComplete = $true
            } elseif ($quotedNext -notin @(0, 43, 44, 51, 60)) {
                $quotedProtocol = 'IPPROTO-' + [string]$quotedNext
                $quotedParseComplete = $true
            }
        }
        $icmpType = [int]$Packet[$transport]
        if ($icmpType -in @(1, 2, 3, 4) -and
            -not $quotedParseComplete) {
            # A truncated ICMPv6 error quote could be the only evidence that
            # the target SYN was rejected. Treat it as non-adjudicable rather
            # than silently converting it into a proved blackhole.
            return $null
        }
        return [pscustomobject][ordered]@{
            timestamp_ms = $TimestampMs
            family = 'IPv6'
            protocol = 'ICMPv6'
            source = $sourceV6
            destination = $destinationV6
            source_port = $null
            destination_port = $null
            sequence_number = $null
            acknowledgement_number = $null
            syn = $false
            ack = $false
            rst = $false
            fin = $false
            icmp_type = $icmpType
            quoted_family = $quotedFamily
            quoted_protocol = $quotedProtocol
            quoted_source = $quotedSource
            quoted_destination = $quotedDestination
            quoted_source_port = $quotedSourcePort
            quoted_destination_port = $quotedDestinationPort
            quoted_sequence_number = $quotedSequence
            quoted_parse_complete = $quotedParseComplete
        }
    }
    if ($nextHeader -eq 17) {
        if ($ipv6End -lt $transport + 8) { return $null }
        $v6UdpLength = Read-D01UInt16BE -Bytes $Packet `
            -Offset ($transport + 4)
        if ($v6UdpLength -lt 8 -or $transport + $v6UdpLength -gt $ipv6End) {
            return $null
        }
        return [pscustomobject][ordered]@{
            timestamp_ms = $TimestampMs
            family = 'IPv6'
            protocol = 'UDP'
            source = $sourceV6
            destination = $destinationV6
            source_port = Read-D01UInt16BE -Bytes $Packet -Offset $transport
            destination_port = Read-D01UInt16BE -Bytes $Packet `
                -Offset ($transport + 2)
            sequence_number = $null
            acknowledgement_number = $null
            syn = $false
            ack = $false
            rst = $false
            fin = $false
            icmp_type = $null
            quoted_family = $null
            quoted_protocol = $null
            quoted_source = $null
            quoted_destination = $null
            quoted_source_port = $null
            quoted_destination_port = $null
            quoted_sequence_number = $null
            quoted_parse_complete = $null
        }
    }
    if ($nextHeader -ne 6) {
        return [pscustomobject][ordered]@{
            timestamp_ms = $TimestampMs
            family = 'IPv6'
            protocol = 'IPPROTO-' + [string]$nextHeader
            source = $sourceV6
            destination = $destinationV6
            source_port = $null
            destination_port = $null
            sequence_number = $null
            acknowledgement_number = $null
            syn = $false
            ack = $false
            rst = $false
            fin = $false
            icmp_type = $null
            quoted_family = $null
            quoted_protocol = $null
            quoted_source = $null
            quoted_destination = $null
            quoted_source_port = $null
            quoted_destination_port = $null
            quoted_sequence_number = $null
            quoted_parse_complete = $null
        }
    }
    if ($ipv6End -lt $transport + 20) { return $null }
    $v6TcpHeaderLength = ($Packet[$transport + 12] -shr 4) * 4
    if ($v6TcpHeaderLength -lt 20 -or
        $transport + $v6TcpHeaderLength -gt $ipv6End) { return $null }
    $sourceV6Port = Read-D01UInt16BE -Bytes $Packet -Offset $transport
    $destinationV6Port = Read-D01UInt16BE -Bytes $Packet -Offset ($transport + 2)
    $v6Flags = [int]$Packet[$transport + 13]
    return [pscustomobject][ordered]@{
        timestamp_ms = $TimestampMs
        family = 'IPv6'
        protocol = 'TCP'
        source = $sourceV6
        destination = $destinationV6
        source_port = $sourceV6Port
        destination_port = $destinationV6Port
        sequence_number = Read-D01UInt32BE -Bytes $Packet `
            -Offset ($transport + 4)
        acknowledgement_number = Read-D01UInt32BE -Bytes $Packet `
            -Offset ($transport + 8)
        syn = ($v6Flags -band 0x02) -ne 0
        ack = ($v6Flags -band 0x10) -ne 0
        rst = ($v6Flags -band 0x04) -ne 0
        fin = ($v6Flags -band 0x01) -ne 0
        icmp_type = $null
        quoted_family = $null
        quoted_protocol = $null
        quoted_source = $null
        quoted_destination = $null
        quoted_source_port = $null
        quoted_destination_port = $null
        quoted_sequence_number = $null
        quoted_parse_complete = $null
    }
}

function Get-D01PcapNgTcpRecords {
    param([Parameter(Mandatory = $true)][string]$Path)

    $snapshot = Open-D01ImmutableEvidenceSnapshot -Path $Path
    $bytes = [byte[]]$snapshot.bytes
    if ($bytes.Length -lt 28 -or
        (Read-D01UInt32LE -Bytes $bytes -Offset 0) -ne 0x0a0d0d0a -or
        (Read-D01UInt32LE -Bytes $bytes -Offset 8) -ne 0x1a2b3c4d) {
        throw 'Only little-endian PCAPNG produced by pktmon is supported'
    }
    $interfaces = @{}
    $interfaceRecords = [System.Collections.Generic.List[object]]::new()
    $interfaceStatisticsRecords =
        [System.Collections.Generic.List[object]]::new()
    $packets = [System.Collections.Generic.List[object]]::new()
    $parserComplete = $true
    $blockErrorCount = 0
    $idbOptionErrorCount = 0
    $unknownInterfaceFrameCount = 0
    $unsupportedLinkTypeFrameCount = 0
    $unsupportedPacketBlockCount = 0
    $unknownBlockCount = 0
    $truncatedFrameCount = 0
    $nonAdjudicableFrameCount = 0
    $parseNullFrameCount = 0
    $enhancedPacketCount = 0
    $enhancedPacketOptionErrorCount = 0
    $enhancedPacketDropcountPresentCount = 0
    $enhancedPacketNonzeroDropcountCount = 0
    $enhancedPacketFlagsPresentCount = 0
    $enhancedPacketErrorFlagsCount = 0
    $interfaceStatisticsBlockCount = 0
    $interfaceStatisticsOptionErrorCount = 0
    $interfaceStatisticsMissingLossCount = 0
    $interfaceStatisticsMissingEndtimeCount = 0
    $interfaceStatisticsNonzeroLossCount = 0
    $sectionIndex = -1
    $interfaceNumber = 0
    $offset = 0
    while ($offset + 12 -le $bytes.Length) {
        $type = Read-D01UInt32LE -Bytes $bytes -Offset $offset
        $length = [int](Read-D01UInt32LE -Bytes $bytes -Offset ($offset + 4))
        if ($length -lt 12 -or ($length % 4) -ne 0 -or
            $offset + $length -gt $bytes.Length -or
            (Read-D01UInt32LE -Bytes $bytes -Offset ($offset + $length - 4)) -ne
                [uint32]$length) {
            $parserComplete = $false
            $blockErrorCount++
            break
        }
        if ($type -eq 0x0a0d0d0a) {
            if ($length -lt 28 -or
                (Read-D01UInt32LE -Bytes $bytes -Offset ($offset + 8)) -ne
                    0x1a2b3c4d) {
                $parserComplete = $false
                $blockErrorCount++
            } else {
                $sectionIndex++
                $interfaceNumber = 0
                $interfaces = @{}
            }
        } elseif ($type -eq 1) {
            if ($sectionIndex -lt 0 -or $length -lt 20) {
                $parserComplete = $false
                $blockErrorCount++
                $offset += $length
                continue
            }
            $linkType = Read-D01UInt16LE -Bytes $bytes -Offset ($offset + 8)
            $snapLength = [uint32](Read-D01UInt32LE -Bytes $bytes `
                -Offset ($offset + 12))
            [byte]$resolution = 6
            $timestampOffsetSeconds = 0L
            $interfaceName = ''
            $interfaceDescription = ''
            $optionsValid = $true
            $option = $offset + 16
            $optionEnd = $offset + $length - 4
            while ($option -lt $optionEnd) {
                if ($option + 4 -gt $optionEnd) {
                    $optionsValid = $false
                    break
                }
                $code = Read-D01UInt16LE -Bytes $bytes -Offset $option
                $optionLength = Read-D01UInt16LE -Bytes $bytes `
                    -Offset ($option + 2)
                $paddedOptionLength = ($optionLength + 3) -band (-bnot 3)
                if ($code -eq 0) {
                    if ($optionLength -ne 0) { $optionsValid = $false }
                    break
                }
                if ($option + 4 + $paddedOptionLength -gt $optionEnd) {
                    $optionsValid = $false
                    break
                }
                if ($code -in @(2, 3)) {
                    try {
                        $optionText = [Text.Encoding]::UTF8.GetString(
                            $bytes, $option + 4, $optionLength
                        ).Trim([char]0)
                        if ($code -eq 2) {
                            $interfaceName = $optionText
                        } else {
                            $interfaceDescription = $optionText
                        }
                    } catch {
                        $optionsValid = $false
                        break
                    }
                }
                if ($code -eq 9 -and $optionLength -ne 1) {
                    $optionsValid = $false
                    break
                }
                if ($code -eq 9) {
                    $resolution = [byte]$bytes[$option + 4]
                }
                if ($code -eq 10) {
                    # Deprecated if_tzone would make epoch normalization
                    # ambiguous across tool versions.
                    $optionsValid = $false
                    break
                }
                if ($code -eq 14) {
                    if ($optionLength -ne 8) {
                        $optionsValid = $false
                        break
                    }
                    $timestampOffsetSeconds = [BitConverter]::ToInt64(
                        $bytes, $option + 4)
                }
                $option += 4 + $paddedOptionLength
            }
            [decimal]$timestampTickNanoseconds = 0
            try {
                $timestampTickNanoseconds =
                    Get-D01PcapTimestampTickNanoseconds `
                        -Resolution $resolution
                # Socket samples and packet ordering are only adjudicated at
                # millisecond-or-better capture resolution.
                if ($timestampTickNanoseconds -gt [decimal]1000000) {
                    $optionsValid = $false
                }
            } catch { $optionsValid = $false }
            if (-not $optionsValid) {
                $parserComplete = $false
                $idbOptionErrorCount++
            }
            $interfaceRecord = [pscustomobject][ordered]@{
                section_index = $sectionIndex
                interface_id = $interfaceNumber
                link_type = [int]$linkType
                snap_length = [uint32]$snapLength
                timestamp_resolution_raw = [int]$resolution
                timestamp_tick_nanoseconds = $timestampTickNanoseconds
                timestamp_resolution_adjudicable =
                    $timestampTickNanoseconds -gt 0 -and
                    $timestampTickNanoseconds -le [decimal]1000000
                timestamp_offset_seconds = [Int64]$timestampOffsetSeconds
                supported_link_type = [int]$linkType -in @(1, 101, 228, 229)
                interface_name_sha256 = if ($interfaceName) {
                    Get-D01StringSha256 -Value $interfaceName
                } else { '' }
                interface_description_sha256 = if ($interfaceDescription) {
                    Get-D01StringSha256 -Value $interfaceDescription
                } else { '' }
                options_valid = $optionsValid
                _interface_name = $interfaceName
                _interface_description = $interfaceDescription
            }
            $interfaces[$interfaceNumber] = $interfaceRecord
            $interfaceRecords.Add($interfaceRecord)
            $interfaceNumber++
        } elseif ($type -in @(2, 3)) {
            # Obsolete Packet Blocks and Simple Packet Blocks also carry frame
            # bytes. This parser cannot preserve their interface/timestamp
            # binding, so their presence makes absence evidence inadmissible.
            $unsupportedPacketBlockCount++
            $nonAdjudicableFrameCount++
            $parserComplete = $false
        } elseif ($type -eq 6) {
            $enhancedPacketCount++
            if ($sectionIndex -lt 0 -or $length -lt 32) {
                $parserComplete = $false
                $blockErrorCount++
                $nonAdjudicableFrameCount++
                $offset += $length
                continue
            }
            $interfaceId = [int](Read-D01UInt32LE -Bytes $bytes `
                -Offset ($offset + 8))
            $capturedLength = [int](Read-D01UInt32LE -Bytes $bytes `
                -Offset ($offset + 20))
            $originalLength = [int](Read-D01UInt32LE -Bytes $bytes `
                -Offset ($offset + 24))
            $paddedCapturedLength = ($capturedLength + 3) -band (-bnot 3)
            if (-not $interfaces.ContainsKey($interfaceId)) {
                $unknownInterfaceFrameCount++
                $nonAdjudicableFrameCount++
                $parserComplete = $false
            } elseif ($capturedLength -lt 0 -or $originalLength -lt 0 -or
                $capturedLength -ne $originalLength -or
                [uint32]$interfaces[$interfaceId].snap_length -eq 0 -or
                [uint32]$originalLength -gt
                    [uint32]$interfaces[$interfaceId].snap_length -or
                $offset + 28 + $paddedCapturedLength -gt
                    $offset + $length - 4) {
                $truncatedFrameCount++
                $nonAdjudicableFrameCount++
                $parserComplete = $false
            } elseif (-not [bool]$interfaces[$interfaceId].supported_link_type) {
                $unsupportedLinkTypeFrameCount++
                $nonAdjudicableFrameCount++
                $parserComplete = $false
            } else {
                $high = [UInt64](Read-D01UInt32LE -Bytes $bytes `
                    -Offset ($offset + 12))
                $low = [UInt64](Read-D01UInt32LE -Bytes $bytes `
                    -Offset ($offset + 16))
                $ticks = ($high -shl 32) -bor $low
                $packetEpochUnixNs = Convert-D01PcapTimestampToUnixNs `
                    -RawTimestamp $ticks `
                    -Resolution ([byte]$interfaces[$interfaceId].
                        timestamp_resolution_raw) `
                    -OffsetSeconds ([Int64]$interfaces[$interfaceId].
                        timestamp_offset_seconds)
                $timeMs = [double](
                    [decimal]$packetEpochUnixNs / [decimal]1000000)
                $packetBytes = New-Object byte[] $capturedLength
                [Array]::Copy($bytes, $offset + 28, $packetBytes, 0,
                    $capturedLength)
                $epbOptionsValid = $true
                $epbDropCount = $null
                $epbFlags = $null
                $option = $offset + 28 + $paddedCapturedLength
                $optionEnd = $offset + $length - 4
                while ($epbOptionsValid -and $option -lt $optionEnd) {
                    if ($option + 4 -gt $optionEnd) {
                        $epbOptionsValid = $false
                        break
                    }
                    $code = Read-D01UInt16LE -Bytes $bytes -Offset $option
                    $optionLength = Read-D01UInt16LE -Bytes $bytes `
                        -Offset ($option + 2)
                    $paddedOptionLength = ($optionLength + 3) -band (-bnot 3)
                    if ($code -eq 0) {
                        if ($optionLength -ne 0) { $epbOptionsValid = $false }
                        break
                    }
                    if ($option + 4 + $paddedOptionLength -gt $optionEnd) {
                        $epbOptionsValid = $false
                        break
                    }
                    if ($code -eq 2) {
                        if ($optionLength -ne 4 -or $null -ne $epbFlags) {
                            $epbOptionsValid = $false
                            break
                        }
                        $epbFlags = Read-D01UInt32LE -Bytes $bytes `
                            -Offset ($option + 4)
                    } elseif ($code -eq 4) {
                        if ($optionLength -ne 8 -or $null -ne $epbDropCount) {
                            $epbOptionsValid = $false
                            break
                        }
                        $epbDropCount = Read-D01PcapUInt64 -Bytes $bytes `
                            -Offset ($option + 4) -LittleEndian $true
                    }
                    $option += 4 + $paddedOptionLength
                }
                if (-not $epbOptionsValid) {
                    $enhancedPacketOptionErrorCount++
                    $nonAdjudicableFrameCount++
                    $parserComplete = $false
                }
                if ($null -ne $epbDropCount) {
                    $enhancedPacketDropcountPresentCount++
                    if ([uint64]$epbDropCount -ne 0) {
                        $enhancedPacketNonzeroDropcountCount++
                    }
                }
                if ($null -ne $epbFlags) {
                    $enhancedPacketFlagsPresentCount++
                    # Bits 16..23 are the standardized link-layer reception
                    # errors; bits 9..15 and 24..31 are reserved.  Any such
                    # bit makes the captured frame inadmissible for absence
                    # or exact-handshake evidence.
                    if (([UInt32]$epbFlags -band [UInt32]0xfffffe00) -ne 0) {
                        $enhancedPacketErrorFlagsCount++
                        $epbOptionsValid = $false
                        $enhancedPacketOptionErrorCount++
                        $nonAdjudicableFrameCount++
                        $parserComplete = $false
                    }
                }
                $parsed = if ($epbOptionsValid) {
                    Convert-D01Packet -Packet $packetBytes `
                        -LinkType $interfaces[$interfaceId].link_type `
                        -TimestampMs $timeMs
                } else { $null }
                if ($null -eq $parsed) {
                    if ($epbOptionsValid) {
                        $parseNullFrameCount++
                        $nonAdjudicableFrameCount++
                        $parserComplete = $false
                    }
                } else {
                    $parsed.family =
                        ([string]$parsed.family).ToLowerInvariant()
                    $parsed.protocol =
                        ([string]$parsed.protocol).ToLowerInvariant()
                    $parsed | Add-Member -NotePropertyName source_address `
                        -NotePropertyValue ([string]$parsed.source)
                    $parsed | Add-Member -NotePropertyName destination_address `
                        -NotePropertyValue ([string]$parsed.destination)
                    $parsed | Add-Member -NotePropertyName tcp_sequence_number `
                        -NotePropertyValue $parsed.sequence_number
                    $parsed | Add-Member -NotePropertyName initial_syn `
                        -NotePropertyValue (
                            [bool]$parsed.syn -and -not [bool]$parsed.ack)
                    $parsed | Add-Member -NotePropertyName five_tuple `
                        -NotePropertyValue (
                            '{0}|{1}|{2}|{3}|{4}' -f
                            ([string]$parsed.protocol).ToLowerInvariant(),
                            [string]$parsed.source, $parsed.source_port,
                            [string]$parsed.destination,
                            $parsed.destination_port)
                    $parsed | Add-Member -NotePropertyName packet_epoch_unix_ns `
                        -NotePropertyValue $packetEpochUnixNs
                    $parsed | Add-Member -NotePropertyName section_index `
                        -NotePropertyValue $sectionIndex
                    $parsed | Add-Member -NotePropertyName capture_interface_id `
                        -NotePropertyValue $interfaceId
                    $parsed | Add-Member -NotePropertyName capture_link_type `
                        -NotePropertyValue ([int]$interfaces[$interfaceId].link_type)
                    $parsed | Add-Member -NotePropertyName captured_length `
                        -NotePropertyValue $capturedLength
                    $parsed | Add-Member -NotePropertyName original_length `
                        -NotePropertyValue $originalLength
                    $parsed | Add-Member -NotePropertyName frame_complete `
                        -NotePropertyValue $true
                    $parsed | Add-Member -NotePropertyName epb_dropcount `
                        -NotePropertyValue $epbDropCount
                    $parsed | Add-Member -NotePropertyName epb_flags `
                        -NotePropertyValue $epbFlags
                    $parsed | Add-Member -NotePropertyName packet_index `
                        -NotePropertyValue ([int]$packets.Count)
                    $packets.Add($parsed)
                }
            }
        } elseif ($type -eq 5) {
            # Interface Statistics Blocks can declare capture loss. Consume
            # their mandatory-for-D01 ifdrop/osdrop evidence rather than
            # silently treating the block as harmless metadata.
            $interfaceStatisticsBlockCount++
            $statisticsValid = $true
            $interfaceId = -1
            $startTimeRaw = $null
            $endTimeRaw = $null
            $sampleTimeRaw = $null
            $ifDrop = $null
            $osDrop = $null
            if ($sectionIndex -lt 0 -or $length -lt 24) {
                $statisticsValid = $false
            } else {
                $interfaceId = [int](Read-D01UInt32LE -Bytes $bytes `
                    -Offset ($offset + 8))
                $sampleTimeRaw = Read-D01PcapTimestampRaw64 `
                    -Bytes $bytes -Offset ($offset + 12)
                if (-not $interfaces.ContainsKey($interfaceId)) {
                    $statisticsValid = $false
                }
                $option = $offset + 20
                $optionEnd = $offset + $length - 4
                while ($statisticsValid -and $option -lt $optionEnd) {
                    if ($option + 4 -gt $optionEnd) {
                        $statisticsValid = $false
                        break
                    }
                    $code = Read-D01UInt16LE -Bytes $bytes -Offset $option
                    $optionLength = Read-D01UInt16LE -Bytes $bytes `
                        -Offset ($option + 2)
                    $paddedOptionLength =
                        ($optionLength + 3) -band (-bnot 3)
                    if ($code -eq 0) {
                        if ($optionLength -ne 0) {
                            $statisticsValid = $false
                        }
                        break
                    }
                    if ($option + 4 + $paddedOptionLength -gt $optionEnd -or
                        $code -notin @(1, 2, 3, 4, 5, 6, 7, 8)) {
                        $statisticsValid = $false
                        break
                    }
                    if ($code -in @(2, 3, 4, 5, 6, 7, 8) -and
                        $optionLength -ne 8) {
                        $statisticsValid = $false
                        break
                    }
                    if ($code -eq 5) {
                        if ($null -ne $ifDrop) {
                            $statisticsValid = $false
                            break
                        }
                        $ifDrop = Read-D01PcapUInt64 -Bytes $bytes `
                            -Offset ($option + 4) -LittleEndian $true
                    } elseif ($code -eq 2) {
                        if ($null -ne $startTimeRaw) {
                            $statisticsValid = $false
                            break
                        }
                        $startTimeRaw = Read-D01PcapTimestampRaw64 `
                            -Bytes $bytes -Offset ($option + 4)
                    } elseif ($code -eq 3) {
                        if ($null -ne $endTimeRaw) {
                            $statisticsValid = $false
                            break
                        }
                        $endTimeRaw = Read-D01PcapTimestampRaw64 `
                            -Bytes $bytes -Offset ($option + 4)
                    } elseif ($code -eq 7) {
                        if ($null -ne $osDrop) {
                            $statisticsValid = $false
                            break
                        }
                        $osDrop = Read-D01PcapUInt64 -Bytes $bytes `
                            -Offset ($option + 4) -LittleEndian $true
                    }
                    $option += 4 + $paddedOptionLength
                }
            }
            if ($statisticsValid -and $null -ne $startTimeRaw -and
                $null -ne $endTimeRaw -and
                ([UInt64]$endTimeRaw -lt [UInt64]$startTimeRaw -or
                    [UInt64]$sampleTimeRaw -lt [UInt64]$endTimeRaw)) {
                $statisticsValid = $false
            }
            if (-not $statisticsValid) {
                $interfaceStatisticsOptionErrorCount++
                $parserComplete = $false
            }
            $missingLossCounters = $null -eq $ifDrop -or $null -eq $osDrop
            if ($missingLossCounters) {
                $interfaceStatisticsMissingLossCount++
            }
            $missingEndTime = $null -eq $endTimeRaw
            if ($missingEndTime) {
                $interfaceStatisticsMissingEndtimeCount++
            }
            $nonzeroLoss = ($null -ne $ifDrop -and [UInt64]$ifDrop -ne 0) -or
                ($null -ne $osDrop -and [UInt64]$osDrop -ne 0)
            if ($nonzeroLoss) { $interfaceStatisticsNonzeroLossCount++ }
            $interfaceStatisticsRecords.Add([pscustomobject][ordered]@{
                section_index = $sectionIndex
                interface_id = $interfaceId
                options_valid = $statisticsValid
                start_epoch_unix_ns = if (
                    $statisticsValid -and $null -ne $startTimeRaw) {
                    Convert-D01PcapTimestampToUnixNs `
                        -RawTimestamp ([UInt64]$startTimeRaw) `
                        -Resolution ([byte]$interfaces[$interfaceId].
                            timestamp_resolution_raw) `
                        -OffsetSeconds ([Int64]$interfaces[$interfaceId].
                            timestamp_offset_seconds)
                } else { $null }
                end_epoch_unix_ns = if (
                    $statisticsValid -and $null -ne $endTimeRaw) {
                    Convert-D01PcapTimestampToUnixNs `
                        -RawTimestamp ([UInt64]$endTimeRaw) `
                        -Resolution ([byte]$interfaces[$interfaceId].
                            timestamp_resolution_raw) `
                        -OffsetSeconds ([Int64]$interfaces[$interfaceId].
                            timestamp_offset_seconds)
                } else { $null }
                sample_epoch_unix_ns = if (
                    $statisticsValid -and $null -ne $sampleTimeRaw) {
                    Convert-D01PcapTimestampToUnixNs `
                        -RawTimestamp ([UInt64]$sampleTimeRaw) `
                        -Resolution ([byte]$interfaces[$interfaceId].
                            timestamp_resolution_raw) `
                        -OffsetSeconds ([Int64]$interfaces[$interfaceId].
                            timestamp_offset_seconds)
                } else { $null }
                ifdrop = $ifDrop
                osdrop = $osDrop
                required_loss_counters_present = -not $missingLossCounters
                required_endtime_present = -not $missingEndTime
                loss_counters_zero = -not $missingLossCounters -and
                    -not $nonzeroLoss
            })
        } elseif ($type -ne 4) {
            # A known NRB metadata block is permitted. Any other block
            # could carry evidence this parser does not understand.
            $unknownBlockCount++
            $nonAdjudicableFrameCount++
            $parserComplete = $false
        }
        $offset += $length
    }
    $trailingByteCount = $bytes.Length - $offset
    if ($trailingByteCount -ne 0) { $parserComplete = $false }
    $valid = $parserComplete -and $blockErrorCount -eq 0 -and
        $idbOptionErrorCount -eq 0 -and
        $unknownInterfaceFrameCount -eq 0 -and
        $unsupportedLinkTypeFrameCount -eq 0 -and
        $unsupportedPacketBlockCount -eq 0 -and
        $unknownBlockCount -eq 0 -and
        $enhancedPacketOptionErrorCount -eq 0 -and
        $truncatedFrameCount -eq 0 -and $parseNullFrameCount -eq 0 -and
        $nonAdjudicableFrameCount -eq 0 -and
        $trailingByteCount -eq 0 -and $sectionIndex -eq 0
    $interfaceStatisticsLossless =
        $enhancedPacketOptionErrorCount -eq 0 -and
        $enhancedPacketNonzeroDropcountCount -eq 0 -and
        $enhancedPacketErrorFlagsCount -eq 0 -and
        ($interfaceStatisticsBlockCount -eq 0 -or
        ($interfaceStatisticsOptionErrorCount -eq 0 -and
            $interfaceStatisticsMissingLossCount -eq 0 -and
            $interfaceStatisticsMissingEndtimeCount -eq 0 -and
            $interfaceStatisticsNonzeroLossCount -eq 0))
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.d01-pcapng-parse/v2'
        source_byte_count = [Int64]$snapshot.byte_count
        source_sha256 = [string]$snapshot.sha256
        source_immutable_read_lock_held =
            [bool]$snapshot.immutable_read_lock_held
        parser_complete = $valid
        valid = $valid
        errors = @()
        section_count = $sectionIndex + 1
        interface_count = $interfaceRecords.Count
        enhanced_packet_count = $enhancedPacketCount
        enhanced_packet_option_error_count =
            $enhancedPacketOptionErrorCount
        enhanced_packet_dropcount_present_count =
            $enhancedPacketDropcountPresentCount
        enhanced_packet_nonzero_dropcount_count =
            $enhancedPacketNonzeroDropcountCount
        enhanced_packet_flags_present_count =
            $enhancedPacketFlagsPresentCount
        enhanced_packet_error_flags_count =
            $enhancedPacketErrorFlagsCount
        parsed_packet_count = $packets.Count
        trailing_byte_count = $trailingByteCount
        block_error_count = $blockErrorCount
        idb_option_error_count = $idbOptionErrorCount
        truncated_frame_count = $truncatedFrameCount
        unknown_interface_frame_count = $unknownInterfaceFrameCount
        unsupported_linktype_frame_count = $unsupportedLinkTypeFrameCount
        unsupported_packet_block_count = $unsupportedPacketBlockCount
        unknown_block_count = $unknownBlockCount
        interface_statistics_block_count =
            $interfaceStatisticsBlockCount
        interface_statistics_option_error_count =
            $interfaceStatisticsOptionErrorCount
        interface_statistics_missing_loss_count =
            $interfaceStatisticsMissingLossCount
        interface_statistics_missing_endtime_count =
            $interfaceStatisticsMissingEndtimeCount
        interface_statistics_nonzero_loss_count =
            $interfaceStatisticsNonzeroLossCount
        interface_statistics_lossless = $interfaceStatisticsLossless
        interface_statistics = @($interfaceStatisticsRecords.ToArray())
        parse_null_frame_count = $parseNullFrameCount
        non_adjudicable_frame_count = $nonAdjudicableFrameCount
        interfaces = @($interfaceRecords.ToArray())
        packets = @($packets.ToArray())
        records = @($packets.ToArray())
    }
}

function Get-D01SocketSamplerEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][object]$ClockAnchor,
        [Parameter(Mandatory = $true)][Int64]$MaximumUncertaintyNs,
        [Parameter(Mandatory = $true)][int]$CandidateProcessId
    )

    $errorHashes = New-Object 'Collections.Generic.List[string]'
    $rows = [System.Collections.Generic.List[object]]::new()
    $sampleCount = 0
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return [pscustomobject][ordered]@{
            valid = $false
            error_sha256s = @(
                Get-LabStringSha256 -Value 'Socket sampler JSONL is missing')
            sample_count = 0
            rows = @()
            snapshot_sha256 = ''
            immutable_read_lock_held = $false
        }
    }
    try {
        $snapshot = Open-D01ImmutableEvidenceSnapshot -Path $Path
        $utf8 = [Text.UTF8Encoding]::new($false, $true)
        $text = $utf8.GetString([byte[]]$snapshot.bytes)
        if ($text.Length -gt 0 -and $text[0] -eq [char]0xfeff) {
            $text = $text.Substring(1)
        }
    } catch {
        return [pscustomobject][ordered]@{
            valid = $false
            error_sha256s = @(
                Get-LabStringSha256 -Value $_.Exception.Message)
            sample_count = 0
            rows = @()
            snapshot_sha256 = ''
            immutable_read_lock_held = $false
        }
    }
    $lineNumber = 0
    $expectedSampleNumber = 1
    [Int64]$previousQpcMidpoint = -1
    [Int64]$previousEpochUnixNs = -1
    [Int64]$previousElapsedMs = -1
    foreach ($line in @($text -split "`r?`n")) {
        $lineNumber++
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        try {
            $sample = $line | ConvertFrom-Json -ErrorAction Stop
            $null = Assert-D01ExactPropertySet -Object $sample -Expected @(
                'schema', 'sample_number', 'captured_at_utc', 'clock',
                'elapsed_ms', 'connections'
            ) -Context "socket sampler line $lineNumber"
            $null = Assert-D01JsonStringValue -Value $sample.schema `
                -Context "socket sampler line $lineNumber.schema"
            $null = Assert-D01JsonStringValue `
                -Value $sample.captured_at_utc `
                -Context "socket sampler line $lineNumber.captured_at_utc"
            if ([string]$sample.schema -cne
                'ese.v91.d01-target-socket-sample/v3') {
                throw 'Socket sample schema is not exact'
            }
            $sampleNumber = Assert-D01JsonInteger `
                -Value $sample.sample_number `
                -Context "socket sampler line $lineNumber.sample_number" `
                -Minimum 1
            $elapsedMs = Assert-D01JsonInteger -Value $sample.elapsed_ms `
                -Context "socket sampler line $lineNumber.elapsed_ms" `
                -Minimum 0
            if ($sampleNumber -ne $expectedSampleNumber -or
                $elapsedMs -lt $previousElapsedMs) {
                throw 'Socket sample sequence/time is not monotonic and gap-free'
            }
            $clock = $sample.clock
            $null = Assert-D01ExactPropertySet -Object $clock -Expected @(
                'schema', 'clock_domain', 'anchor_id', 'qpc_frequency',
                'qpc_start_ticks', 'qpc_end_ticks', 'qpc_midpoint_ticks',
                'epoch_unix_ns', 'uncertainty_ns'
            ) -Context "socket sampler line $lineNumber.clock"
            foreach ($name in @('schema', 'clock_domain', 'anchor_id')) {
                $null = Assert-D01JsonStringValue `
                    -Value $clock.PSObject.Properties[$name].Value `
                    -Context "socket sampler line $lineNumber.clock.$name"
            }
            foreach ($name in @(
                'qpc_frequency', 'qpc_start_ticks', 'qpc_end_ticks',
                'qpc_midpoint_ticks', 'epoch_unix_ns', 'uncertainty_ns'
            )) {
                $null = Assert-D01JsonInteger `
                    -Value $clock.PSObject.Properties[$name].Value `
                    -Context "socket sampler line $lineNumber.clock.$name" `
                    -Minimum 0
            }
            if ([string]$clock.schema -cne
                    'ese.v91.d01-clock-observation/v1' -or
                [string]$clock.clock_domain -cne
                    [string]$ClockAnchor.clock_domain -or
                [string]$clock.anchor_id -cne
                    [string]$ClockAnchor.anchor_id -or
                [Int64]$clock.qpc_frequency -ne
                    [Int64]$ClockAnchor.qpc_frequency) {
                throw 'Socket sample clock/schema contract mismatch'
            }
            $recomputed = Get-D01ClockObservation `
                -Anchor $ClockAnchor `
                -QpcStart ([Int64]$clock.qpc_start_ticks) `
                -QpcEnd ([Int64]$clock.qpc_end_ticks)
            if ([Int64]$recomputed.epoch_unix_ns -ne
                    [Int64]$clock.epoch_unix_ns -or
                [Int64]$recomputed.uncertainty_ns -ne
                    [Int64]$clock.uncertainty_ns -or
                [Int64]$recomputed.qpc_midpoint_ticks -ne
                    [Int64]$clock.qpc_midpoint_ticks -or
                [Int64]$clock.uncertainty_ns -gt
                    $MaximumUncertaintyNs) {
                throw 'Socket sample epoch/QPC conversion is incoherent'
            }
            if ([Int64]$clock.qpc_midpoint_ticks -lt
                    $previousQpcMidpoint -or
                [Int64]$clock.epoch_unix_ns -lt $previousEpochUnixNs) {
                throw 'Socket sample clocks are not monotonic'
            }
            if ($sample.connections -isnot [Array]) {
                throw 'Socket sample connections is not a JSON array'
            }
            $sampleCount++
            foreach ($connection in @($sample.connections)) {
                $null = Assert-D01ExactPropertySet -Object $connection `
                    -Expected @(
                        'captured_at_utc', 'owning_process', 'state',
                        'family', 'local_address', 'local_port',
                        'remote_address', 'remote_port',
                        'local_address_assigned', 'adapter',
                        'physical_nonvirtual', 'sample_clock'
                    ) -Context "socket sampler line $lineNumber connection"
                foreach ($name in @(
                    'captured_at_utc', 'state', 'family', 'local_address',
                    'remote_address'
                )) {
                    $null = Assert-D01JsonStringValue `
                        -Value $connection.PSObject.Properties[$name].Value `
                        -Context (
                            "socket sampler line $lineNumber connection.$name")
                }
                $owner = Assert-D01JsonInteger `
                    -Value $connection.owning_process `
                    -Context (
                        "socket sampler line $lineNumber connection.owning_process") `
                    -Minimum 1 -Maximum ([int]::MaxValue)
                $localPort = Assert-D01JsonInteger `
                    -Value $connection.local_port `
                    -Context (
                        "socket sampler line $lineNumber connection.local_port") `
                    -Minimum 1 -Maximum 65535
                $remotePort = Assert-D01JsonInteger `
                    -Value $connection.remote_port `
                    -Context (
                        "socket sampler line $lineNumber connection.remote_port") `
                    -Minimum 1 -Maximum 65535
                foreach ($name in @(
                    'local_address_assigned', 'physical_nonvirtual'
                )) {
                    $null = Assert-D01JsonBoolean `
                        -Value $connection.PSObject.Properties[$name].Value `
                        -Context (
                            "socket sampler line $lineNumber connection.$name")
                }
                if ([string]$connection.family -notin @('IPv4', 'IPv6')) {
                    throw 'Socket sampler family is not exact'
                }
                $normalizedLocal = Get-D01NormalizedIp `
                    -Address ([string]$connection.local_address)
                $normalizedRemote = Get-D01NormalizedIp `
                    -Address ([string]$connection.remote_address)
                if ($normalizedLocal -cne [string]$connection.local_address -or
                    $normalizedRemote -cne
                        [string]$connection.remote_address) {
                    throw 'Socket sampler address is not canonical'
                }
                $null = Assert-D01AdapterEvidenceContract `
                    -Adapter $connection.adapter -Context (
                        "socket sampler line $lineNumber connection.adapter")
                $connectionClockJson = $connection.sample_clock |
                    ConvertTo-Json -Depth 20 -Compress
                $sampleClockJson = $clock |
                    ConvertTo-Json -Depth 20 -Compress
                if ($connectionClockJson -cne $sampleClockJson) {
                    throw 'Connection clock differs from its sample clock'
                }
                $rows.Add([pscustomobject][ordered]@{
                    sample_number = [int]$sampleNumber
                    epoch_unix_ns = [Int64]$clock.epoch_unix_ns
                    uncertainty_ns = [Int64]$clock.uncertainty_ns
                    qpc_midpoint_ticks =
                        [Int64]$clock.qpc_midpoint_ticks
                    owning_process = [int]$owner
                    candidate_owned = [int]$owner -eq $CandidateProcessId
                    state = [string]$connection.state
                    family = ([string]$connection.family).ToLowerInvariant()
                    local_address = $normalizedLocal
                    local_port = [int]$localPort
                    remote_address = $normalizedRemote
                    remote_port = [int]$remotePort
                    local_address_assigned =
                        [bool]$connection.local_address_assigned
                    physical_nonvirtual =
                        [bool]$connection.physical_nonvirtual
                    adapter = $connection.adapter
                })
            }
            $expectedSampleNumber++
            $previousQpcMidpoint = [Int64]$clock.qpc_midpoint_ticks
            $previousEpochUnixNs = [Int64]$clock.epoch_unix_ns
            $previousElapsedMs = [Int64]$elapsedMs
        } catch {
            $errorHashes.Add((Get-LabStringSha256 -Value (
                "Socket sampler line ${lineNumber}: $($_.Exception.Message)")))
        }
    }
    if ($sampleCount -eq 0) {
        $errorHashes.Add((Get-LabStringSha256 -Value (
            'Socket sampler contains no valid samples')))
    }
    return [pscustomobject][ordered]@{
        valid = $errorHashes.Count -eq 0
        error_sha256s = $errorHashes.ToArray()
        sample_count = $sampleCount
        rows = $rows.ToArray()
        snapshot_sha256 = [string]$snapshot.sha256
        immutable_read_lock_held =
            [bool]$snapshot.immutable_read_lock_held
    }
}

function Get-D01SynCorrelation {
    param(
        [Parameter(Mandatory = $true)][object]$Packet,
        [Parameter(Mandatory = $true)][object[]]$SamplerRows,
        [Parameter(Mandatory = $true)][int]$CandidateProcessId,
        [Parameter(Mandatory = $true)][string]$ExpectedCoordinatorAddress,
        [Parameter(Mandatory = $true)][Int64]$ToleranceNs
    )

    $expectedLocal = Get-D01NormalizedIp `
        -Address $ExpectedCoordinatorAddress
    $packetTime = [Int64]$Packet.packet_epoch_unix_ns
    $nearRows = @(
        $SamplerRows | Where-Object {
            [Math]::Abs(
                [decimal]([Int64]$_.epoch_unix_ns - $packetTime)
            ) -le [decimal]$ToleranceNs
        }
    )
    $exactRows = @(
        $nearRows | Where-Object {
            [string]$_.family -eq [string]$Packet.family -and
            [string]$_.local_address -eq
                [string]$Packet.source_address -and
            [int]$_.local_port -eq [int]$Packet.source_port -and
            [string]$_.remote_address -eq
                [string]$Packet.destination_address -and
            [int]$_.remote_port -eq [int]$Packet.destination_port
        }
    )
    $foreignRows = @(
        $exactRows | Where-Object {
            [int]$_.owning_process -ne $CandidateProcessId
        }
    )
    $portReuseRows = @(
        $nearRows | Where-Object {
            [string]$_.family -eq [string]$Packet.family -and
            [string]$_.local_address -eq
                [string]$Packet.source_address -and
            [int]$_.local_port -eq [int]$Packet.source_port -and
            (
                [int]$_.owning_process -ne $CandidateProcessId -or
                [string]$_.remote_address -ne
                    [string]$Packet.destination_address -or
                [int]$_.remote_port -ne [int]$Packet.destination_port
            )
        }
    )
    $candidateRows = @(
        $exactRows | Where-Object {
            [int]$_.owning_process -eq $CandidateProcessId -and
            [bool]$_.local_address_assigned -and
            [bool]$_.physical_nonvirtual -and
            (
                [string]$Packet.family -ne 'ipv6' -or
                [string]$_.state -eq 'SynSent'
            )
        } | ForEach-Object {
            [pscustomobject]@{
                row = $_
                distance_ns = [Int64][Math]::Abs(
                    [decimal]([Int64]$_.epoch_unix_ns - $packetTime)
                )
            }
        } | Sort-Object distance_ns, {
            [int]$_.row.sample_number
        }
    )
    $minimumDistance = if ($candidateRows.Count -gt 0) {
        [Int64]$candidateRows[0].distance_ns
    } else { $null }
    $nearestRows = @()
    if ($candidateRows.Count -gt 0) {
        $nearestRows = @($candidateRows | Where-Object {
            [Int64]$_.distance_ns -eq $minimumDistance
        })
    }
    $foreignPacket =
        [string]$Packet.source_address -ne $expectedLocal
    $ambiguous = $nearestRows.Count -ne 1 -and
        $candidateRows.Count -gt 0
    $attributed = -not $foreignPacket -and
        $foreignRows.Count -eq 0 -and $portReuseRows.Count -eq 0 -and
        $nearestRows.Count -eq 1
    return [pscustomobject][ordered]@{
        packet_index = [int]$Packet.packet_index
        packet_epoch_unix_ns = $packetTime
        family = [string]$Packet.family
        five_tuple = [string]$Packet.five_tuple
        tcp_sequence_number = [uint32]$Packet.tcp_sequence_number
        tolerance_ns = $ToleranceNs
        candidate_process_id = $CandidateProcessId
        candidate_row_count = $candidateRows.Count
        exact_foreign_row_count = $foreignRows.Count
        port_reuse_row_count = $portReuseRows.Count
        foreign_packet = $foreignPacket
        ambiguous = $ambiguous
        unmatched = $candidateRows.Count -eq 0
        attributed = $attributed
        matched_distance_ns = if ($attributed) {
            [Int64]$nearestRows[0].distance_ns
        } else { $null }
        matched_sampler_row = if ($attributed) {
            $nearestRows[0].row
        } else { $null }
    }
}

function Get-D01CaptureInterfaceBinding {
    param(
        [Parameter(Mandatory = $true)][object]$Pcap,
        [Parameter(Mandatory = $true)][object]$ExpectedAdapter,
        [Parameter(Mandatory = $true)][object[]]$TargetFrames
    )
    try {
        $current = Get-D01AdapterEvidence `
            -InterfaceIndex ([int]$ExpectedAdapter.interface_index) `
            -Context 'capture-interface-binding'
        if (-not $current.physical_nonvirtual -or
            [string]$current.interface_id -cne
                [string]$ExpectedAdapter.interface_id) {
            throw 'Expected capture adapter identity changed'
        }
        $adapterRows = @(Get-NetAdapter -IncludeHidden `
            -InterfaceIndex ([int]$ExpectedAdapter.interface_index) `
            -ErrorAction Stop)
        if ($adapterRows.Count -ne 1) {
            throw 'Capture adapter inventory was not singular'
        }
        $adapter = $adapterRows[0]
        [string[]]$expectedTokens = @(
            [string]$adapter.Name,
            [string]$adapter.InterfaceDescription,
            [string]$adapter.InterfaceGuid,
            ([string]$adapter.InterfaceGuid).Trim('{', '}'),
            [string][int]$adapter.InterfaceIndex,
            'if' + [string][int]$adapter.InterfaceIndex
        ) | ForEach-Object { $_.Trim().ToLowerInvariant() } |
            Select-Object -Unique
        $matches = [Collections.Generic.List[object]]::new()
        foreach ($idb in @($Pcap.interfaces)) {
            [string[]]$tokens = @(
                [string]$idb._interface_name,
                [string]$idb._interface_description
            ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                ForEach-Object { $_.Trim().ToLowerInvariant() }
            $tokenMatch = @($tokens | Where-Object {
                $_ -in $expectedTokens
            }).Count -gt 0
            # The explicit hashes are retained; raw IDB labels stay private.
            if ($tokenMatch) {
                $matches.Add([pscustomobject][ordered]@{
                    section_index = [int]$idb.section_index
                    interface_id = [int]$idb.interface_id
                    interface_name_sha256 =
                        [string]$idb.interface_name_sha256
                    interface_description_sha256 =
                        [string]$idb.interface_description_sha256
                    link_type = [int]$idb.link_type
                    snap_length = [uint32]$idb.snap_length
                    options_valid = [bool]$idb.options_valid
                    supported_link_type = [bool]$idb.supported_link_type
                    timestamp_tick_nanoseconds =
                        [decimal]$idb.timestamp_tick_nanoseconds
                    timestamp_resolution_adjudicable =
                        [bool]$idb.timestamp_resolution_adjudicable
                    adjudicable = [bool]$idb.options_valid -and
                        [bool]$idb.supported_link_type -and
                        [uint32]$idb.snap_length -gt 0 -and
                        [bool]$idb.timestamp_resolution_adjudicable
                })
            }
        }
        [string[]]$targetKeys = @($TargetFrames | ForEach-Object {
            '{0}|{1}' -f [int]$_.section_index,
                [int]$_.capture_interface_id
        } | Select-Object -Unique)
        $expectedKey = if ($matches.Count -eq 1) {
            '{0}|{1}' -f [int]$matches[0].section_index,
                [int]$matches[0].interface_id
        } else { '' }
        $targetFramesOnExpected = $targetKeys.Count -eq 0 -or (
            $targetKeys.Count -eq 1 -and
            [string]$targetKeys[0] -ceq $expectedKey)
        $matchingIdbAdjudicable = $matches.Count -eq 1 -and
            [bool]$matches[0].adjudicable
        $exact = $matchingIdbAdjudicable -and $targetFramesOnExpected
        return [pscustomobject][ordered]@{
            schema = 'ese.v91.d01-capture-interface-binding/v1'
            collector_ok = $true
            expected_adapter = $current
            matching_idb_count = $matches.Count
            matching_idbs = $matches.ToArray()
            matching_idb_adjudicable = $matchingIdbAdjudicable
            expected_section_index = if ($matches.Count -eq 1) {
                [int]$matches[0].section_index
            } else { -1 }
            expected_interface_id = if ($matches.Count -eq 1) {
                [int]$matches[0].interface_id
            } else { -1 }
            target_frame_count = @($TargetFrames).Count
            target_frame_interface_keys = $targetKeys
            exact = $exact
            target_frames_on_expected_physical_nic =
                $targetFramesOnExpected
            error_sha256 = ''
        }
    } catch {
        return [pscustomobject][ordered]@{
            schema = 'ese.v91.d01-capture-interface-binding/v1'
            collector_ok = $false
            expected_adapter = $ExpectedAdapter
            matching_idb_count = 0
            matching_idbs = @()
            matching_idb_adjudicable = $false
            expected_section_index = -1
            expected_interface_id = -1
            target_frame_count = @($TargetFrames).Count
            target_frame_interface_keys = @()
            exact = $false
            target_frames_on_expected_physical_nic = $false
            error_sha256 = Get-LabStringSha256 -Value $_.Exception.Message
        }
    }
}

function Get-D01PcapInterfaceStatisticsCoverage {
    param(
        [Parameter(Mandatory = $true)][object]$Pcap,
        [Parameter(Mandatory = $true)][object]$InterfaceBinding,
        [Parameter(Mandatory = $true)][Int64]$WindowStartEpochUnixNs,
        [Parameter(Mandatory = $true)][Int64]$WindowEndEpochUnixNs
    )

    $matching = @()
    $covering = @()
    if ([bool]$InterfaceBinding.exact) {
        $matching = @($Pcap.interface_statistics | Where-Object {
            [int]$_.section_index -eq
                [int]$InterfaceBinding.expected_section_index -and
            [int]$_.interface_id -eq
                [int]$InterfaceBinding.expected_interface_id
        })
        $covering = @($matching | Where-Object {
            [bool]$_.options_valid -and
            [bool]$_.required_loss_counters_present -and
            [bool]$_.required_endtime_present -and
            [bool]$_.loss_counters_zero -and
            $null -ne $_.start_epoch_unix_ns -and
            $null -ne $_.end_epoch_unix_ns -and
            $null -ne $_.sample_epoch_unix_ns -and
            [Int64]$_.start_epoch_unix_ns -le $WindowStartEpochUnixNs -and
            [Int64]$_.end_epoch_unix_ns -ge $WindowEndEpochUnixNs -and
            [Int64]$_.sample_epoch_unix_ns -ge
                [Int64]$_.end_epoch_unix_ns -and
            [Int64]$_.sample_epoch_unix_ns -ge $WindowEndEpochUnixNs
        })
    }
    $allMatchingLossless = $matching.Count -gt 0 -and
        @($matching | Where-Object {
            -not [bool]$_.options_valid -or
            -not [bool]$_.required_loss_counters_present -or
            -not [bool]$_.required_endtime_present -or
            -not [bool]$_.loss_counters_zero -or
            $null -eq $_.sample_epoch_unix_ns -or
            ($null -ne $_.end_epoch_unix_ns -and
                [Int64]$_.sample_epoch_unix_ns -lt
                    [Int64]$_.end_epoch_unix_ns)
        }).Count -eq 0
    $exact = [bool]$InterfaceBinding.exact -and
        $allMatchingLossless -and $covering.Count -gt 0
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.d01-pcapng-isb-window-coverage/v1'
        expected_section_index =
            [int]$InterfaceBinding.expected_section_index
        expected_interface_id =
            [int]$InterfaceBinding.expected_interface_id
        window_start_epoch_unix_ns = $WindowStartEpochUnixNs
        window_end_epoch_unix_ns = $WindowEndEpochUnixNs
        matching_isb_count = $matching.Count
        covering_isb_count = $covering.Count
        all_matching_isbs_lossless = $allMatchingLossless
        exact = $exact
        matching_isbs = $matching
    }
}

function Get-D01PacketCaptureEvidence {
    param(
        [Parameter(Mandatory = $true)][object]$State,
        [Parameter(Mandatory = $true)][string]$IPv4,
        [Parameter(Mandatory = $true)][Net.IPAddress]$IPv6,
        [Parameter(Mandatory = $true)][string]$CoordinatorIPv4,
        [Parameter(Mandatory = $true)]
        [Net.IPAddress]$CoordinatorIPv6,
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][string]$SocketSamplesPath,
        [Parameter(Mandatory = $true)][int]$CandidateProcessId,
        [Parameter(Mandatory = $true)][object]$ExpectedAdapterEvidence,
        [Parameter(Mandatory = $true)][object]$ClockAnchor,
        [Parameter(Mandatory = $true)][object]$ClockEndAnchor,
        [Parameter(Mandatory = $true)][Int64]$WindowStartEpochUnixNs,
        [Parameter(Mandatory = $true)][Int64]$WindowEndEpochUnixNs
    )

    if ($WindowEndEpochUnixNs -lt $WindowStartEpochUnixNs) {
        throw 'Invalid capture correlation window'
    }
    $baseCorrelationToleranceNs = [Int64]250000000
    $correlationToleranceNs = $baseCorrelationToleranceNs
    $clockPrediction = Get-D01ClockObservation -Anchor $ClockAnchor `
        -QpcStart ([Int64]$ClockEndAnchor.anchor_qpc_ticks) `
        -QpcEnd ([Int64]$ClockEndAnchor.anchor_qpc_ticks)
    $clockDriftNs = [Int64](
        [Int64]$ClockEndAnchor.anchor_epoch_unix_ns -
        [Int64]$clockPrediction.epoch_unix_ns
    )
    $clockCoherent =
        [string]$ClockAnchor.clock_domain -eq
            [string]$ClockEndAnchor.clock_domain -and
        [Int64]$ClockAnchor.qpc_frequency -eq
            [Int64]$ClockEndAnchor.qpc_frequency -and
        [Math]::Abs([decimal]$clockDriftNs) -le [decimal]50000000 -and
        [Int64]$ClockAnchor.anchor_uncertainty_ns -le
            $baseCorrelationToleranceNs -and
        [Int64]$ClockEndAnchor.anchor_uncertainty_ns -le
            $baseCorrelationToleranceNs
    $pcap = Get-D01PcapNgTcpRecords -Path $State.pcapng_path
    $sampler = Get-D01SocketSamplerEvidence `
        -Path $SocketSamplesPath -ClockAnchor $ClockAnchor `
        -MaximumUncertaintyNs $baseCorrelationToleranceNs `
        -CandidateProcessId $CandidateProcessId
    $sourceV4 = Get-D01NormalizedIp -Address $IPv4
    $sourceV6 = Get-D01NormalizedIp -Address $IPv6.ToString()
    $coordinatorV4 =
        Get-D01NormalizedIp -Address $CoordinatorIPv4
    $coordinatorV6 = Get-D01NormalizedIp `
        -Address $CoordinatorIPv6.ToString()
    $targetFrames = @(@($pcap.records) | Where-Object {
        [string]$_.source_address -in @($sourceV4, $sourceV6) -or
        [string]$_.destination_address -in @($sourceV4, $sourceV6) -or
        [string]$_.quoted_source -in @($sourceV4, $sourceV6) -or
        [string]$_.quoted_destination -in @($sourceV4, $sourceV6)
    })
    $interfaceBinding = Get-D01CaptureInterfaceBinding -Pcap $pcap `
        -ExpectedAdapter $ExpectedAdapterEvidence `
        -TargetFrames $targetFrames
    [Int64]$pcapTimestampUncertaintyNs = 0
    if ([bool]$interfaceBinding.exact) {
        $pcapTimestampUncertaintyNs = [Int64][Math]::Ceiling(
            [decimal]$interfaceBinding.matching_idbs[0].
                timestamp_tick_nanoseconds / [decimal]2)
        $correlationToleranceNs = [Int64](
            $baseCorrelationToleranceNs + $pcapTimestampUncertaintyNs)
    }
    $interfaceStatisticsCoverage =
        Get-D01PcapInterfaceStatisticsCoverage -Pcap $pcap `
            -InterfaceBinding $interfaceBinding `
            -WindowStartEpochUnixNs $WindowStartEpochUnixNs `
            -WindowEndEpochUnixNs $WindowEndEpochUnixNs
    $allTargetInitialSyns = @(
        @($pcap.records) | Where-Object {
            [bool]$_.initial_syn -and
            [string]$_.destination_address -in @($sourceV4, $sourceV6)
        }
    )
    $wrongPortSyns = @(
        $allTargetInitialSyns | Where-Object {
            [int]$_.destination_port -ne $Port
        }
    )
    $outOfWindowSyns = @(
        $allTargetInitialSyns | Where-Object {
            [Int64]$_.packet_epoch_unix_ns -lt
                $WindowStartEpochUnixNs -or
            [Int64]$_.packet_epoch_unix_ns -gt
                $WindowEndEpochUnixNs
        }
    )
    $eligibleSyns = @(
        $allTargetInitialSyns | Where-Object {
            [int]$_.destination_port -eq $Port -and
            [Int64]$_.packet_epoch_unix_ns -ge
                $WindowStartEpochUnixNs -and
            [Int64]$_.packet_epoch_unix_ns -le
                $WindowEndEpochUnixNs
        }
    )
    $correlations = @(
        foreach ($packet in $eligibleSyns) {
            $expectedCoordinator = if (
                [string]$packet.family -eq 'ipv4'
            ) { $coordinatorV4 } else { $coordinatorV6 }
            Get-D01SynCorrelation -Packet $packet `
                -SamplerRows @($sampler.rows) `
                -CandidateProcessId $CandidateProcessId `
                -ExpectedCoordinatorAddress $expectedCoordinator `
                -ToleranceNs $correlationToleranceNs
        }
    )
    $v4Correlations = @(
        $correlations | Where-Object { [string]$_.family -eq 'ipv4' }
    )
    $v6Correlations = @(
        $correlations | Where-Object { [string]$_.family -eq 'ipv6' }
    )
    $unattributed = @($correlations | Where-Object {
        -not [bool]$_.attributed
    })
    [int[]]$attributedV4PacketIndexes = @($v4Correlations |
        Where-Object { [bool]$_.attributed } |
        ForEach-Object { [int]$_.packet_index })
    [int[]]$attributedV6PacketIndexes = @($v6Correlations |
        Where-Object { [bool]$_.attributed } |
        ForEach-Object { [int]$_.packet_index })
    $v4SynPackets = @($eligibleSyns | Where-Object {
        [string]$_.family -eq 'ipv4' -and
        [int]$_.packet_index -in $attributedV4PacketIndexes
    })
    $v6SynPackets = @($eligibleSyns | Where-Object {
        [string]$_.family -eq 'ipv6' -and
        [int]$_.packet_index -in $attributedV6PacketIndexes
    })
    $v4HandshakeProofs = [Collections.Generic.List[object]]::new()
    $v4EstablishedKeys = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal)
    foreach ($syn in $v4SynPackets) {
        $expectedSynAck = [uint32](([uint64]$syn.tcp_sequence_number + 1) `
            % [uint64]4294967296)
        $synAcks = @($pcap.records | Where-Object {
            [string]$_.protocol -eq 'tcp' -and [bool]$_.syn -and
            [bool]$_.ack -and -not [bool]$_.rst -and
            [string]$_.source_address -eq $sourceV4 -and
            [int]$_.source_port -eq $Port -and
            [string]$_.destination_address -eq $coordinatorV4 -and
            [int]$_.destination_port -eq [int]$syn.source_port -and
            [uint32]$_.acknowledgement_number -eq $expectedSynAck -and
            [int]$_.packet_index -gt [int]$syn.packet_index -and
            [Int64]$_.packet_epoch_unix_ns -ge
                [Int64]$syn.packet_epoch_unix_ns -and
            [Int64]$_.packet_epoch_unix_ns -le $WindowEndEpochUnixNs
        })
        foreach ($synAck in $synAcks) {
            $expectedFinalAck = [uint32]((
                [uint64]$synAck.tcp_sequence_number + 1) %
                [uint64]4294967296)
            $finalAcks = @($pcap.records | Where-Object {
                [string]$_.protocol -eq 'tcp' -and -not [bool]$_.syn -and
                [bool]$_.ack -and -not [bool]$_.rst -and
                [string]$_.source_address -eq $coordinatorV4 -and
                [int]$_.source_port -eq [int]$syn.source_port -and
                [string]$_.destination_address -eq $sourceV4 -and
                [int]$_.destination_port -eq $Port -and
                [uint32]$_.acknowledgement_number -eq $expectedFinalAck -and
                [uint32]$_.tcp_sequence_number -eq $expectedSynAck -and
                [int]$_.packet_index -gt [int]$synAck.packet_index -and
                [Int64]$_.packet_epoch_unix_ns -ge
                    [Int64]$synAck.packet_epoch_unix_ns -and
                [Int64]$_.packet_epoch_unix_ns -le $WindowEndEpochUnixNs
            })
            $firstFinalAck = @($finalAcks | Sort-Object packet_index |
                Select-Object -First 1)
            $matchingEstablishedRows = @($sampler.rows | Where-Object {
                [int]$_.owning_process -eq $CandidateProcessId -and
                [string]$_.family -eq 'ipv4' -and
                [string]$_.local_address -eq $coordinatorV4 -and
                [int]$_.local_port -eq [int]$syn.source_port -and
                [string]$_.remote_address -eq $sourceV4 -and
                [int]$_.remote_port -eq $Port -and
                [string]$_.state -eq 'Established' -and
                [bool]$_.physical_nonvirtual -and
                $firstFinalAck.Count -eq 1 -and
                ([Int64]$_.epoch_unix_ns - [Int64]$_.uncertainty_ns) -ge
                    ([Int64]$firstFinalAck[0].packet_epoch_unix_ns +
                        $pcapTimestampUncertaintyNs) -and
                [Int64]$_.epoch_unix_ns -le
                    ($WindowEndEpochUnixNs + $correlationToleranceNs)
            })
            if ($finalAcks.Count -gt 0) {
                foreach ($row in $matchingEstablishedRows) {
                    $null = $v4EstablishedKeys.Add(('{0}|{1}|{2}' -f
                        [int]$row.sample_number, [int]$row.local_port,
                        [Int64]$row.epoch_unix_ns))
                }
                $v4HandshakeProofs.Add([pscustomobject][ordered]@{
                    source_port = [int]$syn.source_port
                    syn_packet_index = [int]$syn.packet_index
                    syn_ack_packet_index = [int]$synAck.packet_index
                    final_ack_packet_index =
                        [int]$firstFinalAck[0].packet_index
                    exact_five_tuple = [string]$syn.five_tuple
                    candidate_established_sample_count =
                        $matchingEstablishedRows.Count
                })
                break
            }
        }
    }
    $v6TcpResponseIndexes = [Collections.Generic.HashSet[int]]::new()
    $v6UnboundTcpResponseIndexes =
        [Collections.Generic.HashSet[int]]::new()
    $v6IcmpErrorIndexes = [Collections.Generic.HashSet[int]]::new()
    $v6EstablishedKeys = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal)
    $v6DropProofs = [Collections.Generic.List[object]]::new()
    foreach ($syn in $v6SynPackets) {
        $expectedSynAck = [uint32](([uint64]$syn.tcp_sequence_number + 1) `
            % [uint64]4294967296)
        $allReverseTcpForSyn = @($pcap.records | Where-Object {
            [string]$_.family -eq 'ipv6' -and
            [string]$_.protocol -eq 'tcp' -and
            [string]$_.source_address -eq $sourceV6 -and
            [int]$_.source_port -eq $Port -and
            [string]$_.destination_address -eq $coordinatorV6 -and
            [int]$_.destination_port -eq [int]$syn.source_port -and
            [int]$_.packet_index -gt [int]$syn.packet_index -and
            [Int64]$_.packet_epoch_unix_ns -ge
                [Int64]$syn.packet_epoch_unix_ns -and
            [Int64]$_.packet_epoch_unix_ns -le $WindowEndEpochUnixNs
        })
        $tcpResponsesForSyn = @($allReverseTcpForSyn | Where-Object {
            [bool]$_.ack -and
            ([bool]$_.syn -or [bool]$_.rst) -and
            [uint32]$_.acknowledgement_number -eq $expectedSynAck
        })
        $unboundTcpResponsesForSyn = @($allReverseTcpForSyn |
            Where-Object {
                [int]$_.packet_index -notin @(
                    $tcpResponsesForSyn | ForEach-Object {
                        [int]$_.packet_index
                    })
            })
        $icmpErrorsForSyn = @($pcap.records | Where-Object {
            [string]$_.family -eq 'ipv6' -and
            [string]$_.protocol -eq 'icmpv6' -and
            [int]$_.icmp_type -in @(1, 2, 3, 4) -and
            [bool]$_.quoted_parse_complete -and
            [string]$_.quoted_source -eq $coordinatorV6 -and
            [int]$_.quoted_source_port -eq [int]$syn.source_port -and
            [string]$_.quoted_destination -eq $sourceV6 -and
            [int]$_.quoted_destination_port -eq $Port -and
            [uint32]$_.quoted_sequence_number -eq
                [uint32]$syn.tcp_sequence_number -and
            [int]$_.packet_index -gt [int]$syn.packet_index -and
            [Int64]$_.packet_epoch_unix_ns -ge
                [Int64]$syn.packet_epoch_unix_ns -and
            [Int64]$_.packet_epoch_unix_ns -le $WindowEndEpochUnixNs
        })
        $establishedForSyn = @($sampler.rows | Where-Object {
            [int]$_.owning_process -eq $CandidateProcessId -and
            [string]$_.family -eq 'ipv6' -and
            [string]$_.local_address -eq $coordinatorV6 -and
            [int]$_.local_port -eq [int]$syn.source_port -and
            [string]$_.remote_address -eq $sourceV6 -and
            [int]$_.remote_port -eq $Port -and
            [string]$_.state -eq 'Established' -and
            [bool]$_.physical_nonvirtual -and
            ([Int64]$_.epoch_unix_ns - [Int64]$_.uncertainty_ns) -ge
                ([Int64]$syn.packet_epoch_unix_ns +
                    $pcapTimestampUncertaintyNs) -and
            [Int64]$_.epoch_unix_ns -le
                ($WindowEndEpochUnixNs + $correlationToleranceNs)
        })
        foreach ($packet in $tcpResponsesForSyn) {
            $null = $v6TcpResponseIndexes.Add([int]$packet.packet_index)
        }
        foreach ($packet in $unboundTcpResponsesForSyn) {
            $null = $v6UnboundTcpResponseIndexes.Add(
                [int]$packet.packet_index)
        }
        foreach ($packet in $icmpErrorsForSyn) {
            $null = $v6IcmpErrorIndexes.Add([int]$packet.packet_index)
        }
        foreach ($row in $establishedForSyn) {
            $null = $v6EstablishedKeys.Add(('{0}|{1}|{2}' -f
                [int]$row.sample_number, [int]$row.local_port,
                [Int64]$row.epoch_unix_ns))
        }
        $v6DropProofs.Add([pscustomobject][ordered]@{
            syn_packet_index = [int]$syn.packet_index
            exact_five_tuple = [string]$syn.five_tuple
            tcp_response_count = $tcpResponsesForSyn.Count
            unbound_reverse_tcp_count = $unboundTcpResponsesForSyn.Count
            icmpv6_error_count = $icmpErrorsForSyn.Count
            candidate_established_sample_count = $establishedForSyn.Count
            proved = $tcpResponsesForSyn.Count -eq 0 -and
                $unboundTcpResponsesForSyn.Count -eq 0 -and
                $icmpErrorsForSyn.Count -eq 0 -and
                $establishedForSyn.Count -eq 0
        })
    }
    $v6TcpResponses = @($pcap.records | Where-Object {
        $v6TcpResponseIndexes.Contains([int]$_.packet_index)
    })
    $v6UnboundTcpResponses = @($pcap.records | Where-Object {
        $v6UnboundTcpResponseIndexes.Contains([int]$_.packet_index)
    })
    $v6IcmpErrors = @($pcap.records | Where-Object {
        $v6IcmpErrorIndexes.Contains([int]$_.packet_index)
    })
    $aForwardProved = $v4HandshakeProofs.Count -gt 0
    $aaaaSilentDropProved = $v6DropProofs.Count -gt 0 -and
        @($v6DropProofs.ToArray() | Where-Object {
            -not [bool]$_.proved
        }).Count -eq 0
    $correlationPass = $pcap.valid -and $sampler.valid -and
        $clockCoherent -and $interfaceBinding.exact -and
        $wrongPortSyns.Count -eq 0 -and
        $outOfWindowSyns.Count -eq 0 -and
        $v6UnboundTcpResponses.Count -eq 0 -and
        $unattributed.Count -eq 0
    $artifacts = @()
    $etlByteCount = [Int64]-1
    foreach ($path in @(
        $State.etl_path, $State.pcapng_path, $State.text_path
    )) {
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            $snapshot = Open-D01ImmutableEvidenceSnapshot -Path $path `
                -MetadataOnly
            if ([IO.Path]::GetFullPath($path) -ceq
                [IO.Path]::GetFullPath([string]$State.etl_path)) {
                $etlByteCount = [Int64]$snapshot.byte_count
            }
            $artifacts += [pscustomobject][ordered]@{
                name = Split-Path -Leaf $path
                bytes = [Int64]$snapshot.byte_count
                sha256 = [string]$snapshot.sha256
                immutable_read_lock_held =
                    [bool]$snapshot.immutable_read_lock_held
            }
        }
    }
    $etlBelowCircularLimit = $etlByteCount -gt 0 -and
        [Int64]$State.capture_file_limit_bytes -gt 0 -and
        $etlByteCount -lt [Int64]$State.capture_file_limit_bytes
    $etwSessionIdentityBound =
        Test-D01EtwSessionEvidenceChain -State $State
    $etwFinalLossless = $etwSessionIdentityBound -and
        $null -ne $State.etw_loss -and
        [string]$State.etw_loss.schema -ceq
            'ese.v91.d01-etw-final-loss/v3' -and
        [string]$State.etw_loss.phase -ceq
            'post-final-flush-control-stop' -and
        [bool]$State.etw_loss.session_identity_exact -and
        [bool]$State.etw_loss.flush_success -and
        [bool]$State.etw_loss.session_stopped_by_control_trace -and
        [bool]$State.etw_loss.proved_zero
    $counterEvidenceBound =
        Test-D01PktmonCounterEvidenceChain -State $State
    $globalCounterEvidenceBound =
        Test-D01PktmonGlobalCounterEvidenceChain -State $State
    $pktmonDriverLifecycleExact =
        Test-D01PktmonDriverLifecycleEvidence -State $State
    $counterLossless = $counterEvidenceBound -and
        $null -ne $State.counter_loss -and
        [string]$State.counter_loss.schema -ceq
            'ese.v91.d01-pktmon-counter-loss/v4' -and
        $null -ne $State.counter_baseline -and
        [string]$State.counter_baseline.schema -ceq
            'ese.v91.d01-pktmon-counter-loss/v4' -and
        [bool]$State.counter_baseline.json_contract_valid -and
        [string]$State.counter_baseline.snapshot_sha256 -cmatch
            '^[0-9a-f]{64}$' -and
        [string]$State.counter_baseline.native_schema -ceq
            [string]$State.counter_loss.native_schema -and
        [bool]$State.counter_loss.json_contract_valid -and
        [bool]$State.counter_loss.snapshot_equal_to_baseline -and
        [bool]$State.counter_loss.proved_no_counter_change
    $pcapStatisticsLossless =
        [bool]$pcap.interface_statistics_lossless -and
        [bool]$interfaceStatisticsCoverage.exact
    $lossless = $etwFinalLossless -and $counterLossless -and
        $globalCounterEvidenceBound -and
        $pktmonDriverLifecycleExact -and
        $pcapStatisticsLossless -and $etlBelowCircularLimit
    $filterScopeExact =
        [bool]$State.filters_applied_verified -and
        [string]$State.filter_scope -eq
            'target-address-all-ip-protocols' -and
        [int]$State.expected_destination_port -eq $Port
    $productCaptureObservable =
        [bool]$State.available -and
        [bool]$State.capture_started_verified -and
        $filterScopeExact -and $lossless -and
        $pktmonDriverLifecycleExact -and
        $pcap.valid -and $sampler.valid -and $clockCoherent -and
        $correlationPass -and [bool]$interfaceBinding.exact -and
        [bool]$State.etw_session_stopped_verified -and
        $artifacts.Count -eq 3 -and
        @($artifacts | Where-Object {
            [Int64]$_.bytes -le 0 -or
            -not [bool]$_.immutable_read_lock_held
        }).Count -eq 0
    return [pscustomobject][ordered]@{
        exact_filters_applied = $filterScopeExact
        capture_filter_scope = [string]$State.filter_scope
        all_target_tcp_ports_captured = $filterScopeExact
        all_target_ip_protocols_captured = $filterScopeExact
        tcp_port = $Port
        candidate_process_id = $CandidateProcessId
        pcap_timestamp_uncertainty_ns = $pcapTimestampUncertaintyNs
        correlation_tolerance_ns = $correlationToleranceNs
        correlation_window = [ordered]@{
            start_epoch_unix_ns = $WindowStartEpochUnixNs
            end_epoch_unix_ns = $WindowEndEpochUnixNs
        }
        clock_coherence = [ordered]@{
            valid = $clockCoherent
            drift_ns = $clockDriftNs
            start_anchor = $ClockAnchor
            end_anchor = $ClockEndAnchor
        }
        pcap_parser = $pcap
        capture_interface_binding = $interfaceBinding
        capture_interface_binding_exact = [bool]$interfaceBinding.exact
        target_frames_on_expected_physical_nic =
            [bool]$interfaceBinding.target_frames_on_expected_physical_nic
        socket_sampler = [ordered]@{
            valid = $sampler.valid
            error_sha256s = @($sampler.error_sha256s)
            sample_count = $sampler.sample_count
            row_count = @($sampler.rows).Count
            snapshot_sha256 = $sampler.snapshot_sha256
            immutable_read_lock_held =
                $sampler.immutable_read_lock_held
        }
        etw_session_identity = $State.etw_session_identity
        etw_session_post_counter_identity =
            $State.etw_session_post_counter_identity
        etw_session_pre_stop_identity =
            $State.etw_session_pre_stop_identity
        etw_session_identity_chain_exact = $etwSessionIdentityBound
        etw_loss = $State.etw_loss
        pktmon_driver_api_compatibility =
            $State.pktmon_driver_api_compatibility
        pktmon_driver_status_before = $State.pktmon_driver_status_before
        pktmon_driver_status_armed = $State.pktmon_driver_status_armed
        pktmon_driver_stop_pre_identity =
            $State.pktmon_driver_stop_pre_identity
        pktmon_driver_stop = $State.pktmon_driver_stop
        pktmon_driver_stop_post_identity =
            $State.pktmon_driver_stop_post_identity
        pktmon_driver_stop_verified =
            [bool]$State.pktmon_driver_stop_verified
        pktmon_driver_status_final = $State.pktmon_driver_status_final
        pktmon_driver_configuration_restored_verified =
            [bool]$State.pktmon_driver_configuration_restored_verified
        pktmon_driver_lifecycle_exact = $pktmonDriverLifecycleExact
        pktmon_counter_baseline = $State.counter_baseline
        pktmon_counter_loss = $State.counter_loss
        pktmon_counter_snapshot_chain_exact = $counterEvidenceBound
        pktmon_global_counter_baseline = $State.counter_global_baseline
        pktmon_global_counter_final = $State.counter_global_final
        pktmon_global_counter_post_reset = $State.counter_global_post_reset
        pktmon_counter_reset_result = $State.counter_reset_result
        pktmon_counter_reset_invocation_count =
            [int]$State.counter_reset_invocation_count
        pktmon_drop_counter_final_snapshot = $State.counter_loss_snapshot
        pktmon_global_counter_final_snapshot =
            $State.counter_global_final_snapshot
        pktmon_global_counter_restored_verified =
            [bool]$State.counter_global_restored_verified
        pktmon_global_counter_chain_exact = $globalCounterEvidenceBound
        pktmon_counter_evidence_files = [ordered]@{
            drop_final = Split-Path -Leaf $State.counter_loss_path
            all_final = Split-Path -Leaf $State.counter_global_final_path
        }
        etw_final_control_stop_lossless = $etwFinalLossless
        pcapng_interface_statistics_lossless = $pcapStatisticsLossless
        pcapng_interface_statistics_window_coverage =
            $interfaceStatisticsCoverage
        capture_file_limit_bytes =
            [Int64]$State.capture_file_limit_bytes
        etl_byte_count = $etlByteCount
        etl_below_circular_limit = $etlBelowCircularLimit
        etw_lossless = $lossless
        target_initial_syn_count = $allTargetInitialSyns.Count
        eligible_target_syn_count = $eligibleSyns.Count
        wrong_port_target_syn_count = $wrongPortSyns.Count
        out_of_window_target_syn_count = $outOfWindowSyns.Count
        unattributed_target_syn_count = $unattributed.Count
        ambiguous_target_syn_count = @($correlations | Where-Object {
            [bool]$_.ambiguous
        }).Count
        foreign_target_syn_count = @($correlations | Where-Object {
            [bool]$_.foreign_packet -or
            [int]$_.exact_foreign_row_count -gt 0
        }).Count
        port_reuse_target_syn_count = @($correlations | Where-Object {
            [int]$_.port_reuse_row_count -gt 0
        }).Count
        ipv4_exact_tuple_line_count = $v4Correlations.Count
        ipv6_exact_tuple_line_count = $v6Correlations.Count
        ipv4_exact_tuple_correlated =
            $v4Correlations.Count -gt 0 -and
            @($v4Correlations | Where-Object {
                -not [bool]$_.attributed
            }).Count -eq 0
        ipv6_exact_tuple_correlated =
            $v6Correlations.Count -gt 0 -and
            @($v6Correlations | Where-Object {
                -not [bool]$_.attributed
            }).Count -eq 0
        both_families_observed =
            $v4Correlations.Count -gt 0 -and $v6Correlations.Count -gt 0
        A_forward = [ordered]@{
            proved = $aForwardProved
            outbound_syn_count = $v4SynPackets.Count
            exact_handshake_count = $v4HandshakeProofs.Count
            handshakes = $v4HandshakeProofs.ToArray()
            candidate_established_sample_count = $v4EstablishedKeys.Count
        }
        AAAA_silent_DROP = [ordered]@{
            proved = $aaaaSilentDropProved
            outbound_syn_count = $v6SynPackets.Count
            tcp_response_or_reset_count = $v6TcpResponses.Count
            unbound_reverse_tcp_count = $v6UnboundTcpResponses.Count
            icmpv6_error_count = $v6IcmpErrors.Count
            established_sample_count = $v6EstablishedKeys.Count
            per_candidate_syn = $v6DropProofs.ToArray()
        }
        per_syn_correlations = $correlations
        correlation_pass = $correlationPass
        filter_inventory_restored =
            [bool]$State.filter_inventory_restored_verified
        etw_session_stopped =
            [bool]$State.etw_session_stopped_verified
        capture_started = [bool]$State.capture_started_verified
        artifacts = $artifacts
        capture_observability_pass =
            $productCaptureObservable -and
            [bool]$State.filter_inventory_restored_verified -and
            [bool]$State.etw_session_stopped_verified
        product_capture_observability_pass = $productCaptureObservable
    }
}

function Get-D01SourcePacketLinkEvidence {
    param(
        [Parameter(Mandatory = $true)][object]$State,
        [AllowNull()][object]$Observation,
        [Parameter(Mandatory = $true)][string]$CaptureDestinationIPv4,
        [Parameter(Mandatory = $true)][string]$SourceListenerIPv4,
        [Parameter(Mandatory = $true)][int]$Port,
        [Parameter(Mandatory = $true)][object]$ExpectedAdapterEvidence,
        [Parameter(Mandatory = $true)][object]$ClockAnchor,
        [Parameter(Mandatory = $true)][object]$ClockEndAnchor,
        [Parameter(Mandatory = $true)][Int64]$WindowStartEpochUnixNs,
        [Parameter(Mandatory = $true)][Int64]$WindowEndEpochUnixNs
    )

    if ($WindowEndEpochUnixNs -lt $WindowStartEpochUnixNs) {
        throw 'Invalid source capture correlation window'
    }
    $clockPrediction = Get-D01ClockObservation -Anchor $ClockAnchor `
        -QpcStart ([Int64]$ClockEndAnchor.anchor_qpc_ticks) `
        -QpcEnd ([Int64]$ClockEndAnchor.anchor_qpc_ticks)
    $clockDriftNs = [Int64](
        [Int64]$ClockEndAnchor.anchor_epoch_unix_ns -
        [Int64]$clockPrediction.epoch_unix_ns
    )
    $clockCoherent =
        [string]$ClockAnchor.clock_domain -eq
            [string]$ClockEndAnchor.clock_domain -and
        [Int64]$ClockAnchor.qpc_frequency -eq
            [Int64]$ClockEndAnchor.qpc_frequency -and
        [Math]::Abs([decimal]$clockDriftNs) -le [decimal]50000000 -and
        [Int64]$ClockAnchor.anchor_uncertainty_ns -le 250000000 -and
        [Int64]$ClockEndAnchor.anchor_uncertainty_ns -le 250000000
    $pcap = Get-D01PcapNgTcpRecords -Path $State.pcapng_path
    $normalizedCaptureDestination = Get-D01NormalizedIp `
        -Address $CaptureDestinationIPv4
    $normalizedSourceListener = Get-D01NormalizedIp `
        -Address $SourceListenerIPv4
    $targetFrames = @(@($pcap.records) | Where-Object {
        [string]$_.source_address -eq $normalizedCaptureDestination -or
        [string]$_.destination_address -eq $normalizedCaptureDestination -or
        [string]$_.quoted_source -eq $normalizedCaptureDestination -or
        [string]$_.quoted_destination -eq $normalizedCaptureDestination
    })
    $interfaceBinding = Get-D01CaptureInterfaceBinding -Pcap $pcap `
        -ExpectedAdapter $ExpectedAdapterEvidence -TargetFrames $targetFrames
    $interfaceStatisticsCoverage =
        Get-D01PcapInterfaceStatisticsCoverage -Pcap $pcap `
            -InterfaceBinding $interfaceBinding `
            -WindowStartEpochUnixNs $WindowStartEpochUnixNs `
            -WindowEndEpochUnixNs $WindowEndEpochUnixNs
    $windowSyns = @(
        @($pcap.records) | Where-Object {
            [bool]$_.initial_syn -and [string]$_.family -eq 'ipv4' -and
            [string]$_.destination_address -eq
                $normalizedCaptureDestination -and
            [int]$_.destination_port -eq $Port -and
            [Int64]$_.packet_epoch_unix_ns -ge
                $WindowStartEpochUnixNs -and
            [Int64]$_.packet_epoch_unix_ns -le
                $WindowEndEpochUnixNs
        }
    )
    $observationTupleValid = $false
    $matchingSyns = @()
    if ($null -ne $Observation) {
        try {
            $observationTupleValid =
                [string]$Observation.connection.state -eq 'Established' -and
                [string]$Observation.connection.local_address -eq
                    $normalizedSourceListener -and
                [int]$Observation.connection.local_port -eq $Port -and
                [string]$Observation.connection.remote_address -notin
                    @('', '0.0.0.0', '::') -and
                [int]$Observation.connection.remote_port -gt 0
            if ($observationTupleValid) {
                $matchingSyns = @(
                    $windowSyns | Where-Object {
                        [string]$_.source_address -eq
                            [string]$Observation.connection.remote_address -and
                        [int]$_.source_port -eq
                            [int]$Observation.connection.remote_port
                    }
                )
            }
        } catch {
            $observationTupleValid = $false
            $matchingSyns = @()
        }
    }
    $distinctTuples = @(
        $windowSyns | ForEach-Object { [string]$_.five_tuple } |
            Sort-Object -Unique
    )
    $sequenceNumbers = @(
        $matchingSyns | ForEach-Object {
            [uint32]$_.tcp_sequence_number
        } | Sort-Object -Unique
    )
    $foreignSyns = if ($observationTupleValid) {
        @(
            $windowSyns | Where-Object {
                [string]$_.source_address -ne
                    [string]$Observation.connection.remote_address -or
                [int]$_.source_port -ne
                    [int]$Observation.connection.remote_port
            }
        )
    } else {
        @($windowSyns)
    }
    $filterScopeExact =
        [bool]$State.filters_applied_verified -and
        [string]$State.filter_scope -eq
            'target-address-all-ip-protocols' -and
        [int]$State.expected_destination_port -eq $Port
    $artifacts = @()
    $etlByteCount = [Int64]-1
    foreach ($path in @(
        $State.etl_path, $State.pcapng_path, $State.text_path
    )) {
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            $snapshot = Open-D01ImmutableEvidenceSnapshot -Path $path `
                -MetadataOnly
            if ([IO.Path]::GetFullPath($path) -ceq
                [IO.Path]::GetFullPath([string]$State.etl_path)) {
                $etlByteCount = [Int64]$snapshot.byte_count
            }
            $artifacts += [pscustomobject][ordered]@{
                name = Split-Path -Leaf $path
                bytes = [Int64]$snapshot.byte_count
                sha256 = [string]$snapshot.sha256
                immutable_read_lock_held =
                    [bool]$snapshot.immutable_read_lock_held
            }
        }
    }
    $etwSessionIdentityBound =
        Test-D01EtwSessionEvidenceChain -State $State
    $counterEvidenceBound =
        Test-D01PktmonCounterEvidenceChain -State $State
    $globalCounterEvidenceBound =
        Test-D01PktmonGlobalCounterEvidenceChain -State $State
    $pktmonDriverLifecycleExact =
        Test-D01PktmonDriverLifecycleEvidence -State $State
    $lossless = $etwSessionIdentityBound -and $counterEvidenceBound -and
        $globalCounterEvidenceBound -and
        $pktmonDriverLifecycleExact -and
        $null -ne $State.etw_loss -and
        [string]$State.etw_loss.schema -ceq
            'ese.v91.d01-etw-final-loss/v3' -and
        [string]$State.etw_loss.phase -ceq
            'post-final-flush-control-stop' -and
        [bool]$State.etw_loss.session_identity_exact -and
        [bool]$State.etw_loss.flush_success -and
        [bool]$State.etw_loss.session_stopped_by_control_trace -and
        [bool]$State.etw_loss.proved_zero -and
        $null -ne $State.counter_baseline -and
        [string]$State.counter_baseline.schema -ceq
            'ese.v91.d01-pktmon-counter-loss/v4' -and
        [bool]$State.counter_baseline.json_contract_valid -and
        [string]$State.counter_baseline.snapshot_sha256 -cmatch
            '^[0-9a-f]{64}$' -and
        $null -ne $State.counter_loss -and
        [string]$State.counter_loss.schema -ceq
            'ese.v91.d01-pktmon-counter-loss/v4' -and
        [string]$State.counter_loss.native_schema -ceq
            [string]$State.counter_baseline.native_schema -and
        [bool]$State.counter_loss.json_contract_valid -and
        [bool]$State.counter_loss.snapshot_equal_to_baseline -and
        [bool]$State.counter_loss.proved_no_counter_change -and
        [bool]$pcap.interface_statistics_lossless -and
        [bool]$interfaceStatisticsCoverage.exact -and
        $etlByteCount -gt 0 -and
        $etlByteCount -lt [Int64]$State.capture_file_limit_bytes
    $productCaptureObservable =
        [bool]$State.available -and
        [bool]$State.capture_started_verified -and
        $filterScopeExact -and $lossless -and
        $pktmonDriverLifecycleExact -and $pcap.valid -and
        $clockCoherent -and
        [bool]$State.etw_session_stopped_verified -and
        $artifacts.Count -eq 3 -and
        @($artifacts | Where-Object {
            [Int64]$_.bytes -le 0 -or
            -not [bool]$_.immutable_read_lock_held
        }).Count -eq 0
    $linkValid = $pcap.valid -and $clockCoherent -and
        $observationTupleValid -and $windowSyns.Count -gt 0 -and
        $matchingSyns.Count -eq $windowSyns.Count -and
        $foreignSyns.Count -eq 0 -and $distinctTuples.Count -eq 1 -and
        $sequenceNumbers.Count -eq 1
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.d01-source-packet-link/v1'
        capture_observability_pass = $productCaptureObservable -and
            [bool]$State.filter_inventory_restored_verified
        product_capture_observability_pass = $productCaptureObservable
        link_contract_pass = $linkValid
        filter_scope_exact = $filterScopeExact
        capture_interface_binding = $interfaceBinding
        pcapng_interface_statistics_window_coverage =
            $interfaceStatisticsCoverage
        clock_coherence = [ordered]@{
            valid = $clockCoherent
            drift_ns = $clockDriftNs
        }
        correlation_window = [ordered]@{
            start_epoch_unix_ns = $WindowStartEpochUnixNs
            end_epoch_unix_ns = $WindowEndEpochUnixNs
        }
        incoming_target_initial_syn_count = $windowSyns.Count
        matching_inverse_initial_syn_count = $matchingSyns.Count
        foreign_or_additional_initial_syn_count = $foreignSyns.Count
        distinct_incoming_five_tuple_count = $distinctTuples.Count
        distinct_matching_sequence_count = $sequenceNumbers.Count
        matching_tcp_sequence_numbers = $sequenceNumbers
        matching_five_tuple = if ($distinctTuples.Count -eq 1) {
            $distinctTuples[0]
        } else { '' }
        pcap_parser = $pcap
        etw_session_identity = $State.etw_session_identity
        etw_session_post_counter_identity =
            $State.etw_session_post_counter_identity
        etw_session_pre_stop_identity =
            $State.etw_session_pre_stop_identity
        etw_session_identity_chain_exact = $etwSessionIdentityBound
        etw_loss = $State.etw_loss
        pktmon_driver_api_compatibility =
            $State.pktmon_driver_api_compatibility
        pktmon_driver_status_before = $State.pktmon_driver_status_before
        pktmon_driver_status_armed = $State.pktmon_driver_status_armed
        pktmon_driver_stop_pre_identity =
            $State.pktmon_driver_stop_pre_identity
        pktmon_driver_stop = $State.pktmon_driver_stop
        pktmon_driver_stop_post_identity =
            $State.pktmon_driver_stop_post_identity
        pktmon_driver_stop_verified =
            [bool]$State.pktmon_driver_stop_verified
        pktmon_driver_status_final = $State.pktmon_driver_status_final
        pktmon_driver_configuration_restored_verified =
            [bool]$State.pktmon_driver_configuration_restored_verified
        pktmon_driver_lifecycle_exact = $pktmonDriverLifecycleExact
        pktmon_counter_baseline = $State.counter_baseline
        pktmon_counter_loss = $State.counter_loss
        pktmon_counter_snapshot_chain_exact = $counterEvidenceBound
        pktmon_global_counter_baseline = $State.counter_global_baseline
        pktmon_global_counter_final = $State.counter_global_final
        pktmon_global_counter_post_reset = $State.counter_global_post_reset
        pktmon_counter_reset_result = $State.counter_reset_result
        pktmon_counter_reset_invocation_count =
            [int]$State.counter_reset_invocation_count
        pktmon_drop_counter_final_snapshot = $State.counter_loss_snapshot
        pktmon_global_counter_final_snapshot =
            $State.counter_global_final_snapshot
        pktmon_global_counter_restored_verified =
            [bool]$State.counter_global_restored_verified
        pktmon_global_counter_chain_exact = $globalCounterEvidenceBound
        pktmon_counter_evidence_files = [ordered]@{
            drop_final = Split-Path -Leaf $State.counter_loss_path
            all_final = Split-Path -Leaf $State.counter_global_final_path
        }
        artifacts = $artifacts
    }
}

function Invoke-D01SourceRole {
    if (-not $RunNonce) {
        throw 'Source role requires the coordinator-issued RunNonce'
    }
    $nonce = $RunNonce.ToLowerInvariant()
    $candidateRoot = Get-LabFullPath -Path $PackagePath
    $outputPath = Assert-D01OutputLocation -Path $OutputRoot `
        -Label 'Source OutputRoot' -CandidateRoot $candidateRoot
    if (Test-Path -LiteralPath $outputPath) {
        if (@(Get-ChildItem -LiteralPath $outputPath -Force).Count -ne 0) {
            throw "Source OutputRoot must be absent or empty: $outputPath"
        }
    }
    $output = New-LabDirectory -Path $outputPath
    $evidence = New-LabDirectory -Path (Join-Path $output 'evidence')
    $nodes = New-LabDirectory -Path (Join-Path $output 'nodes')
    $summaryPath = Join-Path $evidence 'summary.json'
    $coordinationBase = Assert-D01OutputLocation -Path $CoordinationRoot `
        -Label 'CoordinationRoot' -CandidateRoot $candidateRoot
    $coordination = Join-Path $coordinationBase "v91-d01-$nonce"
    $runPath = Join-Path $coordination 'run.json'
    $readyPath = Join-Path $coordination 'source-ready.json'
    $observePath = Join-Path $coordination 'observe.json'
    $observeAckPath = Join-Path $coordination 'source-observing.json'
    $armPath = Join-Path $coordination 'arm.json'
    $sourceArmedPath = Join-Path $coordination 'source-armed.json'
    $observationPath = Join-Path $coordination 'source-observation.json'
    $stopPath = Join-Path $coordination 'stop.json'
    $resultPath = Join-Path $coordination 'source-result.json'
    $resultCommitPath = Join-Path $coordination 'source-result-commit.json'
    $socketSamplesPath = Join-Path $evidence 'incoming-sockets.jsonl'
    $healthSamplesPath = Join-Path $evidence 'health-samples.jsonl'
    $source = $null
    $sourceNode = ''
    $sourceExe = ''
    $firewallRuleV4 = 'eSE V91 D01 ' + $nonce + ' v4-allow'
    $firewallRuleV6Drop = 'eSE V91 D01 ' + $nonce + ' v6-drop'
    $firewallRuleNameV4 = 'ESE_V91_D01_' + $nonce + '_V4_ALLOW'
    $firewallRuleNameV6Drop = 'ESE_V91_D01_' + $nonce + '_V6_DROP'
    $firewallRulesCreated = $false
    $firewallRulesRemoved = $false
    $firewallRuleNamesCreated = [Collections.Generic.List[string]]::new()
    $firewallEvidence = $null
    $sourceContainment = $null
    $sourceContainmentArmedEvidence = $null
    $runtimeError = $null
    $failureStage = 'preflight'
    $cleanupFailures = New-Object 'Collections.Generic.List[string]'
    $identityBefore = $null
    $identityAfter = $null
    $isolation = $null
    $topology = $null
    $preferences = $null
    $sourceCodeBinding = $null
    $sourceProcessBinding = $null
    $terminalOwnership = $null
    $listenerEvidence = $null
    $fixture = $null
    $sourceFile = ''
    $fixtureLockedSnapshot = $null
    $fixturePostStopSnapshot = $null
    $fixtureUnchangedAfterStop = $false
    $shared = $null
    $apiSamples = 0
    $apiUnavailable = 0
    $apiIsolationFailures = 0
    $firstApiIsolationFailureEvidence = $null
    $uiSamples = 0
    $uiUnavailable = 0
    $uiUnresponsive = 0
    $firstUiTimeoutFailureEvidence = $null
    $inverseObservation = $null
    $inverseBaselineZero = $false
    $inverseUniqueKeys =
        New-Object 'Collections.Generic.HashSet[string]'
    $inverseActiveKeys =
        New-Object 'Collections.Generic.HashSet[string]'
    $inverseForeignKeys =
        New-Object 'Collections.Generic.HashSet[string]'
    $inverseAllConnectionKeys =
        New-Object 'Collections.Generic.HashSet[string]'
    $inverseAllowedRemoteAddresses = @()
    $inverseSeenCounts = @{}
    $inverseFirstSeenSample = @{}
    $inverseAmbiguityCount = 0
    $inverseGenerationCount = 0
    $sourceStopped = $false
    $sourceArmAck = $null
    $sourceProductActive = $false
    $sourceProductProcessExited = $false
    $sourceProcessExitEvidence = $null
    $nodeExeUnchanged = $false
    $candidateUnchanged = $false
    $startedAt = [DateTime]::UtcNow

    try {
        $identityBefore = Get-D01CandidateIdentity
        Write-LabJson -Value $identityBefore.extracted_manifest -Path (
            Join-Path $evidence 'package-manifest-before.json'
        ) | Out-Null
        Write-LabJson -Value $identityBefore.zip_manifest -Path (
            Join-Path $evidence 'zip-manifest-before.json'
        ) | Out-Null
        if (-not $identityBefore.exact) {
            throw 'Source package/ZIP identity does not match the exact candidate'
        }
        if (-not (Test-Path -LiteralPath $coordination -PathType Container)) {
            throw "Coordinator run directory is unavailable: $coordination"
        }
        $runWait = Wait-D01JsonFile -Path $runPath `
            -TimeoutSeconds $PeerReadyTimeoutSeconds
        if ($null -eq $runWait) {
            throw 'Timed out waiting for coordinator run.json'
        }
        $run = $runWait.value
        $null = Assert-D01RunCoordinationContract -Run $run
        if ([string]$run.schema -cne 'ese.v91.d01-run/v3' -or
            [string]$run.case_id -ne $caseId -or
            [string]$run.run_nonce -ne $nonce -or
            [string]$run.candidate.commit -ne
                $identityBefore.candidate.commit -or
            [string]$run.candidate.emule_sha256 -ne
                $expectedEmuleHash -or
            [string]$run.candidate.package_zip_sha256 -ne
                $expectedZipHash -or
            [string]$run.candidate.extracted_manifest_sha256 -ne
                $identityBefore.extracted_manifest.manifest_sha256 -or
            [string]$run.candidate.zip_manifest_sha256 -ne
                $identityBefore.zip_manifest.manifest_sha256 -or
            [string]$run.fixture.hostname -ne $canonicalHostname -or
            [string]$run.fixture.source_public_ipv4 -ne
                $script:sourcePublicV4Text -or
            [string]$run.fixture.source_local_ipv4 -ne
                $script:sourceLocalV4Text -or
            [string]$run.fixture.source_ipv6 -ne
                $script:sourceV6Text -or
            [string]$run.fixture.coordinator_public_ipv4 -ne
                $script:coordinatorPublicV4Text -or
            [string]$run.fixture.coordinator_local_ipv4 -ne
                $script:coordinatorLocalV4Text -or
            [string]$run.fixture.coordinator_ipv6 -ne
                $script:coordinatorV6Text -or
            [int]$run.fixture.source_tcp_port -ne $SourceTcpPort -or
            [Int64]$run.fixture.file_size_bytes -ne $FileSizeBytes -or
            [string]$run.coordinator.machine_id_sha256 -cne
                $ExpectedCoordinatorMachineIdSha256.ToLowerInvariant() -or
            -not [bool]$run.coordinator.native_physical -or
            -not [bool]$run.coordinator.overlay_vpn_proxy_absent -or
            [string]$run.operator_identity.coordinator.machine_id_sha256 -cne
                $ExpectedCoordinatorMachineIdSha256.ToLowerInvariant() -or
            [string]$run.operator_identity.coordinator.user_sid_sha256 -cne
                $ExpectedCoordinatorUserSidSha256.ToLowerInvariant() -or
            [string]$run.operator_identity.expected_source_machine_id_sha256 -cne
                $ExpectedSourceMachineIdSha256.ToLowerInvariant() -or
            [string]$run.operator_identity.expected_source_user_sid_sha256 -cne
                $ExpectedSourceUserSidSha256.ToLowerInvariant()) {
            throw 'Source arguments/package do not exactly match run.json'
        }

        $isolation = Get-D01IsolationEvidence
        Write-LabJson -Value $isolation -Path (
            Join-Path $evidence 'isolation.json'
        ) | Out-Null
        if (-not $isolation.strict_isolation_valid) {
            throw 'Source has an active overlay/VPN adapter or proxy environment'
        }
        Test-D01PortsFree -Ports @(
            $SourceTcpPort, $SourceUdpPort, $SourceWebPort
        )
        $assignedV4 = Get-D01AssignedAddress `
            -Address $script:sourceLocalV4Text `
            -Family ([Net.Sockets.AddressFamily]::InterNetwork) `
            -Context 'source-local-ipv4'
        $assignedV6 = Get-D01AssignedAddress `
            -Address $script:sourceV6Text `
            -Family ([Net.Sockets.AddressFamily]::InterNetworkV6) `
            -Context 'source-public-ipv6'
        if (-not $assignedV4.adapter.physical_nonvirtual -or
            -not $assignedV6.adapter.physical_nonvirtual) {
            throw 'Source addresses are not assigned to physical native adapters'
        }
        if ([int]$assignedV4.interface_index -ne
            [int]$assignedV6.interface_index) {
            throw 'Source local IPv4 and public IPv6 are not on one physical adapter'
        }
        if ($script:sourcePublicV4Text -eq $script:sourceLocalV4Text -and
            $assignedV4.address_class -ne 'public-unicast-v4') {
            throw 'Direct T1 SourcePublicIPv4 must be a global assigned address'
        }
        $routeV4 = Get-D01RouteEvidence `
            -RemoteAddress $script:coordinatorPublicV4Text `
            -Context 'source-route-to-coordinator-ipv4'
        $routeV6 = Get-D01RouteEvidence `
            -RemoteAddress $script:coordinatorV6Text `
            -Context 'source-route-to-coordinator-ipv6'
        if (-not $routeV4.available -or -not $routeV6.available -or
            -not $routeV4.adapter.physical_nonvirtual -or
            -not $routeV6.adapter.physical_nonvirtual -or
            [int]$routeV4.interface_index -ne
                [int]$assignedV4.interface_index -or
            [int]$routeV6.interface_index -ne
                [int]$assignedV6.interface_index -or
            [string]$routeV4.source_address -cne
                [string]$assignedV4.address -or
            [string]$routeV6.source_address -cne
                [string]$assignedV6.address) {
            throw 'Source does not have native physical routes to coordinator'
        }
        $inverseAllowedRemoteAddresses = @(
            @(
                $script:coordinatorLocalV4Text,
                $script:coordinatorPublicV4Text,
                [string]$routeV4.next_hop
            ) | ForEach-Object {
                Get-D01NormalizedIp -Address ([string]$_)
            } | Where-Object {
                $_ -notin @('', '0.0.0.0', '::')
            } | Sort-Object -Unique
        )
        if ($inverseAllowedRemoteAddresses.Count -eq 0) {
            throw 'No controlled source-visible coordinator address was derived'
        }
        $topology = [pscustomobject][ordered]@{
            machine_id_sha256 = Get-D01MachineId
            source_local_ipv4 = $assignedV4
            source_public_ipv4 = $script:sourcePublicV4Text
            source_public_ipv4_is_nat =
                $script:sourcePublicV4Text -ne $script:sourceLocalV4Text
            source_ipv6 = $assignedV6
            route_to_coordinator_public_ipv4 = $routeV4
            route_to_coordinator_ipv6 = $routeV6
            allowed_inverse_remote_addresses =
                $inverseAllowedRemoteAddresses
            native_physical = $true
            overlay_vpn_proxy_absent = $true
        }
        Write-LabJson -Value $topology -Path (
            Join-Path $evidence 'topology.json'
        ) | Out-Null

        $failureStage = 'profile-setup'
        & (Join-Path $PSScriptRoot 'prepare_node.ps1') -NodeRole A `
            -SourcePackage $identityBefore.candidate.package_path `
            -OutputRoot $nodes -RunId "v91-d01-$nonce" -PortOffset 6100
        $sourceNode = Join-Path $nodes "v91-d01-$nonce-a"
        $sourceExe = Join-Path $sourceNode 'emule.exe'
        $null = Assert-D01PreparedNodeDerivedFromBinding `
            -NodePath $sourceNode -Binding $script:d01CandidateBinding
        if ((Get-LabSha256 -Path $sourceExe) -ne $expectedEmuleHash) {
            throw 'Prepared source executable is not the exact candidate'
        }
        $incoming = New-LabDirectory -Path (Join-Path $sourceNode 'Incoming')
        $temp = New-LabDirectory -Path (Join-Path $sourceNode 'Temp')
        foreach ($directory in @($incoming, $temp)) {
            if (@(Get-ChildItem -LiteralPath $directory -Force).Count -ne 0) {
                throw "Prepared source transfer directory is not empty: $directory"
            }
        }
        $preferences = Set-D01IsolatedPreferences -NodePath $sourceNode `
            -IPv6Mode 0 -IPv6BindAddress $script:sourceV6Text `
            -WebPort $SourceWebPort -TcpPort $SourceTcpPort `
            -UdpPort $SourceUdpPort -IncomingPath $incoming `
            -TempPath $temp -SourceProfile
        $null = Assert-D01SafetyPreferenceContract `
            -Path (Join-Path $sourceNode 'config\preferences.ini')
        $fileName = "v91-d01-$nonce.bin"
        $sourceFile = Join-Path $incoming $fileName
        $fixture = New-D01FixtureFile -Path $sourceFile -Bytes $FileSizeBytes
        $fixture | Add-Member -NotePropertyName file_name `
            -NotePropertyValue $fileName
        $fixtureLockedSnapshot = Open-D01ImmutableEvidenceSnapshot `
            -Path $sourceFile -MetadataOnly
        if ([Int64]$fixtureLockedSnapshot.byte_count -ne $FileSizeBytes -or
            [string]$fixtureLockedSnapshot.sha256 -cne
                [string]$fixture.sha256 -or
            -not [bool]$fixtureLockedSnapshot.immutable_read_lock_held) {
            throw 'Source fixture immutable snapshot does not match generation'
        }

        $failureStage = 'runtime-startup'
        $null = Assert-D01CandidateBindingUnchanged `
            -Binding $script:d01CandidateBinding
        $null = Test-D01PortsFree -Ports @(
            $SourceTcpPort, $SourceUdpPort, $SourceWebPort)
        $sourceCodeBinding = Lock-D01PreparedNodeCode `
            -NodePath $sourceNode -ExpectedExeSha256 $expectedEmuleHash
        Write-D01JsonAtomic -Value ([ordered]@{
            schema = 'ese.v91.d01-firewall-intent/v2'
            captured_at_utc = Get-LabUtcTimestamp
            rules = @(
                [ordered]@{
                    rule_name = $firewallRuleNameV4
                    display_name = $firewallRuleV4
                    action = 'Allow'
                    program = $sourceExe
                    local_address = $script:sourceLocalV4Text
                    remote_addresses =
                        $inverseAllowedRemoteAddresses
                    local_port = $SourceTcpPort
                    protocol = 'TCP'
                },
                [ordered]@{
                    rule_name = $firewallRuleNameV6Drop
                    display_name = $firewallRuleV6Drop
                    action = 'Block'
                    program = 'Any'
                    local_address = $script:sourceV6Text
                    remote_address = $script:coordinatorV6Text
                    local_port = $SourceTcpPort
                    protocol = 'TCP'
                    purpose =
                        'silent controlled AAAA DROP preserving SynSent'
                }
            )
        }) -Path (Join-Path $evidence 'firewall-intent.json')
        $firewallInventoryBefore = @(Get-NetFirewallRule `
            -PolicyStore ActiveStore -ErrorAction Stop)
        if (@($firewallInventoryBefore | Where-Object {
            [string]$_.Name -in @($firewallRuleNameV4,
                $firewallRuleNameV6Drop) -or
            [string]$_.DisplayName -in @($firewallRuleV4,
                $firewallRuleV6Drop)
        }).Count -ne 0) {
            throw 'Nonce-scoped D01 firewall rule identity was not initially absent'
        }
        New-NetFirewallRule -Name $firewallRuleNameV4 `
            -DisplayName $firewallRuleV4 -Direction Inbound `
            -Action Allow -Protocol TCP -Program $sourceExe `
            -LocalAddress $script:sourceLocalV4Text `
            -RemoteAddress $inverseAllowedRemoteAddresses `
            -LocalPort $SourceTcpPort -Profile Any `
            -ErrorAction Stop | Out-Null
        $firewallRuleNamesCreated.Add($firewallRuleNameV4)
        New-NetFirewallRule -Name $firewallRuleNameV6Drop `
            -DisplayName $firewallRuleV6Drop `
            -Direction Inbound -Action Block -Protocol TCP `
            -LocalAddress $script:sourceV6Text `
            -RemoteAddress $script:coordinatorV6Text `
            -LocalPort $SourceTcpPort -Profile Any `
            -ErrorAction Stop | Out-Null
        $firewallRuleNamesCreated.Add($firewallRuleNameV6Drop)
        $firewallRulesCreated = $true
        $firewallEvidence = [pscustomobject][ordered]@{
            ipv4_allow = Get-D01FirewallRuleEvidence `
                -RuleName $firewallRuleNameV4 `
                -DisplayName $firewallRuleV4 -ExpectedAction Allow `
                -ExpectedLocalAddress $script:sourceLocalV4Text `
                -ExpectedRemoteAddress $inverseAllowedRemoteAddresses `
                -ExpectedLocalPort $SourceTcpPort `
                -ExpectedRemotePort Any -ExpectedProgram $sourceExe `
                -ExpectedProfile Any
            ipv6_drop = Get-D01FirewallRuleEvidence `
                -RuleName $firewallRuleNameV6Drop `
                -DisplayName $firewallRuleV6Drop -ExpectedAction Block `
                -ExpectedLocalAddress $script:sourceV6Text `
                -ExpectedRemoteAddress $script:coordinatorV6Text `
                -ExpectedLocalPort $SourceTcpPort `
                -ExpectedRemotePort Any -ExpectedProgram Any `
                -ExpectedProfile Any
        }
        Write-LabJson -Value $firewallEvidence -Path (
            Join-Path $evidence 'firewall-armed.json'
        ) | Out-Null
        if (-not $firewallEvidence.ipv4_allow.exact -or
            -not $firewallEvidence.ipv6_drop.exact) {
            throw 'Source firewall allow/DROP rules are not exact'
        }

        $sourceContainment = Start-D01ProgramNetworkContainment `
            -Nonce $nonce -Role Source -Program $sourceExe `
            -AllowedTcpRemoteAddresses @(
                @($inverseAllowedRemoteAddresses) + @('127.0.0.1', '::1'))
        if (-not [bool]$sourceContainment.armed_exact) {
            throw 'Source program network containment could not be armed exactly'
        }
        $sourceContainmentArmedEvidence =
            Get-D01ProgramContainmentArmedProjection `
                -State $sourceContainment
        $null = Assert-D01ProgramContainmentArmedContract `
            -Evidence $sourceContainmentArmedEvidence `
            -Context 'source local program containment'
        Write-LabJson -Value $sourceContainmentArmedEvidence -Path (
            Join-Path $evidence 'program-containment-armed.json'
        ) | Out-Null

        $source = Start-D01OwnedCandidateProcess -FilePath $sourceExe `
            -ArgumentList @(
                '--portable', '--ignoreinstances',
                "--metrics-port=$SourceWebPort",
                "--tcp-port=$SourceTcpPort",
                "--udp-port=$SourceUdpPort"
            ) -WorkingDirectory $sourceNode -OwnerRole 'Source' -Nonce $nonce
        $sourceProcessBinding = Get-D01OwnedProcessBindingEvidence `
            -Process $source -ExpectedPath $sourceExe -RequireLive
        $listenerEvidence = Wait-D01Listener -Port $SourceTcpPort `
            -Process $source -RequireIPv4Only
        $startupApi = Wait-D01Api -Port $SourceWebPort -Process $source `
            -ExpectedPath $sourceExe
        if (-not (Test-D01ApiIsolation -Data $startupApi)) {
            throw 'Source API shows NetLab, Kad or eD2K server activity'
        }
        if ((Get-LabSha256 -Path $source.Path) -ne $expectedEmuleHash) {
            throw 'Running source process is not the exact candidate'
        }
        $session = Get-D01ClassicSession -Port $SourceWebPort `
            -Process $source -ExpectedPath $sourceExe
        $shared = Get-D01SharedLink -Port $SourceWebPort `
            -Process $source -ExpectedPath $sourceExe `
            -Session $session -FileName $fileName -FileBytes $FileSizeBytes

        $ready = [ordered]@{
            schema = 'ese.v91.d01-source-ready/v6'
            case_id = $caseId
            run_nonce = $nonce
            generated_at_utc = Get-LabUtcTimestamp
            machine_id_sha256 = $topology.machine_id_sha256
            operator_identity = [ordered]@{
                source = Get-D01HostIdentityEvidence
                expected_coordinator_machine_id_sha256 =
                    $ExpectedCoordinatorMachineIdSha256.ToLowerInvariant()
                expected_coordinator_user_sid_sha256 =
                    $ExpectedCoordinatorUserSidSha256.ToLowerInvariant()
            }
            candidate = [ordered]@{
                commit = $identityBefore.candidate.commit
                emule_sha256 = $expectedEmuleHash
                package_zip_sha256 = $expectedZipHash
                extracted_manifest_sha256 =
                    $identityBefore.extracted_manifest.manifest_sha256
                zip_manifest_sha256 =
                    $identityBefore.zip_manifest.manifest_sha256
            }
            topology = $topology
            process = [ordered]@{
                process_id = $source.Id
                process_emule_sha256 = Get-LabSha256 -Path $source.Path
                binding = $sourceProcessBinding
                listener = $listenerEvidence
                api_isolation_valid = $true
            }
            fixture = [ordered]@{
                file_name = $fileName
                file_bytes = $FileSizeBytes
                file_sha256 = $fixture.sha256
                ed2k_hash = $shared.ed2k_hash
                shared_link = $shared.link
                shared_link_sha256 =
                    Get-LabStringSha256 -Value $shared.link
                immutable_read_lock_held =
                    [bool]$fixtureLockedSnapshot.immutable_read_lock_held
                locked_byte_count =
                    [Int64]$fixtureLockedSnapshot.byte_count
                locked_sha256 = [string]$fixtureLockedSnapshot.sha256
            }
            preferences = $preferences
            firewall = [ordered]@{
                rules_created = $firewallRulesCreated
                exact = $firewallEvidence.ipv4_allow.exact -and
                    $firewallEvidence.ipv6_drop.exact -and
                    [bool]$sourceContainmentArmedEvidence.exact
                ipv4_allow = $firewallEvidence.ipv4_allow
                ipv6_drop = $firewallEvidence.ipv6_drop
                program_containment = $sourceContainmentArmedEvidence
                AAAA_failure_mode = 'controlled silent inbound DROP'
            }
        }
        $null = Assert-D01SourceReadyCoordinationContract `
            -Ready ([pscustomobject]$ready)
        Write-D01JsonAtomic -Value $ready -Path $readyPath
        Write-Host (
            "V91-D01 source ready for coordinator nonce $nonce"
        ) -ForegroundColor Cyan

        $failureStage = 'observation-barrier'
        $observeWait = Wait-D01JsonFile -Path $observePath `
            -StopPath $stopPath `
            -TimeoutSeconds ($PeerReadyTimeoutSeconds + $TransferTimeoutSeconds)
        if ($null -eq $observeWait -or $observeWait.kind -eq 'stop') {
            throw 'Coordinator stopped or timed out before observation barrier'
        }
        $observe = $observeWait.value
        $null = Assert-D01ObserveCommandContract -Command $observe
        if ([string]$observe.schema -ne
                'ese.v91.d01-observe-command/v2' -or
            [string]$observe.case_id -ne $caseId -or
            [string]$observe.run_nonce -ne $nonce -or
            [string]$observe.candidate_commit -ne
                $identityBefore.candidate.commit -or
            [string]$observe.candidate_emule_sha256 -ne
                $expectedEmuleHash -or
            [int]$observe.downloader_process_id -le 0 -or
            [string]$observe.hostname_sha256 -ne
                (Get-LabStringSha256 -Value $canonicalHostname)) {
            throw 'Invalid coordinator observation command'
        }
        $baselineWaitStarted = [DateTime]::UtcNow
        $baselineWaitDeadline = $baselineWaitStarted.AddSeconds(
            [Math]::Max(
                1, [Math]::Min(120, $PeerReadyTimeoutSeconds - 5)
            )
        )
        $baselineSampleCount = 0
        do {
            $baselineSampleCount++
            $baselineIncoming = @(
                Get-D01IncomingConnections -ProcessId 0 `
                    -LocalPort $SourceTcpPort
            )
            if ($baselineIncoming.Count -eq 0) { break }
            Start-Sleep -Milliseconds 100
        } while ([DateTime]::UtcNow -lt $baselineWaitDeadline)
        $inverseBaselineZero = $baselineIncoming.Count -eq 0
        Write-D01JsonAtomic -Value ([ordered]@{
            schema = 'ese.v91.d01-source-observing/v4'
            case_id = $caseId
            run_nonce = $nonce
            generated_at_utc = Get-LabUtcTimestamp
            source_process_id = $source.Id
            source_process_emule_sha256 = Get-LabSha256 -Path $source.Path
            expected_downloader_process_id =
                [int]$observe.downloader_process_id
            all_processes_and_nonlisten_states_checked = $true
            allowed_source_visible_remote_addresses =
                $inverseAllowedRemoteAddresses
            baseline_established_connection_count =
                @($baselineIncoming | Where-Object {
                    [string]$_.state -eq 'Established'
                }).Count
            baseline_nonlisten_connection_count =
                $baselineIncoming.Count
            baseline_wait_sample_count = $baselineSampleCount
            baseline_wait_duration_ms = [Int64](
                ([DateTime]::UtcNow - $baselineWaitStarted).
                    TotalMilliseconds
            )
            baseline_zero = $inverseBaselineZero
        }) -Path $observeAckPath
        if (-not $inverseBaselineZero) {
            throw (
                'Source observation baseline contains a pre-existing ' +
                'non-listening socket'
            )
        }

        $failureStage = 'arm-wait'
        $monitorStarted = [DateTime]::UtcNow
        $deadline = $monitorStarted.AddSeconds(
            $PeerReadyTimeoutSeconds + $TransferTimeoutSeconds + 600
        )
        $nextHealth = [DateTime]::UtcNow
        $sampleNumber = 0
        $stopCommand = $null
        do {
            $source.Refresh()
            if ($source.HasExited) {
                if ($sourceProductActive) {
                    $sourceProductProcessExited = $true
                    $sourceProcessExitEvidence = [pscustomobject][ordered]@{
                        schema = 'ese.v91.d01-source-process-exit/v1'
                        arm_id = [string]$sourceArmAck.arm_id
                        observed_epoch_unix_ns = Get-D01EpochUnixNs
                        source_process_id = [int]$source.Id
                        source_ownership_id_sha256 =
                            [string]$sourceProcessBinding.ownership_id_sha256
                        retained_handle_observed_exit = $true
                        has_exited = $true
                        exit_code = [int]$source.ExitCode
                    }
                }
                throw "Source exited during transfer (exit $($source.ExitCode))"
            }
            $now = [DateTime]::UtcNow
            if (-not $sourceProductActive) {
                if (Test-Path -LiteralPath $armPath -PathType Leaf) {
                    if (Test-Path -LiteralPath $sourceArmedPath) {
                        throw 'source-armed.json existed before source arm acknowledgement'
                    }
                    $lockedArm = Read-D01ImmutableJsonFile -Path $armPath
                    $arm = $lockedArm.value
                    $null = Assert-D01ArmCommandContract -Command $arm
                    $armSourceBinding = Get-D01OwnedProcessBindingEvidence `
                        -Process $source -ExpectedPath $sourceExe -RequireLive
                    if ([string]$arm.case_id -cne $caseId -or
                        [string]$arm.run_nonce -cne $nonce -or
                        [string]$arm.candidate_commit -cne
                            [string]$identityBefore.candidate.commit -or
                        [string]$arm.candidate_emule_sha256 -cne
                            $expectedEmuleHash -or
                        [int]$arm.downloader_process_id -ne
                            [int]$observe.downloader_process_id -or
                        [string]$armSourceBinding.ownership_id_sha256 -cne
                            [string]$sourceProcessBinding.ownership_id_sha256) {
                        throw 'Coordinator arm command is not source/candidate-bound'
                    }
                    $apiSamples = 0
                    $apiUnavailable = 0
                    $apiIsolationFailures = 0
                    $uiSamples = 0
                    $uiUnavailable = 0
                    $uiUnresponsive = 0
                    $inverseObservation = $null
                    $inverseUniqueKeys.Clear()
                    $inverseActiveKeys.Clear()
                    $inverseForeignKeys.Clear()
                    $inverseAllConnectionKeys.Clear()
                    $inverseSeenCounts = @{}
                    $inverseFirstSeenSample = @{}
                    $inverseAmbiguityCount = 0
                    $inverseGenerationCount = 0
                    $sampleNumber = 0
                    $monitorStarted = [DateTime]::UtcNow
                    $localArmBoundaryEpochUnixNs = Get-D01EpochUnixNs
                    $sourceArmAck = [pscustomobject][ordered]@{
                        schema = 'ese.v91.d01-source-armed/v1'
                        case_id = $caseId
                        run_nonce = $nonce
                        generated_at_utc = Get-LabUtcTimestamp
                        arm_id = [string]$arm.arm_id
                        source_process_id = [int]$source.Id
                        source_ownership_id_sha256 =
                            [string]$armSourceBinding.ownership_id_sha256
                        downloader_process_id =
                            [int]$arm.downloader_process_id
                        downloader_ownership_id_sha256 =
                            [string]$arm.downloader_ownership_id_sha256
                        health_counters_reset = $true
                        local_arm_boundary_epoch_unix_ns =
                            $localArmBoundaryEpochUnixNs
                    }
                    $null = Assert-D01SourceArmedContract -Ack $sourceArmAck
                    Write-D01JsonAtomic -Value $sourceArmAck `
                        -Path $sourceArmedPath
                    $sourceProductActive = $true
                    $failureStage = 'transfer-observation'
                    $nextHealth = [DateTime]::UtcNow
                    $now = [DateTime]::UtcNow
                } else {
                    if (Test-Path -LiteralPath $stopPath -PathType Leaf) {
                        $lockedStopCommand = Read-D01ImmutableJsonFile `
                            -Path $stopPath
                        $stopCommand = $lockedStopCommand.value
                        $null = Assert-D01StopCommandContract `
                            -Command $stopCommand
                        break
                    }
                    Start-Sleep -Milliseconds 50
                    continue
                }
            }
            $connections = @(
                Get-D01IncomingConnections -ProcessId 0 `
                    -LocalPort $SourceTcpPort
            )
            Add-D01JsonLine -Path $socketSamplesPath -Value ([ordered]@{
                schema = 'ese.v91.d01-source-socket-sample/v2'
                sample_number = ++$sampleNumber
                captured_at_utc = Get-LabUtcTimestamp
                elapsed_ms = [Int64](
                    ($now - $monitorStarted).TotalMilliseconds
                )
                connections = $connections
            })
            $foreignInverseConnections = @(
                $connections | Where-Object {
                    [int]$_.owning_process -ne $source.Id -or
                    [string]$_.local_address -ne
                        $script:sourceLocalV4Text -or
                    [int]$_.local_port -ne $SourceTcpPort -or
                    -not [bool]$_.physical_nonvirtual -or
                    [string]$_.remote_address -notin
                        $inverseAllowedRemoteAddresses -or
                    [int]$_.remote_port -le 0
                }
            )
            foreach ($foreignConnection in $foreignInverseConnections) {
                $foreignKey = '{0}|{1}|{2}|{3}|{4}|{5}' -f
                    [int]$foreignConnection.owning_process,
                    [string]$foreignConnection.state,
                    [string]$foreignConnection.local_address,
                    [int]$foreignConnection.local_port,
                    [string]$foreignConnection.remote_address,
                    [int]$foreignConnection.remote_port
                $null = $inverseForeignKeys.Add($foreignKey)
            }
            foreach ($allowedConnection in @(
                $connections | Where-Object {
                    [int]$_.owning_process -eq $source.Id -and
                    [string]$_.local_address -eq
                        $script:sourceLocalV4Text -and
                    [int]$_.local_port -eq $SourceTcpPort -and
                    [bool]$_.physical_nonvirtual -and
                    [string]$_.remote_address -in
                        $inverseAllowedRemoteAddresses -and
                    [int]$_.remote_port -gt 0
                }
            )) {
                $allStateKey = '{0}|{1}|{2}|{3}|{4}' -f
                    [int]$allowedConnection.owning_process,
                    [string]$allowedConnection.local_address,
                    [int]$allowedConnection.local_port,
                    [string]$allowedConnection.remote_address,
                    [int]$allowedConnection.remote_port
                $null = $inverseAllConnectionKeys.Add($allStateKey)
            }
            if ($inverseForeignKeys.Count -gt 0) {
                $inverseAmbiguityCount =
                    [Math]::Max($inverseAmbiguityCount, 1)
            }
            if ($inverseAllConnectionKeys.Count -gt 1) {
                $inverseAmbiguityCount =
                    [Math]::Max($inverseAmbiguityCount, 1)
            }
            $established = @($connections | Where-Object {
                    [string]$_.state -eq 'Established' -and
                    [string]$_.local_address -eq
                        $script:sourceLocalV4Text -and
                    [int]$_.local_port -eq $SourceTcpPort -and
                    [int]$_.owning_process -eq $source.Id -and
                    [bool]$_.physical_nonvirtual -and
                    [string]$_.remote_address -in
                        $inverseAllowedRemoteAddresses -and
                    [int]$_.remote_port -gt 0
                })
            $currentInverseKeys =
                New-Object 'Collections.Generic.HashSet[string]'
            $connectionsByKey = @{}
            foreach ($establishedConnection in $established) {
                $inverseKey = '{0}|{1}|{2}|{3}|{4}' -f
                    [int]$establishedConnection.owning_process,
                    [string]$establishedConnection.local_address,
                    [int]$establishedConnection.local_port,
                    [string]$establishedConnection.remote_address,
                    [int]$establishedConnection.remote_port
                $null = $currentInverseKeys.Add($inverseKey)
                $connectionsByKey[$inverseKey] = $establishedConnection
            }
            foreach ($inverseKey in @($currentInverseKeys)) {
                if (-not $inverseActiveKeys.Contains($inverseKey) -and
                    $inverseUniqueKeys.Contains($inverseKey)) {
                    $inverseGenerationCount++
                    $inverseAmbiguityCount++
                }
                if ($inverseUniqueKeys.Add($inverseKey)) {
                    $inverseFirstSeenSample[$inverseKey] = $sampleNumber
                    $inverseSeenCounts[$inverseKey] = 0
                }
                $inverseSeenCounts[$inverseKey] =
                    [int]$inverseSeenCounts[$inverseKey] + 1
            }
            $inverseActiveKeys = $currentInverseKeys
            if ($inverseUniqueKeys.Count -gt 1) {
                $inverseAmbiguityCount =
                    [Math]::Max($inverseAmbiguityCount, 1)
            }
            if ($null -eq $inverseObservation -and
                $inverseUniqueKeys.Count -eq 1 -and
                $inverseAllConnectionKeys.Count -eq 1 -and
                $inverseAmbiguityCount -eq 0) {
                $onlyKey = @($inverseUniqueKeys)[0]
                if ($currentInverseKeys.Contains($onlyKey) -and
                    [int]$inverseSeenCounts[$onlyKey] -ge 2) {
                    $establishedConnection = $connectionsByKey[$onlyKey]
                    $inverseObservation = [pscustomobject][ordered]@{
                        schema = 'ese.v91.d01-source-observation/v4'
                        case_id = $caseId
                        run_nonce = $nonce
                        captured_at_utc = Get-LabUtcTimestamp
                        source_process_id = $source.Id
                        source_process_emule_sha256 =
                            Get-LabSha256 -Path $source.Path
                        connection = $establishedConnection
                        exact_inverse_pid_socket = $true
                        physical_adapter_proven = $true
                        baseline_zero = $inverseBaselineZero
                        baseline_established_connection_count = 0
                        baseline_nonlisten_connection_count = 0
                        all_processes_and_nonlisten_states_checked =
                            $true
                        allowed_source_visible_remote_addresses =
                            $inverseAllowedRemoteAddresses
                        source_visible_remote_address_allowed = $true
                        foreign_connection_count = 0
                        all_nonlisten_unique_socket_count = 1
                        new_socket_key_sha256 =
                            Get-LabStringSha256 -Value $onlyKey
                        first_seen_sample =
                            [int]$inverseFirstSeenSample[$onlyKey]
                        confirmed_sample = $sampleNumber
                        unique_new_socket_count = 1
                        ambiguity_count = 0
                        generation_count = 1
                        observation_window_started_at_utc =
                            $monitorStarted.ToString('o')
                        hairpin_nat_remote_address_not_assumed = $true
                    }
                    Write-D01JsonAtomic -Value $inverseObservation `
                        -Path $observationPath
                }
            }
            if ($now -ge $nextHealth) {
                $api = Get-D01ApiProbe -Port $SourceWebPort `
                    -Process $source -ExpectedPath $sourceExe
                $ui = Get-D01UiProbe -Process $source
                $apiSamples++
                $uiSamples++
                if (-not $api.available -or -not $api.contract_valid) {
                    $apiUnavailable++
                }
                if ($api.available -and $api.contract_valid -and
                    $api.contamination_proven) {
                    $apiIsolationFailures++
                    if ($null -eq $firstApiIsolationFailureEvidence) {
                        $firstApiIsolationFailureEvidence =
                            [pscustomobject][ordered]@{
                                schema =
                                    'ese.v91.d01-source-api-isolation-failure/v1'
                                arm_id = [string]$sourceArmAck.arm_id
                                observed_epoch_unix_ns = Get-D01EpochUnixNs
                                sample_number = [int]$apiSamples
                                source_process_id = [int]$source.Id
                                source_ownership_id_sha256 = [string](
                                    $sourceProcessBinding.ownership_id_sha256)
                                probe = $api
                            }
                    }
                }
                if (-not $ui.collector_ok -or -not $ui.source_bound -or
                    -not $ui.main_window_present) { $uiUnavailable++ }
                if ($ui.collector_ok -and $ui.source_bound -and
                    $ui.main_window_present -and $ui.timeout_proven -and
                    -not $ui.message_pump_responsive) {
                    $uiUnresponsive++
                    if ($null -eq $firstUiTimeoutFailureEvidence) {
                        $firstUiTimeoutFailureEvidence =
                            [pscustomobject][ordered]@{
                                schema =
                                    'ese.v91.d01-source-ui-timeout-failure/v1'
                                arm_id = [string]$sourceArmAck.arm_id
                                observed_epoch_unix_ns = Get-D01EpochUnixNs
                                sample_number = [int]$uiSamples
                                source_process_id = [int]$source.Id
                                source_ownership_id_sha256 = [string](
                                    $sourceProcessBinding.ownership_id_sha256)
                                probe = $ui
                            }
                    }
                }
                Add-D01JsonLine -Path $healthSamplesPath -Value ([ordered]@{
                    schema = 'ese.v91.d01-source-health-sample/v2'
                    captured_at_utc = Get-LabUtcTimestamp
                    api = $api
                    ui = $ui
                })
                $nextHealth = $now.AddSeconds(2)
            }
            if (Test-Path -LiteralPath $stopPath -PathType Leaf) {
                $lockedStopCommand = Read-D01ImmutableJsonFile `
                    -Path $stopPath
                $stopCommand = $lockedStopCommand.value
                $null = Assert-D01StopCommandContract `
                    -Command $stopCommand
                $source.Refresh()
                if ($source.HasExited -and $sourceProductActive) {
                    $sourceProductProcessExited = $true
                    $sourceProcessExitEvidence = [pscustomobject][ordered]@{
                        schema = 'ese.v91.d01-source-process-exit/v1'
                        arm_id = [string]$sourceArmAck.arm_id
                        observed_epoch_unix_ns = Get-D01EpochUnixNs
                        source_process_id = [int]$source.Id
                        source_ownership_id_sha256 =
                            [string]$sourceProcessBinding.ownership_id_sha256
                        retained_handle_observed_exit = $true
                        has_exited = $true
                        exit_code = [int]$source.ExitCode
                    }
                    throw (
                        'Source exited at the armed stop boundary ' +
                        "(exit $($source.ExitCode))")
                }
                break
            }
            if (($now - $monitorStarted).TotalSeconds -lt 20) {
                Start-Sleep -Milliseconds 50
            } else {
                Start-Sleep -Milliseconds 250
            }
        } while ([DateTime]::UtcNow -lt $deadline)
        if ($null -eq $stopCommand) {
            throw 'Timed out waiting for coordinator stop command'
        }
        if ([string]$stopCommand.schema -ne
                'ese.v91.d01-stop-command/v2' -or
            [string]$stopCommand.case_id -ne $caseId -or
            [string]$stopCommand.run_nonce -ne $nonce -or
            [string]$stopCommand.candidate_commit -ne
                $identityBefore.candidate.commit -or
            [string]$stopCommand.candidate_emule_sha256 -ne
                $expectedEmuleHash) {
            throw 'Invalid coordinator stop command'
        }
    } catch {
        $runtimeError = $_.Exception.Message
    } finally {

        if ($null -ne $source) {
            $stopResult = Stop-D01OwnedProcess -Process $source `
                -ExpectedPath $sourceExe
            $sourceStopped = [bool]$stopResult.stopped
            if (-not $sourceStopped) {
                $cleanupFailures.Add('Source process remains running')
            }
        } else {
            $sourceStopped = $true
        }
        if ($sourceFile -and $null -ne $fixtureLockedSnapshot) {
            try {
                $fixturePostStopSnapshot =
                    Open-D01ImmutableEvidenceSnapshot -Path $sourceFile `
                        -MetadataOnly
                $fixtureUnchangedAfterStop =
                    [Int64]$fixturePostStopSnapshot.byte_count -eq
                        [Int64]$fixtureLockedSnapshot.byte_count -and
                    [string]$fixturePostStopSnapshot.sha256 -ceq
                        [string]$fixtureLockedSnapshot.sha256 -and
                    [bool]$fixturePostStopSnapshot.immutable_read_lock_held
                if (-not $fixtureUnchangedAfterStop) {
                    $cleanupFailures.Add(
                        'Source fixture changed despite immutable snapshot')
                }
            } catch {
                $fixtureUnchangedAfterStop = $false
                $cleanupFailures.Add(
                    "Source fixture post-stop validation failed: $($_.Exception.Message)")
            }
        }
        if ($null -ne $sourceContainment) {
            if ($sourceStopped) {
                $sourceContainment = Remove-D01ProgramNetworkContainment `
                    -State $sourceContainment -Program $sourceExe
                if (-not [bool]$sourceContainment.cleanup_exact) {
                    $cleanupFailures.Add(
                        'Source program network containment cleanup is not exact')
                }
                Write-LabJson -Value $sourceContainment -Path (
                    Join-Path $evidence 'program-containment-final.json'
                ) | Out-Null
            } else {
                $cleanupFailures.Add(
                    'Source containment retained because source remains running')
            }
        }
        try {
            if (-not $sourceStopped) {
                throw 'Source firewall fixture retained while source remains running'
            }
            $cleanupSpecs = @(
                [pscustomobject]@{
                    name = $firewallRuleNameV4
                    display = $firewallRuleV4
                    action = 'Allow'
                    local = $script:sourceLocalV4Text
                    remote = $inverseAllowedRemoteAddresses
                    program = $sourceExe
                    armed = if ($null -ne $firewallEvidence) {
                        $firewallEvidence.ipv4_allow
                    } else { $null }
                },
                [pscustomobject]@{
                    name = $firewallRuleNameV6Drop
                    display = $firewallRuleV6Drop
                    action = 'Block'
                    local = $script:sourceV6Text
                    remote = @($script:coordinatorV6Text)
                    program = 'Any'
                    armed = if ($null -ne $firewallEvidence) {
                        $firewallEvidence.ipv6_drop
                    } else { $null }
                }
            )
            foreach ($spec in $cleanupSpecs) {
                if (-not $firewallRuleNamesCreated.Contains(
                    [string]$spec.name)) { continue }
                $current = Get-D01FirewallRuleEvidence `
                    -RuleName $spec.name -DisplayName $spec.display `
                    -ExpectedAction $spec.action `
                    -ExpectedLocalAddress $spec.local `
                    -ExpectedRemoteAddress @($spec.remote) `
                    -ExpectedLocalPort $SourceTcpPort `
                    -ExpectedRemotePort Any -ExpectedProgram $spec.program `
                    -ExpectedProfile Any
                if (-not $current.exact -or
                    ($null -ne $spec.armed -and
                        [string]$current.canonical_sha256 -cne
                            [string]$spec.armed.canonical_sha256)) {
                    throw "Nonce-owned firewall rule changed; refusing destructive cleanup: $($spec.name)"
                }
                Remove-NetFirewallRule -Name $spec.name `
                    -PolicyStore ActiveStore -ErrorAction Stop
            }
            $inventoryAfterCleanup = @(Get-NetFirewallRule `
                -PolicyStore ActiveStore -ErrorAction Stop)
            $remainingRules = @($inventoryAfterCleanup | Where-Object {
                [string]$_.Name -in @($firewallRuleNameV4,
                    $firewallRuleNameV6Drop) -or
                [string]$_.DisplayName -in @($firewallRuleV4,
                    $firewallRuleV6Drop)
            })
            $firewallRulesRemoved = $remainingRules.Count -eq 0
            if (-not $firewallRulesRemoved) {
                $cleanupFailures.Add(
                    'Temporary IPv4 allow or IPv6 DROP rule remains'
                )
            }
        } catch {
            $cleanupFailures.Add(
                "Firewall rollback failed: $($_.Exception.Message)"
            )
        }
        try {
            $identityAfter = Get-D01CandidateIdentity
            Write-LabJson -Value $identityAfter.extracted_manifest -Path (
                Join-Path $evidence 'package-manifest-after.json'
            ) | Out-Null
            Write-LabJson -Value $identityAfter.zip_manifest -Path (
                Join-Path $evidence 'zip-manifest-after.json'
            ) | Out-Null
            $candidateUnchanged = $null -ne $identityBefore -and
                $identityAfter.exact -and
                $identityAfter.extracted_manifest.manifest_sha256 -eq
                    $identityBefore.extracted_manifest.manifest_sha256 -and
                $identityAfter.zip_manifest.zip_sha256 -eq
                    $identityBefore.zip_manifest.zip_sha256
            if (-not $candidateUnchanged) {
                $cleanupFailures.Add('Source candidate package or ZIP changed')
            }
        } catch {
            $cleanupFailures.Add(
                "Source identity revalidation failed: $($_.Exception.Message)"
            )
        }
        if ($sourceExe -and
            (Test-Path -LiteralPath $sourceExe -PathType Leaf)) {
            $nodeExeUnchanged =
                (Get-LabSha256 -Path $sourceExe) -eq $expectedEmuleHash
        }
        if (-not $nodeExeUnchanged) {
            $cleanupFailures.Add('Prepared source executable changed')
        }
        if ($sourceNode) {
            try {
                $null = Assert-D01SafetyPreferenceContract `
                    -Path (Join-Path $sourceNode 'config\preferences.ini')
            } catch {
                $cleanupFailures.Add('Source safety preferences changed')
            }
        }
        $terminalOwnership = Get-D01TerminalOwnershipCensus `
            -Process $source -Ports @(
                $SourceTcpPort, $SourceUdpPort, $SourceWebPort) `
            -HostRole 'Source'
        if (-not $terminalOwnership.all_clear) {
            $cleanupFailures.Add('Source terminal process/port census is not clear')
        }
        if ($null -ne $script:d01HostsBaseline -and
            $null -eq $script:d01HostsPostcheck) {
            $script:d01HostsPostcheck =
                Get-D01HostsFilePostcheckEvidence `
                    -Baseline $script:d01HostsBaseline
            if (-not $script:d01HostsPostcheck.safe_to_pass) {
                $cleanupFailures.Add('Source hosts file changed or was unprovable')
            }
        }
        if ($null -ne $script:d01AccountRegistryTransaction -and
            -not $script:d01AccountRegistryPostcheckComplete) {
            $script:d01AccountRegistryPostcheck =
                Get-D01AccountRegistryPostcheckEvidence `
                    -Transaction $script:d01AccountRegistryTransaction
            $script:d01AccountRegistryPostcheckComplete = $true
            if (-not $script:d01AccountRegistryPostcheck.safe_to_pass) {
                $cleanupFailures.Add(
                    'Source account/registry/firewall postcheck is not exact')
            }
        }
    }

    $healthObservabilityAvailable =
        $apiSamples -gt 0 -and $uiSamples -gt 0
    $sourceHealthExact = $healthObservabilityAvailable -and
        $apiUnavailable -eq 0 -and $apiIsolationFailures -eq 0 -and
        $uiUnavailable -eq 0 -and $uiUnresponsive -eq 0
    $sourceInverseObservationContractValid = $false
    if ($null -ne $inverseObservation -and $null -ne $source -and
        $null -ne $sourceProcessBinding) {
        try {
            $null = Assert-D01SourceObservationContract `
                -Observation $inverseObservation
            $sourceInverseObservationContractValid =
                [string]$inverseObservation.case_id -ceq $caseId -and
                [string]$inverseObservation.run_nonce -ceq $nonce -and
                [int]$inverseObservation.source_process_id -eq $source.Id -and
                [string]$inverseObservation.source_process_emule_sha256 -ceq
                    $expectedEmuleHash
        } catch { $sourceInverseObservationContractValid = $false }
    }
    $sourceInverseAggregateExact =
        $sourceInverseObservationContractValid -and $inverseBaselineZero -and
        $inverseForeignKeys.Count -eq 0 -and
        $inverseAllConnectionKeys.Count -eq 1 -and
        $inverseUniqueKeys.Count -eq 1 -and
        $inverseAmbiguityCount -eq 0 -and $inverseGenerationCount -eq 0 -and
        [int]$inverseObservation.foreign_connection_count -eq 0 -and
        [int]$inverseObservation.all_nonlisten_unique_socket_count -eq 1 -and
        [int]$inverseObservation.unique_new_socket_count -eq 1 -and
        [int]$inverseObservation.ambiguity_count -eq 0 -and
        [int]$inverseObservation.generation_count -eq 1
    $sourceProductObservabilityComplete =
        $null -ne $topology -and $null -ne $sourceProcessBinding -and
        $null -ne $listenerEvidence -and $null -ne $shared -and
        $null -ne $fixtureLockedSnapshot -and $fixtureUnchangedAfterStop -and
        $healthObservabilityAvailable -and $apiUnavailable -eq 0 -and
        $uiUnavailable -eq 0 -and $sourceInverseAggregateExact -and
        $null -ne $firewallEvidence -and
        [bool]$firewallEvidence.ipv4_allow.exact -and
        [bool]$firewallEvidence.ipv6_drop.exact -and
        $null -ne $sourceContainmentArmedEvidence -and
        $sourceProductActive -and $null -ne $sourceArmAck -and
        [bool]$sourceContainmentArmedEvidence.exact
    $sourceStatus = if ($null -eq $runtimeError -and
        $sourceStopped -and $firewallRulesCreated -and $firewallRulesRemoved -and
        $null -ne $sourceContainmentArmedEvidence -and
        [bool]$sourceContainmentArmedEvidence.exact -and
        $null -ne $sourceContainment -and
        [bool]$sourceContainment.cleanup_exact -and
        [bool]$sourceContainment.enforcement_exact_through_disarm -and
        $candidateUnchanged -and $nodeExeUnchanged -and
        $sourceProductObservabilityComplete -and $sourceHealthExact -and
        $cleanupFailures.Count -eq 0) {
        'COMPLETE'
    } else { 'INCOMPLETE' }
    $sourcePublicationId = [Guid]::NewGuid().ToString('N')
    $result = [ordered]@{
        schema = 'ese.v91.d01-source-result/v8'
        case_id = $caseId
        run_nonce = $nonce
        publication_id = $sourcePublicationId
        generated_at_utc = Get-LabUtcTimestamp
        status = $sourceStatus
        runtime_error = $runtimeError
        failure_stage = $failureStage
        machine_id_sha256 = if ($null -ne $topology) {
            $topology.machine_id_sha256
        } else { Get-D01MachineId }
        operator_identity = Get-D01HostIdentityEvidence
        candidate = [ordered]@{
            commit = if ($null -ne $identityBefore) {
                $identityBefore.candidate.commit
            } else { $Commit.ToLowerInvariant() }
            emule_sha256 = $expectedEmuleHash
            package_zip_sha256 = $expectedZipHash
            unchanged = $candidateUnchanged
            prepared_executable_unchanged = $nodeExeUnchanged
        }
        topology = $topology
        source_process_id = if ($null -ne $source) {
            $source.Id
        } else { $null }
        source_process_binding = $sourceProcessBinding
        source_listener = $listenerEvidence
        source_arm = $sourceArmAck
        product_process_exited_after_arm = $sourceProductProcessExited
        first_api_isolation_failure_evidence =
            $firstApiIsolationFailureEvidence
        first_ui_timeout_failure_evidence = $firstUiTimeoutFailureEvidence
        process_exit_evidence = $sourceProcessExitEvidence
        fixture = if ($null -ne $shared) {
            [ordered]@{
                file_name = $fixture.file_name
                file_bytes = $fixture.bytes
                file_sha256 = $fixture.sha256
                ed2k_hash = $shared.ed2k_hash
                immutable_source_lock_held =
                    $null -ne $fixtureLockedSnapshot -and
                    [bool]$fixtureLockedSnapshot.immutable_read_lock_held
                post_stop_bytes = if ($null -ne $fixturePostStopSnapshot) {
                    [Int64]$fixturePostStopSnapshot.byte_count
                } else { [Int64]0 }
                post_stop_sha256 = if ($null -ne $fixturePostStopSnapshot) {
                    [string]$fixturePostStopSnapshot.sha256
                } else { '' }
                unchanged_after_stop = $fixtureUnchangedAfterStop
            }
        } else { $null }
        inverse_socket_observation = $inverseObservation
        inverse_socket_observed = $null -ne $inverseObservation
        inverse_socket_baseline_zero = $inverseBaselineZero
        inverse_socket_baseline_all_nonlisten_states_checked = $true
        inverse_socket_allowed_remote_addresses =
            $inverseAllowedRemoteAddresses
        inverse_socket_foreign_connection_count =
            $inverseForeignKeys.Count
        inverse_socket_all_nonlisten_unique_count =
            $inverseAllConnectionKeys.Count
        inverse_socket_unique_new_count = $inverseUniqueKeys.Count
        inverse_socket_ambiguity_count = $inverseAmbiguityCount
        inverse_socket_generation_count =
            $inverseUniqueKeys.Count + $inverseGenerationCount
        product_observability_complete =
            $sourceProductObservabilityComplete
        health = [ordered]@{
            observability_available = $healthObservabilityAvailable
            api_sample_count = $apiSamples
            api_unavailable_count = $apiUnavailable
            api_isolation_failure_count = $apiIsolationFailures
            ui_sample_count = $uiSamples
            ui_unavailable_count = $uiUnavailable
            ui_unresponsive_count = $uiUnresponsive
        }
        cleanup = [ordered]@{
            source_process_stopped = $sourceStopped
            temporary_firewall_rules_created = $firewallRulesCreated
            temporary_firewall_rules_removed = $firewallRulesRemoved
            ipv4_allow_rule_name = $firewallRuleV4
            ipv6_drop_rule_name = $firewallRuleV6Drop
            firewall_armed_evidence = $firewallEvidence
            program_containment_armed_evidence =
                $sourceContainmentArmedEvidence
            program_containment_removed =
                $null -ne $sourceContainment -and
                [bool]$sourceContainment.cleanup_exact
            program_containment_enforcement_exact_through_disarm =
                $null -ne $sourceContainment -and
                [bool]$sourceContainment.enforcement_exact_through_disarm
            candidate_unchanged = $candidateUnchanged
            prepared_executable_unchanged = $nodeExeUnchanged
            dns_modified = $false
            hosts_modified = $null -eq $script:d01HostsPostcheck -or
                -not [bool]$script:d01HostsPostcheck.safe_to_pass
            routes_modified = $false
            adapters_modified = $false
            overlay_vpn_modified = $false
            proxy_modified = $false
            account_registry_firewall_postcheck =
                $script:d01AccountRegistryPostcheck
            terminal_ownership = $terminalOwnership
            hosts_file_postcheck = $script:d01HostsPostcheck
            failures = @($cleanupFailures)
        }
    }
    $null = Assert-D01SourceResultCoordinationContract `
        -Result ([pscustomobject]$result) `
        -ExpectedSourceWebPort $SourceWebPort
    Write-D01JsonAtomic -Value $result -Path $summaryPath
    $sourcePrivateSnapshot = Open-D01ImmutableEvidenceSnapshot `
        -Path $summaryPath `
        -MetadataOnly
    $sourcePublicSummary = Get-D01SourcePublicSummaryProjection `
        -PrivateResult ([pscustomobject]$result) `
        -PublicationId $sourcePublicationId
    $null = Assert-D01SourcePublicSummaryProjection `
        -Projection $sourcePublicSummary
    $sourcePublicPath = Join-Path $evidence 'public-summary.json'
    Write-D01JsonAtomic -Value $sourcePublicSummary -Path $sourcePublicPath
    $sourcePublicSnapshot = Open-D01ImmutableEvidenceSnapshot `
        -Path $sourcePublicPath -MetadataOnly
    if (Test-Path -LiteralPath $resultPath -PathType Leaf) {
        throw 'source-result.json already exists; immutable publication refused'
    }
    if (Test-Path -LiteralPath $resultCommitPath -PathType Leaf) {
        throw 'source-result-commit.json already exists; publication refused'
    }
    Write-D01JsonAtomic -Value $result -Path $resultPath
    $sourceCoordinationSnapshot = Open-D01ImmutableEvidenceSnapshot `
        -Path $resultPath -MetadataOnly
    if ([string]$sourceCoordinationSnapshot.sha256 -cne
        [string]$sourcePrivateSnapshot.sha256) {
        throw 'Source private and coordination result bytes differ'
    }
    $precommitSourceIdentity = Get-D01CandidateIdentity
    $precommitSourceTerminal = Get-D01TerminalOwnershipCensus `
        -Process $source `
        -Ports @($SourceTcpPort, $SourceUdpPort, $SourceWebPort) `
        -HostRole 'Source'
    $precommitSourceHosts = Get-D01HostsFilePostcheckEvidence `
        -Baseline $script:d01HostsBaseline
    $precommitSourceAccount = Get-D01AccountRegistryPostcheckEvidence `
        -Transaction $script:d01AccountRegistryTransaction
    $precommitSourceNodeExact = if ([string]::IsNullOrWhiteSpace($sourceExe)) {
        $null -eq $sourceCodeBinding
    } else {
        (Test-Path -LiteralPath $sourceExe -PathType Leaf) -and
            (Get-LabSha256 -Path $sourceExe) -ceq $expectedEmuleHash
    }
    if (-not $precommitSourceIdentity.exact -or
        [string]$precommitSourceIdentity.extracted_manifest.manifest_sha256 -cne
            [string]$identityBefore.extracted_manifest.manifest_sha256 -or
        [string]$precommitSourceIdentity.zip_manifest.zip_sha256 -cne
            [string]$identityBefore.zip_manifest.zip_sha256 -or
        -not $precommitSourceNodeExact -or
        -not [bool]$precommitSourceTerminal.all_clear -or
        -not [bool]$precommitSourceHosts.safe_to_pass -or
        -not [bool]$precommitSourceAccount.safe_to_pass) {
        throw 'Source immutable state changed before publication commit'
    }
    $sourceCommitPath = Join-Path $evidence 'source-publication-commit.json'
    $sourceLocalCommit = [ordered]@{
        schema = 'ese.v91.d01-source-publication-commit/v1'
        case_id = $caseId
        publication_id = $sourcePublicationId
        committed_at_utc = Get-LabUtcTimestamp
        status = $sourceStatus
        exit_code = if ($sourceStatus -eq 'COMPLETE') { 0 } else { 2 }
        private_summary_sha256 = [string]$sourcePrivateSnapshot.sha256
        public_summary_sha256 = [string]$sourcePublicSnapshot.sha256
        coordination_result_sha256 =
            [string]$sourceCoordinationSnapshot.sha256
    }
    Write-D01JsonAtomic -Value $sourceLocalCommit -Path $sourceCommitPath
    $sourceLocalCommitSnapshot = Open-D01ImmutableEvidenceSnapshot `
        -Path $sourceCommitPath `
        -MetadataOnly
    # This nonce-scoped coordination marker is the sole externally visible
    # commit point.  The result file remains uncommitted until this final
    # atomic rename succeeds.
    $sourceCoordinationCommit = [pscustomobject][ordered]@{
        schema = 'ese.v91.d01-source-result-commit/v1'
        case_id = $caseId
        run_nonce = $nonce
        publication_id = $sourcePublicationId
        committed_at_utc = Get-LabUtcTimestamp
        status = $sourceStatus
        exit_code = if ($sourceStatus -eq 'COMPLETE') { 0 } else { 2 }
        private_summary_sha256 = [string]$sourcePrivateSnapshot.sha256
        public_summary_sha256 = [string]$sourcePublicSnapshot.sha256
        coordination_result_sha256 =
            [string]$sourceCoordinationSnapshot.sha256
        local_commit_sha256 = [string]$sourceLocalCommitSnapshot.sha256
    }
    $null = Assert-D01SourceResultCommitContract `
        -Commit $sourceCoordinationCommit
    Write-D01JsonAtomic -Value $sourceCoordinationCommit `
        -Path $resultCommitPath
    $null = Open-D01ImmutableEvidenceSnapshot -Path $resultCommitPath `
        -MetadataOnly
    $script:d01CommittedExitCode = if ($sourceStatus -eq 'COMPLETE') {
        0
    } else { 2 }
    Write-Host "V91-D01 source status: $sourceStatus" -ForegroundColor $(
        if ($sourceStatus -eq 'COMPLETE') { 'Green' } else { 'Yellow' }
    )
    if ($sourceStatus -eq 'COMPLETE') { return 0 }
    return 2
}

function Invoke-D01CoordinatorRole {
    if (-not $RunNonce) {
        $script:RunNonce = [Guid]::NewGuid().ToString('N')
    }
    $nonce = $RunNonce.ToLowerInvariant()
    $candidateRoot = Get-LabFullPath -Path $PackagePath
    $outputPath = Assert-D01OutputLocation -Path $OutputRoot `
        -Label 'Coordinator OutputRoot' -CandidateRoot $candidateRoot
    if (Test-Path -LiteralPath $outputPath) {
        if (@(Get-ChildItem -LiteralPath $outputPath -Force).Count -ne 0) {
            throw "Coordinator OutputRoot must be absent or empty: $outputPath"
        }
    }
    $output = New-LabDirectory -Path $outputPath
    $evidence = New-LabDirectory -Path (Join-Path $output 'evidence')
    $captureEvidencePath =
        New-LabDirectory -Path (Join-Path $evidence 'capture')
    $apiEvidencePath = New-LabDirectory -Path (Join-Path $evidence 'api')
    $nodes = New-LabDirectory -Path (Join-Path $output 'nodes')
    $summaryPath = Join-Path $evidence 'summary.json'
    $socketSamplesPath = Join-Path $evidence 'target-sockets.jsonl'
    $tcpPeerSamplesPath = Join-Path $evidence `
        'candidate-tcp-peer-connections.jsonl'
    $healthSamplesPath = Join-Path $evidence 'health-samples.jsonl'
    $telemetrySamplesPath =
        Join-Path $apiEvidencePath 'source-resolutions.jsonl'
    $coordinationBase = Assert-D01OutputLocation -Path $CoordinationRoot `
        -Label 'CoordinationRoot' -CandidateRoot $candidateRoot
    if (-not (Test-Path -LiteralPath $coordinationBase -PathType Container)) {
        $null = New-Item -ItemType Directory -Path $coordinationBase -Force
    }
    $coordination = Join-Path $coordinationBase "v91-d01-$nonce"
    if (Test-Path -LiteralPath $coordination) {
        throw "Nonce-scoped CoordinationRoot already exists: $coordination"
    }
    $null = New-Item -ItemType Directory -Path $coordination
    $runPath = Join-Path $coordination 'run.json'
    $readyPath = Join-Path $coordination 'source-ready.json'
    $observePath = Join-Path $coordination 'observe.json'
    $observeAckPath = Join-Path $coordination 'source-observing.json'
    $armPath = Join-Path $coordination 'arm.json'
    $sourceArmedPath = Join-Path $coordination 'source-armed.json'
    $sourceObservationPath =
        Join-Path $coordination 'source-observation.json'
    $stopPath = Join-Path $coordination 'stop.json'
    $sourceResultPath = Join-Path $coordination 'source-result.json'
    $sourceResultCommitPath =
        Join-Path $coordination 'source-result-commit.json'

    $identityBefore = $null
    $identityAfter = $null
    $candidateUnchanged = $false
    $nodeExeUnchanged = $false
    $isolation = $null
    $coordinatorTopology = $null
    $topologyEvidence = $null
    $sourceReady = $null
    $sourceFirewallSemanticsValidated = $false
    $sourceResult = $null
    $sourceResultCommit = $null
    $sourceObservation = $null
    $sourceResultContractErrorSha256 = ''
    $sourceObservationContractErrorSha256 = ''
    $dnsInitial = $null
    $dnsFinal = $null
    $aProbe = $null
    $aaaaProbe = $null
    $preferences = $null
    $controlledProfile = $null
    $controlledServer = $null
    $controlledServerStop = $null
    $controlledLogin = $null
    $downloader = $null
    $downloaderNode = ''
    $downloaderExe = ''
    $downloaderCodeBinding = $null
    $coordinatorContainment = $null
    $coordinatorContainmentArmedEvidence = $null
    $stopDownloader = $null
    $terminalOwnership = $null
    $destinationFile = ''
    $destinationBytes = 0L
    $destinationSha256 = ''
    $destinationFinalSnapshot = $null
    $destinationFinalizedAfterStop = $false
    $destinationTerminalStateObserved = $false
    $injection = $null
    $injectionCount = 0
    $preObserveTelemetry = $null
    $baselineTelemetry = $null
    $finalTelemetry = $null
    $telemetryVerdict = $null
    $capture = $null
    $captureEvidence = $null
    $captureClockAnchor = $null
    $captureClockEndAnchor = $null
    [Int64]$captureWindowStartEpochUnixNs = 0
    [Int64]$captureWindowEndEpochUnixNs = 0
    $caseArmed = $false
    [Int64]$caseArmBoundaryEpochUnixNs = 0
    [Int64]$caseArmBoundaryQpcTicks = 0
    [Int64]$productObservationWindowClosedEpochUnixNs = 0
    $caseArmProcessBinding = $null
    $armId = ''
    $sourceArmAck = $null
    $sourcePacketLinkEvidence = $null
    $sourceNetworkProof = $null
    $runtimeError = $null
    $failureStage = 'preflight'
    $cleanupFailures = New-Object 'Collections.Generic.List[string]'
    $apiSamples = 0
    $apiUnavailable = 0
    $apiIsolationFailures = 0
    $uiSamples = 0
    $uiUnavailable = 0
    $uiUnresponsive = 0
    $socketSampleCount = 0
    $sawV4Socket = $false
    $sawV4Established = $false
    $sawV4Physical = $false
    $v4EstablishedEvidence = $null
    $coordinatorSocketBaselineZero = $false
    $sawV6Socket = $false
    $sawV6Established = $false
    $sawV6SynSent = $false
    $sawV6Physical = $false
    $v6SynSentEvidence = $null
    $v6ObservedStates = New-Object 'Collections.Generic.HashSet[string]'
    $sawForeignTargetSocket = $false
    $sawWrongPortTargetSocket = $false
    $unexpectedTcpPeerConnections = @()
    $unexpectedTcpPeerPositiveEvidence =
        [Collections.Generic.List[object]]::new()
    $firstCoordinatorApiIsolationFailureEvidence = $null
    $firstCoordinatorUiTimeoutFailureEvidence = $null
    $firstCoordinatorProcessExitEvidence = $null
    $unexpectedTcpPeerKeys =
        [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $tcpPeerCollectorSourceBound = $false
    $tcpPeerSamplingComplete = $true
    $tcpPeerSampleCount = 0
    $transferCompleted = $false
    $productProcessExited = $false
    $startedAt = [DateTime]::UtcNow
    $transferStarted = $null
    $transferFinished = $null
    $stopPublished = $false

    try {
        $identityBefore = Get-D01CandidateIdentity
        Write-LabJson -Value $identityBefore.extracted_manifest -Path (
            Join-Path $evidence 'package-manifest-before.json'
        ) | Out-Null
        Write-LabJson -Value $identityBefore.zip_manifest -Path (
            Join-Path $evidence 'zip-manifest-before.json'
        ) | Out-Null
        if (-not $identityBefore.exact) {
            throw 'Coordinator package/ZIP identity is not the exact candidate'
        }
        $isolation = Get-D01IsolationEvidence
        Write-LabJson -Value $isolation -Path (
            Join-Path $evidence 'isolation.json'
        ) | Out-Null
        if (-not $isolation.strict_isolation_valid) {
            throw 'Coordinator has an active overlay/VPN adapter or proxy environment'
        }
        Test-D01PortsFree -Ports @(
            $DownloaderTcpPort, $DownloaderUdpPort, $DownloaderWebPort
        )
        $assignedV4 = Get-D01AssignedAddress `
            -Address $script:coordinatorLocalV4Text `
            -Family ([Net.Sockets.AddressFamily]::InterNetwork) `
            -Context 'coordinator-local-ipv4'
        $assignedV6 = Get-D01AssignedAddress `
            -Address $script:coordinatorV6Text `
            -Family ([Net.Sockets.AddressFamily]::InterNetworkV6) `
            -Context 'coordinator-public-ipv6'
        if (-not $assignedV4.adapter.physical_nonvirtual -or
            -not $assignedV6.adapter.physical_nonvirtual) {
            throw 'Coordinator addresses are not on physical native adapters'
        }
        if ([int]$assignedV4.interface_index -ne
            [int]$assignedV6.interface_index) {
            throw 'Coordinator IPv4 and IPv6 are not on one physical adapter'
        }
        if ($script:coordinatorPublicV4Text -eq
                $script:coordinatorLocalV4Text -and
            $assignedV4.address_class -ne 'public-unicast-v4') {
            throw 'Direct T1 CoordinatorPublicIPv4 must be globally routable'
        }
        $routeV4 = Get-D01RouteEvidence `
            -RemoteAddress $script:sourcePublicV4Text `
            -Context 'coordinator-route-to-source-ipv4'
        $routeV6 = Get-D01RouteEvidence `
            -RemoteAddress $script:sourceV6Text `
            -Context 'coordinator-route-to-source-ipv6'
        if (-not $routeV4.available -or -not $routeV6.available -or
            -not $routeV4.adapter.physical_nonvirtual -or
            -not $routeV6.adapter.physical_nonvirtual -or
            [int]$routeV4.interface_index -ne
                [int]$assignedV4.interface_index -or
            [int]$routeV6.interface_index -ne
                [int]$assignedV6.interface_index -or
            [string]$routeV4.source_address -cne
                [string]$assignedV4.address -or
            [string]$routeV6.source_address -cne
                [string]$assignedV6.address) {
            throw 'Coordinator lacks native physical routes to both DNS targets'
        }
        $coordinatorTopology = [pscustomobject][ordered]@{
            machine_id_sha256 = Get-D01MachineId
            coordinator_local_ipv4 = $assignedV4
            coordinator_public_ipv4 = $script:coordinatorPublicV4Text
            coordinator_public_ipv4_is_nat =
                $script:coordinatorPublicV4Text -ne
                    $script:coordinatorLocalV4Text
            coordinator_ipv6 = $assignedV6
            route_to_source_public_ipv4 = $routeV4
            route_to_source_ipv6 = $routeV6
            native_physical = $true
            overlay_vpn_proxy_absent = $true
        }
        Write-LabJson -Value $coordinatorTopology -Path (
            Join-Path $evidence 'coordinator-topology.json'
        ) | Out-Null
        $run = [ordered]@{
            schema = 'ese.v91.d01-run/v3'
            case_id = $caseId
            run_nonce = $nonce
            created_at_utc = Get-LabUtcTimestamp
            controlled_fixture_acknowledged = $true
            operator_identity = [ordered]@{
                coordinator = Get-D01HostIdentityEvidence
                expected_source_machine_id_sha256 =
                    $ExpectedSourceMachineIdSha256.ToLowerInvariant()
                expected_source_user_sid_sha256 =
                    $ExpectedSourceUserSidSha256.ToLowerInvariant()
            }
            candidate = [ordered]@{
                commit = $identityBefore.candidate.commit
                emule_sha256 = $expectedEmuleHash
                ese_server_sha256 =
                    $identityBefore.candidate.ese_server_sha256
                build_info_sha256 =
                    $identityBefore.candidate.build_info_sha256
                package_zip_sha256 = $expectedZipHash
                extracted_manifest_sha256 =
                    $identityBefore.extracted_manifest.manifest_sha256
                zip_manifest_sha256 =
                    $identityBefore.zip_manifest.manifest_sha256
            }
            coordinator = $coordinatorTopology
            fixture = [ordered]@{
                hostname = $canonicalHostname
                hostname_sha256 =
                    Get-LabStringSha256 -Value $canonicalHostname
                source_public_ipv4 = $script:sourcePublicV4Text
                source_local_ipv4 = $script:sourceLocalV4Text
                source_ipv6 = $script:sourceV6Text
                coordinator_public_ipv4 =
                    $script:coordinatorPublicV4Text
                coordinator_local_ipv4 =
                    $script:coordinatorLocalV4Text
                coordinator_ipv6 = $script:coordinatorV6Text
                source_tcp_port = $SourceTcpPort
                source_udp_port = $SourceUdpPort
                source_web_port = $SourceWebPort
                downloader_tcp_port = $DownloaderTcpPort
                downloader_udp_port = $DownloaderUdpPort
                downloader_web_port = $DownloaderWebPort
                file_size_bytes = $FileSizeBytes
            }
        }
        Write-D01JsonAtomic -Value $run -Path $runPath
        Write-Host "V91-D01 RunNonce: $nonce" -ForegroundColor Cyan
        Write-Host (
            'Start Source role on Maria with this same RunNonce and ' +
            'the same fixture/candidate arguments.'
        ) -ForegroundColor Cyan

        $failureStage = 'source-ready'
        $readyWait = Wait-D01JsonFile -Path $readyPath `
            -TimeoutSeconds $PeerReadyTimeoutSeconds
        if ($null -eq $readyWait) {
            throw 'Timed out waiting for Maria source-ready.json'
        }
        $sourceReady = $readyWait.value
        $null = Assert-D01SourceReadyCoordinationContract `
            -Ready $sourceReady
        if ([string]$sourceReady.schema -cne
                'ese.v91.d01-source-ready/v6' -or
            [string]$sourceReady.case_id -ne $caseId -or
            [string]$sourceReady.run_nonce -ne $nonce -or
            [string]$sourceReady.candidate.commit -ne
                $identityBefore.candidate.commit -or
            [string]$sourceReady.candidate.emule_sha256 -ne
                $expectedEmuleHash -or
            [string]$sourceReady.candidate.package_zip_sha256 -ne
                $expectedZipHash -or
            [string]$sourceReady.candidate.extracted_manifest_sha256 -ne
                $identityBefore.extracted_manifest.manifest_sha256 -or
            [string]$sourceReady.candidate.zip_manifest_sha256 -ne
                $identityBefore.zip_manifest.manifest_sha256 -or
            [Int64]$sourceReady.fixture.file_bytes -ne $FileSizeBytes -or
            [int]$sourceReady.process.process_id -le 0 -or
            [string]$sourceReady.process.process_emule_sha256 -cne
                $expectedEmuleHash -or
            -not [bool]$sourceReady.process.listener.ipv4_only -or
            -not [bool]$sourceReady.process.api_isolation_valid -or
            -not [bool]$sourceReady.firewall.rules_created -or
            -not [bool]$sourceReady.firewall.exact -or
            -not [bool]$sourceReady.firewall.ipv4_allow.exact -or
            -not [bool]$sourceReady.firewall.ipv6_drop.exact -or
            [string]$sourceReady.firewall.ipv6_drop.program -ne 'Any' -or
            [string]$sourceReady.firewall.ipv6_drop.remote_port -ne 'Any' -or
            [string]$sourceReady.firewall.ipv6_drop.profile -ne 'Any' -or
            [string]$sourceReady.firewall.AAAA_failure_mode -ne
                'controlled silent inbound DROP' -or
            [string]$sourceReady.operator_identity.source.machine_id_sha256 -cne
                $ExpectedSourceMachineIdSha256.ToLowerInvariant() -or
            [string]$sourceReady.operator_identity.source.user_sid_sha256 -cne
                $ExpectedSourceUserSidSha256.ToLowerInvariant() -or
            [string]$sourceReady.operator_identity.expected_coordinator_machine_id_sha256 -cne
                $ExpectedCoordinatorMachineIdSha256.ToLowerInvariant() -or
            [string]$sourceReady.operator_identity.expected_coordinator_user_sid_sha256 -cne
                $ExpectedCoordinatorUserSidSha256.ToLowerInvariant() -or
            [string]$sourceReady.machine_id_sha256 -cne
                $ExpectedSourceMachineIdSha256.ToLowerInvariant() -or
            [string]$sourceReady.topology.machine_id_sha256 -cne
                $ExpectedSourceMachineIdSha256.ToLowerInvariant()) {
            throw 'Maria source-ready evidence does not match the exact run'
        }
        if ([string]$sourceReady.machine_id_sha256 -eq
            [string]$coordinatorTopology.machine_id_sha256) {
            throw 'D01 requires two distinct physical machines'
        }
        $readyFirewallV4RemoteAddresses = @(
            @($sourceReady.firewall.ipv4_allow.remote_addresses) |
                ForEach-Object { [string]$_ } |
                Sort-Object -Unique
        )
        $readyTopologyAllowedRemoteAddresses = @(
            @($sourceReady.topology.allowed_inverse_remote_addresses) |
                ForEach-Object { [string]$_ } |
                Sort-Object -Unique
        )
        if ($readyTopologyAllowedRemoteAddresses.Count -eq 0 -or
            $readyFirewallV4RemoteAddresses.Count -ne
                $readyTopologyAllowedRemoteAddresses.Count -or
            @(Compare-Object `
                -ReferenceObject $readyTopologyAllowedRemoteAddresses `
                -DifferenceObject
                    $readyFirewallV4RemoteAddresses).Count -ne 0) {
            throw 'Maria IPv4 allow rule is not scoped to controlled peers'
        }
        $null = Assert-D01SourceFirewallFixtureSemantics `
            -Firewall $sourceReady.firewall `
            -ProcessBinding $sourceReady.process.binding `
            -RunNonce $nonce `
            -SourceLocalIPv4 $script:sourceLocalV4Text `
            -SourceIPv6 $script:sourceV6Text `
            -CoordinatorIPv6 $script:coordinatorV6Text `
            -AllowedIPv4Remotes $readyTopologyAllowedRemoteAddresses `
            -SourcePort $SourceTcpPort
        $sourceFirewallSemanticsValidated = $true

        $sourceTopology = $sourceReady.topology
        $samePhysicalV4Prefix =
            [string]$sourceTopology.source_local_ipv4.network_prefix -eq
                [string]$coordinatorTopology.
                    coordinator_local_ipv4.network_prefix
        $samePhysicalV6Prefix =
            [string]$sourceTopology.source_ipv6.network_prefix -eq
                [string]$coordinatorTopology.coordinator_ipv6.network_prefix
        $bilateralIpv6OnLink =
            [bool]$coordinatorTopology.route_to_source_ipv6.on_link -and
            [bool]$sourceTopology.route_to_coordinator_ipv6.on_link
        $t1 = $samePhysicalV4Prefix -and $samePhysicalV6Prefix -and
            $bilateralIpv6OnLink
        $nativeRoutedNextHopClasses = @(
            'linklocal-v6', 'ula-v6', 'native-global-v6'
        )
        $coordinatorV6NextHopClass =
            [string]$coordinatorTopology.
                route_to_source_ipv6.next_hop_class
        $sourceV6NextHopClass =
            [string]$sourceTopology.
                route_to_coordinator_ipv6.next_hop_class
        $t2Discriminator = -not $t1 -and
            $coordinatorV6NextHopClass -in $nativeRoutedNextHopClasses -and
            $sourceV6NextHopClass -in $nativeRoutedNextHopClasses
        $observedTopology = if ($t1) {
            'T1'
        } elseif ($t2Discriminator) { 'T2' } else { 'UNPROVEN' }
        $observedClass = if ($t1) {
            'T1-native-physical-same-prefix'
        } elseif ($t2Discriminator) {
            'T2-native-physical-routed-ipv6'
        } else {
            'UNPROVEN-native-topology'
        }
        $topologyValid =
            [bool]$coordinatorTopology.native_physical -and
            [bool]$sourceTopology.native_physical -and
            [bool]$coordinatorTopology.overlay_vpn_proxy_absent -and
            [bool]$sourceTopology.overlay_vpn_proxy_absent -and
            ($t1 -or $t2Discriminator)
        $topologyEvidence = [pscustomobject][ordered]@{
            observed_topology = $observedTopology
            observed_class = $observedClass
            accepted_topologies = @('T1', 'T2')
            distinct_machine_ids = $true
            coordinator = $coordinatorTopology
            source = $sourceTopology
            t1_direct_on_link = $t1
            t1_same_physical_ipv4_prefix = $samePhysicalV4Prefix
            t1_same_physical_ipv6_prefix = $samePhysicalV6Prefix
            t1_bilateral_ipv6_on_link = $bilateralIpv6OnLink
            t2_direct_native_discriminator = $t2Discriminator
            t2_coordinator_ipv6_next_hop_class =
                $coordinatorV6NextHopClass
            t2_source_ipv6_next_hop_class = $sourceV6NextHopClass
            nat_mapping_used_only_as_context = [ordered]@{
                source = $script:sourcePublicV4Text -ne
                    $script:sourceLocalV4Text
                coordinator = $script:coordinatorPublicV4Text -ne
                    $script:coordinatorLocalV4Text
            }
            no_overlay_vpn_proxy_data_plane = $true
            valid = $topologyValid
        }
        Write-LabJson -Value $topologyEvidence -Path (
            Join-Path $evidence 'topology.json'
        ) | Out-Null
        if (-not $topologyValid) {
            throw 'Observed topology is neither valid native T1 nor native T2'
        }

        $failureStage = 'dns-and-endpoint-fixture'
        $dnsInitial = Get-D01DnsEvidence -Name $canonicalHostname `
            -ExpectedA $script:sourcePublicV4Text `
            -ExpectedAAAA $script:sourceV6Text -Stage 'initial'
        Write-LabJson -Value $dnsInitial -Path (
            Join-Path $evidence 'dns-initial.json'
        ) | Out-Null
        if (-not $dnsInitial.exact_controlled_answer_set) {
            throw 'Controlled hostname does not resolve to exactly expected A+AAAA'
        }
        $aProbe = Test-D01TcpEndpoint -Address $script:sourcePublicV4Address `
            -Port $SourceTcpPort `
            -TimeoutMilliseconds $EndpointProbeTimeoutMilliseconds
        $aaaaProbe = Test-D01TcpEndpoint -Address $script:sourceV6Address `
            -Port $SourceTcpPort `
            -TimeoutMilliseconds $EndpointProbeTimeoutMilliseconds
        Write-LabJson -Value ([ordered]@{
            schema = 'ese.v91.d01-endpoint-probes/v2'
            captured_at_utc = Get-LabUtcTimestamp
            A = $aProbe
            AAAA = $aaaaProbe
        }) -Path (Join-Path $evidence 'endpoint-probes.json') | Out-Null
        if (-not $aProbe.connected) {
            throw 'Controlled A does not reach Maria source listener'
        }
        if ($aaaaProbe.connected -or -not $aaaaProbe.timed_out) {
            throw (
                'Controlled AAAA did not exhibit the required silent ' +
                'firewall DROP timeout'
            )
        }

        $failureStage = 'downloader-profile'
        & (Join-Path $PSScriptRoot 'prepare_node.ps1') -NodeRole B `
            -SourcePackage $identityBefore.candidate.package_path `
            -OutputRoot $nodes -RunId "v91-d01-$nonce" -PortOffset 6200
        $downloaderNode = Join-Path $nodes "v91-d01-$nonce-b"
        $downloaderExe = Join-Path $downloaderNode 'emule.exe'
        $null = Assert-D01PreparedNodeDerivedFromBinding `
            -NodePath $downloaderNode -Binding $script:d01CandidateBinding
        if ((Get-LabSha256 -Path $downloaderExe) -ne
            $expectedEmuleHash) {
            throw 'Prepared downloader executable is not exact candidate'
        }
        $incoming = New-LabDirectory `
            -Path (Join-Path $downloaderNode 'Incoming')
        $temp = New-LabDirectory -Path (Join-Path $downloaderNode 'Temp')
        foreach ($directory in @($incoming, $temp)) {
            if (@(Get-ChildItem -LiteralPath $directory -Force).Count -ne 0) {
                throw "Prepared downloader directory is not empty: $directory"
            }
        }
        $preferences = Set-D01IsolatedPreferences `
            -NodePath $downloaderNode -IPv6Mode 2 `
            -IPv6BindAddress $script:coordinatorV6Text `
            -WebPort $DownloaderWebPort -TcpPort $DownloaderTcpPort `
            -UdpPort $DownloaderUdpPort -IncomingPath $incoming `
            -TempPath $temp
        $controlledServer = Start-D01ControlledEd2kServer `
            -EvidencePath (
                Join-Path $evidence 'controlled-ed2k-server.json'
            ) -ListenAddress $script:coordinatorLocalV4Text `
            -ExpectedClientAddress $script:coordinatorLocalV4Text `
            -Nonce $nonce -PublishedOwner ([ref]$controlledServer)
        $controlledProfile = Enable-D01ControlledEd2kProfile `
            -NodePath $downloaderNode `
            -ServerAddress $script:coordinatorLocalV4Text `
            -ServerPort $controlledServer.port -Nonce $nonce
        $null = Assert-D01SafetyPreferenceContract `
            -Path (Join-Path $downloaderNode 'config\preferences.ini')
        $destinationFile = Join-Path $incoming `
            ([string]$sourceReady.fixture.file_name)

        $failureStage = 'downloader-startup'
        $null = Assert-D01CandidateBindingUnchanged `
            -Binding $script:d01CandidateBinding
        $null = Test-D01PortsFree -Ports @(
            $DownloaderTcpPort, $DownloaderUdpPort, $DownloaderWebPort)
        $downloaderCodeBinding = Lock-D01PreparedNodeCode `
            -NodePath $downloaderNode -ExpectedExeSha256 $expectedEmuleHash
        $coordinatorContainment = Start-D01ProgramNetworkContainment `
            -Nonce $nonce -Role Coordinator -Program $downloaderExe `
            -AllowedTcpRemoteAddresses @(
                $script:sourcePublicV4Text,
                $script:sourceV6Text,
                $script:coordinatorLocalV4Text,
                '127.0.0.1', '::1'
            ) -OutboundTcpRestrictions @(
                [pscustomobject]@{
                    label = 'SOURCE_PORT'
                    addresses = @(
                        $script:sourcePublicV4Text, $script:sourceV6Text)
                    allowed_ports = @($SourceTcpPort)
                },
                [pscustomobject]@{
                    label = 'SCHEDULER_PORT'
                    addresses = @($script:coordinatorLocalV4Text)
                    allowed_ports = @([int]$controlledServer.port)
                },
                [pscustomobject]@{
                    label = 'LOOPBACK_DENY'
                    addresses = @('127.0.0.1', '::1')
                    allowed_ports = @()
                }
            )
        if (-not [bool]$coordinatorContainment.armed_exact) {
            throw 'Coordinator program network containment was not armed exactly'
        }
        $coordinatorContainmentArmedEvidence =
            Get-D01ProgramContainmentArmedProjection `
                -State $coordinatorContainment
        $null = Assert-D01ProgramContainmentArmedContract `
            -Evidence $coordinatorContainmentArmedEvidence `
            -Context 'coordinator local program containment'
        if ([string]$coordinatorContainmentArmedEvidence.role -cne
                'Coordinator' -or
            [int]$coordinatorContainmentArmedEvidence.rule_count -ne 7) {
            throw 'Coordinator containment rule set shape is not exact'
        }
        Write-LabJson -Value $coordinatorContainmentArmedEvidence -Path (
            Join-Path $evidence 'program-containment-armed.json'
        ) | Out-Null
        $downloader = Start-D01OwnedCandidateProcess `
            -FilePath $downloaderExe -ArgumentList @(
                '--portable', '--ignoreinstances',
                "--metrics-port=$DownloaderWebPort",
                "--tcp-port=$DownloaderTcpPort",
                "--udp-port=$DownloaderUdpPort"
            ) -WorkingDirectory $downloaderNode -OwnerRole 'Coordinator' `
            -Nonce $nonce
        $null = Wait-D01Listener -Port $DownloaderTcpPort `
            -Process $downloader
        $startupApi = Wait-D01Api -Port $DownloaderWebPort `
            -Process $downloader -ExpectedPath $downloaderExe
        $controlledLogin = Wait-D01ControlledEd2kLogin `
            -Server $controlledServer -Process $downloader `
            -ExpectedTcpPort $DownloaderTcpPort
        $startupApi = Wait-D01Api -Port $DownloaderWebPort `
            -Process $downloader -ExpectedPath $downloaderExe
        if (-not (Test-D01ApiIsolation -Data $startupApi `
            -AllowControlledEd2k)) {
            throw 'Downloader is not isolated on the controlled eD2K server'
        }
        if ((Get-LabSha256 -Path $downloader.Path) -ne
            $expectedEmuleHash) {
            throw 'Running downloader is not exact candidate'
        }

        $failureStage = 'observability-baseline'
        $preObserveTelemetry = Get-D01TelemetrySnapshot `
            -Port $DownloaderWebPort -Process $downloader `
            -ExpectedPath $downloaderExe
        Add-D01JsonLine -Path $telemetrySamplesPath `
            -Value $preObserveTelemetry
        $baselineSequence = if (
            $preObserveTelemetry.available -and
            $preObserveTelemetry.contract_valid
        ) {
            [Int64]$preObserveTelemetry.data.sequence
        } else { [Int64]0 }
        $captureClockAnchor = New-D01ClockAnchor
        Write-LabJson -Value $captureClockAnchor -Path (
            Join-Path $captureEvidencePath 'clock-anchor-start.json'
        ) | Out-Null
        $script:d01PendingPktmonCleanupFailures = $cleanupFailures
        $capture = Start-D01PacketCapture `
            -EvidencePath $captureEvidencePath -Nonce $nonce `
            -IPv4 $script:sourcePublicV4Text `
            -IPv6 $script:sourceV6Text -Port $SourceTcpPort
        Write-LabJson -Value $capture -Path (
            Join-Path $captureEvidencePath 'capture-start.json'
        ) | Out-Null
        Write-D01JsonAtomic -Value ([ordered]@{
            schema = 'ese.v91.d01-observe-command/v2'
            case_id = $caseId
            run_nonce = $nonce
            generated_at_utc = Get-LabUtcTimestamp
            candidate_commit = $identityBefore.candidate.commit
            candidate_emule_sha256 = $expectedEmuleHash
            downloader_process_id = $downloader.Id
            downloader_process_emule_sha256 =
                Get-LabSha256 -Path $downloader.Path
            hostname_sha256 =
                Get-LabStringSha256 -Value $canonicalHostname
            telemetry_baseline_sequence = $baselineSequence
            pktmon_started = [bool]$capture.started
        }) -Path $observePath
        $observeAckWait = Wait-D01JsonFile -Path $observeAckPath `
            -TimeoutSeconds $PeerReadyTimeoutSeconds
        if ($null -eq $observeAckWait) {
            throw 'Timed out waiting for source observation acknowledgement'
        }
        $observeAck = $observeAckWait.value
        $null = Assert-D01SourceObservingContract -Ack $observeAck
        $ackAllowedInverseAddresses = @(
            @($observeAck.allowed_source_visible_remote_addresses) |
                ForEach-Object {
                    Get-D01NormalizedIp -Address ([string]$_)
                } | Sort-Object -Unique
        )
        $readyAllowedInverseAddresses = @(
            @($sourceReady.topology.allowed_inverse_remote_addresses) |
                ForEach-Object {
                    Get-D01NormalizedIp -Address ([string]$_)
                } | Sort-Object -Unique
        )
        $allowedInverseAddressSetMatches =
            $ackAllowedInverseAddresses.Count -gt 0 -and
            $ackAllowedInverseAddresses.Count -eq
                $readyAllowedInverseAddresses.Count -and
            @(Compare-Object `
                -ReferenceObject $readyAllowedInverseAddresses `
                -DifferenceObject
                $ackAllowedInverseAddresses).Count -eq 0
        if ([string]$observeAck.schema -ne
                'ese.v91.d01-source-observing/v4' -or
            [string]$observeAck.case_id -ne $caseId -or
            [string]$observeAck.run_nonce -ne $nonce -or
            [int]$observeAck.source_process_id -ne
                [int]$sourceReady.process.process_id -or
            [int]$observeAck.expected_downloader_process_id -ne
                $downloader.Id -or
            -not [bool]$observeAck.
                all_processes_and_nonlisten_states_checked -or
            -not $allowedInverseAddressSetMatches -or
            -not [bool]$observeAck.baseline_zero -or
            [int]$observeAck.baseline_established_connection_count -ne 0 -or
            [int]$observeAck.baseline_nonlisten_connection_count -ne 0) {
            throw 'Invalid source observation acknowledgement'
        }

        $failureStage = 'product-transfer'
        $baseLink = [string]$sourceReady.fixture.shared_link
        if (-not $baseLink.StartsWith(
            'ed2k://|file|', [StringComparison]::OrdinalIgnoreCase
        ) -or -not $baseLink.EndsWith('|/')) {
            throw 'Source published an invalid ED2K file link'
        }
        $directLink = $baseLink +
            "|sources,$canonicalHostname`:$SourceTcpPort|/"
        $canonicalEndpoints = Get-D01CanonicalEndpointEvidence `
            -Addresses @(
                $script:sourcePublicV4Address,
                $script:sourceV6Address
            ) -Port $SourceTcpPort
        Write-LabJson -Value $canonicalEndpoints -Path (
            Join-Path $evidence 'canonical-endpoints.json'
        ) | Out-Null
        $coordinatorBaselineWaitStarted = [DateTime]::UtcNow
        $coordinatorBaselineWaitDeadline =
            $coordinatorBaselineWaitStarted.AddSeconds(
                [Math]::Max(
                    1, [Math]::Min(120, $PeerReadyTimeoutSeconds - 5)
                )
            )
        $coordinatorBaselineSampleCount = 0
        do {
            $coordinatorBaselineSampleCount++
            $coordinatorSocketBaseline = @(
                Get-D01TargetConnections -ProcessId 0 `
                    -RemoteAddresses @(
                        $script:sourcePublicV4Text,
                        $script:sourceV6Text
                    ) -RemotePort 0
            )
            if ($coordinatorSocketBaseline.Count -eq 0) { break }
            Start-Sleep -Milliseconds 100
        } while ([DateTime]::UtcNow -lt
            $coordinatorBaselineWaitDeadline)
        $coordinatorSocketBaselineZero =
            $coordinatorSocketBaseline.Count -eq 0
        Write-LabJson -Value ([ordered]@{
            schema = 'ese.v91.d01-target-socket-baseline/v1'
            captured_at_utc = Get-LabUtcTimestamp
            candidate_process_id = $downloader.Id
            all_processes_checked = $true
            all_target_ports_checked = $true
            connection_count = $coordinatorSocketBaseline.Count
            baseline_zero = $coordinatorSocketBaselineZero
            baseline_wait_sample_count =
                $coordinatorBaselineSampleCount
            baseline_wait_duration_ms = [Int64](
                ([DateTime]::UtcNow -
                    $coordinatorBaselineWaitStarted).TotalMilliseconds
            )
            connections = $coordinatorSocketBaseline
        }) -Path (Join-Path $evidence 'target-socket-baseline.json') |
            Out-Null
        if (-not $coordinatorSocketBaselineZero) {
            throw 'A process has a pre-existing target socket before injection'
        }
        $captureArmedExact = [bool]$capture.available -and
            [bool]$capture.started -and
            [bool]$capture.filters_applied_verified
        if (-not $captureArmedExact) {
            throw 'External packet capture could not be armed exactly'
        }
        $caseArmProcessBinding = Get-D01OwnedProcessBindingEvidence `
            -Process $downloader -ExpectedPath $downloaderExe -RequireLive
        $caseArmBoundaryQpcTicks =
            [Diagnostics.Stopwatch]::GetTimestamp()
        $caseArmBoundaryEpochUnixNs = Get-D01EpochUnixNs
        $baselineTelemetry = Get-D01TelemetrySnapshot `
            -Port $DownloaderWebPort -Process $downloader `
            -ExpectedPath $downloaderExe
        Add-D01JsonLine -Path $telemetrySamplesPath `
            -Value $baselineTelemetry
        if (-not [bool]$baselineTelemetry.available -or
            -not [bool]$baselineTelemetry.contract_valid -or
            -not [bool]$baselineTelemetry.source_bound -or
            [Int64]$baselineTelemetry.after_sequence -ne -1 -or
            [string]$baselineTelemetry.candidate_ownership_id_sha256 -cne
                [string]$caseArmProcessBinding.ownership_id_sha256) {
            throw 'Arm-bound telemetry baseline is not candidate-owned and exact'
        }
        $baselineSequence = [Int64]$baselineTelemetry.data.sequence
        Write-LabJson -Value $baselineTelemetry -Path (
            Join-Path $evidence 'telemetry-baseline-at-arm.json') | Out-Null
        if ((Test-Path -LiteralPath $armPath) -or
            (Test-Path -LiteralPath $sourceArmedPath)) {
            throw 'Arm command/ack path was not empty at the arm boundary'
        }
        $armId = [Guid]::NewGuid().ToString('N')
        $armCommand = [pscustomobject][ordered]@{
            schema = 'ese.v91.d01-arm-command/v1'
            case_id = $caseId
            run_nonce = $nonce
            generated_at_utc = Get-LabUtcTimestamp
            arm_id = $armId
            candidate_commit = [string]$identityBefore.candidate.commit
            candidate_emule_sha256 = $expectedEmuleHash
            downloader_process_id = [int]$downloader.Id
            downloader_ownership_id_sha256 =
                [string]$caseArmProcessBinding.ownership_id_sha256
        }
        $null = Assert-D01ArmCommandContract -Command $armCommand
        Write-D01JsonAtomic -Value $armCommand -Path $armPath
        $sourceArmWait = Wait-D01JsonFile -Path $sourceArmedPath `
            -TimeoutSeconds $PeerReadyTimeoutSeconds
        if ($null -eq $sourceArmWait) {
            throw 'Timed out waiting for source arm acknowledgement'
        }
        $sourceArmAck = $sourceArmWait.value
        $null = Assert-D01SourceArmedContract -Ack $sourceArmAck
        if ([string]$sourceArmAck.case_id -cne $caseId -or
            [string]$sourceArmAck.run_nonce -cne $nonce -or
            [string]$sourceArmAck.arm_id -cne $armId -or
            [int]$sourceArmAck.source_process_id -ne
                [int]$sourceReady.process.process_id -or
            [string]$sourceArmAck.source_ownership_id_sha256 -cne
                [string]$sourceReady.process.binding.ownership_id_sha256 -or
            [int]$sourceArmAck.downloader_process_id -ne
                [int]$downloader.Id -or
            [string]$sourceArmAck.downloader_ownership_id_sha256 -cne
                [string]$caseArmProcessBinding.ownership_id_sha256 -or
            [string]$sourceArmAck.downloader_ownership_id_sha256 -cne
                [string]$armCommand.downloader_ownership_id_sha256 -or
            -not [bool]$sourceArmAck.health_counters_reset) {
            throw 'Source arm acknowledgement is not bilaterally process-bound'
        }
        $caseArmed = $true
        $injectionQpcStart = [Diagnostics.Stopwatch]::GetTimestamp()
        $transferStarted = [DateTime]::UtcNow
        $injection = Send-D01Ed2kLink -Process $downloader `
            -ExpectedPath $downloaderExe -Link $directLink
        $injectionQpcEnd = [Diagnostics.Stopwatch]::GetTimestamp()
        $injectionClock = Get-D01ClockObservation `
            -Anchor $captureClockAnchor -QpcStart $injectionQpcStart `
            -QpcEnd $injectionQpcEnd
        $injection | Add-Member -NotePropertyName clock `
            -NotePropertyValue $injectionClock
        $captureWindowStartEpochUnixNs =
            [Int64]$injectionClock.epoch_unix_ns - [Int64]250000000
        $injectionCount = 1
        Write-LabJson -Value $injection -Path (
            Join-Path $evidence 'sole-link-injection.json'
        ) | Out-Null
        $deadline = $transferStarted.AddSeconds($TransferTimeoutSeconds)
        $nextHealth = [DateTime]::UtcNow
        $nextTelemetry = [DateTime]::UtcNow
        $completionObservedAt = $null
        do {
            $downloader.Refresh()
            if ($downloader.HasExited) {
                $productProcessExited = $true
                if ($null -eq $firstCoordinatorProcessExitEvidence) {
                    $firstCoordinatorProcessExitEvidence =
                        New-D01CoordinatorProcessExitEvidence `
                            -Process $downloader -ArmId $armId `
                            -CandidateBinding $caseArmProcessBinding
                }
                break
            }
            $now = [DateTime]::UtcNow
            $socketSampleQpcStart =
                [Diagnostics.Stopwatch]::GetTimestamp()
            $connections = @(
                Get-D01TargetConnections -ProcessId 0 `
                    -RemoteAddresses @(
                        $script:sourcePublicV4Text,
                        $script:sourceV6Text
                    ) -RemotePort 0
            )
            $socketSampleQpcEnd =
                [Diagnostics.Stopwatch]::GetTimestamp()
            $socketClock = Get-D01ClockObservation `
                -Anchor $captureClockAnchor `
                -QpcStart $socketSampleQpcStart `
                -QpcEnd $socketSampleQpcEnd
            foreach ($connection in $connections) {
                $connection | Add-Member -NotePropertyName sample_clock `
                    -NotePropertyValue $socketClock
            }
            $socketSampleCount++
            Add-D01JsonLine -Path $socketSamplesPath -Value ([ordered]@{
                schema = 'ese.v91.d01-target-socket-sample/v3'
                sample_number = $socketSampleCount
                captured_at_utc = Get-LabUtcTimestamp
                clock = $socketClock
                elapsed_ms = [Int64](
                    ($now - $transferStarted).TotalMilliseconds
                )
                connections = $connections
            })
            try {
                $tcpPeerCensus =
                    Get-D01CandidateTcpPeerConnectionCensus `
                    -Process $downloader -ExpectedPath $downloaderExe `
                    -SourceAddresses @(
                        $script:sourcePublicV4Text, $script:sourceV6Text) `
                    -SourcePort $SourceTcpPort `
                    -SchedulerAddress $script:coordinatorLocalV4Text `
                    -SchedulerPort ([int]$controlledServer.port) `
                    -WebPort $DownloaderWebPort `
                    -ClockAnchor $captureClockAnchor
                $tcpPeerSampleCount++
                Add-D01JsonLine -Path $tcpPeerSamplesPath `
                    -Value $tcpPeerCensus
                foreach ($unexpected in
                    @($tcpPeerCensus.unexpected_peer_connections)) {
                    $key = '{0}|{1}|{2}|{3}|{4}|{5}' -f
                        [int]$unexpected.owning_process,
                        [string]$unexpected.state,
                        [string]$unexpected.local_address,
                        [int]$unexpected.local_port,
                        [string]$unexpected.remote_address,
                        [int]$unexpected.remote_port
                    if ($unexpectedTcpPeerKeys.Add($key)) {
                        $unexpectedTcpPeerConnections += $unexpected
                        $unexpectedTcpPeerPositiveEvidence.Add(
                            [pscustomobject][ordered]@{
                                schema =
                                    'ese.v91.d01-unexpected-tcp-peer-connection-failure/v1'
                                arm_id = $armId
                                observed_epoch_unix_ns = (
                                    [Int64]$tcpPeerCensus.query_clock.
                                        epoch_unix_ns)
                                process_binding =
                                    $tcpPeerCensus.process_binding_after
                                transport = 'tcp'
                                scope = 'connected-peer-tuples-only'
                                query_clock = $tcpPeerCensus.query_clock
                                expected_source_addresses = @(
                                    $script:sourcePublicV4Text,
                                    $script:sourceV6Text)
                                expected_source_port = $SourceTcpPort
                                expected_scheduler_address =
                                    $script:coordinatorLocalV4Text
                                expected_scheduler_port =
                                    [int]$controlledServer.port
                                expected_web_port = $DownloaderWebPort
                                connection = $unexpected
                            })
                    }
                }
            } catch {
                $tcpPeerSamplingComplete = $false
                throw
            }
            if (@($connections | Where-Object {
                [int]$_.remote_port -ne $SourceTcpPort
            }).Count -gt 0) {
                $sawWrongPortTargetSocket = $true
            }
            foreach ($connection in @($connections | Where-Object {
                [int]$_.owning_process -eq $downloader.Id -and
                [int]$_.remote_port -eq $SourceTcpPort
            })) {
                if ([string]$connection.remote_address -eq
                    $script:sourcePublicV4Text) {
                    $sawV4Socket = $true
                    if ([string]$connection.state -eq 'Established') {
                        $sawV4Established = $true
                        if ([bool]$connection.physical_nonvirtual) {
                            $sawV4Physical = $true
                            if ($null -eq $v4EstablishedEvidence) {
                                $v4EstablishedEvidence = $connection
                            }
                        }
                    }
                } elseif ([string]$connection.remote_address -eq
                    $script:sourceV6Text) {
                    $sawV6Socket = $true
                    $null = $v6ObservedStates.Add(
                        [string]$connection.state
                    )
                    if ([bool]$connection.physical_nonvirtual) {
                        $sawV6Physical = $true
                    }
                    if ([string]$connection.state -eq 'SynSent' -and
                        [bool]$connection.physical_nonvirtual -and
                        [string]$connection.local_address -eq
                            $script:coordinatorV6Text) {
                        $sawV6SynSent = $true
                        if ($null -eq $v6SynSentEvidence) {
                            $v6SynSentEvidence = $connection
                        }
                    }
                    if ([string]$connection.state -eq 'Established') {
                        $sawV6Established = $true
                    }
                }
            }
            if (@($connections | Where-Object {
                [int]$_.owning_process -ne $downloader.Id
            }).Count -gt 0) {
                $sawForeignTargetSocket = $true
            }
            if ($now -ge $nextHealth) {
                $api = Get-D01ApiProbe -Port $DownloaderWebPort `
                    -Process $downloader -ExpectedPath $downloaderExe `
                    -AllowControlledEd2k
                $ui = Get-D01UiProbe -Process $downloader
                $healthObservedEpochUnixNs = Get-D01EpochUnixNs
                $apiSamples++
                $uiSamples++
                if (-not $api.available -or -not $api.contract_valid) {
                    $apiUnavailable++
                }
                if ($api.available -and $api.contract_valid -and
                    $api.contamination_proven) {
                    $apiIsolationFailures++
                    if ($null -eq
                        $firstCoordinatorApiIsolationFailureEvidence) {
                        $firstCoordinatorApiIsolationFailureEvidence =
                            [pscustomobject][ordered]@{
                                schema =
                                    'ese.v91.d01-coordinator-api-isolation-failure/v1'
                                arm_id = $armId
                                observed_epoch_unix_ns =
                                    $healthObservedEpochUnixNs
                                sample_number = $apiSamples
                                candidate_process_id = [int]$downloader.Id
                                candidate_ownership_id_sha256 =
                                    [string]$caseArmProcessBinding.
                                        ownership_id_sha256
                                probe = $api
                            }
                    }
                }
                if (-not $ui.collector_ok -or -not $ui.source_bound -or
                    -not $ui.main_window_present) { $uiUnavailable++ }
                if ($ui.collector_ok -and $ui.source_bound -and
                    $ui.main_window_present -and $ui.timeout_proven -and
                    -not $ui.message_pump_responsive) {
                    $uiUnresponsive++
                    if ($null -eq $firstCoordinatorUiTimeoutFailureEvidence) {
                        $firstCoordinatorUiTimeoutFailureEvidence =
                            [pscustomobject][ordered]@{
                                schema =
                                    'ese.v91.d01-coordinator-ui-timeout-failure/v1'
                                arm_id = $armId
                                observed_epoch_unix_ns =
                                    $healthObservedEpochUnixNs
                                sample_number = $uiSamples
                                candidate_process_id = [int]$downloader.Id
                                candidate_ownership_id_sha256 =
                                    [string]$caseArmProcessBinding.
                                        ownership_id_sha256
                                probe = $ui
                            }
                    }
                }
                Add-D01JsonLine -Path $healthSamplesPath -Value ([ordered]@{
                    schema = 'ese.v91.d01-coordinator-health-sample/v2'
                    captured_at_utc = Get-LabUtcTimestamp
                    api = $api
                    ui = $ui
                })
                $nextHealth = $now.AddSeconds(2)
            }
            if ($now -ge $nextTelemetry) {
                $telemetrySample = Get-D01TelemetrySnapshot `
                    -Port $DownloaderWebPort `
                    -Process $downloader -ExpectedPath $downloaderExe `
                    -AfterSequence $baselineSequence
                Add-D01JsonLine -Path $telemetrySamplesPath `
                    -Value $telemetrySample
                if ($telemetrySample.available -and
                    $telemetrySample.contract_valid) {
                    $finalTelemetry = $telemetrySample
                }
                $nextTelemetry = $now.AddMilliseconds(500)
            }
            if (Test-Path -LiteralPath $destinationFile -PathType Leaf) {
                $destinationItem = Get-Item -LiteralPath $destinationFile
                if ([Int64]$destinationItem.Length -eq $FileSizeBytes) {
                    if ($null -eq $completionObservedAt) {
                        $completionObservedAt = $now
                    }
                    $hasTelemetryEvent = $null -ne $finalTelemetry -and
                        @($finalTelemetry.data.events).Count -gt 0
                    $hasInverse = Test-Path `
                        -LiteralPath $sourceObservationPath -PathType Leaf
                    if (($hasTelemetryEvent -and $hasInverse) -or
                        ($now - $completionObservedAt).TotalSeconds -ge 10) {
                        break
                    }
                }
            }
            if (($now - $transferStarted).TotalSeconds -lt 20) {
                Start-Sleep -Milliseconds 50
            } else {
                Start-Sleep -Milliseconds 250
            }
        } while ([DateTime]::UtcNow -lt $deadline)
        $transferFinished = [DateTime]::UtcNow
        if (Test-Path -LiteralPath $destinationFile -PathType Leaf) {
            $destinationBytes =
                [Int64](Get-Item -LiteralPath $destinationFile).Length
            if ($destinationBytes -eq $FileSizeBytes) {
                $destinationSha256 =
                    Get-LabSha256 -Path $destinationFile
                $transferCompleted = $destinationSha256 -eq
                    ([string]$sourceReady.fixture.file_sha256).
                        ToLowerInvariant()
            }
        }
        $finalTelemetry = Get-D01TelemetrySnapshot `
            -Port $DownloaderWebPort -Process $downloader `
            -ExpectedPath $downloaderExe `
            -AfterSequence $baselineSequence
        Add-D01JsonLine -Path $telemetrySamplesPath `
            -Value $finalTelemetry
        $telemetryVerdict = Get-D01TelemetryVerdict `
            -Snapshot $finalTelemetry `
            -BaselineSequence $baselineSequence `
            -HostnameSha256 (
                Get-LabStringSha256 -Value $canonicalHostname
            ) -FileEd2kHash ([string]$sourceReady.fixture.ed2k_hash) `
            -Port $SourceTcpPort `
            -CanonicalEndpoints $canonicalEndpoints
        Write-LabJson -Value $telemetryVerdict -Path (
            Join-Path $apiEvidencePath 'telemetry-verdict.json'
        ) | Out-Null
        if (Test-Path -LiteralPath $sourceObservationPath -PathType Leaf) {
            $lockedSourceObservation = Read-D01ImmutableJsonFile `
                -Path $sourceObservationPath
            $sourceObservation = $lockedSourceObservation.value
            $null = Assert-D01SourceObservationContract `
                -Observation $sourceObservation
        }
        $dnsFinal = Get-D01DnsEvidence -Name $canonicalHostname `
            -ExpectedA $script:sourcePublicV4Text `
            -ExpectedAAAA $script:sourceV6Text -Stage 'final'
        Write-LabJson -Value $dnsFinal -Path (
            Join-Path $evidence 'dns-final.json'
        ) | Out-Null

        if (-not $productProcessExited) {
            $downloader.Refresh()
            if ($downloader.HasExited) {
                $productProcessExited = $true
                if ($null -eq $firstCoordinatorProcessExitEvidence) {
                    $firstCoordinatorProcessExitEvidence =
                        New-D01CoordinatorProcessExitEvidence `
                            -Process $downloader -ArmId $armId `
                            -CandidateBinding $caseArmProcessBinding
                }
            }
        }
        if (-not $productProcessExited) {
            try {
                $finalTcpPeerCensus =
                    Get-D01CandidateTcpPeerConnectionCensus `
                    -Process $downloader -ExpectedPath $downloaderExe `
                    -SourceAddresses @(
                        $script:sourcePublicV4Text, $script:sourceV6Text) `
                    -SourcePort $SourceTcpPort `
                    -SchedulerAddress $script:coordinatorLocalV4Text `
                    -SchedulerPort ([int]$controlledServer.port) `
                    -WebPort $DownloaderWebPort `
                    -ClockAnchor $captureClockAnchor
                $tcpPeerSampleCount++
                Add-D01JsonLine -Path $tcpPeerSamplesPath `
                    -Value $finalTcpPeerCensus
                foreach ($unexpected in
                    @($finalTcpPeerCensus.
                        unexpected_peer_connections)) {
                    $key = '{0}|{1}|{2}|{3}|{4}|{5}' -f
                        [int]$unexpected.owning_process,
                        [string]$unexpected.state,
                        [string]$unexpected.local_address,
                        [int]$unexpected.local_port,
                        [string]$unexpected.remote_address,
                        [int]$unexpected.remote_port
                    if ($unexpectedTcpPeerKeys.Add($key)) {
                        $unexpectedTcpPeerConnections += $unexpected
                        $unexpectedTcpPeerPositiveEvidence.Add(
                            [pscustomobject][ordered]@{
                                schema =
                                    'ese.v91.d01-unexpected-tcp-peer-connection-failure/v1'
                                arm_id = $armId
                                observed_epoch_unix_ns = (
                                    [Int64]$finalTcpPeerCensus.query_clock.
                                        epoch_unix_ns)
                                process_binding =
                                    $finalTcpPeerCensus.process_binding_after
                                transport = 'tcp'
                                scope = 'connected-peer-tuples-only'
                                query_clock =
                                    $finalTcpPeerCensus.query_clock
                                expected_source_addresses = @(
                                    $script:sourcePublicV4Text,
                                    $script:sourceV6Text)
                                expected_source_port = $SourceTcpPort
                                expected_scheduler_address =
                                    $script:coordinatorLocalV4Text
                                expected_scheduler_port =
                                    [int]$controlledServer.port
                                expected_web_port = $DownloaderWebPort
                                connection = $unexpected
                            })
                    }
                }
                $tcpPeerCollectorSourceBound =
                    $tcpPeerSamplingComplete -and
                    $tcpPeerSampleCount -gt 1
            } catch {
                $tcpPeerSamplingComplete = $false
                throw
            }
        }
    } catch {
        $runtimeError = $_.Exception.Message
    } finally {

        if ($null -ne $capture) {
            try {
                $captureEndQpc = [Diagnostics.Stopwatch]::GetTimestamp()
                $captureEndClock = Get-D01ClockObservation `
                    -Anchor $captureClockAnchor `
                    -QpcStart $captureEndQpc -QpcEnd $captureEndQpc
                $captureWindowEndEpochUnixNs =
                    [Int64]$captureEndClock.epoch_unix_ns + [Int64]250000000
                if ($captureWindowStartEpochUnixNs -eq 0) {
                    $captureWindowStartEpochUnixNs =
                        [Int64]$captureClockAnchor.anchor_epoch_unix_ns
                }
                $captureClockEndAnchor = New-D01ClockAnchor
                Write-LabJson -Value $captureClockEndAnchor -Path (
                    Join-Path $captureEvidencePath 'clock-anchor-end.json'
                ) | Out-Null
                $null = Stop-D01PacketCapture -State $capture `
                    -CleanupFailures $cleanupFailures
                Write-LabJson -Value $capture -Path (
                    Join-Path $captureEvidencePath 'capture-final.json'
                ) | Out-Null
                $captureEvidence = Get-D01PacketCaptureEvidence `
                    -State $capture -IPv4 $script:sourcePublicV4Text `
                    -IPv6 $script:sourceV6Address `
                    -CoordinatorIPv4 $script:coordinatorLocalV4Text `
                    -CoordinatorIPv6 $script:coordinatorV6Address `
                    -Port $SourceTcpPort `
                    -SocketSamplesPath $socketSamplesPath `
                    -CandidateProcessId $downloader.Id `
                    -ExpectedAdapterEvidence $assignedV4.adapter `
                    -ClockAnchor $captureClockAnchor `
                    -ClockEndAnchor $captureClockEndAnchor `
                    -WindowStartEpochUnixNs `
                        $captureWindowStartEpochUnixNs `
                    -WindowEndEpochUnixNs `
                        $captureWindowEndEpochUnixNs
                Write-LabJson -Value $captureEvidence -Path (
                    Join-Path $captureEvidencePath 'capture-verdict.json'
                ) | Out-Null
            } catch {
                $cleanupFailures.Add(
                    "Packet capture finalization failed: $($_.Exception.Message)"
                )
            }
        }
        if ($null -ne $downloader) {
            if ($null -eq $finalTelemetry) {
                try {
                    $after = if ($null -ne $baselineTelemetry -and
                        $baselineTelemetry.available -and
                        $baselineTelemetry.contract_valid) {
                        [Int64]$baselineTelemetry.data.sequence
                    } else { [Int64]0 }
                    $finalTelemetry = Get-D01TelemetrySnapshot `
                        -Port $DownloaderWebPort -Process $downloader `
                        -ExpectedPath $downloaderExe -AfterSequence $after
                    Add-D01JsonLine -Path $telemetrySamplesPath `
                        -Value $finalTelemetry
                } catch {}
            }
            if ($null -eq $dnsFinal) {
                try {
                    $dnsFinal = Get-D01DnsEvidence `
                        -Name $canonicalHostname `
                        -ExpectedA $script:sourcePublicV4Text `
                        -ExpectedAAAA $script:sourceV6Text `
                        -Stage 'final'
                    Write-LabJson -Value $dnsFinal -Path (
                        Join-Path $evidence 'dns-final.json'
                    ) | Out-Null
                } catch {}
            }
            if (-not $productProcessExited) {
                $candidateObservationWindowBoundaryEpochUnixNs =
                    Get-D01EpochUnixNs
                $downloader.Refresh()
                if ($downloader.HasExited) {
                    $productProcessExited = $true
                    if ($caseArmed -and
                        $null -ne $caseArmProcessBinding -and
                        $null -eq $firstCoordinatorProcessExitEvidence) {
                        $firstCoordinatorProcessExitEvidence =
                            New-D01CoordinatorProcessExitEvidence `
                                -Process $downloader -ArmId $armId `
                                -CandidateBinding $caseArmProcessBinding
                    }
                } else {
                    $productObservationWindowClosedEpochUnixNs =
                        $candidateObservationWindowBoundaryEpochUnixNs
                }
            }
            $stopDownloader = Stop-D01OwnedProcess `
                -Process $downloader -ExpectedPath $downloaderExe
            if (-not $stopDownloader.stopped) {
                $cleanupFailures.Add('Downloader process remains running')
            } elseif ($destinationFile -and
                (Test-Path -LiteralPath $destinationFile -PathType Leaf)) {
                try {
                    $destinationFinalSnapshot =
                        Open-D01ImmutableEvidenceSnapshot `
                            -Path $destinationFile -MetadataOnly
                    $destinationBytes =
                        [Int64]$destinationFinalSnapshot.byte_count
                    $destinationSha256 =
                        [string]$destinationFinalSnapshot.sha256
                    $destinationFinalizedAfterStop =
                        [bool]$destinationFinalSnapshot.
                            immutable_read_lock_held
                    $destinationTerminalStateObserved =
                        $destinationFinalizedAfterStop
                    $transferCompleted = $destinationFinalizedAfterStop -and
                        $null -ne $sourceReady -and
                        $destinationBytes -eq $FileSizeBytes -and
                        $destinationSha256 -ceq
                            ([string]$sourceReady.fixture.file_sha256).
                                ToLowerInvariant()
                } catch {
                    $destinationFinalizedAfterStop = $false
                    $destinationTerminalStateObserved = $false
                    $transferCompleted = $false
                    $cleanupFailures.Add(
                        "Destination final snapshot failed: $($_.Exception.Message)")
                }
            } else {
                $destinationTerminalStateObserved =
                    [bool]$stopDownloader.stopped
                $transferCompleted = $false
            }
        }
        if ($null -ne $coordinatorContainment) {
            if ($null -eq $downloader -or
                ($null -ne $stopDownloader -and
                    [bool]$stopDownloader.stopped)) {
                $coordinatorContainment =
                    Remove-D01ProgramNetworkContainment `
                        -State $coordinatorContainment `
                        -Program $downloaderExe
                if (-not [bool]$coordinatorContainment.cleanup_exact) {
                    $cleanupFailures.Add(
                        'Coordinator program containment cleanup is not exact')
                }
                Write-LabJson -Value $coordinatorContainment -Path (
                    Join-Path $evidence 'program-containment-final.json'
                ) | Out-Null
            } else {
                $cleanupFailures.Add(
                    'Coordinator containment retained because downloader remains')
            }
        }
        $controlledServerStop =
            Stop-D01ControlledEd2kServer -Server $controlledServer
        if (-not $controlledServerStop.stopped -or
            $controlledServerStop.error) {
            $cleanupFailures.Add(
                'Controlled eD2K server did not stop cleanly'
            )
        }
        if (-not (Test-Path -LiteralPath $stopPath -PathType Leaf)) {
            try {
                Write-D01JsonAtomic -Value ([ordered]@{
                    schema = 'ese.v91.d01-stop-command/v2'
                    case_id = $caseId
                    run_nonce = $nonce
                    generated_at_utc = Get-LabUtcTimestamp
                    candidate_commit = if ($null -ne $identityBefore) {
                        $identityBefore.candidate.commit
                    } else { $Commit.ToLowerInvariant() }
                    candidate_emule_sha256 = $expectedEmuleHash
                    action = 'stop-owned-source'
                }) -Path $stopPath
                $stopPublished = $true
            } catch {
                $cleanupFailures.Add(
                    "Source stop command could not be published: $($_.Exception.Message)"
                )
            }
        } else {
            $stopPublished = $true
        }
        try {
            $sourceResultCommitWait = Wait-D01JsonFile `
                -Path $sourceResultCommitPath `
                -TimeoutSeconds ($PeerReadyTimeoutSeconds + 600)
            if ($null -ne $sourceResultCommitWait) {
                $sourceResultCommit = $sourceResultCommitWait.value
                $null = Assert-D01SourceResultCommitContract `
                    -Commit $sourceResultCommit
                if ([string]$sourceResultCommit.case_id -cne $caseId -or
                    [string]$sourceResultCommit.run_nonce -cne $nonce) {
                    throw 'Source result commit does not bind to this run'
                }
                $sourceResultWait = Wait-D01JsonFile `
                    -Path $sourceResultPath -TimeoutSeconds 5
                if ($null -eq $sourceResultWait -or
                    [string]$sourceResultWait.sha256 -cne
                        [string]$sourceResultCommit.
                            coordination_result_sha256) {
                    throw 'Committed source-result bytes do not match marker'
                }
                $candidateSourceResult = $sourceResultWait.value
                $null = Assert-D01SourceResultCoordinationContract `
                    -Result $candidateSourceResult `
                    -ExpectedSourceWebPort $SourceWebPort
                if ([string]$candidateSourceResult.case_id -cne $caseId -or
                    [string]$candidateSourceResult.run_nonce -cne $nonce -or
                    [string]$candidateSourceResult.publication_id -cne
                        [string]$sourceResultCommit.publication_id -or
                    [string]$candidateSourceResult.status -cne
                        [string]$sourceResultCommit.status -or
                    ([string]$candidateSourceResult.status -ceq 'COMPLETE' -and
                        [int]$sourceResultCommit.exit_code -ne 0) -or
                    ([string]$candidateSourceResult.status -ceq 'INCOMPLETE' -and
                        [int]$sourceResultCommit.exit_code -ne 2) -or
                    [string]$candidateSourceResult.candidate.commit -cne
                        [string]$identityBefore.candidate.commit -or
                    [string]$candidateSourceResult.candidate.emule_sha256 -cne
                        $expectedEmuleHash -or
                    [string]$candidateSourceResult.candidate.
                        package_zip_sha256 -cne $expectedZipHash -or
                    [string]$candidateSourceResult.machine_id_sha256 -cne
                        $ExpectedSourceMachineIdSha256.ToLowerInvariant() -or
                    [string]$candidateSourceResult.operator_identity.
                        machine_id_sha256 -cne
                        $ExpectedSourceMachineIdSha256.ToLowerInvariant() -or
                    [string]$candidateSourceResult.operator_identity.
                        user_sid_sha256 -cne
                        $ExpectedSourceUserSidSha256.ToLowerInvariant() -or
                    ($null -ne $candidateSourceResult.
                            source_process_binding -and
                        [string]$candidateSourceResult.
                            source_process_binding.owner_sid_sha256 -cne
                        $ExpectedSourceUserSidSha256.ToLowerInvariant()) -or
                    ($null -ne $sourceReady -and
                        $null -ne $candidateSourceResult.
                            source_process_binding -and
                        [string]$candidateSourceResult.
                            source_process_binding.ownership_id_sha256 -cne
                        [string]$sourceReady.process.binding.
                            ownership_id_sha256) -or
                    ($caseArmed -and
                        ($null -eq $sourceArmAck -or
                            $null -eq $candidateSourceResult.source_arm -or
                            [string]$candidateSourceResult.source_arm.arm_id -cne
                                [string]$sourceArmAck.arm_id -or
                            [int]$candidateSourceResult.source_arm.
                                source_process_id -ne
                                [int]$sourceArmAck.source_process_id -or
                            [string]$candidateSourceResult.source_arm.
                                source_ownership_id_sha256 -cne
                                [string]$sourceArmAck.
                                    source_ownership_id_sha256 -or
                            [int]$candidateSourceResult.source_arm.
                                downloader_process_id -ne
                                [int]$caseArmProcessBinding.process_id -or
                            [string]$candidateSourceResult.source_arm.
                                downloader_ownership_id_sha256 -cne
                                [string]$caseArmProcessBinding.
                                    ownership_id_sha256)) -or
                    ($null -ne $sourceReady -and
                        [string]$candidateSourceResult.cleanup.
                            firewall_armed_evidence.ipv4_allow.
                            canonical_sha256 -cne
                        [string]$sourceReady.firewall.ipv4_allow.
                            canonical_sha256) -or
                    ($null -ne $sourceReady -and
                        [string]$candidateSourceResult.cleanup.
                            firewall_armed_evidence.ipv6_drop.
                            canonical_sha256 -cne
                        [string]$sourceReady.firewall.ipv6_drop.
                            canonical_sha256) -or
                    ($null -ne $sourceReady -and
                        [string]$candidateSourceResult.cleanup.
                            program_containment_armed_evidence.
                            rule_set_sha256 -cne
                        [string]$sourceReady.firewall.program_containment.
                            rule_set_sha256) -or
                    ($null -ne $sourceReady -and
                        ([string]$candidateSourceResult.fixture.file_name -cne
                            [string]$sourceReady.fixture.file_name -or
                        [Int64]$candidateSourceResult.fixture.file_bytes -ne
                            [Int64]$sourceReady.fixture.file_bytes -or
                        [string]$candidateSourceResult.fixture.file_sha256 -cne
                            [string]$sourceReady.fixture.file_sha256 -or
                        [string]$candidateSourceResult.fixture.ed2k_hash -cne
                            [string]$sourceReady.fixture.ed2k_hash))) {
                    throw 'source-result.json does not bind to the exact run/source'
                }
                $sourceResult = $candidateSourceResult
            }
        } catch {
            $sourceResult = $null
            $sourceResultContractErrorSha256 =
                Get-LabStringSha256 -Value $_.Exception.Message
        }
        if ($null -eq $sourceObservation -and
            (Test-Path -LiteralPath $sourceObservationPath -PathType Leaf)) {
            try {
                $lockedSourceObservation = Read-D01ImmutableJsonFile `
                    -Path $sourceObservationPath
                $candidateSourceObservation =
                    $lockedSourceObservation.value
                $null = Assert-D01SourceObservationContract `
                    -Observation $candidateSourceObservation
                if ([string]$candidateSourceObservation.case_id -cne
                        $caseId -or
                    [string]$candidateSourceObservation.run_nonce -cne
                        $nonce -or
                    ($null -ne $sourceReady -and
                        [int]$candidateSourceObservation.source_process_id -ne
                        [int]$sourceReady.process.process_id)) {
                    throw 'source-observation.json does not bind to the exact run'
                }
                $sourceObservation = $candidateSourceObservation
            } catch {
                $sourceObservation = $null
                $sourceObservationContractErrorSha256 =
                    Get-LabStringSha256 -Value $_.Exception.Message
            }
        }
        try {
            $identityAfter = Get-D01CandidateIdentity
            Write-LabJson -Value $identityAfter.extracted_manifest -Path (
                Join-Path $evidence 'package-manifest-after.json'
            ) | Out-Null
            Write-LabJson -Value $identityAfter.zip_manifest -Path (
                Join-Path $evidence 'zip-manifest-after.json'
            ) | Out-Null
            $candidateUnchanged = $null -ne $identityBefore -and
                $identityAfter.exact -and
                $identityAfter.extracted_manifest.manifest_sha256 -eq
                    $identityBefore.extracted_manifest.manifest_sha256 -and
                $identityAfter.zip_manifest.zip_sha256 -eq
                    $identityBefore.zip_manifest.zip_sha256
            if (-not $candidateUnchanged) {
                $cleanupFailures.Add(
                    'Coordinator candidate package or ZIP changed'
                )
            }
        } catch {
            $cleanupFailures.Add(
                "Coordinator identity revalidation failed: $($_.Exception.Message)"
            )
        }
        if ($downloaderExe -and
            (Test-Path -LiteralPath $downloaderExe -PathType Leaf)) {
            $nodeExeUnchanged =
                (Get-LabSha256 -Path $downloaderExe) -eq
                    $expectedEmuleHash
        }
        if (-not $nodeExeUnchanged) {
            $cleanupFailures.Add('Prepared downloader executable changed')
        }
        if ($downloaderNode) {
            try {
                $null = Assert-D01SafetyPreferenceContract `
                    -Path (Join-Path $downloaderNode 'config\preferences.ini')
            } catch {
                $cleanupFailures.Add('Downloader safety preferences changed')
            }
        }
        $terminalOwnership = Get-D01TerminalOwnershipCensus `
            -Process $downloader -Ports @(
                $DownloaderTcpPort, $DownloaderUdpPort, $DownloaderWebPort) `
            -HostRole 'Coordinator'
        if (-not $terminalOwnership.all_clear) {
            $cleanupFailures.Add(
                'Coordinator terminal process/port census is not clear')
        }
        if ($null -ne $script:d01HostsBaseline -and
            $null -eq $script:d01HostsPostcheck) {
            $script:d01HostsPostcheck =
                Get-D01HostsFilePostcheckEvidence `
                    -Baseline $script:d01HostsBaseline
            if (-not $script:d01HostsPostcheck.safe_to_pass) {
                $cleanupFailures.Add(
                    'Coordinator hosts file changed or was unprovable')
            }
        }
        if ($null -ne $script:d01AccountRegistryTransaction -and
            -not $script:d01AccountRegistryPostcheckComplete) {
            $script:d01AccountRegistryPostcheck =
                Get-D01AccountRegistryPostcheckEvidence `
                    -Transaction $script:d01AccountRegistryTransaction
            $script:d01AccountRegistryPostcheckComplete = $true
            if (-not $script:d01AccountRegistryPostcheck.safe_to_pass) {
                $cleanupFailures.Add(
                    'Coordinator account/registry/firewall postcheck is not exact')
            }
        }
    }

    if ($null -eq $telemetryVerdict -and
        $null -ne $finalTelemetry -and $null -ne $sourceReady) {
        try {
            $baselineSequence = if ($null -ne $baselineTelemetry -and
                $baselineTelemetry.available -and
                $baselineTelemetry.contract_valid) {
                [Int64]$baselineTelemetry.data.sequence
            } else { [Int64]0 }
            $canonicalEndpoints =
                Get-D01CanonicalEndpointEvidence -Addresses @(
                    $script:sourcePublicV4Address,
                    $script:sourceV6Address
                ) -Port $SourceTcpPort
            $telemetryVerdict = Get-D01TelemetryVerdict `
                -Snapshot $finalTelemetry `
                -BaselineSequence $baselineSequence `
                -HostnameSha256 (
                    Get-LabStringSha256 -Value $canonicalHostname
                ) -FileEd2kHash (
                    [string]$sourceReady.fixture.ed2k_hash
                ) -Port $SourceTcpPort `
                -CanonicalEndpoints $canonicalEndpoints
        } catch {}
    }

    $baselineTelemetryObservable =
        $null -ne $baselineTelemetry -and
        $baselineTelemetry.available -and
        $baselineTelemetry.contract_valid
    $finalTelemetryObservable =
        $null -ne $finalTelemetry -and
        $finalTelemetry.available -and
        $finalTelemetry.contract_valid
    $captureSubstrateObservable =
        $null -ne $capture -and $null -ne $captureEvidence -and
        [bool]$capture.available -and
        [bool]$capture.capture_started_verified -and
        [bool]$capture.filters_applied_verified -and
        [bool]$captureEvidence.product_capture_observability_pass

    $sourceFirewallFixtureValid = $false
    if ($null -ne $sourceReady) {
        try {
            $firewallV4RemoteAddresses = @(
                @($sourceReady.firewall.ipv4_allow.remote_addresses) |
                    ForEach-Object { [string]$_ } |
                    Sort-Object -Unique
            )
            $topologyAllowedRemoteAddresses = @(
                @($sourceReady.topology.
                    allowed_inverse_remote_addresses) |
                    ForEach-Object { [string]$_ } |
                    Sort-Object -Unique
            )
            $firewallV4RemoteSetExact =
                $topologyAllowedRemoteAddresses.Count -gt 0 -and
                $firewallV4RemoteAddresses.Count -eq
                    $topologyAllowedRemoteAddresses.Count -and
                @(Compare-Object `
                    -ReferenceObject $topologyAllowedRemoteAddresses `
                    -DifferenceObject
                        $firewallV4RemoteAddresses).Count -eq 0
            $sourceFirewallFixtureValid =
                $sourceFirewallSemanticsValidated -and
                [bool]$sourceReady.firewall.rules_created -and
                [bool]$sourceReady.firewall.exact -and
                [bool]$sourceReady.firewall.ipv4_allow.exact -and
                $firewallV4RemoteSetExact -and
                [bool]$sourceReady.firewall.ipv6_drop.exact -and
                [bool]$sourceReady.firewall.program_containment.exact -and
                [string]$sourceReady.firewall.program_containment.role -ceq
                    'Source' -and
                [int]$sourceReady.firewall.program_containment.rule_count -eq
                    4 -and
                [string]$sourceReady.firewall.ipv6_drop.program -eq 'Any' -and
                [string]$sourceReady.firewall.ipv6_drop.remote_port -eq
                    'Any' -and
                [string]$sourceReady.firewall.ipv6_drop.profile -eq 'Any' -and
                [string]$sourceReady.firewall.AAAA_failure_mode -eq
                    'controlled silent inbound DROP'
        } catch {}
    }
    $sourceFirewallCleanupFailed = $false
    if ($null -ne $sourceResult) {
        try {
            $sourceFirewallCleanupFailed =
                -not [bool]$sourceResult.cleanup.
                    temporary_firewall_rules_removed -or
                -not [bool]$sourceResult.cleanup.program_containment_removed
        } catch {}
    }

    if ($null -ne $capture -and $null -ne $captureClockAnchor -and
        $null -ne $captureClockEndAnchor -and
        $captureWindowStartEpochUnixNs -gt 0 -and
        $captureWindowEndEpochUnixNs -ge $captureWindowStartEpochUnixNs) {
        try {
            $sourcePacketLinkEvidence = Get-D01SourcePacketLinkEvidence `
                -State $capture -Observation $sourceObservation `
                 -CaptureDestinationIPv4 $script:sourcePublicV4Text `
                 -SourceListenerIPv4 $script:sourceLocalV4Text `
                 -Port $SourceTcpPort `
                 -ExpectedAdapterEvidence $assignedV4.adapter `
                 -ClockAnchor $captureClockAnchor `
                -ClockEndAnchor $captureClockEndAnchor `
                -WindowStartEpochUnixNs $captureWindowStartEpochUnixNs `
                -WindowEndEpochUnixNs $captureWindowEndEpochUnixNs
        } catch {
            $sourcePacketLinkEvidence = [pscustomobject][ordered]@{
                schema = 'ese.v91.d01-source-packet-link/v1'
                capture_observability_pass = $false
                product_capture_observability_pass = $false
                link_contract_pass = $false
                error_sha256 =
                    Get-LabStringSha256 -Value $_.Exception.Message
            }
        }
        Write-LabJson -Value $sourcePacketLinkEvidence -Path (
            Join-Path $captureEvidencePath 'source-packet-link.json'
        ) | Out-Null
    }
    $sourceResultBindingMatches = $false
    $sourceArmBindingMatches = $false
    if ($null -ne $sourceReady -and $null -ne $sourceResult) {
        try {
            $sourceResultBindingMatches =
                [string]$sourceReady.process.binding.
                    ownership_id_sha256 -ceq
                [string]$sourceResult.source_process_binding.
                    ownership_id_sha256 -and
                [int]$sourceReady.process.process_id -eq
                    [int]$sourceResult.source_process_id
            $sourceArmBindingMatches = $null -ne $sourceArmAck -and
                $null -ne $sourceResult.source_arm -and
                [string]$sourceResult.source_arm.arm_id -ceq
                    [string]$sourceArmAck.arm_id -and
                [string]$sourceResult.source_arm.source_ownership_id_sha256 -ceq
                    [string]$sourceReady.process.binding.
                        ownership_id_sha256 -and
                [int]$sourceResult.source_arm.downloader_process_id -eq
                    [int]$caseArmProcessBinding.process_id -and
                [string]$sourceResult.source_arm.
                    downloader_ownership_id_sha256 -ceq
                    [string]$caseArmProcessBinding.ownership_id_sha256
        } catch {}
    }
    $sourceNetworkProof = [pscustomobject][ordered]@{
        schema = 'ese.v91.d01-source-bound-network-proof/v2'
        source_process_ownership_id_sha256 = if ($null -ne $sourceReady) {
            [string]$sourceReady.process.binding.ownership_id_sha256
        } else { '' }
        source_result_binding_matches_ready = $sourceResultBindingMatches
        source_arm_binding_matches = $sourceArmBindingMatches
        ipv4_allow_canonical_sha256 = if ($null -ne $sourceReady) {
            [string]$sourceReady.firewall.ipv4_allow.canonical_sha256
        } else { '' }
        ipv6_drop_canonical_sha256 = if ($null -ne $sourceReady) {
            [string]$sourceReady.firewall.ipv6_drop.canonical_sha256
        } else { '' }
        exact_source_firewall_fixture = $sourceFirewallFixtureValid
        exact_coordinator_physical_interface =
            $null -ne $captureEvidence -and
            [bool]$captureEvidence.capture_interface_binding_exact
        source_inverse_packet_link = $sourcePacketLinkEvidence
        A_forward_proved = $null -ne $captureEvidence -and
            [bool]$captureEvidence.A_forward.proved
        AAAA_silent_DROP_proved = $null -ne $captureEvidence -and
            [bool]$captureEvidence.AAAA_silent_DROP.proved
        source_bound = $sourceFirewallFixtureValid -and
            $null -ne $sourceReady -and
            $null -ne $sourcePacketLinkEvidence -and
            [bool]$sourcePacketLinkEvidence.link_contract_pass -and
            $null -ne $captureEvidence -and
            [bool]$captureEvidence.capture_interface_binding_exact
        exact = $sourceFirewallFixtureValid -and
            $sourceResultBindingMatches -and $sourceArmBindingMatches -and
            $null -ne $sourcePacketLinkEvidence -and
            [bool]$sourcePacketLinkEvidence.
                product_capture_observability_pass -and
            [bool]$sourcePacketLinkEvidence.link_contract_pass -and
            $null -ne $captureEvidence -and
            [bool]$captureEvidence.A_forward.proved -and
            [bool]$captureEvidence.AAAA_silent_DROP.proved -and
            [bool]$captureEvidence.capture_interface_binding_exact
    }
    Write-LabJson -Value $sourceNetworkProof -Path (
        Join-Path $captureEvidencePath 'source-bound-network-proof.json'
    ) | Out-Null

    $fixtureReasons = New-Object 'Collections.Generic.List[string]'
    $observabilityReasons = New-Object 'Collections.Generic.List[string]'
    $productReasons = New-Object 'Collections.Generic.List[string]'
    $productFailures = [Collections.Generic.List[object]]::new()
    if ($null -eq $identityBefore -or -not $identityBefore.exact) {
        $fixtureReasons.Add('exact candidate package/ZIP fixture was not proven')
    }
    if ($null -eq $sourceReady) {
        $fixtureReasons.Add('controlled Maria source never reached ready barrier')
    }
    if (-not $sourceFirewallFixtureValid) {
        $fixtureReasons.Add(
            'exact IPv4 allow and controlled IPv6 DROP fixture was not proven'
        )
    }
    if ($null -eq $topologyEvidence -or -not $topologyEvidence.valid) {
        $fixtureReasons.Add('direct native T1/T2 topology was not proven')
    }
    if ($null -eq $isolation -or -not $isolation.strict_isolation_valid) {
        $fixtureReasons.Add('overlay/VPN/proxy isolation was not valid')
    }
    if ($null -eq $dnsInitial -or
        -not $dnsInitial.exact_controlled_answer_set -or
        $null -eq $dnsFinal -or
        -not $dnsFinal.exact_controlled_answer_set) {
        $fixtureReasons.Add('exact controlled A+AAAA DNS set was not stable')
    }
    if ($null -eq $aProbe -or -not $aProbe.connected) {
        $fixtureReasons.Add('baseline A reachability was not proven')
    }
    if ($null -eq $aaaaProbe -or $aaaaProbe.connected -or
        -not $aaaaProbe.timed_out) {
        $fixtureReasons.Add(
            'baseline AAAA controlled silent DROP timeout was not proven'
        )
    }
    if ($null -eq $controlledLogin -or -not $controlledLogin.connected) {
        $fixtureReasons.Add('controlled minimal eD2K scheduler was not proven')
    }
    if (-not $caseArmed) {
        $fixtureReasons.Add('controlled product case never reached armed boundary')
    }
    if ($runtimeError -and -not $caseArmed) {
        $fixtureReasons.Add(
            "pre-arming infrastructure error during $failureStage"
        )
    }
    $fixtureStatus = if ($fixtureReasons.Count -eq 0) {
        'PASS'
    } else { 'BLOCKED' }

    if (-not $captureSubstrateObservable) {
        $observabilityReasons.Add(
            'armed, lossless and fully restored PktMon+ETW capture was unavailable'
        )
    }
    $observabilityStatus = if ($observabilityReasons.Count -eq 0) {
        'PASS'
    } else { 'BLOCKED' }

    $hairpinClockToleranceMs = $null
    $sourceObservationInWindow = $false
    $coordinatorObservationInWindow = $false
    $hairpinObservationDeltaMs = $null
    if ($null -ne $sourceObservation -and
        $null -ne $v4EstablishedEvidence -and $null -ne $injection) {
        try {
            $sourceObservedAt = [DateTimeOffset]::Parse(
                [string]$sourceObservation.captured_at_utc,
                [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::RoundtripKind
            ).UtcDateTime
            $coordinatorObservedAt = [DateTimeOffset]::Parse(
                [string]$v4EstablishedEvidence.captured_at_utc,
                [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::RoundtripKind
            ).UtcDateTime
            $hairpinObservationDeltaMs = [Int64][Math]::Abs(
                ($sourceObservedAt - $coordinatorObservedAt).
                    TotalMilliseconds
            )
            $sourceObservationInWindow = $null -ne $sourceArmAck -and
                $null -ne $sourceResult -and $sourceArmBindingMatches -and
                [int]$sourceObservation.first_seen_sample -ge 1 -and
                [int]$sourceObservation.confirmed_sample -ge
                    [int]$sourceObservation.first_seen_sample
            $coordinatorEpoch =
                [Int64]$v4EstablishedEvidence.sample_clock.epoch_unix_ns
            $coordinatorObservationInWindow =
                $coordinatorEpoch -ge
                    [Int64]$injection.clock.epoch_unix_ns -and
                $coordinatorEpoch -le $captureWindowEndEpochUnixNs
        } catch {}
    }
    $inverseStructureValid = $false
    if ($null -ne $sourceObservation -and $null -ne $sourceReady) {
        try {
            $inverseStructureValid =
                [string]$sourceObservation.schema -eq
                    'ese.v91.d01-source-observation/v4' -and
                [string]$sourceObservation.run_nonce -eq $nonce -and
                [string]$sourceObservation.
                    source_process_emule_sha256 -ceq $expectedEmuleHash -and
                [bool]$sourceObservation.exact_inverse_pid_socket -and
                [bool]$sourceObservation.physical_adapter_proven -and
                [bool]$sourceObservation.baseline_zero -and
                [int]$sourceObservation.
                    baseline_established_connection_count -eq 0 -and
                [int]$sourceObservation.
                    baseline_nonlisten_connection_count -eq 0 -and
                [bool]$sourceObservation.
                    all_processes_and_nonlisten_states_checked -and
                [bool]$sourceObservation.
                    source_visible_remote_address_allowed -and
                [int]$sourceObservation.foreign_connection_count -eq 0 -and
                [int]$sourceObservation.
                    all_nonlisten_unique_socket_count -eq 1 -and
                [int]$sourceObservation.unique_new_socket_count -eq 1 -and
                [int]$sourceObservation.ambiguity_count -eq 0 -and
                [int]$sourceObservation.generation_count -eq 1 -and
                [bool]$sourceObservation.
                    hairpin_nat_remote_address_not_assumed -and
                [int]$sourceObservation.source_process_id -eq
                    [int]$sourceReady.process.process_id -and
                [int]$sourceObservation.connection.owning_process -eq
                    [int]$sourceReady.process.process_id -and
                [string]$sourceObservation.connection.state -eq
                    'Established' -and
                [string]$sourceObservation.connection.local_address -eq
                    $script:sourceLocalV4Text -and
                [int]$sourceObservation.connection.local_port -eq
                    $SourceTcpPort -and
                [bool]$sourceObservation.connection.physical_nonvirtual -and
                [string]$sourceObservation.connection.remote_address -in
                    @($sourceReady.topology.
                        allowed_inverse_remote_addresses) -and
                [int]$sourceObservation.connection.remote_port -gt 0 -and
                @($sourceObservation.
                    allowed_source_visible_remote_addresses).Count -eq
                    @($sourceReady.topology.
                        allowed_inverse_remote_addresses).Count -and
                @(Compare-Object -ReferenceObject @(
                        $sourceReady.topology.
                            allowed_inverse_remote_addresses) `
                    -DifferenceObject @($sourceObservation.
                        allowed_source_visible_remote_addresses)).Count -eq 0
        } catch {}
    }
    $v4CoordinatorSocketValid = $false
    if ($null -ne $v4EstablishedEvidence -and $null -ne $downloader) {
        try {
            $v4CoordinatorSocketValid =
                [int]$v4EstablishedEvidence.owning_process -eq
                    [int]$downloader.Id -and
                [string]$v4EstablishedEvidence.state -eq 'Established' -and
                [string]$v4EstablishedEvidence.local_address -eq
                    $script:coordinatorLocalV4Text -and
                [int]$v4EstablishedEvidence.local_port -gt 0 -and
                [string]$v4EstablishedEvidence.remote_address -eq
                    $script:sourcePublicV4Text -and
                [int]$v4EstablishedEvidence.remote_port -eq $SourceTcpPort -and
                [bool]$v4EstablishedEvidence.physical_nonvirtual
        } catch {}
    }
    $exactInverseTupleLinked = $false
    if ($null -ne $sourceObservation -and
        $null -ne $v4EstablishedEvidence) {
        try {
            $exactInverseTupleLinked =
                [string]$sourceObservation.connection.local_address -eq
                    $script:sourceLocalV4Text -and
                [int]$sourceObservation.connection.local_port -eq
                    $SourceTcpPort -and
                [string]$sourceObservation.connection.remote_address -in
                    @(
                        [string]$v4EstablishedEvidence.local_address,
                        $script:coordinatorPublicV4Text
                    ) -and
                [int]$sourceObservation.connection.remote_port -eq
                    [int]$v4EstablishedEvidence.local_port
        } catch {}
    }
    $v4PcapSocketLinked = $false
    if ($null -ne $captureEvidence -and
        $null -ne $v4EstablishedEvidence) {
        try {
            $v4PcapSocketLinked = @(
                @($captureEvidence.per_syn_correlations) |
                    Where-Object {
                        [string]$_.family -eq 'ipv4' -and
                        [bool]$_.attributed -and
                        [int]$_.matched_sampler_row.owning_process -eq
                            [int]$downloader.Id -and
                        [int]$_.matched_sampler_row.local_port -eq
                            [int]$v4EstablishedEvidence.local_port
                    }
            ).Count -gt 0
        } catch {}
    }
    $inverseValid = $inverseStructureValid -and
        $v4CoordinatorSocketValid -and $exactInverseTupleLinked -and
        $v4PcapSocketLinked -and $coordinatorSocketBaselineZero -and
        $sourceObservationInWindow -and $coordinatorObservationInWindow
    if ($caseArmed -and -not $exactInverseTupleLinked) {
        $fixtureReasons.Add(
            'source-visible inverse tuple was rewritten or not proven exactly'
        )
        $fixtureStatus = 'BLOCKED'
    }
    $sourceReadyTopology = Get-D01OptionalProperty `
        -InputObject $sourceReady -Name 'topology'
    $sourceAllowedInverseAddresses = @(
        Get-D01OptionalProperty -InputObject $sourceReadyTopology `
            -Name 'allowed_inverse_remote_addresses' -DefaultValue @()
    )
    $hairpinCorrelation = [ordered]@{
        valid = $inverseValid
        source_pid_and_local_port_valid = $inverseStructureValid
        coordinator_pid_socket_valid = $v4CoordinatorSocketValid
        exact_cross_host_inverse_tuple_linked =
            $exactInverseTupleLinked
        source_observation_in_window = $sourceObservationInWindow
        coordinator_observation_in_window =
            $coordinatorObservationInWindow
        coordinator_socket_baseline_zero =
            $coordinatorSocketBaselineZero
        source_socket_baseline_zero = [bool](
            Get-D01OptionalProperty -InputObject $sourceObservation `
                -Name 'baseline_zero' -DefaultValue $false
        )
        source_all_nonlisten_states_baselined = [bool](
            Get-D01OptionalProperty -InputObject $sourceObservation `
                -Name 'all_processes_and_nonlisten_states_checked' `
                -DefaultValue $false
        )
        source_foreign_connection_count = [int](
            Get-D01OptionalProperty -InputObject $sourceObservation `
                -Name 'foreign_connection_count' -DefaultValue -1
        )
        source_visible_remote_address_allowlist =
            $sourceAllowedInverseAddresses
        pcap_syn_linked_by_pid_and_local_port = $v4PcapSocketLinked
        coordinator_local_port = if ($null -ne $v4EstablishedEvidence) {
            [int]$v4EstablishedEvidence.local_port
        } else { 0 }
        cross_host_observation_delta_ms = $hairpinObservationDeltaMs
        maximum_cross_host_delta_ms = $hairpinClockToleranceMs
        source_remote_address_equality_required = $true
        source_remote_port_equality_required = $true
        rationale =
            'Formal PASS requires Maria to see the coordinator local/public ' +
            'address with its exact ephemeral port; SNAT rewriting makes ' +
            'the fixture BLOCKED'
    }

    $v6SocketEvidenceValid = $false
    if ($null -ne $v6SynSentEvidence -and $null -ne $downloader) {
        try {
            $v6SocketEvidenceValid =
                [int]$v6SynSentEvidence.owning_process -eq
                    [int]$downloader.Id -and
                [string]$v6SynSentEvidence.state -eq 'SynSent' -and
                [string]$v6SynSentEvidence.local_address -eq
                    $script:coordinatorV6Text -and
                [int]$v6SynSentEvidence.local_port -gt 0 -and
                [string]$v6SynSentEvidence.remote_address -eq
                    $script:sourceV6Text -and
                [int]$v6SynSentEvidence.remote_port -eq $SourceTcpPort -and
                [bool]$v6SynSentEvidence.physical_nonvirtual
        } catch {}
    }
    if ($caseArmed) {
        if (-not $baselineTelemetryObservable -or
            -not $finalTelemetryObservable) {
            $productReasons.Add(
                'localhost product telemetry endpoint/contract was unavailable'
            )
        }
        if ($null -eq $telemetryVerdict -or
            -not $telemetryVerdict.exactly_one_new_event -or
            -not $telemetryVerdict.product_contract_pass) {
            $productReasons.Add(
                'one exact canonical A+AAAA materialization event was not proven'
            )
        }
        if ($captureSubstrateObservable) {
            if (-not $captureEvidence.correlation_pass -or
                -not $captureEvidence.ipv4_exact_tuple_correlated) {
                $productReasons.Add(
                    'PCAP/SYN sampler did not correlate every exact physical A tuple'
                )
            }
            if (-not $captureEvidence.correlation_pass -or
                -not $captureEvidence.ipv6_exact_tuple_correlated) {
                $productReasons.Add(
                    'PCAP/SYN sampler did not correlate every exact physical AAAA tuple'
                )
            }
        }
        if (-not $sawV4Socket -or -not $sawV4Established -or
            -not $sawV4Physical -or -not $v4CoordinatorSocketValid) {
            $productReasons.Add(
                'A connection was not attributed to downloader PID/physical route'
            )
        }
        if ($exactInverseTupleLinked -and
            $captureSubstrateObservable -and -not $v4PcapSocketLinked) {
            $productReasons.Add(
                'exact Maria inverse tuple lacked the coordinator PCAP/PID link'
            )
        }
        if (-not $sawV6Socket -or -not $sawV6Physical -or
            -not $sawV6SynSent -or -not $v6SocketEvidenceValid) {
            $productReasons.Add(
                'AAAA attempt lacked exact PID/physical SynSent attribution'
            )
        }
        if ($sawV6Established) {
            $productReasons.Add(
                'failing AAAA candidate unexpectedly established'
            )
        }
        if (-not $transferCompleted) {
            $productReasons.Add('one-file transfer did not complete hash-intact')
        }
        if ($injectionCount -ne 1 -or $null -eq $injection -or
            -not $injection.one_injection) {
            $productReasons.Add('ordinary hostname link was not injected exactly once')
        }
        if ($socketSampleCount -eq 0) {
            $productReasons.Add('coordinator PID socket sampler did not run')
        }
        if ($apiSamples -eq 0 -or $uiSamples -eq 0 -or
            $apiUnavailable -ne 0 -or $uiUnavailable -ne 0) {
            $productReasons.Add(
                'coordinator API/UI availability was not continuous'
            )
        }
        if ($apiIsolationFailures -ne 0) {
            $productReasons.Add(
                'API reported Kad/NetLab/third-party eD2K contamination'
            )
        }
        if ($uiUnresponsive -ne 0) {
            $productReasons.Add('UI message pump became unresponsive')
        }
        if ($null -eq $sourceResult) {
            $productReasons.Add(
                'Maria source result was unavailable after case arming'
            )
        } else {
            try {
                if ([string]$sourceResult.status -ne 'COMPLETE') {
                    $productReasons.Add(
                        'Maria source did not complete the armed product case'
                    )
                }
                if (-not [bool]$sourceResult.health.
                        observability_available -or
                    [int]$sourceResult.health.api_unavailable_count -ne 0 -or
                    [int]$sourceResult.health.ui_unavailable_count -ne 0) {
                    $productReasons.Add(
                        'Maria PID/API/UI availability was not continuous'
                    )
                }
                if ([int]$sourceResult.health.
                        api_isolation_failure_count -ne 0) {
                    $productReasons.Add(
                        'Maria API reported network isolation contamination'
                    )
                }
                if ([int]$sourceResult.health.ui_unresponsive_count -ne 0) {
                    $productReasons.Add(
                        'Maria UI message pump became unresponsive'
                    )
                }
                if (-not [bool]$sourceResult.cleanup.
                        source_process_stopped) {
                    $productReasons.Add(
                        'Maria source process did not stop after the case'
                    )
                }
                if (-not [bool]$sourceResult.candidate.unchanged -or
                    -not [bool]$sourceResult.candidate.
                        prepared_executable_unchanged) {
                    $productReasons.Add(
                        'Maria candidate identity changed during the armed case'
                    )
                }
                if (-not [bool]$sourceResult.
                        inverse_socket_baseline_zero -or
                    -not [bool]$sourceResult.
                        inverse_socket_baseline_all_nonlisten_states_checked -or
                    [int]$sourceResult.
                        inverse_socket_foreign_connection_count -ne 0 -or
                    [int]$sourceResult.
                        inverse_socket_all_nonlisten_unique_count -ne 1 -or
                    [int]$sourceResult.
                        inverse_socket_unique_new_count -ne 1 -or
                    [int]$sourceResult.
                        inverse_socket_ambiguity_count -ne 0 -or
                    [int]$sourceResult.
                        inverse_socket_generation_count -ne 1) {
                    $productReasons.Add(
                        'Maria inverse socket was pre-existing, foreign, ambiguous or reused'
                    )
                }
            } catch {
                $productReasons.Add(
                    'Maria source result contract was malformed'
                )
            }
        }
        if (-not $candidateUnchanged -or -not $nodeExeUnchanged) {
            $productReasons.Add(
                'coordinator candidate identity changed during the armed case'
            )
        }
        if ($unexpectedTcpPeerConnections.Count -ne 0) {
            $productReasons.Add(
                'downloader exposed a third-party/unexpected TCP peer connection'
            )
        }
        if ($sawForeignTargetSocket) {
            $productReasons.Add(
                'a foreign PID opened a target A/AAAA socket during the case'
            )
        }
        if ($sawWrongPortTargetSocket) {
            $productReasons.Add(
                'a target A/AAAA socket used a non-fixture destination port'
            )
        }
        $nonCaptureCleanupFailures = @(
            $cleanupFailures | Where-Object {
                [string]$_ -notmatch
                    '(?i)pktmon|packet capture|ETW|capture finalization'
            }
        )
        if ($nonCaptureCleanupFailures.Count -ne 0) {
            $productReasons.Add(
                'post-arming process, identity or cleanup checks failed'
            )
        }
        if ($null -eq $controlledServerStop -or
            -not $controlledServerStop.stopped -or
            $controlledServerStop.error -or
            -not [bool]$controlledServerStop.ownership.
                all_owned_resources_released) {
            $productReasons.Add(
                'controlled minimal eD2K scheduler did not stop cleanly'
            )
        }
        if (-not $stopPublished) {
            $productReasons.Add('Maria stop command was not published')
        }
        if ($productProcessExited) {
            $productReasons.Add('downloader exited during the product case')
        }
        if ($runtimeError -and $caseArmed) {
            $productReasons.Add("product-stage error: $runtimeError")
        }
    }

    $telemetryCollectorReady = $false
    if ($caseArmed -and $null -ne $caseArmProcessBinding -and
        $baselineTelemetryObservable -and $null -ne $finalTelemetry) {
        try {
            $finalOwnership = $finalTelemetry.endpoint_ownership
            $finalOwnershipBefore =
                $finalTelemetry.endpoint_ownership_before
            $finalEndpointStateAdjudicable =
                [bool]$finalOwnershipBefore.collector_ok -and
                [bool]$finalOwnershipBefore.process_binding_exact -and
                [bool]$finalOwnershipBefore.endpoint_bound_to_candidate -and
                [bool]$finalOwnership.collector_ok -and
                [bool]$finalOwnership.process_binding_exact -and
                (([bool]$finalOwnership.endpoint_bound_to_candidate -and
                    [bool]$finalTelemetry.ownership_stable_across_request) -or
                    [int]$finalOwnership.listener_count -eq 0)
            $telemetryCollectorReady =
                [bool]$finalTelemetry.available -and
                [bool]$finalTelemetry.contract_valid -and
                [bool]$finalTelemetry.source_bound -and
                $baselineTelemetry.source_bound -is [bool] -and
                [bool]$baselineTelemetry.source_bound -and
                [string]$baselineTelemetry.
                    candidate_ownership_id_sha256 -ceq
                    [string]$caseArmProcessBinding.ownership_id_sha256 -and
                [string]$finalTelemetry.
                    candidate_ownership_id_sha256 -ceq
                    [string]$caseArmProcessBinding.ownership_id_sha256 -and
                [Int64]$baselineTelemetry.after_sequence -eq -1 -and
                [Int64]$finalTelemetry.after_sequence -eq
                    [Int64]$baselineTelemetry.data.sequence -and
                $finalEndpointStateAdjudicable
        } catch { $telemetryCollectorReady = $false }
    }
    $soleInjectionSourceBound = $false
    if ($caseArmed -and $null -ne $caseArmProcessBinding -and
        $null -ne $injection) {
        try {
            $soleInjectionSourceBound =
                $injection.one_injection -is [bool] -and
                [bool]$injection.one_injection -and
                $injectionCount -eq 1 -and
                [int]$injection.process_id -eq
                    [int]$caseArmProcessBinding.process_id
        } catch { $soleInjectionSourceBound = $false }
    }
    $networkCollectorReady = $captureSubstrateObservable -and
        $null -ne $captureEvidence -and
        [bool]$captureEvidence.pcap_parser.valid -and
        [bool]$captureEvidence.socket_sampler.valid -and
        [bool]$captureEvidence.clock_coherence.valid -and
        [bool]$captureEvidence.capture_interface_binding_exact -and
        [bool]$captureEvidence.target_frames_on_expected_physical_nic -and
        [bool]$captureEvidence.etw_lossless -and
        [bool]$captureEvidence.correlation_pass -and
        [bool]$captureEvidence.exact_filters_applied -and
        $null -ne $coordinatorContainmentArmedEvidence -and
        [bool]$coordinatorContainmentArmedEvidence.exact -and
        [string]$coordinatorContainmentArmedEvidence.role -ceq
            'Coordinator' -and
        [int]$coordinatorContainmentArmedEvidence.rule_count -eq 7 -and
        $sourceFirewallFixtureValid
    $materializationSourceBound = $telemetryCollectorReady -and
        $null -ne $telemetryVerdict -and
        [bool]$finalTelemetry.available -and
        [bool]$finalTelemetry.contract_valid -and
        [bool]$finalTelemetry.source_bound -and
        [bool]$telemetryVerdict.product_contract_pass -and
        $soleInjectionSourceBound
    $failureObservedEpochUnixNs = Get-D01EpochUnixNs

    if ($caseArmed -and $null -ne $caseArmProcessBinding) {
        $hasCoordinatorApiFailureEvidence =
            $null -ne $firstCoordinatorApiIsolationFailureEvidence
        $hasCoordinatorUiFailureEvidence =
            $null -ne $firstCoordinatorUiTimeoutFailureEvidence
        if (($apiIsolationFailures -gt 0) -ne
                $hasCoordinatorApiFailureEvidence -or
            ($uiUnresponsive -gt 0) -ne
                $hasCoordinatorUiFailureEvidence) {
            throw 'Coordinator positive health counters lack exact evidence'
        }
        if ($productProcessExited -ne
            ($null -ne $firstCoordinatorProcessExitEvidence)) {
            throw 'Coordinator process-exit state lacks exact positive evidence'
        }
        if ($hasCoordinatorApiFailureEvidence) {
            $null = Assert-D01CoordinatorApiFailureEvidenceContract `
                -Evidence $firstCoordinatorApiIsolationFailureEvidence `
                -ExpectedArmId $armId `
                -ArmBoundaryEpochUnixNs $caseArmBoundaryEpochUnixNs `
                -CandidateBinding $caseArmProcessBinding `
                -ExpectedWebPort $DownloaderWebPort
        }
        if ($hasCoordinatorUiFailureEvidence) {
            $null = Assert-D01CoordinatorUiFailureEvidenceContract `
                -Evidence $firstCoordinatorUiTimeoutFailureEvidence `
                -ExpectedArmId $armId `
                -ArmBoundaryEpochUnixNs $caseArmBoundaryEpochUnixNs `
                -CandidateBinding $caseArmProcessBinding
        }
        if ($null -ne $firstCoordinatorProcessExitEvidence) {
            $null = Assert-D01CoordinatorProcessExitEvidenceContract `
                -Evidence $firstCoordinatorProcessExitEvidence `
                -ExpectedArmId $armId `
                -ArmBoundaryEpochUnixNs $caseArmBoundaryEpochUnixNs `
                -CandidateBinding $caseArmProcessBinding
        }
        $coordinatorApiFailureObservedEpochUnixNs = if (
            $hasCoordinatorApiFailureEvidence
        ) {
            [Int64]$firstCoordinatorApiIsolationFailureEvidence.
                observed_epoch_unix_ns
        } else { [Int64]0 }
        $coordinatorUiFailureObservedEpochUnixNs = if (
            $hasCoordinatorUiFailureEvidence
        ) {
            [Int64]$firstCoordinatorUiTimeoutFailureEvidence.
                observed_epoch_unix_ns
        } else { [Int64]0 }
        $coordinatorProcessExitObservedEpochUnixNs = if (
            $null -ne $firstCoordinatorProcessExitEvidence
        ) {
            [Int64]$firstCoordinatorProcessExitEvidence.
                observed_epoch_unix_ns
        } else { [Int64]0 }
        if ($telemetryCollectorReady -and
            ($null -eq $telemetryVerdict -or
                -not [bool]$telemetryVerdict.product_contract_pass)) {
            $productFailures.Add((New-D01ProductFailure `
                -FailureType 'telemetry-materialization' `
                -DisplayMessage (
                    'The candidate did not emit the exact canonical A+AAAA ' +
                    'materialization event') `
                -SourceKind 'candidate-telemetry' `
                -ObservedEpochUnixNs $failureObservedEpochUnixNs `
                -ArmBoundaryEpochUnixNs $caseArmBoundaryEpochUnixNs `
                -CandidateProcessBinding $caseArmProcessBinding `
                -CollectorOk $true -SourceBound $true -Evidence ([ordered]@{
                    baseline_sequence = if ($null -ne $baselineTelemetry) {
                        [Int64]$baselineTelemetry.data.sequence
                    } else { -1L }
                    final_sequence = if ($null -ne $finalTelemetry) {
                        if ([bool]$finalTelemetry.contract_valid) {
                            [Int64]$finalTelemetry.data.sequence
                        } else { -1L }
                    } else { -1L }
                    endpoint_listener_count = if ($null -ne $finalTelemetry) {
                        [int]$finalTelemetry.endpoint_ownership.listener_count
                    } else { -1 }
                    endpoint_bound_to_candidate =
                        $null -ne $finalTelemetry -and
                        [bool]$finalTelemetry.endpoint_ownership.
                            endpoint_bound_to_candidate
                    payload_available = $null -ne $finalTelemetry -and
                        [bool]$finalTelemetry.available
                    payload_contract_valid = $null -ne $finalTelemetry -and
                        [bool]$finalTelemetry.contract_valid
                    exactly_one_new_event = $null -ne $telemetryVerdict -and
                        [bool]$telemetryVerdict.exactly_one_new_event
                    product_contract_pass = $false
                })))
        }
        if ($networkCollectorReady -and $materializationSourceBound -and
            -not [bool]$captureEvidence.A_forward.proved) {
            $productFailures.Add((New-D01ProductFailure `
                -FailureType 'A-forward' `
                -DisplayMessage (
                    'The materialized A candidate did not complete the ' +
                    'required physical IPv4 forward path') `
                -SourceKind 'candidate-network' `
                -ObservedEpochUnixNs $failureObservedEpochUnixNs `
                -ArmBoundaryEpochUnixNs $caseArmBoundaryEpochUnixNs `
                -CandidateProcessBinding $caseArmProcessBinding `
                -CollectorOk $true -SourceBound $true -Evidence ([ordered]@{
                    outbound_syn_count =
                        [int]$captureEvidence.A_forward.
                            outbound_syn_count
                    exact_handshake_count =
                        [int]$captureEvidence.A_forward.
                            exact_handshake_count
                    established_sample_count =
                        [int]$captureEvidence.A_forward.
                            candidate_established_sample_count
                    capture_interface_binding_exact =
                        [bool]$captureEvidence.
                            capture_interface_binding_exact
                })))
        }
        if ($networkCollectorReady -and $materializationSourceBound -and
            -not [bool]$captureEvidence.AAAA_silent_DROP.proved) {
            $productFailures.Add((New-D01ProductFailure `
                -FailureType 'AAAA-silent-DROP' `
                -DisplayMessage (
                    'The materialized AAAA candidate did not exhibit the ' +
                    'required controlled silent DROP') `
                -SourceKind 'candidate-network' `
                -ObservedEpochUnixNs $failureObservedEpochUnixNs `
                -ArmBoundaryEpochUnixNs $caseArmBoundaryEpochUnixNs `
                -CandidateProcessBinding $caseArmProcessBinding `
                -CollectorOk $true -SourceBound $true -Evidence ([ordered]@{
                    outbound_syn_count =
                        [int]$captureEvidence.AAAA_silent_DROP.
                            outbound_syn_count
                    tcp_response_or_reset_count =
                        [int]$captureEvidence.AAAA_silent_DROP.
                            tcp_response_or_reset_count
                    icmpv6_error_count =
                        [int]$captureEvidence.AAAA_silent_DROP.
                            icmpv6_error_count
                    established_sample_count =
                        [int]$captureEvidence.AAAA_silent_DROP.
                            established_sample_count
                    source_firewall_fixture_exact =
                        $sourceFirewallFixtureValid
                })))
        }
        $transferOutcomeCollectorReady = $materializationSourceBound -and
            $networkCollectorReady -and
            [bool]$captureEvidence.A_forward.proved -and
            [bool]$captureEvidence.AAAA_silent_DROP.proved -and
            $inverseValid -and $null -ne $transferFinished -and
            $destinationTerminalStateObserved -and
            $apiSamples -gt 0 -and $uiSamples -gt 0 -and
            $apiUnavailable -eq 0 -and $uiUnavailable -eq 0 -and
            $null -ne $sourceResult -and
            $sourceResultBindingMatches -and
            [bool]$sourceResult.product_observability_complete -and
            [bool]$sourceResult.health.observability_available -and
            [int]$sourceResult.health.api_unavailable_count -eq 0 -and
            [int]$sourceResult.health.ui_unavailable_count -eq 0
        if ($transferOutcomeCollectorReady -and -not $transferCompleted) {
            $productFailures.Add((New-D01ProductFailure `
                -FailureType 'transfer-integrity' `
                -DisplayMessage (
                    'The fully observed one-file transfer did not complete ' +
                    'with the exact source hash') `
                -SourceKind 'candidate-output' `
                -ObservedEpochUnixNs $failureObservedEpochUnixNs `
                -ArmBoundaryEpochUnixNs $caseArmBoundaryEpochUnixNs `
                -CandidateProcessBinding $caseArmProcessBinding `
                -CollectorOk $true -SourceBound $true -Evidence ([ordered]@{
                    expected_bytes = $FileSizeBytes
                    observed_bytes = $destinationBytes
                    expected_sha256 = if ($null -ne $sourceReady) {
                        [string]$sourceReady.fixture.file_sha256
                    } else { '' }
                    observed_sha256 = $destinationSha256
                    hash_match = $false
                })))
        }
        if ($hasCoordinatorApiFailureEvidence) {
            $productFailures.Add((New-D01ProductFailure `
                -FailureType 'network-isolation' `
                -DisplayMessage (
                    'The candidate API reported forbidden network activity') `
                -SourceKind 'candidate-telemetry' `
                -ObservedEpochUnixNs `
                    $coordinatorApiFailureObservedEpochUnixNs `
                -ArmBoundaryEpochUnixNs $caseArmBoundaryEpochUnixNs `
                -CandidateProcessBinding $caseArmProcessBinding `
                -CollectorOk $true -SourceBound $true `
                -Evidence $firstCoordinatorApiIsolationFailureEvidence))
        }
        if ($hasCoordinatorUiFailureEvidence) {
            $productFailures.Add((New-D01ProductFailure `
                -FailureType 'UI-responsiveness' `
                -DisplayMessage (
                    'The retained candidate UI became unresponsive') `
                -SourceKind 'candidate-process' `
                -ObservedEpochUnixNs `
                    $coordinatorUiFailureObservedEpochUnixNs `
                -ArmBoundaryEpochUnixNs $caseArmBoundaryEpochUnixNs `
                -CandidateProcessBinding $caseArmProcessBinding `
                -CollectorOk $true -SourceBound $true `
                -Evidence $firstCoordinatorUiTimeoutFailureEvidence))
        }
        $sourcePositiveFailureReady = $null -ne $sourceResult -and
            $sourceResultBindingMatches -and $sourceArmBindingMatches
        $sourceApiPositiveFailureEvidence = if (
            $sourcePositiveFailureReady -and
            [int]$sourceResult.health.api_sample_count -gt 0 -and
            [int]$sourceResult.health.api_isolation_failure_count -gt 0
        ) { $sourceResult.first_api_isolation_failure_evidence } else { $null }
        $sourceUiPositiveFailureEvidence = if (
            $sourcePositiveFailureReady -and
            [int]$sourceResult.health.ui_sample_count -gt 0 -and
            [int]$sourceResult.health.ui_unresponsive_count -gt 0
        ) { $sourceResult.first_ui_timeout_failure_evidence } else { $null }
        $sourceProcessExitPositiveEvidence = if (
            $sourcePositiveFailureReady -and
            [bool]$sourceResult.product_process_exited_after_arm
        ) { $sourceResult.process_exit_evidence } else { $null }
        if ($null -ne $sourceApiPositiveFailureEvidence) {
            $productFailures.Add((New-D01ProductFailure `
                -FailureType 'network-isolation' `
                -DisplayMessage (
                    'The retained source candidate API reported forbidden ' +
                    'network activity after bilateral arm') `
                -SourceKind 'candidate-telemetry' `
                -ObservedEpochUnixNs $failureObservedEpochUnixNs `
                -ArmBoundaryEpochUnixNs $caseArmBoundaryEpochUnixNs `
                -CandidateProcessBinding $sourceResult.source_process_binding `
                -CollectorOk $true -SourceBound $true `
                -Evidence $sourceApiPositiveFailureEvidence))
        }
        if ($null -ne $sourceUiPositiveFailureEvidence) {
            $productFailures.Add((New-D01ProductFailure `
                -FailureType 'UI-responsiveness' `
                -DisplayMessage (
                    'The retained source candidate UI became unresponsive ' +
                    'after bilateral arm') `
                -SourceKind 'candidate-process' `
                -ObservedEpochUnixNs $failureObservedEpochUnixNs `
                -ArmBoundaryEpochUnixNs $caseArmBoundaryEpochUnixNs `
                -CandidateProcessBinding $sourceResult.source_process_binding `
                -CollectorOk $true -SourceBound $true `
                -Evidence $sourceUiPositiveFailureEvidence))
        }
        if ($null -ne $sourceProcessExitPositiveEvidence) {
            $productFailures.Add((New-D01ProductFailure `
                -FailureType 'candidate-process-exit' `
                -DisplayMessage (
                    'The retained source candidate exited after bilateral arm') `
                -SourceKind 'candidate-process' `
                -ObservedEpochUnixNs $failureObservedEpochUnixNs `
                -ArmBoundaryEpochUnixNs $caseArmBoundaryEpochUnixNs `
                -CandidateProcessBinding $sourceResult.source_process_binding `
                -CollectorOk $true -SourceBound $true `
                -Evidence $sourceProcessExitPositiveEvidence))
        }
        if ($unexpectedTcpPeerPositiveEvidence.Count -gt 0) {
            $firstUnexpectedEvidence =
                $unexpectedTcpPeerPositiveEvidence[0]
            $null = Assert-D01UnexpectedTcpPeerFailureEvidenceContract `
                -Evidence $firstUnexpectedEvidence `
                -ExpectedArmId $armId `
                -ArmBoundaryEpochUnixNs $caseArmBoundaryEpochUnixNs `
                -ArmBoundaryQpcTicks $caseArmBoundaryQpcTicks `
                -ExpectedClockAnchor $captureClockAnchor `
                -CandidateBinding $caseArmProcessBinding `
                -ExpectedSourceAddresses @(
                    $script:sourcePublicV4Text, $script:sourceV6Text) `
                -ExpectedSourcePort $SourceTcpPort `
                -ExpectedSchedulerAddress $script:coordinatorLocalV4Text `
                -ExpectedSchedulerPort ([int]$controlledServer.port) `
                -ExpectedWebPort $DownloaderWebPort
            $productFailures.Add((New-D01ProductFailure `
                -FailureType 'unexpected-candidate-tcp-peer-connection' `
                -DisplayMessage (
                    'The candidate exposed an unexpected connected TCP ' +
                    'peer tuple outside the scheduler/source/API allowlist') `
                -SourceKind 'candidate-network' `
                -ObservedEpochUnixNs (
                    [Int64]$firstUnexpectedEvidence.observed_epoch_unix_ns) `
                -ArmBoundaryEpochUnixNs $caseArmBoundaryEpochUnixNs `
                -CandidateProcessBinding `
                    $firstUnexpectedEvidence.process_binding `
                -CollectorOk $true -SourceBound $true `
                -Evidence $firstUnexpectedEvidence))
        }
        if ($null -ne $firstCoordinatorProcessExitEvidence) {
            $productFailures.Add((New-D01ProductFailure `
                -FailureType 'candidate-process-exit' `
                -DisplayMessage (
                    'The retained downloader process exited during the ' +
                    'armed product case') `
                -SourceKind 'candidate-process' `
                -ObservedEpochUnixNs `
                    $coordinatorProcessExitObservedEpochUnixNs `
                -ArmBoundaryEpochUnixNs $caseArmBoundaryEpochUnixNs `
                -CandidateProcessBinding $caseArmProcessBinding `
                -CollectorOk $true -SourceBound $true `
                -Evidence $firstCoordinatorProcessExitEvidence))
        }
        foreach ($bindingSpec in @(
            [pscustomobject]@{
                evidence = $firstCoordinatorApiIsolationFailureEvidence
                failure_type = 'network-isolation'
                source_kind = 'candidate-telemetry'
                binding = $caseArmProcessBinding
            },
            [pscustomobject]@{
                evidence = $firstCoordinatorUiTimeoutFailureEvidence
                failure_type = 'UI-responsiveness'
                source_kind = 'candidate-process'
                binding = $caseArmProcessBinding
            },
            [pscustomobject]@{
                evidence = $firstCoordinatorProcessExitEvidence
                failure_type = 'candidate-process-exit'
                source_kind = 'candidate-process'
                binding = $caseArmProcessBinding
            },
            [pscustomobject]@{
                evidence = if (
                    $unexpectedTcpPeerPositiveEvidence.Count -gt 0
                ) { $unexpectedTcpPeerPositiveEvidence[0] } else { $null }
                failure_type =
                    'unexpected-candidate-tcp-peer-connection'
                source_kind = 'candidate-network'
                binding = $caseArmProcessBinding
            }
        )) {
            if ($null -ne $bindingSpec.evidence) {
                $null = Assert-D01ProductFailureEvidenceHashBinding `
                    -ProductFailures @($productFailures) `
                    -Evidence $bindingSpec.evidence `
                    -ExpectedFailureType $bindingSpec.failure_type `
                    -ExpectedSourceKind $bindingSpec.source_kind `
                    -CandidateProcessBinding $bindingSpec.binding `
                    -RequireEvidenceObservedEpochMatch
            }
        }
        if ($sourcePositiveFailureReady) {
            foreach ($bindingSpec in @(
                [pscustomobject]@{
                    evidence = $sourceApiPositiveFailureEvidence
                    failure_type = 'network-isolation'
                    source_kind = 'candidate-telemetry'
                },
                [pscustomobject]@{
                    evidence = $sourceUiPositiveFailureEvidence
                    failure_type = 'UI-responsiveness'
                    source_kind = 'candidate-process'
                },
                [pscustomobject]@{
                    evidence = $sourceProcessExitPositiveEvidence
                    failure_type = 'candidate-process-exit'
                    source_kind = 'candidate-process'
                }
            )) {
                if ($null -ne $bindingSpec.evidence) {
                    $null = Assert-D01ProductFailureEvidenceHashBinding `
                        -ProductFailures @($productFailures) `
                        -Evidence $bindingSpec.evidence `
                        -ExpectedFailureType $bindingSpec.failure_type `
                        -ExpectedSourceKind $bindingSpec.source_kind `
                        -CandidateProcessBinding `
                            $sourceResult.source_process_binding
                }
            }
        }
    }

    if ($caseArmed -and $null -eq $caseArmProcessBinding) {
        $observabilityReasons.Add(
            'armed candidate process ownership boundary was unavailable')
    }
    if (-not $baselineTelemetryObservable -or
        -not $finalTelemetryObservable -or
        -not $telemetryCollectorReady) {
        $observabilityReasons.Add(
            'candidate-bound baseline/final telemetry collection was incomplete')
    }
    if ($null -eq $sourceResult) {
        $observabilityReasons.Add(
            'exact source-result coordination contract was unavailable')
    } elseif ([string]$sourceResult.status -cne 'COMPLETE') {
        $observabilityReasons.Add(
            'source result was incomplete and cannot adjudicate product behavior')
    }
    if ($null -eq $sourceObservation) {
        $observabilityReasons.Add(
            'exact source inverse-socket observation was unavailable')
    }
    if ($null -eq $sourcePacketLinkEvidence -or
        -not [bool]$sourcePacketLinkEvidence.
            product_capture_observability_pass) {
        $observabilityReasons.Add(
            'source inverse packet-link capture was not observable')
    }
    if ($apiSamples -eq 0 -or $uiSamples -eq 0 -or
        $apiUnavailable -ne 0 -or $uiUnavailable -ne 0 -or
        $socketSampleCount -eq 0) {
        $observabilityReasons.Add(
            'coordinator PID/API/UI/TCP-peer scheduled sampling was unavailable')
    }
    if (-not $productProcessExited -and
        -not $tcpPeerCollectorSourceBound) {
        $observabilityReasons.Add(
            'final candidate-bound TCP peer sampling was unavailable')
    }
    if ($sourceFirewallCleanupFailed) {
        $observabilityReasons.Add(
            'source nonce firewall cleanup was not proven exact')
    }
    if ($cleanupFailures.Count -ne 0) {
        $observabilityReasons.Add(
            'post-case cleanup or immutable-state postchecks were not exact')
    }
    if (-not $candidateUnchanged -or -not $nodeExeUnchanged) {
        $observabilityReasons.Add(
            'coordinator candidate identity was not immutable through cleanup')
    }
    if ($null -eq $controlledServerStop -or
        -not $controlledServerStop.stopped -or
        $controlledServerStop.error -or
        -not [bool]$controlledServerStop.ownership.
            all_owned_resources_released -or -not $stopPublished) {
        $observabilityReasons.Add(
            'owned scheduler/source stop and resource release were not exact')
    }
    if ($null -eq $script:d01HostsPostcheck -or
        -not $script:d01HostsPostcheck.safe_to_pass -or
        $null -eq $script:d01AccountRegistryPostcheck -or
        -not $script:d01AccountRegistryPostcheck.safe_to_pass -or
        $null -eq $terminalOwnership -or
        -not $terminalOwnership.all_clear) {
        $observabilityReasons.Add(
            'terminal hosts/registry/firewall/process/port postchecks were incomplete')
    }
    if ($runtimeError -and $caseArmed) {
        $observabilityReasons.Add(
            'an armed-stage runtime error lacked a typed product attribution')
    }
    $healthSamplesSnapshot = $null
    if (Test-Path -LiteralPath $healthSamplesPath -PathType Leaf) {
        try {
            $healthSamplesSnapshot = Open-D01ImmutableEvidenceSnapshot `
                -Path $healthSamplesPath -MetadataOnly
        } catch {
            $observabilityReasons.Add(
                'coordinator health-sample evidence could not be locked/hashed')
        }
    }
    if (($apiSamples -gt 0 -or $uiSamples -gt 0) -and
        $null -eq $healthSamplesSnapshot) {
        $observabilityReasons.Add(
            'coordinator health-sample evidence file is unavailable')
    }
    if ($sawForeignTargetSocket -or $sawWrongPortTargetSocket) {
        $fixtureReasons.Add(
            'foreign or wrong-port target socket contamination was observed')
    }
    if ($caseArmed -and -not $soleInjectionSourceBound) {
        $fixtureReasons.Add(
            'the sole hostname-link injection was not exactly candidate-bound')
    }
    if ($caseArmed -and -not $inverseValid) {
        $fixtureReasons.Add(
            'the exact time-bounded cross-host inverse tuple was not proven')
    }
    if ($null -ne $sourceResult) {
        if (-not $sourceResultBindingMatches) {
            $observabilityReasons.Add(
                'source ready/result process ownership binding was not exact')
        }
        if (-not [bool]$sourceResult.health.observability_available -or
            [int]$sourceResult.health.api_unavailable_count -ne 0 -or
            [int]$sourceResult.health.ui_unavailable_count -ne 0 -or
            [int]$sourceResult.health.api_isolation_failure_count -ne 0 -or
            [int]$sourceResult.health.ui_unresponsive_count -ne 0) {
            $observabilityReasons.Add(
                'source health aggregate was incomplete or not arm-partitioned')
        }
    }
    $fixtureStatus = if ($fixtureReasons.Count -eq 0) {
        'PASS'
    } else { 'BLOCKED' }
    $observabilityStatus = if ($observabilityReasons.Count -eq 0) {
        'PASS'
    } else { 'BLOCKED' }

    $adjudication = Get-D01AdjudicationStatus `
        -CaseArmed $caseArmed `
        -ArmBoundaryEpochUnixNs $caseArmBoundaryEpochUnixNs `
        -FixtureStatus $fixtureStatus `
        -ObservabilityStatus $observabilityStatus `
        -ProductFailures @($productFailures)
    $productStatus = [string]$adjudication.product_status
    $formalStatus = [string]$adjudication.formal_status
    $sourceResultHealth = Get-D01OptionalProperty `
        -InputObject $sourceResult -Name 'health'
    $sourceResultCleanup = Get-D01OptionalProperty `
        -InputObject $sourceResult -Name 'cleanup'
    $sourceResultStatus = [string](
        Get-D01OptionalProperty -InputObject $sourceResult `
            -Name 'status' -DefaultValue 'UNAVAILABLE'
    )

    $publicationId = [Guid]::NewGuid().ToString('N')
    $summary = [ordered]@{
        schema = 'ese.v91.d01-dual-dns/v3'
        case_id = $caseId
        run_nonce = $nonce
        publication = [ordered]@{
            schema = 'ese.v91.d01-adjudication-publication/v1'
            publication_id = $publicationId
            commit_required = $true
            commit_file = 'evidence\adjudication-commit.json'
        }
        case_armed = $caseArmed
        formal_status = $formalStatus
        fixture_status = $fixtureStatus
        observability_status = $observabilityStatus
        product_status = $productStatus
        exit_code = if ($formalStatus -eq 'PASS') {
            0
        } elseif ($formalStatus -eq 'FAIL') { 1 } else { 2 }
        observed_topology = if ($null -ne $topologyEvidence) {
            $topologyEvidence.observed_topology
        } else { 'NOT_PROVEN' }
        accepted_topologies = @('T1', 'T2')
        candidate = [ordered]@{
            commit = if ($null -ne $identityBefore) {
                $identityBefore.candidate.commit
            } else { $Commit.ToLowerInvariant() }
            emule_sha256 = $expectedEmuleHash
            package_zip_sha256 = $expectedZipHash
            extracted_manifest_sha256 = if ($null -ne $identityBefore) {
                $identityBefore.extracted_manifest.manifest_sha256
            } else { '' }
            zip_manifest_sha256 = if ($null -ne $identityBefore) {
                $identityBefore.zip_manifest.manifest_sha256
            } else { '' }
            zip_matches_extracted_directory =
                $null -ne $identityBefore -and
                $identityBefore.zip_matches_extracted_directory
            candidate_unchanged = $candidateUnchanged
            prepared_executable_unchanged = $nodeExeUnchanged
        }
        timing = [ordered]@{
            started_at_utc = $startedAt.ToString('o')
            transfer_started_at_utc = if ($null -ne $transferStarted) {
                $transferStarted.ToString('o')
            } else { $null }
            transfer_finished_at_utc = if ($null -ne $transferFinished) {
                $transferFinished.ToString('o')
            } else { $null }
            finished_at_utc = Get-LabUtcTimestamp
            product_observation_window_closed_epoch_unix_ns =
                $productObservationWindowClosedEpochUnixNs
        }
        topology = $topologyEvidence
        controlled_dns = [ordered]@{
            hostname = $canonicalHostname
            hostname_sha256 =
                Get-LabStringSha256 -Value $canonicalHostname
            expected_A = $script:sourcePublicV4Text
            expected_AAAA = $script:sourceV6Text
            initial = $dnsInitial
            final = $dnsFinal
            A_baseline_probe = $aProbe
            AAAA_baseline_probe = $aaaaProbe
        }
        scheduler_isolation = [ordered]@{
            controlled_profile = $controlledProfile
            controlled_login = $controlledLogin
            controlled_server_stop = $controlledServerStop
            kad_disabled = $true
            netlab_disabled = $true
            third_party_server_files_removed = $true
            coordinator_program_containment =
                $coordinatorContainmentArmedEvidence
            coordinator_program_containment_removed =
                $null -ne $coordinatorContainment -and
                [bool]$coordinatorContainment.cleanup_exact
            source_program_containment = if ($null -ne $sourceReady) {
                $sourceReady.firewall.program_containment
            } else { $null }
            source_program_containment_removed =
                $null -ne $sourceResult -and
                [bool]$sourceResult.cleanup.program_containment_removed
            unexpected_tcp_peer_connection_count =
                $unexpectedTcpPeerConnections.Count
            unexpected_tcp_peer_connections =
                $unexpectedTcpPeerConnections
            overlay_vpn_proxy_absent =
                $null -ne $isolation -and
                $isolation.strict_isolation_valid
        }
        telemetry = [ordered]@{
            endpoint =
                'http://127.0.0.1:<port>/api/debug/source-resolutions'
            query_after_used = $true
            pre_observe = $preObserveTelemetry
            baseline = $baselineTelemetry
            final = $finalTelemetry
            verdict = $telemetryVerdict
        }
        packet_capture = $captureEvidence
        source_bound_network_proof = $sourceNetworkProof
        sockets = [ordered]@{
            coordinator_sample_count = $socketSampleCount
            candidate_tcp_peer_connection_sample_count =
                $tcpPeerSampleCount
            candidate_tcp_peer_connection_sampling_available =
                $tcpPeerCollectorSourceBound
            all_target_ports_sampled = $true
            wrong_port_target_socket_observed =
                $sawWrongPortTargetSocket
            foreign_pid_target_socket_observed =
                $sawForeignTargetSocket
            A_socket_observed = $sawV4Socket
            A_established = $sawV4Established
            A_established_on_physical_adapter = $sawV4Physical
            A_established_evidence = $v4EstablishedEvidence
            AAAA_socket_observed_by_os_sampler = $sawV6Socket
            AAAA_observed_on_physical_adapter = $sawV6Physical
            AAAA_SynSent_observed = $sawV6SynSent
            AAAA_established = $sawV6Established
            AAAA_observed_states = @($v6ObservedStates)
            AAAA_SynSent_evidence = $v6SynSentEvidence
            AAAA_SynSent_evidence_valid = $v6SocketEvidenceValid
            source_inverse_socket = $sourceObservation
            source_inverse_socket_valid = $inverseValid
            hairpin_correlation = $hairpinCorrelation
        }
        transfer = [ordered]@{
            one_file = $true
            one_hostname_source = $true
            injection_count = $injectionCount
            injection = $injection
            file_name = if ($null -ne $sourceReady) {
                $sourceReady.fixture.file_name
            } else { '' }
            file_bytes = $FileSizeBytes
            ed2k_hash = if ($null -ne $sourceReady) {
                ([string]$sourceReady.fixture.ed2k_hash).ToLowerInvariant()
            } else { '' }
            source_sha256 = if ($null -ne $sourceReady) {
                $sourceReady.fixture.file_sha256
            } else { '' }
            destination_bytes = $destinationBytes
            destination_sha256 = $destinationSha256
            destination_terminal_state_observed_after_stop =
                $destinationTerminalStateObserved
            destination_immutable_snapshot_held =
                $destinationFinalizedAfterStop
            hash_match = $transferCompleted
        }
        health = [ordered]@{
            coordinator = [ordered]@{
                api_sample_count = $apiSamples
                api_unavailable_count = $apiUnavailable
                api_isolation_failure_count = $apiIsolationFailures
                first_api_isolation_failure_evidence =
                    $firstCoordinatorApiIsolationFailureEvidence
                ui_sample_count = $uiSamples
                ui_unavailable_count = $uiUnavailable
                ui_unresponsive_count = $uiUnresponsive
                first_ui_timeout_failure_evidence =
                    $firstCoordinatorUiTimeoutFailureEvidence
                first_process_exit_evidence =
                    $firstCoordinatorProcessExitEvidence
                first_unexpected_tcp_peer_connection_evidence = if (
                    $unexpectedTcpPeerPositiveEvidence.Count -gt 0
                ) { $unexpectedTcpPeerPositiveEvidence[0] } else { $null }
                health_samples_snapshot = $healthSamplesSnapshot
            }
            source = $sourceResultHealth
        }
        adjudication = [ordered]@{
            fixture_blockers = @($fixtureReasons)
            observability_blockers = @($observabilityReasons)
            typed_product_failures = @($productFailures)
            diagnostic_product_reasons = @($productReasons)
            typed_product_failure_count = $productFailures.Count
            arm_boundary_epoch_unix_ns =
                $caseArmBoundaryEpochUnixNs
            rule =
                'Only a typed, collector-complete, source-bound failure ' +
                'strictly at/after the armed boundary is FAIL; otherwise ' +
                'missing fixture, observability or cleanup proof is BLOCKED'
        }
        execution = [ordered]@{
            failure_stage = $failureStage
            runtime_error = $runtimeError
            source_result_status = $sourceResultStatus
            source_result_contract_error_sha256 =
                $sourceResultContractErrorSha256
            source_observation_contract_error_sha256 =
                $sourceObservationContractErrorSha256
        }
        cleanup = [ordered]@{
            downloader_process_stopped = if ($null -eq $downloader) {
                $true
            } else {
                try { $downloader.Refresh(); [bool]$downloader.HasExited } catch {
                    $false
                }
            }
            controlled_server_stopped =
                $null -ne $controlledServerStop -and
                $controlledServerStop.stopped
            source_stop_published = $stopPublished
            source = $sourceResultCleanup
            candidate_unchanged = $candidateUnchanged
            pktmon_filter_inventory_restored =
                $null -ne $capture -and
                $capture.filter_inventory_restored_verified
            pktmon_driver_monitoring_stopped =
                $null -ne $capture -and
                $null -ne $capture.pktmon_driver_status_final -and
                [bool]$capture.pktmon_driver_status_final.inactive_exact -and
                [bool]$capture.
                    pktmon_driver_configuration_restored_verified -and
                ((-not [bool]$capture.session_owned) -or
                    [bool]$capture.pktmon_driver_stop_verified -or
                    [bool]$capture.pktmon_driver_rollback_stop_verified -or
                    [bool]$capture.
                        pktmon_driver_inactive_pre_stop_verified)
            pktmon_driver_configuration_restored =
                $null -ne $capture -and
                [bool]$capture.
                    pktmon_driver_configuration_restored_verified
            pktmon_global_counter_state_restored =
                $null -ne $capture -and
                [bool]$capture.counter_global_restored_verified -and
                (Test-D01PktmonGlobalCounterEvidenceChain -State $capture)
            pktmon_etw_session_stopped =
                $null -ne $capture -and
                $capture.etw_session_stopped_verified
            dns_modified = $false
            hosts_modified = $null -eq $script:d01HostsPostcheck -or
                -not [bool]$script:d01HostsPostcheck.safe_to_pass
            routes_modified = $false
            adapters_modified = $false
            overlay_vpn_modified = $false
            proxy_modified = $false
            account_registry_firewall_postcheck =
                $script:d01AccountRegistryPostcheck
            terminal_ownership = $terminalOwnership
            hosts_file_postcheck = $script:d01HostsPostcheck
            failures = @($cleanupFailures)
        }
        evidence = [ordered]@{
            summary = 'evidence\summary.json'
            package_manifest_before =
                'evidence\package-manifest-before.json'
            package_manifest_after =
                'evidence\package-manifest-after.json'
            zip_manifest_before = 'evidence\zip-manifest-before.json'
            zip_manifest_after = 'evidence\zip-manifest-after.json'
            topology = 'evidence\topology.json'
            dns_initial = 'evidence\dns-initial.json'
            dns_final = 'evidence\dns-final.json'
            endpoint_probes = 'evidence\endpoint-probes.json'
            sole_injection = 'evidence\sole-link-injection.json'
            telemetry_samples =
                'evidence\api\source-resolutions.jsonl'
            telemetry_verdict =
                'evidence\api\telemetry-verdict.json'
            socket_samples = 'evidence\target-sockets.jsonl'
            candidate_tcp_peer_connection_samples =
                'evidence\candidate-tcp-peer-connections.jsonl'
            health_samples = 'evidence\health-samples.jsonl'
            packet_capture = 'evidence\capture'
            source_packet_link =
                'evidence\capture\source-packet-link.json'
            source_bound_network_proof =
                'evidence\capture\source-bound-network-proof.json'
            source_result_coordination_file = $sourceResultPath
            source_result_commit_coordination_file =
                $sourceResultCommitPath
            adjudication_commit = 'evidence\adjudication-commit.json'
        }
    }
    $publicSummary = Get-D01PublicSummaryProjection `
        -PrivateSummary ([pscustomobject]$summary)
    $null = Assert-D01PublicSummaryProjection -Projection $publicSummary
    $publicSummaryPath = Join-Path $evidence 'public-summary.json'
    Write-D01JsonAtomic -Value $publicSummary -Path $publicSummaryPath
    $publicSummarySnapshot = Open-D01ImmutableEvidenceSnapshot `
        -Path $publicSummaryPath -MetadataOnly
    $summary.evidence['public_summary'] = 'evidence\public-summary.json'
    $summary.evidence['public_summary_sha256'] =
        [string]$publicSummarySnapshot.sha256
    Write-D01JsonAtomic -Value $summary -Path $summaryPath
    $privateSummarySnapshot = Open-D01ImmutableEvidenceSnapshot `
        -Path $summaryPath `
        -MetadataOnly
    $precommitCoordinatorIdentity = Get-D01CandidateIdentity
    $precommitCoordinatorTerminal = Get-D01TerminalOwnershipCensus `
        -Process $downloader `
        -Ports @($DownloaderTcpPort, $DownloaderUdpPort, $DownloaderWebPort) `
        -HostRole 'Coordinator'
    $precommitCoordinatorHosts = Get-D01HostsFilePostcheckEvidence `
        -Baseline $script:d01HostsBaseline
    $precommitCoordinatorAccount = Get-D01AccountRegistryPostcheckEvidence `
        -Transaction $script:d01AccountRegistryTransaction
    $precommitCoordinatorNodeExact = if (
        [string]::IsNullOrWhiteSpace($downloaderExe)
    ) { $null -eq $downloaderCodeBinding } else {
        (Test-Path -LiteralPath $downloaderExe -PathType Leaf) -and
            (Get-LabSha256 -Path $downloaderExe) -ceq $expectedEmuleHash
    }
    if (-not $precommitCoordinatorIdentity.exact -or
        [string]$precommitCoordinatorIdentity.extracted_manifest.
            manifest_sha256 -cne
            [string]$identityBefore.extracted_manifest.manifest_sha256 -or
        [string]$precommitCoordinatorIdentity.zip_manifest.zip_sha256 -cne
            [string]$identityBefore.zip_manifest.zip_sha256 -or
        -not $precommitCoordinatorNodeExact -or
        -not [bool]$precommitCoordinatorTerminal.all_clear -or
        -not [bool]$precommitCoordinatorHosts.safe_to_pass -or
        -not [bool]$precommitCoordinatorAccount.safe_to_pass) {
        throw 'Coordinator immutable state changed before adjudication commit'
    }
    $precommitPktmonSnapshot = $null
    if ($null -ne $capture -and
        [bool]$capture.filter_inventory_before_valid) {
        $precommitFilterResult = Invoke-D01Pktmon `
            -LogPath $capture.command_log -Arguments @('filter', 'list')
        $precommitFilterCensus = Get-D01PktmonInventoryCensus `
            -Text ([string]$precommitFilterResult.stdout)
        $precommitEtwProbe =
            Get-D01EtwLossEvidence -IdentityProbeOnly
        $precommitEtwAbsent = $false
        try {
            $null = Assert-D01EtwSessionNameProbeContract `
                -Probe $precommitEtwProbe -RequireAbsent
            $precommitEtwAbsent = $true
        } catch { $precommitEtwAbsent = $false }
        $precommitDriverInactive = $false
        try {
            $null = Assert-D01PktmonDriverApiCompatibilityContract `
                -Evidence $capture.pktmon_driver_api_compatibility
            $precommitDriverStatus =
                Get-D01PktmonDriverStatus -ExpectedLibrarySha256 (
                    [string]$capture.pktmon_driver_api_compatibility.
                        library_sha256) -ExpectedDriverSha256 (
                    [string]$capture.pktmon_driver_api_compatibility.
                        driver_sha256)
            $null = Assert-D01PktmonDriverStatusContract `
                -Evidence $precommitDriverStatus `
                -ExpectedLibrarySha256 (
                    [string]$capture.pktmon_driver_api_compatibility.
                        library_sha256) -RequireInactive `
                -ExpectedConfigurationBaseline `
                    $capture.pktmon_driver_status_before
            $precommitDriverInactive = $true
        } catch { $precommitDriverInactive = $false }
        $precommitCounterRestored = $false
        $precommitGlobalCounterChainExact = $false
        try {
            $null = Assert-D01PktmonAllCounterSnapshotContract `
                -Evidence $capture.counter_global_baseline -RequireAllZero
            if ([bool]$capture.start_attempted) {
                $null = Assert-D01PktmonCounterResetContract `
                    -Evidence $capture.counter_reset_result
                $null = Assert-D01PktmonAllCounterSnapshotContract `
                    -Evidence $capture.counter_global_post_reset `
                    -ExpectedBaseline $capture.counter_global_baseline `
                    -RequireAllZero -RequireRestored
                if (-not [bool]$capture.counter_loss_frozen_verified -or
                    -not [bool]$capture.counter_global_final_frozen_verified -or
                    -not [bool]$capture.counter_reset_attempted -or
                    [int]$capture.counter_reset_invocation_count -ne 1 -or
                    [bool]$capture.counter_reset_required) {
                    throw 'PktMon reset/frozen-evidence state is contradictory'
                }
            } elseif ([bool]$capture.counter_reset_attempted -or
                [int]$capture.counter_reset_invocation_count -ne 0 -or
                [bool]$capture.counter_reset_required) {
                throw 'PktMon reset was attempted without crossing START'
            }
            $precommitAllResult = Invoke-D01Pktmon `
                -LogPath $capture.command_log `
                -Arguments @(
                    'counters', '--type', 'all', '--include-hidden',
                    '--zero', '--json')
            $capture.counter_global_precommit =
                Get-D01PktmonAllCounterSnapshotEvidence `
                    -Stdout ([string]$precommitAllResult.stdout) `
                    -Stderr ([string]$precommitAllResult.stderr) `
                    -ExitCode ([int]$precommitAllResult.exit_code) `
                    -ProcessExited ([bool]$precommitAllResult.process_exited) `
                    -OutputComplete ([bool]$precommitAllResult.output_complete) `
                    -ExpectedBaseline $capture.counter_global_baseline
            $null = Assert-D01PktmonAllCounterSnapshotContract `
                -Evidence $capture.counter_global_precommit `
                -ExpectedBaseline $capture.counter_global_baseline `
                -RequireAllZero -RequireRestored
            $precommitCounterRestored =
                [bool]$capture.counter_global_restored_verified
            $precommitGlobalCounterChainExact =
                Test-D01PktmonGlobalCounterEvidenceChain -State $capture
            if (-not $precommitGlobalCounterChainExact) {
                throw 'PktMon global counter evidence chain is not exact'
            }
        } catch { $precommitCounterRestored = $false }
        if ([int]$precommitFilterResult.exit_code -ne 0 -or
            -not [bool]$precommitFilterResult.process_exited -or
            -not [bool]$precommitFilterCensus.exact -or
            -not [bool]$precommitFilterCensus.empty -or
            [int]$precommitFilterCensus.entry_count -ne 0 -or
            -not $precommitEtwAbsent -or
            -not $precommitDriverInactive -or
            -not $precommitCounterRestored -or
            -not $precommitGlobalCounterChainExact -or
            -not [bool]$capture.
                pktmon_driver_configuration_restored_verified -or
            -not (Test-D01TrustedCommandLedgerQuiescent)) {
            throw 'PktMon state changed before adjudication commit'
        }
        $precommitPktmonPath = Join-Path $evidence `
            'pktmon-precommit-state.json'
        $precommitPktmonEvidence = [ordered]@{
            schema = 'ese.v91.d01-pktmon-precommit-state/v2'
            captured_at_utc = Get-LabUtcTimestamp
            filter_census = $precommitFilterCensus
            etw_absence = $precommitEtwProbe
            driver_status = $precommitDriverStatus
            global_counter_baseline_sha256 =
                [string]$capture.counter_global_baseline.snapshot_sha256
            global_counter_precommit = $capture.counter_global_precommit
            drop_counter_final_snapshot = $capture.counter_loss_snapshot
            global_counter_final_snapshot =
                $capture.counter_global_final_snapshot
            global_counter_chain_exact =
                $precommitGlobalCounterChainExact
            reset_result = $capture.counter_reset_result
            reset_invocation_count =
                [int]$capture.counter_reset_invocation_count
            trusted_command_ledger_quiescent = $true
            driver_configuration_restored =
                [bool]$capture.
                    pktmon_driver_configuration_restored_verified
            global_counter_state_restored =
                [bool]$capture.counter_global_restored_verified
        }
        Write-D01JsonAtomic -Value $precommitPktmonEvidence `
            -Path $precommitPktmonPath
        $precommitPktmonSnapshot = Open-D01ImmutableEvidenceSnapshot `
            -Path $precommitPktmonPath -MetadataOnly
        if (-not [bool]$precommitPktmonSnapshot.immutable_read_lock_held -or
            [string]$precommitPktmonSnapshot.sha256 -cnotmatch
                '^[0-9a-f]{64}$') {
            throw 'PktMon precommit evidence was not frozen exactly'
        }
    } elseif ($null -ne $capture -and
        (@($capture.filters_created).Count -ne 0 -or
            [bool]$capture.started -or [bool]$capture.session_owned)) {
        throw 'PktMon mutation lacks a precommit baseline inventory'
    }
    if ($null -ne $script:d01PendingPktmonCleanupState) {
        throw 'PktMon cleanup remains pending before adjudication commit'
    }
    $commitPath = Join-Path $evidence 'adjudication-commit.json'
    $expectedPktmonPrecommitSha256 = if (
        $null -eq $precommitPktmonSnapshot
    ) { '' } else { [string]$precommitPktmonSnapshot.sha256 }
    $commit = [ordered]@{
        schema = 'ese.v91.d01-adjudication-commit/v2'
        case_id = $caseId
        publication_id = $publicationId
        committed_at_utc = Get-LabUtcTimestamp
        formal_status = $formalStatus
        exit_code = [int]$summary.exit_code
        public_summary_sha256 = [string]$publicSummarySnapshot.sha256
        private_summary_sha256 = [string]$privateSummarySnapshot.sha256
        pktmon_precommit_state_sha256 = $expectedPktmonPrecommitSha256
    }
    $null = Assert-D01AdjudicationCommitContract `
        -Commit ([pscustomobject]$commit) -ExpectedCaseId $caseId `
        -ExpectedPublicationId $publicationId `
        -ExpectedStatus $formalStatus `
        -ExpectedExitCode ([int]$summary.exit_code) `
        -ExpectedPktmonPrecommitSha256 $expectedPktmonPrecommitSha256
    Write-D01JsonAtomic -Value $commit -Path $commitPath
    $null = Open-D01ImmutableEvidenceSnapshot -Path $commitPath `
        -MetadataOnly
    # Atomic publication plus an immutable, hashable read handle is the local
    # commit point.  Only now may later diagnostics preserve the formal exit.
    $script:d01CommittedExitCode = [int]$summary.exit_code
    Write-Host (
        "V91-D01 $formalStatus; topology=$($summary.observed_topology); " +
        "fixture=$fixtureStatus; observability=$observabilityStatus; " +
        "product=$productStatus"
    ) -ForegroundColor $(
        if ($formalStatus -eq 'PASS') {
            'Green'
        } elseif ($formalStatus -eq 'FAIL') { 'Red' } else { 'Yellow' }
    )
    if ($formalStatus -eq 'PASS') { return 0 }
    if ($formalStatus -eq 'FAIL') { return 1 }
    return 2
}

if ($PSCmdlet.ParameterSetName -eq 'NativeHelper') {
    $helperExitCode = 0
    try {
        $helperScriptPath = Assert-D01NoReparsePath `
            -Path $PSCommandPath -Kind File
        if ((Get-LabSha256 -Path $helperScriptPath) -cne
            $InternalExpectedScriptSha256) {
            throw 'Native helper script hash changed before dispatch'
        }
        $helperPayload = switch ($InternalNativeOperation) {
            'driver-status' {
                if (-not $InternalExpectedLibrarySha256 -or
                    -not $InternalExpectedDriverSha256) {
                    throw 'Driver-status helper hashes are absent'
                }
                Get-D01PktmonDriverStatus `
                    -ExpectedLibrarySha256 $InternalExpectedLibrarySha256 `
                    -ExpectedDriverSha256 $InternalExpectedDriverSha256 `
                    -DirectInternal
            }
            'driver-stop' {
                if (-not $InternalExpectedLibrarySha256 -or
                    -not $InternalExpectedDriverSha256) {
                    throw 'Driver-stop helper hashes are absent'
                }
                Invoke-D01PktmonDriverStop `
                    -ExpectedLibrarySha256 $InternalExpectedLibrarySha256 `
                    -ExpectedDriverSha256 $InternalExpectedDriverSha256 `
                    -DirectInternal
            }
            'etw-probe' {
                Get-D01EtwLossEvidence -IdentityProbeOnly -DirectInternal
            }
            'etw-query' {
                Get-D01EtwLossEvidence `
                    -ExpectedLogFilePath $InternalExpectedLogFilePath `
                    -ExpectedControlTraceIdHex (
                        $InternalExpectedControlTraceIdHex) -DirectInternal
            }
            'etw-stop' {
                if (-not $InternalExpectedLogFilePath -or
                    -not $InternalExpectedControlTraceIdHex) {
                    throw 'ETW-stop helper identity is incomplete'
                }
                Get-D01EtwLossEvidence -StopOwnedSession `
                    -ExpectedLogFilePath $InternalExpectedLogFilePath `
                    -ExpectedControlTraceIdHex (
                        $InternalExpectedControlTraceIdHex) -DirectInternal
            }
        }
        $helperEnvelope = [pscustomobject][ordered]@{
            schema = 'ese.v91.d01-bounded-native-helper/v1'
            operation = $InternalNativeOperation
            success = $true
            payload = $helperPayload
            error_sha256 = ''
        }
    } catch {
        $helperExitCode = 2
        $helperEnvelope = [pscustomobject][ordered]@{
            schema = 'ese.v91.d01-bounded-native-helper/v1'
            operation = $InternalNativeOperation
            success = $false
            payload = $null
            error_sha256 =
                Get-LabStringSha256 -Value $_.Exception.Message
        }
    }
    [Console]::Out.WriteLine(($helperEnvelope |
        ConvertTo-Json -Depth 100 -Compress))
    exit $helperExitCode
}

$exitCode = 2
try {
    if (-not $ControlledFixtureAcknowledged) {
        throw 'D01 requires an explicitly controlled/authorized two-host fixture'
    }
    if (-not $DisposableLabAccountAcknowledged) {
        throw 'D01 requires an acknowledged disposable lab account on both hosts'
    }
    if ($Role -eq 'Coordinator' -and
        -not $ExclusivePktmonDriverControlAcknowledged) {
        throw 'D01 Coordinator requires exclusive PktMon control; concurrent CLI, filter, driver, ETW/provider and direct pktmonapi/IOCTL mutators must be excluded'
    }
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        throw 'V91-D01 is a Windows-only physical two-host harness'
    }
    if (-not (Test-D01Administrator)) {
        throw "$Role role requires elevated PowerShell for PID, firewall and ETW evidence"
    }
    if ($ExpectedCoordinatorMachineIdSha256 -ieq
            $ExpectedSourceMachineIdSha256 -or
        $ExpectedCoordinatorUserSidSha256 -ieq
            $ExpectedSourceUserSidSha256) {
        throw 'D01 requires two distinct bound machines and disposable accounts'
    }
    $canonicalHostname = Get-D01CanonicalHostname -Value $Hostname
    $script:d01HostIdentity = Get-D01CurrentHostIdentity
    $expectedLocalMachineHash = if ($Role -eq 'Source') {
        $ExpectedSourceMachineIdSha256.ToLowerInvariant()
    } else { $ExpectedCoordinatorMachineIdSha256.ToLowerInvariant() }
    $expectedLocalSidHash = if ($Role -eq 'Source') {
        $ExpectedSourceUserSidSha256.ToLowerInvariant()
    } else { $ExpectedCoordinatorUserSidSha256.ToLowerInvariant() }
    if ([string]$script:d01HostIdentity.machine_id_sha256 -cne
            $expectedLocalMachineHash -or
        [string]$script:d01HostIdentity.user_sid_sha256 -cne
            $expectedLocalSidHash) {
        throw "$Role host/account identity differs from the operator binding"
    }
    $null = Assert-D01DisjointOperationalPaths `
        -PackageDirectory $PackagePath -PackageZip $PackageZipPath `
        -OutputDirectory $OutputRoot `
        -CoordinationDirectory $CoordinationRoot
    $rolePorts = if ($Role -eq 'Source') {
        @($SourceTcpPort, $SourceUdpPort, $SourceWebPort)
    } else {
        @($DownloaderTcpPort, $DownloaderUdpPort, $DownloaderWebPort)
    }
    $null = Enter-D01CampaignLocks `
        -Roots @($PackagePath, $PackageZipPath, $OutputRoot,
            $CoordinationRoot) -Ports $rolePorts `
        -IncludePktmon:($Role -eq 'Coordinator')
    $null = Get-D01CandidateIdentity
    $script:d01AccountRegistryTransaction =
        Start-D01AccountRegistryTransaction `
            -ExpectedUserSidSha256 $expectedLocalSidHash
    $script:d01HostsBaseline = Get-D01HostsFileSnapshot
    $script:sourcePublicV4Address = Convert-D01Address `
        -Value $SourcePublicIPv4 `
        -Family ([Net.Sockets.AddressFamily]::InterNetwork) `
        -Name 'SourcePublicIPv4'
    $script:sourceLocalV4Address = Convert-D01Address `
        -Value $SourceLocalIPv4 `
        -Family ([Net.Sockets.AddressFamily]::InterNetwork) `
        -Name 'SourceLocalIPv4'
    $script:sourceV6Address = Convert-D01Address `
        -Value $SourceIPv6 `
        -Family ([Net.Sockets.AddressFamily]::InterNetworkV6) `
        -Name 'SourceIPv6'
    $script:coordinatorPublicV4Address = Convert-D01Address `
        -Value $CoordinatorPublicIPv4 `
        -Family ([Net.Sockets.AddressFamily]::InterNetwork) `
        -Name 'CoordinatorPublicIPv4'
    $script:coordinatorLocalV4Address = Convert-D01Address `
        -Value $CoordinatorLocalIPv4 `
        -Family ([Net.Sockets.AddressFamily]::InterNetwork) `
        -Name 'CoordinatorLocalIPv4'
    $script:coordinatorV6Address = Convert-D01Address `
        -Value $CoordinatorIPv6 `
        -Family ([Net.Sockets.AddressFamily]::InterNetworkV6) `
        -Name 'CoordinatorIPv6'
    $script:sourcePublicV4Text = $sourcePublicV4Address.ToString()
    $script:sourceLocalV4Text = $sourceLocalV4Address.ToString()
    $script:sourceV6Text = $sourceV6Address.ToString()
    $script:coordinatorPublicV4Text =
        $coordinatorPublicV4Address.ToString()
    $script:coordinatorLocalV4Text =
        $coordinatorLocalV4Address.ToString()
    $script:coordinatorV6Text = $coordinatorV6Address.ToString()
    if ((Get-D01StrictAddressClass -Address $sourcePublicV4Text) -cne
        'public-unicast-v4') {
        throw 'SourcePublicIPv4 must be a globally routable A record'
    }
    if ((Get-D01StrictAddressClass -Address $coordinatorPublicV4Text) -cne
        'public-unicast-v4') {
        throw 'CoordinatorPublicIPv4 must be globally routable'
    }
    if ((Get-D01StrictAddressClass -Address $sourceV6Text) -cne
        'native-global-v6') {
        throw 'SourceIPv6 must be a native globally routable AAAA record'
    }
    if ((Get-D01StrictAddressClass -Address $coordinatorV6Text) -cne
        'native-global-v6') {
        throw 'CoordinatorIPv6 must be native and globally routable'
    }
    if (-not (Test-D01UsableLocalIPv4 -Address $sourceLocalV4Text)) {
        throw 'SourceLocalIPv4 must be assigned unicast IPv4'
    }
    if (-not (Test-D01UsableLocalIPv4 -Address $coordinatorLocalV4Text)) {
        throw 'CoordinatorLocalIPv4 must be assigned unicast IPv4'
    }
    $ports = @(
        $SourceTcpPort, $SourceUdpPort, $SourceWebPort,
        $DownloaderTcpPort, $DownloaderUdpPort, $DownloaderWebPort
    )
    if (@($ports | Sort-Object -Unique).Count -ne $ports.Count) {
        throw 'All source/downloader TCP, UDP and Web ports must be unique'
    }
    if ($Role -eq 'Source') {
        $exitCode = Invoke-D01SourceRole
    } else {
        $exitCode = Invoke-D01CoordinatorRole
    }
} catch {
    if ($null -ne $script:d01CommittedExitCode) {
        [Console]::Error.WriteLine(
            'V91-D01 post-commit diagnostic error; committed adjudication ' +
            "is preserved: $($_.Exception.Message)")
        $exitCode = [int]$script:d01CommittedExitCode
    } else {
        [Console]::Error.WriteLine(
            "V91-D01 BLOCKED before a committed formal adjudication: " +
            $_.Exception.Message)
        $exitCode = 2
    }
} finally {
    $outerLedgerQuiescent =
        Test-D01TrustedCommandLedgerQuiescent -Terminate
    if ($outerLedgerQuiescent -and
        $null -ne $script:d01PendingPktmonCleanupState) {
        try {
            if ($null -eq $script:d01PendingPktmonCleanupFailures) {
                throw 'Deferred PktMon cleanup lost its failure ledger'
            }
            $retryCompleted = Stop-D01PacketCapture `
                -State $script:d01PendingPktmonCleanupState `
                -CleanupFailures $script:d01PendingPktmonCleanupFailures
            if (-not [bool]$retryCompleted) {
                throw 'Deferred PktMon cleanup did not enter after quiescence'
            }
        } catch {
            [Console]::Error.WriteLine(
                'V91-D01 BLOCKED: deferred PktMon cleanup retry failed: ' +
                $_.Exception.Message)
            if ($null -eq $script:d01CommittedExitCode) { $exitCode = 2 }
        }
        $outerLedgerQuiescent =
            Test-D01TrustedCommandLedgerQuiescent -Terminate
    }
    if (-not $outerLedgerQuiescent) {
        [Console]::Error.WriteLine(
            'V91-D01 BLOCKED: a retained trusted command process remains active')
        if ($null -eq $script:d01CommittedExitCode) { $exitCode = 2 }
    }
    if ($null -ne $script:d01PendingPktmonCleanupState) {
        [Console]::Error.WriteLine(
            'V91-D01 BLOCKED: deferred PktMon cleanup remains incomplete')
        if ($null -eq $script:d01CommittedExitCode) { $exitCode = 2 }
    }
    if ($null -ne $script:d01HostsBaseline -and
        $null -eq $script:d01HostsPostcheck) {
        $script:d01HostsPostcheck = Get-D01HostsFilePostcheckEvidence `
            -Baseline $script:d01HostsBaseline
        if (-not $script:d01HostsPostcheck.safe_to_pass) {
            if ($null -eq $script:d01CommittedExitCode) { $exitCode = 2 }
        }
    }
    if ($null -ne $script:d01AccountRegistryTransaction -and
        -not $script:d01AccountRegistryPostcheckComplete) {
        $script:d01AccountRegistryPostcheck =
            Get-D01AccountRegistryPostcheckEvidence `
                -Transaction $script:d01AccountRegistryTransaction
        $script:d01AccountRegistryPostcheckComplete = $true
        if (-not $script:d01AccountRegistryPostcheck.safe_to_pass) {
            if ($null -eq $script:d01CommittedExitCode) { $exitCode = 2 }
        }
    }
    for ($lockIndex = $script:d01CandidateLocks.Count - 1;
        $lockIndex -ge 0; $lockIndex--) {
        $lock = $script:d01CandidateLocks[$lockIndex]
        try {
            if ($lock -is [Threading.Mutex]) { $lock.ReleaseMutex() }
        } catch {}
        try { $lock.Dispose() } catch {}
    }
    $script:d01CandidateLocks.Clear()
}
$webPassword = $null
exit $exitCode
