Set-StrictMode -Version 2.0

$script:I07OverlayPattern =
    '(?i)tailscale|wireguard|cloudflare|warp|zerotier|openvpn|' +
    'hyper-v|vethernet|loopback|tunnel|tap|vpn|hamachi'

function Test-I07StrictBoolean {
    param([AllowNull()]$Value)
    return $Value -is [bool]
}

function Test-I07StrictInteger {
    param(
        [AllowNull()]$Value,
        [Int64]$Minimum = [Int64]::MinValue,
        [Int64]$Maximum = [Int64]::MaxValue
    )
    $integral = $Value -is [byte] -or $Value -is [sbyte] -or
        $Value -is [Int16] -or $Value -is [UInt16] -or
        $Value -is [Int32] -or $Value -is [UInt32] -or
        $Value -is [Int64] -or $Value -is [UInt64]
    if (-not $integral) { return $false }
    try {
        $number = [Int64]$Value
        return $number -ge $Minimum -and $number -le $Maximum
    } catch { return $false }
}

function Test-I07StrictString {
    param([AllowNull()]$Value, [switch]$AllowEmpty)
    if (-not ($Value -is [string])) { return $false }
    return $AllowEmpty -or -not [string]::IsNullOrWhiteSpace([string]$Value)
}

function Get-I07ObjectPropertyNames {
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return @() }
    if ($Value -is [Collections.IDictionary]) {
        return @($Value.Keys | ForEach-Object { [string]$_ })
    }
    return @($Value.PSObject.Properties | ForEach-Object {
            [string]$_.Name
        })
}

function Test-I07ExactPropertySet {
    param([AllowNull()]$Value, [string[]]$Expected)
    return ((@(Get-I07ObjectPropertyNames -Value $Value | Sort-Object) `
                -join "`n") -ceq (@($Expected | Sort-Object) -join "`n"))
}

function Test-I07NoRawDiagnosticProperties {
    param([AllowNull()]$Value, [int]$Depth = 0)
    if ($Depth -gt 32) { return $false }
    if ($null -eq $Value -or $Value -is [string] -or
        $Value.GetType().IsPrimitive -or $Value -is [decimal] -or
        $Value -is [DateTime] -or $Value -is [DateTimeOffset]) {
        return $true
    }
    if ($Value -is [Collections.IEnumerable] -and
        -not ($Value -is [Collections.IDictionary]) -and
        -not ($Value -is [pscustomobject])) {
        foreach ($item in $Value) {
            if (-not (Test-I07NoRawDiagnosticProperties -Value $item `
                    -Depth ($Depth + 1))) { return $false }
        }
        return $true
    }
    $banned = @(
        'message', 'exception', 'controller_error', 'last_error', 'error',
        'token', 'password', 'stream_key', 'playlist_path', 'user_hash',
        'raw_response', 'response_body', 'stdout', 'stderr')
    if ($Value -is [Collections.IDictionary]) {
        foreach ($key in $Value.Keys) {
            if ([string]$key -iin $banned -or
                -not (Test-I07NoRawDiagnosticProperties -Value $Value[$key] `
                    -Depth ($Depth + 1))) { return $false }
        }
        return $true
    }
    foreach ($property in $Value.PSObject.Properties) {
        if ([string]$property.Name -iin $banned -or
            -not (Test-I07NoRawDiagnosticProperties -Value $property.Value `
                -Depth ($Depth + 1))) { return $false }
    }
    return $true
}

function Write-I07JsonAtomic {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][string]$Path,
        [ValidateRange(2, 32)][int]$Depth = 16
    )

    $directory = Split-Path -Parent ([IO.Path]::GetFullPath($Path))
    if (-not [string]::IsNullOrWhiteSpace($directory)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }
    $temporary = $Path + '.new'
    $Value | ConvertTo-Json -Depth $Depth |
        Set-Content -LiteralPath $temporary -Encoding UTF8
    Move-Item -LiteralPath $temporary -Destination $Path -Force
}

function Remove-I07TreeNoReparse {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedParent
    )

    $fullPath = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $parent = [IO.Path]::GetFullPath($ExpectedParent).TrimEnd('\')
    $actualParent = [IO.Path]::GetDirectoryName($fullPath).TrimEnd('\')
    if ($actualParent -ine $parent) {
        throw 'Safe tree deletion rejected a path outside its exact parent.'
    }
    if (-not (Test-Path -LiteralPath $fullPath)) { return $true }
    $rootPrefix = $fullPath + '\'

    function Remove-I07EntryNoReparse {
        param(
            [Parameter(Mandatory = $true)][string]$EntryPath,
            [Parameter(Mandatory = $true)][string]$AllowedRoot,
            [Parameter(Mandatory = $true)][string]$AllowedPrefix
        )
        $entryFull = [IO.Path]::GetFullPath($EntryPath).TrimEnd('\')
        if ($entryFull -ine $AllowedRoot -and
            -not $entryFull.StartsWith(
                $AllowedPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Safe tree deletion encountered an escaping child path.'
        }
        $item = Get-Item -LiteralPath $entryFull -Force -ErrorAction Stop
        $isReparse = ($item.Attributes -band
            [IO.FileAttributes]::ReparsePoint) -ne 0
        if ($isReparse) {
            if ($item.PSIsContainer) {
                [IO.Directory]::Delete($entryFull, $false)
            } else {
                [IO.File]::Delete($entryFull)
            }
            return
        }
        if ($item.PSIsContainer) {
            foreach ($child in @(Get-ChildItem -LiteralPath $entryFull -Force `
                    -ErrorAction Stop)) {
                Remove-I07EntryNoReparse -EntryPath $child.FullName `
                    -AllowedRoot $AllowedRoot -AllowedPrefix $AllowedPrefix
            }
            [IO.Directory]::Delete($entryFull, $false)
        } else {
            [IO.File]::Delete($entryFull)
        }
    }

    Remove-I07EntryNoReparse -EntryPath $fullPath -AllowedRoot $fullPath `
        -AllowedPrefix $rootPrefix
    return -not (Test-Path -LiteralPath $fullPath)
}

function Get-I07StringSha256 {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value)

    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash(
                    [Text.Encoding]::UTF8.GetBytes($Value)))).
            Replace('-', '').ToLowerInvariant()
    } finally { $sha.Dispose() }
}

function ConvertTo-I07RegistryValueCanonical {
    param([AllowNull()]$Value)

    if ($null -eq $Value) { return 'null' }
    if ($Value -is [byte[]]) {
        return 'bytes:' + ([BitConverter]::ToString($Value)).Replace('-', '')
    }
    if ($Value -is [Array]) {
        return 'array:' + (@($Value | ForEach-Object {
                    ConvertTo-I07RegistryValueCanonical -Value $_
                }) -join '|')
    }
    if ($Value -is [string]) {
        return 'string:' + ([string]$Value).Length.ToString(
            [Globalization.CultureInfo]::InvariantCulture) + ':' +
            [string]$Value
    }
    if ($Value -is [IFormattable]) {
        return $Value.GetType().FullName + ':' +
            ([IFormattable]$Value).ToString(
                $null, [Globalization.CultureInfo]::InvariantCulture)
    }
    throw 'I07_REGISTRY::UNSUPPORTED_VALUE_TYPE'
}

function Get-I07RegistrySubtreeSnapshotOnce {
    param(
        [Parameter(Mandatory = $true)][string]$RelativePath,
        [AllowEmptyString()][string]$TrackedRootValueName = ''
    )

    $root = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey(
        $RelativePath, $false)
    if ($null -eq $root) {
        return [pscustomobject][ordered]@{
            schema = 'ese.v91.i07-registry-subtree/v1'
            path_sha256 = Get-I07StringSha256 -Value $RelativePath
            exists = $false
            node_count = 0
            value_count = 0
            tracked_root_value_count = 0
            canonical_sha256 = Get-I07StringSha256 -Value 'absent'
        }
    }
    $lines = [Collections.Generic.List[string]]::new()
    $state = [pscustomobject]@{ nodes = 0; values = 0 }
    $visit = $null
    $visit = {
        param(
            [Parameter(Mandatory = $true)]
            [Microsoft.Win32.RegistryKey]$Key,
            [Parameter(Mandatory = $true)][string]$LogicalPath
        )
        $state.nodes++
        $lines.Add('K|' + $LogicalPath.ToLowerInvariant())
        $valueNames = @($Key.GetValueNames() | Sort-Object)
        $subkeyNames = @($Key.GetSubKeyNames() | Sort-Object)
        foreach ($valueName in $valueNames) {
            $kind = $Key.GetValueKind([string]$valueName)
            $value = $Key.GetValue(
                [string]$valueName, $null,
                [Microsoft.Win32.RegistryValueOptions]::
                    DoNotExpandEnvironmentNames)
            $canonical = ConvertTo-I07RegistryValueCanonical -Value $value
            $valueAgain = $Key.GetValue(
                [string]$valueName, $null,
                [Microsoft.Win32.RegistryValueOptions]::
                    DoNotExpandEnvironmentNames)
            if ($kind -ne $Key.GetValueKind([string]$valueName) -or
                $canonical -cne
                    (ConvertTo-I07RegistryValueCanonical -Value $valueAgain)) {
                throw 'I07_REGISTRY::UNSTABLE_VALUE'
            }
            $lines.Add(('V|{0}|{1}|{2}' -f
                    ([string]$valueName).ToLowerInvariant(), [string]$kind,
                    (Get-I07StringSha256 -Value $canonical)))
            $state.values++
        }
        foreach ($subkeyName in $subkeyNames) {
            $child = $Key.OpenSubKey([string]$subkeyName, $false)
            if ($null -eq $child) {
                throw 'I07_REGISTRY::UNSTABLE_SUBKEY'
            }
            try {
                & $visit -Key $child `
                    -LogicalPath ($LogicalPath + '\' + [string]$subkeyName)
            } finally { $child.Dispose() }
        }
        if ((@($Key.GetValueNames() | Sort-Object) -join "`n") -cne
                ($valueNames -join "`n") -or
            (@($Key.GetSubKeyNames() | Sort-Object) -join "`n") -cne
                ($subkeyNames -join "`n")) {
            throw 'I07_REGISTRY::UNSTABLE_SUBTREE'
        }
    }
    try {
        $trackedCount = if ([string]::IsNullOrEmpty(
                $TrackedRootValueName)) { 0 } else {
            @($root.GetValueNames() | Where-Object {
                    [string]$_ -ieq $TrackedRootValueName
                }).Count
        }
        & $visit -Key $root -LogicalPath $RelativePath
    } finally { $root.Dispose() }
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.i07-registry-subtree/v1'
        path_sha256 = Get-I07StringSha256 -Value $RelativePath
        exists = $true
        node_count = [int]$state.nodes
        value_count = [int]$state.values
        tracked_root_value_count = [int]$trackedCount
        canonical_sha256 = Get-I07StringSha256 -Value ($lines -join "`n")
    }
}

function Test-I07RegistrySubtreeSnapshotEqual {
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

function Get-I07RegistrySubtreeSnapshot {
    param(
        [Parameter(Mandatory = $true)][string]$RelativePath,
        [AllowEmptyString()][string]$TrackedRootValueName = ''
    )
    $first = Get-I07RegistrySubtreeSnapshotOnce @PSBoundParameters
    $second = Get-I07RegistrySubtreeSnapshotOnce @PSBoundParameters
    if (-not (Test-I07RegistrySubtreeSnapshotEqual `
            -Left $first -Right $second)) {
        throw 'I07_REGISTRY::UNSTABLE_BASELINE'
    }
    return $second
}

function ConvertTo-I07FirewallValueCanonical {
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return 'null' }
    if ($Value -is [Array]) {
        [string[]]$members = @($Value | ForEach-Object {
                ConvertTo-I07FirewallValueCanonical -Value $_
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

function Get-I07FirewallCimCanonical {
    param([Parameter(Mandatory = $true)]$Instance)
    $properties = @($Instance.CimInstanceProperties)
    if ($properties.Count -eq 0) {
        throw 'I07_FIREWALL::EMPTY_CIM_INSTANCE'
    }
    [string[]]$lines = @($properties | Sort-Object Name | ForEach-Object {
            '{0}|{1}|{2}' -f ([string]$_.Name).ToLowerInvariant(),
                [string]$_.CimType,
                (ConvertTo-I07FirewallValueCanonical -Value $_.Value)
        })
    return $lines -join "`n"
}

function Get-I07GlobalFirewallSnapshotOnce {
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
            throw "I07_FIREWALL::EMPTY_$($entry.Key.ToUpperInvariant())"
        }
        [string[]]$records = @($items | ForEach-Object {
                Get-I07FirewallCimCanonical -Instance $_
            })
        [Array]::Sort($records, [StringComparer]::Ordinal)
        $digest = Get-I07StringSha256 -Value (
            $records -join "`n--ITEM--`n")
        $categories[$entry.Key] = [pscustomobject][ordered]@{
            item_count = $items.Count
            canonical_sha256 = $digest
        }
        $aggregate += '{0}|{1}|{2}' -f $entry.Key, $items.Count, $digest
    }
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.i07-global-firewall-snapshot/v1'
        policy_store = 'ActiveStore'
        privacy_safe = $true
        categories = [pscustomobject]$categories
        canonical_sha256 = Get-I07StringSha256 -Value ($aggregate -join "`n")
    }
}

function Get-I07GlobalFirewallSnapshot {
    $first = Get-I07GlobalFirewallSnapshotOnce
    $second = Get-I07GlobalFirewallSnapshotOnce
    if ([string]$first.canonical_sha256 -cne
            [string]$second.canonical_sha256) {
        throw 'I07_FIREWALL::UNSTABLE_GLOBAL_SNAPSHOT'
    }
    return $second
}

function ConvertTo-I07OrdinalValueSet {
    param([AllowNull()]$Value)
    [string[]]$values = @($Value | ForEach-Object {
            ([string]$_).Trim().ToLowerInvariant()
        })
    [Array]::Sort($values, [StringComparer]::Ordinal)
    return $values
}

function Get-I07BoundFirewallRuleSnapshot {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)]
        [ValidateSet('Allow', 'Block')][string]$ExpectedAction,
        [Parameter(Mandatory = $true)]
        [ValidateSet('Inbound', 'Outbound')][string]$ExpectedDirection,
        [Parameter(Mandatory = $true)][string]$ExpectedProtocol,
        [Parameter(Mandatory = $true)][string]$ExpectedLocalPort,
        [string[]]$ExpectedLocalAddress = @('Any'),
        [string[]]$ExpectedRemoteAddress = @('Any'),
        [string]$ExpectedProgram = 'Any',
        [string[]]$ExpectedInterfaceAlias = @('Any')
    )
    $rules = @(Get-NetFirewallRule -Name $Name -PolicyStore ActiveStore `
        -ErrorAction Stop)
    if ($rules.Count -ne 1) {
        throw 'I07_FIREWALL_RULE::RULE_COUNT_NOT_ONE'
    }
    $rule = $rules[0]
    $port = @($rule | Get-NetFirewallPortFilter -ErrorAction Stop)
    $application = @($rule | Get-NetFirewallApplicationFilter `
        -ErrorAction Stop)
    $address = @($rule | Get-NetFirewallAddressFilter -ErrorAction Stop)
    $interface = @($rule | Get-NetFirewallInterfaceFilter `
        -ErrorAction Stop)
    $interfaceType = @($rule | Get-NetFirewallInterfaceTypeFilter `
        -ErrorAction Stop)
    $service = @($rule | Get-NetFirewallServiceFilter -ErrorAction Stop)
    $security = @($rule | Get-NetFirewallSecurityFilter -ErrorAction Stop)
    if ($port.Count -ne 1 -or $application.Count -ne 1 -or
        $address.Count -ne 1 -or $interface.Count -ne 1 -or
        $interfaceType.Count -ne 1 -or $service.Count -ne 1 -or
        $security.Count -ne 1) {
        throw 'I07_FIREWALL_RULE::FILTER_COUNT_NOT_ONE'
    }
    $protocol = ([string]$port[0].Protocol).ToLowerInvariant()
    $protocolExact = if ($ExpectedProtocol -ieq 'TCP') {
        $protocol -in @('tcp', '6')
    } elseif ($ExpectedProtocol -ieq 'UDP') {
        $protocol -in @('udp', '17')
    } else { $protocol -ceq $ExpectedProtocol.ToLowerInvariant() }
    $actualProgram = [string]$application[0].Program
    $programExact = if ($ExpectedProgram -ieq 'Any') {
        $actualProgram -ieq 'Any'
    } else {
        [IO.Path]::GetFullPath($actualProgram) -ieq
            [IO.Path]::GetFullPath($ExpectedProgram)
    }
    $actualLocal = @(ConvertTo-I07OrdinalValueSet `
        -Value @($address[0].LocalAddress))
    $actualRemote = @(ConvertTo-I07OrdinalValueSet `
        -Value @($address[0].RemoteAddress))
    $actualInterfaces = @(ConvertTo-I07OrdinalValueSet `
        -Value @($interface[0].InterfaceAlias))
    $expectedLocal = @(ConvertTo-I07OrdinalValueSet `
        -Value $ExpectedLocalAddress)
    $expectedRemote = @(ConvertTo-I07OrdinalValueSet `
        -Value $ExpectedRemoteAddress)
    $expectedInterfaces = @(ConvertTo-I07OrdinalValueSet `
        -Value $ExpectedInterfaceAlias)
    $exact = [string]$rule.Action -ceq $ExpectedAction -and
        [string]$rule.Direction -ceq $ExpectedDirection -and
        [string]$rule.Enabled -ceq 'True' -and
        [string]$rule.Profile -ceq 'Any' -and $protocolExact -and
        [string]$port[0].LocalPort -ceq $ExpectedLocalPort -and
        [string]$port[0].RemotePort -ceq 'Any' -and $programExact -and
        ($actualLocal -join "`n") -ceq ($expectedLocal -join "`n") -and
        ($actualRemote -join "`n") -ceq ($expectedRemote -join "`n") -and
        ($actualInterfaces -join "`n") -ceq
            ($expectedInterfaces -join "`n") -and
        [string]$interfaceType[0].InterfaceType -ceq 'Any' -and
        [string]$service[0].Service -ceq 'Any'
    if (-not $exact) {
        throw 'I07_FIREWALL_RULE::TUPLE_MISMATCH'
    }
    $canonical = @(
        Get-I07FirewallCimCanonical -Instance $rule
        Get-I07FirewallCimCanonical -Instance $port[0]
        Get-I07FirewallCimCanonical -Instance $application[0]
        Get-I07FirewallCimCanonical -Instance $address[0]
        Get-I07FirewallCimCanonical -Instance $interface[0]
        Get-I07FirewallCimCanonical -Instance $interfaceType[0]
        Get-I07FirewallCimCanonical -Instance $service[0]
        Get-I07FirewallCimCanonical -Instance $security[0]
    )
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.i07-bound-firewall-rule/v1'
        name_sha256 = Get-I07StringSha256 -Value $Name
        tuple_exact = $true
        filter_count = 7
        canonical_sha256 = Get-I07StringSha256 -Value (
            $canonical -join "`n--FILTER--`n")
    }
}

function Remove-I07BoundFirewallRule {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)]$ExpectedSnapshot,
        [Parameter(Mandatory = $true)]$ExpectedTuple
    )
    $current = Get-I07BoundFirewallRuleSnapshot -Name $Name `
        -ExpectedAction ([string]$ExpectedTuple.action) `
        -ExpectedDirection ([string]$ExpectedTuple.direction) `
        -ExpectedProtocol ([string]$ExpectedTuple.protocol) `
        -ExpectedLocalPort ([string]$ExpectedTuple.local_port) `
        -ExpectedLocalAddress @($ExpectedTuple.local_address) `
        -ExpectedRemoteAddress @($ExpectedTuple.remote_address) `
        -ExpectedProgram ([string]$ExpectedTuple.program) `
        -ExpectedInterfaceAlias @($ExpectedTuple.interface_alias)
    if ([string]$current.name_sha256 -cne
            [string]$ExpectedSnapshot.name_sha256 -or
        [string]$current.canonical_sha256 -cne
            [string]$ExpectedSnapshot.canonical_sha256) {
        throw 'I07_FIREWALL_RULE::IDENTITY_CHANGED_BEFORE_REMOVE'
    }
    Remove-NetFirewallRule -Name $Name -PolicyStore ActiveStore `
        -ErrorAction Stop
    if (@(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop |
            Where-Object { [string]$_.Name -ceq $Name }).Count -ne 0) {
        throw 'I07_FIREWALL_RULE::REMOVE_NOT_PROVEN'
    }
    return $true
}

function Get-I07AccountMutationSnapshot {
    param([Parameter(Mandatory = $true)][string]$ExpectedUserSidSha256)

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ($null -eq $identity -or $null -eq $identity.User) {
        throw 'I07_ACCOUNT_GATE::SID_UNAVAILABLE'
    }
    $sidHash = Get-I07StringSha256 -Value ([string]$identity.User.Value)
    if ($ExpectedUserSidSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $sidHash -cne $ExpectedUserSidSha256.ToLowerInvariant()) {
        throw 'I07_ACCOUNT_GATE::SID_MISMATCH'
    }
    $run = Get-I07RegistrySubtreeSnapshot `
        -RelativePath 'Software\Microsoft\Windows\CurrentVersion\Run' `
        -TrackedRootValueName 'eMuleAutoStart'
    $ed2k = Get-I07RegistrySubtreeSnapshot `
        -RelativePath 'Software\Classes\ed2k'
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.i07-account-mutation-snapshot/v1'
        user_sid_sha256 = $sidHash
        run_subtree = $run
        ed2k_subtree = $ed2k
        emule_autostart_absent =
            [int]$run.tracked_root_value_count -eq 0
        ed2k_subtree_absent = -not [bool]$ed2k.exists
    }
}

function Start-I07SystemMutationTransaction {
    param(
        [Parameter(Mandatory = $true)][bool]$DisposableAccountAcknowledged,
        [Parameter(Mandatory = $true)][string]$ExpectedUserSidSha256
    )
    if (-not $DisposableAccountAcknowledged) {
        throw 'I07_ACCOUNT_GATE::DISPOSABLE_ACCOUNT_NOT_ACKNOWLEDGED'
    }
    $registry = Get-I07AccountMutationSnapshot `
        -ExpectedUserSidSha256 $ExpectedUserSidSha256
    if (-not [bool]$registry.emule_autostart_absent -or
        -not [bool]$registry.ed2k_subtree_absent) {
        throw 'I07_ACCOUNT_GATE::INITIAL_REGISTRY_ABSENCE_NOT_PROVEN'
    }
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.i07-system-mutation-transaction/v1'
        expected_user_sid_sha256 = $ExpectedUserSidSha256.ToLowerInvariant()
        disposable_lab_account_attested = $true
        registry_baseline = $registry
        firewall_baseline = Get-I07GlobalFirewallSnapshot
        initial_absence_proved = $true
        destructive_registry_restore_permitted = $false
    }
}

function Complete-I07SystemMutationTransaction {
    param([Parameter(Mandatory = $true)]$Transaction)
    try {
        $registryAfter = Get-I07AccountMutationSnapshot `
            -ExpectedUserSidSha256 (
                [string]$Transaction.expected_user_sid_sha256)
        $firewallAfter = Get-I07GlobalFirewallSnapshot
        $runUnchanged = Test-I07RegistrySubtreeSnapshotEqual `
            -Left $Transaction.registry_baseline.run_subtree `
            -Right $registryAfter.run_subtree
        $ed2kUnchanged = Test-I07RegistrySubtreeSnapshotEqual `
            -Left $Transaction.registry_baseline.ed2k_subtree `
            -Right $registryAfter.ed2k_subtree
        $firewallUnchanged = [string]$Transaction.firewall_baseline.
            canonical_sha256 -ceq [string]$firewallAfter.canonical_sha256
        $complete = $runUnchanged -and $ed2kUnchanged -and
            $firewallUnchanged -and
            [bool]$registryAfter.emule_autostart_absent -and
            [bool]$registryAfter.ed2k_subtree_absent
        return [pscustomobject][ordered]@{
            schema = 'ese.v91.i07-system-mutation-postcheck/v1'
            collector_ok = $true
            complete = $complete
            bound_sid_unchanged = [string]$registryAfter.user_sid_sha256 `
                -ceq [string]$Transaction.expected_user_sid_sha256
            run_subtree_unchanged = $runUnchanged
            emule_autostart_absent =
                [bool]$registryAfter.emule_autostart_absent
            ed2k_subtree_unchanged = $ed2kUnchanged
            ed2k_subtree_absent = [bool]$registryAfter.ed2k_subtree_absent
            global_firewall_unchanged = $firewallUnchanged
            baseline_registry_sha256 = Get-I07StringSha256 -Value (
                [string]$Transaction.registry_baseline.run_subtree.
                    canonical_sha256 + '|' +
                [string]$Transaction.registry_baseline.ed2k_subtree.
                    canonical_sha256)
            post_registry_sha256 = Get-I07StringSha256 -Value (
                [string]$registryAfter.run_subtree.canonical_sha256 + '|' +
                [string]$registryAfter.ed2k_subtree.canonical_sha256)
            baseline_firewall_sha256 =
                [string]$Transaction.firewall_baseline.canonical_sha256
            post_firewall_sha256 = [string]$firewallAfter.canonical_sha256
        }
    } catch {
        return [pscustomobject][ordered]@{
            schema = 'ese.v91.i07-system-mutation-postcheck/v1'
            collector_ok = $false
            complete = $false
            bound_sid_unchanged = $false
            run_subtree_unchanged = $false
            emule_autostart_absent = $false
            ed2k_subtree_unchanged = $false
            ed2k_subtree_absent = $false
            global_firewall_unchanged = $false
            baseline_registry_sha256 = ''
            post_registry_sha256 = ''
            baseline_firewall_sha256 = ''
            post_firewall_sha256 = ''
        }
    }
}

function Assert-I07NormalPathChain {
    param([Parameter(Mandatory = $true)][string]$Path)

    $current = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    while (-not [string]::IsNullOrWhiteSpace($current)) {
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
            if (($item.Attributes -band
                    [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'I07_PACKAGE_BINDING::REPARSE_ANCESTOR'
            }
        }
        $parent = [IO.Path]::GetDirectoryName($current)
        if ([string]::IsNullOrWhiteSpace($parent) -or
            $parent -ceq $current) { break }
        $current = $parent.TrimEnd('\')
    }
}

function ConvertTo-I07SafePackagePath {
    param([Parameter(Mandatory = $true)][string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value) -or
        $Value.IndexOf([char]0) -ge 0 -or $Value.Contains('\') -or
        $Value.StartsWith('/') -or $Value -match '^[A-Za-z]:' -or
        [IO.Path]::IsPathRooted($Value)) {
        throw 'I07_PACKAGE_BINDING::UNSAFE_RELATIVE_PATH'
    }
    $normalized = $Value.Normalize([Text.NormalizationForm]::FormC)
    if (-not [string]::Equals(
            $normalized, $Value, [StringComparison]::Ordinal)) {
        throw 'I07_PACKAGE_BINDING::NONCANONICAL_UNICODE_PATH'
    }
    $segments = @($normalized.Split('/'))
    if ($segments.Count -eq 0) {
        throw 'I07_PACKAGE_BINDING::UNSAFE_RELATIVE_PATH'
    }
    foreach ($segment in $segments) {
        if ([string]::IsNullOrWhiteSpace($segment) -or
            $segment -cin @('.', '..') -or $segment.Contains(':') -or
            $segment.EndsWith('.') -or $segment.EndsWith(' ') -or
            $segment -match
                '^(?i:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)') {
            throw 'I07_PACKAGE_BINDING::UNSAFE_RELATIVE_PATH'
        }
    }
    return $normalized
}

function Get-I07PackageManifestSha256 {
    param([Parameter(Mandatory = $true)][object[]]$Files)

    $builder = [Text.StringBuilder]::new()
    foreach ($file in @($Files | Sort-Object path)) {
        $null = $builder.Append([string]$file.path)
        $null = $builder.Append([char]0)
        $null = $builder.Append(([Int64]$file.bytes).ToString(
                [Globalization.CultureInfo]::InvariantCulture))
        $null = $builder.Append([char]0)
        $null = $builder.Append(([string]$file.sha256).ToLowerInvariant())
        $null = $builder.Append("`n")
    }
    return Get-I07StringSha256 -Value $builder.ToString()
}

function Assert-I07CriticalPackageContract {
    param([Parameter(Mandatory = $true)]$Files)

    # Kept under its historical name because this contract is serialized in
    # already deployed agents. It now covers the complete package, while also
    # requiring the seven production-critical leaves.
    $required = @(
        'BUILD_INFO.txt', 'emule.exe', 'eMule.tmpl', 'ese-server.exe',
        'ffmpeg.exe', 'ffprobe.exe', 'SHA256SUMS.txt'
    )
    $items = @($Files)
    if ($items.Count -lt $required.Count) {
        throw 'I07_PACKAGE_BINDING::PACKAGE_FILE_SET_INCOMPLETE'
    }
    $seen = [Collections.Generic.Dictionary[string,object]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    foreach ($item in $items) {
        if (-not (Test-I07ExactPropertySet -Value $item -Expected @(
                    'path', 'bytes', 'sha256')) -or
            -not (Test-I07StrictString -Value $item.path) -or
            -not (Test-I07StrictInteger -Value $item.bytes -Minimum 0) -or
            -not (Test-I07StrictString -Value $item.sha256) -or
            [string]$item.sha256 -cnotmatch '^[0-9a-f]{64}$') {
            throw 'I07_PACKAGE_BINDING::MALFORMED_PACKAGE_ENTRY'
        }
        $relative = ConvertTo-I07SafePackagePath -Value ([string]$item.path)
        if ([string]::Equals(
                $relative, 'config/preferences.ini',
                [StringComparison]::OrdinalIgnoreCase)) {
            throw 'I07_PACKAGE_BINDING::RUNTIME_PREFERENCES_MUST_NOT_BE_PACKAGED'
        }
        if ($seen.ContainsKey($relative)) {
            throw 'I07_PACKAGE_BINDING::PACKAGE_CASE_OR_UNICODE_COLLISION'
        }
        $seen.Add($relative, $item)
    }
    foreach ($name in $required) {
        if (-not $seen.ContainsKey($name) -or
            [Int64]$seen[$name].bytes -le 0) {
            throw 'I07_PACKAGE_BINDING::CRITICAL_FILE_MISSING_OR_EMPTY'
        }
    }
    return @($items | Sort-Object path)
}

function Get-I07HeldFileContract {
    param([Parameter(Mandatory = $true)][string]$Path)

    $fullPath = [IO.Path]::GetFullPath($Path)
    Assert-I07NormalPathChain -Path $fullPath
    $item = Get-Item -LiteralPath $fullPath -Force -ErrorAction Stop
    if ($item.PSIsContainer) {
        throw 'I07_PACKAGE_BINDING::EXPECTED_NORMAL_FILE'
    }
    $stream = [IO.FileStream]::new(
        $fullPath, [IO.FileMode]::Open, [IO.FileAccess]::Read,
        [IO.FileShare]::Read)
    try {
        $sha = [Security.Cryptography.SHA256]::Create()
        try {
            $digest = ([BitConverter]::ToString(
                    $sha.ComputeHash($stream))).Replace('-', '').
                ToLowerInvariant()
        } finally { $sha.Dispose() }
        return [pscustomobject][ordered]@{
            path = $fullPath
            bytes = [Int64]$stream.Length
            sha256 = $digest
        }
    } finally { $stream.Dispose() }
}

function Get-I07PackageIdentity {
    param([Parameter(Mandatory = $true)][string]$PackagePath)

    $root = [IO.Path]::GetFullPath($PackagePath).TrimEnd('\')
    Assert-I07NormalPathChain -Path $root
    $rootItem = Get-Item -LiteralPath $root -Force -ErrorAction Stop
    if (-not $rootItem.PSIsContainer) {
        throw 'I07_PACKAGE_BINDING::PACKAGE_ROOT_INVALID'
    }
    $prefix = $root + '\'
    $pending = [Collections.Generic.Stack[string]]::new()
    $pending.Push($root)
    $files = [Collections.Generic.List[object]]::new()
    $directories = [Collections.Generic.List[string]]::new()
    while ($pending.Count -gt 0) {
        $directory = $pending.Pop()
        foreach ($item in @(Get-ChildItem -LiteralPath $directory -Force `
                -ErrorAction Stop)) {
            $full = [IO.Path]::GetFullPath([string]$item.FullName)
            if (-not $full.StartsWith(
                    $prefix, [StringComparison]::OrdinalIgnoreCase) -or
                ($item.Attributes -band
                    [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'I07_PACKAGE_BINDING::PACKAGE_REPARSE_OR_ESCAPE'
            }
            if ($item.PSIsContainer) {
                $directories.Add((ConvertTo-I07SafePackagePath -Value (
                            $full.Substring($root.Length).TrimStart('\').
                                Replace('\', '/'))))
                $pending.Push($full)
                continue
            }
            $relative = ConvertTo-I07SafePackagePath -Value (
                $full.Substring($root.Length).TrimStart('\').Replace('\', '/'))
            $held = Get-I07HeldFileContract -Path $full
            $files.Add([pscustomobject][ordered]@{
                path = $relative
                bytes = [Int64]$held.bytes
                sha256 = [string]$held.sha256
            })
        }
    }
    $contract = @(Assert-I07CriticalPackageContract -Files $files.ToArray())
    $allowedDirectories =
        [Collections.Generic.Dictionary[string,string]]::new(
            [StringComparer]::OrdinalIgnoreCase)
    foreach ($file in $contract) {
        $segments = @(([string]$file.path).Split('/'))
        for ($index = 1; $index -lt $segments.Count; $index++) {
            $directory = ($segments[0..($index - 1)] -join '/')
            if ($allowedDirectories.ContainsKey($directory)) {
                if (-not [string]::Equals(
                        $allowedDirectories[$directory], $directory,
                        [StringComparison]::Ordinal)) {
                    throw 'I07_PACKAGE_BINDING::DIRECTORY_CASE_COLLISION'
                }
            } else { $allowedDirectories.Add($directory, $directory) }
        }
    }
    if ($directories.Count -ne $allowedDirectories.Count) {
        throw 'I07_PACKAGE_BINDING::UNBOUND_OR_MISSING_DIRECTORY'
    }
    $seenDirectories =
        [Collections.Generic.Dictionary[string,string]]::new(
            [StringComparer]::OrdinalIgnoreCase)
    foreach ($directory in $directories) {
        if (-not $allowedDirectories.ContainsKey($directory) -or
            -not [string]::Equals(
                $allowedDirectories[$directory], $directory,
                [StringComparison]::Ordinal) -or
            $seenDirectories.ContainsKey($directory)) {
            throw 'I07_PACKAGE_BINDING::UNBOUND_OR_DUPLICATE_DIRECTORY'
        }
        $seenDirectories.Add($directory, $directory)
    }
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.i07-extracted-package-manifest/v2'
        file_count = $contract.Count
        total_bytes = [Int64](($contract | Measure-Object bytes -Sum).Sum)
        manifest_sha256 = Get-I07PackageManifestSha256 -Files $contract
        files = $contract
    }
}

function Get-I07CriticalZipEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$ZipPath,
        [Parameter(Mandatory = $true)]$ExpectedFiles,
        [Parameter(Mandatory = $true)][string]$ExpectedZipSha256,
        [Parameter(Mandatory = $true)][Int64]$ExpectedZipBytes
    )

    $files = @(Assert-I07CriticalPackageContract -Files $ExpectedFiles)
    $fullPath = [IO.Path]::GetFullPath($ZipPath)
    Assert-I07NormalPathChain -Path $fullPath
    if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
        throw 'I07_PACKAGE_BINDING::MISSING_ZIP'
    }
    $zipItem = Get-Item -LiteralPath $fullPath -Force -ErrorAction Stop
    if (($zipItem.Attributes -band
            [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'I07_PACKAGE_BINDING::ZIP_REPARSE_POINT'
    }
    if ($ExpectedZipSha256 -cnotmatch '^[0-9a-f]{64}$' -or
        $ExpectedZipBytes -le 0) {
        throw 'I07_PACKAGE_BINDING::MALFORMED_ZIP_IDENTITY'
    }

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zipStream = [IO.FileStream]::new(
        $fullPath, [IO.FileMode]::Open, [IO.FileAccess]::Read,
        [IO.FileShare]::Read)
    try {
        $sha256 = [Security.Cryptography.SHA256]::Create()
        try {
            $zipSha = ([BitConverter]::ToString(
                    $sha256.ComputeHash($zipStream))).Replace('-', '').
                ToLowerInvariant()
        } finally { $sha256.Dispose() }
        if ($zipSha -cne $ExpectedZipSha256.ToLowerInvariant() -or
            [Int64]$zipStream.Length -ne $ExpectedZipBytes) {
            throw 'I07_PACKAGE_BINDING::ZIP_IDENTITY_MISMATCH'
        }
        $zipStream.Position = 0
        $archive = [IO.Compression.ZipArchive]::new(
            $zipStream, [IO.Compression.ZipArchiveMode]::Read, $true)
        try {
            $packageByPath =
                [Collections.Generic.Dictionary[string,object]]::new(
                    [StringComparer]::OrdinalIgnoreCase)
            foreach ($file in $files) {
                $packageByPath.Add([string]$file.path, $file)
            }
            $allowedDirectories =
                [Collections.Generic.Dictionary[string,string]]::new(
                    [StringComparer]::OrdinalIgnoreCase)
            foreach ($file in $files) {
                $segments = @(([string]$file.path).Split('/'))
                for ($index = 1; $index -lt $segments.Count; $index++) {
                    $directory = ($segments[0..($index - 1)] -join '/')
                    if ($allowedDirectories.ContainsKey($directory)) {
                        if (-not [string]::Equals(
                                $allowedDirectories[$directory], $directory,
                                [StringComparison]::Ordinal)) {
                            throw 'I07_PACKAGE_BINDING::DIRECTORY_CASE_COLLISION'
                        }
                    } else { $allowedDirectories.Add($directory, $directory) }
                }
            }
            $fileEntries = @($archive.Entries | Where-Object {
                    -not [string]::IsNullOrEmpty([string]$_.Name)
                })
            $markers = @($fileEntries | Where-Object {
                    $name = ([string]$_.FullName).Replace('\', '/')
                    ($name -ceq 'BUILD_INFO.txt' -or
                        $name.EndsWith('/BUILD_INFO.txt',
                            [StringComparison]::Ordinal))
                })
            if ($markers.Count -ne 1) {
                throw 'I07_PACKAGE_BINDING::AMBIGUOUS_ARCHIVE_ROOT'
            }
            $marker = ([string]$markers[0].FullName).Replace('\', '/')
            $rootPrefix = $marker.Substring(
                0, $marker.Length - 'BUILD_INFO.txt'.Length)
            if ($rootPrefix -ne '') {
                $rootName = $rootPrefix.TrimEnd('/')
                if ($rootName.Contains('/') -or
                    (ConvertTo-I07SafePackagePath -Value $rootName) -cne
                        $rootName) {
                    throw 'I07_PACKAGE_BINDING::UNSAFE_ARCHIVE_ROOT'
                }
            }
            $zipByPath =
                [Collections.Generic.Dictionary[string,object]]::new(
                    [StringComparer]::OrdinalIgnoreCase)
            $zipDirectoryByPath =
                [Collections.Generic.Dictionary[string,string]]::new(
                    [StringComparer]::OrdinalIgnoreCase)
            foreach ($entry in @($archive.Entries)) {
                $rawEntryName = [string]$entry.FullName
                if ($rawEntryName.Contains('\') -and
                    $rawEntryName.Contains('/')) {
                    throw 'I07_PACKAGE_BINDING::MIXED_ZIP_SEPARATORS'
                }
                $entryName = $rawEntryName.Replace('\', '/')
                if ([string]::IsNullOrWhiteSpace($entryName) -or
                    $entryName.StartsWith('/') -or
                    $entryName -match '^[A-Za-z]:' -or
                    $entryName.IndexOf([char]0) -ge 0) {
                    throw 'I07_PACKAGE_BINDING::UNSAFE_ZIP_ENTRY'
                }
                $external = [BitConverter]::ToUInt32(
                    [BitConverter]::GetBytes(
                        [int]$entry.ExternalAttributes), 0)
                $unixType = ($external -shr 16) -band 0xf000
                $dosAttributes = $external -band 0xffff
                if ($unixType -eq 0xa000 -or
                    ($dosAttributes -band 0x0400) -ne 0) {
                    throw 'I07_PACKAGE_BINDING::LINK_OR_REPARSE_ENTRY'
                }
                if ([string]::IsNullOrEmpty([string]$entry.Name)) {
                    if (-not $entryName.EndsWith('/')) {
                        throw 'I07_PACKAGE_BINDING::MALFORMED_DIRECTORY_ENTRY'
                    }
                    if ($rootPrefix -ne '' -and
                        [string]::Equals($entryName, $rootPrefix,
                            [StringComparison]::Ordinal)) {
                        continue
                    }
                    if (-not $entryName.StartsWith(
                            $rootPrefix, [StringComparison]::Ordinal) -or
                        $entryName.Length -le $rootPrefix.Length) {
                        throw 'I07_PACKAGE_BINDING::MULTIPLE_OR_ESCAPING_ROOTS'
                    }
                    $relativeDirectory = ConvertTo-I07SafePackagePath -Value (
                        $entryName.Substring($rootPrefix.Length).TrimEnd('/'))
                    if (-not $allowedDirectories.ContainsKey(
                            $relativeDirectory) -or
                        -not [string]::Equals(
                            $allowedDirectories[$relativeDirectory],
                            $relativeDirectory, [StringComparison]::Ordinal) -or
                        $zipDirectoryByPath.ContainsKey($relativeDirectory)) {
                        throw 'I07_PACKAGE_BINDING::UNBOUND_OR_DUPLICATE_DIRECTORY'
                    }
                    $zipDirectoryByPath.Add(
                        $relativeDirectory, $relativeDirectory)
                    continue
                }
                if (-not $entryName.StartsWith(
                        $rootPrefix, [StringComparison]::Ordinal) -or
                    $entryName.Length -le $rootPrefix.Length) {
                    throw 'I07_PACKAGE_BINDING::MULTIPLE_OR_ESCAPING_ROOTS'
                }
                $relative = ConvertTo-I07SafePackagePath -Value (
                    $entryName.Substring($rootPrefix.Length))
                if ($zipByPath.ContainsKey($relative)) {
                    throw 'I07_PACKAGE_BINDING::ZIP_CASE_OR_UNICODE_COLLISION'
                }
                $entryStream = $entry.Open()
                $entryShaObject = [Security.Cryptography.SHA256]::Create()
                try {
                    $entrySha = ([BitConverter]::ToString(
                            $entryShaObject.ComputeHash($entryStream))).
                        Replace('-', '').ToLowerInvariant()
                } finally {
                    $entryShaObject.Dispose()
                    $entryStream.Dispose()
                }
                $zipByPath.Add($relative, [pscustomobject][ordered]@{
                    path = $relative
                    bytes = [Int64]$entry.Length
                    sha256 = $entrySha
                })
            }
            if ($zipByPath.Count -ne $packageByPath.Count) {
                throw 'I07_PACKAGE_BINDING::FILE_SET_MISMATCH'
            }
            foreach ($relative in @($packageByPath.Keys)) {
                if (-not $zipByPath.ContainsKey($relative)) {
                    throw 'I07_PACKAGE_BINDING::FILE_SET_MISMATCH'
                }
                $expected = $packageByPath[$relative]
                $actual = $zipByPath[$relative]
                if ([string]$actual.path -cne [string]$expected.path -or
                    [Int64]$actual.bytes -ne [Int64]$expected.bytes -or
                    [string]$actual.sha256 -cne [string]$expected.sha256) {
                    throw 'I07_PACKAGE_BINDING::ENTRY_MISMATCH'
                }
            }
            $boundFiles = @($zipByPath.Values | Sort-Object path)
            if ((Get-I07PackageManifestSha256 -Files $boundFiles) -cne
                    (Get-I07PackageManifestSha256 -Files $files)) {
                throw 'I07_PACKAGE_BINDING::MANIFEST_MISMATCH'
            }
            return [pscustomobject][ordered]@{
                schema = 'ese.v91.i07-node-zip-binding/v2'
                verified = $true
                zip_sha256 = $zipSha
                zip_bytes = [Int64]$zipStream.Length
                critical_file_count = $boundFiles.Count
                critical_files = $boundFiles
            }
        } finally { $archive.Dispose() }
    } finally { $zipStream.Dispose() }
}

function ConvertTo-I07CanonicalIPv6 {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [string]$Context = 'address'
    )

    $parsed = $null
    $withoutScope = $Value.Split('%')[0]
    if (-not [Net.IPAddress]::TryParse($withoutScope, [ref]$parsed) -or
        $parsed.AddressFamily -ne
            [Net.Sockets.AddressFamily]::InterNetworkV6 -or
        $parsed.IsIPv4MappedToIPv6) {
        throw "$Context is not a native IPv6 address: '$Value'."
    }
    return $parsed.ToString().ToLowerInvariant()
}

function Test-I07IPv6Prefix {
    param(
        [Parameter(Mandatory = $true)][Net.IPAddress]$Address,
        [Parameter(Mandatory = $true)][string]$Network,
        [ValidateRange(0, 128)][int]$PrefixLength
    )

    $networkAddress = [Net.IPAddress]::Parse($Network)
    $addressBytes = $Address.GetAddressBytes()
    $networkBytes = $networkAddress.GetAddressBytes()
    $wholeBytes = [Math]::Floor($PrefixLength / 8)
    for ($i = 0; $i -lt $wholeBytes; ++$i) {
        if ($addressBytes[$i] -ne $networkBytes[$i]) { return $false }
    }
    $remainingBits = $PrefixLength % 8
    if ($remainingBits -eq 0) { return $true }
    $mask = [byte](0xff -band (0xff -shl (8 - $remainingBits)))
    return (($addressBytes[$wholeBytes] -band $mask) -eq
        ($networkBytes[$wholeBytes] -band $mask))
}

function Get-I07IPv6Class {
    param([Parameter(Mandatory = $true)][Net.IPAddress]$Address)

    if ($Address.AddressFamily -ne
        [Net.Sockets.AddressFamily]::InterNetworkV6) {
        return 'not-ipv6'
    }
    if ($Address.IsIPv4MappedToIPv6) { return 'ipv4-mapped' }
    if ($Address.Equals([Net.IPAddress]::IPv6Any)) { return 'unspecified' }
    if ($Address.Equals([Net.IPAddress]::IPv6Loopback)) { return 'loopback' }
    if ($Address.IsIPv6Multicast) { return 'multicast' }
    if ($Address.IsIPv6LinkLocal) { return 'link-local' }
    if (Test-I07IPv6Prefix -Address $Address -Network 'fc00::' `
            -PrefixLength 7) { return 'ula' }
    if (Test-I07IPv6Prefix -Address $Address -Network '64:ff9b::' `
            -PrefixLength 96) { return 'nat64-well-known' }
    if (Test-I07IPv6Prefix -Address $Address -Network '64:ff9b:1::' `
            -PrefixLength 48) { return 'nat64-local-use' }
    if (Test-I07IPv6Prefix -Address $Address -Network '2001::' `
            -PrefixLength 32) { return 'teredo' }
    if (Test-I07IPv6Prefix -Address $Address -Network '2002::' `
            -PrefixLength 16) { return '6to4' }
    if (Test-I07IPv6Prefix -Address $Address -Network '2001:2::' `
            -PrefixLength 48) { return 'benchmark' }
    if (Test-I07IPv6Prefix -Address $Address -Network '2001:db8::' `
            -PrefixLength 32) { return 'documentation' }
    if (Test-I07IPv6Prefix -Address $Address -Network '3fff::' `
            -PrefixLength 20) { return 'documentation' }
    if (Test-I07IPv6Prefix -Address $Address -Network '2001:10::' `
            -PrefixLength 28) { return 'orchid' }
    if (Test-I07IPv6Prefix -Address $Address -Network '2001:20::' `
            -PrefixLength 28) { return 'orchidv2' }
    if (Test-I07IPv6Prefix -Address $Address -Network '2001::' `
            -PrefixLength 23) { return 'special-purpose' }
    if (Test-I07IPv6Prefix -Address $Address -Network '2620:4f:8000::' `
            -PrefixLength 48) { return 'as112-direct-delegation' }
    if (-not (Test-I07IPv6Prefix -Address $Address -Network '2000::' `
                -PrefixLength 3)) { return 'non-global' }
    return 'global-native'
}

function Test-I07OverlayAdapter {
    param([Parameter(Mandatory = $true)]$Adapter)

    $text = @(
        [string]$Adapter.Name,
        [string]$Adapter.InterfaceAlias,
        [string]$Adapter.InterfaceDescription
    ) -join ' '
    return $text -match $script:I07OverlayPattern
}

function Get-I07NetworkProfileEvidence {
    param([Parameter(Mandatory = $true)][int]$InterfaceIndex)

    $profiles = @(Get-NetConnectionProfile -InterfaceIndex $InterfaceIndex `
        -ErrorAction Stop)
    $adapters = @(Get-NetAdapter -InterfaceIndex $InterfaceIndex `
        -IncludeHidden -ErrorAction Stop)
    if ($profiles.Count -ne 1 -or $adapters.Count -ne 1) {
        throw 'Expected exactly one NLA profile and adapter for the interface.'
    }
    $profile = $profiles[0]
    $adapter = $adapters[0]
    $guid = [string](Get-I07PropertyValue -Object $adapter `
        -Name 'InterfaceGuid' -Default '')
    # Shared R01 -> I07 contract: SHA-256 over the UTF-8 profile name only.
    # The clear profile/SSID is never persisted by this harness.
    $canonical = [string]$profile.Name
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $hash = ([BitConverter]::ToString(
            $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($canonical))
        )).Replace('-', '').ToLowerInvariant()
    } finally { $sha.Dispose() }
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.r01-hotspot-profile-fingerprint/v1'
        interface_index = $InterfaceIndex
        interface_guid = $guid
        profile_sha256 = $hash
        network_category = [string]$profile.NetworkCategory
        ipv4_connectivity = [string]$profile.IPv4Connectivity
        ipv6_connectivity = [string]$profile.IPv6Connectivity
        # The profile/SSID name is deliberately represented only inside the
        # fingerprint and is never written to campaign evidence.
    }
}

function Get-I07CurrentWlanProfileEvidence {
    param([Parameter(Mandatory = $true)][int]$InterfaceIndex)

    $adapters = @(Get-NetAdapter -InterfaceIndex $InterfaceIndex `
        -IncludeHidden -ErrorAction Stop)
    if ($adapters.Count -ne 1) {
        throw 'Expected exactly one adapter for current WLAN evidence.'
    }
    $adapter = $adapters[0]
    $alias = [string]$adapter.Name
    $guid = ([string](Get-I07PropertyValue -Object $adapter `
        -Name 'InterfaceGuid' -Default '')).Trim('{}').ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($alias) -or
        $guid -notmatch '^[0-9a-f-]{36}$') {
        throw 'Current WLAN adapter identity is incomplete.'
    }
    $lines = @(& netsh.exe wlan show interfaces 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not inspect the current WLAN profile.'
    }
    $currentAlias = ''
    $matches = [Collections.Generic.List[string]]::new()
    foreach ($line in $lines) {
        $text = [string]$line
        $nameMatch = [regex]::Match(
            $text, '(?i)^\s*(?:name|nombre)\s*:\s*(.+?)\s*$')
        if ($nameMatch.Success) {
            $currentAlias = $nameMatch.Groups[1].Value.Trim()
            continue
        }
        $profileMatch = [regex]::Match(
            $text, '(?i)^\s*(?:profile|perfil)\s*:\s*(.+?)\s*$')
        if ($profileMatch.Success -and $currentAlias -ieq $alias) {
            $matches.Add($profileMatch.Groups[1].Value.Trim())
        }
    }
    $unique = @($matches | Where-Object {
            -not [string]::IsNullOrWhiteSpace($_)
        } | Select-Object -Unique)
    if ($unique.Count -ne 1) {
        throw 'Current WLAN profile was not uniquely observed on the adapter.'
    }
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $hash = ([BitConverter]::ToString($sha.ComputeHash(
            [Text.Encoding]::UTF8.GetBytes([string]$unique[0])
        ))).Replace('-', '').ToLowerInvariant()
    } finally { $sha.Dispose() }
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.i07-current-wlan-profile/v1'
        interface_index = $InterfaceIndex
        interface_guid = $guid
        wlan_profile_sha256 = $hash
    }
}

function Get-I07PropertyValue {
    param(
        [AllowNull()]$Object,
        [Parameter(Mandatory = $true)][string]$Name,
        $Default = $null
    )

    if ($null -eq $Object) { return $Default }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $Default }
    return $property.Value
}

function Test-I07PortContract {
    param([Parameter(Mandatory = $true)][int[]]$Ports)

    return ($Ports.Count -gt 0 -and
        @($Ports | Where-Object { $_ -lt 1024 -or $_ -gt 65535 }).Count `
            -eq 0 -and
        @($Ports | Select-Object -Unique).Count -eq $Ports.Count)
}

function Get-I07NativeRouteEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$RemoteIPv6,
        [int]$ExpectedInterfaceIndex = 0,
        [string]$ExpectedSourceIPv6 = '',
        [string]$ExpectedInterfaceGuid = ''
    )

    $remote = ConvertTo-I07CanonicalIPv6 -Value $RemoteIPv6 `
        -Context 'RemoteIPv6'
    $remoteAddress = [Net.IPAddress]::Parse($remote)
    $remoteClass = Get-I07IPv6Class -Address $remoteAddress
    $base = [ordered]@{
        captured_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
        valid = $false
        reason = ''
        remote_address = $remote
        remote_class = $remoteClass
        source_address = $null
        source_class = $null
        interface_index = $null
        interface_alias = $null
        interface_guid = $null
        interface_description = $null
        media_type = $null
        physical_media_type = $null
        hardware_interface = $null
        virtual = $null
        destination_prefix = $null
        next_hop = $null
        route_metric = $null
        interface_metric = $null
        address_state = $null
        prefix_origin = $null
        suffix_origin = $null
        default_route_present = $false
        overlay = $null
    }
    if ($remoteClass -cne 'global-native') {
        $base.reason = "remote_$remoteClass"
        return [pscustomobject]$base
    }

    try {
        $objects = @(Find-NetRoute -RemoteIPAddress $remote -ErrorAction Stop)
        $route = @($objects | Where-Object {
                $null -ne $_.PSObject.Properties['DestinationPrefix'] -and
                -not [string]::IsNullOrWhiteSpace(
                    [string]$_.DestinationPrefix)
            }) | Select-Object -First 1
        $sourceRow = @($objects | Where-Object {
                $null -ne $_.PSObject.Properties['IPAddress'] -and
                -not [string]::IsNullOrWhiteSpace([string]$_.IPAddress)
            }) | Select-Object -First 1
        if ($null -eq $route -or $null -eq $sourceRow) {
            throw 'Find-NetRoute returned no route/source pair.'
        }

        $interfaceIndex = [int]$route.InterfaceIndex
        $source = ConvertTo-I07CanonicalIPv6 `
            -Value ([string]$sourceRow.IPAddress) -Context 'selected source'
        $sourceAddress = [Net.IPAddress]::Parse($source)
        $sourceClass = Get-I07IPv6Class -Address $sourceAddress
        $adapter = Get-NetAdapter -InterfaceIndex $interfaceIndex `
            -IncludeHidden -ErrorAction Stop
        $addressRows = @(Get-NetIPAddress -InterfaceIndex $interfaceIndex `
            -AddressFamily IPv6 -ErrorAction Stop | Where-Object {
                try {
                    (ConvertTo-I07CanonicalIPv6 -Value ([string]$_.IPAddress)) `
                        -ceq $source
                } catch { $false }
            })
        $addressRow = $addressRows | Select-Object -First 1
        $defaultRoutes = @(Get-NetRoute -InterfaceIndex $interfaceIndex `
            -AddressFamily IPv6 -DestinationPrefix '::/0' `
            -ErrorAction Stop | Where-Object {
                [string]$_.State -notin @('Invalid', 'Unreachable')
            })

        $hardware = [bool](Get-I07PropertyValue -Object $adapter `
            -Name 'HardwareInterface' -Default $false)
        $virtual = [bool](Get-I07PropertyValue -Object $adapter `
            -Name 'Virtual' -Default (-not $hardware))
        $guid = [string](Get-I07PropertyValue -Object $adapter `
            -Name 'InterfaceGuid' -Default '')
        $alias = [string](Get-I07PropertyValue -Object $adapter `
            -Name 'InterfaceAlias' -Default (
                Get-I07PropertyValue -Object $adapter -Name 'Name' -Default ''))
        $description = [string](Get-I07PropertyValue -Object $adapter `
            -Name 'InterfaceDescription' -Default '')
        $overlay = Test-I07OverlayAdapter -Adapter $adapter

        $base.source_address = $source
        $base.source_class = $sourceClass
        $base.interface_index = $interfaceIndex
        $base.interface_alias = $alias
        $base.interface_guid = $guid
        $base.interface_description = $description
        $base.media_type = [string](Get-I07PropertyValue -Object $adapter `
            -Name 'MediaType' -Default '')
        $base.physical_media_type = [string](Get-I07PropertyValue `
            -Object $adapter -Name 'PhysicalMediaType' -Default '')
        $base.hardware_interface = $hardware
        $base.virtual = $virtual
        $base.destination_prefix = [string]$route.DestinationPrefix
        $base.next_hop = [string]$route.NextHop
        $base.route_metric = [int](Get-I07PropertyValue -Object $route `
            -Name 'RouteMetric' -Default 0)
        $base.interface_metric = [int](Get-I07PropertyValue -Object $route `
            -Name 'InterfaceMetric' -Default 0)
        $base.address_state = [string](Get-I07PropertyValue `
            -Object $addressRow -Name 'AddressState' -Default '')
        $base.prefix_origin = [string](Get-I07PropertyValue `
            -Object $addressRow -Name 'PrefixOrigin' -Default '')
        $base.suffix_origin = [string](Get-I07PropertyValue `
            -Object $addressRow -Name 'SuffixOrigin' -Default '')
        $base.default_route_present = $defaultRoutes.Count -gt 0
        $base.overlay = $overlay

        if ($sourceClass -cne 'global-native') {
            $base.reason = "selected_source_$sourceClass"
        } elseif ($addressRows.Count -ne 1) {
            $base.reason = 'selected_source_not_uniquely_assigned'
        } elseif ([string]$base.address_state -cne 'Preferred') {
            $base.reason = 'selected_source_not_preferred'
        } elseif (-not $hardware -or $virtual -or $overlay) {
            $base.reason = 'selected_interface_not_native_physical'
        } elseif ([string]$adapter.Status -cne 'Up') {
            $base.reason = 'selected_interface_not_up'
        } elseif ($defaultRoutes.Count -lt 1) {
            $base.reason = 'no_default_route_on_selected_interface'
        } elseif ($ExpectedInterfaceIndex -gt 0 -and
            $interfaceIndex -ne $ExpectedInterfaceIndex) {
            $base.reason = 'selected_interface_changed'
        } elseif (-not [string]::IsNullOrWhiteSpace($ExpectedSourceIPv6) -and
            $source -cne (ConvertTo-I07CanonicalIPv6 `
                -Value $ExpectedSourceIPv6 -Context 'ExpectedSourceIPv6')) {
            $base.reason = 'selected_source_changed'
        } elseif (-not [string]::IsNullOrWhiteSpace($ExpectedInterfaceGuid) -and
            $guid.Trim('{}').ToLowerInvariant() -cne
                $ExpectedInterfaceGuid.Trim('{}').ToLowerInvariant()) {
            $base.reason = 'selected_interface_guid_changed'
        } else {
            $base.valid = $true
            $base.reason = 'native_global_route_selected'
        }
    } catch {
        $base.reason = 'route_inspection_error'
    }
    return [pscustomobject]$base
}

function Set-I07IniValue {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Section,
        [Parameter(Mandatory = $true)][string]$Key,
        [AllowEmptyString()][string]$Value
    )

    $lines = [Collections.Generic.List[string]]::new()
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        foreach ($line in Get-Content -LiteralPath $Path) {
            $lines.Add([string]$line)
        }
    }
    $sectionStart = -1
    $sectionEnd = $lines.Count
    for ($i = 0; $i -lt $lines.Count; ++$i) {
        if ($lines[$i] -match '^\s*\[(.+)\]\s*$') {
            if ($sectionStart -ge 0) {
                $sectionEnd = $i
                break
            }
            if ($Matches[1] -ieq $Section) { $sectionStart = $i }
        }
    }
    if ($sectionStart -lt 0) {
        if ($lines.Count -gt 0 -and $lines[$lines.Count - 1] -ne '') {
            $lines.Add('')
        }
        $lines.Add("[$Section]")
        $lines.Add("$Key=$Value")
    } else {
        $found = $false
        for ($i = $sectionStart + 1; $i -lt $sectionEnd; ++$i) {
            if ($lines[$i] -match
                ('^\s*' + [regex]::Escape($Key) + '\s*=')) {
                $lines[$i] = "$Key=$Value"
                $found = $true
                break
            }
        }
        if (-not $found) { $lines.Insert($sectionEnd, "$Key=$Value") }
    }
    [IO.File]::WriteAllLines(
        $Path, $lines, (New-Object Text.UTF8Encoding($false)))
}

function Get-I07Md5 {
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

function New-I07CandidateNode {
    param(
        [Parameter(Mandatory = $true)][string]$PackagePath,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256,
        [Parameter(Mandatory = $true)][object[]]$ExpectedPackageFiles,
        [Parameter(Mandatory = $true)][string]$NodePath,
        [Parameter(Mandatory = $true)]
        [ValidateSet('source', 'viewer')][string]$Role,
        [Parameter(Mandatory = $true)][string]$BindIPv6,
        [ValidateRange(1024, 65535)][int]$TcpPort,
        [ValidateRange(1024, 65535)][int]$UdpPort,
        [ValidateRange(1024, 65535)][int]$WebPort,
        [Parameter(Mandatory = $true)][string]$Password
    )

    $package = [IO.Path]::GetFullPath($PackagePath)
    if (-not (Test-Path -LiteralPath $package -PathType Container)) {
        throw "Candidate package missing: $package"
    }
    Assert-I07NormalPathChain -Path $package
    $expected = $ExpectedSha256.ToLowerInvariant()
    if ($expected -notmatch '^[0-9a-f]{64}$') {
        throw 'Expected candidate SHA-256 is invalid.'
    }
    $expectedFiles = @(Assert-I07CriticalPackageContract `
        -Files $ExpectedPackageFiles)
    $packageIdentity = Get-I07PackageIdentity -PackagePath $package
    if ([int]$packageIdentity.file_count -ne $expectedFiles.Count -or
        [string]$packageIdentity.manifest_sha256 -cne
            (Get-I07PackageManifestSha256 -Files $expectedFiles)) {
        throw 'I07_PACKAGE_BINDING::REMOTE_PACKAGE_FILE_SET_MISMATCH'
    }
    $validatedFiles = [Collections.Generic.List[object]]::new()
    foreach ($contract in $expectedFiles) {
        $relative = ([string]$contract.path).Replace('/', '\')
        if ([string]::IsNullOrWhiteSpace($relative) -or
            [IO.Path]::IsPathRooted($relative) -or $relative.Contains(':') -or
            @($relative -split '\\' | Where-Object {
                    $_ -eq '.' -or $_ -eq '..'
                }).Count -gt 0) {
            throw "Unsafe candidate package path: '$relative'."
        }
        $sourceFile = [IO.Path]::GetFullPath((Join-Path $package $relative))
        $packagePrefix = $package.TrimEnd('\') + '\'
        if (-not $sourceFile.StartsWith(
                $packagePrefix, [StringComparison]::OrdinalIgnoreCase) -or
            -not (Test-Path -LiteralPath $sourceFile -PathType Leaf)) {
            throw "Candidate package file missing: $relative"
        }
        $held = Get-I07HeldFileContract -Path $sourceFile
        if ([Int64]$held.bytes -ne [Int64]$contract.bytes -or
            [string]$held.sha256 -cne
                ([string]$contract.sha256).ToLowerInvariant()) {
            throw "Candidate package contract mismatch: $relative"
        }
        $item = Get-Item -LiteralPath $sourceFile -Force -ErrorAction Stop
        $actualHash = [string]$held.sha256
        if ([Int64]$item.Length -ne [Int64]$contract.bytes -or
            $actualHash -cne ([string]$contract.sha256).ToLowerInvariant()) {
            throw "Candidate package contract mismatch: $relative"
        }
        $validatedFiles.Add([ordered]@{
            path = $relative.Replace('\', '/')
            bytes = [Int64]$item.Length
            sha256 = $actualHash
            source_path = $sourceFile
        })
    }
    $candidateContract = @($validatedFiles | Where-Object {
            [string]$_.path -ceq 'emule.exe'
        })
    if ($candidateContract.Count -ne 1 -or
        [string]$candidateContract[0].sha256 -cne $expected) {
        throw 'Candidate package does not contain the exact contracted emule.exe.'
    }
    $bind = ConvertTo-I07CanonicalIPv6 -Value $BindIPv6 `
        -Context 'BindIPv6'
    if ((Get-I07IPv6Class -Address ([Net.IPAddress]::Parse($bind))) -cne
        'global-native') {
        throw 'Candidate bind address is not native global IPv6.'
    }

    if (Test-Path -LiteralPath $NodePath) {
        throw 'The nonce-owned candidate node path already exists.'
    }
    $nodeParent = [IO.Path]::GetDirectoryName(
        [IO.Path]::GetFullPath($NodePath))
    Assert-I07NormalPathChain -Path $nodeParent
    New-Item -ItemType Directory -Path $NodePath -Force | Out-Null
    Assert-I07NormalPathChain -Path $NodePath
    foreach ($name in @('config', 'Incoming', 'Temp', 'logs')) {
        New-Item -ItemType Directory -Path (Join-Path $NodePath $name) `
            -Force | Out-Null
    }
    foreach ($file in $validatedFiles) {
        $destination = Join-Path $NodePath (
            ([string]$file.path).Replace('/', '\'))
        New-Item -ItemType Directory -Path (Split-Path -Parent $destination) `
            -Force | Out-Null
        # Keep the frozen package immutable even if Windows removes a zone
        # stream or the candidate writes beside/through a runtime file.
        Copy-Item -LiteralPath ([string]$file.source_path) `
            -Destination $destination -Force
        $copied = Get-Item -LiteralPath $destination
        $copiedHash = (Get-FileHash -LiteralPath $destination `
            -Algorithm SHA256).Hash.ToLowerInvariant()
        if ([Int64]$copied.Length -ne [Int64]$file.bytes -or
            $copiedHash -cne [string]$file.sha256) {
            throw "Prepared node file mismatch: $($file.path)"
        }
    }
    $exe = Join-Path $NodePath 'emule.exe'
    Unblock-File -LiteralPath $exe -ErrorAction Stop
    $copiedHash = (Get-FileHash -LiteralPath $exe `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($copiedHash -cne $expected) {
        throw 'Copied candidate SHA-256 mismatch.'
    }

    $preferences = Join-Path $NodePath 'config\preferences.ini'
    [IO.File]::WriteAllText(
        $preferences, '', (New-Object Text.UTF8Encoding($false)))
    $nick = if ($Role -ceq 'source') { 'eSE-A' } else { 'eSE-B' }
    foreach ($entry in @(
        @('eMule', 'AppVersion', '0.70b x64 - eSE 9.1.0'),
        @('eMule', 'Nick', $nick),
        @('eMule', 'BindAddr', ''),
        @('eMule', 'Port', [string]$TcpPort),
        @('eMule', 'UDPPort', [string]$UdpPort),
        @('eMule', 'NetworkKademlia', '0'),
        @('eMule', 'NetworkED2K', '0'),
        @('eMule', 'AutoConnect', '0'),
        @('eMule', 'OpenPortsOnStartUp', '0'),
        @('eMule', 'AutoTakeED2KLinks', '0'),
        @('eMule', 'WatchClipboard4ED2kFilelinks', '0'),
        @('eMule', 'AutoStart', '0'),
        @('eMule', 'SaveLogToDisk', '1'),
        @('eMule', 'SaveDebugToDisk', '1'),
        @('eMule', 'VerboseOptions', '1'),
        @('eMule', 'Verbose', '1'),
        @('eMule', 'FullVerbose', '1'),
        @('eMule', 'ConfirmExit', '0'),
        @('Connection', 'NetworkED2K', '0'),
        @('Connection', 'KadNetworkMask', '0'),
        @('Connection', 'IPv6Mode', '2'),
        @('Connection', 'IPv6BindAddr', $bind),
        @('UPnP', 'EnableUPnP', '0'),
        @('Proxy', 'ProxyEnableProxy', '0'),
        @('Proxy', 'ProxyEnablePassword', '0'),
        @('WebServer', 'Enabled', '1'),
        @('WebServer', 'Port', [string]$WebPort),
        @('WebServer', 'WebUseUPnP', '0'),
        @('WebServer', 'Password', (Get-I07Md5 -Value $Password)),
        @('WebServer', 'AllowAdminHiLevelFunc', '1'),
        @('WebServer', 'AllowedIPs', '127.0.0.1'),
        @('eSE', 'EseNetLabEnabled', '0'),
        @('eSE', 'EseNetLabConsent', '0'),
        @('eSE', 'EseNetLabAdvancedConsent', '0'),
        @('eSE', 'EseNetLabContributionConsent', '0'),
        @('eSE', 'EseV9Experimental', '0'),
        @('eSE', 'Kad6BetaExitOptIn', '0'),
        @('eSE', 'Kad6PublicExitOptIn', '0')
    )) {
        Set-I07IniValue -Path $preferences -Section $entry[0] `
            -Key $entry[1] -Value $entry[2]
    }
    return [pscustomobject][ordered]@{
        exe_path = $exe
        sha256 = $copiedHash
        bytes = [Int64](Get-Item -LiteralPath $exe).Length
        preferences_path = $preferences
        bind_ipv6 = $bind
        tcp_port = $TcpPort
        udp_port = $UdpPort
        web_port = $WebPort
        role = $Role
        nick = $nick
        package_path = $package
        package_files = @($validatedFiles | ForEach-Object {
            [ordered]@{
                path = [string]$_.path
                bytes = [Int64]$_.bytes
                sha256 = [string]$_.sha256
            }
        })
    }
}

function Get-I07PreparedNodeLaunchBinding {
    param(
        [Parameter(Mandatory = $true)]$CandidateNode,
        [Parameter(Mandatory = $true)][object[]]$ExpectedPackageFiles
    )

    $root = [IO.Path]::GetFullPath(
        [IO.Path]::GetDirectoryName([string]$CandidateNode.exe_path)).
        TrimEnd('\')
    Assert-I07NormalPathChain -Path $root
    $expected = @(Assert-I07CriticalPackageContract `
        -Files $ExpectedPackageFiles)
    $expectedByPath =
        [Collections.Generic.Dictionary[string,object]]::new(
            [StringComparer]::OrdinalIgnoreCase)
    foreach ($row in $expected) {
        $expectedByPath.Add([string]$row.path, $row)
    }
    $observedByPath =
        [Collections.Generic.Dictionary[string,object]]::new(
            [StringComparer]::OrdinalIgnoreCase)
    $prefix = $root + '\'
    $pending = [Collections.Generic.Stack[string]]::new()
    $pending.Push($root)
    while ($pending.Count -gt 0) {
        $directory = $pending.Pop()
        foreach ($item in @(Get-ChildItem -LiteralPath $directory -Force `
                -ErrorAction Stop)) {
            $full = [IO.Path]::GetFullPath([string]$item.FullName)
            if (-not $full.StartsWith(
                    $prefix, [StringComparison]::OrdinalIgnoreCase) -or
                ($item.Attributes -band
                    [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'I07_LAUNCH_BINDING::REPARSE_OR_ESCAPE'
            }
            if ($item.PSIsContainer) {
                $pending.Push($full)
                continue
            }
            $relative = ConvertTo-I07SafePackagePath -Value (
                $full.Substring($root.Length).TrimStart('\').Replace('\', '/'))
            if ($observedByPath.ContainsKey($relative)) {
                throw 'I07_LAUNCH_BINDING::CASE_OR_UNICODE_COLLISION'
            }
            $observedByPath.Add($relative, $item)
        }
    }
    $allowedPaths = @($expectedByPath.Keys) + @('config/preferences.ini')
    foreach ($relative in @($observedByPath.Keys)) {
        if ($relative -notin $allowedPaths) {
            throw 'I07_LAUNCH_BINDING::UNEXPECTED_FILE'
        }
    }
    $verified = [Collections.Generic.List[object]]::new()
    foreach ($row in $expected) {
        $relative = [string]$row.path
        if ($relative -ieq 'config/preferences.ini') { continue }
        if (-not $observedByPath.ContainsKey($relative)) {
            throw 'I07_LAUNCH_BINDING::STATIC_FILE_MISSING'
        }
        $held = Get-I07HeldFileContract -Path (
            [string]$observedByPath[$relative].FullName)
        if ([Int64]$held.bytes -ne [Int64]$row.bytes -or
            [string]$held.sha256 -cne [string]$row.sha256) {
            throw 'I07_LAUNCH_BINDING::STATIC_FILE_MISMATCH'
        }
        $verified.Add([pscustomobject][ordered]@{
            path = $relative
            bytes = [Int64]$held.bytes
            sha256 = [string]$held.sha256
        })
    }
    $preferencesPath = Join-Path $root 'config\preferences.ini'
    $preferences = Get-I07HeldFileContract -Path $preferencesPath
    $exe = @($verified | Where-Object { $_.path -ceq 'emule.exe' })
    if ($exe.Count -ne 1 -or [string]$exe[0].sha256 -cne
            [string]$CandidateNode.sha256) {
        throw 'I07_LAUNCH_BINDING::CANDIDATE_EXE_MISMATCH'
    }
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.i07-prelaunch-binding/v1'
        verified = $true
        static_file_count = $verified.Count
        static_manifest_sha256 = Get-I07PackageManifestSha256 `
            -Files $verified.ToArray()
        preferences_sha256 = [string]$preferences.sha256
        preferences_bytes = [Int64]$preferences.bytes
        candidate_sha256 = [string]$exe[0].sha256
    }
}

function Get-I07ProcessOwnerSidSha256 {
    param([Parameter(Mandatory = $true)][int]$ProcessId)

    $rows = @(Get-CimInstance -ClassName Win32_Process `
        -Filter "ProcessId = $ProcessId" -ErrorAction Stop)
    if ($rows.Count -ne 1) {
        throw 'I07_PROCESS_IDENTITY::CIM_ROW_AMBIGUOUS'
    }
    $owner = Invoke-CimMethod -InputObject $rows[0] `
        -MethodName GetOwnerSid -ErrorAction Stop
    if ([UInt32]$owner.ReturnValue -ne 0 -or
        [string]::IsNullOrWhiteSpace([string]$owner.Sid)) {
        throw 'I07_PROCESS_IDENTITY::OWNER_SID_UNAVAILABLE'
    }
    $sid = [Security.Principal.SecurityIdentifier]::new(
        [string]$owner.Sid).Value
    return Get-I07StringSha256 -Value $sid
}

function Get-I07ProcessIdentity {
    param(
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [Parameter(Mandatory = $true)][string]$ExpectedPath,
        [Parameter(Mandatory = $true)][string]$ExpectedFileSha256,
        [Parameter(Mandatory = $true)][string]$ExpectedUserSidSha256
    )

    $Process.Refresh()
    [void]$Process.Handle
    if ($Process.HasExited) {
        throw 'I07_PROCESS_IDENTITY::PROCESS_ALREADY_EXITED'
    }
    $actualPath = [IO.Path]::GetFullPath([string]$Process.Path)
    $expectedFullPath = [IO.Path]::GetFullPath($ExpectedPath)
    $file = Get-I07HeldFileContract -Path $actualPath
    $sidHash = Get-I07ProcessOwnerSidSha256 -ProcessId $Process.Id
    if ($actualPath -ine $expectedFullPath -or
        [string]$file.sha256 -cne $ExpectedFileSha256.ToLowerInvariant() -or
        $sidHash -cne $ExpectedUserSidSha256.ToLowerInvariant()) {
        throw 'I07_PROCESS_IDENTITY::BINDING_MISMATCH'
    }
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.i07-process-identity/v1'
        process_id = [int]$Process.Id
        start_time_utc = $Process.StartTime.ToUniversalTime().ToString('o')
        executable_path_sha256 = Get-I07StringSha256 -Value (
            $actualPath.ToLowerInvariant())
        executable_sha256 = [string]$file.sha256
        user_sid_sha256 = $sidHash
    }
}

function Wait-I07Api {
    param(
        [Parameter(Mandatory = $true)][Diagnostics.Process]$Process,
        [ValidateRange(1024, 65535)][int]$Port,
        [ValidateRange(5, 180)][int]$TimeoutSeconds = 60,
        [scriptblock]$CancellationCheck = $null
    )

    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        if ($null -ne $CancellationCheck) { & $CancellationCheck }
        Start-Sleep -Milliseconds 300
        $Process.Refresh()
        if ($Process.HasExited) {
            throw "Candidate exited with code $($Process.ExitCode)."
        }
        try {
            return Invoke-RestMethod -Uri (
                "http://127.0.0.1:$Port/api/status") -TimeoutSec 2
        } catch {}
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    throw "Candidate API on port $Port did not become ready."
}

function Stop-I07Candidate {
    param(
        [AllowNull()][Diagnostics.Process]$Process,
        [AllowNull()]$ExpectedIdentity,
        [string]$ExpectedFfmpegPath = '',
        [string]$ExpectedFfmpegSha256 = '',
        [string]$ExpectedUserSidSha256 = '',
        [int]$WebPort = 0
    )

    $result = [ordered]@{
        schema = 'ese.v91.i07-process-cleanup/v1'
        stopped = $true
        root_identity_matched = $true
        descendants_collector_ok = $true
        descendant_count = 0
        descendants_stopped = $true
    }
    if ($null -eq $Process) { return [pscustomobject]$result }
    $verifiedDescendants = [Collections.Generic.List[object]]::new()
    try {
        $Process.Refresh()
        [void]$Process.Handle
        $rootExited = $Process.HasExited
        if ($null -eq $ExpectedIdentity) {
            $result.root_identity_matched = $false
            $result.descendants_collector_ok = $false
        } elseif (-not $rootExited) {
            $actualIdentity = Get-I07ProcessIdentity -Process $Process `
                -ExpectedPath ([string]$Process.Path) `
                -ExpectedFileSha256 ([string]$ExpectedIdentity.executable_sha256) `
                -ExpectedUserSidSha256 $ExpectedUserSidSha256
            $result.root_identity_matched =
                [int]$actualIdentity.process_id -eq
                    [int]$ExpectedIdentity.process_id -and
                [string]$actualIdentity.start_time_utc -ceq
                    [string]$ExpectedIdentity.start_time_utc -and
                [string]$actualIdentity.executable_path_sha256 -ceq
                    [string]$ExpectedIdentity.executable_path_sha256 -and
                [string]$actualIdentity.executable_sha256 -ceq
                    [string]$ExpectedIdentity.executable_sha256 -and
                [string]$actualIdentity.user_sid_sha256 -ceq
                    [string]$ExpectedIdentity.user_sid_sha256
        }
        if (-not [bool]$result.root_identity_matched) {
            # The Process object carries the handle returned by Start-Process;
            # it remains safe to terminate that exact object, but no PID-based
            # descendant action is permitted without an identity match.
            if (-not $rootExited) {
                try {
                    $Process.Kill()
                    $null = $Process.WaitForExit(15000)
                    $Process.Refresh()
                    $result.stopped = $Process.HasExited
                } catch { $result.stopped = $false }
            }
            return [pscustomobject]$result
        }

        if (-not $rootExited) {
            $allRows = @(Get-CimInstance -ClassName Win32_Process `
                -ErrorAction Stop)
            $knownParents = [Collections.Generic.HashSet[int]]::new()
            $seen = [Collections.Generic.HashSet[int]]::new()
            $null = $knownParents.Add([int]$Process.Id)
            $descendantRows = [Collections.Generic.List[object]]::new()
            do {
                $added = $false
                foreach ($row in $allRows) {
                    $pid = [int]$row.ProcessId
                    if ($pid -eq [int]$Process.Id -or $seen.Contains($pid) -or
                        -not $knownParents.Contains([int]$row.ParentProcessId)) {
                        continue
                    }
                    $null = $seen.Add($pid)
                    $null = $knownParents.Add($pid)
                    $descendantRows.Add($row)
                    $added = $true
                }
            } while ($added)
            $result.descendant_count = $descendantRows.Count
            foreach ($row in $descendantRows) {
                if ([string]$row.Name -ine 'ffmpeg.exe' -or
                    [string]::IsNullOrWhiteSpace([string]$row.ExecutablePath) -or
                    [IO.Path]::GetFullPath([string]$row.ExecutablePath) -ine
                        [IO.Path]::GetFullPath($ExpectedFfmpegPath)) {
                    throw 'I07_PROCESS_CLEANUP::UNEXPECTED_DESCENDANT'
                }
                $child = Get-Process -Id ([int]$row.ProcessId) `
                    -ErrorAction Stop
                $childIdentity = Get-I07ProcessIdentity -Process $child `
                    -ExpectedPath $ExpectedFfmpegPath `
                    -ExpectedFileSha256 $ExpectedFfmpegSha256 `
                    -ExpectedUserSidSha256 $ExpectedUserSidSha256
                if ([DateTimeOffset]::Parse(
                        [string]$childIdentity.start_time_utc) -lt
                    [DateTimeOffset]::Parse(
                        [string]$ExpectedIdentity.start_time_utc)) {
                    throw 'I07_PROCESS_CLEANUP::DESCENDANT_PREDATES_ROOT'
                }
                $verifiedDescendants.Add([pscustomobject]@{
                    process = $child
                    identity = $childIdentity
                })
            }
        }

        if (-not $rootExited -and $WebPort -gt 0) {
            try {
                Invoke-RestMethod -Uri (
                    "http://127.0.0.1:$WebPort/api/network/disconnect") `
                    -TimeoutSec 3 | Out-Null
            } catch {}
        }
        if (-not $rootExited) {
            $Process.Refresh()
            if ($Process.MainWindowHandle -ne [IntPtr]::Zero) {
                $null = $Process.CloseMainWindow()
                $null = $Process.WaitForExit(5000)
            }
            $Process.Refresh()
            if (-not $Process.HasExited) {
                $Process.Kill()
                $null = $Process.WaitForExit(15000)
            }
        }
        foreach ($owned in $verifiedDescendants) {
            $child = [Diagnostics.Process]$owned.process
            $child.Refresh()
            if (-not $child.HasExited) {
                $child.Kill()
                if (-not $child.WaitForExit(10000)) {
                    $result.descendants_stopped = $false
                }
            }
        }
        $Process.Refresh()
        $result.stopped = $Process.HasExited -and
            [bool]$result.descendants_stopped
        return [pscustomobject]$result
    } catch {
        $result.root_identity_matched = $false
        $result.descendants_collector_ok = $false
        $result.descendants_stopped = $false
        # The root and already verified children are held Process objects, not
        # fresh PID lookups. Terminating those exact handles is safe even when
        # later identity/descendant collection fails; unverified processes are
        # deliberately left untouched and force a blocked cleanup result.
        try {
            $Process.Refresh()
            if (-not $Process.HasExited) {
                $Process.Kill()
                $null = $Process.WaitForExit(15000)
            }
            $Process.Refresh()
            $result.stopped = $Process.HasExited
        } catch { $result.stopped = $false }
        foreach ($owned in $verifiedDescendants) {
            try {
                $child = [Diagnostics.Process]$owned.process
                $child.Refresh()
                if (-not $child.HasExited) {
                    $child.Kill()
                    $null = $child.WaitForExit(10000)
                }
            } catch {}
        }
        return [pscustomobject]$result
    }
}

function Get-I07CandidateSocketEvidence {
    param(
        [Parameter(Mandatory = $true)][int]$ProcessId,
        [Parameter(Mandatory = $true)][string]$LocalIPv6,
        [Parameter(Mandatory = $true)][string]$PeerIPv6,
        [Parameter(Mandatory = $true)][string]$ExpectedInterfaceGuid,
        [ValidateRange(1024, 65535)][int]$PeerTcpPort,
        [ValidateRange(1024, 65535)][int]$LocalTcpPort,
        [Parameter(Mandatory = $true)]
        [ValidateSet('source', 'viewer')][string]$Role
    )

    $local = ConvertTo-I07CanonicalIPv6 -Value $LocalIPv6 `
        -Context 'LocalIPv6'
    $peer = ConvertTo-I07CanonicalIPv6 -Value $PeerIPv6 `
        -Context 'PeerIPv6'
    $rows = @(Get-NetTCPConnection -ErrorAction Stop | Where-Object {
            if ([int]$_.OwningProcess -ne $ProcessId -or
                [string]$_.State -cne 'Established') {
                return $false
            }
            $remote = ''
            try {
                $remote = ConvertTo-I07CanonicalIPv6 `
                    -Value ([string]$_.RemoteAddress)
            } catch { return $false }
            $socketLocal = ''
            try {
                $socketLocal = ConvertTo-I07CanonicalIPv6 `
                    -Value ([string]$_.LocalAddress)
            } catch { return $false }
            if ($remote -cne $peer -or $socketLocal -cne $local) {
                return $false
            }
            if ($Role -ceq 'source') {
                return [int]$_.LocalPort -eq $LocalTcpPort
            }
            return [int]$_.RemotePort -eq $PeerTcpPort
        })
    $tuples = @($rows | ForEach-Object {
        [ordered]@{
            local_address = ConvertTo-I07CanonicalIPv6 `
                -Value ([string]$_.LocalAddress)
            local_port = [int]$_.LocalPort
            remote_address = ConvertTo-I07CanonicalIPv6 `
                -Value ([string]$_.RemoteAddress)
            remote_port = [int]$_.RemotePort
            owning_process = [int]$_.OwningProcess
            state = [string]$_.State
        }
    })
    $addressRows = @(Get-NetIPAddress -AddressFamily IPv6 `
        -ErrorAction Stop | Where-Object {
            try {
                (ConvertTo-I07CanonicalIPv6 -Value ([string]$_.IPAddress)) `
                    -ceq $local
            } catch { $false }
        })
    $interfaceIndex = if ($addressRows.Count -eq 1) {
        [int]$addressRows[0].InterfaceIndex
    } else { 0 }
    $adapter = if ($interfaceIndex -gt 0) {
        Get-NetAdapter -InterfaceIndex $interfaceIndex -IncludeHidden `
            -ErrorAction Stop
    } else { $null }
    $interfaceGuid = [string](Get-I07PropertyValue -Object $adapter `
        -Name 'InterfaceGuid' -Default '')
    $hardware = [bool](Get-I07PropertyValue -Object $adapter `
        -Name 'HardwareInterface' -Default $false)
    $virtual = [bool](Get-I07PropertyValue -Object $adapter `
        -Name 'Virtual' -Default $true)
    $overlay = if ($null -eq $adapter) { $true } else {
        Test-I07OverlayAdapter -Adapter $adapter
    }
    $interfaceMatches = (
        $addressRows.Count -eq 1 -and $hardware -and -not $virtual -and
        -not $overlay -and
        $interfaceGuid.Trim('{}').ToLowerInvariant() -ceq
            $ExpectedInterfaceGuid.Trim('{}').ToLowerInvariant())
    return [pscustomobject][ordered]@{
        observed = $tuples.Count -gt 0 -and $interfaceMatches
        count = $tuples.Count
        tuples = $tuples
        local_address = $local
        interface_index = $interfaceIndex
        interface_guid = $interfaceGuid
        hardware_interface = $hardware
        virtual = $virtual
        overlay = $overlay
        interface_matches_route = $interfaceMatches
    }
}

function Get-I07ControlledApiPeerEvidence {
    param(
        [AllowNull()]$PeersResponse,
        [Parameter(Mandatory = $true)][string]$PeerIPv6,
        [ValidateRange(1024, 65535)][int]$PeerTcpPort
    )

    $expected = ConvertTo-I07CanonicalIPv6 -Value $PeerIPv6
    $matches = [Collections.Generic.List[object]]::new()
    if ($null -ne $PeersResponse) {
        foreach ($peer in @($PeersResponse.peers)) {
            $address = ''
            try {
                $address = ConvertTo-I07CanonicalIPv6 `
                    -Value ([string]$peer.address)
            } catch { continue }
            if ($address -ceq $expected -and
                (Test-I07StrictInteger -Value $peer.port `
                    -Minimum 1024 -Maximum 65535) -and
                [Int64]$peer.port -eq $PeerTcpPort -and
                (Test-I07StrictBoolean -Value $peer.isFork) -and
                [bool]$peer.isFork -and
                (Test-I07StrictBoolean -Value $peer.dataplaneCap) -and
                [bool]$peer.dataplaneCap) {
                $matches.Add([pscustomobject][ordered]@{
                    address = $address
                    port = [int]$peer.port
                    isFork = $true
                    dataplaneCap = $true
                })
            }
        }
    }
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.i07-controlled-api-peer/v1'
        matched = $matches.Count -eq 1
        controlled_peer = if ($matches.Count -eq 1) {
            $matches[0]
        } else { $null }
    }
}

function Test-I07ApiPeer {
    param(
        [AllowNull()]$PeersResponse,
        [Parameter(Mandatory = $true)][string]$PeerIPv6,
        [ValidateRange(1024, 65535)][int]$PeerTcpPort
    )

    return [bool](Get-I07ControlledApiPeerEvidence `
        -PeersResponse $PeersResponse -PeerIPv6 $PeerIPv6 `
        -PeerTcpPort $PeerTcpPort).matched
}

function Get-I07HlsEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$StreamKey,
        [DateTimeOffset]$MinimumWriteTimeUtc = [DateTimeOffset]::MinValue
    )

    $key = $StreamKey.ToLowerInvariant()
    if ($key -cnotmatch '^[0-9a-f]{32}$') {
        throw 'The HLS stream key is not a nonce-owned 32-hex identifier.'
    }
    $hlsRoot = [IO.Path]::GetFullPath((
        Join-Path $env:TEMP 'eMule_RTMP'))
    $streamRoot = [IO.Path]::GetFullPath((Join-Path $hlsRoot $key))
    $hlsPrefix = $hlsRoot.TrimEnd('\') + '\'
    if (-not $streamRoot.StartsWith(
            $hlsPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'The nonce-owned HLS directory escaped its root.'
    }
    $streamPrefix = $streamRoot.TrimEnd('\') + '\'
    $playlistPath = [IO.Path]::GetFullPath((
        Join-Path $streamRoot 'stream.m3u8'))
    $playlist = $false
    $segment = $false
    $segmentPathContained = $false
    $segmentBytes = 0L
    $playlistWriteUtc = $null
    $segmentWriteUtc = $null
    $streamKeyHash = ''
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        $streamKeyHash = ([BitConverter]::ToString(
            $sha256.ComputeHash([Text.Encoding]::UTF8.GetBytes($key)))).
                Replace('-', '').ToLowerInvariant()
    } finally { $sha256.Dispose() }
    if ((Test-Path -LiteralPath $streamRoot -PathType Container) -and
        (Test-Path -LiteralPath $playlistPath -PathType Leaf)) {
        $streamItem = Get-Item -LiteralPath $streamRoot -ErrorAction Stop
        $playlistItem = Get-Item -LiteralPath $playlistPath -ErrorAction Stop
        if (($streamItem.Attributes -band [IO.FileAttributes]::ReparsePoint) `
                -ne 0 -or
            ($playlistItem.Attributes -band [IO.FileAttributes]::ReparsePoint) `
                -ne 0) {
            throw 'The nonce-owned HLS root or playlist is a reparse point.'
        }
        $playlistWriteUtc = [DateTimeOffset]$playlistItem.LastWriteTimeUtc
        $text = Get-Content -LiteralPath $playlistPath -Raw -ErrorAction Stop
        $playlist = $text -match '#EXTM3U' -and
            $playlistWriteUtc -ge $MinimumWriteTimeUtc
        $match = [regex]::Match($text, '(?m)^([^#\r\n]+\.ts)\s*$')
        if ($match.Success) {
            $relative = ([string]$match.Groups[1].Value).Replace('/', '\')
            $parts = @($relative -split '\\')
            if ([IO.Path]::IsPathRooted($relative) -or
                $relative.Contains(':') -or $parts.Count -eq 0 -or
                @($parts | Where-Object {
                        [string]::IsNullOrWhiteSpace($_) -or
                        $_ -eq '.' -or $_ -eq '..'
                    }).Count -ne 0) {
                throw 'The HLS segment URI is not a safe relative path.'
            }
            $path = [IO.Path]::GetFullPath((Join-Path $streamRoot $relative))
            $segmentPathContained = $path.StartsWith(
                $streamPrefix, [StringComparison]::OrdinalIgnoreCase)
            if (-not $segmentPathContained) {
                throw 'The HLS segment path escaped its nonce-owned directory.'
            }
            $current = $streamRoot
            foreach ($part in $parts) {
                $current = Join-Path $current $part
                $currentItem = Get-Item -LiteralPath $current -ErrorAction Stop
                if (($currentItem.Attributes -band
                        [IO.FileAttributes]::ReparsePoint) -ne 0) {
                    throw 'The HLS segment path contains a reparse point.'
                }
            }
            $segmentItem = Get-Item -LiteralPath $path -ErrorAction Stop
            $segmentBytes = [Int64]$segmentItem.Length
            $segmentWriteUtc = [DateTimeOffset]$segmentItem.LastWriteTimeUtc
            $segment = $segmentBytes -gt 0 -and
                $segmentWriteUtc -ge $MinimumWriteTimeUtc
        }
    }
    return [pscustomobject][ordered]@{
        playlist_name = 'stream.m3u8'
        stream_key_sha256 = $streamKeyHash
        playlist_seen = $playlist
        segment_seen = $segment
        segment_path_contained = $segmentPathContained
        segment_bytes = $segmentBytes
        playlist_last_write_utc = if ($null -eq $playlistWriteUtc) {
            $null
        } else { $playlistWriteUtc.ToString('o') }
        segment_last_write_utc = if ($null -eq $segmentWriteUtc) {
            $null
        } else { $segmentWriteUtc.ToString('o') }
        minimum_write_utc = $MinimumWriteTimeUtc.ToString('o')
    }
}

function Get-I07ApiEvidenceSummary {
    param(
        [AllowNull()]$Value,
        [AllowNull()][Nullable[DateTimeOffset]]$CapturedAt
    )
    if ($null -eq $Value -or $null -eq $CapturedAt) {
        return [pscustomobject][ordered]@{
            schema = 'ese.v91.i07-api-status-evidence/v2'
            available = $false
            contract_valid = $false
            isolation_invariant_satisfied = $false
            captured_at_utc = $null
            safe_response_sha256 = $null
            safe_response_bytes = 0
            safe_scalars = [ordered]@{}
        }
    }
    $boolNames = @(
        'ed2k_connected', 'kad_connected', 'kad2_running',
        'kad2_connected', 'kad6_running', 'kad6_connected',
        'netlab_enabled')
    $maskNames = @('kad_configured_mask', 'kad_running_mask')
    $safe = [ordered]@{}
    $contractValid = $true
    foreach ($name in $boolNames) {
        $property = $Value.PSObject.Properties[$name]
        if ($null -eq $property -or -not ($property.Value -is [bool])) {
            $contractValid = $false
            break
        }
        $safe[$name] = [bool]$property.Value
    }
    if ($contractValid) {
        foreach ($name in $maskNames) {
            $property = $Value.PSObject.Properties[$name]
            $isIntegral = $null -ne $property -and (
                $property.Value -is [byte] -or
                $property.Value -is [sbyte] -or
                $property.Value -is [Int16] -or
                $property.Value -is [UInt16] -or
                $property.Value -is [Int32] -or
                $property.Value -is [UInt32] -or
                $property.Value -is [Int64] -or
                $property.Value -is [UInt64])
            if (-not $isIntegral -or [Int64]$property.Value -lt 0 -or
                [Int64]$property.Value -gt 255) {
                $contractValid = $false
                break
            }
            $safe[$name] = [Int64]$property.Value
        }
    }
    if (-not $contractValid) {
        return [pscustomobject][ordered]@{
            schema = 'ese.v91.i07-api-status-evidence/v2'
            available = $false
            contract_valid = $false
            isolation_invariant_satisfied = $false
            captured_at_utc = ([DateTimeOffset]$CapturedAt).
                ToUniversalTime().ToString('o')
            safe_response_sha256 = $null
            safe_response_bytes = 0
            safe_scalars = [ordered]@{}
        }
    }
    $invariantSatisfied = @($boolNames | Where-Object {
            [bool]$safe[$_]
        }).Count -eq 0 -and @($maskNames | Where-Object {
            [Int64]$safe[$_] -ne 0
        }).Count -eq 0
    $safeJson = $safe | ConvertTo-Json -Depth 4 -Compress
    $safeBytes = [Text.Encoding]::UTF8.GetBytes($safeJson)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $safeHash = ([BitConverter]::ToString(
            $sha.ComputeHash($safeBytes))).Replace('-', '').ToLowerInvariant()
    } finally { $sha.Dispose() }
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.i07-api-status-evidence/v2'
        available = $true
        contract_valid = $true
        isolation_invariant_satisfied = $invariantSatisfied
        captured_at_utc = ([DateTimeOffset]$CapturedAt).
            ToUniversalTime().ToString('o')
        safe_response_sha256 = $safeHash
        safe_response_bytes = $safeBytes.Length
        safe_scalars = $safe
    }
}

function Write-I07RetainedNodeEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$EvidencePath,
        [Parameter(Mandatory = $true)][string]$NodePath,
        [Parameter(Mandatory = $true)][string]$ExpectedBuildInfoSha256,
        [AllowNull()]$ApiStatusInitial,
        [AllowNull()]$ApiStatusFinal,
        [AllowNull()][Nullable[DateTimeOffset]]$ApiInitialAtUtc,
        [AllowNull()][Nullable[DateTimeOffset]]$ApiFinalAtUtc,
        [Parameter(Mandatory = $true)][string]$Role,
        [int]$CandidatePid,
        [AllowNull()]$TopologyPorts,
        [string[]]$Secrets = @()
    )

    function Get-I07EvidenceFileContract {
        param([string]$Path, [string]$Name)
        $item = Get-Item -LiteralPath $Path -ErrorAction Stop
        return [pscustomobject][ordered]@{
            name = $Name
            bytes = [Int64]$item.Length
            sha256 = (Get-FileHash -LiteralPath $Path `
                -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }

    $root = [IO.Path]::GetFullPath($EvidencePath).TrimEnd('\')
    $nodeDirectory = [IO.Path]::GetFullPath($NodePath).TrimEnd('\')
    $jobRoot = [IO.Path]::GetDirectoryName($nodeDirectory).TrimEnd('\')
    if ([IO.Path]::GetDirectoryName($root).TrimEnd('\') -ine $jobRoot -or
        (Test-Path -LiteralPath $root)) {
        throw 'EvidencePath must be a new normal sibling of the nonce node.'
    }
    $nodeItem = Get-Item -LiteralPath $nodeDirectory -Force -ErrorAction Stop
    if (-not $nodeItem.PSIsContainer -or
        ($nodeItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'The nonce node is not a normal directory.'
    }
    New-Item -ItemType Directory -Path $root -ErrorAction Stop | Out-Null
    $rootItem = Get-Item -LiteralPath $root -Force -ErrorAction Stop
    if (-not $rootItem.PSIsContainer -or
        ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'The retained-evidence root is not a normal directory.'
    }
    $nodeRoot = $nodeDirectory + '\'
    $buildSource = [IO.Path]::GetFullPath((
        Join-Path $NodePath 'BUILD_INFO.txt'))
    $buildItem = Get-Item -LiteralPath $buildSource -Force -ErrorAction Stop
    if (-not $buildSource.StartsWith(
            $nodeRoot, [StringComparison]::OrdinalIgnoreCase) -or
        $buildItem.PSIsContainer -or
        ($buildItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Staged BUILD_INFO is missing from the nonce node.'
    }
    $buildSourceSha = (Get-FileHash -LiteralPath $buildSource `
        -Algorithm SHA256).Hash.ToLowerInvariant()
    $buildExact = $buildSourceSha -ceq
        $ExpectedBuildInfoSha256.ToLowerInvariant()
    $buildFields = [ordered]@{}
    $buildUnknownLineCount = 0
    $allowedBuildFields = @(
        'release', 'commit', 'dirty', 'built_utc', 'node', 'npm', 'ffmpeg',
        'ffmpeg_sha256', 'ffprobe_sha256', 'nodes_dat_sha256')
    foreach ($line in Get-Content -LiteralPath $buildSource -ErrorAction Stop) {
        if ([string]::IsNullOrWhiteSpace([string]$line)) { continue }
        if ($line -match '^\s*([A-Za-z0-9_]+):\s*(.*?)\s*$' -and
            $allowedBuildFields -ccontains $Matches[1].ToLowerInvariant()) {
            $name = $Matches[1].ToLowerInvariant()
            if ($buildFields.Contains($name)) {
                throw "Duplicate BUILD_INFO field: $name"
            }
            $buildFields[$name] = $Matches[2]
        } else {
            $buildUnknownLineCount++
        }
    }
    $builtUtc = [DateTimeOffset]::MinValue
    $builtUtcValid = [DateTimeOffset]::TryParseExact(
        [string]$buildFields['built_utc'], 'yyyy-MM-ddTHH:mm:ssZ',
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$builtUtc)
    $buildFieldsValid =
        $buildFields.Count -eq $allowedBuildFields.Count -and
        $buildUnknownLineCount -eq 0 -and
        [string]$buildFields['commit'] -cmatch '^[0-9a-f]{40}$' -and
        [string]$buildFields['dirty'] -ceq 'false' -and
        [string]$buildFields['release'] -cmatch '^[A-Za-z0-9._+-]{1,80}$' -and
        $builtUtcValid -and
        [string]$buildFields['node'] -cmatch
            '^v?[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$' -and
        [string]$buildFields['npm'] -cmatch
            '^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$' -and
        [string]$buildFields['ffmpeg'] -cmatch
            '^ffmpeg version [A-Za-z0-9 .,_+()=:;-]{1,240}$' -and
        [string]$buildFields['ffmpeg_sha256'] -match '^[0-9a-f]{64}$' -and
        [string]$buildFields['ffprobe_sha256'] -match '^[0-9a-f]{64}$' -and
        [string]$buildFields['nodes_dat_sha256'] -match '^[0-9a-f]{64}$'
    $publicBuildFields = [ordered]@{}
    if ($buildFieldsValid) {
        foreach ($name in $allowedBuildFields) {
            $publicBuildFields[$name] = if ($name -like '*_sha256') {
                ([string]$buildFields[$name]).ToLowerInvariant()
            } else { [string]$buildFields[$name] }
        }
    }
    $buildValue = [ordered]@{
        schema = 'ese.v91.i07-build-info-evidence/v1'
        original_sha256 = $buildSourceSha
        expected_sha256 = $ExpectedBuildInfoSha256.ToLowerInvariant()
        exact = $buildExact
        fields_valid = $buildFieldsValid
        unknown_line_count = $buildUnknownLineCount
        fields = $publicBuildFields
    }
    $buildDestination = Join-Path $root 'build-info-evidence.json'
    Write-I07JsonAtomic -Path $buildDestination -Value $buildValue
    if (-not $buildExact -or -not $buildFieldsValid) {
        throw 'BUILD_INFO does not match the exact public production schema.'
    }
    $buildRawDestination = Join-Path $root 'BUILD_INFO.txt'
    Copy-Item -LiteralPath $buildSource -Destination $buildRawDestination
    $buildRawItem = Get-Item -LiteralPath $buildRawDestination -Force `
        -ErrorAction Stop
    if ($buildRawItem.PSIsContainer -or
        ($buildRawItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        (Get-FileHash -LiteralPath $buildRawDestination -Algorithm SHA256).
            Hash.ToLowerInvariant() -cne $buildSourceSha) {
        throw 'Retained BUILD_INFO copy changed after schema validation.'
    }

    $preferences = [IO.Path]::GetFullPath((
        Join-Path $NodePath 'config\preferences.ini'))
    $preferencesItem = Get-Item -LiteralPath $preferences -Force `
        -ErrorAction Stop
    if (-not $preferences.StartsWith(
            $nodeRoot, [StringComparison]::OrdinalIgnoreCase) -or
        $preferencesItem.PSIsContainer -or
        ($preferencesItem.Attributes -band
            [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Staged preferences are not a normal nonce-owned file.'
    }
    $expectedConfig = [ordered]@{
        'eMule/Nick' = if ($Role -ceq 'source') { 'eSE-A' } else { 'eSE-B' }
        'eMule/Port' = [string]$TopologyPorts.ports.tcp
        'eMule/UDPPort' = [string]$TopologyPorts.ports.udp
        'eMule/NetworkKademlia' = '0'
        'eMule/NetworkED2K' = '0'
        'eMule/AutoConnect' = '0'
        'eMule/OpenPortsOnStartUp' = '0'
        'eMule/AutoTakeED2KLinks' = '0'
        'eMule/WatchClipboard4ED2kFilelinks' = '0'
        'eMule/AutoStart' = '0'
        'Connection/NetworkED2K' = '0'
        'Connection/KadNetworkMask' = '0'
        'Connection/IPv6Mode' = '2'
        'UPnP/EnableUPnP' = '0'
        'Proxy/ProxyEnableProxy' = '0'
        'Proxy/ProxyEnablePassword' = '0'
        'WebServer/Enabled' = '1'
        'WebServer/Port' = [string]$TopologyPorts.ports.web
        'WebServer/WebUseUPnP' = '0'
        'WebServer/AllowedIPs' = '127.0.0.1'
        'eSE/EseNetLabEnabled' = '0'
        'eSE/EseNetLabConsent' = '0'
        'eSE/EseNetLabAdvancedConsent' = '0'
        'eSE/EseNetLabContributionConsent' = '0'
        'eSE/EseV9Experimental' = '0'
        'eSE/Kad6BetaExitOptIn' = '0'
        'eSE/Kad6PublicExitOptIn' = '0'
    }
    $observedConfig = [ordered]@{}
    $duplicateConfigCount = 0
    $section = ''
    foreach ($line in Get-Content -LiteralPath $preferences `
            -ErrorAction Stop) {
        if ($line -match '^\s*\[(.+?)\]\s*$') {
            $section = $Matches[1]
        } elseif ($line -match '^\s*([^;#][^=]*?)\s*=\s*(.*?)\s*$') {
            $key = $Matches[1].Trim()
            $contractName = "$section/$key"
            if ($expectedConfig.Contains($contractName)) {
                if ($observedConfig.Contains($contractName)) {
                    $duplicateConfigCount++
                } else {
                    $observedConfig[$contractName] = [string]$Matches[2]
                }
            }
        }
    }
    $configAllowlistOnly = $duplicateConfigCount -eq 0 -and
        $observedConfig.Count -eq $expectedConfig.Count -and
        @($expectedConfig.Keys | Where-Object {
                [string]$observedConfig[$_] -cne [string]$expectedConfig[$_]
            }).Count -eq 0
    $effectiveEntries = @()
    if ($configAllowlistOnly) {
        $effectiveEntries = @($expectedConfig.Keys | ForEach-Object {
            $parts = $_.Split('/')
            [pscustomobject][ordered]@{
                section = $parts[0]
                key = $parts[1]
                value = [string]$expectedConfig[$_]
            }
        })
    }
    $configValue = [ordered]@{
        schema = 'ese.v91.i07-effective-config/v2'
        allowlist_only = $configAllowlistOnly
        values_exact = $configAllowlistOnly
        role = $Role
        entries = @($effectiveEntries)
    }
    $configPath = Join-Path $root 'effective-config.json'
    Write-I07JsonAtomic -Path $configPath -Value $configValue

    $apiPre = Get-I07ApiEvidenceSummary -Value $ApiStatusInitial `
        -CapturedAt $ApiInitialAtUtc
    $apiPost = Get-I07ApiEvidenceSummary -Value $ApiStatusFinal `
        -CapturedAt $ApiFinalAtUtc
    $apiPrePath = Join-Path $root 'api-status-pre.json'
    $apiPostPath = Join-Path $root 'api-status-post.json'
    Write-I07JsonAtomic -Path $apiPrePath -Value $apiPre
    Write-I07JsonAtomic -Path $apiPostPath -Value $apiPost

    $topologyValue = [ordered]@{
        schema = 'ese.v91.i07-topology-ports-evidence/v1'
        role = $Role
        topology_id = 'T3'
        candidate_pid = $CandidatePid
        retained_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
        contract = $TopologyPorts
    }
    $topologyPath = Join-Path $root 'topology-ports.json'
    Write-I07JsonAtomic -Path $topologyPath -Value $topologyValue -Depth 20

    $logsRoot = [IO.Path]::GetFullPath((Join-Path $NodePath 'logs'))
    $logsItem = Get-Item -LiteralPath $logsRoot -Force -ErrorAction Stop
    if (-not $logsRoot.StartsWith(
            $nodeRoot, [StringComparison]::OrdinalIgnoreCase) -or
        -not $logsItem.PSIsContainer -or
        ($logsItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'The nonce-owned log root is not a normal directory.'
    }
    $logFiles = @()
    foreach ($log in @(Get-ChildItem -LiteralPath $logsRoot -Force -File `
            -Filter '*.log' -ErrorAction Stop | Sort-Object Name)) {
        if ([IO.Path]::GetDirectoryName(
                [IO.Path]::GetFullPath($log.FullName)).TrimEnd('\') -ine
                $logsRoot.TrimEnd('\') -or
            ($log.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'A retained log source is not a normal immediate file.'
        }
        $logFiles += $log
    }
    $timestampPattern =
        '(?i)(?:\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}|' +
        '\d{1,2}[/. -]\d{1,2}[/. -]\d{2,4}\s+\d{1,2}:\d{2}:\d{2}|' +
        '\[\d{1,2}:\d{2}:\d{2}\])'
    $inspectedLineCount = 0
    $timestampedCount = 0
    $logEvents = [Collections.Generic.List[object]]::new()
    foreach ($log in $logFiles) {
        foreach ($line in [IO.File]::ReadLines($log.FullName)) {
            if ([string]::IsNullOrWhiteSpace([string]$line)) { continue }
            $inspectedLineCount++
            $timestampMatch = [regex]::Match([string]$line, $timestampPattern)
            if ($timestampMatch.Success) {
                $timestampedCount++
                if ($logEvents.Count -lt 20) {
                    $eventClass = if ($line -match
                        '(?i)fatal|error|failed|failure') { 'error' }
                    elseif ($line -match '(?i)warn') { 'warning' }
                    elseif ($line -match
                        '(?i)live|stream|hls|broadcast|ffmpeg') { 'livetv' }
                    elseif ($line -match
                        '(?i)connect|socket|peer') { 'connectivity' }
                    elseif ($line -match
                        '(?i)start|ready|initializ') { 'lifecycle' }
                    else { 'other' }
                    $logEvents.Add([pscustomobject][ordered]@{
                        timestamp = [string]$timestampMatch.Value
                        event_class = $eventClass
                    })
                }
            }
            if ($inspectedLineCount -ge 200) { break }
        }
        if ($inspectedLineCount -ge 200) { break }
    }
    $logValue = [ordered]@{
        schema = 'ese.v91.i07-log-evidence/v1'
        source_file_count = $logFiles.Count
        inspected_nonempty_line_count = $inspectedLineCount
        timestamped_line_count = $timestampedCount
        capped_at_200_lines = $inspectedLineCount -ge 200
        events = @($logEvents)
    }
    $logPath = Join-Path $root 'log-evidence.json'
    Write-I07JsonAtomic -Path $logPath -Value $logValue -Depth 8

    $artifactNames = @(
        'BUILD_INFO.txt', 'build-info-evidence.json', 'effective-config.json',
        'api-status-pre.json', 'api-status-post.json',
        'topology-ports.json', 'log-evidence.json'
    )
    $files = @($artifactNames | ForEach-Object {
        Get-I07EvidenceFileContract -Path (Join-Path $root $_) -Name $_
    })
    $fileContractsValid = $files.Count -eq $artifactNames.Count -and
        @($files | Where-Object {
                [Int64]$_.bytes -le 0 -or
                [string]$_.sha256 -notmatch '^[0-9a-f]{64}$'
            }).Count -eq 0
    $requirements = [ordered]@{
        build_info_exact = $buildExact -and $buildFieldsValid
        build_info_source_sha256 = $buildSourceSha
        config_allowlist_only = $configAllowlistOnly
        api_pre_retained = [bool]$apiPre.available
        api_post_retained = [bool]$apiPost.available
        topology_ports_retained = $null -ne $TopologyPorts -and
            $CandidatePid -gt 0 -and $Role -cin @('source', 'viewer')
        real_log_line_count = $inspectedLineCount
        timestamped_log_line_count = $timestampedCount
    }
    $complete = $fileContractsValid -and $buildExact -and $buildFieldsValid -and
        $configAllowlistOnly -and [bool]$apiPre.available -and
        [bool]$apiPost.available -and
        [bool]$requirements.topology_ports_retained -and
        $inspectedLineCount -ge 1 -and $timestampedCount -ge 1
    $manifestValue = [ordered]@{
        schema = 'ese.v91.i07-evidence-manifest/v1'
        case_id = 'V91-I07'
        complete = $complete
        created_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
        files = $files
        requirements = $requirements
    }
    $manifestPath = Join-Path $root 'manifest.json'
    Write-I07JsonAtomic -Path $manifestPath -Value $manifestValue -Depth 16
    $manifestContract = Get-I07EvidenceFileContract `
        -Path $manifestPath -Name 'manifest.json'
    foreach ($file in $files) {
        $actual = Get-I07EvidenceFileContract `
            -Path (Join-Path $root ([string]$file.name)) `
            -Name ([string]$file.name)
        if ([Int64]$actual.bytes -ne [Int64]$file.bytes -or
            [string]$actual.sha256 -cne [string]$file.sha256) {
            throw "Retained I07 evidence changed: $($file.name)."
        }
    }
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.i07-retained-evidence/v1'
        complete = $complete
        directory = 'evidence'
        files = $files
        manifest = $manifestContract
        requirements = $requirements
        build_info = $buildValue
        effective_config = $configValue
        log_evidence = $logValue
    }
}

function Invoke-I07SelfTest {
    $cases = @(
        @('2a02:26f7:abcd::1', 'global-native'),
        @('2001:4860:4860::8888', 'global-native'),
        @('fd00::1', 'ula'),
        @('fe80::1', 'link-local'),
        @('2001:db8::1', 'documentation'),
        @('3fff::1', 'documentation'),
        @('2001:2::1', 'benchmark'),
        @('2001::1', 'teredo'),
        @('2002::1', '6to4'),
        @('2001:1::1', 'special-purpose'),
        @('2001:3::1', 'special-purpose'),
        @('2001:4:112::1', 'special-purpose'),
        @('2001:30::1', 'special-purpose'),
        @('2001:1ff::1', 'special-purpose'),
        @('2620:4f:8000::1', 'as112-direct-delegation'),
        @('2001:200::1', 'global-native'),
        @('64:ff9b::c000:201', 'nat64-well-known'),
        @('64:ff9b:1::1', 'nat64-local-use'),
        @('::1', 'loopback')
    )
    foreach ($case in $cases) {
        $address = [Net.IPAddress]::Parse([string]$case[0])
        $actual = Get-I07IPv6Class -Address $address
        if ($actual -cne [string]$case[1]) {
            throw "IPv6 class self-test failed for $($case[0]): $actual"
        }
    }
    $canonical = ConvertTo-I07CanonicalIPv6 `
        -Value '2A02:26F7:0:0:0:0:0:1'
    if ($canonical -cne '2a02:26f7::1') {
        throw "Canonicalization self-test failed: $canonical"
    }
    $mappedRejected = $false
    try { $null = ConvertTo-I07CanonicalIPv6 -Value '::ffff:192.0.2.1' }
    catch { $mappedRejected = $true }
    if (-not $mappedRejected) {
        throw 'IPv4-mapped IPv6 was accepted by the self-test.'
    }
    if (-not (Test-I07PortContract -Ports @(48067, 48077, 48117)) -or
        (Test-I07PortContract -Ports @(80, 48077, 48117)) -or
        (Test-I07PortContract -Ports @(48067, 48067, 48117))) {
        throw 'Port-contract self-test failed.'
    }
    return [pscustomobject][ordered]@{
        status = 'PASS'
        address_cases = $cases.Count
        mapped_rejected = $mappedRejected
        port_contract_checked = $true
    }
}
