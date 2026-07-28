Set-StrictMode -Version 2.0

function Get-T8Sha256Text {
    param([Parameter(Mandatory = $true)][string]$Value)

    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($Value)
        return ([BitConverter]::ToString(
            $sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function ConvertTo-T8GuidText {
    param([Parameter(Mandatory = $true)][string]$Value)

    $guid = [Guid]::Empty
    if (-not [Guid]::TryParse($Value, [ref]$guid) -or
        $guid -eq [Guid]::Empty) {
        throw "T8 requires a non-empty GUID: $Value"
    }
    return $guid.ToString('D').ToLowerInvariant()
}

function ConvertTo-T8PrefixRange {
    param([Parameter(Mandatory = $true)][string]$Prefix)

    if ($Prefix -notmatch '^(\d{1,3}(?:\.\d{1,3}){3})/(\d|[12]\d|3[0-2])$') {
        throw "T8 requires an IPv4 CIDR prefix: $Prefix"
    }
    $address = $null
    if (-not [Net.IPAddress]::TryParse($Matches[1], [ref]$address) -or
        $address.AddressFamily -ne
            [Net.Sockets.AddressFamily]::InterNetwork) {
        throw "T8 requires an IPv4 CIDR prefix: $Prefix"
    }
    $length = [int]$Matches[2]
    $bytes = $address.GetAddressBytes()
    [Array]::Reverse($bytes)
    $value = [BitConverter]::ToUInt32($bytes, 0)
    $blockSize = [uint64][Math]::Pow(2, 32 - $length)
    $first = [uint64]([Math]::Floor(
        ([double]$value) / $blockSize) * $blockSize)
    $last = $first + $blockSize - 1
    return [pscustomobject][ordered]@{
        prefix = $Prefix
        first = [uint64]$first
        last = [uint64]$last
    }
}

function Test-T8PrefixOverlap {
    param(
        [Parameter(Mandatory = $true)][string]$Left,
        [Parameter(Mandatory = $true)][string]$Right
    )

    $leftRange = ConvertTo-T8PrefixRange -Prefix $Left
    $rightRange = ConvertTo-T8PrefixRange -Prefix $Right
    return $leftRange.first -le $rightRange.last -and
        $rightRange.first -le $leftRange.last
}

function Get-T8UniqueNames {
    param(
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[a-z0-9][a-z0-9-]{2,31}$')]
        [string]$RunLabel,
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[0-9a-f]{12}$')]
        [string]$Nonce
    )

    $labelDigest = (Get-T8Sha256Text -Value $RunLabel).Substring(0, 6)
    $suffix = '{0}-{1}' -f $labelDigest, $Nonce
    return [pscustomobject][ordered]@{
        switch = 'ese-v92-t8-sw-' + $suffix
        nat = 'ese-v92-t8-nat-' + $suffix
        suffix = $suffix
    }
}

function Select-T8PrivatePrefix {
    param(
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[0-9a-f]{12}$')]
        [string]$Nonce,
        [string[]]$UsedPrefixes = @()
    )

    $seed = [Convert]::ToInt32($Nonce.Substring(0, 6), 16)
    for ($attempt = 0; $attempt -lt 2560; $attempt++) {
        $slot = ($seed + $attempt) % 2560
        $secondOctet = 20 + [Math]::Floor($slot / 256)
        $thirdOctet = $slot % 256
        $candidate = '172.{0}.{1}.0/24' -f $secondOctet, $thirdOctet
        $overlaps = $false
        foreach ($used in @($UsedPrefixes)) {
            if ([string]::IsNullOrWhiteSpace($used)) { continue }
            if (Test-T8PrefixOverlap -Left $candidate -Right $used) {
                $overlaps = $true
                break
            }
        }
        if (-not $overlaps) { return $candidate }
    }
    throw 'No collision-free T8 /24 remains in 172.20.0.0/14'
}

function Get-T8GatewayAddress {
    param([Parameter(Mandatory = $true)][string]$Prefix)

    if ($Prefix -notmatch '^(\d{1,3}\.\d{1,3}\.\d{1,3})\.0/24$') {
        throw "T8 gateway derivation requires a canonical /24: $Prefix"
    }
    return $Matches[1] + '.1'
}

function Assert-T8PlanShape {
    param([Parameter(Mandatory = $true)][object]$Plan)

    if ([string]$Plan.schema -ne 'ese.v92.t8-hyperv-plan/v1') {
        throw 'Unsupported or missing T8 Hyper-V plan schema'
    }
    if ([string]$Plan.plan_id -notmatch '^[0-9a-f]{32}$') {
        throw 'T8 plan_id is invalid'
    }
    if ([string]$Plan.nonce -notmatch '^[0-9a-f]{12}$') {
        throw 'T8 plan nonce is invalid'
    }
    $expectedNames = Get-T8UniqueNames -RunLabel ([string]$Plan.run_label) `
        -Nonce ([string]$Plan.nonce)
    if ([string]$Plan.resources.switch_name -ne $expectedNames.switch -or
        [string]$Plan.resources.nat_name -ne $expectedNames.nat) {
        throw 'T8 resource names do not match the immutable plan identity'
    }
    if ([string]$Plan.resources.switch_type -ne 'Internal') {
        throw 'T8 only permits an Internal Hyper-V switch'
    }
    $expectedGateway = Get-T8GatewayAddress `
        -Prefix ([string]$Plan.resources.prefix)
    if ([string]$Plan.resources.gateway_address -ne $expectedGateway) {
        throw 'T8 gateway address does not match the planned prefix'
    }
    if ([int]$Plan.resources.prefix_length -ne 24) {
        throw 'T8 only permits a /24 fixture prefix'
    }
    foreach ($gateName in @(
            'teardown_prepared',
            'management_route_preserved',
            'management_interface_never_targeted',
            'names_are_unique'
        )) {
        $gate = $Plan.safety.PSObject.Properties[$gateName]
        if ($null -eq $gate -or
            $gate.Value -isnot [bool] -or
            $gate.Value -ne $true) {
            throw "T8 plan safety gate is not strict true: $gateName"
        }
    }
    if ([string]::IsNullOrWhiteSpace(
            [string]$Plan.host_fingerprint_sha256) -or
        [string]$Plan.host_fingerprint_sha256 -notmatch
            '^[0-9a-f]{64}$') {
        throw 'T8 plan host fingerprint is invalid'
    }
    if ((ConvertTo-T8GuidText -Value (
            [string]$Plan.baseline.management_interface_guid)) -ne
        [string]$Plan.baseline.management_interface_guid) {
        throw 'T8 management interface GUID is not canonical'
    }
    if ([int]$Plan.baseline.management_interface_index -le 0) {
        throw 'T8 management interface index is invalid'
    }
    if ([string]$Plan.safety.mutation_model -ne 'additive-only') {
        throw 'T8 plan does not satisfy all pre-mutation safety gates'
    }
    return $true
}

function Assert-T8StateShape {
    param([Parameter(Mandatory = $true)][object]$State)

    $requiredTop = @(
        'schema', 'plan_id', 'plan_hash', 'phase',
        'prepared_at_utc', 'baseline_management_interface_index',
        'created', 'resources'
    )
    $allowedTop = @($requiredTop + @(
        'applied_at_utc', 'completed_at_utc'
    ))
    $topNames = @($State.PSObject.Properties.Name)
    foreach ($name in $requiredTop) {
        if ($topNames -notcontains $name) {
            throw "T8 state is missing property: $name"
        }
    }
    foreach ($name in $topNames) {
        if ($allowedTop -notcontains $name) {
            throw "T8 state contains unexpected property: $name"
        }
    }
    if ([string]$State.schema -ne 'ese.v92.t8-hyperv-state/v1' -or
        [string]$State.plan_id -notmatch '^[0-9a-f]{32}$' -or
        [string]$State.plan_hash -notmatch '^[0-9a-f]{64}$') {
        throw 'T8 state identity or phase is invalid'
    }
    $createdNames = @($State.created.PSObject.Properties.Name)
    $expectedCreated = @('switch', 'gateway_address', 'nat')
    if (@($createdNames).Count -ne $expectedCreated.Count) {
        throw 'T8 state created flags have an invalid shape'
    }
    foreach ($name in $expectedCreated) {
        $property = $State.created.PSObject.Properties[$name]
        if ($null -eq $property -or
            $property.Value -isnot [bool]) {
            throw "T8 state created flag is not Boolean: $name"
        }
    }
    $flagKey = '{0}{1}{2}' -f
        ([int][bool]$State.created.switch),
        ([int][bool]$State.created.gateway_address),
        ([int][bool]$State.created.nat)
    $phaseFlags = @{
        PREPARED = '000'
        SWITCH_CREATED = '100'
        ADDRESS_CREATED = '110'
        APPLIED = '111'
        TEARDOWN_NAT_REMOVED = '110'
        TEARDOWN_ADDRESS_REMOVED = '100'
        TORN_DOWN = '000'
    }
    $phase = [string]$State.phase
    if (-not $phaseFlags.ContainsKey($phase) -or
        $phaseFlags[$phase] -ne $flagKey) {
        throw "T8 state phase/created flags are inconsistent: $phase/$flagKey"
    }
    $resourceNames = @($State.resources.PSObject.Properties.Name)
    $expectedResources = @(
        'switch_id', 'interface_index', 'interface_guid',
        'vm_adapter_device_id'
    )
    if (@($resourceNames).Count -ne $expectedResources.Count) {
        throw 'T8 state resources have an invalid shape'
    }
    foreach ($name in $expectedResources) {
        if ($resourceNames -notcontains $name) {
            throw "T8 state resources are missing property: $name"
        }
    }
    if ([bool]$State.created.switch) {
        $null = ConvertTo-T8GuidText -Value (
            [string]$State.resources.switch_id)
    }
    if ([bool]$State.created.gateway_address) {
        if ([int]$State.resources.interface_index -le 0) {
            throw 'T8 state fixture interface index is invalid'
        }
        $interfaceGuid = ConvertTo-T8GuidText -Value (
            [string]$State.resources.interface_guid)
        $deviceGuid = ConvertTo-T8GuidText -Value (
            [string]$State.resources.vm_adapter_device_id)
        if ($interfaceGuid -ne $deviceGuid) {
            throw 'T8 state adapter identity binding is inconsistent'
        }
    }
    $resourceValues = @(
        $State.resources.switch_id
        $State.resources.interface_index
        $State.resources.interface_guid
        $State.resources.vm_adapter_device_id
    )
    if ($phase -eq 'PREPARED' -and @(
            $resourceValues | Where-Object { $null -ne $_ }
        ).Count -gt 0) {
        throw 'T8 PREPARED state cannot contain created resource identities'
    }
    return $true
}

function Get-T8PlanHash {
    param([Parameter(Mandatory = $true)][object]$Plan)

    $json = $Plan | ConvertTo-Json -Depth 16 -Compress
    return Get-T8Sha256Text -Value $json
}

function New-T8HyperVPlan {
    param(
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[a-z0-9][a-z0-9-]{2,31}$')]
        [string]$RunLabel,
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[0-9a-f]{12}$')]
        [string]$Nonce,
        [Parameter(Mandatory = $true)][int]$ManagementInterfaceIndex,
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[{(]?[0-9a-fA-F-]{32,38}[)}]?$')]
        [string]$ManagementInterfaceGuid,
        [string[]]$UsedPrefixes = @(),
        [string[]]$ExistingSwitchNames = @(),
        [string[]]$ExistingNatNames = @(),
        [object[]]$AdapterInventory = @(),
        [object[]]$RouteInventory = @(),
        [Parameter(Mandatory = $true)][string]$HostFingerprint
    )

    if ($ManagementInterfaceIndex -le 0) {
        throw 'A positive management route interface index is required'
    }
    $names = Get-T8UniqueNames -RunLabel $RunLabel -Nonce $Nonce
    if (@($ExistingSwitchNames | Where-Object {
            $_ -ieq $names.switch
        }).Count -gt 0 -or
        @($ExistingNatNames | Where-Object {
            $_ -ieq $names.nat
        }).Count -gt 0) {
        throw 'Unique T8 resource name collision; generate a new plan'
    }
    $prefix = Select-T8PrivatePrefix -Nonce $Nonce `
        -UsedPrefixes $UsedPrefixes
    $gateway = Get-T8GatewayAddress -Prefix $prefix
    $plan = [pscustomobject][ordered]@{
        schema = 'ese.v92.t8-hyperv-plan/v1'
        plan_id = [Guid]::NewGuid().ToString('N')
        created_at_utc = [DateTime]::UtcNow.ToString(
            'yyyy-MM-ddTHH:mm:ss.fffZ')
        run_label = $RunLabel
        nonce = $Nonce
        host_fingerprint_sha256 = Get-T8Sha256Text -Value $HostFingerprint
        baseline = [pscustomobject][ordered]@{
            management_interface_index = $ManagementInterfaceIndex
            management_interface_guid = ConvertTo-T8GuidText `
                -Value $ManagementInterfaceGuid
            used_prefixes = @($UsedPrefixes | Sort-Object -Unique)
            existing_switch_names = @($ExistingSwitchNames |
                Sort-Object -Unique)
            existing_nat_names = @($ExistingNatNames |
                Sort-Object -Unique)
            adapters = @($AdapterInventory)
            routes = @($RouteInventory)
        }
        resources = [pscustomobject][ordered]@{
            switch_name = $names.switch
            switch_type = 'Internal'
            nat_name = $names.nat
            prefix = $prefix
            gateway_address = $gateway
            prefix_length = 24
        }
        safety = [pscustomobject][ordered]@{
            mutation_model = 'additive-only'
            management_route_preserved = $true
            management_interface_never_targeted = $true
            names_are_unique = $true
            teardown_prepared = $true
        }
        teardown = @(
            'remove exact NAT by recorded name and prefix',
            'remove exact gateway address by recorded interface identity',
            'remove exact Internal switch by recorded Hyper-V identifier'
        )
    }
    $null = Assert-T8PlanShape -Plan $plan
    return $plan
}
