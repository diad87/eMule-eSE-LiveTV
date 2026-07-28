[CmdletBinding(DefaultParameterSetName = 'Plan')]
param(
    [Parameter(ParameterSetName = 'Plan')]
    [ValidatePattern('^[a-z0-9][a-z0-9-]{2,31}$')]
    [string]$RunLabel = 'v92-t8',

    [Parameter(Mandatory = $true, ParameterSetName = 'Plan')]
    [string]$PlanPath,

    [Parameter(Mandatory = $true, ParameterSetName = 'Apply')]
    [switch]$Apply,

    [Parameter(Mandatory = $true, ParameterSetName = 'Teardown')]
    [switch]$Teardown,

    [Parameter(Mandatory = $true, ParameterSetName = 'Apply')]
    [Parameter(Mandatory = $true, ParameterSetName = 'Teardown')]
    [string]$ExistingPlanPath,

    [Parameter(Mandatory = $true, ParameterSetName = 'Apply')]
    [Parameter(Mandatory = $true, ParameterSetName = 'Teardown')]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$ExpectedPlanHash,

    [Parameter(Mandatory = $true, ParameterSetName = 'Apply')]
    [Parameter(Mandatory = $true, ParameterSetName = 'Teardown')]
    [string]$StatePath
)

$ErrorActionPreference = 'Stop'
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $scriptRoot 'common.ps1')
. (Join-Path $scriptRoot 't8_hyperv_common.ps1')

function Assert-T8JsonPath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [switch]$MustExist
    )

    $full = [IO.Path]::GetFullPath($Path)
    $root = [IO.Path]::GetPathRoot($full)
    if ($full -eq $root -or
        [IO.Path]::GetExtension($full) -ine '.json') {
        throw "T8 artifact path must be a non-root .json file: $Path"
    }
    if ($MustExist -and
        -not (Test-Path -LiteralPath $full -PathType Leaf)) {
        throw "T8 artifact does not exist: $full"
    }
    if (Test-Path -LiteralPath $full) {
        $item = Get-Item -LiteralPath $full -Force
        if (($item.Attributes -band
                [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "T8 artifact cannot be a reparse point: $full"
        }
    }
    return $full
}

function Get-T8LiveInventory {
    $requiredCommands = @(
        'Get-VMSwitch', 'New-VMSwitch', 'Remove-VMSwitch',
        'Get-VMNetworkAdapter',
        'Get-NetAdapter', 'Get-NetRoute', 'Get-NetIPAddress',
        'New-NetIPAddress', 'Remove-NetIPAddress',
        'Get-NetNat', 'New-NetNat', 'Remove-NetNat'
    )
    $missing = @($requiredCommands | Where-Object {
        -not (Get-Command $_ -ErrorAction SilentlyContinue)
    })
    if ($missing.Count -gt 0) {
        throw 'Missing required Hyper-V/network commands: ' +
            ($missing -join ', ')
    }

    $defaultRoutes = @(Get-NetRoute -AddressFamily IPv4 `
        -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop |
        Sort-Object RouteMetric, InterfaceMetric)
    if ($defaultRoutes.Count -ne 1) {
        throw (
            'T8 requires exactly one unambiguous IPv4 default route; found ' +
            $defaultRoutes.Count)
    }
    $managementIndex = [int]$defaultRoutes[0].InterfaceIndex
    $managementAdapter = Get-NetAdapter -InterfaceIndex $managementIndex `
        -ErrorAction Stop
    if ($null -eq $managementAdapter -or
        [string]$managementAdapter.Status -ne 'Up') {
        throw 'The management-route adapter is not available and Up'
    }

    $routes = @(Get-NetRoute -AddressFamily IPv4 -ErrorAction Stop)
    $routePrefixes = @($routes | ForEach-Object {
        [string]$_.DestinationPrefix
    } | Where-Object {
        $_ -ne '0.0.0.0/0' -and
        $_ -match '^\d{1,3}(?:\.\d{1,3}){3}/(?:\d|[12]\d|3[0-2])$'
    } | Sort-Object -Unique)
    $switches = @(Get-VMSwitch -ErrorAction Stop)
    $nats = @(Get-NetNat -ErrorAction Stop)
    $natPrefixes = @($nats | ForEach-Object {
        [string]$_.InternalIPInterfaceAddressPrefix
    } | Where-Object {
        $_ -match '^\d{1,3}(?:\.\d{1,3}){3}/(?:\d|[12]\d|3[0-2])$'
    })
    $usedPrefixes = @($routePrefixes + $natPrefixes |
        Sort-Object -Unique)
    $adapters = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop)
    $adapterInventory = @($adapters | ForEach-Object {
        [pscustomobject][ordered]@{
            interface_index = [int]$_.InterfaceIndex
            interface_guid = ([string]$_.InterfaceGuid).ToLowerInvariant()
            name = [string]$_.Name
            interface_description = [string]$_.InterfaceDescription
            status = [string]$_.Status
            mac_address = [string]$_.MacAddress
        }
    })
    $routeInventory = @($routes | ForEach-Object {
        [pscustomobject][ordered]@{
            destination_prefix = [string]$_.DestinationPrefix
            next_hop = [string]$_.NextHop
            interface_index = [int]$_.InterfaceIndex
            route_metric = [int]$_.RouteMetric
            protocol = [string]$_.Protocol
        }
    })
    $hostSource = @(
        [Environment]::MachineName,
        [Environment]::OSVersion.VersionString,
        [string]$managementAdapter.InterfaceGuid
    ) -join '|'
    return [pscustomobject][ordered]@{
        management_interface_index = $managementIndex
        management_interface_guid = ConvertTo-T8GuidText `
            -Value ([string]$managementAdapter.InterfaceGuid)
        used_prefixes = $usedPrefixes
        switch_names = @($switches | ForEach-Object { [string]$_.Name })
        nat_names = @($nats | ForEach-Object { [string]$_.Name })
        adapter_guids = @($adapters | ForEach-Object {
            [string]$_.InterfaceGuid
        })
        adapters = $adapterInventory
        routes = $routeInventory
        host_fingerprint = $hostSource
    }
}

function Read-T8Plan {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedHash
    )

    $full = Assert-T8JsonPath -Path $Path -MustExist
    $plan = Get-Content -LiteralPath $full -Raw | ConvertFrom-Json
    $null = Assert-T8PlanShape -Plan $plan
    $actualHash = Get-T8PlanHash -Plan $plan
    if ($actualHash -cne $ExpectedHash) {
        throw "T8 plan hash mismatch: actual=$actualHash"
    }
    return $plan
}

function Test-T8Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Write-T8State {
    param(
        [Parameter(Mandatory = $true)][object]$State,
        [Parameter(Mandatory = $true)][string]$Path
    )
    $target = Assert-T8JsonPath -Path $Path
    $null = Write-LabJson -Value $State -Path $target -Depth 16
}

function Assert-T8BaselineStillSafe {
    param([Parameter(Mandatory = $true)][object]$Plan)

    $inventory = Get-T8LiveInventory
    if ($inventory.management_interface_index -ne
        [int]$Plan.baseline.management_interface_index) {
        throw 'Management route changed after planning; create a new T8 plan'
    }
    if ([string]$inventory.management_interface_guid -ne
        [string]$Plan.baseline.management_interface_guid) {
        throw 'Management adapter identity changed; create a new T8 plan'
    }
    if ((Get-T8Sha256Text -Value $inventory.host_fingerprint) -cne
        [string]$Plan.host_fingerprint_sha256) {
        throw 'Host identity changed after planning; create a new T8 plan'
    }
    if (@($inventory.switch_names | Where-Object {
            $_ -ieq [string]$Plan.resources.switch_name
        }).Count -gt 0 -or
        @($inventory.nat_names | Where-Object {
            $_ -ieq [string]$Plan.resources.nat_name
        }).Count -gt 0) {
        throw 'A planned T8 resource name now exists; refusing mutation'
    }
    foreach ($prefix in $inventory.used_prefixes) {
        if (Test-T8PrefixOverlap `
                -Left ([string]$Plan.resources.prefix) -Right $prefix) {
            throw "The planned T8 prefix now overlaps route $prefix"
        }
    }
    return $inventory
}

function Assert-T8ManagementBaseline {
    param([Parameter(Mandatory = $true)][object]$Plan)

    $defaultRoutes = @(Get-NetRoute -AddressFamily IPv4 `
        -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop |
        Sort-Object RouteMetric, InterfaceMetric)
    if ($defaultRoutes.Count -ne 1 -or
        [int]$defaultRoutes[0].InterfaceIndex -ne
            [int]$Plan.baseline.management_interface_index) {
        throw 'T8 management route changed; refusing destructive action'
    }
    $adapter = Get-NetAdapter -InterfaceIndex `
        ([int]$Plan.baseline.management_interface_index) -ErrorAction Stop
    $actualGuid = ConvertTo-T8GuidText `
        -Value ([string]$adapter.InterfaceGuid)
    if ($actualGuid -ne
        [string]$Plan.baseline.management_interface_guid -or
        [string]$adapter.Status -ne 'Up') {
        throw 'T8 management adapter changed; refusing destructive action'
    }
    return $true
}

function Get-T8BoundFixtureAdapter {
    param(
        [Parameter(Mandatory = $true)][object]$Plan,
        [Parameter(Mandatory = $true)][object]$State,
        [switch]$AllowAbsent
    )

    if ([int]$State.resources.interface_index -eq
            [int]$Plan.baseline.management_interface_index -or
        [string]$State.resources.interface_guid -eq
            [string]$Plan.baseline.management_interface_guid) {
        throw 'T8 state targets the management adapter'
    }
    $baselineAdapterGuids = @($Plan.baseline.adapters | ForEach-Object {
        [string]$_.interface_guid
    })
    if ($baselineAdapterGuids -contains
        [string]$State.resources.interface_guid) {
        throw 'T8 state targets an adapter that existed before the fixture'
    }
    $switch = @(Get-VMSwitch -Name `
        ([string]$Plan.resources.switch_name) `
        -ErrorAction SilentlyContinue)
    if ($switch.Count -eq 0 -and $AllowAbsent) { return $null }
    if ($switch.Count -ne 1 -or
        [string]$switch[0].Id -ne
            [string]$State.resources.switch_id -or
        [string]$switch[0].SwitchType -ne 'Internal') {
        throw 'T8 fixture switch identity/type mismatch'
    }
    $vmAdapters = @(Get-VMNetworkAdapter -ManagementOS `
        -SwitchName ([string]$Plan.resources.switch_name) `
        -ErrorAction Stop)
    if ($vmAdapters.Count -ne 1) {
        throw 'T8 switch does not have exactly one management-OS adapter'
    }
    $deviceGuid = ConvertTo-T8GuidText `
        -Value ([string]$vmAdapters[0].DeviceId)
    if ($deviceGuid -ne
            [string]$State.resources.vm_adapter_device_id -or
        $deviceGuid -ne [string]$State.resources.interface_guid) {
        throw 'T8 switch-to-adapter binding mismatch'
    }
    $adapter = Get-NetAdapter -InterfaceIndex `
        ([int]$State.resources.interface_index) `
        -ErrorAction SilentlyContinue
    if ($null -eq $adapter) {
        if ($AllowAbsent) { return $null }
        throw 'T8 fixture adapter is absent'
    }
    if ((ConvertTo-T8GuidText -Value (
            [string]$adapter.InterfaceGuid)) -ne $deviceGuid) {
        throw 'T8 interface index no longer belongs to the fixture adapter'
    }
    return $adapter
}

function Invoke-T8Teardown {
    param(
        [Parameter(Mandatory = $true)][object]$Plan,
        [Parameter(Mandatory = $true)][object]$State,
        [Parameter(Mandatory = $true)][string]$OutputPath
    )

    $null = Assert-T8StateShape -State $State
    if ([string]$State.plan_id -cne [string]$Plan.plan_id -or
        [string]$State.plan_hash -cne (Get-T8PlanHash -Plan $Plan)) {
        throw 'T8 state does not belong to the supplied immutable plan'
    }
    $unexpectedNat = @(Get-NetNat -Name `
        ([string]$Plan.resources.nat_name) `
        -ErrorAction SilentlyContinue)
    if (-not [bool]$State.created.nat -and
        $unexpectedNat.Count -gt 0) {
        throw 'T8 state says NAT absent but the planned NAT name exists'
    }
    $unexpectedSwitch = @(Get-VMSwitch -Name `
        ([string]$Plan.resources.switch_name) `
        -ErrorAction SilentlyContinue)
    if (-not [bool]$State.created.switch -and
        $unexpectedSwitch.Count -gt 0) {
        throw 'T8 state says switch absent but the planned switch name exists'
    }
    $unexpectedAddress = @(Get-NetIPAddress -AddressFamily IPv4 `
        -IPAddress ([string]$Plan.resources.gateway_address) `
        -ErrorAction SilentlyContinue)
    if (-not [bool]$State.created.gateway_address -and
        $unexpectedAddress.Count -gt 0) {
        throw 'T8 state says gateway absent but the planned address exists'
    }

    if ([bool]$State.created.nat) {
        $null = Assert-T8ManagementBaseline -Plan $Plan
        $nat = @(Get-NetNat -Name ([string]$Plan.resources.nat_name) `
            -ErrorAction SilentlyContinue)
        if ($nat.Count -gt 1 -or
            ($nat.Count -eq 1 -and
             [string]$nat[0].InternalIPInterfaceAddressPrefix -cne
                [string]$Plan.resources.prefix)) {
            throw 'T8 NAT identity/prefix mismatch during teardown'
        }
        if ($nat.Count -eq 1) {
            Remove-NetNat -Name ([string]$Plan.resources.nat_name) `
                -Confirm:$false -ErrorAction Stop
        }
        $State.created.nat = $false
        $State.phase = 'TEARDOWN_NAT_REMOVED'
        Write-T8State -State $State -Path $OutputPath
    }

    if ([bool]$State.created.gateway_address) {
        $null = Assert-T8ManagementBaseline -Plan $Plan
        $adapter = Get-T8BoundFixtureAdapter -Plan $Plan `
            -State $State -AllowAbsent
        if ($null -eq $adapter) {
            throw (
                'T8 fixture adapter/switch is absent while its gateway ' +
                'address is still marked present')
        }
        $address = @(Get-NetIPAddress -InterfaceIndex `
            ([int]$State.resources.interface_index) -AddressFamily IPv4 `
            -IPAddress ([string]$Plan.resources.gateway_address) `
            -ErrorAction SilentlyContinue)
        if ($address.Count -gt 1) {
            throw 'Ambiguous T8 gateway address during teardown'
        }
        if ($address.Count -eq 1) {
            Remove-NetIPAddress -InterfaceIndex `
                ([int]$State.resources.interface_index) `
                -IPAddress ([string]$Plan.resources.gateway_address) `
                -Confirm:$false -ErrorAction Stop
        }
        $State.created.gateway_address = $false
        $State.phase = 'TEARDOWN_ADDRESS_REMOVED'
        Write-T8State -State $State -Path $OutputPath
    }

    if ([bool]$State.created.switch) {
        $null = Assert-T8ManagementBaseline -Plan $Plan
        $switch = @(Get-VMSwitch -Name `
            ([string]$Plan.resources.switch_name) `
            -ErrorAction SilentlyContinue)
        if ($switch.Count -gt 1 -or
            ($switch.Count -eq 1 -and
             [string]$switch[0].Id -cne
                [string]$State.resources.switch_id)) {
            throw 'T8 switch identity mismatch during teardown'
        }
        if ($switch.Count -eq 1) {
            Remove-VMSwitch -Name ([string]$Plan.resources.switch_name) `
                -Force -Confirm:$false -ErrorAction Stop
        }
        $State.created.switch = $false
        $State.phase = 'TORN_DOWN'
        Write-T8State -State $State -Path $OutputPath
    }

    $State.phase = 'TORN_DOWN'
    $State.completed_at_utc = Get-LabUtcTimestamp
    Write-T8State -State $State -Path $OutputPath
    return $State
}

if ($PSCmdlet.ParameterSetName -eq 'Plan') {
    $target = Assert-T8JsonPath -Path $PlanPath
    if (Test-Path -LiteralPath $target) {
        throw "Refusing to overwrite an existing T8 plan: $target"
    }
    $inventory = Get-T8LiveInventory
    $nonce = [Guid]::NewGuid().ToString('N').Substring(0, 12)
    $plan = New-T8HyperVPlan -RunLabel $RunLabel -Nonce $nonce `
        -ManagementInterfaceIndex $inventory.management_interface_index `
        -ManagementInterfaceGuid $inventory.management_interface_guid `
        -UsedPrefixes $inventory.used_prefixes `
        -ExistingSwitchNames $inventory.switch_names `
        -ExistingNatNames $inventory.nat_names `
        -AdapterInventory $inventory.adapters `
        -RouteInventory $inventory.routes `
        -HostFingerprint $inventory.host_fingerprint
    $null = Write-LabJson -Value $plan -Path $target -Depth 16
    $plan = Get-Content -LiteralPath $target -Raw | ConvertFrom-Json
    $null = Assert-T8PlanShape -Plan $plan
    $result = [pscustomobject][ordered]@{
        schema = 'ese.v92.t8-hyperv-result/v1'
        operation = 'plan'
        verdict = 'PASS'
        plan_path = $target
        plan_hash = Get-T8PlanHash -Plan $plan
        plan_id = $plan.plan_id
        management_interface_index = $plan.baseline.management_interface_index
        resources = $plan.resources
        mutation_performed = $false
    }
    $result | ConvertTo-Json -Depth 8
    exit 0
}

if (-not (Test-T8Administrator)) {
    throw 'T8 Apply/Teardown requires an elevated PowerShell session'
}

$plan = Read-T8Plan -Path $ExistingPlanPath `
    -ExpectedHash $ExpectedPlanHash
$stateTarget = Assert-T8JsonPath -Path $StatePath

if ($PSCmdlet.ParameterSetName -eq 'Teardown') {
    if (-not (Test-Path -LiteralPath $stateTarget -PathType Leaf)) {
        throw "T8 teardown state does not exist: $stateTarget"
    }
    $state = Get-Content -LiteralPath $stateTarget -Raw | ConvertFrom-Json
    $state = Invoke-T8Teardown -Plan $plan -State $state `
        -OutputPath $stateTarget
    [pscustomobject][ordered]@{
        schema = 'ese.v92.t8-hyperv-result/v1'
        operation = 'teardown'
        verdict = 'PASS'
        plan_id = $plan.plan_id
        phase = $state.phase
    } | ConvertTo-Json -Depth 6
    exit 0
}

if (Test-Path -LiteralPath $stateTarget) {
    throw "Refusing to overwrite existing T8 state: $stateTarget"
}
$before = Assert-T8BaselineStillSafe -Plan $plan
$state = [pscustomobject][ordered]@{
    schema = 'ese.v92.t8-hyperv-state/v1'
    plan_id = $plan.plan_id
    plan_hash = Get-T8PlanHash -Plan $plan
    phase = 'PREPARED'
    prepared_at_utc = Get-LabUtcTimestamp
    applied_at_utc = $null
    completed_at_utc = $null
    baseline_management_interface_index =
        $before.management_interface_index
    created = [pscustomobject][ordered]@{
        switch = $false
        gateway_address = $false
        nat = $false
    }
    resources = [pscustomobject][ordered]@{
        switch_id = $null
        interface_index = $null
        interface_guid = $null
        vm_adapter_device_id = $null
    }
}
Write-T8State -State $state -Path $stateTarget

try {
    $switch = New-VMSwitch -Name ([string]$plan.resources.switch_name) `
        -SwitchType Internal -ErrorAction Stop
    $state.resources.switch_id = [string]$switch.Id
    $state.created.switch = $true
    $state.phase = 'SWITCH_CREATED'
    Write-T8State -State $state -Path $stateTarget

    $vmAdapters = @(Get-VMNetworkAdapter -ManagementOS `
        -SwitchName ([string]$plan.resources.switch_name) `
        -ErrorAction Stop)
    if ($vmAdapters.Count -ne 1) {
        throw 'T8 expected one management-OS adapter on the new switch'
    }
    $deviceGuid = ConvertTo-T8GuidText `
        -Value ([string]$vmAdapters[0].DeviceId)
    $afterAdapters = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop)
    $fixtureAdapters = @($afterAdapters | Where-Object {
        $candidateGuid = ConvertTo-T8GuidText `
            -Value ([string]$_.InterfaceGuid)
        $before.adapter_guids -notcontains [string]$_.InterfaceGuid -and
            $candidateGuid -eq $deviceGuid
    })
    if ($fixtureAdapters.Count -ne 1) {
        throw (
            'T8 expected exactly one new adapter bound to DeviceId; found ' +
            $fixtureAdapters.Count)
    }
    $fixtureAdapter = $fixtureAdapters[0]
    $interfaceGuid = ConvertTo-T8GuidText `
        -Value ([string]$fixtureAdapter.InterfaceGuid)
    if ([int]$fixtureAdapter.InterfaceIndex -eq
            [int]$plan.baseline.management_interface_index -or
        $interfaceGuid -ne $deviceGuid) {
        throw 'T8 could not bind the new adapter to the new switch'
    }
    $state.resources.interface_index = [int]$fixtureAdapter.InterfaceIndex
    $state.resources.interface_guid = $interfaceGuid
    $state.resources.vm_adapter_device_id = $deviceGuid

    $null = New-NetIPAddress -InterfaceIndex `
        ([int]$fixtureAdapter.InterfaceIndex) `
        -IPAddress ([string]$plan.resources.gateway_address) `
        -PrefixLength ([int]$plan.resources.prefix_length) `
        -AddressFamily IPv4 -ErrorAction Stop
    $state.created.gateway_address = $true
    $state.phase = 'ADDRESS_CREATED'
    Write-T8State -State $state -Path $stateTarget

    $null = New-NetNat -Name ([string]$plan.resources.nat_name) `
        -InternalIPInterfaceAddressPrefix ([string]$plan.resources.prefix) `
        -ErrorAction Stop
    $state.created.nat = $true
    $state.phase = 'APPLIED'
    $state.applied_at_utc = Get-LabUtcTimestamp
    Write-T8State -State $state -Path $stateTarget
} catch {
    $applyError = $_
    try {
        $null = Invoke-T8Teardown -Plan $plan -State $state `
            -OutputPath $stateTarget
    } catch {
        throw (
            'T8 apply failed and automatic teardown also failed. ' +
            'Apply error: ' + $applyError.Exception.Message +
            '; teardown error: ' + $_.Exception.Message)
    }
    throw ('T8 apply failed; automatic teardown completed: ' +
        $applyError.Exception.Message)
}

[pscustomobject][ordered]@{
    schema = 'ese.v92.t8-hyperv-result/v1'
    operation = 'apply'
    verdict = 'PASS'
    plan_id = $plan.plan_id
    phase = $state.phase
    resources = $plan.resources
} | ConvertTo-Json -Depth 8
