[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
. (Join-Path $PSScriptRoot 'v91_r01_upnp.ps1')

function New-R01UpnpCapacitySummary {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()][object[]]$Entries,
        [Parameter(Mandatory = $true)][bool]$EnumerationComplete,
        [Parameter(Mandatory = $true)][bool]$LimitReached,
        [string]$FailureClass = ''
    )
    $tcp = 0
    $udp = 0
    $finite = 0
    $permanent = 0
    $tailscale = 0
    $eseTagged = 0
    $other = 0
    foreach ($entry in $Entries) {
        if ([string]$entry.Protocol -ceq 'TCP') { $tcp++ }
        elseif ([string]$entry.Protocol -ceq 'UDP') { $udp++ }
        else { throw 'Capacity summary received an invalid protocol.' }
        if ([uint32]$entry.LeaseDuration -eq 0) { $permanent++ }
        else { $finite++ }
        $description = [string]$entry.Description
        if ($description.StartsWith('tailscale-portmap',
                [StringComparison]::OrdinalIgnoreCase)) {
            $tailscale++
        } elseif ($description.StartsWith('eR01-',
                [StringComparison]::Ordinal) -or
            $description.StartsWith('ese-owned',
                [StringComparison]::OrdinalIgnoreCase)) {
            $eseTagged++
        } else { $other++ }
    }
    $valid = $EnumerationComplete -and -not $LimitReached -and
        [string]::IsNullOrEmpty($FailureClass)
    return [pscustomobject][ordered]@{
        schema = 'ese.v91.r01-upnp-capacity/v1'
        status = if ($valid) { 'PASS' } else { 'FAIL' }
        read_only = $true
        enumeration_complete = $EnumerationComplete
        limit_reached = $LimitReached
        failure_class = if ($valid) { $null } else { $FailureClass }
        total = $Entries.Count
        protocols = [pscustomobject][ordered]@{
            TCP = $tcp
            UDP = $udp
        }
        leases = [pscustomobject][ordered]@{
            finite = $finite
            permanent = $permanent
        }
        descriptions = [pscustomobject][ordered]@{
            tailscale_tag_prefix = $tailscale
            ese_tag_prefix = $eseTagged
            other = $other
        }
    }
}

function Invoke-R01UpnpCapacityEnumeration {
    param(
        [Parameter(Mandatory = $true)]$Backend,
        [ValidateRange(1, 256)][int]$MaxEntries = 256
    )
    $entries = [Collections.ArrayList]::new()
    $complete = $false
    $failure = $null
    try {
        for ($index = 0; $index -lt $MaxEntries; $index++) {
            $entry = Get-R01UpnpGenericMappingEntry -Backend $Backend `
                -Index $index
            if ($null -eq $entry) {
                $complete = $true
                break
            }
            $null = $entries.Add($entry)
        }
    } catch { $failure = $_ }
    $limitReached = -not $complete -and $null -eq $failure
    $failureClass = if ($null -ne $failure) {
        'ENUMERATION_FAILED_CLOSED'
    } elseif ($limitReached) { 'ENUMERATION_LIMIT_REACHED' } else { '' }
    return New-R01UpnpCapacitySummary -Entries @($entries) `
        -EnumerationComplete $complete -LimitReached $limitReached `
        -FailureClass $failureClass
}

$defaultRoutes = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' `
    -AddressFamily IPv4 -ErrorAction Stop | Sort-Object RouteMetric)
$selectedRoute = $null
$selectedAdapter = $null
foreach ($route in $defaultRoutes) {
    $adapter = Get-NetAdapter -InterfaceIndex ([int]$route.InterfaceIndex) `
        -ErrorAction SilentlyContinue
    if ($null -ne $adapter -and [bool]$adapter.HardwareInterface -and
        -not [bool]$adapter.Virtual -and [string]$adapter.Status -ceq 'Up') {
        $selectedRoute = $route
        $selectedAdapter = $adapter
        break
    }
}
if ($null -eq $selectedAdapter) {
    throw 'Default IPv4 route is not attached to a physical adapter.'
}
$localAddresses = @(Get-NetIPAddress `
    -InterfaceIndex ([int]$selectedAdapter.ifIndex) -AddressFamily IPv4 `
    -AddressState Preferred -ErrorAction Stop | Where-Object {
        -not [bool]$_.SkipAsSource
    })
if ($localAddresses.Count -ne 1) {
    throw 'Expected exactly one usable local IPv4 address.'
}
$backend = New-R01UpnpBackend `
    -LocalAddress ([string]$localAddresses[0].IPAddress) `
    -GatewayAddress ([string]$selectedRoute.NextHop)

$result = Invoke-R01UpnpCapacityEnumeration -Backend $backend
$result | ConvertTo-Json -Depth 4 -Compress
if ([string]$result.status -cne 'PASS') {
    throw "UPnP mapping enumeration failed closed: $($result.failure_class)."
}
