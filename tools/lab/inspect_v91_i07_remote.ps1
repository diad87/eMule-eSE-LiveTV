[CmdletBinding()]
param(
    [string]$JobRequestPath = '',
    [switch]$SelfTest
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
. (Join-Path $PSScriptRoot 'v91_i07_common.ps1')

if ($SelfTest) {
    Invoke-I07SelfTest
    exit 0
}
if ([string]::IsNullOrWhiteSpace($JobRequestPath) -or
    -not (Test-Path -LiteralPath $JobRequestPath -PathType Leaf)) {
    throw 'JobRequestPath is required.'
}

$parsedRequest = Get-Content -LiteralPath $JobRequestPath -Raw |
    ConvertFrom-Json
$requestProperty = $parsedRequest.PSObject.Properties['request']
$request = if ($null -ne $requestProperty) {
    $requestProperty.Value
} else { $parsedRequest }
$jobRoot = Split-Path -Parent ([IO.Path]::GetFullPath($JobRequestPath))
$resultPath = Join-Path $jobRoot 'result.json'

$target = if ($null -ne $request.PSObject.Properties['route_target_ipv6']) {
    [string]$request.route_target_ipv6
} else { '' }
if ([string]::IsNullOrWhiteSpace($target)) {
    throw 'route_target_ipv6 is required.'
}
$candidateSha = if (
    $null -ne $request.PSObject.Properties['candidate_sha256']) {
    ([string]$request.candidate_sha256).ToLowerInvariant()
} else { '' }
$role = if ($null -ne $request.PSObject.Properties['role']) {
    ([string]$request.role).ToLowerInvariant()
} else { '' }
$nonce = if ($null -ne $request.PSObject.Properties['nonce']) {
    ([string]$request.nonce).ToLowerInvariant()
} else { '' }
if (-not [string]::IsNullOrWhiteSpace($candidateSha) -and
    $candidateSha -notmatch '^[0-9a-f]{64}$') {
    throw 'candidate_sha256 is invalid.'
}
if ($role -notin @('source', 'viewer') -or
    $nonce -notmatch '^[0-9a-f]{32}$' -or
    $candidateSha -notmatch '^[0-9a-f]{64}$') {
    throw 'I07 preflight role/nonce/candidate contract is invalid.'
}

$inventory = @(
    Get-NetIPAddress -AddressFamily IPv6 -ErrorAction Stop |
        Where-Object { $_.AddressState -notin @('Invalid', 'Duplicate') } |
        ForEach-Object {
            $addressText = ''
            $class = 'invalid'
            try {
                $addressText = ConvertTo-I07CanonicalIPv6 `
                    -Value ([string]$_.IPAddress)
                $class = Get-I07IPv6Class `
                    -Address ([Net.IPAddress]::Parse($addressText))
            } catch {
                $addressText = [string]$_.IPAddress
            }
            $adapter = Get-NetAdapter -InterfaceIndex ([int]$_.InterfaceIndex) `
                -IncludeHidden -ErrorAction Stop
            [ordered]@{
                address = $addressText
                class = $class
                prefix_length = [int]$_.PrefixLength
                state = [string]$_.AddressState
                prefix_origin = [string]$_.PrefixOrigin
                suffix_origin = [string]$_.SuffixOrigin
                interface_index = [int]$_.InterfaceIndex
                interface_alias = [string]$_.InterfaceAlias
                interface_guid = [string](Get-I07PropertyValue `
                    -Object $adapter -Name 'InterfaceGuid' -Default '')
                interface_description = [string](Get-I07PropertyValue `
                    -Object $adapter -Name 'InterfaceDescription' -Default '')
                hardware_interface = [bool](Get-I07PropertyValue `
                    -Object $adapter -Name 'HardwareInterface' -Default $false)
                virtual = [bool](Get-I07PropertyValue -Object $adapter `
                    -Name 'Virtual' -Default $true)
                overlay = if ($null -eq $adapter) {
                    $null
                } else { Test-I07OverlayAdapter -Adapter $adapter }
            }
        }
)

$route = Get-I07NativeRouteEvidence -RemoteIPv6 $target
$valid = [bool]$route.valid
$selectedRoute = [ordered]@{
    captured_at_utc = [string]$route.captured_at_utc
    valid = $valid
    source_address = [string]$route.source_address
    remote_address = [string]$route.remote_address
    source_class = [string]$route.source_class
    remote_class = [string]$route.remote_class
    interface_index = [int]$route.interface_index
    interface_guid = [string]$route.interface_guid
    hardware_interface = [bool]$route.hardware_interface
    virtual = [bool]$route.virtual
    overlay = [bool]$route.overlay
    default_route_present = [bool]$route.default_route_present
    address_state = [string]$route.address_state
}
$classCounts = [ordered]@{}
foreach ($class in @($inventory | ForEach-Object { [string]$_.class } |
        Sort-Object -Unique)) {
    $classCounts[$class] = @($inventory | Where-Object {
            [string]$_.class -ceq $class
        }).Count
}
$eligibleCount = @($inventory | Where-Object {
        $_.class -ceq 'global-native' -and
        $_.hardware_interface -and -not $_.virtual -and -not $_.overlay
    }).Count
$result = [ordered]@{
    schema = 'ese.v91.i07-preflight/v2'
    case_id = 'V91-I07'
    status = if ($valid) { 'PREFLIGHT_PASS' } else { 'LAB_BLOCKED' }
    created_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
    role = $role
    nonce = if ($null -ne $request.PSObject.Properties['nonce']) {
        $nonce
    } else { '' }
    candidate_sha256 = $candidateSha
    selected_route = $selectedRoute
    inventory_summary = [ordered]@{
        address_count = $inventory.Count
        class_counts = $classCounts
        eligible_native_global_count = $eligibleCount
    }
    checks = [ordered]@{
        selected_source_is_global_native =
            [string]$route.source_class -ceq 'global-native'
        selected_interface_is_hardware = [bool]$route.hardware_interface
        selected_interface_is_virtual = [bool]$route.virtual
        selected_interface_is_overlay = [bool]$route.overlay
        default_route_on_selected_interface =
            [bool]$route.default_route_present
        selected_route_is_native = $valid
    }
    limitation_code = if ($valid) { $null } else { 'NATIVE_ROUTE_NOT_PROVEN' }
}

Write-I07JsonAtomic -Value $result -Path $resultPath
if (-not $valid) {
    Write-Error 'No native delegated global IPv6 address and route were proven.'
    exit 2
}
exit 0
