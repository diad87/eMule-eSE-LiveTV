[CmdletBinding()]
param(
    [string]$ObservedExternalAddress = '',
    [switch]$MappingOnly
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
. (Join-Path $PSScriptRoot 'v91_r01_upnp.ps1')

function Get-R01IPv4Class {
    param([Parameter(Mandatory = $true)][string]$Address)
    $parsed = $null
    if (-not [Net.IPAddress]::TryParse($Address, [ref]$parsed) -or
        $parsed.AddressFamily -ne
            [Net.Sockets.AddressFamily]::InterNetwork) { return 'invalid' }
    $bytes = $parsed.GetAddressBytes()
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
    if ($special) { return 'special' }
    return 'global'
}

function Get-R01StringSha256 {
    param([Parameter(Mandatory = $true)][string]$Value)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return (($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value)) |
                    ForEach-Object { $_.ToString('x2') }) -join '')
    } finally { $sha.Dispose() }
}

$defaultRoutes = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' `
    -AddressFamily IPv4 -ErrorAction Stop | Sort-Object RouteMetric)
if ($defaultRoutes.Count -lt 1) { throw 'No IPv4 default route.' }
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
        -not [bool]$_.SkipAsSource -and
        (Get-R01IPv4Class -Address ([string]$_.IPAddress)) -in
            @('private', 'global')
    })
if ($localAddresses.Count -ne 1) {
    throw "Expected one usable local IPv4, found $($localAddresses.Count)."
}
$localAddress = [string]$localAddresses[0].IPAddress

$gatewayAddress = [string]$selectedRoute.NextHop
$backend = New-R01UpnpBackend -LocalAddress $localAddress `
    -GatewayAddress $gatewayAddress
$rng = [Security.Cryptography.RandomNumberGenerator]::Create()
$portBytes = New-Object byte[] 2
$externalPort = 0
try {
    for ($attempt = 0; $attempt -lt 64; $attempt++) {
        $rng.GetBytes($portBytes)
        $candidatePort = 49152 + (
            [BitConverter]::ToUInt16($portBytes, 0) % 16384)
        if (@(Get-NetTCPConnection -LocalPort $candidatePort `
                    -ErrorAction SilentlyContinue).Count -ne 0) { continue }
        $existing = Get-R01UpnpMapping -Backend $backend `
            -ExternalPort $candidatePort
        if ($null -eq $existing) {
            $externalPort = $candidatePort
            break
        }
    }
} finally { $rng.Dispose() }
if ($externalPort -eq 0) { throw 'No clean UPnP probe port was found.' }

$nonce = [Guid]::NewGuid().ToString('N')
$description = Get-R01UpnpOwnershipDescription -Nonce $nonce `
    -Role PREFLIGHT -ExternalPort $externalPort `
    -InternalPort $externalPort -InternalClient $localAddress
$mappingCreated = $false
$cleanupComplete = $false
$externalAddress = ''
$listener = [Net.Sockets.TcpListener]::new(
    [Net.IPAddress]::Parse($localAddress), $externalPort)
try {
    $listener.Start(1)
    $created = Add-R01UpnpMapping -Backend $backend `
        -ExternalPort $externalPort -InternalPort $externalPort `
        -InternalClient $localAddress -Description $description
    $current = Get-R01UpnpMapping -Backend $backend `
        -ExternalPort $externalPort
    $mappingCreated = $null -ne $created -and $null -ne $current -and
        [string]$created.Description -ceq $description -and
        [string]$created.InternalClient -ceq $localAddress -and
        [int]$created.InternalPort -eq $externalPort -and
        [bool]$created.Enabled -and
        [string]$current.Description -ceq $description -and
        [string]$current.InternalClient -ceq $localAddress -and
        [int]$current.InternalPort -eq $externalPort -and
        [bool]$current.Enabled
    if (-not $mappingCreated) {
        throw 'UPnP did not return the exact nonce-owned mapping.'
    }
    $externalAddress = [string]$created.ExternalIPAddress
    if (-not [string]::IsNullOrWhiteSpace($ObservedExternalAddress)) {
        if (-not [string]::IsNullOrWhiteSpace($externalAddress) -and
            $externalAddress -cne $ObservedExternalAddress) {
            throw 'Observed public IPv4 differs from the UPnP report.'
        }
        $externalAddress = $ObservedExternalAddress
    }
    if (-not $MappingOnly -and
        (Get-R01IPv4Class -Address $externalAddress) -cne 'global') {
        throw 'No globally routable H1 IPv4 was supplied or reported.'
    }
} finally {
    $currentReadComplete = $true
    try {
        $current = Get-R01UpnpMapping -Backend $backend `
            -ExternalPort $externalPort
    } catch {
        $current = $null
        $currentReadComplete = $false
    }
    if ($null -ne $current -and
        [string]$current.Description -ceq $description -and
        [string]$current.InternalClient -ceq $localAddress -and
        [int]$current.InternalPort -eq $externalPort -and
        [bool]$current.Enabled) {
        Remove-R01UpnpMapping -Backend $backend `
            -ExternalPort $externalPort
    }
    $remainingReadComplete = $true
    try {
        $remaining = Get-R01UpnpMapping -Backend $backend `
            -ExternalPort $externalPort
    } catch {
        $remaining = $null
        $remainingReadComplete = $false
    }
    $cleanupComplete = $currentReadComplete -and
        $remainingReadComplete -and $null -eq $remaining
    try { $listener.Stop() } catch {}
}
if (-not $mappingCreated -or -not $cleanupComplete) {
    throw 'UPnP preflight ownership or cleanup was not complete.'
}

[pscustomobject][ordered]@{
    schema = 'ese.v91.r01-upnp-preflight/v2'
    status = if ($MappingOnly) { 'MAPPING_PASS' } else { 'PASS' }
    formal_endpoint_validated = -not $MappingOnly
    backend = [string]$backend.kind
    physical_adapter = $true
    local_ipv4_class = Get-R01IPv4Class -Address $localAddress
    external_ipv4_class = Get-R01IPv4Class -Address $externalAddress
    external_ipv4_sha256 = if ([string]::IsNullOrWhiteSpace(
            $externalAddress)) { $null } else {
        Get-R01StringSha256 -Value $externalAddress
    }
    exact_nonce_mapping_created = $mappingCreated
    ownership_description_length = $description.Length
    cleanup_complete = $cleanupComplete
    mapping_remaining = $false
} | ConvertTo-Json -Compress
