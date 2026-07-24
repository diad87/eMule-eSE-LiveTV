[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidateRange(1, 2147483647)]
    [int]$TargetProcessId,
    [string]$ExpectedRemoteAddress = '',
    [ValidateRange(0, 65535)][int]$ExpectedRemotePort = 0,
    [ValidateSet('Any', 'IPv4', 'IPv6')][string]$RequiredFamily = 'Any',
    [string]$ForbiddenInterfacePattern = 'Tailscale',
    [ValidateRange(1, 1000)][int]$MinimumConnections = 1,
    [string]$OutFile = '',
    [switch]$IncludeSensitive
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')

if (-not $OutFile) {
    $OutFile = Join-Path (Get-Location) ('lab-route-{0}.json' -f $TargetProcessId)
}

$process = Get-Process -Id $TargetProcessId -ErrorAction SilentlyContinue
if ($null -eq $process) {
    throw "Process $TargetProcessId does not exist"
}

$expectedNormalized = $ExpectedRemoteAddress.Trim('[', ']').Split('%')[0]
$connections = @()
foreach ($socket in @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue)) {
    if ($socket.OwningProcess -ne $TargetProcessId) { continue }

    $localAddress = $socket.LocalAddress.Trim('[', ']').Split('%')[0]
    $remoteAddress = $socket.RemoteAddress.Trim('[', ']').Split('%')[0]
    $remoteNormalized = $remoteAddress
    if ($ExpectedRemoteAddress -and
        -not $remoteNormalized.Equals($expectedNormalized, [StringComparison]::OrdinalIgnoreCase)) {
        continue
    }
    if ($ExpectedRemotePort -gt 0 -and $socket.RemotePort -ne $ExpectedRemotePort) { continue }

    $localClass = Get-LabAddressClass -Address $localAddress
    $family = if ($localClass.EndsWith('-v6')) { 'IPv6' } else { 'IPv4' }
    if ($RequiredFamily -ne 'Any' -and $family -ne $RequiredFamily) { continue }

    $adapter = Get-LabInterfaceForAddress -Address $localAddress
    $adapterText = if ($null -eq $adapter) {
        '<unmapped>'
    } else {
        '{0}|{1}' -f $adapter.name, $adapter.description
    }
    $forbidden = $null -eq $adapter -or $adapterText -match $ForbiddenInterfacePattern

    $item = [ordered]@{
        state = 'ESTABLISHED'
        family = $family
        local_address_class = $localClass
        local_port = $socket.LocalPort
        remote_address_class = Get-LabAddressClass -Address $remoteAddress
        remote_port = $socket.RemotePort
        interface_id = if ($null -eq $adapter) {
            $null
        } else {
            Get-LabInterfaceId -Id $adapter.id `
                -Name $adapter.name -Description $adapter.description
        }
        interface_forbidden = [bool]$forbidden
    }
    if ($IncludeSensitive) {
        $item.local_address = $localAddress
        $item.remote_address = $remoteAddress
        $item.interface_name = if ($null -eq $adapter) { $null } else { $adapter.name }
        $item.interface_description = if ($null -eq $adapter) { $null } else { $adapter.description }
    }
    $connections += [pscustomobject]$item
}

$forbiddenConnections = @($connections | Where-Object { $_.interface_forbidden })
$passed = $connections.Count -ge $MinimumConnections -and $forbiddenConnections.Count -eq 0
$reason = if ($connections.Count -lt $MinimumConnections) {
    "Found $($connections.Count) matching established connection(s); required $MinimumConnections"
} elseif ($forbiddenConnections.Count -gt 0) {
    "Found $($forbiddenConnections.Count) matching connection(s) on a forbidden interface"
} else {
    'Matching TCP data route is active and avoids the forbidden interface'
}

$report = [ordered]@{
    schema = 'ese.lab.route-assertion/v1'
    captured_at_utc = Get-LabUtcTimestamp
    process_id = $TargetProcessId
    process_name = $process.ProcessName
    expected = [ordered]@{
        remote_address_class = if ($ExpectedRemoteAddress) {
            Get-LabAddressClass -Address $ExpectedRemoteAddress
        } else {
            'any'
        }
        remote_port = if ($ExpectedRemotePort -gt 0) { $ExpectedRemotePort } else { 'any' }
        family = $RequiredFamily
        minimum_connections = $MinimumConnections
        forbidden_interface_pattern = $ForbiddenInterfacePattern
    }
    matching_connections = $connections
    verdict = if ($passed) { 'PASS' } else { 'FAIL' }
    reason = $reason
    limitation = 'This assertion proves the route of established TCP sockets. UDP requires packet-capture evidence.'
}

$writtenPath = Write-LabJson -Value $report -Path $OutFile
if (-not $passed) {
    throw "Data-route assertion FAIL: $reason (report: $writtenPath)"
}
Write-Host "Data-route assertion PASS: $writtenPath" -ForegroundColor Green
