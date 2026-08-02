[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$JobRequestPath
)

$ErrorActionPreference = 'Stop'
$request = Get-Content -LiteralPath $JobRequestPath -Raw |
    ConvertFrom-Json
$jobRoot = Split-Path -Parent $JobRequestPath
$interfaceIndex = [int]$request.interface_index
$addresses = @(
    Get-NetIPAddress -InterfaceIndex $interfaceIndex `
        -AddressFamily IPv4 -ErrorAction Stop |
        Where-Object {
            [string]$_.IPAddress -notmatch '^169\.254\.' -and
            [string]$_.AddressState -ne 'Duplicate'
        } |
        Sort-Object IPAddress |
        ForEach-Object {
            [ordered]@{
                address = [string]$_.IPAddress
                prefix_length = [int]$_.PrefixLength
                interface_index = [int]$_.InterfaceIndex
                interface_alias = [string]$_.InterfaceAlias
                address_state = [string]$_.AddressState
            }
        }
)
if ($addresses.Count -ne 1) {
    throw "Expected one physical IPv4 address, found $($addresses.Count)."
}
$result = [ordered]@{
    schema = 'ese.lab.physical-ipv4-probe/v1'
    status = 'PASS'
    address = [string]$addresses[0].address
    prefix_length = [int]$addresses[0].prefix_length
    interface_index = $interfaceIndex
    interface_alias = [string]$addresses[0].interface_alias
    observed_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
}
$result | ConvertTo-Json -Depth 5 |
    Set-Content -LiteralPath (Join-Path $jobRoot 'ipv4-probe.json') `
        -Encoding UTF8
$result | ConvertTo-Json -Depth 5
