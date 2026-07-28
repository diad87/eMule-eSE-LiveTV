[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$JobRequestPath
)

$ErrorActionPreference = 'Stop'
$jobRoot = Split-Path -Parent ([IO.Path]::GetFullPath($JobRequestPath))
$jobsRoot = Split-Path -Parent $jobRoot
$kitRoot = Split-Path -Parent $jobsRoot
$runner = Join-Path $kitRoot 'run_v91_i05_downloader_kit.ps1'
if (-not (Test-Path -LiteralPath $runner -PathType Leaf)) {
    throw 'No existe el runner V91-I05 instalado.'
}

$previousLibraryOnly = $env:ESE_V91_I05_LIBRARY_ONLY
try {
    $env:ESE_V91_I05_LIBRARY_ONLY = '1'
    . $runner
} finally {
    $env:ESE_V91_I05_LIBRARY_ONLY = $previousLibraryOnly
}
$address = Get-NetIPAddress -AddressFamily IPv4 |
    Where-Object { $_.IPAddress -ceq '192.168.68.64' } |
    Select-Object -First 1
if ($null -eq $address) {
    throw 'No existe la IPv4 fisica esperada 192.168.68.64.'
}
$adapter = Get-NetAdapter -InterfaceIndex ([int]$address.InterfaceIndex)
$pktmonJson = (& pktmon.exe list --json 2>&1 | ForEach-Object {
        [string]$_
    }) -join "`r`n"
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($pktmonJson)) {
    throw 'pktmon list --json no produjo inventario.'
}
$mapping = Get-I05PktMonComponentMappingFromJson -Json $pktmonJson `
    -InterfaceGuid ([string]$adapter.InterfaceGuid) `
    -InterfaceIndex ([int]$adapter.ifIndex) `
    -MacAddress ([string]$adapter.MacAddress)

[pscustomobject][ordered]@{
    status = 'PASS'
    job_id = (Get-Content -LiteralPath $JobRequestPath -Raw |
        ConvertFrom-Json).job_id
    adapter = [ordered]@{
        name = [string]$adapter.Name
        if_index = [int]$adapter.ifIndex
        interface_guid = [string]$mapping.interface_guid
        mac_address = [string]$mapping.mac_address
    }
    pktmon_mapping = $mapping
} | ConvertTo-Json -Depth 8 -Compress
