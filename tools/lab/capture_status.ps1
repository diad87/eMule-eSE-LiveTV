[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidateSet('A', 'B', 'R', 'controller')]
    [string]$NodeRole,
    [string]$BaseUrl = 'http://127.0.0.1:4711',
    [string]$Token = '',
    [string]$OutFile = '',
    [int[]]$TargetProcessIds = @(),
    [switch]$AllowRemoteApi,
    [switch]$AllowUnavailable,
    [switch]$IncludeNetworkInterfaces,
    [switch]$IncludeSensitive
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')

if (-not $OutFile) {
    $OutFile = Join-Path (Get-Location) ('lab-status-{0}.json' -f $NodeRole.ToLowerInvariant())
}

$status = Invoke-LabApi -BaseUrl $BaseUrl -Path '/api/status' -Token $Token `
    -AllowRemoteApi:$AllowRemoteApi -AllowUnavailable:$AllowUnavailable
$krpStatus = Invoke-LabApi -BaseUrl $BaseUrl -Path '/api/krp/status' -Token $Token `
    -AllowRemoteApi:$AllowRemoteApi -AllowUnavailable

$capture = [ordered]@{
    schema = 'ese.lab.status/v1'
    captured_at_utc = Get-LabUtcTimestamp
    node_role = $NodeRole
    api_origin = [ordered]@{
        scheme = ([Uri]$BaseUrl).Scheme
        loopback = ([Uri]$BaseUrl).IsLoopback
    }
    status = $status
    krp_status = $krpStatus
    processes = @(Get-LabProcessSnapshot -TargetProcessIds $TargetProcessIds)
}
if ($IncludeNetworkInterfaces) {
    $capture.network_interfaces = @(Get-LabNetworkInventory -IncludeSensitive:$IncludeSensitive)
}

$safeCapture = ConvertTo-LabSanitizedValue -InputObject $capture `
    -RedactAddresses:(-not $IncludeSensitive)
$writtenPath = Write-LabJson -Value $safeCapture -Path $OutFile
Write-Host "Lab status written: $writtenPath" -ForegroundColor Green
