[CmdletBinding()]
param(
    [ValidateSet('A', 'B', 'R', 'N1', 'controller', 'unassigned')]
    [string]$NodeRole = 'unassigned',
    [string]$OutFile = '',
    [string]$ApiBase = '',
    [string]$ApiToken = '',
    [string]$PackagePath = '',
    [switch]$AllowRemoteApi,
    [switch]$IncludeSensitive
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')

if (-not $OutFile) {
    $OutFile = Join-Path (Get-Location) ('lab-inventory-{0}.json' -f $NodeRole.ToLowerInvariant())
}

$toolNames = @('powershell', 'git', 'python', 'node', 'npm', 'tshark', 'pktmon', 'netsh')
$tools = @()
foreach ($toolName in $toolNames) {
    $command = Get-Command $toolName -ErrorAction SilentlyContinue | Select-Object -First 1
    $item = [ordered]@{
        name = $toolName
        available = $null -ne $command
    }
    if ($null -ne $command) {
        $item.command_type = $command.CommandType.ToString()
        $item.executable_name = Split-Path -Leaf $command.Source
    }
    $tools += [pscustomobject]$item
}

$machineSeed = '{0}|{1}|{2}' -f $env:COMPUTERNAME, [Environment]::OSVersion.VersionString, $env:PROCESSOR_ARCHITECTURE
$candidateBuild = $null
if ($PackagePath) {
    $resolvedPackagePath = (Resolve-Path -LiteralPath $PackagePath).Path
    if (-not (Test-Path -LiteralPath $resolvedPackagePath -PathType Container)) {
        throw "PackagePath is not a directory: $PackagePath"
    }
    $candidateBuild = [ordered]@{
        package_name = Split-Path -Leaf $resolvedPackagePath
        version = $null
        commit = $null
        files = [ordered]@{}
    }
    foreach ($relativeFile in @('BUILD_INFO.txt', 'emule.exe', 'ese-server.exe')) {
        $candidateFile = Join-Path $resolvedPackagePath $relativeFile
        if (Test-Path -LiteralPath $candidateFile -PathType Leaf) {
            $candidateBuild.files[$relativeFile] = [ordered]@{
                bytes = (Get-Item -LiteralPath $candidateFile).Length
                sha256 = Get-LabSha256 -Path $candidateFile
            }
        }
    }
    $buildInfoPath = Join-Path $resolvedPackagePath 'BUILD_INFO.txt'
    if (Test-Path -LiteralPath $buildInfoPath -PathType Leaf) {
        $buildInfoText = Get-Content -LiteralPath $buildInfoPath -Raw
        $versionMatch = [regex]::Match(
            $buildInfoText,
            '(?im)^\s*(?:version|release|tag)\s*[:=]\s*(\S+)\s*$'
        )
        if ($versionMatch.Success) { $candidateBuild.version = $versionMatch.Groups[1].Value }
        $commitMatch = [regex]::Match(
            $buildInfoText,
            '(?im)^\s*(?:commit|git(?:\s+sha)?)\s*[:=]\s*([0-9a-f]{7,64})\s*$'
        )
        if ($commitMatch.Success) { $candidateBuild.commit = $commitMatch.Groups[1].Value }
    }
}
$api = $null
if ($ApiBase) {
    $api = Invoke-LabApi -BaseUrl $ApiBase -Path '/api/status' -Token $ApiToken `
        -AllowRemoteApi:$AllowRemoteApi -AllowUnavailable
}

$inventory = [ordered]@{
    schema = 'ese.lab.inventory/v1'
    captured_at_utc = Get-LabUtcTimestamp
    node_role = $NodeRole
    machine_id = (Get-LabStringSha256 -Value $machineSeed).Substring(0, 16)
    environment = [ordered]@{
        os_platform = [Environment]::OSVersion.Platform.ToString()
        os_version = [Environment]::OSVersion.Version.ToString()
        process_architecture = $env:PROCESSOR_ARCHITECTURE
        powershell_version = $PSVersionTable.PSVersion.ToString()
        dotnet_version = [Environment]::Version.ToString()
    }
    candidate_build = $candidateBuild
    network_interfaces = @(Get-LabNetworkInventory -IncludeSensitive:$IncludeSensitive)
    routes = @(Get-LabRouteInventory -IncludeSensitive:$IncludeSensitive)
    relevant_processes = @(Get-LabProcessSnapshot)
    tools = $tools
    local_api = $api
    privacy = [ordered]@{
        sensitive_values_included = [bool]$IncludeSensitive
        host_name_included = [bool]$IncludeSensitive
        full_addresses_included = [bool]$IncludeSensitive
    }
}
if ($IncludeSensitive) {
    $inventory.machine_name = $env:COMPUTERNAME
}

$safeInventory = ConvertTo-LabSanitizedValue -InputObject $inventory `
    -RedactAddresses:(-not $IncludeSensitive)
$writtenPath = Write-LabJson -Value $safeInventory -Path $OutFile
Write-Host "Lab inventory written: $writtenPath" -ForegroundColor Green
