[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidateSet('A', 'B', 'R')][string]$NodeRole,
    [Parameter(Mandatory = $true)][string]$SourcePackage,
    [string]$OutputRoot = '',
    [string]$RunId = '',
    [ValidateRange(-1, 60000)][int]$PortOffset = -1
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')

if (-not $RunId) { $RunId = [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss') }
if ($RunId -notmatch '^[A-Za-z0-9._-]{1,64}$') {
    throw 'RunId may only contain letters, digits, dot, underscore and hyphen (maximum 64 characters)'
}
if (-not $OutputRoot) { $OutputRoot = Join-Path (Get-Location) 'lab-runs' }

$sourcePath = (Resolve-Path -LiteralPath $SourcePackage).Path
if (-not (Test-Path -LiteralPath $sourcePath -PathType Container)) {
    throw "Source package is not a directory: $SourcePackage"
}
if (-not (Test-Path -LiteralPath (Join-Path $sourcePath 'emule.exe') -PathType Leaf)) {
    throw "Source package does not contain emule.exe: $sourcePath"
}

if ($PortOffset -lt 0) {
    $PortOffset = switch ($NodeRole) {
        'A' { 0 }
        'B' { 100 }
        'R' { 200 }
    }
}

$ports = [ordered]@{
    tcp = 4662 + $PortOffset
    udp = 4672 + $PortOffset
    web = 4711 + $PortOffset
}
foreach ($portName in $ports.Keys) {
    if ($ports[$portName] -lt 1 -or $ports[$portName] -gt 65535) {
        throw "Calculated $portName port is outside 1..65535: $($ports[$portName])"
    }
}
if (@($ports.Values | Sort-Object -Unique).Count -ne $ports.Count) {
    throw 'Calculated node ports are not unique'
}

$outputRootPath = New-LabDirectory -Path $OutputRoot
$targetPath = Join-Path $outputRootPath ('{0}-{1}' -f $RunId, $NodeRole.ToLowerInvariant())
if (Test-Path -LiteralPath $targetPath) {
    throw "Target already exists; refusing to overwrite it: $targetPath"
}

$null = New-Item -ItemType Directory -Path $targetPath
try {
    Get-ChildItem -LiteralPath $sourcePath -Force | Copy-Item -Destination $targetPath -Recurse -Force

    $preferencesPath = Join-Path $targetPath 'config\preferences.ini'
    Set-LabIniValue -Path $preferencesPath -Section 'eMule' -Key 'Nick' `
        -Value ('eSE-v9-lab-{0}-{1}' -f $RunId, $NodeRole)
    Set-LabIniValue -Path $preferencesPath -Section 'eMule' -Key 'Port' -Value ([string]$ports.tcp)
    Set-LabIniValue -Path $preferencesPath -Section 'eMule' -Key 'UDPPort' -Value ([string]$ports.udp)
    Set-LabIniValue -Path $preferencesPath -Section 'eMule' -Key 'AppVersion' `
        -Value 'eSE v9 lab prepared profile'
    Set-LabIniValue -Path $preferencesPath -Section 'eMule' -Key 'MaxUpload' -Value '-1'
    Set-LabIniValue -Path $preferencesPath -Section 'eMule' -Key 'MaxDownload' -Value '-1'
    Set-LabIniValue -Path $preferencesPath -Section 'eMule' -Key 'UploadCapacityNew' -Value '100000'
    Set-LabIniValue -Path $preferencesPath -Section 'eMule' -Key 'DownloadCapacity' -Value '100000'
    Set-LabIniValue -Path $preferencesPath -Section 'WebServer' -Key 'Port' -Value ([string]$ports.web)
    Set-LabIniValue -Path $preferencesPath -Section 'WebServer' -Key 'WebUseUPnP' -Value '0'

    $safeDefaults = [ordered]@{
        EseNetLabConsent = '0'
        EseNetLabAdvancedConsent = '0'
        EseNetLabContributionConsent = '0'
        EseNetLabEnabled = '0'
        EseV9Experimental = '0'
        EseKad3Rendezvous = '0'
        EseAutoKeepalive = '0'
        EseRelayAccept = '0'
        EseRelayEgress = '0'
        EseReachSelector = '0'
        EseHolePunchPortPredict = '0'
        EseEd2kPunch3 = '0'
        Kad6PublicExitOptIn = '0'
        Kad6BetaExitOptIn = '0'
    }
    foreach ($key in $safeDefaults.Keys) {
        Set-LabIniValue -Path $preferencesPath -Section 'eSE' -Key $key -Value $safeDefaults[$key]
    }
    Set-LabIniValue -Path $preferencesPath -Section 'KRPRelay' -Key 'KrpRelayEnabled' -Value '0'
    Set-LabIniValue -Path $preferencesPath -Section 'KRPRelay' -Key 'KrpRelayKillSwitch' -Value '1'
    Set-LabIniValue -Path $preferencesPath -Section 'KRPRelay' -Key 'ExperimentalTcpDataPlane' -Value '0'

    $hashes = [ordered]@{}
    foreach ($relativeFile in @('emule.exe', 'ese-server.exe', 'config\preferences.ini')) {
        $candidate = Join-Path $targetPath $relativeFile
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            $hashes[$relativeFile.Replace('\', '/')] = Get-LabSha256 -Path $candidate
        }
    }

    $manifest = [ordered]@{
        schema = 'ese.lab.node/v1'
        prepared_at_utc = Get-LabUtcTimestamp
        run_id = $RunId
        node_role = $NodeRole
        source_package_name = Split-Path -Leaf $sourcePath
        target_directory_name = Split-Path -Leaf $targetPath
        ports = $ports
        experimental_features_enabled = $false
        safe_defaults = $safeDefaults
        file_sha256 = $hashes
        launch_performed = $false
    }
    $manifestPath = Write-LabJson -Value $manifest -Path (Join-Path $targetPath 'LAB_NODE.json')
} catch {
    throw "Node preparation failed; partial directory retained for diagnosis at '$targetPath': $($_.Exception.Message)"
}

Write-Host "Lab node $NodeRole prepared: $targetPath" -ForegroundColor Green
Write-Host "Manifest: $manifestPath"
