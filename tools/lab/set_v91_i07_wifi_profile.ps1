[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$JobRequestPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
. (Join-Path $PSScriptRoot 'v91_i07_common.ps1')

$request = Get-Content -LiteralPath $JobRequestPath -Raw | ConvertFrom-Json
$wrapper = $request.PSObject.Properties['request']
if ($null -ne $wrapper) { $request = $wrapper.Value }
$jobRoot = Split-Path -Parent ([IO.Path]::GetFullPath($JobRequestPath))
$jobsRoot = Split-Path -Parent $jobRoot
$agentRoot = Split-Path -Parent $jobsRoot
$resultPath = Join-Path $jobRoot 'result.json'
$targetWlanHash =
    ([string]$request.target_wlan_profile_sha256).ToLowerInvariant()
$expectedConnectionHash =
    ([string]$request.expected_connection_profile_sha256).ToLowerInvariant()
$homeWlanHash =
    ([string]$request.home_wlan_profile_sha256).ToLowerInvariant()
$homeConnectionHash =
    ([string]$request.home_connection_profile_sha256).ToLowerInvariant()
$expectedGuid = ([string]$request.interface_guid).Trim('{}').ToLowerInvariant()
$nonce = ([string]$request.nonce).ToLowerInvariant()
$action = ([string]$request.action).ToLowerInvariant()
$status = 'LAB_BLOCKED'
$errorCode = ''
$profileEvidence = $null
$watchdogEvidence = $null
$disarmEvidence = $null
$leaseRoot = $null

function Get-I07WifiTextSha256 {
    param([Parameter(Mandatory = $true)][string]$Value)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash(
            [Text.Encoding]::UTF8.GetBytes($Value)
        ))).Replace('-', '').ToLowerInvariant()
    } finally { $sha.Dispose() }
}

function Get-I07WifiAdapter {
    $adapters = @(Get-NetAdapter -IncludeHidden | Where-Object {
        ([string]$_.InterfaceGuid).Trim('{}').ToLowerInvariant() -ceq
            $expectedGuid -and [bool]$_.HardwareInterface -and
        -not [bool]$_.Virtual -and
        (@([string]$_.MediaType, [string]$_.PhysicalMediaType,
            [string]$_.InterfaceDescription) -join ' ') -match
            '(?i)802\.11|wi-?fi|wireless'
    })
    if ($adapters.Count -ne 1) {
        throw 'R01 Wi-Fi adapter is not uniquely available.'
    }
    return $adapters[0]
}

function Resolve-I07SavedProfile {
    param(
        [Parameter(Mandatory = $true)][string]$Alias,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256
    )
    $rawProfiles = @(& netsh.exe wlan show profiles interface="$Alias" 2>&1)
    if ($LASTEXITCODE -ne 0) { throw 'Could not enumerate Wi-Fi profiles.' }
    $matches = [Collections.Generic.List[string]]::new()
    foreach ($line in $rawProfiles) {
        $match = [regex]::Match([string]$line, ':\s*(.+?)\s*$')
        if ($match.Success) {
            $name = $match.Groups[1].Value
            if ((Get-I07WifiTextSha256 -Value $name) -ceq $ExpectedSha256) {
                $matches.Add($name)
            }
        }
    }
    $unique = @($matches | Select-Object -Unique)
    if ($unique.Count -ne 1) {
        throw 'Target Wi-Fi profile hash was not uniquely resolved locally.'
    }
    return [string]$unique[0]
}

function Wait-I07ConnectionProfile {
    param(
        [Parameter(Mandatory = $true)][int]$InterfaceIndex,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256,
        [Parameter(Mandatory = $true)][string]$ExpectedWlanSha256,
        [ValidateRange(1, 150)][int]$TimeoutSeconds = 90
    )
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        Start-Sleep -Milliseconds 500
        try {
            $evidence = Get-I07NetworkProfileEvidence `
                -InterfaceIndex $InterfaceIndex
            $wlanEvidence = Get-I07CurrentWlanProfileEvidence `
                -InterfaceIndex $InterfaceIndex
            if ([string]$evidence.profile_sha256 -ceq $ExpectedSha256 -and
                [string]$wlanEvidence.wlan_profile_sha256 -ceq
                    $ExpectedWlanSha256 -and
                ([string]$evidence.interface_guid).Trim('{}') -ieq
                    ([string]$wlanEvidence.interface_guid).Trim('{}')) {
                return [pscustomobject][ordered]@{
                    connection_profile = $evidence
                    wlan_profile = $wlanEvidence
                }
            }
        } catch {}
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    throw 'Wi-Fi transition did not reach the requested connection profile.'
}

try {
    if ([string]$request.schema -cne 'ese.v91.i07-wifi-request/v2' -or
        $targetWlanHash -notmatch '^[0-9a-f]{64}$' -or
        $expectedConnectionHash -notmatch '^[0-9a-f]{64}$' -or
        $homeWlanHash -notmatch '^[0-9a-f]{64}$' -or
        $homeConnectionHash -notmatch '^[0-9a-f]{64}$' -or
        $expectedGuid -notmatch '^[0-9a-f-]{36}$' -or
        $nonce -notmatch '^[0-9a-f]{32}$' -or
        $action -notin @('hotspot', 'home') -or
        ($action -ceq 'home' -and (
            $targetWlanHash -cne $homeWlanHash -or
            $expectedConnectionHash -cne $homeConnectionHash)) -or
        [IO.Path]::GetFileName($jobsRoot) -ine 'jobs') {
        throw 'Invalid Wi-Fi transition contract.'
    }
    $adapter = Get-I07WifiAdapter
    $alias = [string]$adapter.Name
    $leaseParent = [IO.Path]::GetFullPath((
        Join-Path $agentRoot 'i07-leases')).TrimEnd('\') + '\'
    $leaseRoot = [IO.Path]::GetFullPath((Join-Path $leaseParent $nonce))
    if (-not $leaseRoot.StartsWith(
            $leaseParent, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'I07 Home lease escaped the agent root.'
    }

    if ($action -ceq 'hotspot') {
        $leaseSeconds = [int]$request.lease_seconds
        if ($leaseSeconds -lt 300 -or $leaseSeconds -gt 1800) {
            throw 'I07 Home lease must be between 300 and 1800 seconds.'
        }
        if (Test-Path -LiteralPath $leaseRoot) {
            throw 'The nonce-owned I07 Home lease already exists.'
        }
        New-Item -ItemType Directory -Path $leaseRoot -Force | Out-Null
        $watchdogSource = Join-Path $PSScriptRoot `
            'restore_v91_i07_wifi_watchdog.ps1'
        $commonSource = Join-Path $PSScriptRoot 'v91_i07_common.ps1'
        foreach ($required in @($watchdogSource, $commonSource)) {
            if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
                throw "Missing local watchdog dependency: $required"
            }
        }
        $watchdogLocal = Join-Path $leaseRoot `
            'restore_v91_i07_wifi_watchdog.ps1'
        Copy-Item -LiteralPath $watchdogSource -Destination $watchdogLocal
        Copy-Item -LiteralPath $commonSource -Destination (
            Join-Path $leaseRoot 'v91_i07_common.ps1')
        $deadline = [DateTimeOffset]::UtcNow.AddSeconds($leaseSeconds)
        $leaseRequest = Join-Path $leaseRoot 'lease-request.json'
        Write-I07JsonAtomic -Path $leaseRequest -Value ([ordered]@{
            schema = 'ese.v91.i07-home-lease/v1'
            case_id = 'V91-I07'
            nonce = $nonce
            created_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
            deadline_utc = $deadline.ToString('o')
            home_wlan_profile_sha256 = $homeWlanHash
            home_connection_profile_sha256 = $homeConnectionHash
            interface_guid = $expectedGuid
        })
        $powershell = Join-Path $PSHOME 'powershell.exe'
        $arguments = '-NoLogo -NoProfile -ExecutionPolicy Bypass ' +
            '-File "{0}" -LeaseRequestPath "{1}"' -f
                $watchdogLocal, $leaseRequest
        $watchdog = Start-Process -FilePath $powershell `
            -ArgumentList $arguments -WindowStyle Hidden -PassThru
        $armedPath = Join-Path $leaseRoot 'armed.json'
        $armDeadline = [DateTimeOffset]::UtcNow.AddSeconds(15)
        while (-not (Test-Path -LiteralPath $armedPath -PathType Leaf) -and
            [DateTimeOffset]::UtcNow -lt $armDeadline) {
            $watchdog.Refresh()
            if ($watchdog.HasExited) {
                throw 'The local Home watchdog exited before arming.'
            }
            Start-Sleep -Milliseconds 100
        }
        if (-not (Test-Path -LiteralPath $armedPath -PathType Leaf)) {
            throw 'Timed out arming the local Home watchdog.'
        }
        $watchdogEvidence = Get-Content -LiteralPath $armedPath -Raw |
            ConvertFrom-Json
        if ([string]$watchdogEvidence.schema -cne
                'ese.v91.i07-home-watchdog-armed/v1' -or
            [string]$watchdogEvidence.status -cne 'ARMED' -or
            [string]$watchdogEvidence.nonce -cne $nonce -or
            [string]$watchdogEvidence.home_wlan_profile_sha256 -cne
                $homeWlanHash -or
            [string]$watchdogEvidence.home_connection_profile_sha256 -cne
                $homeConnectionHash -or
            ([string]$watchdogEvidence.interface_guid).Trim('{}') -ine
                $expectedGuid -or
            [int]$watchdogEvidence.watchdog_pid -ne [int]$watchdog.Id) {
            throw 'The local Home watchdog arm evidence is invalid.'
        }

        $profileName = Resolve-I07SavedProfile -Alias $alias `
            -ExpectedSha256 $targetWlanHash
        $null = @(& netsh.exe wlan connect name="$profileName" `
            interface="$alias" 2>&1)
        if ($LASTEXITCODE -ne 0) {
            throw 'Windows rejected the Wi-Fi transition.'
        }
        $profileEvidence = Wait-I07ConnectionProfile `
            -InterfaceIndex ([int]$adapter.ifIndex) `
            -ExpectedSha256 $expectedConnectionHash `
            -ExpectedWlanSha256 $targetWlanHash
    } else {
        if (-not (Test-Path -LiteralPath $leaseRoot -PathType Container)) {
            throw 'The nonce-owned I07 Home lease is missing.'
        }
        Write-I07JsonAtomic -Path (Join-Path $leaseRoot 'restore-now.json') `
            -Value ([ordered]@{
                schema = 'ese.v91.i07-home-restore-signal/v1'
                nonce = $nonce
                requested_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
            })
        $watchdogResultPath = Join-Path $leaseRoot 'watchdog-result.json'
        $watchdogDeadline = [DateTimeOffset]::UtcNow.AddSeconds(150)
        while (-not (Test-Path -LiteralPath $watchdogResultPath `
                -PathType Leaf) -and
            [DateTimeOffset]::UtcNow -lt $watchdogDeadline) {
            Start-Sleep -Milliseconds 250
        }
        if (-not (Test-Path -LiteralPath $watchdogResultPath -PathType Leaf)) {
            throw 'The local Home watchdog did not publish a restore result.'
        }
        $watchdogEvidence = Get-Content -LiteralPath $watchdogResultPath -Raw |
            ConvertFrom-Json
        if ([string]$watchdogEvidence.schema -cne
                'ese.v91.i07-home-watchdog-result/v1' -or
            [string]$watchdogEvidence.case_id -cne 'V91-I07' -or
            [string]$watchdogEvidence.status -cne 'PASS' -or
            [string]$watchdogEvidence.nonce -cne $nonce -or
            -not [bool]$watchdogEvidence.restore_signal_valid -or
            [string]$watchdogEvidence.profile.connection_profile.profile_sha256 -cne
                $homeConnectionHash -or
            [string]$watchdogEvidence.profile.wlan_profile.wlan_profile_sha256 -cne
                $homeWlanHash -or
            ([string]$watchdogEvidence.profile.connection_profile.interface_guid).
                Trim('{}') -ine $expectedGuid -or
            ([string]$watchdogEvidence.profile.wlan_profile.interface_guid).
                Trim('{}') -ine $expectedGuid) {
            throw 'The local Home watchdog restore evidence is invalid.'
        }
        $watchdogPid = [int]$watchdogEvidence.watchdog_pid
        $exitDeadline = [DateTimeOffset]::UtcNow.AddSeconds(10)
        while (@(Get-Process -ErrorAction Stop | Where-Object {
                    [int]$_.Id -eq $watchdogPid
                }).Count -ne 0 -and
            [DateTimeOffset]::UtcNow -lt $exitDeadline) {
            Start-Sleep -Milliseconds 100
        }
        if (@(Get-Process -ErrorAction Stop | Where-Object {
                    [int]$_.Id -eq $watchdogPid
                }).Count -ne 0) {
            throw 'The local Home watchdog did not disarm after restoration.'
        }
        $profileEvidence = Wait-I07ConnectionProfile `
            -InterfaceIndex ([int]$adapter.ifIndex) `
            -ExpectedSha256 $homeConnectionHash `
            -ExpectedWlanSha256 $homeWlanHash -TimeoutSeconds 10
        if ([string]$watchdogEvidence.trigger -cne 'controller_restore') {
            throw 'The Home watchdog deadline fired before normal disarm.'
        }
        if ([string]$profileEvidence.connection_profile.profile_sha256 -cne
            $homeConnectionHash -or
            [string]$profileEvidence.wlan_profile.wlan_profile_sha256 -cne
            $homeWlanHash) {
            throw 'Home profile changed after watchdog restoration.'
        }
        $disarmEvidence = [pscustomobject][ordered]@{
            schema = 'ese.v91.i07-home-watchdog-disarmed/v1'
            case_id = 'V91-I07'
            status = 'PASS'
            nonce = $nonce
            watchdog_pid = $watchdogPid
            process_exited = $true
            restore_trigger = [string]$watchdogEvidence.trigger
            disarmed_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
        }
        Write-I07JsonAtomic -Path (Join-Path $leaseRoot 'disarmed.json') `
            -Value $disarmEvidence
    }
    $status = 'PASS'
} catch {
    $errorCode = 'WIFI_TRANSITION_NOT_PROVEN'
}

$result = [ordered]@{
    schema = 'ese.v91.i07-wifi-transition/v2'
    case_id = 'V91-I07'
    action = $action
    status = $status
    nonce = $nonce
    completed_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
    target_wlan_profile_sha256 = $targetWlanHash
    expected_connection_profile_sha256 = $expectedConnectionHash
    home_wlan_profile_sha256 = $homeWlanHash
    home_connection_profile_sha256 = $homeConnectionHash
    interface_guid = $expectedGuid
    profile = $profileEvidence
    watchdog = $watchdogEvidence
    watchdog_disarm = $disarmEvidence
    error_code = if ($status -ceq 'PASS') { $null } else { $errorCode }
}
Write-I07JsonAtomic -Path $resultPath -Value $result
if ($status -ceq 'PASS') { exit 0 }
exit 2
