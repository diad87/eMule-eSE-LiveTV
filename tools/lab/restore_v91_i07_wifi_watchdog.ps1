[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$LeaseRequestPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
. (Join-Path $PSScriptRoot 'v91_i07_common.ps1')

$requestPath = [IO.Path]::GetFullPath($LeaseRequestPath)
$leaseRoot = Split-Path -Parent $requestPath
$armedPath = Join-Path $leaseRoot 'armed.json'
$restorePath = Join-Path $leaseRoot 'restore-now.json'
$resultPath = Join-Path $leaseRoot 'watchdog-result.json'
$status = 'LAB_BLOCKED'
$trigger = ''
$errorCode = ''
$profileEvidence = $null
$restoreSignalValid = $false
$startedAt = [DateTimeOffset]::UtcNow
$request = $null

function Get-I07WatchdogTextSha256 {
    param([Parameter(Mandatory = $true)][string]$Value)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash(
            [Text.Encoding]::UTF8.GetBytes($Value)
        ))).Replace('-', '').ToLowerInvariant()
    } finally { $sha.Dispose() }
}

try {
    $request = Get-Content -LiteralPath $requestPath -Raw |
        ConvertFrom-Json
    $nonce = ([string]$request.nonce).ToLowerInvariant()
    $homeWlanHash =
        ([string]$request.home_wlan_profile_sha256).ToLowerInvariant()
    $homeConnectionHash =
        ([string]$request.home_connection_profile_sha256).ToLowerInvariant()
    $interfaceGuid =
        ([string]$request.interface_guid).Trim('{}').ToLowerInvariant()
    $deadline = [DateTimeOffset]::MinValue
    $deadlineValid = [DateTimeOffset]::TryParse(
        [string]$request.deadline_utc,
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::RoundtripKind,
        [ref]$deadline)
    if ([string]$request.schema -cne 'ese.v91.i07-home-lease/v1' -or
        $nonce -notmatch '^[0-9a-f]{32}$' -or
        $homeWlanHash -notmatch '^[0-9a-f]{64}$' -or
        $homeConnectionHash -notmatch '^[0-9a-f]{64}$' -or
        $interfaceGuid -notmatch '^[0-9a-f-]{36}$' -or
        -not $deadlineValid -or $deadline -le $startedAt -or
        $deadline -gt $startedAt.AddMinutes(30)) {
        throw 'Invalid I07 Home watchdog lease contract.'
    }
    $adapters = @(Get-NetAdapter -IncludeHidden | Where-Object {
        ([string]$_.InterfaceGuid).Trim('{}').ToLowerInvariant() -ceq
            $interfaceGuid -and [bool]$_.HardwareInterface -and
        -not [bool]$_.Virtual -and
        (@([string]$_.MediaType, [string]$_.PhysicalMediaType,
            [string]$_.InterfaceDescription) -join ' ') -match
            '(?i)802\.11|wi-?fi|wireless'
    })
    if ($adapters.Count -ne 1) {
        throw 'The leased physical Wi-Fi adapter is not uniquely available.'
    }
    $alias = [string]$adapters[0].Name
    $rawProfiles = @(& netsh.exe wlan show profiles interface="$alias" 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not enumerate saved Wi-Fi profiles for the lease.'
    }
    $matches = [Collections.Generic.List[string]]::new()
    foreach ($line in $rawProfiles) {
        $match = [regex]::Match([string]$line, ':\s*(.+?)\s*$')
        if ($match.Success) {
            $name = $match.Groups[1].Value
            if ((Get-I07WatchdogTextSha256 -Value $name) -ceq
                $homeWlanHash) {
                $matches.Add($name)
            }
        }
    }
    $resolvedProfiles = @($matches | Select-Object -Unique)
    if ($resolvedProfiles.Count -ne 1) {
        throw 'The leased Home WLAN hash was not uniquely resolved locally.'
    }
    $homeProfileName = [string]$resolvedProfiles[0]
    Write-I07JsonAtomic -Path $armedPath -Value ([ordered]@{
        schema = 'ese.v91.i07-home-watchdog-armed/v1'
        case_id = 'V91-I07'
        status = 'ARMED'
        nonce = $nonce
        watchdog_pid = $PID
        armed_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
        deadline_utc = $deadline.ToUniversalTime().ToString('o')
        home_wlan_profile_sha256 = $homeWlanHash
        home_connection_profile_sha256 = $homeConnectionHash
        interface_guid = $interfaceGuid
    })

    while ([DateTimeOffset]::UtcNow -lt $deadline) {
        if (Test-Path -LiteralPath $restorePath -PathType Leaf) {
            try {
                $restoreSignal = Get-Content -LiteralPath $restorePath -Raw |
                    ConvertFrom-Json
                $restoreSignalValid =
                    [string]$restoreSignal.schema -ceq
                        'ese.v91.i07-home-restore-signal/v1' -and
                    [string]$restoreSignal.nonce -ceq $nonce
            } catch { $restoreSignalValid = $false }
            $trigger = if ($restoreSignalValid) {
                'controller_restore'
            } else { 'invalid_restore_signal' }
            break
        }
        Start-Sleep -Milliseconds 250
    }
    if ([string]::IsNullOrWhiteSpace($trigger)) { $trigger = 'lease_deadline' }

    $null = @(& netsh.exe wlan connect name="$homeProfileName" `
        interface="$alias" 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw 'Windows rejected the leased Home Wi-Fi restoration.'
    }
    $restoreDeadline = [DateTimeOffset]::UtcNow.AddSeconds(120)
    do {
        Start-Sleep -Milliseconds 500
        try {
            $connectionEvidence = Get-I07NetworkProfileEvidence `
                -InterfaceIndex ([int]$adapters[0].ifIndex)
            $wlanEvidence = Get-I07CurrentWlanProfileEvidence `
                -InterfaceIndex ([int]$adapters[0].ifIndex)
            if ([string]$connectionEvidence.profile_sha256 -ceq
                    $homeConnectionHash -and
                [string]$wlanEvidence.wlan_profile_sha256 -ceq
                    $homeWlanHash -and
                ([string]$connectionEvidence.interface_guid).Trim('{}') -ieq
                    $interfaceGuid -and
                ([string]$wlanEvidence.interface_guid).Trim('{}') -ieq
                    $interfaceGuid) {
                $profileEvidence = [pscustomobject][ordered]@{
                    connection_profile = $connectionEvidence
                    wlan_profile = $wlanEvidence
                }
                break
            }
        } catch {}
    } while ([DateTimeOffset]::UtcNow -lt $restoreDeadline)
    if ($null -eq $profileEvidence -or
        [string]$profileEvidence.connection_profile.profile_sha256 -cne
            $homeConnectionHash -or
        [string]$profileEvidence.wlan_profile.wlan_profile_sha256 -cne
            $homeWlanHash) {
        throw 'The leased restoration did not reach the qualified Home profile.'
    }
    $status = 'PASS'
} catch {
    $errorCode = 'HOME_RESTORE_NOT_PROVEN'
}

$nonceForResult = if ($null -ne $request -and
    $null -ne $request.PSObject.Properties['nonce']) {
    [string]$request.nonce
} else { '' }
Write-I07JsonAtomic -Path $resultPath -Value ([ordered]@{
    schema = 'ese.v91.i07-home-watchdog-result/v1'
    case_id = 'V91-I07'
    status = $status
    nonce = $nonceForResult
    watchdog_pid = $PID
    trigger = $trigger
    restore_signal_valid = $restoreSignalValid
    started_at_utc = $startedAt.ToString('o')
    completed_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
    profile = $profileEvidence
    error_code = if ($status -ceq 'PASS') { $null } else { $errorCode }
})
if ($status -ceq 'PASS') { exit 0 }
exit 2
