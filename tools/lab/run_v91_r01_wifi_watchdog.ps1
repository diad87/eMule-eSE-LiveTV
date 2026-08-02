[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$StatePath,
    [Parameter(Mandatory = $true)][string]$DisarmPath,
    [Parameter(Mandatory = $true)][string]$HomeProfile,
    [Parameter(Mandatory = $true)][string]$WifiInterfaceAlias,
    [Parameter(Mandatory = $true)][string]$ExpectedInterfaceGuid,
    [Parameter(Mandatory = $true)][string]$ExpectedHomeWlanProfileSha256,
    [Parameter(Mandatory = $true)]
    [string]$ExpectedHomeConnectionProfileSha256,
    [Parameter(Mandatory = $true)][DateTimeOffset]$DeadlineUtc,
    [Parameter(Mandatory = $true)][string]$NonceSha256
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$state = [ordered]@{
    schema = 'ese.v91.r01-wifi-watchdog/v1'
    nonce_sha256 = $NonceSha256
    expected_interface_guid = $ExpectedInterfaceGuid
    expected_home_wlan_profile_sha256 = $ExpectedHomeWlanProfileSha256
    expected_home_connection_profile_sha256 =
        $ExpectedHomeConnectionProfileSha256
    armed = $false
    armed_at_utc = $null
    deadline_utc = $DeadlineUtc.ToString('o')
    disarmed = $false
    disarmed_at_utc = $null
    fired = $false
    fired_at_utc = $null
    home_restored = $false
    observed_interface_guid = $null
    observed_home_wlan_profile_sha256 = $null
    observed_home_connection_profile_sha256 = $null
    completed_at_utc = $null
    error = ''
}

function Write-WatchdogState {
    $temporary = $StatePath + '.new'
    [IO.File]::WriteAllText($temporary,
        ($script:state | ConvertTo-Json -Depth 6),
        [Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $temporary -Destination $StatePath -Force
}

function Get-CurrentWlanProfile {
    $text = (& netsh.exe wlan show interfaces `
            name="$WifiInterfaceAlias" 2>&1 | Out-String)
    foreach ($line in ($text -split "`r?`n")) {
        if ($line -match '(?i)^\s*(?:perfil|profile)\s+:\s*(.+?)\s*$') {
            return $Matches[1].Trim()
        }
    }
    return ''
}

function Get-WatchdogHash {
    param([Parameter(Mandatory = $true)][string]$Text)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return (($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text)) |
                ForEach-Object { $_.ToString('x2') }) -join '')
    } finally { $sha.Dispose() }
}

function Test-TypedHomeState {
    $adapter = Get-NetAdapter -Name $WifiInterfaceAlias -ErrorAction Stop
    $profiles = @(Get-NetConnectionProfile -InterfaceIndex $adapter.ifIndex `
            -ErrorAction Stop)
    if ($profiles.Count -ne 1) { return $false }
    $wlanHash = Get-WatchdogHash -Text (Get-CurrentWlanProfile)
    $connectionHash = Get-WatchdogHash -Text ([string]$profiles[0].Name)
    $state.observed_interface_guid = [string]$adapter.InterfaceGuid
    $state.observed_home_wlan_profile_sha256 = $wlanHash
    $state.observed_home_connection_profile_sha256 = $connectionHash
    return [string]::Equals([string]$adapter.InterfaceGuid,
            $ExpectedInterfaceGuid, [StringComparison]::OrdinalIgnoreCase) -and
        $wlanHash -ceq $ExpectedHomeWlanProfileSha256 -and
        $connectionHash -ceq $ExpectedHomeConnectionProfileSha256
}

try {
    if (-not (Test-TypedHomeState)) {
        throw 'Watchdog cannot arm: typed Home NIC/profile baseline mismatches.'
    }
    $state.armed = $true
    $state.armed_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
    Write-WatchdogState
    while ([DateTimeOffset]::UtcNow -lt $DeadlineUtc) {
        if (Test-Path -LiteralPath $DisarmPath -PathType Leaf) {
            if (Test-TypedHomeState) {
                $state.disarmed = $true
                $state.home_restored = $true
                $state.disarmed_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
                $state.completed_at_utc = $state.disarmed_at_utc
                Write-WatchdogState
                exit 0
            }
            $state.error =
                'Disarm ignored because typed Home state did not match.'
            Write-WatchdogState
        }
        Start-Sleep -Milliseconds 250
    }
    $state.fired = $true
    $state.fired_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
    Write-WatchdogState
    $null = & netsh.exe wlan connect name="$HomeProfile" `
        interface="$WifiInterfaceAlias" 2>&1
    $restoreDeadline = [DateTimeOffset]::UtcNow.AddSeconds(60)
    do {
        if (Test-TypedHomeState) {
            $state.home_restored = $true
            break
        }
        Start-Sleep -Milliseconds 500
    } while ([DateTimeOffset]::UtcNow -lt $restoreDeadline)
    if (-not $state.home_restored) {
        throw 'Watchdog could not restore the typed Home WLAN profile.'
    }
} catch {
    $state.error = $_.Exception.Message
} finally {
    $state.completed_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
    Write-WatchdogState
}
if (-not $state.home_restored) { exit 2 }
exit 0
