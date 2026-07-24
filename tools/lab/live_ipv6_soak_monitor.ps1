[CmdletBinding()]
param(
    [string]$BaseUrl = 'http://127.0.0.1:4711',
    [Parameter(Mandatory = $true)][ValidateRange(1, 2147483647)]
    [int]$TargetProcessId,
    [Parameter(Mandatory = $true)][ValidateRange(1, 65535)]
    [int]$ExpectedRemotePort,
    [ValidateRange(1, 604800)][int]$DurationSeconds = 7200,
    [ValidateRange(2, 300)][int]$IntervalSeconds = 15,
    [Parameter(Mandatory = $true)][string]$OutFile,
    [Parameter(Mandatory = $true)][string]$SamplesFile
)

$ErrorActionPreference = 'Stop'

$samplesPath = [IO.Path]::GetFullPath($SamplesFile)
$summaryPath = [IO.Path]::GetFullPath($OutFile)
$parent = Split-Path -Parent $samplesPath
if (-not (Test-Path -LiteralPath $parent)) {
    New-Item -ItemType Directory -Path $parent | Out-Null
}
if (Test-Path -LiteralPath $samplesPath) {
    throw "Samples file already exists: $samplesPath"
}

$encoding = New-Object Text.UTF8Encoding($false)
$started = [DateTime]::UtcNow
$deadline = $started.AddSeconds($DurationSeconds)
$sampleNumber = 0
$failures = New-Object Collections.Generic.List[string]
$firstReceived = $null
$lastReceived = $null

do {
    $sampleNumber++
    $sampleFailures = New-Object Collections.Generic.List[string]
    $debug = $null
    $playlistValid = $false

    if ($null -eq (Get-Process -Id $TargetProcessId -ErrorAction SilentlyContinue)) {
        $sampleFailures.Add('viewer process unavailable')
    }

    try {
        Invoke-RestMethod -Uri ($BaseUrl.TrimEnd('/') + '/api/live/player-alive') `
            -TimeoutSec 5 | Out-Null
        $debug = Invoke-RestMethod -Uri ($BaseUrl.TrimEnd('/') + '/api/live/debug') `
            -TimeoutSec 5
        $playlist = Invoke-WebRequest -UseBasicParsing `
            -Uri ($BaseUrl.TrimEnd('/') + '/hls/stream.m3u8') -TimeoutSec 5
        $playlistText = if ($playlist.Content -is [byte[]]) {
            [Text.Encoding]::UTF8.GetString($playlist.Content)
        } else {
            [string]$playlist.Content
        }
        $playlistValid = $playlist.StatusCode -eq 200 `
            -and $playlistText -match '#EXTM3U' `
            -and $playlistText -match '\.ts'
    } catch {
        $sampleFailures.Add("Live API/HLS unavailable: $($_.Exception.Message)")
    }

    $connections = @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
        Where-Object {
            $_.OwningProcess -eq $TargetProcessId `
                -and $_.RemotePort -eq $ExpectedRemotePort
        })
    $ipv6Connections = @($connections | Where-Object { $_.RemoteAddress -like '*:*' })
    $ipv4Connections = @($connections | Where-Object { $_.RemoteAddress -notlike '*:*' })
    if ($ipv6Connections.Count -lt 1) {
        $sampleFailures.Add('no established IPv6 Live data connection')
    }
    if ($ipv4Connections.Count -gt 0) {
        $sampleFailures.Add('IPv4 fallback detected on the Live data port')
    }

    if ($null -ne $debug) {
        if (-not $debug.viewing) {
            $sampleFailures.Add('viewer is no longer in viewing state')
        }
        if (-not $playlistValid) {
            $sampleFailures.Add('HLS playlist is missing or invalid')
        }
        if ([int64]$debug.chunks.missing -ne 0) {
            $sampleFailures.Add("viewer buffer reports $($debug.chunks.missing) missing chunk(s)")
        }
        $received = [int64]$debug.counters.chunksReceived
        if ($null -eq $firstReceived) {
            $firstReceived = $received
        }
        $lastReceived = $received
    }

    foreach ($failure in $sampleFailures) {
        $failures.Add("sample ${sampleNumber}: $failure")
    }

    $sample = [ordered]@{
        schema = 'ese.lab.live-ipv6-soak-sample/v1'
        sample_number = $sampleNumber
        captured_at_utc = [DateTime]::UtcNow.ToString('o')
        elapsed_seconds = [Math]::Round(([DateTime]::UtcNow - $started).TotalSeconds, 3)
        viewing = if ($null -eq $debug) { $null } else { [bool]$debug.viewing }
        playlist_valid = $playlistValid
        chunks = if ($null -eq $debug) { $null } else { $debug.chunks }
        counters = if ($null -eq $debug) { $null } else { $debug.counters }
        ipv6_connection_count = $ipv6Connections.Count
        ipv4_fallback_count = $ipv4Connections.Count
        failures = @($sampleFailures)
    }
    [IO.File]::AppendAllText(
        $samplesPath,
        (($sample | ConvertTo-Json -Depth 16 -Compress) + [Environment]::NewLine),
        $encoding)

    $remainingMs = [int][Math]::Ceiling(
        ($deadline - [DateTime]::UtcNow).TotalMilliseconds)
    if ($remainingMs -gt 0) {
        Start-Sleep -Milliseconds ([Math]::Min(
            $remainingMs, $IntervalSeconds * 1000))
    }
} while ([DateTime]::UtcNow -lt $deadline)

if ($null -eq $firstReceived -or $null -eq $lastReceived `
    -or $lastReceived -le $firstReceived) {
    $failures.Add('received chunk counter did not advance during the soak')
}

$summary = [ordered]@{
    schema = 'ese.lab.live-ipv6-soak-summary/v1'
    started_at_utc = $started.ToString('o')
    finished_at_utc = [DateTime]::UtcNow.ToString('o')
    requested_duration_seconds = $DurationSeconds
    interval_seconds = $IntervalSeconds
    sample_count = $sampleNumber
    first_chunks_received = $firstReceived
    last_chunks_received = $lastReceived
    verdict = if ($failures.Count -eq 0) { 'PASS' } else { 'FAIL' }
    failures = @($failures)
    samples_file = [IO.Path]::GetFileName($samplesPath)
}
[IO.File]::WriteAllText(
    $summaryPath, ($summary | ConvertTo-Json -Depth 16), $encoding)

if ($failures.Count -gt 0) {
    throw "Live IPv6 soak FAIL: $($failures.Count) failure(s)"
}
Write-Host "Live IPv6 soak PASS: $summaryPath" -ForegroundColor Green
