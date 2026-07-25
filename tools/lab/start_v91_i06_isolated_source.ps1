[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$PackagePath,
    [Parameter(Mandatory = $true)][string]$OutputRoot,
    [ValidateRange(1, 65535)][int]$TcpPort = 6962,
    [ValidateRange(1, 65535)][int]$UdpPort = 6972,
    [ValidateRange(1, 65535)][int]$WebPort = 7011,
    [ValidateRange(1, 100000)][int]$BitrateKbps = 4000,
    [string]$Commit = '',
    [switch]$AllowDirtyDevelopmentBuild
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')

$candidate = Get-LabCandidateInfo -PackagePath $PackagePath `
    -ExpectedCommit $Commit -AllowDirty:$AllowDirtyDevelopmentBuild
$package = $candidate.package_path
$output = Get-LabFullPath -Path $OutputRoot
if (Test-Path -LiteralPath $output) {
    throw "OutputRoot already exists; refusing to mix evidence: $output"
}

$nodes = New-LabDirectory -Path (Join-Path $output 'nodes')
$evidence = New-LabDirectory -Path (Join-Path $output 'evidence')
$runId = 'v91-i06-isolated'
$offset = $TcpPort - 4662
if (($UdpPort - 4672) -ne $offset -or ($WebPort - 4711) -ne $offset) {
    throw 'TcpPort, UdpPort, and WebPort must use the same offset from 4662/4672/4711'
}

& (Join-Path $PSScriptRoot 'prepare_node.ps1') -NodeRole A `
    -SourcePackage $package -OutputRoot $nodes -RunId $runId `
    -PortOffset $offset

$node = Join-Path $nodes "$runId-a"
$preferences = Join-Path $node 'config\preferences.ini'
foreach ($entry in ([ordered]@{
    NetworkKademlia = '0'
    AutoConnect = '0'
}).GetEnumerator()) {
    Set-LabIniValue -Path $preferences -Section 'eMule' `
        -Key $entry.Key -Value $entry.Value
}
Set-LabIniValue -Path $preferences -Section 'Connection' `
    -Key 'KadNetworkMask' -Value '0'
Set-LabIniValue -Path $preferences -Section 'Connection' `
    -Key 'IPv6Mode' -Value '2'
Set-LabIniValue -Path $preferences -Section 'WebServer' `
    -Key 'Enabled' -Value '1'
Set-LabIniValue -Path $preferences -Section 'WebServer' `
    -Key 'Port' -Value ([string]$WebPort)

$source = $null
try {
    $source = Start-Process -FilePath (Join-Path $node 'emule.exe') `
        -ArgumentList @(
            '--portable', '--ignoreinstances', '--headless',
            "--metrics-port=$WebPort",
            "--tcp-port=$TcpPort",
            "--udp-port=$UdpPort"
        ) -WorkingDirectory $node -WindowStyle Hidden -PassThru

    $deadline = [DateTime]::UtcNow.AddSeconds(90)
    $status = $null
    do {
        Start-Sleep -Milliseconds 400
        $source.Refresh()
        if ($source.HasExited) {
            throw "Isolated source exited with code $($source.ExitCode)"
        }
        try {
            $status = Invoke-RestMethod `
                -Uri "http://127.0.0.1:$WebPort/api/status" `
                -TimeoutSec 2
        } catch {}
    } while ($null -eq $status -and [DateTime]::UtcNow -lt $deadline)
    if ($null -eq $status) {
        throw "Isolated source API did not become ready on port $WebPort"
    }

    $broadcast = Invoke-RestMethod -Uri (
        "http://127.0.0.1:$WebPort/api/live/broadcast/start" +
        "?source=testpattern&title=V91-I06-ULA-Isolated" +
        "&bitrate=$BitrateKbps"
    ) -TimeoutSec 30
    $keyMatch = [regex]::Match(
        [string]$broadcast.link,
        '\|live\|([0-9A-Fa-f]{32})\|'
    )
    if (-not [bool]$broadcast.success -or
        -not [bool]$broadcast.ready -or
        -not $keyMatch.Success) {
        throw "Isolated broadcast failed: $($broadcast | ConvertTo-Json -Compress)"
    }

    $session = [ordered]@{
        schema = 'ese.v91.i06-isolated-source/v1'
        candidate_version = $candidate.version
        candidate_commit = $candidate.commit
        candidate_dirty = $candidate.dirty
        development_override = [bool]$AllowDirtyDevelopmentBuild
        candidate_binary_sha256 = Get-LabSha256 `
            -Path (Join-Path $package 'emule.exe')
        started_at_utc = Get-LabUtcTimestamp
        process_id = $source.Id
        node_path = $node
        tcp_port = $TcpPort
        udp_port = $UdpPort
        web_port = $WebPort
        stream_key = $keyMatch.Groups[1].Value.ToLowerInvariant()
        title = 'V91-I06-ULA-Isolated'
        kad_enabled = $false
        auto_connect = $false
    }
    $sessionPath = Write-LabJson -Value $session `
        -Path (Join-Path $evidence 'session.json')

    Write-Host "V91-I06 isolated source started: $output" `
        -ForegroundColor Green
    Write-Host "Session: $sessionPath"
    $session | ConvertTo-Json -Depth 8
} catch {
    if ($null -ne $source) {
        try {
            $source.Refresh()
            if (-not $source.HasExited) {
                Stop-Process -Id $source.Id -Force -ErrorAction SilentlyContinue
            }
        } catch {}
    }
    throw
}
