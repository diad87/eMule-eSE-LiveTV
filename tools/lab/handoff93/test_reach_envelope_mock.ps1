<#
.SYNOPSIS
    Reproducible loopback-only envelope tests for the handoff93 reach tools.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$validator = Join-Path $root 'validate_reach_status.ps1'
$probe = Join-Path $root 'reach_probe.ps1'
$candidatePath = Join-Path $root 'goldens\candidate.json'
$candidateJson = Get-Content -LiteralPath $candidatePath -Raw -Encoding UTF8
$lookalikeJson = @'
{
  "schema": "ESE_REACH_STATUS_V1",
  "available": true,
  "topology_generation": 1,
  "planes": {
    "ed2k_tcp_v4": { "state": "Bogus", "gate_state": "VERIFIED", "generation": 1, "expired": false, "stale": false, "lease": {}, "primary_evidence": {}, "inbound_evidence": {} },
    "kad_udp_v4": { "state": "Bogus", "gate_state": "VERIFIED", "generation": 1, "expired": false, "stale": false, "lease": {}, "primary_evidence": {}, "inbound_evidence": {} },
    "direct_v6": { "state": "Bogus", "gate_state": "VERIFIED", "generation": 1, "expired": false, "stale": false, "lease": {}, "primary_evidence": {}, "inbound_evidence": {} }
  }
}
'@
$unavailableContractJson = @'
{
  "schema": "ESE_REACH_STATUS_V1",
  "available": false,
  "topology_generation": 0,
  "planes": {}
}
'@
$sensitiveUserHash = 'HG02_USER_HASH_MUST_NOT_PERSIST_7f5d9c'
$sensitiveFfmpegPath = 'C:\Users\hg02-privacy-marker\Desktop\ffmpeg.exe'
$sensitivePublicIp = '2001:db8:dead:beef::92'
$adversarialPcpNonce = 'PCP_NONCE_MUST_NOT_PERSIST_92'
$adversarialOkSecret = 'OK_OBJECT_SECRET_MUST_NOT_PERSIST_92'
$adversarialReadyPath = 'C:\Users\private\token.txt'
$adversarialFfmpegIpv6 = '2001:db8:cafe::92'
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('reach-envelope-' + [Guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $testRoot -Force
$activeMocks = New-Object System.Collections.ArrayList

function Get-FreeLoopbackPort {
    $listener = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback, 0)
    try {
        $listener.Start()
        return ([Net.IPEndPoint]$listener.LocalEndpoint).Port
    } finally {
        $listener.Stop()
    }
}

function Start-ReachMock {
    param(
        [Parameter(Mandatory = $true)][string]$Mode,
        [Parameter(Mandatory = $true)][int]$Requests
    )

    $port = Get-FreeLoopbackPort
    $job = Start-Job -ArgumentList $port, $Mode, $Requests, $candidateJson, $lookalikeJson, $unavailableContractJson, $sensitiveUserHash, $sensitiveFfmpegPath, $sensitivePublicIp, $adversarialPcpNonce, $adversarialOkSecret, $adversarialReadyPath, $adversarialFfmpegIpv6 -ScriptBlock {
        param($Port, $ModeName, $ExpectedRequests, $Candidate, $Lookalike, $UnavailableContract, $UserHash, $FfmpegPath, $PublicIp, $PcpNonce, $OkSecret, $ReadyPath, $FfmpegIpv6)

        # HttpListener may be unavailable or ACL-restricted on lab hosts.  A
        # tiny TCP HTTP responder keeps this test PowerShell 5.1-compatible
        # and binds only to the IPv4 loopback address.
        $listener = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback, $Port)
        try {
            $listener.Start()
            for ($index = 0; $index -lt $ExpectedRequests; $index++) {
                $client = $listener.AcceptTcpClient()
                try {
                    $stream = $client.GetStream()
                    $reader = New-Object IO.StreamReader($stream, [Text.Encoding]::ASCII, $false, 1024, $true)
                    $requestLine = $reader.ReadLine()
                    while ($true) {
                        $header = $reader.ReadLine()
                        if ($null -eq $header -or $header.Length -eq 0) { break }
                    }
                    $path = (($requestLine -split ' ')[1])
                    $body = '{}'
                    $statusCode = 200
                    if ($path -eq '/api/reach/status') {
                        switch ($ModeName) {
                            'candidate' { $body = $Candidate }
                            'candidate-adversarial' { $body = $Candidate }
                            'candidate-envelope' { $body = '{"available":true,"data":' + $Candidate + '}' }
                            'candidate-envelope-unavailable' { $body = '{"available":false,"data":' + $Candidate + '}' }
                            'candidate-envelope-error' { $body = '{"available":true,"data":' + $Candidate + ',"error":"mock nested failure"}' }
                            'lookalike' { $body = $Lookalike }
                            'unavailable-contract' { $body = $UnavailableContract }
                            'absent' { $body = '{}' }
                            'malformed' { $body = '[]' }
                            'deceptive' { $body = '{"available":true}' }
                            'transport' { $body = '{"error":"mock unavailable"}'; $statusCode = 503 }
                        }
                    } elseif ($path -eq '/api/status') {
                        if ($ModeName -eq 'candidate-adversarial') {
                            $body = [ordered]@{
                                upnp_ports_forwarded = [ordered]@{ credential = $PcpNonce }
                            } | ConvertTo-Json -Compress
                        } else {
                            $body = [ordered]@{
                                upnp_ports_forwarded = 'unknown'
                                user_hash = $UserHash
                                public_ip = $PublicIp
                            } | ConvertTo-Json -Compress
                        }
                    } elseif ($path -eq '/api/live/preflight') {
                        if ($ModeName -eq 'candidate-adversarial') {
                            $body = [ordered]@{
                                ok = [ordered]@{ secret = $OkSecret }
                                ready = $ReadyPath
                                ffmpeg_available = $FfmpegIpv6
                            } | ConvertTo-Json -Compress
                        } else {
                            $body = [ordered]@{
                                ok = $true
                                ffmpeg_available = $true
                                ffmpeg_path = $FfmpegPath
                                public_ip = $PublicIp
                            } | ConvertTo-Json -Compress
                        }
                    }
                    $bytes = [Text.Encoding]::UTF8.GetBytes($body)
                    $reason = if ($statusCode -eq 200) { 'OK' } else { 'Service Unavailable' }
                    $response = "HTTP/1.1 $statusCode $reason`r`nContent-Type: application/json; charset=utf-8`r`nContent-Length: $($bytes.Length)`r`nConnection: close`r`n`r`n"
                    $responseBytes = [Text.Encoding]::ASCII.GetBytes($response)
                    $stream.Write($responseBytes, 0, $responseBytes.Length)
                    $stream.Write($bytes, 0, $bytes.Length)
                    $stream.Flush()
                } finally {
                    $client.Close()
                }
            }
        } finally {
            $listener.Stop()
        }
    }
    Start-Sleep -Milliseconds 150
    $mock = [pscustomobject]@{ port = $port; job = $job }
    $null = $activeMocks.Add($mock)
    return $mock
}

function Stop-ReachMock {
    param([Parameter(Mandatory = $true)][object]$Mock)

    try {
        $completed = Wait-Job -Job $Mock.job -Timeout 15
        if ($null -eq $completed) {
            Stop-Job -Job $Mock.job -ErrorAction SilentlyContinue
            throw 'loopback mock did not finish within 15 seconds'
        }
        Receive-Job -Job $Mock.job -ErrorAction Stop | Out-Null
    } finally {
        if ($Mock.job.State -eq 'Running') {
            Stop-Job -Job $Mock.job -ErrorAction SilentlyContinue
        }
        Remove-Job -Job $Mock.job -Force -ErrorAction SilentlyContinue
        $null = $activeMocks.Remove($Mock)
    }
}

function Invoke-ExpectExit {
    param(
        [Parameter(Mandatory = $true)][int]$Expected,
        [Parameter(Mandatory = $true)][scriptblock]$Action,
        [Parameter(Mandatory = $true)][string]$Name
    )

    & $Action
    if ($LASTEXITCODE -ne $Expected) {
        throw "$Name exit code was $LASTEXITCODE, expected $Expected"
    }
}

try {
    $golden = Start-ReachMock -Mode candidate -Requests 1
    Invoke-ExpectExit -Expected 0 -Name 'candidate Live validation' -Action {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $validator -Live `
            -BaseUrl "http://127.0.0.1:$($golden.port)" | Out-Null
    }
    Stop-ReachMock -Mock $golden

    $nestedGolden = Start-ReachMock -Mode candidate-envelope -Requests 1
    Invoke-ExpectExit -Expected 0 -Name 'candidate nested envelope Live validation' -Action {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $validator -Live `
            -BaseUrl "http://127.0.0.1:$($nestedGolden.port)" | Out-Null
    }
    Stop-ReachMock -Mock $nestedGolden

    $nestedUnavailable = Start-ReachMock -Mode candidate-envelope-unavailable -Requests 1
    Invoke-ExpectExit -Expected 1 -Name 'candidate unavailable nested envelope Live validation' -Action {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $validator -Live `
            -BaseUrl "http://127.0.0.1:$($nestedUnavailable.port)" | Out-Null
    }
    Stop-ReachMock -Mock $nestedUnavailable

    $nestedError = Start-ReachMock -Mode candidate-envelope-error -Requests 1
    Invoke-ExpectExit -Expected 1 -Name 'candidate error nested envelope Live validation' -Action {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $validator -Live `
            -BaseUrl "http://127.0.0.1:$($nestedError.port)" | Out-Null
    }
    Stop-ReachMock -Mock $nestedError

    $transport = Start-ReachMock -Mode transport -Requests 1
    Invoke-ExpectExit -Expected 1 -Name 'unavailable transport Live validation' -Action {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $validator -Live `
            -BaseUrl "http://127.0.0.1:$($transport.port)" | Out-Null
    }
    Stop-ReachMock -Mock $transport

    $absent = Start-ReachMock -Mode absent -Requests 1
    Invoke-ExpectExit -Expected 1 -Name 'missing data Live validation' -Action {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $validator -Live `
            -BaseUrl "http://127.0.0.1:$($absent.port)" | Out-Null
    }
    Stop-ReachMock -Mock $absent

    $malformed = Start-ReachMock -Mode malformed -Requests 1
    Invoke-ExpectExit -Expected 1 -Name 'malformed Live validation' -Action {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $validator -Live `
            -BaseUrl "http://127.0.0.1:$($malformed.port)" | Out-Null
    }
    Stop-ReachMock -Mock $malformed

    $lookalike = Start-ReachMock -Mode lookalike -Requests 1
    Invoke-ExpectExit -Expected 1 -Name 'lookalike Live validation' -Action {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $validator -Live `
            -BaseUrl "http://127.0.0.1:$($lookalike.port)" | Out-Null
    }
    Stop-ReachMock -Mock $lookalike

    $unavailableContract = Start-ReachMock -Mode unavailable-contract -Requests 1
    Invoke-ExpectExit -Expected 0 -Name 'valid unavailable Live validation' -Action {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $validator -Live `
            -BaseUrl "http://127.0.0.1:$($unavailableContract.port)" | Out-Null
    }
    Stop-ReachMock -Mock $unavailableContract

    $ready = Start-ReachMock -Mode candidate -Requests 3
    $readyOut = Join-Path $testRoot 'probe-ready.json'
    Invoke-ExpectExit -Expected 0 -Name 'candidate reach probe' -Action {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $probe -NodeRole A `
            -BaseUrl "http://127.0.0.1:$($ready.port)" -OutFile $readyOut | Out-Null
    }
    Stop-ReachMock -Mock $ready
    $readyProbe = Get-Content -LiteralPath $readyOut -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($readyProbe.gate_readiness -ne 'READY') { throw 'candidate reach probe was not READY' }
    $readyRaw = Get-Content -LiteralPath $readyOut -Raw -Encoding UTF8
    foreach ($forbiddenName in @('user_hash', 'ffmpeg_path', 'public_ip')) {
        if ($readyRaw -match ('"' + [regex]::Escape($forbiddenName) + '"\s*:')) {
            throw "candidate reach probe persisted forbidden field '$forbiddenName'"
        }
    }
    foreach ($forbiddenValue in @($sensitiveUserHash, $sensitiveFfmpegPath, $sensitivePublicIp)) {
        $encodedValue = (($forbiddenValue | ConvertTo-Json -Compress).Trim('"'))
        if ($readyRaw.Contains($forbiddenValue) -or $readyRaw.Contains($encodedValue)) {
            throw "candidate reach probe persisted forbidden marker '$forbiddenValue'"
        }
    }
    if ($readyProbe.status.upnp_ports_forwarded -ne 'unknown') {
        throw 'candidate reach probe lost the legacy UPnP tri-state projection'
    }
    if ((@($readyProbe.status.PSObject.Properties.Name) -join ',') -ne 'upnp_ports_forwarded') {
        throw 'candidate reach probe status projection contains fields outside its allowlist'
    }
    if ((@($readyProbe.live_preflight.PSObject.Properties.Name) -join ',') -ne 'ok,ffmpeg_available') {
        throw 'candidate reach probe preflight projection contains fields outside its allowlist'
    }
    foreach ($envelopeName in @('reach', 'status', 'live_preflight')) {
        $envelopeFields = @($readyProbe.api_envelopes.$envelopeName.PSObject.Properties.Name)
        if (($envelopeFields -join ',') -ne 'available,path,captured_at,error_present') {
            throw "candidate reach probe envelope '$envelopeName' contains unsafe or missing metadata fields"
        }
    }

    $adversarial = Start-ReachMock -Mode candidate-adversarial -Requests 3
    $adversarialOut = Join-Path $testRoot 'probe-adversarial-values.json'
    Invoke-ExpectExit -Expected 0 -Name 'candidate adversarial-value reach probe' -Action {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $probe -NodeRole A `
            -BaseUrl "http://127.0.0.1:$($adversarial.port)" -OutFile $adversarialOut | Out-Null
    }
    Stop-ReachMock -Mock $adversarial
    $adversarialProbe = Get-Content -LiteralPath $adversarialOut -Raw -Encoding UTF8 | ConvertFrom-Json
    $adversarialRaw = Get-Content -LiteralPath $adversarialOut -Raw -Encoding UTF8
    if ($adversarialProbe.gate_readiness -ne 'READY') {
        throw 'adversarial auxiliary values changed reach-contract readiness'
    }
    foreach ($forbiddenValue in @($adversarialPcpNonce, $adversarialOkSecret, $adversarialReadyPath, $adversarialFfmpegIpv6)) {
        $encodedValue = (($forbiddenValue | ConvertTo-Json -Compress).Trim('"'))
        if ($adversarialRaw.Contains($forbiddenValue) -or $adversarialRaw.Contains($encodedValue)) {
            throw "candidate reach probe persisted adversarial allowed-field value '$forbiddenValue'"
        }
    }
    $adversarialStatusFields = @()
    if ($null -ne $adversarialProbe.status) {
        $adversarialStatusFields = @($adversarialProbe.status.PSObject.Properties | ForEach-Object { $_.Name })
    }
    if ($adversarialStatusFields.Count -ne 0) {
        throw "invalid UPnP tri-state was not omitted from the safe status projection: $($adversarialStatusFields -join ',')"
    }
    $adversarialPreflightFields = @()
    if ($null -ne $adversarialProbe.live_preflight) {
        $adversarialPreflightFields = @($adversarialProbe.live_preflight.PSObject.Properties | ForEach-Object { $_.Name })
    }
    if ($adversarialPreflightFields.Count -ne 0) {
        throw "non-boolean preflight values were not omitted from the safe projection: $($adversarialPreflightFields -join ',')"
    }

    $deceptive = Start-ReachMock -Mode deceptive -Requests 3
    $deceptiveOut = Join-Path $testRoot 'probe-deceptive.json'
    Invoke-ExpectExit -Expected 0 -Name 'deceptive reach probe' -Action {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $probe -NodeRole A `
            -BaseUrl "http://127.0.0.1:$($deceptive.port)" -OutFile $deceptiveOut | Out-Null
    }
    Stop-ReachMock -Mock $deceptive
    $deceptiveProbe = Get-Content -LiteralPath $deceptiveOut -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($deceptiveProbe.gate_readiness -ne 'INSUFFICIENT_OBSERVABILITY') {
        throw 'deceptive wrapper reached READY without a reach-status contract'
    }

    $lookalikeProbeMock = Start-ReachMock -Mode lookalike -Requests 3
    $lookalikeOut = Join-Path $testRoot 'probe-lookalike.json'
    Invoke-ExpectExit -Expected 0 -Name 'lookalike reach probe' -Action {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $probe -NodeRole A `
            -BaseUrl "http://127.0.0.1:$($lookalikeProbeMock.port)" -OutFile $lookalikeOut | Out-Null
    }
    Stop-ReachMock -Mock $lookalikeProbeMock
    $lookalikeProbe = Get-Content -LiteralPath $lookalikeOut -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($lookalikeProbe.gate_readiness -ne 'INSUFFICIENT_OBSERVABILITY') {
        throw 'lookalike reach probe reached READY despite validator rejection'
    }
    Write-Host 'lookalike contract: validator FAIL; probe INSUFFICIENT_OBSERVABILITY' -ForegroundColor Green

    $unavailableProbeMock = Start-ReachMock -Mode unavailable-contract -Requests 3
    $unavailableOut = Join-Path $testRoot 'probe-unavailable-contract.json'
    Invoke-ExpectExit -Expected 0 -Name 'valid unavailable reach probe' -Action {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $probe -NodeRole A `
            -BaseUrl "http://127.0.0.1:$($unavailableProbeMock.port)" -OutFile $unavailableOut | Out-Null
    }
    Stop-ReachMock -Mock $unavailableProbeMock
    $unavailableProbe = Get-Content -LiteralPath $unavailableOut -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($unavailableProbe.gate_readiness -ne 'INSUFFICIENT_OBSERVABILITY') {
        throw 'valid unavailable reach probe reached READY'
    }
    Write-Host 'unavailable contract: validator PASS; probe INSUFFICIENT_OBSERVABILITY' -ForegroundColor Green
    Write-Host 'reach envelope mock: PASS' -ForegroundColor Green
} finally {
    foreach ($activeMock in @($activeMocks)) {
        try {
            Stop-ReachMock -Mock $activeMock
        } catch {
            Write-Verbose "failed to clean up loopback mock: $($_.Exception.Message)"
        }
    }
    Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction SilentlyContinue
}
