[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$root = Join-Path $env:TEMP (
    'ese-smallframe-selftest-' + [Guid]::NewGuid().ToString('N'))
$dataRoot = Join-Path $root 'data'
$tokenPath = Join-Path $root 'token.txt'
$agentStdout = Join-Path $root 'agent.stdout.log'
$agentStderr = Join-Path $root 'agent.stderr.log'
$token = 'a' * 64
$port = Get-Random -Minimum 18000 -Maximum 28000
$mutexName = 'Local\eSE-Lab-SmallFrame-Agent-' +
    [Guid]::NewGuid().ToString('N')
New-Item -ItemType Directory -Path $root -Force | Out-Null
[IO.File]::WriteAllText(
    $tokenPath, $token, (New-Object Text.ASCIIEncoding))

function Invoke-SmallFrame {
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [AllowNull()]$Payload
    )
    $client = New-Object Net.Sockets.TcpClient
    try {
        $client.Connect('127.0.0.1', $port)
        $stream = $client.GetStream()
        $stream.ReadTimeout = 5000
        $writer = New-Object IO.StreamWriter(
            $stream, (New-Object Text.UTF8Encoding($false)), 1024, $true)
        $writer.NewLine = "`n"
        $request = [ordered]@{
            token = $token
            command = $Command
            payload = $Payload
        }
        $writer.WriteLine(($request | ConvertTo-Json -Depth 8 -Compress))
        $writer.Flush()
        $reader = New-Object IO.StreamReader(
            $stream, (New-Object Text.UTF8Encoding($false)),
            $false, 1024, $true)
        $line = $reader.ReadLine()
        if ([Text.Encoding]::UTF8.GetByteCount($line) -gt 900) {
            throw 'Response exceeded the small-frame contract.'
        }
        $response = $line | ConvertFrom-Json
        if (-not [bool]$response.ok) {
            throw (
                "Agent rejected $Command at line $($response.line): " +
                [string]$response.error + ' ' + [string]$response.stack
            )
        }
        return $response.data
    } finally {
        $client.Dispose()
    }
}

$agent = $null
try {
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = Join-Path $env:SystemRoot (
        'System32\WindowsPowerShell\v1.0\powershell.exe')
    $start.Arguments = (
        '-NoProfile -ExecutionPolicy Bypass -File "{0}" ' +
        '-TokenFile "{1}" -Root "{2}" -ListenIPv4 127.0.0.1 ' +
        '-AllowedSourceIPv4 127.0.0.1 -Port {3} -MutexName "{4}"'
    ) -f (
        Join-Path $PSScriptRoot 'run_ese_lab_smallframe_agent.ps1'
    ), $tokenPath, $dataRoot, $port, $mutexName
    $start.UseShellExecute = $true
    $start.WindowStyle = [Diagnostics.ProcessWindowStyle]::Hidden
    $agent = [Diagnostics.Process]::Start($start)

    $ready = $false
    foreach ($attempt in 1..50) {
        Start-Sleep -Milliseconds 100
        try {
            $ping = Invoke-SmallFrame -Command ping -Payload @{}
            $pingUtc = [DateTimeOffset]::MinValue
            $clockValid = [DateTimeOffset]::TryParse(
                [string]$ping.utc_now,
                [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::RoundtripKind,
                [ref]$pingUtc)
            if ([string]$ping.schema -ceq 'ese.lab.smallframe-ping/v2' -and
                [int]$ping.protocol -eq 2 -and $clockValid -and
                @($ping.capabilities) -ccontains 'cooperative_cancel') {
                $ready = $true
                break
            }
        } catch {
        }
    }
    if (-not $ready) {
        throw 'Agent did not start.'
    }

    $job = [Guid]::NewGuid().ToString('N')
    $relative = "injected/$job/selftest.ps1"
    $source = @'
param([string]$JobRequestPath)
$request = Get-Content -LiteralPath $JobRequestPath -Raw | ConvertFrom-Json
$jobRoot = Split-Path -Parent $JobRequestPath
$value = [string]$request.value
if ($value -ceq 'wait-for-cancel') {
    $cancelPath = Join-Path $jobRoot 'cancel-request.json'
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds(10)
    while (-not (Test-Path -LiteralPath $cancelPath -PathType Leaf) -and
        [DateTimeOffset]::UtcNow -lt $deadline) {
        Start-Sleep -Milliseconds 50
    }
    if (-not (Test-Path -LiteralPath $cancelPath -PathType Leaf)) {
        throw 'Cooperative cancel was not observed by the child.'
    }
    $value = 'cancellation-observed'
}
$result = [ordered]@{
    schema = 'ese.lab.smallframe-selftest/v1'
    value = $value
}
$path = Join-Path $jobRoot 'result.json'
[IO.File]::WriteAllText(
    $path, ($result | ConvertTo-Json -Compress),
    (New-Object Text.UTF8Encoding($false)))
'@
    $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes($source)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $hash = (($sha.ComputeHash($bytes) | ForEach-Object {
                    $_.ToString('x2')
                }) -join '')
    } finally {
        $sha.Dispose()
    }
    $begin = Invoke-SmallFrame -Command put_begin -Payload (
        [ordered]@{ path = $relative; bytes = $bytes.Length; sha256 = $hash })
    if ($begin.state -cne 'READY') { throw 'put_begin failed' }
    $offset = 0
    while ($offset -lt $bytes.Length) {
        $count = [Math]::Min(127, $bytes.Length - $offset)
        $chunk = New-Object byte[] $count
        [Array]::Copy($bytes, $offset, $chunk, 0, $count)
        $written = Invoke-SmallFrame -Command put_chunk -Payload (
            [ordered]@{
                path = $relative
                offset = $offset
                data = [Convert]::ToBase64String($chunk)
            })
        $offset = [int]$written.offset
    }
    $commit = Invoke-SmallFrame -Command put_commit -Payload (
        [ordered]@{ path = $relative })
    if ($commit.sha256 -cne $hash) { throw 'put_commit hash mismatch' }

    $started = Invoke-SmallFrame -Command run -Payload ([ordered]@{
            job_id = $job
            entrypoint = $relative
            request = [ordered]@{ value = 'round-trip-ok' }
        })
    if ($started.state -cne 'RUNNING') { throw 'run failed' }
    $state = $null
    foreach ($attempt in 1..100) {
        Start-Sleep -Milliseconds 100
        $state = Invoke-SmallFrame -Command job -Payload (
            [ordered]@{ job_id = $job })
        if ($state.state -in 'COMPLETE', 'ERROR') { break }
    }
    if ($state.state -cne 'COMPLETE') {
        throw "Job state was $($state.state)."
    }

    $relativeResult = "jobs/$job/result.json"
    $resultBytes = [Collections.Generic.List[byte]]::new()
    $offset = 0L
    do {
        $part = Invoke-SmallFrame -Command read -Payload (
            [ordered]@{
                path = $relativeResult
                offset = $offset
                length = 73
            })
        $chunk = [Convert]::FromBase64String([string]$part.data)
        $resultBytes.AddRange($chunk)
        $offset += $chunk.Length
    } while (-not [bool]$part.eof)
    $result = (New-Object Text.UTF8Encoding($false)).
        GetString($resultBytes.ToArray()) | ConvertFrom-Json
    if ($result.value -cne 'round-trip-ok') {
        throw 'Result round trip failed.'
    }
    $cancelJob = [Guid]::NewGuid().ToString('N')
    $cancelStarted = Invoke-SmallFrame -Command run -Payload ([ordered]@{
            job_id = $cancelJob
            entrypoint = $relative
            request = [ordered]@{ value = 'wait-for-cancel' }
        })
    if ([string]$cancelStarted.state -cne 'RUNNING') {
        throw 'Cancellation fixture did not start.'
    }
    $cancel = Invoke-SmallFrame -Command cancel -Payload (
        [ordered]@{ job_id = $cancelJob })
    if ([string]$cancel.state -cne 'CANCEL_SIGNALLED' -or
        [string]$cancel.job_id -cne $cancelJob) {
        throw 'Authenticated cooperative cancel signal failed.'
    }
    $cancelRelative = "jobs/$cancelJob/cancel-request.json"
    $cancelBytes = [Collections.Generic.List[byte]]::new()
    $cancelOffset = 0L
    do {
        $cancelPart = Invoke-SmallFrame -Command read -Payload (
            [ordered]@{
                path = $cancelRelative
                offset = $cancelOffset
                length = 73
            })
        $cancelChunk = [Convert]::FromBase64String(
            [string]$cancelPart.data)
        $cancelBytes.AddRange($cancelChunk)
        $cancelOffset += $cancelChunk.Length
    } while (-not [bool]$cancelPart.eof)
    $cancelEvidence = (New-Object Text.UTF8Encoding($false)).
        GetString($cancelBytes.ToArray()) | ConvertFrom-Json
    if ([string]$cancelEvidence.schema -cne
            'ese.lab.cooperative-cancel/v1' -or
        [string]$cancelEvidence.job_id -cne $cancelJob) {
        throw 'Cooperative cancel evidence is invalid.'
    }
    $cancelState = $null
    foreach ($attempt in 1..100) {
        Start-Sleep -Milliseconds 100
        $cancelState = Invoke-SmallFrame -Command job -Payload (
            [ordered]@{ job_id = $cancelJob })
        if ($cancelState.state -in 'COMPLETE', 'ERROR') { break }
    }
    if ([string]$cancelState.state -cne 'COMPLETE') {
        throw "Cancellation fixture state was $($cancelState.state)."
    }
    Write-Host "Small-frame agent self-test PASS: $root"
} finally {
    if ($null -ne $agent -and -not $agent.HasExited) {
        Stop-Process -Id $agent.Id -Force -ErrorAction SilentlyContinue
        $agent.WaitForExit(5000) | Out-Null
    }
}
