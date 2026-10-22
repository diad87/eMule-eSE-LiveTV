[CmdletBinding()]
param(
    [string]$TokenFile = 'C:\ProgramData\eSE-Lab-Agent\smallframe-token.txt',
    [string]$Root = 'C:\ProgramData\eSE-Lab-Agent\smallframe-data',
    [string]$ListenIPv4 = '0.0.0.0',
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$AllowedSourceIPv4,
    [ValidateRange(1024, 65535)][int]$Port = 8015,
    [ValidatePattern('^(?:Global|Local)\\eSE-Lab-SmallFrame-Agent(?:-[0-9a-f]{32})?$')]
    [string]$MutexName = 'Global\eSE-Lab-SmallFrame-Agent'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$parsedAllowedSourceIPv4 = $null
if (-not [Net.IPAddress]::TryParse(
        $AllowedSourceIPv4, [ref]$parsedAllowedSourceIPv4) -or
    $parsedAllowedSourceIPv4.AddressFamily -ne
        [Net.Sockets.AddressFamily]::InterNetwork -or
    $parsedAllowedSourceIPv4.Equals([Net.IPAddress]::Any)) {
    throw 'AllowedSourceIPv4 must be an explicit, usable IPv4 literal.'
}
$AllowedSourceIPv4 = $parsedAllowedSourceIPv4.ToString()

function Write-CompactJson {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][string]$Path
    )
    $temporary = $Path + '.new'
    [IO.File]::WriteAllText(
        $temporary,
        ($Value | ConvertTo-Json -Depth 8 -Compress),
        (New-Object Text.UTF8Encoding($false))
    )
    Move-Item -LiteralPath $temporary -Destination $Path -Force
}

function Get-Sha256 {
    param([Parameter(Mandatory = $true)][string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).
        Hash.ToLowerInvariant()
}

function Resolve-ContainedPath {
    param(
        [Parameter(Mandatory = $true)][string]$RelativePath,
        [switch]$AllowPartial
    )
    $relative = $RelativePath.Replace('\', '/').Trim('/')
    if ([string]::IsNullOrWhiteSpace($relative) -or
        [IO.Path]::IsPathRooted($relative) -or
        $relative.Split('/') -contains '..' -or
        $relative -cnotmatch (
            '^(injected|jobs)/[0-9a-f]{32}/' +
            '[A-Za-z0-9_.\-/]+\.(ps1|json|log|txt|bin|pcap|pcapng' +
            $(if ($AllowPartial) { '|part' } else { '' }) + ')$'
        )) {
        throw 'path_not_allowed'
    }
    $path = [IO.Path]::GetFullPath(
        (Join-Path $Root $relative.Replace('/', '\')))
    $prefix = [IO.Path]::GetFullPath($Root).TrimEnd('\') + '\'
    if (-not $path.StartsWith(
            $prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'path_escape'
    }
    return $path
}

$token = (Get-Content -LiteralPath $TokenFile -Raw).Trim()
if ($token -notmatch '^[0-9a-f]{64}$') {
    throw 'invalid_token_file'
}
New-Item -ItemType Directory -Path $Root -Force | Out-Null

$child = $null
$childJob = ''
$childStdout = ''
$childStderr = ''

function Update-Child {
    if ($null -eq $script:child) { return }
    $script:child.Refresh()
    if (-not $script:child.HasExited) { return }
    $statusPath = Join-Path $Root "jobs\$($script:childJob)\status.json"
    Write-CompactJson -Path $statusPath -Value ([ordered]@{
            schema = 'ese.lab.smallframe-job/v1'
            job_id = $script:childJob
            state = if ($script:child.ExitCode -eq 0) {
                'COMPLETE'
            } else { 'ERROR' }
            exit_code = [int]$script:child.ExitCode
            stdout = 'stdout.log'
            stderr = 'stderr.log'
            updated_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
        })
    $script:child.Dispose()
    $script:child = $null
    $script:childJob = ''
}

function Invoke-SmallFrameRequest {
    param([Parameter(Mandatory = $true)]$Request)

    if ([string]$Request.token -cne $token) { throw 'auth_rejected' }
    Update-Child
    $command = ([string]$Request.command).ToLowerInvariant()
    $payload = $Request.payload
    switch ($command) {
        'ping' {
            return [ordered]@{
                schema = 'ese.lab.smallframe-ping/v2'
                state = if ($null -eq $script:child) { 'IDLE' } else {
                    'RUNNING'
                }
                job_id = $script:childJob
                protocol = 2
                utc_now = [DateTimeOffset]::UtcNow.ToString('o')
                capabilities = @('cooperative_cancel')
            }
        }
        'put_begin' {
            if ($null -ne $script:child) { throw 'job_active' }
            $path = Resolve-ContainedPath -RelativePath (
                [string]$payload.path)
            [Int64]$bytes = [Int64]$payload.bytes
            $sha256 = ([string]$payload.sha256).ToLowerInvariant()
            if ($bytes -lt 1 -or $bytes -gt 16777216 -or
                $sha256 -notmatch '^[0-9a-f]{64}$') {
                throw 'invalid_file_contract'
            }
            $directory = Split-Path -Parent $path
            New-Item -ItemType Directory -Path $directory -Force |
                Out-Null
            $partial = $path + '.part'
            [IO.File]::WriteAllBytes($partial, (New-Object byte[] 0))
            Write-CompactJson -Path ($partial + '.json') -Value (
                [ordered]@{
                    path = [string]$payload.path
                    bytes = $bytes
                    sha256 = $sha256
                })
            return [ordered]@{ state = 'READY'; offset = 0 }
        }
        'put_chunk' {
            if ($null -ne $script:child) { throw 'job_active' }
            $path = Resolve-ContainedPath -RelativePath (
                [string]$payload.path)
            $partial = $path + '.part'
            $contractPath = $partial + '.json'
            if (-not (Test-Path -LiteralPath $partial -PathType Leaf) -or
                -not (Test-Path -LiteralPath $contractPath -PathType Leaf)) {
                throw 'upload_not_started'
            }
            $contract = Get-Content -LiteralPath $contractPath -Raw |
                ConvertFrom-Json
            $chunk = [Convert]::FromBase64String([string]$payload.data)
            if ($chunk.Length -lt 1 -or $chunk.Length -gt 384) {
                throw 'invalid_chunk_size'
            }
            $item = Get-Item -LiteralPath $partial
            if ([Int64]$payload.offset -ne $item.Length -or
                $item.Length + $chunk.Length -gt [Int64]$contract.bytes) {
                throw 'invalid_chunk_offset'
            }
            $stream = [IO.File]::Open(
                $partial, [IO.FileMode]::Append, [IO.FileAccess]::Write,
                [IO.FileShare]::None)
            try {
                $stream.Write($chunk, 0, $chunk.Length)
                $stream.Flush($true)
            } finally {
                $stream.Dispose()
            }
            return [ordered]@{
                state = 'PARTIAL'
                offset = [Int64]$item.Length + $chunk.Length
            }
        }
        'put_commit' {
            if ($null -ne $script:child) { throw 'job_active' }
            $path = Resolve-ContainedPath -RelativePath (
                [string]$payload.path)
            $partial = $path + '.part'
            $contractPath = $partial + '.json'
            $contract = Get-Content -LiteralPath $contractPath -Raw |
                ConvertFrom-Json
            $item = Get-Item -LiteralPath $partial
            if ($item.Length -ne [Int64]$contract.bytes -or
                (Get-Sha256 -Path $partial) -cne
                    [string]$contract.sha256) {
                throw 'file_integrity_failed'
            }
            Move-Item -LiteralPath $partial -Destination $path -Force
            Remove-Item -LiteralPath $contractPath -Force
            return [ordered]@{
                state = 'COMMITTED'
                bytes = [Int64]$item.Length
                sha256 = [string]$contract.sha256
            }
        }
        'run' {
            if ($null -ne $script:child) { throw 'job_active' }
            $job = ([string]$payload.job_id).ToLowerInvariant()
            if ($job -notmatch '^[0-9a-f]{32}$') {
                throw 'invalid_job_id'
            }
            $entrypoint = Resolve-ContainedPath -RelativePath (
                [string]$payload.entrypoint)
            if (-not (Test-Path -LiteralPath $entrypoint -PathType Leaf) -or
                [IO.Path]::GetExtension($entrypoint) -cne '.ps1') {
                throw 'entrypoint_missing'
            }
            $jobRoot = Join-Path $Root "jobs\$job"
            if (Test-Path -LiteralPath $jobRoot) {
                throw 'job_id_used'
            }
            New-Item -ItemType Directory -Path $jobRoot -Force | Out-Null
            $requestPath = Join-Path $jobRoot 'request.json'
            [IO.File]::WriteAllText(
                $requestPath,
                ($payload.request | ConvertTo-Json -Depth 8 -Compress),
                (New-Object Text.UTF8Encoding($false))
            )
            $script:childStdout = Join-Path $jobRoot 'stdout.log'
            $script:childStderr = Join-Path $jobRoot 'stderr.log'
            $arguments = (
                '-NoProfile -ExecutionPolicy Bypass -File "{0}" ' +
                '-JobRequestPath "{1}"'
            ) -f $entrypoint, $requestPath
            [IO.File]::WriteAllText(
                $script:childStdout, '',
                (New-Object Text.UTF8Encoding($false)))
            [IO.File]::WriteAllText(
                $script:childStderr, '',
                (New-Object Text.UTF8Encoding($false)))
            # ShellExecute avoids the Windows PowerShell Start-Process defect
            # when an orchestrator injected both Path and PATH. The wrapper
            # then canonicalizes Path before launching the actual job.
            $wrapper = Join-Path $jobRoot 'run.cmd'
            $powershellPath = Join-Path $env:SystemRoot (
                'System32\WindowsPowerShell\v1.0\powershell.exe')
            $canonicalPath = (
                "$env:SystemRoot\System32;$env:SystemRoot;" +
                "$env:SystemRoot\System32\WindowsPowerShell\v1.0;" +
                "$env:ProgramFiles\Tailscale"
            )
            $wrapperText = @(
                '@echo off',
                ('set "PATH={0}"' -f $canonicalPath),
                (
                    '"{0}" {1} 1>"{2}" 2>"{3}"' -f
                    $powershellPath, $arguments,
                    $script:childStdout, $script:childStderr
                ),
                'exit /b %errorlevel%'
            ) -join "`r`n"
            [IO.File]::WriteAllText(
                $wrapper, $wrapperText,
                (New-Object Text.ASCIIEncoding))
            $start = New-Object Diagnostics.ProcessStartInfo
            $start.FileName = $wrapper
            $start.UseShellExecute = $true
            $start.WindowStyle = [Diagnostics.ProcessWindowStyle]::Hidden
            $script:child = [Diagnostics.Process]::Start($start)
            $script:childJob = $job
            Write-CompactJson -Path (Join-Path $jobRoot 'status.json') `
                -Value ([ordered]@{
                    schema = 'ese.lab.smallframe-job/v1'
                    job_id = $job
                    state = 'RUNNING'
                    pid = [int]$script:child.Id
                    updated_at_utc =
                        [DateTimeOffset]::UtcNow.ToString('o')
                })
            return [ordered]@{
                state = 'RUNNING'
                job_id = $job
                pid = [int]$script:child.Id
            }
        }
        'job' {
            $job = ([string]$payload.job_id).ToLowerInvariant()
            $statusPath = Resolve-ContainedPath -RelativePath (
                "jobs/$job/status.json")
            if (-not (Test-Path -LiteralPath $statusPath -PathType Leaf)) {
                throw 'job_missing'
            }
            return Get-Content -LiteralPath $statusPath -Raw |
                ConvertFrom-Json
        }
        'cancel' {
            $job = ([string]$payload.job_id).ToLowerInvariant()
            if ($job -notmatch '^[0-9a-f]{32}$') {
                throw 'invalid_job_id'
            }
            if ($null -eq $script:child -or
                $script:childJob -cne $job) {
                throw 'job_not_active'
            }
            $cancelPath = Join-Path $Root "jobs\$job\cancel-request.json"
            Write-CompactJson -Path $cancelPath -Value ([ordered]@{
                    schema = 'ese.lab.cooperative-cancel/v1'
                    job_id = $job
                    requested_at_utc =
                        [DateTimeOffset]::UtcNow.ToString('o')
                })
            return [ordered]@{
                state = 'CANCEL_SIGNALLED'
                job_id = $job
            }
        }
        'read' {
            $path = Resolve-ContainedPath -RelativePath (
                [string]$payload.path)
            if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
                throw 'file_missing'
            }
            [Int64]$offset = [Int64]$payload.offset
            [int]$length = [int]$payload.length
            if ($length -lt 1 -or $length -gt 256) {
                throw 'invalid_read_length'
            }
            $item = Get-Item -LiteralPath $path
            if ($offset -lt 0 -or $offset -gt $item.Length) {
                throw 'invalid_read_offset'
            }
            $count = [int][Math]::Min(
                [Int64]$length, $item.Length - $offset)
            $bytes = New-Object byte[] $count
            $stream = [IO.File]::Open(
                $path, [IO.FileMode]::Open, [IO.FileAccess]::Read,
                [IO.FileShare]::ReadWrite)
            try {
                $stream.Position = $offset
                $read = $stream.Read($bytes, 0, $count)
            } finally {
                $stream.Dispose()
            }
            if ($read -ne $count) { throw 'partial_read' }
            return [ordered]@{
                offset = $offset
                bytes = $count
                file_bytes = [Int64]$item.Length
                eof = ($offset + $count -ge $item.Length)
                data = [Convert]::ToBase64String($bytes)
            }
        }
        'stop' {
            if ($null -ne $script:child) {
                Stop-Process -Id $script:child.Id -Force `
                    -ErrorAction SilentlyContinue
                $script:child.WaitForExit(5000) | Out-Null
                Update-Child
            }
            return [ordered]@{ state = 'IDLE' }
        }
        default { throw 'command_not_allowed' }
    }
}

$created = $false
$mutex = New-Object Threading.Mutex(
    $true, $MutexName, [ref]$created)
if (-not $created) { throw 'agent_already_running' }
$listener = $null
try {
    $listener = New-Object Net.Sockets.TcpListener(
        [Net.IPAddress]::Parse($ListenIPv4), $Port)
    $listener.Start(8)
    while ($true) {
        Update-Child
        $client = $listener.AcceptTcpClient()
        try {
            $remote = [Net.IPEndPoint]$client.Client.RemoteEndPoint
            if ($remote.Address.ToString() -cne $AllowedSourceIPv4) {
                throw 'source_rejected'
            }
            $stream = $client.GetStream()
            $stream.ReadTimeout = 10000
            $stream.WriteTimeout = 10000
            $reader = New-Object IO.StreamReader(
                $stream, (New-Object Text.UTF8Encoding($false)),
                $false, 1024, $true)
            $line = $reader.ReadLine()
            if ([string]::IsNullOrWhiteSpace($line) -or
                [Text.Encoding]::UTF8.GetByteCount($line) -gt 8192) {
                throw 'request_size'
            }
            $request = $line | ConvertFrom-Json
            $data = Invoke-SmallFrameRequest -Request $request
            $response = [ordered]@{ ok = $true; data = $data }
        } catch {
            $response = [ordered]@{
                ok = $false
                error = $_.Exception.Message.Substring(
                    0, [Math]::Min(160, $_.Exception.Message.Length))
                line = [int]$_.InvocationInfo.ScriptLineNumber
                stack = ([string]$_.ScriptStackTrace).Substring(
                    0, [Math]::Min(
                        300, ([string]$_.ScriptStackTrace).Length))
            }
        }
        try {
            $writer = New-Object IO.StreamWriter(
                $client.GetStream(),
                (New-Object Text.UTF8Encoding($false)), 1024, $true)
            $writer.NewLine = "`n"
            $json = $response | ConvertTo-Json -Depth 8 -Compress
            if ([Text.Encoding]::UTF8.GetByteCount($json) -gt 900) {
                $json = '{"ok":false,"error":"response_too_large"}'
            }
            $writer.WriteLine($json)
            $writer.Flush()
        } finally {
            $client.Dispose()
        }
    }
} finally {
    if ($null -ne $listener) { $listener.Stop() }
    if ($null -ne $child) {
        Stop-Process -Id $child.Id -Force -ErrorAction SilentlyContinue
    }
    if ($created) { $mutex.ReleaseMutex() }
    $mutex.Dispose()
}
