[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('ping', 'upload', 'run', 'job', 'cancel', 'download', 'stop')]
    [string]$Command,
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$AgentIPv4,
    [ValidateRange(1024, 65535)][int]$Port = 8015,
    [string]$Token = '',
    [string]$TokenDpapiPath = (
        Join-Path $env:LOCALAPPDATA (
            'eSE-Lab-Controller\smallframe-token.dpapi')),
    [string]$SourcePath = '',
    [string]$RemotePath = '',
    [string]$JobId = '',
    [string]$JobRequestPath = '',
    [string]$OutputPath = '',
    [ValidateRange(64, 384)][int]$ChunkBytes = 256,
    [ValidateRange(1000, 30000)][int]$TimeoutMilliseconds = 10000
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$parsedAgentIPv4 = $null
if (-not [Net.IPAddress]::TryParse($AgentIPv4, [ref]$parsedAgentIPv4) -or
    $parsedAgentIPv4.AddressFamily -ne
        [Net.Sockets.AddressFamily]::InterNetwork -or
    $parsedAgentIPv4.Equals([Net.IPAddress]::Any)) {
    throw 'AgentIPv4 must be an explicit, usable IPv4 literal.'
}
$AgentIPv4 = $parsedAgentIPv4.ToString()

function Get-ControllerToken {
    if ($Token -match '^[0-9a-fA-F]{64}$') {
        return $Token.ToLowerInvariant()
    }
    if (-not (Test-Path -LiteralPath $TokenDpapiPath -PathType Leaf)) {
        throw "Missing small-frame token: $TokenDpapiPath"
    }
    $secure = ConvertTo-SecureString (
        (Get-Content -LiteralPath $TokenDpapiPath -Raw).Trim())
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try {
        $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
    if ($plain -notmatch '^[0-9a-fA-F]{64}$') {
        throw 'Stored small-frame token is invalid.'
    }
    return $plain.ToLowerInvariant()
}

function Invoke-SmallFrame {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [AllowNull()]$Payload
    )
    $request = [ordered]@{
        token = $script:controllerToken
        command = $Name
        payload = $Payload
    }
    $json = $request | ConvertTo-Json -Depth 8 -Compress
    if ([Text.Encoding]::UTF8.GetByteCount($json) -gt 8192) {
        throw 'Small-frame request exceeded 8192 bytes.'
    }
    $client = New-Object Net.Sockets.TcpClient
    try {
        $async = $client.BeginConnect($AgentIPv4, $Port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne(5000)) {
            throw "Timeout connecting to $AgentIPv4`:$Port."
        }
        $client.EndConnect($async)
        $stream = $client.GetStream()
        $stream.ReadTimeout = $TimeoutMilliseconds
        $stream.WriteTimeout = $TimeoutMilliseconds
        $writer = New-Object IO.StreamWriter(
            $stream, (New-Object Text.UTF8Encoding($false)), 1024, $true)
        $writer.NewLine = "`n"
        $writer.WriteLine($json)
        $writer.Flush()
        $reader = New-Object IO.StreamReader(
            $stream, (New-Object Text.UTF8Encoding($false)),
            $false, 1024, $true)
        $line = $reader.ReadLine()
        if ([string]::IsNullOrWhiteSpace($line)) {
            throw 'Agent returned an empty response.'
        }
        if ([Text.Encoding]::UTF8.GetByteCount($line) -gt 900) {
            throw 'Agent violated the small-frame response limit.'
        }
        $response = $line | ConvertFrom-Json
        if (-not [bool]$response.ok) {
            throw "Agent rejected $Name`: $($response.error)"
        }
        return $response.data
    } finally {
        $client.Dispose()
    }
}

$script:controllerToken = Get-ControllerToken

switch ($Command) {
    'ping' {
        Invoke-SmallFrame -Name ping -Payload @{}
    }
    'upload' {
        if (-not (Test-Path -LiteralPath $SourcePath -PathType Leaf) -or
            [string]::IsNullOrWhiteSpace($RemotePath)) {
            throw 'upload requires SourcePath and RemotePath.'
        }
        $bytes = [IO.File]::ReadAllBytes(
            [IO.Path]::GetFullPath($SourcePath))
        $sha = [Security.Cryptography.SHA256]::Create()
        try {
            $hash = (($sha.ComputeHash($bytes) | ForEach-Object {
                        $_.ToString('x2')
                    }) -join '')
        } finally {
            $sha.Dispose()
        }
        $null = Invoke-SmallFrame -Name put_begin -Payload ([ordered]@{
                path = $RemotePath.Replace('\', '/')
                bytes = $bytes.Length
                sha256 = $hash
            })
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $count = [Math]::Min($ChunkBytes, $bytes.Length - $offset)
            $chunk = New-Object byte[] $count
            [Array]::Copy($bytes, $offset, $chunk, 0, $count)
            $result = Invoke-SmallFrame -Name put_chunk -Payload (
                [ordered]@{
                    path = $RemotePath.Replace('\', '/')
                    offset = $offset
                    data = [Convert]::ToBase64String($chunk)
                })
            $offset = [int]$result.offset
        }
        Invoke-SmallFrame -Name put_commit -Payload (
            [ordered]@{ path = $RemotePath.Replace('\', '/') })
    }
    'run' {
        if ($JobId -notmatch '^[0-9a-fA-F]{32}$' -or
            [string]::IsNullOrWhiteSpace($RemotePath)) {
            throw 'run requires JobId and remote entrypoint path.'
        }
        $jobRequest = @{}
        if (-not [string]::IsNullOrWhiteSpace($JobRequestPath)) {
            $jobRequest = Get-Content -LiteralPath $JobRequestPath -Raw |
                ConvertFrom-Json
        }
        Invoke-SmallFrame -Name run -Payload ([ordered]@{
                job_id = $JobId.ToLowerInvariant()
                entrypoint = $RemotePath.Replace('\', '/')
                request = $jobRequest
            })
    }
    'job' {
        if ($JobId -notmatch '^[0-9a-fA-F]{32}$') {
            throw 'job requires JobId.'
        }
        Invoke-SmallFrame -Name job -Payload (
            [ordered]@{ job_id = $JobId.ToLowerInvariant() })
    }
    'cancel' {
        if ($JobId -notmatch '^[0-9a-fA-F]{32}$') {
            throw 'cancel requires JobId.'
        }
        Invoke-SmallFrame -Name cancel -Payload (
            [ordered]@{ job_id = $JobId.ToLowerInvariant() })
    }
    'download' {
        if ([string]::IsNullOrWhiteSpace($RemotePath) -or
            [string]::IsNullOrWhiteSpace($OutputPath)) {
            throw 'download requires RemotePath and OutputPath.'
        }
        $output = [IO.Path]::GetFullPath($OutputPath)
        $directory = Split-Path -Parent $output
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
        $temporary = $output + '.new'
        $stream = [IO.File]::Open(
            $temporary, [IO.FileMode]::Create, [IO.FileAccess]::Write,
            [IO.FileShare]::None)
        $offset = 0L
        try {
            do {
                $part = Invoke-SmallFrame -Name read -Payload ([ordered]@{
                        path = $RemotePath.Replace('\', '/')
                        offset = $offset
                        length = [Math]::Min(256, $ChunkBytes)
                    })
                $bytes = [Convert]::FromBase64String([string]$part.data)
                $stream.Write($bytes, 0, $bytes.Length)
                $offset += $bytes.Length
            } while (-not [bool]$part.eof)
            $stream.Flush($true)
        } finally {
            $stream.Dispose()
        }
        Move-Item -LiteralPath $temporary -Destination $output -Force
        Get-Item -LiteralPath $output
    }
    'stop' {
        Invoke-SmallFrame -Name stop -Payload @{}
    }
}
