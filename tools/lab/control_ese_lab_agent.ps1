# Generic controller for the installed eSE lab agent.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet(
        'status', 'set_config', 'run', 'deploy', 'fetch_from_h1', 'run_tool',
        'list_files', 'download', 'stop_test', 'restart_agent', 'shutdown'
    )]
    [string]$Command,

    [ValidatePattern('^\d{1,3}(\.\d{1,3}){3}$')]
    [string]$AgentIPv4 = '192.168.68.64',

    [ValidateRange(1024, 65535)]
    [int]$Port = 8013,

    [ValidatePattern('^$|^[0-9A-Fa-f]{64}$')]
    [string]$Token = $env:ESE_LAB_AGENT_TOKEN,

    [string]$ConfigPath = '',

    [string[]]$DeploySourcePath = @(),
    [string[]]$DeployTargetPath = @(),

    [ValidatePattern('^$|^[0-9A-Fa-f]{32}$')]
    [string]$JobId = '',
    [string]$Entrypoint = '',
    [string]$JobRequestPath = '',
    [string]$RemotePath = '',
    [string]$SourceUrl = '',
    [string]$ExpectedSha256 = '',
    [ValidateRange(1, 8589934592)]
    [Int64]$ExpectedBytes = 1,
    [ValidateRange(0, 9223372036854775807)]
    [Int64]$Offset = 0,
    [ValidateRange(1, 786432)]
    [int]$Length = 786432,

    [ValidateRange(1000, 120000)]
    [int]$ResponseTimeoutMilliseconds = 10000
)

$ErrorActionPreference = 'Stop'
if ($Token -notmatch '^[0-9A-Fa-f]{64}$') {
    throw (
        'Falta ESE_LAB_AGENT_TOKEN o -Token con la credencial de 256 bits ' +
        'emparejada con el agente.'
    )
}
$request = [ordered]@{
    token = $Token
    command = $Command
}

if ($Command -eq 'set_config') {
    if ([string]::IsNullOrWhiteSpace($ConfigPath) -or
        -not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
        throw 'set_config requiere -ConfigPath a un fichero existente.'
    }
    $bytes = [IO.File]::ReadAllBytes(
        [IO.Path]::GetFullPath($ConfigPath))
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $hash = (($sha.ComputeHash($bytes) | ForEach-Object {
                    $_.ToString('x2')
                }) -join '')
    } finally {
        $sha.Dispose()
    }
    $request.content_base64 = [Convert]::ToBase64String($bytes)
    $request.sha256 = $hash
}
if ($Command -eq 'deploy') {
    if ($DeploySourcePath.Count -lt 1 -or
        $DeploySourcePath.Count -ne $DeployTargetPath.Count) {
        throw (
            'deploy requiere el mismo numero de -DeploySourcePath y ' +
            '-DeployTargetPath.'
        )
    }
    $deployFiles = [Collections.Generic.List[object]]::new()
    foreach ($index in 0..($DeploySourcePath.Count - 1)) {
        $source = [IO.Path]::GetFullPath($DeploySourcePath[$index])
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
            throw "No existe el archivo de despliegue: $source"
        }
        $bytes = [IO.File]::ReadAllBytes($source)
        $sha = [Security.Cryptography.SHA256]::Create()
        try {
            $hash = (($sha.ComputeHash($bytes) | ForEach-Object {
                        $_.ToString('x2')
                    }) -join '')
        } finally {
            $sha.Dispose()
        }
        $deployFiles.Add([pscustomobject][ordered]@{
            path = $DeployTargetPath[$index].Replace('\', '/')
            bytes = $bytes.Length
            sha256 = $hash
            content_base64 = [Convert]::ToBase64String($bytes)
        })
    }
    $request.payload = [ordered]@{ files = $deployFiles.ToArray() }
}
if ($Command -eq 'fetch_from_h1') {
    if ([string]::IsNullOrWhiteSpace($SourceUrl) -or
        [string]::IsNullOrWhiteSpace($RemotePath) -or
        $ExpectedSha256 -notmatch '^[0-9A-Fa-f]{64}$') {
        throw (
            'fetch_from_h1 requiere SourceUrl, RemotePath, ExpectedBytes ' +
            'y ExpectedSha256.'
        )
    }
    $request.payload = [ordered]@{
        url = $SourceUrl
        path = $RemotePath
        bytes = $ExpectedBytes
        sha256 = $ExpectedSha256.ToLowerInvariant()
    }
}
if ($Command -eq 'run_tool') {
    if ($JobId -notmatch '^[0-9A-Fa-f]{32}$' -or
        [string]::IsNullOrWhiteSpace($Entrypoint)) {
        throw 'run_tool requiere -JobId 32hex y -Entrypoint.'
    }
    $jobRequest = $null
    if (-not [string]::IsNullOrWhiteSpace($JobRequestPath)) {
        if (-not (Test-Path -LiteralPath $JobRequestPath -PathType Leaf)) {
            throw 'No existe JobRequestPath.'
        }
        $jobRequest = Get-Content -LiteralPath $JobRequestPath -Raw |
            ConvertFrom-Json
    }
    $request.payload = [ordered]@{
        job_id = $JobId.ToLowerInvariant()
        entrypoint = $Entrypoint.Replace('\', '/')
        request = $jobRequest
    }
}
if ($Command -eq 'list_files') {
    if ([string]::IsNullOrWhiteSpace($RemotePath)) {
        throw 'list_files requiere -RemotePath.'
    }
    $request.payload = [ordered]@{ path = $RemotePath }
}
if ($Command -eq 'download') {
    if ([string]::IsNullOrWhiteSpace($RemotePath)) {
        throw 'download requiere -RemotePath.'
    }
    $request.payload = [ordered]@{
        path = $RemotePath
        offset = $Offset
        length = $Length
    }
}

$client = New-Object Net.Sockets.TcpClient
try {
    $async = $client.BeginConnect($AgentIPv4, $Port, $null, $null)
    if (-not $async.AsyncWaitHandle.WaitOne(5000)) {
        throw "Timeout conectando al agente $AgentIPv4`:$Port."
    }
    $client.EndConnect($async)
    $stream = $client.GetStream()
    $stream.ReadTimeout = $ResponseTimeoutMilliseconds
    $writer = New-Object IO.StreamWriter(
        $stream, (New-Object Text.UTF8Encoding($false)), 4096, $true)
    $writer.NewLine = "`n"
    $writer.WriteLine(($request | ConvertTo-Json -Depth 6 -Compress))
    $writer.Flush()
    $reader = New-Object IO.StreamReader(
        $stream, (New-Object Text.UTF8Encoding($false)), $false, 4096, $true)
    $line = $reader.ReadLine()
    if ([string]::IsNullOrWhiteSpace($line)) {
        throw 'El agente cerro la conexion sin respuesta.'
    }
    $response = $line | ConvertFrom-Json
    if (-not [bool]$response.ok) {
        throw "El agente rechazo la orden: $($response.error)"
    }
    $response.data
} finally {
    $client.Dispose()
}
