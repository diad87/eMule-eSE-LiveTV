[CmdletBinding()]
param(
    [ValidatePattern('^$|^[0-9A-Fa-f]{64}$')]
    [string]$Token = $env:ESE_LAB_AGENT_TOKEN,

    [ValidatePattern('^$|^\d{1,3}(\.\d{1,3}){3}$')]
    [string]$ListenIPv4 = '',

    [ValidatePattern('^$|^\d{1,3}(\.\d{1,3}){3}$')]
    [string]$AllowedSourceIPv4 = '',

    [ValidatePattern('^$|^\d{1,3}(\.\d{1,3}){3}$')]
    [string]$I05SourceIPv4 = '',

    [ValidatePattern('^$|^\d{1,3}(\.\d{1,3}){3}$')]
    [string]$I05DownloaderIPv4 = '',

    [ValidateRange(1024, 65535)]
    [int]$Port = 8013,

    [ValidateNotNullOrEmpty()]
    [string]$TaskName = 'eSE Lab Agent',

    [switch]$LoopbackSelfTest
)

$ErrorActionPreference = 'Stop'
if ($Token -notmatch '^[0-9A-Fa-f]{64}$') {
    throw (
        'Falta ESE_LAB_AGENT_TOKEN o -Token con una credencial aleatoria ' +
        'de 256 bits (64 caracteres hexadecimales).'
    )
}
if ($LoopbackSelfTest) {
    foreach ($name in @(
            'ListenIPv4',
            'AllowedSourceIPv4',
            'I05SourceIPv4',
            'I05DownloaderIPv4')) {
        if ([string]::IsNullOrWhiteSpace((Get-Variable $name).Value)) {
            Set-Variable -Name $name -Value '127.0.0.1'
        }
    }
} else {
    foreach ($name in @(
            'ListenIPv4',
            'AllowedSourceIPv4',
            'I05SourceIPv4',
            'I05DownloaderIPv4')) {
        if ([string]::IsNullOrWhiteSpace((Get-Variable $name).Value)) {
            throw "Falta el parametro obligatorio -$name."
        }
    }
}
$kitRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$runnerPath = Join-Path $kitRoot 'run_v91_i05_downloader_kit.ps1'
$cleanupPath = Join-Path $kitRoot 'cleanup_v91_i05_downloader.ps1'
$configPath = Join-Path $kitRoot 'V91-I05-T1-CONFIG.json'
$failurePath = Join-Path $kitRoot 'LAST-FAILURE-V91-I05-T1.json'
$errorPath = Join-Path $kitRoot 'LAST-ERROR-V91-I05-T1.txt'
$statusPath = Join-Path $kitRoot 'AGENT-STATUS.json'
$stopFlagPath = Join-Path $kitRoot 'STOP-ESE-LAB-AGENT.flag'
$logRoot = Join-Path $kitRoot 'agent-logs'
$firewallName = 'eSE-Lab-Agent-' + $Token.Substring(0, 12)
$powershellPath = Join-Path $env:SystemRoot `
    'System32\WindowsPowerShell\v1.0\powershell.exe'
$maximumRequestBytes = 16777216
$maximumDeployBytes = 8388608

$listener = $null
$acceptTask = $null
$child = $null
$childStartedAt = $null
$childStdout = ''
$childStderr = ''
$childKind = ''
$childJobId = ''
$agentState = 'STARTING'
$lastExitCode = $null
$lastErrorText = ''
$lastCommand = ''
$lastCommandAt = $null
$shutdownRequested = $false
$restartRequested = $false
$mutex = $null
$mutexOwned = $false
$nextStatusWriteAt = [DateTimeOffset]::MinValue

function Assert-AgentAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'El agente V91-I05 debe ejecutarse como administrador.'
    }
}

function Get-AgentSha256 {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)

    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return (($sha.ComputeHash($Bytes) | ForEach-Object {
                    $_.ToString('x2')
                }) -join '')
    } finally {
        $sha.Dispose()
    }
}

function Write-AgentJsonAtomic {
    param(
        [Parameter(Mandatory = $true)][object]$Value,
        [Parameter(Mandatory = $true)][string]$Path
    )

    $json = $Value | ConvertTo-Json -Depth 10
    $utf8 = New-Object Text.UTF8Encoding($false)
    $temp = $Path + '.tmp-' + [Guid]::NewGuid().ToString('N')
    [IO.File]::WriteAllText($temp, $json + [Environment]::NewLine, $utf8)
    Move-Item -LiteralPath $temp -Destination $Path -Force
}

function Update-AgentChildState {
    if ($null -eq $script:child) {
        return
    }

    $script:child.Refresh()
    if (-not $script:child.HasExited) {
        $script:agentState = if ($script:childKind -ceq 'tool') {
            'JOB_RUNNING'
        } else {
            'TEST_RUNNING'
        }
        return
    }

    $script:lastExitCode = [int]$script:child.ExitCode
    $script:lastErrorText = ''
    $failurePresent = $false
    if ($script:childKind -ceq 'i05' -and
        (Test-Path -LiteralPath $errorPath -PathType Leaf)) {
        $failurePresent = $true
        $script:lastErrorText = [Convert]::ToString((
                Get-Content -LiteralPath $errorPath -Raw `
                    -ErrorAction SilentlyContinue
            )).Trim()
    } elseif (Test-Path -LiteralPath $script:childStderr -PathType Leaf) {
        $script:lastErrorText = [Convert]::ToString((
                Get-Content -LiteralPath $script:childStderr -Raw `
                    -ErrorAction SilentlyContinue
            )).Trim()
    }
    $script:agentState = if ($script:lastExitCode -eq 0 -and
        -not $failurePresent) {
        if ($script:childKind -ceq 'tool') {
            'JOB_COMPLETE'
        } else {
            'TEST_COMPLETE'
        }
    } else {
        if ($script:childKind -ceq 'tool') {
            'JOB_ERROR'
        } else {
            'TEST_ERROR'
        }
    }
    if ($script:childKind -ceq 'tool' -and
        $script:childJobId -match '^[0-9a-f]{32}$') {
        $jobRoot = Join-Path $kitRoot "jobs\$($script:childJobId)"
        Write-AgentJsonAtomic -Value ([ordered]@{
                schema = 'ese.lab.agent-job-status/v1'
                job_id = $script:childJobId
                status = $script:agentState
                exit_code = $script:lastExitCode
                error = $script:lastErrorText
                finished_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
                stdout = 'stdout.log'
                stderr = 'stderr.log'
            }) -Path (Join-Path $jobRoot 'status.json')
    }
    $script:child.Dispose()
    $script:child = $null
}

function Get-AgentStatus {
    Update-AgentChildState
    $failure = $null
    if (Test-Path -LiteralPath $failurePath -PathType Leaf) {
        try {
            $failure = Get-Content -LiteralPath $failurePath -Raw |
                ConvertFrom-Json
        } catch {
            $failure = $null
        }
    }
    $config = $null
    if (Test-Path -LiteralPath $configPath -PathType Leaf) {
        try {
            $config = Get-Content -LiteralPath $configPath -Raw |
                ConvertFrom-Json
        } catch {
            $config = $null
        }
    }

    return [ordered]@{
        schema = 'ese.lab.agent-status/v1'
        status = $script:agentState
        agent_pid = $PID
        listen = "$ListenIPv4`:$Port"
        allowed_source = $AllowedSourceIPv4
        i05_source_ipv4 = $I05SourceIPv4
        i05_downloader_ipv4 = $I05DownloaderIPv4
        test_pid = if ($null -ne $script:child) {
            [int]$script:child.Id
        } else {
            $null
        }
        child_kind = $script:childKind
        job_id = $script:childJobId
        test_started_at_utc = if ($null -ne $script:childStartedAt) {
            $script:childStartedAt.ToString('o')
        } else {
            $null
        }
        test_exit_code = $script:lastExitCode
        last_error = $script:lastErrorText
        failure = $failure
        config_nonce = if ($null -ne $config) {
            [string]$config.nonce
        } else {
            $null
        }
        config_expires_at_utc = if ($null -ne $config) {
            [string]$config.expires_at_utc
        } else {
            $null
        }
        last_command = $script:lastCommand
        last_command_at_utc = if ($null -ne $script:lastCommandAt) {
            $script:lastCommandAt.ToString('o')
        } else {
            $null
        }
        updated_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
    }
}

function Save-AgentStatus {
    Write-AgentJsonAtomic -Value (Get-AgentStatus) -Path $statusPath
}

function Stop-AgentTest {
    Update-AgentChildState
    if ($null -ne $script:child -and -not $script:child.HasExited) {
        Stop-Process -Id $script:child.Id -Force -ErrorAction SilentlyContinue
        try {
            $script:child.WaitForExit(10000) | Out-Null
        } catch {
        }
    }
    $script:child = $null
    if ($script:childKind -ceq 'i05' -and
        (Test-Path -LiteralPath $cleanupPath -PathType Leaf) -and
        (Test-Path -LiteralPath (
            Join-Path $kitRoot 'ACTIVE-V91-I05-T1.json'
        ) -PathType Leaf)) {
        & $powershellPath -NoProfile -ExecutionPolicy Bypass `
            -File $cleanupPath 2>&1 | Out-Null
    }
    $script:agentState = 'IDLE'
}

function Start-AgentTest {
    Update-AgentChildState
    if ($null -ne $script:child -and -not $script:child.HasExited) {
        throw 'Ya hay una prueba V91-I05 en ejecucion.'
    }
    if (-not (Test-Path -LiteralPath $runnerPath -PathType Leaf)) {
        throw "Falta el runner: $runnerPath"
    }
    if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) {
        throw "Falta la configuracion: $configPath"
    }

    $config = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
    if ([string]$config.schema -cne 'ese.v91.i05.t1-config/v1') {
        throw 'La configuracion no tiene el schema V91-I05 T1 esperado.'
    }
    if ([string]$config.source.ipv4_address -cne $I05SourceIPv4) {
        throw 'La configuracion no pertenece al H1 fisico autorizado.'
    }
    if ([string]$config.downloader.expected_ipv4_address -cne
            $I05DownloaderIPv4) {
        throw 'La configuracion no pertenece al H3 fisico autorizado.'
    }
    $expires = [DateTimeOffset]::Parse([string]$config.expires_at_utc)
    if ($expires -le [DateTimeOffset]::UtcNow.AddMinutes(5)) {
        throw 'La configuracion caduca en menos de cinco minutos.'
    }

    New-Item -ItemType Directory -Path $logRoot -Force | Out-Null
    Remove-Item -LiteralPath $failurePath, $errorPath `
        -Force -ErrorAction SilentlyContinue
    $stamp = [DateTimeOffset]::UtcNow.ToString('yyyyMMdd-HHmmss')
    $script:childStdout = Join-Path $logRoot "$stamp-stdout.log"
    $script:childStderr = Join-Path $logRoot "$stamp-stderr.log"
    $arguments = (
        '-NoProfile -ExecutionPolicy Bypass -File "{0}"' -f $runnerPath
    )
    $script:child = Start-Process -FilePath $powershellPath `
        -ArgumentList $arguments -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput $script:childStdout `
        -RedirectStandardError $script:childStderr
    $script:childStartedAt = [DateTimeOffset]::UtcNow
    $script:childKind = 'i05'
    $script:childJobId = ''
    $script:lastExitCode = $null
    $script:lastErrorText = ''
    $script:agentState = 'TEST_RUNNING'
}

function Set-AgentConfig {
    param([Parameter(Mandatory = $true)][object]$Request)

    $bytes = [Convert]::FromBase64String([string]$Request.content_base64)
    if ($bytes.Length -gt $maximumRequestBytes) {
        throw 'La configuracion excede el limite permitido.'
    }
    $actual = Get-AgentSha256 -Bytes $bytes
    if ($actual -cne ([string]$Request.sha256).ToLowerInvariant()) {
        throw 'SHA-256 de configuracion incorrecto.'
    }
    $json = [Text.Encoding]::UTF8.GetString($bytes) | ConvertFrom-Json
    if ([string]$json.schema -cne 'ese.v91.i05.t1-config/v1' -or
        [string]$json.source.ipv4_address -cne $I05SourceIPv4 -or
        [string]$json.downloader.expected_ipv4_address -cne
            $I05DownloaderIPv4) {
        throw 'La configuracion no corresponde a la topologia autorizada.'
    }
    $temp = $configPath + '.incoming'
    [IO.File]::WriteAllBytes($temp, $bytes)
    Move-Item -LiteralPath $temp -Destination $configPath -Force
    $script:agentState = 'IDLE'
}

function Resolve-AgentDeployPath {
    param([Parameter(Mandatory = $true)][string]$RelativePath)

    $relative = $RelativePath.Replace('\', '/').Trim('/')
    if ([string]::IsNullOrWhiteSpace($relative) -or
        [IO.Path]::IsPathRooted($relative) -or
        $relative.Split('/') -contains '..') {
        throw 'Ruta de despliegue no valida.'
    }
    $rootFiles = @(
        'run_v91_i05_downloader_kit.ps1',
        'selftest_v91_i05_downloader.ps1',
        'cleanup_v91_i05_downloader.ps1',
        'ensure_v91_i05_canonical_fixture.ps1',
        'v91_i05_t1_contract.ps1',
        'common.ps1',
        'prepare_node.ps1',
        'V91-I05-T1-CONFIG.json'
    )
    $allowed = $relative -cin $rootFiles -or
        $relative -cmatch '^tools/lab/[A-Za-z0-9_.-]+\.(ps1|psm1|cmd|json)$' -or
        $relative -cmatch (
            '^injected/[0-9a-f]{32}/' +
            '[A-Za-z0-9_.\-/]+\.(ps1|psm1|cmd|json|dll|exe|config|txt)$'
        )
    if (-not $allowed) {
        throw "Ruta fuera de la allowlist de despliegue: $relative"
    }
    $target = [IO.Path]::GetFullPath(
        (Join-Path $kitRoot $relative.Replace('/', '\')))
    $prefix = $kitRoot.TrimEnd('\') + '\'
    if (-not $target.StartsWith(
            $prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'La ruta de despliegue escapa del kit.'
    }
    return $target
}

function Install-AgentDeployment {
    param([Parameter(Mandatory = $true)][object]$Payload)

    Update-AgentChildState
    if ($null -ne $script:child) {
        throw 'No se puede desplegar codigo durante una prueba activa.'
    }
    $files = @($Payload.files)
    if ($files.Count -lt 1 -or $files.Count -gt 32) {
        throw 'El despliegue debe contener entre 1 y 32 archivos.'
    }
    [Int64]$totalBytes = 0
    $staged = [Collections.Generic.List[object]]::new()
    foreach ($file in $files) {
        $relative = [string]$file.path
        $target = Resolve-AgentDeployPath -RelativePath $relative
        $bytes = [Convert]::FromBase64String([string]$file.content_base64)
        $totalBytes += $bytes.Length
        if ($totalBytes -gt $maximumDeployBytes) {
            throw 'El despliegue supera 8 MiB.'
        }
        if ([Int64]$file.bytes -ne $bytes.Length) {
            throw "Tamano declarado incorrecto: $relative"
        }
        $sha256 = Get-AgentSha256 -Bytes $bytes
        if ($sha256 -cne ([string]$file.sha256).ToLowerInvariant()) {
            throw "SHA-256 incorrecto: $relative"
        }
        $directory = Split-Path -Parent $target
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
        $temp = $target + '.deploy-' + [Guid]::NewGuid().ToString('N')
        [IO.File]::WriteAllBytes($temp, $bytes)
        $staged.Add([pscustomobject]@{
            relative = $relative
            target = $target
            temp = $temp
            bytes = $bytes.Length
            sha256 = $sha256
        })
    }
    try {
        foreach ($item in $staged) {
            Move-Item -LiteralPath $item.temp `
                -Destination $item.target -Force
            if ((Get-FileHash -LiteralPath $item.target -Algorithm SHA256).
                    Hash.ToLowerInvariant() -cne [string]$item.sha256) {
                throw "Verificacion posterior fallida: $($item.relative)"
            }
        }
    } finally {
        foreach ($item in $staged) {
            Remove-Item -LiteralPath $item.temp -Force `
                -ErrorAction SilentlyContinue
        }
    }
    $receipt = [ordered]@{
        schema = 'ese.lab.agent-deployment/v1'
        status = 'DEPLOYED'
        deployment_id = [Guid]::NewGuid().ToString('N')
        deployed_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
        file_count = $staged.Count
        total_bytes = $totalBytes
        files = @($staged | ForEach-Object {
            [ordered]@{
                path = [string]$_.relative
                bytes = [Int64]$_.bytes
                sha256 = [string]$_.sha256
            }
        })
    }
    Write-AgentJsonAtomic -Value $receipt -Path (
        Join-Path $kitRoot 'LAST-AGENT-DEPLOYMENT.json')
    return $receipt
}

function Resolve-AgentTransferPath {
    param([Parameter(Mandatory = $true)][string]$RelativePath)

    $relative = $RelativePath.Replace('\', '/').Trim('/')
    if ([string]::IsNullOrWhiteSpace($relative) -or
        [IO.Path]::IsPathRooted($relative) -or
        $relative.Split('/') -contains '..') {
        throw 'Ruta de transferencia no valida.'
    }
    $allowed = $relative -cmatch (
        '^payload/candidates/[A-Za-z0-9_.-]+\.' +
        '(zip|7z|exe|dll|json)$') -or
        $relative -cmatch (
            '^injected/[0-9a-f]{32}/assets/' +
            '[A-Za-z0-9_.\-/]+\.(zip|7z|bin|exe|dll|json|txt)$'
        )
    if (-not $allowed) {
        throw 'Destino fuera de la allowlist de transferencias grandes.'
    }
    $target = [IO.Path]::GetFullPath(
        (Join-Path $kitRoot $relative.Replace('/', '\')))
    $prefix = $kitRoot.TrimEnd('\') + '\'
    if (-not $target.StartsWith(
            $prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'El destino de transferencia escapa del kit.'
    }
    return $target
}

function Receive-AgentFileFromH1 {
    param([Parameter(Mandatory = $true)][object]$Payload)

    Update-AgentChildState
    if ($null -ne $script:child) {
        throw 'No se puede transferir durante un trabajo activo.'
    }
    $uri = $null
    if (-not [Uri]::TryCreate(
            [string]$Payload.url, [UriKind]::Absolute, [ref]$uri) -or
        $uri.Scheme -cne 'http' -or
        $uri.Host -cne $AllowedSourceIPv4 -or
        -not [string]::IsNullOrWhiteSpace($uri.UserInfo) -or
        -not [string]::IsNullOrWhiteSpace($uri.Query) -or
        $uri.Port -lt 1024 -or $uri.Port -gt 65535) {
        throw 'La descarga solo puede proceder del H1 HTTP autorizado.'
    }
    [Int64]$expectedBytes = [Int64]$Payload.bytes
    $expectedSha256 = ([string]$Payload.sha256).ToLowerInvariant()
    if ($expectedBytes -lt 1 -or $expectedBytes -gt 8589934592L -or
        $expectedSha256 -notmatch '^[0-9a-f]{64}$') {
        throw 'Tamano o SHA-256 esperado no valido.'
    }
    $relative = [string]$Payload.path
    $target = Resolve-AgentTransferPath -RelativePath $relative
    $directory = Split-Path -Parent $target
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
    $temp = $target + '.transfer-' + [Guid]::NewGuid().ToString('N')
    $request = [Net.HttpWebRequest]::Create($uri)
    $request.Method = 'GET'
    $request.Timeout = 30000
    $request.ReadWriteTimeout = 30000
    $request.AllowAutoRedirect = $false
    $response = $null
    $input = $null
    $output = $null
    $sha = [Security.Cryptography.SHA256]::Create()
    [Int64]$total = 0
    try {
        $response = $request.GetResponse()
        if ([int]$response.StatusCode -ne 200) {
            throw "H1 HTTP devolvio $([int]$response.StatusCode)."
        }
        if ($response.ContentLength -ge 0 -and
            [Int64]$response.ContentLength -ne $expectedBytes) {
            throw 'Content-Length no coincide con el tamano autorizado.'
        }
        $input = $response.GetResponseStream()
        $output = New-Object IO.FileStream(
            $temp, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write,
            [IO.FileShare]::None, 1048576,
            [IO.FileOptions]::SequentialScan)
        $buffer = New-Object byte[] 1048576
        while (($read = $input.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $total += $read
            if ($total -gt $expectedBytes) {
                throw 'H1 envio mas bytes de los autorizados.'
            }
            $output.Write($buffer, 0, $read)
            $null = $sha.TransformBlock($buffer, 0, $read, $null, 0)
        }
        $null = $sha.TransformFinalBlock((New-Object byte[] 0), 0, 0)
        $output.Flush($true)
        if ($total -ne $expectedBytes) {
            throw 'La transferencia termino con tamano incompleto.'
        }
        $actualSha256 = (($sha.Hash | ForEach-Object {
                    $_.ToString('x2')
                }) -join '')
        if ($actualSha256 -cne $expectedSha256) {
            throw 'La transferencia no coincide con el SHA-256 autorizado.'
        }
    } finally {
        if ($null -ne $output) { $output.Dispose() }
        if ($null -ne $input) { $input.Dispose() }
        if ($null -ne $response) { $response.Dispose() }
        $sha.Dispose()
    }
    try {
        Move-Item -LiteralPath $temp -Destination $target -Force
    } finally {
        Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue
    }
    return [ordered]@{
        schema = 'ese.lab.agent-transfer/v1'
        status = 'TRANSFERRED'
        path = $relative
        bytes = $total
        sha256 = $expectedSha256
        source = "$($uri.Scheme)://$($uri.Host):$($uri.Port)"
        completed_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
    }
}

function Start-AgentTool {
    param([Parameter(Mandatory = $true)][object]$Payload)

    Update-AgentChildState
    if ($null -ne $script:child) {
        throw 'Ya hay una prueba o trabajo en ejecucion.'
    }
    $jobId = ([string]$Payload.job_id).ToLowerInvariant()
    if ($jobId -notmatch '^[0-9a-f]{32}$') {
        throw 'job_id debe ser 32hex lowercase.'
    }
    $entryRelative = ([string]$Payload.entrypoint).Replace('\', '/')
    if ($entryRelative -cnotmatch (
            "^injected/$jobId/[A-Za-z0-9_.\-/]+\.ps1$")) {
        throw 'El entrypoint debe pertenecer al job inyectado.'
    }
    $entrypoint = Resolve-AgentDeployPath -RelativePath $entryRelative
    if (-not (Test-Path -LiteralPath $entrypoint -PathType Leaf)) {
        throw 'No existe el entrypoint desplegado.'
    }
    $jobRoot = Join-Path $kitRoot "jobs\$jobId"
    if (Test-Path -LiteralPath $jobRoot) {
        throw 'job_id ya utilizado.'
    }
    New-Item -ItemType Directory -Path $jobRoot -Force | Out-Null
    $requestPath = Join-Path $jobRoot 'request.json'
    Write-AgentJsonAtomic -Value ([ordered]@{
            schema = 'ese.lab.agent-job-request/v1'
            job_id = $jobId
            created_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
            request = $Payload.request
        }) -Path $requestPath
    $script:childStdout = Join-Path $jobRoot 'stdout.log'
    $script:childStderr = Join-Path $jobRoot 'stderr.log'
    $arguments = ((
            '-NoProfile -ExecutionPolicy Bypass -File "{0}" ' +
            '-JobRequestPath "{1}"'
        ) -f $entrypoint, $requestPath)
    $script:child = Start-Process -FilePath $powershellPath `
        -ArgumentList $arguments -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput $script:childStdout `
        -RedirectStandardError $script:childStderr
    $script:childStartedAt = [DateTimeOffset]::UtcNow
    $script:childKind = 'tool'
    $script:childJobId = $jobId
    $script:lastExitCode = $null
    $script:lastErrorText = ''
    $script:agentState = 'JOB_RUNNING'
    Write-AgentJsonAtomic -Value ([ordered]@{
            schema = 'ese.lab.agent-job-status/v1'
            job_id = $jobId
            status = 'RUNNING'
            process_id = [int]$script:child.Id
            started_at_utc = $script:childStartedAt.ToString('o')
            entrypoint = $entryRelative
        }) -Path (Join-Path $jobRoot 'status.json')
}

function Resolve-AgentReadablePath {
    param([Parameter(Mandatory = $true)][string]$RelativePath)

    $relative = $RelativePath.Replace('\', '/').Trim('/')
    if ([string]::IsNullOrWhiteSpace($relative) -or
        [IO.Path]::IsPathRooted($relative) -or
        $relative.Split('/') -contains '..') {
        throw 'Ruta de lectura no valida.'
    }
    $allowed = $relative -cmatch (
        '^(agent-logs|jobs|runs|injected)(/|$)') -or
        $relative -cin @(
            'AGENT-STATUS.json',
            'LAST-ERROR-V91-I05-T1.txt',
            'LAST-FAILURE-V91-I05-T1.json',
            'LAST-PROGRESS-V91-I05-T1.json',
            'LAST-AGENT-DEPLOYMENT.json',
            'PATCH-APPLIED-V91-I05-IPV6-FIREWALL.json'
        )
    if (-not $allowed) {
        throw 'La ruta no pertenece a los resultados exportables.'
    }
    $target = [IO.Path]::GetFullPath(
        (Join-Path $kitRoot $relative.Replace('/', '\')))
    $prefix = $kitRoot.TrimEnd('\') + '\'
    if (-not $target.StartsWith(
            $prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'La ruta de lectura escapa del kit.'
    }
    return $target
}

function Get-AgentFileList {
    param([Parameter(Mandatory = $true)][object]$Payload)

    $relative = [string]$Payload.path
    $root = Resolve-AgentReadablePath -RelativePath $relative
    if (-not (Test-Path -LiteralPath $root -PathType Container)) {
        throw 'No existe el directorio solicitado.'
    }
    $items = @(Get-ChildItem -LiteralPath $root -Recurse -File |
        Select-Object -First 500)
    return [ordered]@{
        path = $relative
        truncated = $items.Count -ge 500
        files = @($items | ForEach-Object {
            [ordered]@{
                path = $_.FullName.Substring(
                    $kitRoot.TrimEnd('\').Length + 1).Replace('\', '/')
                bytes = [Int64]$_.Length
                last_write_utc = $_.LastWriteTimeUtc.ToString('o')
            }
        })
    }
}

function Get-AgentFileChunk {
    param([Parameter(Mandatory = $true)][object]$Payload)

    $relative = [string]$Payload.path
    $path = Resolve-AgentReadablePath -RelativePath $relative
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw 'No existe el archivo solicitado.'
    }
    [Int64]$offset = [Int64]$Payload.offset
    [int]$length = [int]$Payload.length
    if ($offset -lt 0 -or $length -lt 1 -or $length -gt 786432) {
        throw 'Rango de descarga no permitido.'
    }
    $item = Get-Item -LiteralPath $path
    if ($offset -gt $item.Length) {
        throw 'Offset fuera del archivo.'
    }
    $count = [int][Math]::Min([Int64]$length, $item.Length - $offset)
    $buffer = New-Object byte[] $count
    $stream = [IO.File]::Open(
        $path, [IO.FileMode]::Open, [IO.FileAccess]::Read,
        [IO.FileShare]::ReadWrite)
    try {
        $stream.Position = $offset
        $read = $stream.Read($buffer, 0, $count)
    } finally {
        $stream.Dispose()
    }
    if ($read -ne $count) {
        throw 'Lectura parcial inesperada.'
    }
    return [ordered]@{
        path = $relative
        file_bytes = [Int64]$item.Length
        offset = $offset
        bytes = $count
        eof = ($offset + $count -ge $item.Length)
        content_base64 = [Convert]::ToBase64String($buffer)
        chunk_sha256 = Get-AgentSha256 -Bytes $buffer
    }
}

function Invoke-AgentRequest {
    param([Parameter(Mandatory = $true)][object]$Request)

    if ([string]$Request.token -cne $Token) {
        throw 'Autenticacion rechazada.'
    }
    $command = ([string]$Request.command).ToLowerInvariant()
    $script:lastCommand = $command
    $script:lastCommandAt = [DateTimeOffset]::UtcNow
    switch ($command) {
        'status' {
        }
        'set_config' {
            Update-AgentChildState
            if ($null -ne $script:child) {
                throw 'No se puede cambiar la configuracion durante una prueba.'
            }
            Set-AgentConfig -Request $Request
        }
        'run' {
            Start-AgentTest
        }
        'deploy' {
            $deployment = Install-AgentDeployment -Payload $Request.payload
        }
        'fetch_from_h1' {
            $transfer = Receive-AgentFileFromH1 -Payload $Request.payload
        }
        'run_tool' {
            Start-AgentTool -Payload $Request.payload
        }
        'list_files' {
            $fileList = Get-AgentFileList -Payload $Request.payload
        }
        'download' {
            $download = Get-AgentFileChunk -Payload $Request.payload
        }
        'stop_test' {
            Stop-AgentTest
        }
        'restart_agent' {
            Update-AgentChildState
            if ($null -ne $script:child) {
                throw 'No se puede reiniciar el agente con un trabajo activo.'
            }
            $script:restartRequested = $true
            $script:shutdownRequested = $true
            $script:agentState = 'RESTARTING'
        }
        'shutdown' {
            Stop-AgentTest
            $script:shutdownRequested = $true
            $script:agentState = 'SHUTTING_DOWN'
        }
        default {
            throw "Orden no permitida: $command"
        }
    }
    Save-AgentStatus
    if ($command -ceq 'deploy') { return $deployment }
    if ($command -ceq 'fetch_from_h1') { return $transfer }
    if ($command -ceq 'list_files') { return $fileList }
    if ($command -ceq 'download') { return $download }
    return Get-AgentStatus
}

function Send-AgentResponse {
    param(
        [Parameter(Mandatory = $true)][Net.Sockets.TcpClient]$Client,
        [Parameter(Mandatory = $true)][object]$Response
    )

    $stream = $Client.GetStream()
    $writer = New-Object IO.StreamWriter(
        $stream, (New-Object Text.UTF8Encoding($false)), 4096, $true)
    $writer.NewLine = "`n"
    $writer.WriteLine(($Response | ConvertTo-Json -Depth 12 -Compress))
    $writer.Flush()
    $writer.Dispose()
}

function Receive-AgentRequest {
    param([Parameter(Mandatory = $true)][Net.Sockets.TcpClient]$Client)

    $stream = $Client.GetStream()
    $stream.ReadTimeout = 10000
    $reader = New-Object IO.StreamReader(
        $stream, (New-Object Text.UTF8Encoding($false)), $false, 4096, $true)
    $line = $reader.ReadLine()
    $reader.Dispose()
    if ([string]::IsNullOrWhiteSpace($line) -or
        [Text.Encoding]::UTF8.GetByteCount($line) -gt $maximumRequestBytes) {
        throw 'Peticion vacia o demasiado grande.'
    }
    return $line | ConvertFrom-Json
}

if ($env:ESE_LAB_AGENT_LIBRARY_ONLY -ceq '1') {
    return
}

if ($LoopbackSelfTest) {
    if ($ListenIPv4 -cne '127.0.0.1' -or
        $AllowedSourceIPv4 -cne '127.0.0.1') {
        throw 'LoopbackSelfTest solo permite 127.0.0.1.'
    }
} else {
    Assert-AgentAdministrator
}
if (-not (Test-Path -LiteralPath $runnerPath -PathType Leaf)) {
    throw "El agente no esta dentro de un kit V91-I05 valido: $kitRoot"
}

$createdNew = $false
$mutex = New-Object Threading.Mutex($true, 'Global\eSE-Lab-Agent', `
    [ref]$createdNew)
$mutexOwned = $createdNew
if (-not $mutexOwned) {
    throw 'Ya hay un agente V91-I05 activo.'
}

try {
    Remove-Item -LiteralPath $stopFlagPath -Force -ErrorAction SilentlyContinue
    if (-not $LoopbackSelfTest) {
        New-NetFirewallRule -Name $firewallName `
            -DisplayName 'eSE unattended lab agent' `
            -Direction Inbound -Action Allow -Protocol TCP `
            -LocalAddress $ListenIPv4 -LocalPort $Port `
            -RemoteAddress $AllowedSourceIPv4 -Program $powershellPath `
            -Profile Any | Out-Null
    }

    $listener = New-Object Net.Sockets.TcpListener(
        [Net.IPAddress]::Parse($ListenIPv4), $Port)
    $listener.Start(4)
    $acceptTask = $listener.BeginAcceptTcpClient($null, $null)
    $agentState = 'IDLE'
    Save-AgentStatus
    Write-Host (
        "eSE LAB AGENT READY: {0}:{1} (solo H1 {2})" -f
        $ListenIPv4, $Port, $AllowedSourceIPv4
    ) -ForegroundColor Green
    Write-Host 'Deje esta ventana abierta. No requiere mas intervencion.'

    while (-not $shutdownRequested) {
        Update-AgentChildState
        if ([DateTimeOffset]::UtcNow -ge $nextStatusWriteAt) {
            Save-AgentStatus
            $nextStatusWriteAt = [DateTimeOffset]::UtcNow.AddSeconds(2)
        }
        if (Test-Path -LiteralPath $stopFlagPath -PathType Leaf) {
            $shutdownRequested = $true
            break
        }
        if ($acceptTask.AsyncWaitHandle.WaitOne(250)) {
            $client = $null
            try {
                $client = $listener.EndAcceptTcpClient($acceptTask)
                $acceptTask = $listener.BeginAcceptTcpClient($null, $null)
                $remote = [Net.IPEndPoint]$client.Client.RemoteEndPoint
                if ($remote.Address.ToString() -cne $AllowedSourceIPv4) {
                    throw 'Origen no autorizado.'
                }
                $request = Receive-AgentRequest -Client $client
                $data = Invoke-AgentRequest -Request $request
                Send-AgentResponse -Client $client -Response ([ordered]@{
                        ok = $true
                        data = $data
                    })
            } catch {
                if ($null -ne $client) {
                    try {
                        Send-AgentResponse -Client $client -Response ([ordered]@{
                                ok = $false
                                error = $_.Exception.Message
                            })
                    } catch {
                    }
                }
            } finally {
                if ($null -ne $client) {
                    $client.Dispose()
                }
            }
        }
    }
} catch {
    try {
        Write-AgentJsonAtomic -Value ([ordered]@{
                schema = 'ese.lab.agent-fatal/v1'
                created_at_utc = [DateTimeOffset]::UtcNow.ToString('o')
                message = $_.Exception.Message
                exception_type = $_.Exception.GetType().FullName
                script_stack_trace = $_.ScriptStackTrace
                position = [string]$_.InvocationInfo.PositionMessage
            }) -Path (Join-Path $kitRoot 'AGENT-FATAL.json')
    } catch {
    }
    throw
} finally {
    try {
        Stop-AgentTest
    } catch {
    }
    if ($null -ne $listener) {
        $listener.Stop()
    }
    if (-not $LoopbackSelfTest) {
        Remove-NetFirewallRule -Name $firewallName `
            -ErrorAction SilentlyContinue
    }
    Remove-Item -LiteralPath $stopFlagPath -Force -ErrorAction SilentlyContinue
    $agentState = 'STOPPED'
    try {
        Save-AgentStatus
    } catch {
    }
    if ($mutexOwned -and $null -ne $mutex) {
        try {
            $mutex.ReleaseMutex()
        } catch {
        }
    }
    if ($null -ne $mutex) {
        $mutex.Dispose()
    }
}

if ($restartRequested) {
    $escapedTaskName = $TaskName.Replace("'", "''")
    $restartTaskName = (
        '{0} Restart {1}' -f
        $TaskName, [Guid]::NewGuid().ToString('N')
    )
    $escapedRestartTaskName = $restartTaskName.Replace("'", "''")
    $helperCommand = (
        '$deadline=(Get-Date).AddMinutes(2); ' +
        'try { do { ' +
        "$task=Get-ScheduledTask -TaskName '$escapedTaskName' " +
        '-ErrorAction SilentlyContinue; ' +
        'if ($null -ne $task -and $task.State -ne ''Running'') { ' +
        "Start-ScheduledTask -TaskName '$escapedTaskName'; exit 0 }; " +
        'Start-Sleep -Seconds 2 ' +
        '} while ((Get-Date) -lt $deadline); exit 1 ' +
        '} finally { ' +
        "Unregister-ScheduledTask -TaskName '$escapedRestartTaskName' " +
        '-Confirm:$false -ErrorAction SilentlyContinue }'
    )
    $restartAction = New-ScheduledTaskAction -Execute $powershellPath `
        -Argument (
            '-NoProfile -NonInteractive -ExecutionPolicy Bypass ' +
            "-Command `"$helperCommand`""
        )
    $restartTrigger = New-ScheduledTaskTrigger -Once `
        -At (Get-Date).AddSeconds(10)
    $restartSettings = New-ScheduledTaskSettingsSet `
        -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 3)
    $restartPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' `
        -LogonType ServiceAccount -RunLevel Highest
    $restartTask = New-ScheduledTask -Action $restartAction `
        -Trigger $restartTrigger -Settings $restartSettings `
        -Principal $restartPrincipal -Description (
            'One-shot supervised restart for the eSE unattended lab agent.'
        )
    Register-ScheduledTask -TaskName $restartTaskName `
        -InputObject $restartTask -Force | Out-Null
    exit 75
}
